import express, { type Request, type Response } from 'express';
import { type ChildProcess, spawn } from 'child_process';
import { createInterface } from 'readline';
import http from 'node:http';
import https from 'node:https';
import { PolicyEngine } from '../policy/engine.js';
import {
  type MCPRequest,
  type MCPResponse,
  interceptRequest,
  filterToolsListResponse,
  filterResourcesListResponse,
  filterPromptsListResponse,
  scanResponse,
} from './intercept.js';
import type { McpServerConfig, PolicyConfig, ProxyStats, ProxyServerOptions } from '../types.js';
import { trackCall } from '../security/attack-chains.js';
import { validateToolArgs, validatePathSafety } from '../security/schema-validator.js';
import { checkAccess } from '../policy/rbac.js';
import { checkThreatIntel, type ThreatIntelResult } from '../policy/threat-intel.js';
import { injectHoneytokens, detectHoneytokenAccess } from '../security/honeytokens.js';
import { captureRequest, captureResponse } from '../security/forensics.js';

export interface RegisteredServer {
  name: string;
  originalUrl: string;
  proxyUrl: string;
  risk: string;
}

// Shared keep-alive connection pools for upstream HTTP(S) calls. Without an
// explicit agent, every proxied call pays for a fresh TCP handshake.
const HTTP_KEEPALIVE_AGENT = new http.Agent({
  keepAlive: true,
  maxSockets: 1024,
  keepAliveMsecs: 30000,
});
const HTTPS_KEEPALIVE_AGENT = new https.Agent({
  keepAlive: true,
  maxSockets: 1024,
  keepAliveMsecs: 30000,
});

export interface LatencyStats {
  p50: number;
  p95: number;
  p99: number;
  avg: number;
  max: number;
  count: number;
  throughput: number;
}

interface ServerRegistration {
  name: string;
  command: string;
  args: string[];
  env?: Record<string, string>;
  transport: 'stdio' | 'http' | 'sse' | 'streamable-http';
  url?: string;
}

interface PendingRequest {
  resolve: (value: MCPResponse) => void;
  reject: (reason: Error) => void;
  timer: NodeJS.Timeout;
}

interface CircuitBreakerState {
  failures: number;
  openUntil: number;
  halfOpen: boolean;
}

interface RateLimitEntry {
  count: number;
  resetTime: number;
}

export class StdioClient {
  private child: ChildProcess | null = null;
  private pending: Map<number | string, PendingRequest> = new Map();
  private command: string;
  private args: string[];
  private env: Record<string, string>;
  private stopped = false;
  private restartCount = 0;
  private readonly MAX_RESTARTS = 5;
  timedOut = 0;
  onNotification: ((notification: MCPResponse) => void) | null = null;

  constructor(command: string, args: string[], env?: Record<string, string>) {
    this.command = command;
    this.args = args;
    this.env = Object.fromEntries(
      Object.entries(process.env).filter(([, v]) => v !== undefined),
    ) as Record<string, string>;
    if (env) {
      Object.assign(this.env, env);
    }
  }

  async start(): Promise<void> {
    this.stopped = false;
    this.restartCount = 0;
    this.spawnProcess();
  }

  private spawnProcess(): void {
    if (this.stopped) return;

    this.child = spawn(this.command, this.args, {
      env: this.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    // A write to a dead child's stdin surfaces as an async 'error' event
    // (EPIPE), not a synchronous throw. Without a listener, Node raises it
    // as an uncaught exception. Swallow it here and reject pending requests
    // cleanly instead.
    this.child.stdin?.on('error', (err: NodeJS.ErrnoException) => {
      this.rejectPendingOnTransportError(err);
    });

    const rl = createInterface({ input: this.child.stdout! });

    rl.on('line', (line: string) => {
      try {
        const response: MCPResponse = JSON.parse(line);
        const id = response.id;
        if (id !== undefined && id !== null) {
          const pending = this.pending.get(id);
          if (pending) {
            clearTimeout(pending.timer);
            this.pending.delete(id);
            pending.resolve(response);
          }
        } else {
          this.onNotification?.(response);
        }
      } catch {
        // ignore unparseable lines (stderr noise, etc.)
      }
    });

    rl.on('error', (err: Error) => {
      console.error(`[mcp-seatbelt:${this.command}] Readline error: ${err.message}`);
    });

    rl.on('close', () => {
      // readline closed; process exit handler will trigger reconnect
    });

    this.child.stderr?.on('data', (data: Buffer) => {
      let handled = false;
      const text = data.toString();
      for (const line of text.split('\n').map((l) => l.trim()).filter(Boolean)) {
        try {
          const response: MCPResponse = JSON.parse(line);
          const id = response.id;
          if (id !== undefined && id !== null) {
            const pending = this.pending.get(id);
            if (pending) {
              clearTimeout(pending.timer);
              this.pending.delete(id);
              pending.resolve(response);
              handled = true;
            }
          } else {
            this.onNotification?.(response);
          }
        } catch {
          // not JSON-RPC
        }
      }
      if (!handled) {
        process.stderr.write(`[mcp-seatbelt:${this.command}] ${text}`);
      }
    });

    this.child.on('exit', (code, signal) => {
      this.restartCount++;
      if (!this.stopped && this.restartCount < this.MAX_RESTARTS) {
        process.stderr.write(`[mcp-seatbelt:${this.command}] exited (code=${code}). Restart ${this.restartCount}/${this.MAX_RESTARTS}\n`);
        setTimeout(() => this.spawnProcess(), 1000);
      } else if (!this.stopped) {
        process.stderr.write(`[mcp-seatbelt:${this.command}] max restarts (${this.MAX_RESTARTS}) reached. Not restarting.\n`);
      }
      for (const [, pending] of this.pending) {
        clearTimeout(pending.timer);
        pending.reject(
          new Error(`Process exited with code ${code}, signal ${signal}`),
        );
      }
      this.pending.clear();
    });
  }

  private isStdinWritable(): boolean {
    const stdin = this.child?.stdin;
    return (
      !this.stopped &&
      !!this.child &&
      !this.child.killed &&
      this.child.exitCode === null &&
      this.child.signalCode === null &&
      !!stdin &&
      !stdin.destroyed &&
      stdin.writable
    );
  }

  private rejectPendingOnTransportError(err: NodeJS.ErrnoException): void {
    // stdin is broken (e.g. EPIPE after the child died): in-flight requests
    // can never be delivered, so reject them cleanly rather than letting the
    // stream error escape as an uncaught exception.
    const reason = new Error(
      `Process not running (${err.code ?? err.message})`,
    );
    for (const [, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.reject(reason);
    }
    this.pending.clear();
  }

  private failPendingWrite(id: number | string, err: Error): void {
    const pending = this.pending.get(id);
    if (pending) {
      clearTimeout(pending.timer);
      this.pending.delete(id);
      pending.reject(err);
    }
  }

  async send(request: MCPRequest, timeoutMs?: number): Promise<MCPResponse | null> {
    if (!this.isStdinWritable()) {
      throw new Error('Process not running');
    }

    const payload = JSON.stringify(request) + '\n';
    const stdin = this.child!.stdin!;

    if (request.id === undefined || request.id === null) {
      try {
        // The child may die between the writability check and the flush of
        // this write; the callback and the stdin 'error' listener absorb it.
        stdin.write(payload, () => {});
      } catch {
        // nothing pending to reject for notifications
      }
      return null;
    }

    const effectiveTimeout = timeoutMs ?? 30000;

    return new Promise<MCPResponse>((resolve, reject) => {
      const id = request.id!;
      const timer = setTimeout(() => {
        this.timedOut++;

        if (this.child && !this.child.killed) {
          process.stderr.write(`[mcp-seatbelt:${this.command}] timeout after ${effectiveTimeout}ms, killing...\n`);
          this.child.kill('SIGTERM');
          setTimeout(() => {
            if (this.child && !this.child.killed) {
              this.child.kill('SIGKILL');
            }
          }, 2000);
        }

        for (const [, p] of this.pending) {
          clearTimeout(p.timer);
          p.reject(new Error(`Call exceeded timeout (${effectiveTimeout}ms)`));
        }
        this.pending.clear();
      }, effectiveTimeout);

      this.pending.set(id, { resolve, reject, timer });

      try {
        stdin.write(payload, (err?: Error | null) => {
          if (err) {
            this.failPendingWrite(id, err);
          }
        });
      } catch (e: any) {
        this.failPendingWrite(id, e instanceof Error ? e : new Error(String(e)));
      }
    });
  }

  stop(): void {
    this.stopped = true;
    if (this.child) {
      this.child.kill();
      this.child = null;
    }
    for (const [, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.reject(new Error('Transport stopped'));
    }
    this.pending.clear();
  }
}

export class HttpClient {
  private url: URL;
  private inflight: Set<http.ClientRequest> = new Set();
  private stopped = false;
  timedOut = 0;

  constructor(url: string) {
    this.url = new URL(url);
  }

  async start(): Promise<void> {
    this.stopped = false;
  }

  stop(): void {
    this.stopped = true;
    for (const req of this.inflight) {
      req.destroy();
    }
    this.inflight.clear();
  }

  async send(request: MCPRequest, timeoutMs: number = 30000): Promise<MCPResponse> {
    const body = JSON.stringify(request);
    const isHttps = this.url.protocol === 'https:';
    const transport = isHttps ? https : http;

    return new Promise<MCPResponse>((resolve, reject) => {
      let settled = false;
      let didTimeOut = false;

      const req = transport.request(
        {
          hostname: this.url.hostname,
          port: this.url.port || (isHttps ? 443 : 80),
          path: this.url.pathname + this.url.search,
          method: 'POST',
          agent: isHttps ? HTTPS_KEEPALIVE_AGENT : HTTP_KEEPALIVE_AGENT,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            finish(() => {
              const status = res.statusCode ?? 0;
              if (status < 200 || status >= 300) {
                reject(new Error(`HTTP ${status}: ${res.statusMessage}`));
                return;
              }
              try {
                resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) as MCPResponse);
              } catch (err) {
                reject(err instanceof Error ? err : new Error(String(err)));
              }
            });
          });
          res.on('error', (err: Error) => {
            finish(() => reject(err));
          });
        },
      );

      const finish = (fn: () => void): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.inflight.delete(req);
        fn();
      };

      const timer = setTimeout(() => {
        didTimeOut = true;
        this.timedOut++;
        req.destroy(new Error('request timeout'));
      }, timeoutMs);

      req.on('error', (err) => {
        finish(() => {
          if (didTimeOut) {
            reject(new Error(`Call exceeded timeout (${timeoutMs}ms)`));
          } else {
            reject(err);
          }
        });
      });

      this.inflight.add(req);
      req.end(body);
    });
  }
}

export class SseClient {
  private url: string;
  private pending: Map<number | string, PendingRequest> = new Map();
  private streamAbort: AbortController | null = null;
  private stopped = false;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private reconnectCount = 0;
  private readonly MAX_RECONNECTS = 5;
  private messageEndpoint: string;
  timedOut = 0;
  onNotification: ((notification: MCPResponse) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    this.messageEndpoint = url.replace(/\/sse\/?$/, '');
    if (!this.messageEndpoint.endsWith('/message')) {
      if (this.messageEndpoint.endsWith('/')) {
        this.messageEndpoint += 'message';
      } else {
        this.messageEndpoint += '/message';
      }
    }
  }

  async start(): Promise<void> {
    this.stopped = false;
    this.reconnectCount = 0;
    this.connectSSE();
  }

  private connectSSE(): void {
    if (this.stopped) return;

    this.streamAbort = new AbortController();

    fetch(this.url, {
      headers: { 'Accept': 'text/event-stream' },
      signal: this.streamAbort.signal,
    })
      .then(async (response) => {
        if (!response.ok || !response.body) {
          throw new Error(`SSE connection failed: HTTP ${response.status}`);
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          let eventData = '';
          for (const line of lines) {
            if (line.startsWith('data: ')) {
              eventData += line.slice(6);
            } else if (line === '') {
              if (eventData) {
                this.handleSSEMessage(eventData);
                eventData = '';
              }
            }
          }
        }
      })
      .catch((err: unknown) => {
        if (!this.stopped) {
          console.error(`[mcp-seatbelt:sse] Connection error: ${err instanceof Error ? err.message : 'Unknown error'}`);
          this.scheduleReconnect();
        }
      });
  }

  private handleSSEMessage(data: string): void {
    try {
      const response: MCPResponse = JSON.parse(data);
      const id = response.id;
      if (id !== undefined && id !== null) {
        const pending = this.pending.get(id);
        if (pending) {
          clearTimeout(pending.timer);
          this.pending.delete(id);
          pending.resolve(response);
        }
      } else {
        this.onNotification?.(response);
      }
    } catch {
      // ignore unparseable SSE data
    }
  }

  private scheduleReconnect(): void {
    if (this.stopped) return;
    this.reconnectCount++;
    if (this.reconnectCount >= this.MAX_RECONNECTS) {
      process.stderr.write(`[mcp-seatbelt:sse] max reconnects (${this.MAX_RECONNECTS}) reached. Not reconnecting.\n`);
      return;
    }
    process.stderr.write(`[mcp-seatbelt:sse] reconnecting ${this.reconnectCount}/${this.MAX_RECONNECTS}\n`);
    this.reconnectTimer = setTimeout(() => this.connectSSE(), 1000);
  }

  async send(request: MCPRequest, timeoutMs: number = 30000): Promise<MCPResponse | null> {
    if (request.id === undefined || request.id === null) {
      fetch(this.messageEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      }).catch(() => {});
      return null;
    }

    const id = request.id;

    return new Promise<MCPResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        this.timedOut++;
        reject(new Error(`Call exceeded timeout (${timeoutMs}ms)`));
      }, timeoutMs);

      this.pending.set(id, { resolve, reject, timer });

      fetch(this.messageEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      }).catch((err) => {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new Error(`SSE POST failed: ${err instanceof Error ? err.message : 'Unknown error'}`));
      });
    });
  }

  stop(): void {
    this.stopped = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.streamAbort) {
      this.streamAbort.abort();
      this.streamAbort = null;
    }
    for (const [, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.reject(new Error('Transport stopped'));
    }
    this.pending.clear();
  }
}

export class StreamableHttpClient {
  private url: string;
  private stopped = false;
  timedOut = 0;

  constructor(url: string) {
    this.url = url;
  }

  async start(): Promise<void> {
    this.stopped = false;
  }

  stop(): void {
    this.stopped = true;
  }

  async send(request: MCPRequest, timeoutMs: number = 30000): Promise<MCPResponse> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(this.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json, text/event-stream',
        },
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('text/event-stream')) {
        const text = await response.text();
        const lines = text.split('\n');
        let data = '';
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            data += line.slice(6);
          }
        }
        if (data) {
          return JSON.parse(data) as MCPResponse;
        }
        throw new Error('Empty SSE stream response from streamable-http endpoint');
      }

      return response.json() as Promise<MCPResponse>;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof Error && error.name === 'AbortError') {
        this.timedOut++;
        throw new Error(`Call exceeded timeout (${timeoutMs}ms)`);
      }
      throw error;
    }
  }
}

type McpClient = StdioClient | HttpClient | SseClient | StreamableHttpClient;

export class ProxyServer {
  private policy: PolicyEngine;
  private port: number;
  private servers: Map<string, ServerRegistration> = new Map();
  private clients: Map<string, McpClient> = new Map();
  private registeredServers: RegisteredServer[] = [];
  private app: express.Express;
  private httpServer: http.Server | null = null;
  private stats: ProxyStats;
  private startTime: Date = new Date();

  private apiKey: string | null;
  private rateLimitMax: number;
  private rateLimitWindow: number = 60000;
  private dlp: boolean;
  private defaultTimeoutMs: number;
  private injectHoneytokensFlag: boolean;
  private forensicsCaptureFlag: boolean;
  private rateLimits: Map<string, RateLimitEntry> = new Map();
  private circuits: Map<string, CircuitBreakerState> = new Map();
  private readonly CIRCUIT_THRESHOLD = 5;
  private readonly CIRCUIT_TIMEOUT = 30000;

  private toolDescriptions: Map<string, string> = new Map();

  private latencies: number[] = [];
  private readonly MAX_LATENCY_SAMPLES = 10000;
  private requestTimestamps: number[] = [];
  private requestTimestampsStart = 0;
  private readonly THROUGHPUT_WINDOW_MS = 5000;

  constructor(policy: PolicyEngine, port: number = 9420, options?: ProxyServerOptions) {
    this.policy = policy;
    this.port = port;
    this.apiKey = options?.apiKey ?? null;
    this.rateLimitMax = options?.rateLimit ?? 100;
    this.dlp = options?.dlp ?? true;
    this.defaultTimeoutMs = options?.defaultTimeoutMs ?? 30000;
    this.injectHoneytokensFlag = options?.injectHoneytokens ?? (policy.getConfig().mode === 'audit');
    this.forensicsCaptureFlag = options?.forensicsCapture ?? false;

    this.app = express();
    // Skip per-response ETag hashing and the X-Powered-By header; this is a
    // localhost JSON-RPC proxy, not a cacheable web API.
    this.app.disable('etag');
    this.app.disable('x-powered-by');
    this.app.use(express.json({ limit: '5mb' }));

    this.stats = {
      totalRequests: 0,
      blocked: 0,
      allowed: 0,
      warned: 0,
      redacted: 0,
      redactedCount: 0,
      timedOut: 0,
      honeytokenDetections: 0,
      startTime: '',
      uptime: 0,
    };

    this.setupRoutes();

    setInterval(() => this.cleanupRateLimits(), 60000);
  }

  reloadPolicy(newPolicyConfig: PolicyConfig): number {
    this.policy = new PolicyEngine(newPolicyConfig);
    return newPolicyConfig.rules.length;
  }

  shouldInjectHoneytokens(): boolean {
    return this.injectHoneytokensFlag;
  }

  isForensicsCaptureEnabled(): boolean {
    return this.forensicsCaptureFlag;
  }

  getLatencyStats(): LatencyStats {
    const sorted = [...this.latencies].sort((a, b) => a - b);
    const count = sorted.length;

    if (count === 0) {
      return { p50: 0, p95: 0, p99: 0, avg: 0, max: 0, count: 0, throughput: 0 };
    }

    const p50 = sorted[Math.floor(count * 0.5)];
    const p95 = sorted[Math.floor(count * 0.95)];
    const p99 = sorted[Math.floor(count * 0.99)];
    const avg = sorted.reduce((sum, v) => sum + v, 0) / count;
    const max = sorted[count - 1];

    const now = Date.now();
    const cutoff = now - this.THROUGHPUT_WINDOW_MS;
    let recent = 0;
    for (let i = this.requestTimestampsStart; i < this.requestTimestamps.length; i++) {
      if (this.requestTimestamps[i] > cutoff) recent++;
    }
    const throughput = recent / (this.THROUGHPUT_WINDOW_MS / 1000);

    return {
      p50: parseFloat((p50 / 1_000_000).toFixed(2)),
      p95: parseFloat((p95 / 1_000_000).toFixed(2)),
      p99: parseFloat((p99 / 1_000_000).toFixed(2)),
      avg: parseFloat((avg / 1_000_000).toFixed(2)),
      max: parseFloat((max / 1_000_000).toFixed(2)),
      count,
      throughput: parseFloat(throughput.toFixed(1)),
    };
  }

  private recordRequestTiming(startNs: bigint): void {
    const endNs = process.hrtime.bigint();
    const latencyNs = Number(endNs - startNs);

    this.latencies.push(latencyNs);
    // Amortized trim: one slice every MAX samples instead of an O(n) shift()
    // on every request once the buffer is full.
    if (this.latencies.length > this.MAX_LATENCY_SAMPLES * 2) {
      this.latencies = this.latencies.slice(-this.MAX_LATENCY_SAMPLES);
    }

    const now = Date.now();
    this.requestTimestamps.push(now);
    const cutoff = now - this.THROUGHPUT_WINDOW_MS;
    // Advance a start index instead of shift()-ing expired entries one by one.
    while (
      this.requestTimestampsStart < this.requestTimestamps.length &&
      this.requestTimestamps[this.requestTimestampsStart] <= cutoff
    ) {
      this.requestTimestampsStart++;
    }
    if (this.requestTimestampsStart > 4096) {
      this.requestTimestamps = this.requestTimestamps.slice(this.requestTimestampsStart);
      this.requestTimestampsStart = 0;
    }
  }

  register(server: McpServerConfig, _client: string): void {
    const originalUrl =
      server.url ||
      `${server.command} ${server.args.join(' ')} (${server.transport})`;

    this.registeredServers.push({
      name: server.name,
      originalUrl,
      proxyUrl: `http://localhost:${this.port}/${server.name}`,
      risk: server.risk.level,
    });

    this.registerServer(server);
  }

  registerServer(config: McpServerConfig): void {
    this.servers.set(config.name, {
      name: config.name,
      command: config.command,
      args: config.args,
      env: config.env,
      transport: config.transport,
      url: config.url,
    });
  }

  async start(): Promise<void> {
    this.startTime = new Date();
    this.stats.startTime = this.startTime.toISOString();

    for (const [name, reg] of this.servers) {
      let client: McpClient;
      if (reg.transport === 'sse' && reg.url) {
        client = new SseClient(reg.url);
        await (client as SseClient).start();
      } else if (reg.transport === 'streamable-http' && reg.url) {
        client = new StreamableHttpClient(reg.url);
      } else if (reg.transport === 'http' && reg.url) {
        client = new HttpClient(reg.url);
      } else {
        client = new StdioClient(reg.command, reg.args, reg.env);
        await (client as StdioClient).start();
      }
      this.clients.set(name, client);

      if (client instanceof StdioClient || client instanceof SseClient) {
        client.onNotification = (notification: MCPResponse) => {
          if (notification.method === 'notifications/tools/list_changed') {
            this.cacheToolDescriptions(name, client).catch(() => {});
          }
        };
      }

      await this.cacheToolDescriptions(name, client);
    }

    return new Promise((resolve) => {
      this.httpServer = this.app.listen(this.port, () => {
        resolve();
      });
    });
  }

  private async cacheToolDescriptions(serverName: string, client: McpClient): Promise<void> {
    try {
      const resp = await client.send({
        jsonrpc: '2.0',
        method: 'tools/list',
        id: `cache-desc-${serverName}`,
      });
      if (resp?.result && typeof resp.result === 'object') {
        const result = resp.result as Record<string, unknown>;
        if (Array.isArray(result.tools)) {
          for (const tool of result.tools) {
            if (tool && typeof tool === 'object') {
              const t = tool as Record<string, unknown>;
              if (typeof t.name === 'string') {
                this.toolDescriptions.set(t.name, typeof t.description === 'string' ? t.description : '');
              }
            }
          }
        }
      }
    } catch {
      // ignore caching errors, tool descriptions will default to empty string
    }
  }

  async stop(): Promise<void> {
    for (const client of this.clients.values()) {
      client.stop();
    }
    this.clients.clear();

    return new Promise((resolve) => {
      if (this.httpServer) {
        this.httpServer.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  getServers(): RegisteredServer[] {
    return [...this.registeredServers];
  }

  isRunning(): boolean {
    return this.httpServer?.listening ?? false;
  }

  getProxyUrl(name: string): string {
    return `http://localhost:${this.port}/${name}`;
  }

  getStats(): ProxyStats {
    let totalTimedOut = this.stats.timedOut;
    for (const client of this.clients.values()) {
      const c = client as unknown as { timedOut: number };
      totalTimedOut += c.timedOut;
    }
    return {
      ...this.stats,
      timedOut: totalTimedOut,
      uptime: Date.now() - this.startTime.getTime(),
    };
  }

  private checkCircuit(serverName: string): 'open' | 'half-open' | 'closed' {
    const circuit = this.circuits.get(serverName);
    if (!circuit) return 'closed';

    const now = Date.now();
    if (circuit.openUntil > now) {
      return 'open';
    }

    if (circuit.failures >= this.CIRCUIT_THRESHOLD && circuit.openUntil <= now && !circuit.halfOpen) {
      circuit.halfOpen = true;
      return 'half-open';
    }

    return 'closed';
  }

  private recordSuccess(serverName: string): void {
    const circuit = this.circuits.get(serverName);
    if (circuit) {
      this.circuits.delete(serverName);
    }
  }

  private recordFailure(serverName: string): void {
    let circuit = this.circuits.get(serverName);
    if (!circuit) {
      circuit = { failures: 0, openUntil: 0, halfOpen: false };
      this.circuits.set(serverName, circuit);
    }
    circuit.failures++;
    if (circuit.failures >= this.CIRCUIT_THRESHOLD) {
      circuit.openUntil = Date.now() + this.CIRCUIT_TIMEOUT;
    }
  }

  private cleanupRateLimits(): void {
    const now = Date.now();
    for (const [ip, entry] of this.rateLimits) {
      if (now >= entry.resetTime) {
        this.rateLimits.delete(ip);
      }
    }
  }

  private checkRateLimit(ip: string): boolean {
    const now = Date.now();
    const entry = this.rateLimits.get(ip);

    if (!entry || now >= entry.resetTime) {
      this.rateLimits.set(ip, { count: 1, resetTime: now + this.rateLimitWindow });
      return true;
    }

    if (entry.count >= this.rateLimitMax) {
      return false;
    }

    entry.count++;
    return true;
  }

  private setupRoutes(): void {
    this.app.get('/health', (_req: Request, res: Response) => {
      res.json({
        status: 'ok',
        stats: this.getStats(),
        latency: this.getLatencyStats(),
      });
    });

    this.app.get('/servers', (_req: Request, res: Response) => {
      res.json({
        servers: this.registeredServers.map((s) => ({
          name: s.name,
          proxyUrl: s.proxyUrl,
          risk: s.risk,
        })),
      });
    });

    this.app.post('/:serverName', async (req: Request, res: Response) => {
      const startNs = process.hrtime.bigint();
      res.on('finish', () => this.recordRequestTiming(startNs));

      if (this.apiKey) {
        const authHeader = req.headers['authorization'];
        if (!authHeader || !authHeader.startsWith('Bearer ') || authHeader.slice(7) !== this.apiKey) {
          res.status(401).json({
            jsonrpc: '2.0',
            error: {
              code: -32003,
              message: 'Unauthorized: invalid or missing API key',
            },
            id: null,
          });
          return;
        }
      }

      const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
      if (!this.checkRateLimit(clientIp)) {
        res.status(429).json({
          jsonrpc: '2.0',
          error: {
            code: -32004,
            message: 'Rate limit exceeded',
          },
          id: null,
        });
        return;
      }

      const { serverName } = req.params;
      const mcpRequest = req.body as MCPRequest;

      this.stats.totalRequests++;

      if (this.forensicsCaptureFlag) {
        captureRequest(mcpRequest);
      }

      if (mcpRequest.method === 'tools/call' && mcpRequest.params?.arguments) {
        const detected = detectHoneytokenAccess(mcpRequest.params.arguments, serverName);
        if (detected) {
          console.error(`[mcp-seatbelt:honeytoken] ALERT: Honeytoken ${detected.id} (${detected.type}) accessed by ${serverName}!`);
          this.stats.honeytokenDetections++;
          res.status(403).json({
            jsonrpc: '2.0',
            error: { code: -32001, message: `Honeytoken detected: ${detected.type} credential was accessed. This is a decoy.` },
            id: mcpRequest.id ?? null,
          });
          return;
        }
      }

      if (!mcpRequest || mcpRequest.jsonrpc !== '2.0') {
        res.status(400).json({
          jsonrpc: '2.0',
          error: {
            code: -32600,
            message: 'Invalid Request: not a valid JSON-RPC 2.0 request',
          },
          id: mcpRequest?.id ?? null,
        });
        return;
      }

      if (!this.servers.has(serverName)) {
        res.status(404).json({
          jsonrpc: '2.0',
          error: {
            code: -32601,
            message: `Unknown server: ${serverName}`,
          },
          id: mcpRequest.id ?? null,
        });
        return;
      }

      const circuitState = this.checkCircuit(serverName);
      if (circuitState === 'open') {
        res.status(503).json({
          jsonrpc: '2.0',
          error: {
            code: -32002,
            message: `Circuit open for server "${serverName}". Service temporarily unavailable.`,
          },
          id: mcpRequest.id ?? null,
        });
        return;
      }

      const toolDescription = mcpRequest.method === 'tools/call' && mcpRequest.params?.name
        ? this.toolDescriptions.get(mcpRequest.params.name) || ''
        : '';

      const blockedResponse = interceptRequest(
        mcpRequest,
        this.policy,
        serverName,
        undefined,
        toolDescription,
      );
      if (blockedResponse) {
        this.stats.blocked++;
        const reason = blockedResponse.error?.data && typeof blockedResponse.error.data === 'object'
          ? ((blockedResponse.error.data as Record<string, unknown>).reasons as string[] || []).join('; ')
          : (blockedResponse.error?.message || '');
        (async () => {
          try {
            const { addBlockedCall } = await import('../commands/dashboard.js');
            addBlockedCall(
              mcpRequest.method === 'tools/call' && mcpRequest.params?.name
                ? mcpRequest.params.name
                : mcpRequest.method,
              serverName,
              reason,
            );
          } catch {}
        })();
        res.json(blockedResponse);
        return;
      }

      const toolName =
        mcpRequest.method === 'tools/call' && mcpRequest.params?.name
          ? mcpRequest.params.name
          : mcpRequest.method;

      // Stable session per upstream server: a fresh session id per request
      // would spawn a new xstate actor for every call (and leak it in the
      // sessions map) while making cross-call chain detection impossible.
      const chain = trackCall({
        toolName,
        args: mcpRequest.params?.arguments ?? {},
        sessionId: serverName,
        timestamp: Date.now(),
      });

      if (chain.alert) {
        console.error("[mcp-seatbelt:attack-chain] Attack chain detected — escalating to deny");
        this.stats.blocked++;
        res.status(400).json({
          jsonrpc: "2.0",
          error: {
            code: -32001,
            message: "Blocked by MCP Seatbelt: attack chain detected — exfiltration confirmed",
          },
          id: mcpRequest.id ?? null,
        });
        return;
      }

      if (mcpRequest.method === 'tools/call' && mcpRequest.params?.name) {
        const toolArgs = mcpRequest.params.arguments ?? {};
        const schemaResult = validateToolArgs(mcpRequest.params.name, toolArgs);
        if (!schemaResult.valid) {
          res.status(400).json({
            jsonrpc: "2.0",
            error: { code: -32602, message: `Schema validation failed: ${schemaResult.errors.join("; ")}` },
            id: mcpRequest.id ?? null,
          });
          return;
        }

        const pathResult = validatePathSafety(toolArgs as Record<string, unknown>);
        if (!pathResult.safe) {
          res.status(400).json({
            jsonrpc: "2.0",
            error: { code: -32001, message: `Path safety violation: ${pathResult.violations.join("; ")}` },
            id: mcpRequest.id ?? null,
          });
          return;
        }
      }

      const agentId = (req.headers['x-agent-id'] as string) || 'unknown_agent';
      const hasAccess = await checkAccess(agentId, toolName, 'execute');
      if (!hasAccess) {
        this.stats.blocked++;
        res.status(403).json({
          jsonrpc: '2.0',
          error: {
            code: -32001,
            message: `RBAC denied: agent '${agentId}' cannot execute '${toolName}'`,
          },
          id: mcpRequest.id ?? null,
        });
        return;
      }

      if (mcpRequest.method === 'tools/call' && mcpRequest.params?.arguments) {
        const tiResults = await checkThreatIntel(mcpRequest.params.arguments as Record<string, unknown>);
        if (tiResults.some((r: ThreatIntelResult) => r.malicious)) {
          const malicious = tiResults.filter((r: ThreatIntelResult) => r.malicious);
          console.warn(`[mcp-seatbelt:threat-intel] Blocked ${toolName}: ${malicious.map((r: ThreatIntelResult) => `${r.queryType}=${r.queryValue}`).join(", ")}`);
          this.stats.blocked++;
          res.status(403).json({
            jsonrpc: '2.0',
            error: {
              code: -32001,
              message: `Blocked by threat intel: malicious indicators detected in arguments`,
              data: { indicators: malicious.map((r) => ({ type: r.queryType, value: r.queryValue, source: r.source })) },
            },
            id: mcpRequest.id ?? null,
          });
          return;
        }
      }

      const client = this.clients.get(serverName);
      if (!client) {
        res.status(503).json({
          jsonrpc: '2.0',
          error: {
            code: -32603,
            message: `Server ${serverName} transport not available`,
          },
          id: mcpRequest.id ?? null,
        });
        return;
      }

      let effectiveTimeout = this.defaultTimeoutMs;

      if (mcpRequest.method === 'tools/call' && mcpRequest.params?.name) {
        const description = this.toolDescriptions.get(mcpRequest.params.name) || '';
        effectiveTimeout = this.policy.getEffectiveTimeout(
          mcpRequest.params.name,
          description,
          mcpRequest.params.arguments ?? {},
          effectiveTimeout,
        );
      } else {
        effectiveTimeout = this.policy.getConfig().defaultTimeoutMs ?? effectiveTimeout;
      }

      try {
        const upstreamResponse = await client.send(mcpRequest, effectiveTimeout);

        this.recordSuccess(serverName);

        if (this.forensicsCaptureFlag) {
          captureResponse(upstreamResponse);
        }

        if (upstreamResponse === null) {
          this.stats.allowed++;
          res.status(202).end();
          return;
        }

        let finalResponse = upstreamResponse;

        if (this.dlp) {
          const scanResult = scanResponse(upstreamResponse, this.policy);
          finalResponse = scanResult.response;
          if (scanResult.redactedCount > 0) {
            this.stats.redactedCount += scanResult.redactedCount;
            for (const redaction of scanResult.redactions) {
              console.warn(
                `[mcp-seatbelt:dlp] Redacted [${redaction.type}] at ${redaction.path}`,
              );
            }
          }
        }

        if (this.injectHoneytokensFlag) {
          const injectionResult = injectHoneytokens(finalResponse, {
            serverName,
            sessionId: String(mcpRequest.id ?? 'unknown'),
          });
          if (injectionResult.modified) {
            console.log(`[mcp-seatbelt:honeytoken] Planted ${injectionResult.planted} honeytokens in response for ${serverName}`);
          }
        }

        if (mcpRequest.method === 'tools/list') {
          const filtered = filterToolsListResponse(
            finalResponse,
            this.policy,
            serverName,
          );
          this.stats.allowed++;
          res.json(filtered);
        } else if (mcpRequest.method === 'resources/list') {
          const filtered = filterResourcesListResponse(
            finalResponse,
            this.policy,
            serverName,
          );
          this.stats.allowed++;
          res.json(filtered);
        } else if (mcpRequest.method === 'prompts/list') {
          const filtered = filterPromptsListResponse(
            finalResponse,
            this.policy,
            serverName,
          );
          this.stats.allowed++;
          res.json(filtered);
        } else {
          if (mcpRequest.method === 'tools/call' && mcpRequest.params?.name) {
            const description = this.toolDescriptions.get(mcpRequest.params.name) || '';
            const evalResult = this.policy.evaluate(
              mcpRequest.params.name,
              description,
              mcpRequest.params.arguments ?? {},
            );
            if (evalResult.action === 'warn') {
              this.stats.warned++;
            }
            if (evalResult.action === 'redact') {
              this.stats.redacted++;
            }
          }
          this.stats.allowed++;
          res.json(finalResponse);
        }
      } catch (error) {
        this.recordFailure(serverName);
        const errMsg = error instanceof Error ? error.message : 'Unknown error';
        if (/timeout/i.test(errMsg)) {
          this.stats.timedOut++;
          res.status(504).json({
            jsonrpc: '2.0',
            error: { code: -32001, message: errMsg },
            id: mcpRequest.id ?? null,
          });
        } else {
          res.status(502).json({
            jsonrpc: '2.0',
            error: {
              code: -32603,
              message: `Upstream error: ${errMsg}`,
            },
            id: mcpRequest.id ?? null,
          });
        }
      }
    });

    this.app.get('/:serverName', (req: Request, res: Response) => {
      const { serverName } = req.params;
      if (!this.servers.has(serverName)) {
        res.status(404).json({ error: `Unknown server: ${serverName}` });
        return;
      }
      res.json({
        name: serverName,
        proxyUrl: this.getProxyUrl(serverName),
      });
    });

    this.app.post('/:serverName/explain', (req: Request, res: Response) => {
      const { serverName } = req.params;
      if (!this.servers.has(serverName)) {
        res.status(404).json({ error: `Unknown server: ${serverName}` });
        return;
      }

      const body = req.body as Record<string, unknown>;
      const toolName = (body.tool as string) || '';
      const toolDescription = (body.description as string) || '';
      const args = (body.args as Record<string, unknown>) || {};

      if (!toolName) {
        res.status(400).json({ error: 'Missing tool name in request body' });
        return;
      }

      const evalResult = this.policy.evaluate(toolName, toolDescription, args, {
        client: serverName,
        requestCount: this.stats.totalRequests,
      });

      const rulesEvaluated = this.policy.getConfig().rules
        .filter((r) => r.action !== 'redact')
        .map((rule) => {
          const wasApplied = evalResult.reasons.some((r) =>
            r.startsWith(`[${rule.id}]`),
          );
          return {
            id: rule.id,
            description: rule.description,
            action: rule.action,
            target: rule.target,
            match: rule.match,
            matched: wasApplied,
            hasTimeWindow: !!rule.timeWindow,
          };
        });

      res.json({
        server: serverName,
        tool: toolName,
        description: toolDescription,
        args,
        action: evalResult.action,
        reasons: evalResult.reasons,
        redactedKeys: evalResult.redactedKeys,
        rules: rulesEvaluated,
      });
    });
  }
}

import express, { type Request, type Response } from 'express';
import { type ChildProcess, spawn } from 'child_process';
import { createInterface } from 'readline';
import type http from 'http';
import type { PolicyEngine } from '../policy/engine.js';
import {
  type MCPRequest,
  type MCPResponse,
  interceptRequest,
  filterToolsListResponse,
  filterResourcesListResponse,
  filterPromptsListResponse,
} from './intercept.js';
import type { McpServerConfig, ProxyStats } from '../types.js';

export interface RegisteredServer {
  name: string;
  originalUrl: string;
  proxyUrl: string;
  risk: string;
}

export interface ProxyServerOptions {
  apiKey?: string;
  rateLimit?: number;
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
    this.spawnProcess();
  }

  private spawnProcess(): void {
    if (this.stopped) return;

    this.child = spawn(this.command, this.args, {
      env: this.env,
      stdio: ['pipe', 'pipe', 'pipe'],
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
      if (!this.stopped) {
        setTimeout(() => this.spawnProcess(), 1000);
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

  async send(request: MCPRequest): Promise<MCPResponse | null> {
    if (!this.child || this.child.killed) {
      throw new Error('Process not running');
    }

    if (request.id === undefined || request.id === null) {
      this.child.stdin!.write(JSON.stringify(request) + '\n');
      return null;
    }

    return new Promise<MCPResponse>((resolve, reject) => {
      const id = request.id!;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Request timeout: ${request.method}`));
      }, 30000);

      this.pending.set(id, { resolve, reject, timer });
      if (!this.child?.stdin?.destroyed) {
        try { this.child!.stdin!.write(JSON.stringify(request) + '\n'); }
        catch (e: any) { if (e.code !== 'EPIPE') throw e; }
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
  private url: string;
  private pendingControllers: Set<AbortController> = new Set();
  private stopped = false;

  constructor(url: string) {
    this.url = url;
  }

  async start(): Promise<void> {
    this.stopped = false;
  }

  stop(): void {
    this.stopped = true;
    for (const controller of this.pendingControllers) {
      controller.abort();
    }
    this.pendingControllers.clear();
  }

  async send(request: MCPRequest): Promise<MCPResponse> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);
    this.pendingControllers.add(controller);

    try {
      const response = await fetch(this.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      this.pendingControllers.delete(controller);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return response.json() as Promise<MCPResponse>;
    } catch (error) {
      clearTimeout(timeoutId);
      this.pendingControllers.delete(controller);

      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(`Request timeout: ${request.method}`);
      }
      throw error;
    }
  }
}

export class SseClient {
  private url: string;
  private pending: Map<number | string, PendingRequest> = new Map();
  private streamAbort: AbortController | null = null;
  private stopped = false;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private messageEndpoint: string;
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
    this.reconnectTimer = setTimeout(() => this.connectSSE(), 1000);
  }

  async send(request: MCPRequest): Promise<MCPResponse | null> {
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
        reject(new Error(`Request timeout: ${request.method}`));
      }, 30000);

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

  constructor(url: string) {
    this.url = url;
  }

  async start(): Promise<void> {
    this.stopped = false;
  }

  stop(): void {
    this.stopped = true;
  }

  async send(request: MCPRequest): Promise<MCPResponse> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

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
        throw new Error(`Request timeout: ${request.method}`);
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
  private rateLimits: Map<string, RateLimitEntry> = new Map();
  private circuits: Map<string, CircuitBreakerState> = new Map();
  private readonly CIRCUIT_THRESHOLD = 5;
  private readonly CIRCUIT_TIMEOUT = 30000;

  private toolDescriptions: Map<string, string> = new Map();

  constructor(policy: PolicyEngine, port: number = 9420, options?: ProxyServerOptions) {
    this.policy = policy;
    this.port = port;
    this.apiKey = options?.apiKey ?? null;
    this.rateLimitMax = options?.rateLimit ?? 100;

    this.app = express();
    this.app.use(express.json({ limit: '5mb' }));

    this.stats = {
      totalRequests: 0,
      blocked: 0,
      allowed: 0,
      warned: 0,
      redacted: 0,
      startTime: '',
      uptime: 0,
    };

    this.setupRoutes();

    setInterval(() => this.cleanupRateLimits(), 60000);
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
    return {
      ...this.stats,
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
      res.json({ status: 'ok', stats: this.getStats() });
    });

    this.app.post('/:serverName', async (req: Request, res: Response) => {
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

      const ctx = {
        client: serverName,
        requestCount: this.stats.totalRequests,
      };

      const blockedResponse = interceptRequest(
        mcpRequest,
        this.policy,
        serverName,
        undefined,
        toolDescription,
      );
      if (blockedResponse) {
        this.stats.blocked++;
        res.json(blockedResponse);
        return;
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

      try {
        const upstreamResponse = await client.send(mcpRequest);

        this.recordSuccess(serverName);

        if (upstreamResponse === null) {
          this.stats.allowed++;
          res.status(202).end();
          return;
        }

        if (mcpRequest.method === 'tools/list') {
          const filtered = filterToolsListResponse(
            upstreamResponse,
            this.policy,
            serverName,
          );
          this.stats.allowed++;
          res.json(filtered);
        } else if (mcpRequest.method === 'resources/list') {
          const filtered = filterResourcesListResponse(
            upstreamResponse,
            this.policy,
            serverName,
          );
          this.stats.allowed++;
          res.json(filtered);
        } else if (mcpRequest.method === 'prompts/list') {
          const filtered = filterPromptsListResponse(
            upstreamResponse,
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
          res.json(upstreamResponse);
        }
      } catch (error) {
        this.recordFailure(serverName);
        res.status(502).json({
          jsonrpc: '2.0',
          error: {
            code: -32603,
            message: `Upstream error: ${error instanceof Error ? error.message : 'Unknown error'}`,
          },
          id: mcpRequest.id ?? null,
        });
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
  }
}

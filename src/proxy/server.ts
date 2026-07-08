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
} from './intercept.js';
import type { McpServerConfig, ProxyStats } from '../types.js';

export interface RegisteredServer {
  name: string;
  originalUrl: string;
  proxyUrl: string;
  risk: string;
}

interface ServerRegistration {
  name: string;
  command: string;
  args: string[];
  env?: Record<string, string>;
  transport: 'stdio' | 'http';
  url?: string;
}

interface PendingRequest {
  resolve: (value: MCPResponse) => void;
  reject: (reason: Error) => void;
  timer: NodeJS.Timeout;
}

class StdioClient {
  private child: ChildProcess | null = null;
  private pending: Map<number | string, PendingRequest> = new Map();
  private command: string;
  private args: string[];
  private env: Record<string, string>;
  private stopped = false;

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
        }
      } catch {
        // ignore unparseable lines (stderr noise, etc.)
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

    this.child.stderr?.on('data', (data: Buffer) => {
      process.stderr.write(`[mcp-seatbelt:${this.command}] ${data.toString()}`);
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
      this.child!.stdin!.write(JSON.stringify(request) + '\n');
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

class HttpClient {
  private url: string;

  constructor(url: string) {
    this.url = url;
  }

  async start(): Promise<void> {}

  stop(): void {}

  async send(request: MCPRequest): Promise<MCPResponse> {
    const response = await fetch(this.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
    return response.json() as Promise<MCPResponse>;
  }
}

type McpClient = StdioClient | HttpClient;

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

  constructor(policy: PolicyEngine, port: number = 9420) {
    this.policy = policy;
    this.port = port;
    this.app = express();
    this.app.use(express.json());

    this.stats = {
      totalRequests: 0,
      blocked: 0,
      allowed: 0,
      warned: 0,
      startTime: '',
      uptime: 0,
    };

    this.setupRoutes();
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

    this.registerServer(server.name, server.command, server.args, server.env);
  }

  registerServer(
    name: string,
    command: string,
    args: string[],
    env?: Record<string, string>,
  ): void {
    this.servers.set(name, { name, command, args, env, transport: 'stdio' });
  }

  async start(): Promise<void> {
    this.startTime = new Date();
    this.stats.startTime = this.startTime.toISOString();

    for (const [name, reg] of this.servers) {
      let client: McpClient;
      if (reg.transport === 'http' && reg.url) {
        client = new HttpClient(reg.url);
      } else {
        client = new StdioClient(reg.command, reg.args, reg.env);
        await (client as StdioClient).start();
      }
      this.clients.set(name, client);
    }

    return new Promise((resolve) => {
      this.httpServer = this.app.listen(this.port, () => {
        resolve();
      });
    });
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

  private setupRoutes(): void {
    this.app.get('/health', (_req: Request, res: Response) => {
      res.json({ status: 'ok', stats: this.getStats() });
    });

    this.app.post('/:serverName', async (req: Request, res: Response) => {
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

      const blockedResponse = interceptRequest(
        mcpRequest,
        this.policy,
        serverName,
      );
      if (blockedResponse) {
        this.stats.blocked++;
        res.json(blockedResponse);
        return;
      }

      if (
        mcpRequest.method === 'tools/call' &&
        mcpRequest.params?.name
      ) {
        const evalResult = this.policy.evaluate(
          mcpRequest.params.name,
          '',
          mcpRequest.params.arguments ?? {},
        );
        if (evalResult.action === 'warn') {
          this.stats.warned++;
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

      try {
        const upstreamResponse = await client.send(mcpRequest);

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
        } else {
          this.stats.allowed++;
          res.json(upstreamResponse);
        }
      } catch (error) {
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

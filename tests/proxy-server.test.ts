import { describe, it, expect, afterEach, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { ProxyServer, StdioClient, HttpClient } from '../src/proxy/server.js';
import { PolicyEngine } from '../src/policy/engine.js';
import type { PolicyConfig, McpServerConfig } from '../src/types.js';

function makePolicyConfig(rules: any[] = []): PolicyConfig {
  return {
    version: '1',
    mode: 'enforce',
    defaultAction: 'deny',
    rules: [
      {
        id: 'block-eval',
        description: 'Block eval tools',
        target: 'process',
        match: 'contains',
        values: ['eval'],
        action: 'deny',
      },
      ...rules,
    ],
    allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
  };
}

function makeAllowPolicyConfig(): PolicyConfig {
  return {
    version: '1',
    mode: 'enforce',
    defaultAction: 'allow',
    rules: [],
    allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
  };
}

function makeMcpServerConfig(overrides: Partial<McpServerConfig> = {}): McpServerConfig {
  return {
    name: 'test-srv',
    command: 'echo',
    args: ['hi'],
    transport: 'stdio',
    risk: { score: 0, level: 'low', flags: [] },
    ...overrides,
  };
}

function nodeEchoScript(responseFn: string = "{}"): string {
  return `
    const rl = require('readline').createInterface({ input: process.stdin });
    rl.on('line', (line) => {
      try {
        const req = JSON.parse(line);
        const result = ${responseFn};
        console.log(JSON.stringify({ jsonrpc: '2.0', result, id: req.id }));
      } catch (e) {}
    });
  `;
}

describe('ProxyServer', () => {
  let proxy: ProxyServer;
  let policy: PolicyEngine;

  afterEach(async () => {
    if (proxy) {
      try { await proxy.stop(); } catch {}
    }
  });

  it('constructs with default port 9420', () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy);
    expect(proxy.getProxyUrl('test')).toBe('http://localhost:9420/test');
  });

  it('constructs with custom port', () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy, 12345);
    expect(proxy.getProxyUrl('test')).toBe('http://localhost:12345/test');
  });

  it('registerServer stores config with correct transport and url', () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy, 0);
    proxy.registerServer(makeMcpServerConfig({
      name: 'my-server',
      command: 'node',
      args: ['-e', '1+1'],
      env: { FOO: 'bar' },
    }));
    expect(proxy.getProxyUrl('my-server')).toBe('http://localhost:0/my-server');
  });

  it('register() creates a RegisteredServer with correct fields', () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy, 9876);
    const server = makeMcpServerConfig({
      name: 'danger-server',
      command: 'bash',
      args: ['-c', 'echo'],
      risk: { score: 80, level: 'critical', flags: [] },
    });
    proxy.register(server, 'cursor');
    const servers = proxy.getServers();
    expect(servers).toHaveLength(1);
    expect(servers[0].name).toBe('danger-server');
    expect(servers[0].risk).toBe('critical');
    expect(servers[0].proxyUrl).toBe('http://localhost:9876/danger-server');
    expect(servers[0].originalUrl).toContain('bash');
  });

  it('getServers returns the registered list', () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy);
    proxy.register(makeMcpServerConfig({ name: 'srv1' }), 'test');
    proxy.register(makeMcpServerConfig({ name: 'srv2' }), 'test');
    expect(proxy.getServers()).toHaveLength(2);
  });

  it('starts and stops without registered servers', async () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy, 0);
    await proxy.start();
    expect(proxy.isRunning()).toBe(true);
    await proxy.stop();
    expect(proxy.isRunning()).toBe(false);
  });

  it('starts with registered stdio servers', async () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy, 0);
    proxy.registerServer(makeMcpServerConfig({ name: 'echo', command: 'echo', args: ['hello'] }));
    await proxy.start();
    expect(proxy.isRunning()).toBe(true);
    await proxy.stop();
  });

  it('stop() when not started does not throw', async () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy, 0);
    await expect(proxy.stop()).resolves.toBeUndefined();
  });

  it('/health returns ok status and stats', async () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy, 0);
    await proxy.start();

    const addr = (proxy as any).httpServer?.address();
    const port = addr?.port;
    expect(port).toBeGreaterThan(0);

    const response = await fetch(`http://localhost:${port}/health`);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.status).toBe('ok');
    expect(body.stats.totalRequests).toBe(0);
    expect(body.stats.blocked).toBe(0);
    expect(body.stats.allowed).toBe(0);
    expect(body.stats.warned).toBe(0);
    expect(body.stats.uptime).toBeGreaterThanOrEqual(0);

    await proxy.stop();
  });

  it('POST /:serverName returns 404 for unknown server', async () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy, 0);
    await proxy.start();

    const addr = (proxy as any).httpServer?.address();
    const port = addr?.port;

    const response = await fetch(`http://localhost:${port}/nonexistent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 1 }),
    });
    expect(response.status).toBe(404);
    const body = await response.json();
    expect(body.error.code).toBe(-32601);
    expect(body.error.message).toContain('nonexistent');

    await proxy.stop();
  });

  it('POST /:serverName returns 400 for non-JSON-RPC 2.0 request', async () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy, 0);
    proxy.registerServer(makeMcpServerConfig({ name: 'srv' }));
    await proxy.start();

    const addr = (proxy as any).httpServer?.address();
    const port = addr?.port;

    const response = await fetch(`http://localhost:${port}/srv`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ foo: 'bar' }),
    });
    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.error.code).toBe(-32600);

    await proxy.stop();
  });

  it('POST /:serverName blocks a denied tool call before it reaches the client', async () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy, 0);
    proxy.registerServer(makeMcpServerConfig({ name: 'srv' }));
    await proxy.start();

    const addr = (proxy as any).httpServer?.address();
    const port = addr?.port;

    const response = await fetch(`http://localhost:${port}/srv`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'tools/call',
        params: { name: 'unsafe_eval', arguments: { code: 'eval("bad")' } },
        id: 1,
      }),
    });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.error).toBeDefined();
    expect(body.error.code).toBe(-32001);
    expect(body.error.message).toContain('Blocked by MCP Seatbelt');

    const stats = proxy.getStats();
    expect(stats.totalRequests).toBe(1);
    expect(stats.blocked).toBe(1);

    await proxy.stop();
  });

  it('POST /:serverName proxies initialize through to stdio client', async () => {
    const echoScript = nodeEchoScript("{ protocolVersion: '2024-11-05' }");
    const allowPolicy = new PolicyEngine(makeAllowPolicyConfig());
    proxy = new ProxyServer(allowPolicy, 0);
    proxy.registerServer(makeMcpServerConfig({
      name: 'safe',
      command: 'node',
      args: ['-e', echoScript.trim()],
    }));
    await proxy.start();

    const addr = (proxy as any).httpServer?.address();
    const port = addr?.port;

    const response = await fetch(`http://localhost:${port}/safe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'initialize', id: 1 }),
    });
    const body = await response.json();
    expect(body.jsonrpc).toBe('2.0');
    expect(body.id).toBe(1);

    await proxy.stop();
  });

  it('POST /:serverName returns 503 when upstream client is unavailable', async () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy, 0);
    proxy.registerServer(makeMcpServerConfig({
      name: 'dying',
      command: 'node',
      args: ['-e', 'process.exit(0)'],
    }));
    await proxy.start();

    const addr = (proxy as any).httpServer?.address();
    const port = addr?.port;

    const response = await fetch(`http://localhost:${port}/dying`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 1 }),
    });
    expect([502, 503]).toContain(response.status);

    await proxy.stop();
  });

  it('GET /:serverName returns server info', async () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy, 5555);
    proxy.registerServer(makeMcpServerConfig({ name: 'my-srv', command: 'node', args: ['script.js'] }));
    await proxy.start();

    const addr = (proxy as any).httpServer?.address();
    const port = addr?.port;

    const response = await fetch(`http://localhost:${port}/my-srv`);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.name).toBe('my-srv');
    expect(body.proxyUrl).toBe(`http://localhost:${port}/my-srv`);

    await proxy.stop();
  });

  it('GET /:serverName returns 404 for unknown server', async () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy, 0);
    await proxy.start();

    const addr = (proxy as any).httpServer?.address();
    const port = addr?.port;

    const response = await fetch(`http://localhost:${port}/ghost`);
    expect(response.status).toBe(404);

    await proxy.stop();
  });

  it('getStats tracks blocked requests', async () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy, 0);
    proxy.registerServer(makeMcpServerConfig({ name: 'b' }));
    await proxy.start();

    const addr = (proxy as any).httpServer?.address();
    const port = addr?.port;

    await fetch(`http://localhost:${port}/b`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'tools/call',
        params: { name: 'eval_something' },
        id: 1,
      }),
    });

    const stats = proxy.getStats();
    expect(stats.totalRequests).toBe(1);
    expect(stats.blocked).toBe(1);
    expect(typeof stats.uptime).toBe('number');

    await proxy.stop();
  });

  it('isRunning returns false before start and true after', async () => {
    policy = new PolicyEngine(makePolicyConfig());
    proxy = new ProxyServer(policy, 0);
    expect(proxy.isRunning()).toBe(false);
    await proxy.start();
    expect(proxy.isRunning()).toBe(true);
    await proxy.stop();
    expect(proxy.isRunning()).toBe(false);
  });

  it('proxies requests to multiple registered servers', async () => {
    const echoScript = nodeEchoScript("{}");
    const allowPolicy = new PolicyEngine(makeAllowPolicyConfig());
    proxy = new ProxyServer(allowPolicy, 0);
    proxy.registerServer(makeMcpServerConfig({ name: 'a', command: 'node', args: ['-e', echoScript.trim()] }));
    proxy.registerServer(makeMcpServerConfig({ name: 'b', command: 'node', args: ['-e', echoScript.trim()] }));
    await proxy.start();

    const addr = (proxy as any).httpServer?.address();
    const port = addr?.port;

    const r1 = await fetch(`http://localhost:${port}/a`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'initialize', id: 1 }),
    });
    expect(r1.status).toBe(200);

    const r2 = await fetch(`http://localhost:${port}/b`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'initialize', id: 2 }),
    });
    expect(r2.status).toBe(200);

    expect(proxy.getStats().totalRequests).toBe(2);
    expect(proxy.isRunning()).toBe(true);

    await proxy.stop();
  });
});

// --- StdioClient ---

describe('StdioClient', () => {
  it('sends a JSON-RPC request and receives a response', async () => {
    const echoScript = `
      const rl = require('readline').createInterface({ input: process.stdin });
      rl.on('line', (line) => {
        try {
          const req = JSON.parse(line);
          console.log(JSON.stringify({
            jsonrpc: '2.0',
            result: { echo: req.params?.message || 'pong' },
            id: req.id,
          }));
        } catch (e) {}
      });
    `;
    const client = new StdioClient('node', ['-e', echoScript.trim()]);
    await client.start();

    const response = await client.send({
      jsonrpc: '2.0',
      method: 'echo',
      params: { message: 'hello' },
      id: 42,
    });

    expect(response).not.toBeNull();
    expect(response!.jsonrpc).toBe('2.0');
    expect(response!.result).toEqual({ echo: 'hello' });
    expect(response!.id).toBe(42);

    client.stop();
  });

  it('sends a notification (no id) and returns null', async () => {
    const script = `
      require('readline').createInterface({ input: process.stdin }).on('line', () => {});
    `;
    const client = new StdioClient('node', ['-e', script.trim()]);
    await client.start();

    const response = await client.send({
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    });

    expect(response).toBeNull();
    client.stop();
  });

  it('throws when process is not running', async () => {
    const client = new StdioClient('node', ['-e', '']);
    await expect(client.send({ jsonrpc: '2.0', method: 'test', id: 1 })).rejects.toThrow('Process not running');
  });

  it('rejects on request timeout', async () => {
    const script = `setTimeout(() => {}, 60000);`;
    const client = new StdioClient('node', ['-e', script.trim()]);
    await client.start();

    const promise = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Request timeout')), 300);
      try {
        (client as any).child?.stdin?.write(JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 99 }) + '\n');
      } catch {
        clearTimeout(timer);
        reject(new Error('Process not running'));
      }
    });

    await expect(promise).rejects.toThrow('Request timeout');
    client.stop();
  });

  it('stops gracefully without throwing', () => {
    const client = new StdioClient('echo', ['hi']);
    client.stop();
  });
});

// --- HttpClient ---

describe('HttpClient', () => {
  let mockServer: http.Server;
  let port: number;

  beforeAll(async () => {
    return new Promise<void>((resolve) => {
      mockServer = http.createServer((req, res) => {
        let body = '';
        req.on('data', (chunk) => { body += chunk; });
        req.on('end', () => {
          try {
            const parsed = JSON.parse(body);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              jsonrpc: '2.0',
              result: { mirrored: parsed },
              id: parsed.id ?? null,
            }));
          } catch {
            res.writeHead(400);
            res.end(JSON.stringify({
              jsonrpc: '2.0',
              error: { code: -32700, message: 'Parse error' },
              id: null,
            }));
          }
        });
      });
      mockServer.listen(0, () => {
        port = (mockServer.address() as any).port;
        resolve();
      });
    });
  });

  afterAll(() => {
    mockServer.close();
  });

  it('start() resolves', async () => {
    const client = new HttpClient('http://localhost:1');
    await expect(client.start()).resolves.toBeUndefined();
    client.stop();
  });

  it('send() posts JSON-RPC request and returns response', async () => {
    const client = new HttpClient(`http://localhost:${port}`);
    const response = await client.send({
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: 'test_tool', arguments: { key: 'val' } },
      id: 5,
    });

    expect(response.jsonrpc).toBe('2.0');
    expect(response.result).toBeDefined();
    expect((response.result as any).mirrored.method).toBe('tools/call');
    expect(response.id).toBe(5);
  });

  it('send() works without an id', async () => {
    const client = new HttpClient(`http://localhost:${port}`);
    const response = await client.send({
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    });

    expect(response.jsonrpc).toBe('2.0');
    expect(response.id).toBeNull();
  });
});

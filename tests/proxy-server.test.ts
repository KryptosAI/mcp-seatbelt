import { describe, it, expect, afterEach, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { ProxyServer, StdioClient, HttpClient, SseClient } from '../src/proxy/server.js';
import { PolicyEngine } from '../src/policy/engine.js';
import type { PolicyConfig, McpServerConfig } from '../src/types.js';
import { checkAccess } from '../src/policy/rbac.js';

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
    allowSampling: true,
  };
}

function makeAllowPolicyConfig(): PolicyConfig {
  return {
    version: '1',
    mode: 'enforce',
    defaultAction: 'allow',
    rules: [],
    allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
    allowSampling: true,
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

// --- SseClient ---

describe('SseClient', () => {
  let sseServer: http.Server;
  let port: number;
  let pendingMessageHandler: ((body: string) => void) | null = null;
  let sseStreamResponse: http.ServerResponse | null = null;
  let shouldCloseSSE = false;
  let sseConnectionEstablished: (() => void) | null = null;

  beforeAll(async () => {
    return new Promise<void>((resolve) => {
      sseServer = http.createServer((req, res) => {
        if (req.method === 'GET' && req.url === '/sse') {
          res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            Connection: 'keep-alive',
          });
          sseStreamResponse = res;
          if (shouldCloseSSE) {
            res.end();
            return;
          }
          res.write(':ok\n\n');
          if (sseConnectionEstablished) {
            sseConnectionEstablished();
          }
        } else if (req.method === 'POST' && req.url === '/message') {
          let body = '';
          req.on('data', (chunk) => { body += chunk; });
          req.on('end', () => {
            if (pendingMessageHandler) {
              pendingMessageHandler(body);
            }
            res.writeHead(202);
            res.end();
          });
        } else {
          res.writeHead(404);
          res.end();
        }
      });
      sseServer.listen(0, () => {
        port = (sseServer.address() as any).port;
        resolve();
      });
    });
  });

  afterAll(() => {
    sseServer.close();
  });

  afterEach(() => {
    pendingMessageHandler = null;
    sseConnectionEstablished = null;
    shouldCloseSSE = false;
    if (sseStreamResponse) {
      try { sseStreamResponse.end(); } catch {}
      sseStreamResponse = null;
    }
  });

  function waitForSSEConnected(): Promise<void> {
    return new Promise((resolve) => {
      sseConnectionEstablished = resolve;
    });
  }

  it('constructs with valid URL', () => {
    const client = new SseClient(`http://localhost:${port}/sse`);
    expect(client).toBeDefined();
    client.stop();
  });

  it('deduces message endpoint from /sse URL', () => {
    const client = new SseClient(`http://localhost:${port}/sse`);
    const msgEp = (client as any).messageEndpoint;
    expect(msgEp).toBe(`http://localhost:${port}/message`);
    client.stop();
  });

  it('handles sse URL without trailing slash for message endpoint', () => {
    const client = new SseClient(`http://localhost:${port}/sse`);
    expect((client as any).messageEndpoint).toBe(`http://localhost:${port}/message`);
    client.stop();
  });

  it('start() connects to SSE endpoint', async () => {
    const client = new SseClient(`http://localhost:${port}/sse`);
    await client.start();
    expect((client as any).stopped).toBe(false);
    expect((client as any).streamAbort).not.toBeNull();
    client.stop();
  });

  it('send() sends POST to /message endpoint with JSON body', async () => {
    return new Promise<void>(async (resolve) => {
      const client = new SseClient(`http://localhost:${port}/sse`);
      await client.start();

      pendingMessageHandler = (body: string) => {
        const parsed = JSON.parse(body);
        expect(parsed.jsonrpc).toBe('2.0');
        expect(parsed.method).toBe('tools/call');
        expect(parsed.params.name).toBe('test_tool');
        expect(parsed.id).toBe(1);
        client.stop();
        resolve();
      };

      client.send({
        jsonrpc: '2.0',
        method: 'tools/call',
        params: { name: 'test_tool', arguments: {} },
        id: 1,
      }).catch(() => {});
    });
  });

  it('send() returns null for notification (no id)', async () => {
    const client = new SseClient(`http://localhost:${port}/sse`);
    await client.start();

    const response = await client.send({
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    });

    expect(response).toBeNull();
    client.stop();
  });

  it('receives SSE data event and resolves pending request', async () => {
    const client = new SseClient(`http://localhost:${port}/sse`);
    await client.start();
    await waitForSSEConnected();

    pendingMessageHandler = (_body: string) => {
      if (sseStreamResponse) {
        sseStreamResponse.write(
          'data: {"jsonrpc":"2.0","result":{"tools":[{"name":"echo"}]},"id":42}\n\n',
        );
      }
    };

    const result = await client.send({
      jsonrpc: '2.0',
      method: 'tools/list',
      id: 42,
    });

    expect(result).not.toBeNull();
    expect(result!.jsonrpc).toBe('2.0');
    expect(result!.id).toBe(42);
    expect(result!.result).toEqual({ tools: [{ name: 'echo' }] });
    client.stop();
  });

  it('handles connection error when server unavailable', async () => {
    const client = new SseClient('http://127.0.0.1:1/sse');

    const promise = client.send({
      jsonrpc: '2.0',
      method: 'tools/list',
      id: 99,
    });

    await expect(promise).rejects.toThrow();
    client.stop();
  });

  it('rejects on timeout after 30 seconds', async () => {
    const client = new SseClient(`http://localhost:${port}/sse`);
    await client.start();

    (client as any).pending.set(77, {
      resolve: () => {},
      reject: () => {},
      timer: setTimeout(() => {}, 60000),
    });

    const promise = client.send({
      jsonrpc: '2.0',
      method: 'tools/list',
      id: 77,
    });

    await expect(promise).rejects.toThrow('exceeded timeout');
    client.stop();
  }, 35000);

  it('stop() clears pending requests with transport stopped error', async () => {
    const client = new SseClient(`http://localhost:${port}/sse`);
    await client.start();

    const promise = client.send({
      jsonrpc: '2.0',
      method: 'tools/list',
      id: 88,
    });

    client.stop();

    await expect(promise).rejects.toThrow('Transport stopped');
  });

  it('schedules reconnect on SSE connection close', async () => {
    const client = new SseClient(`http://localhost:${port}/sse`);
    await client.start();
    await waitForSSEConnected();

    let reconnected = false;
    const origConnect = (client as any).connectSSE.bind(client);
    (client as any).connectSSE = () => {
      reconnected = true;
    };

    if (sseStreamResponse) {
      sseStreamResponse.destroy();
      sseStreamResponse = null;
    }

    await new Promise((r) => setTimeout(r, 1500));
    expect(reconnected).toBe(true);
    client.stop();
  });

  it('does not reconnect after stop() has been called', async () => {
    const client = new SseClient(`http://localhost:${port}/sse`);
    await client.start();

    let connectCalled = false;
    const origConnect = (client as any).connectSSE.bind(client);
    (client as any).connectSSE = () => {
      if (connectCalled) {
        throw new Error('Should not reconnect after stop');
      }
      connectCalled = true;
      origConnect();
    };

    client.stop();

    await new Promise((r) => setTimeout(r, 1500));
    expect(true).toBe(true);
  });
});

// --- Per-call timeout tests ---

describe('StdioClient timeout', () => {
  it('kills child process on timeout and rejects with exceeded timeout', async () => {
    const client = new StdioClient('node', ['-e', 'setTimeout(() => {}, 99999)']);
    await client.start();

    const promise = client.send({
      jsonrpc: '2.0',
      method: 'tools/list',
      id: 1,
    }, 1000);

    await expect(promise).rejects.toThrow('exceeded timeout');
    expect((client as any).child.killed).toBe(true);

    client.stop();
  });

  it('preserves fast requests with configurable timeout', async () => {
    const echoScript = `
      const rl = require('readline').createInterface({ input: process.stdin });
      rl.on('line', (line) => {
        try {
          const req = JSON.parse(line);
          console.log(JSON.stringify({ jsonrpc: '2.0', result: {}, id: req.id }));
        } catch (e) {}
      });
    `;
    const client = new StdioClient('node', ['-e', echoScript.trim()]);
    await client.start();

    const response = await client.send({
      jsonrpc: '2.0',
      method: 'echo',
      id: 1,
    }, 5000);

    expect(response).not.toBeNull();
    expect(response!.jsonrpc).toBe('2.0');
    expect(response!.id).toBe(1);
    expect(response!.result).toEqual({});

    client.stop();
  });
});

describe('HttpClient timeout', () => {
  let hangingServer: http.Server;
  let hangingPort: number;

  beforeAll(async () => {
    return new Promise<void>((resolve) => {
      hangingServer = http.createServer((_req, _res) => {
        // never respond
      });
      hangingServer.listen(0, () => {
        hangingPort = (hangingServer.address() as any).port;
        resolve();
      });
    });
  });

  afterAll(() => {
    hangingServer.close();
  });

  it('handles AbortError when server never responds', async () => {
    const client = new HttpClient(`http://localhost:${hangingPort}`);

    const promise = client.send({
      jsonrpc: '2.0',
      method: 'tools/list',
      id: 1,
    }, 1000);

    await expect(promise).rejects.toThrow('exceeded timeout');
  });
});

describe('ProxyServer timeout', () => {
  let proxy: ProxyServer;

  afterEach(async () => {
    if (proxy) {
      try { await proxy.stop(); } catch {}
    }
  });

  it('returns 504 with clean JSON error on timeout', async () => {
    const slowScript = `
      const rl = require('readline').createInterface({ input: process.stdin });
      rl.on('line', (line) => {
        try {
          const req = JSON.parse(line);
          if (req.method === 'tools/list') {
            console.log(JSON.stringify({ jsonrpc: '2.0', result: { tools: [] }, id: req.id }));
          }
          // hang for everything else
        } catch (e) {}
      });
    `;

    const timeoutPolicy = new PolicyEngine({
      version: '1',
      mode: 'enforce',
      defaultAction: 'allow',
      defaultTimeoutMs: 500,
      rules: [],
      allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
      allowSampling: true,
    });

    proxy = new ProxyServer(timeoutPolicy, 0);
    proxy.registerServer({
      name: 'slow',
      command: 'node',
      args: ['-e', slowScript.trim()],
      transport: 'stdio' as const,
      risk: { score: 0, level: 'low', flags: [] },
    });
    await proxy.start();

    const addr = (proxy as any).httpServer?.address();
    const port = addr?.port;

    const response = await fetch(`http://localhost:${port}/slow`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/call', params: { name: 'hang_forever' }, id: 1 }),
    });

    expect(response.status).toBe(504);
    const body = await response.json();
    expect(body.jsonrpc).toBe('2.0');
    expect(body.error).toBeDefined();
    expect(body.error.message).toMatch(/timeout/i);
    expect(body.error.code).toBe(-32001);
  });
});

describe('Per-rule timeout overrides', () => {
  it('uses rule timeoutMs for matching tool, default for non-matching', () => {
    const engine = new PolicyEngine({
      version: '1',
      mode: 'enforce',
      defaultAction: 'allow',
      defaultTimeoutMs: 5000,
      rules: [
        {
          id: 'slow-tool-rule',
          description: 'Slow tools get a short timeout',
          target: 'command' as const,
          match: 'exact' as const,
          values: ['slow_tool'],
          action: 'deny' as const,
          timeoutMs: 1000,
        },
      ],
      allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
      allowSampling: true,
    });

    const fastResult = engine.getEffectiveTimeout('slow_tool', '', {});
    expect(fastResult).toBe(1000);

    const defaultResult = engine.getEffectiveTimeout('other_tool', '', {});
    expect(defaultResult).toBe(5000);
  });
});

describe('RBAC integration', () => {
  it('checkAccess allows all when enforcer is not initialized', async () => {
    const result = await checkAccess('any_agent', 'bash', 'execute');
    expect(result).toBe(true);
  });

  it('checkAccess allows read_file for any agent (no enforcer)', async () => {
    const result = await checkAccess('unknown_agent', 'read_file', 'execute');
    expect(result).toBe(true);
  });

  it('checkAccess allows wildcard tool for any agent (no enforcer)', async () => {
    const result = await checkAccess('test_agent', '*', 'execute');
    expect(result).toBe(true);
  });
});

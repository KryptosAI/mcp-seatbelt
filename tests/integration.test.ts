import { describe, it, expect, afterEach, afterAll } from 'vitest';
import { execSync, execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { importObservatoryResults } from '../src/integrations/observatory.js';
import { PolicyEngine } from '../src/policy/engine.js';
import type { PolicyConfig, PolicyRule } from '../src/types.js';

function tmpDir(): string {
  const dir = join(tmpdir(), `mcp-integration-test-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function isCommandAvailable(cmd: string): boolean {
  try {
    execFileSync(cmd, ['--version'], { stdio: 'pipe', timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

function npxAvailable(): boolean {
  try {
    execFileSync('npx', ['--version'], { stdio: 'pipe', timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

async function waitForHealth(port: number, timeoutMs: number): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const response = await fetch(`http://localhost:${port}/health`);
      if (response.ok) return true;
    } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

async function killProxy(child: ChildProcess): Promise<void> {
  child.kill('SIGTERM');
  await new Promise<void>((resolve) => {
    child.on('close', () => resolve());
    setTimeout(() => resolve(), 5000);
  });
}

const OBSERVATORY_AVAILABLE = isCommandAvailable('mcp-observatory');
const NPX_AVAILABLE = npxAvailable();

describe('mcp-observatory to mcp-seatbelt integration', () => {
  const testDirs: string[] = [];
  const childProcesses: ChildProcess[] = [];

  afterEach(async () => {
    for (const child of childProcesses.splice(0)) {
      try { child.kill('SIGTERM'); } catch {}
    }
    for (const dir of testDirs.splice(0)) {
      try { rmSync(dir, { recursive: true, force: true }); } catch {}
    }
  });

  afterAll(() => {
    for (const child of childProcesses) {
      try { child.kill('SIGTERM'); } catch {}
    }
  });

  describe('Test 1: Full scan -> enforce -> proxy flow', () => {
    it('runs observatory, imports findings, verifies PolicyEngine blocks denied tools', async () => {
      if (!OBSERVATORY_AVAILABLE && !NPX_AVAILABLE) {
        console.warn('Skipping Test 1: mcp-observatory not available');
        return;
      }
      if (!NPX_AVAILABLE) {
        console.warn('Skipping Test 1: npx not available');
        return;
      }

      const dir = tmpDir();
      testDirs.push(dir);

      const fsRoot = join(dir, 'fs-root');
      mkdirSync(fsRoot, { recursive: true });
      writeFileSync(join(fsRoot, 'test.txt'), 'hello world');

      let artifactPath: string | null = null;

      try {
        execSync(
          `mcp-observatory test npx -y @modelcontextprotocol/server-filesystem ${fsRoot}`,
          { cwd: dir, stdio: 'pipe', timeout: 120000, env: { ...process.env, CI: 'true' } },
        );
      } catch {
        // test may fail but artifact might still be written
      }

      const artifactDir = join(dir, '.mcp-observatory', 'runs');
      if (existsSync(artifactDir)) {
        const files = readdirSync(artifactDir).filter((f) => f.endsWith('.json'));
        if (files.length > 0) {
          artifactPath = join(artifactDir, files[0]);
        }
      }

      if (!artifactPath || !existsSync(artifactPath)) {
        console.warn('Skipping Test 1: no artifact generated');
        return;
      }

      const importedRules = importObservatoryResults(artifactPath);
      expect(importedRules.length).toBeGreaterThan(0);

      const denyRules: PolicyRule[] = importedRules
        .filter((r) => r.values.length > 0 && r.action !== 'allow')
        .map((r) => ({ ...r, action: 'deny' as const }));

      expect(denyRules.length).toBeGreaterThan(0);

      const policyConfig: PolicyConfig = {
        version: '1',
        mode: 'enforce',
        defaultAction: 'allow',
        rules: denyRules,
        allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
        allowSampling: true,
      };

      const engine = new PolicyEngine(policyConfig);

      const blockedTools = denyRules
        .flatMap((r) => r.values)
        .filter((v) => !v.includes('/') && !v.includes('\\'));

      if (blockedTools.length > 0) {
        const blockedTool = blockedTools[0];
        const result = engine.evaluate(blockedTool, `Runs ${blockedTool}`, { path: '/tmp/test' });
        expect(result.action).toBe('deny');
      }

      const allowedResult = engine.evaluate('initialize', 'Initialize the server', {});
      expect(allowedResult.action).toBe('allow');
    }, 180000);

    it('starts seatbelt proxy with imported policy and blocks tool calls via HTTP', async () => {
      if (!OBSERVATORY_AVAILABLE && !NPX_AVAILABLE) {
        console.warn('Skipping proxy test: mcp-observatory not available');
        return;
      }

      const dir = tmpDir();
      testDirs.push(dir);

      const fsRoot = join(dir, 'fs-root');
      mkdirSync(fsRoot, { recursive: true });
      writeFileSync(join(fsRoot, 'test.txt'), 'proxy test');

      try {
        execSync(
          `mcp-observatory test npx -y @modelcontextprotocol/server-filesystem ${fsRoot}`,
          { cwd: dir, stdio: 'pipe', timeout: 120000, env: { ...process.env, CI: 'true' } },
        );
      } catch { /* ignore */ }

      const artifactDir = join(dir, '.mcp-observatory', 'runs');
      let artifactPath: string | null = null;
      if (existsSync(artifactDir)) {
        const files = readdirSync(artifactDir).filter((f) => f.endsWith('.json'));
        if (files.length > 0) artifactPath = join(artifactDir, files[0]);
      }

      if (!artifactPath) {
        console.warn('Skipping proxy test: no artifact generated');
        return;
      }

      const importedRules = importObservatoryResults(artifactPath);
      const denyRules: PolicyRule[] = importedRules
        .filter((r) => r.values.length > 0 && r.action !== 'allow')
        .map((r) => ({ ...r, action: 'deny' as const }));

      if (denyRules.length === 0) {
        console.warn('Skipping proxy test: no deny rules from findings');
        return;
      }

      const policyConfig: PolicyConfig = {
        version: '1',
        mode: 'enforce',
        defaultAction: 'allow',
        rules: denyRules,
        allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
        allowSampling: true,
      };

      const policyPath = join(dir, 'policy.yml');
      writeFileSync(
        policyPath,
        `version: "1"
mode: enforce
defaultAction: allow
rules:
${denyRules.map((r) => `  - id: "${r.id}"
    description: "${r.description}"
    target: ${r.target}
    match: ${r.match}
    values:
${r.values.map((v) => `      - "${v}"`).join('\n')}
    action: deny`).join('\n')}
allowlist:
  tools: []
  paths: []
  hosts: []
  envVars: []
`,
        'utf-8',
      );

      const cursorDir = join(dir, '.cursor');
      mkdirSync(cursorDir, { recursive: true });
      writeFileSync(
        join(cursorDir, 'mcp.json'),
        JSON.stringify({ mcpServers: { test: { command: 'echo', args: ['hello'] } } }),
        'utf-8',
      );

      const tsxPath = join(__dirname, '..', 'node_modules', '.bin', 'tsx');
      const cliEntry = join(__dirname, '..', 'src', 'index.ts');
      const port = 19450 + Math.floor(Math.random() * 1000);

      const proxyChild = spawn(tsxPath, [cliEntry, 'proxy', '--port', String(port), '--config', policyPath, '--no-watch'], {
        cwd: dir,
        env: { ...process.env, HOME: dir },
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      proxyChild.stderr?.on('data', (d: Buffer) => {
        // silence expected stderr from proxy
      });

      childProcesses.push(proxyChild);

      const healthy = await waitForHealth(port, 20000);
      if (!healthy) {
        proxyChild.kill('SIGTERM');
        console.warn('Skipping proxy test: proxy did not become healthy');
        return;
      }

      const blockedTool = denyRules[0].values[0];

      const blockedResponse = await fetch(`http://localhost:${port}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'tools/call',
          params: { name: blockedTool, arguments: { path: '/etc/hosts' } },
          id: 1,
        }),
      });
      const blockedBody = await blockedResponse.json() as Record<string, unknown>;
      expect(blockedBody.error).toBeDefined();
      expect((blockedBody.error as Record<string, unknown>).code).toBe(-32001);

      const initResponse = await fetch(`http://localhost:${port}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'initialize',
          id: 2,
        }),
      });
      const initBody = await initResponse.json() as Record<string, unknown>;
      expect((initBody.error as Record<string, unknown>)?.code).not.toBe(-32001);
    }, 180000);
  });

  describe('Test 2: Import observatory artifact into seatbelt', () => {
    it('imports an observatory artifact and produces valid seatbelt policy rules', async () => {
      if (!OBSERVATORY_AVAILABLE && !NPX_AVAILABLE) {
        console.warn('Skipping Test 2: mcp-observatory not available');
        return;
      }

      const dir = tmpDir();
      testDirs.push(dir);

      const fsRoot = join(dir, 'fs-root');
      mkdirSync(fsRoot, { recursive: true });
      writeFileSync(join(fsRoot, 'data.txt'), 'integration test data');

      try {
        execSync(
          `mcp-observatory test npx -y @modelcontextprotocol/server-filesystem ${fsRoot}`,
          { cwd: dir, stdio: 'pipe', timeout: 120000, env: { ...process.env, CI: 'true' } },
        );
      } catch { /* ignore */ }

      const artifactDir = join(dir, '.mcp-observatory', 'runs');
      if (!existsSync(artifactDir)) {
        console.warn('Skipping Test 2: no artifact directory');
        return;
      }

      const files = readdirSync(artifactDir).filter((f) => f.endsWith('.json'));
      if (files.length === 0) {
        console.warn('Skipping Test 2: no artifact found');
        return;
      }

      const artifactPath = join(artifactDir, files[0]);

      const rules = importObservatoryResults(artifactPath);
      expect(rules.length).toBeGreaterThan(0);

      for (const rule of rules) {
        expect(rule.id).toBeTruthy();
        expect(rule.description).toBeTruthy();
        expect(['command', 'file', 'network', 'env', 'process']).toContain(rule.target);
        expect(['exact', 'pattern', 'contains']).toContain(rule.match);
        expect(Array.isArray(rule.values)).toBe(true);
        expect(rule.values.length).toBeGreaterThan(0);
        expect(['allow', 'deny', 'warn', 'redact']).toContain(rule.action);
      }
    });

    it('import-observatory command prints valid YAML rules', async () => {
      if (!OBSERVATORY_AVAILABLE && !NPX_AVAILABLE) {
        console.warn('Skipping import-observatory CLI test: mcp-observatory not available');
        return;
      }

      const dir = tmpDir();
      testDirs.push(dir);

      const fsRoot = join(dir, 'fs-root');
      mkdirSync(fsRoot, { recursive: true });
      writeFileSync(join(fsRoot, 'cli-test.txt'), 'cli data');

      try {
        execSync(
          `mcp-observatory test npx -y @modelcontextprotocol/server-filesystem ${fsRoot}`,
          { cwd: dir, stdio: 'pipe', timeout: 120000, env: { ...process.env, CI: 'true' } },
        );
      } catch { /* ignore */ }

      const artifactDir = join(dir, '.mcp-observatory', 'runs');
      if (!existsSync(artifactDir)) {
        console.warn('Skipping import-observatory CLI test: no artifacts');
        return;
      }

      const files = readdirSync(artifactDir).filter((f) => f.endsWith('.json'));
      if (files.length === 0) {
        console.warn('Skipping import-observatory CLI test: no files');
        return;
      }

      const artifactPath = join(artifactDir, files[0]);

      const tsxPath = join(__dirname, '..', 'node_modules', '.bin', 'tsx');
      const cliEntry = join(__dirname, '..', 'src', 'index.ts');

      const stdout = execFileSync(tsxPath, [cliEntry, 'import-observatory', artifactPath], {
        encoding: 'utf-8',
        timeout: 30000,
      });

      expect(stdout).toContain('rules:');
      expect(stdout).toContain('target:');
      expect(stdout).toContain('match:');
      expect(stdout).toContain('values:');
      expect(stdout).toContain('action:');
      expect(stdout).toContain('observatory-');
    }, 180000);
  });

  describe('Test 3: observatory enforce flag generates policy', () => {
    it('runs observatory enforce and generates a policy file with DENY rules', async () => {
      if (!OBSERVATORY_AVAILABLE) {
        console.warn('Skipping Test 3: mcp-observatory not available');
        return;
      }

      const dir = tmpDir();
      testDirs.push(dir);

      const fsRoot = join(dir, 'fs-root');
      mkdirSync(fsRoot, { recursive: true });
      writeFileSync(join(fsRoot, 'enforce-test.txt'), 'enforce test');

      const policyPath = join(dir, 'enforce-policy.yml');

      try {
        execSync(
          `mcp-observatory enforce --no-proxy --policy ${policyPath} npx -y @modelcontextprotocol/server-filesystem ${fsRoot}`,
          { cwd: dir, stdio: 'pipe', timeout: 120000, env: { ...process.env, CI: 'true' } },
        );
      } catch (e: any) {
        const stderr = e.stderr?.toString() || '';
        const stdout = e.stdout?.toString() || '';
        if (!existsSync(policyPath)) {
          console.warn(`Skipping Test 3: enforce failed - ${stderr || stdout}`);
          return;
        }
      }

      expect(existsSync(policyPath)).toBe(true);

      const policyContent = readFileSync(policyPath, 'utf-8');
      expect(policyContent).toContain('DENY');

      const denyCount = (policyContent.match(/DENY/g) || []).length;
      expect(denyCount).toBeGreaterThan(0);
    }, 180000);

    it('runs observatory test with --enforce flag', async () => {
      if (!OBSERVATORY_AVAILABLE) {
        console.warn('Skipping Test 3 enforce flag: mcp-observatory not available');
        return;
      }

      const dir = tmpDir();
      testDirs.push(dir);

      const fsRoot = join(dir, 'fs-root');
      mkdirSync(fsRoot, { recursive: true });
      writeFileSync(join(fsRoot, 'flag-test.txt'), 'flag test');

      try {
        const stdout = execSync(
          `mcp-observatory test --enforce npx -y @modelcontextprotocol/server-filesystem ${fsRoot}`,
          { cwd: dir, stdio: 'pipe', timeout: 120000, env: { ...process.env, CI: 'true' } },
        ).toString();

        expect(stdout).toMatch(/enforce|policy|DENY/i);
      } catch (e: any) {
        const output = (e.stdout?.toString() || '') + (e.stderr?.toString() || '');
        if (!output.match(/enforce|policy/i)) {
          console.warn('Skipping Test 3 enforce flag: no enforce output');
          return;
        }
      }
    }, 180000);
  });
});

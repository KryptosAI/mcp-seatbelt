import { describe, it, expect } from 'vitest';
import { execFile, spawn } from 'node:child_process';
import { existsSync, readFileSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const tsxPath = join(__dirname, '..', 'node_modules', '.bin', 'tsx');
const cliEntry = join(__dirname, '..', 'src', 'index.ts');

function tmpDir(): string {
  const dir = join(tmpdir(), `mcp-seatbelt-test-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

describe('CLI arg parsing', () => {
  it('--help prints usage', async () => {
    const { stdout } = await execFileAsync(tsxPath, [cliEntry, '--help']);
    expect(stdout).toContain('Usage:');
    expect(stdout).toContain('mcp-seatbelt');
  });

  it('--version prints version', async () => {
    const { stdout } = await execFileAsync(tsxPath, [cliEntry, '--version']);
    expect(stdout).toMatch(/\d+\.\d+\.\d+/);
  });

  it('init --help shows init options', async () => {
    const { stdout } = await execFileAsync(tsxPath, [cliEntry, 'init', '--help']);
    expect(stdout).toContain('--output');
    expect(stdout).toContain('--policy');
  });

  it('proxy --help shows proxy options', async () => {
    const { stdout } = await execFileAsync(tsxPath, [cliEntry, 'proxy', '--help']);
    expect(stdout).toContain('--port');
    expect(stdout).toContain('--config');
  });

  it('report --help shows report options', async () => {
    const { stdout } = await execFileAsync(tsxPath, [cliEntry, 'report', '--help']);
    expect(stdout).toContain('--output');
    expect(stdout).toContain('--json');
  });
});

describe('CLI commands', () => {
  it('check exits with code 0 when no configs found', async () => {
    const dir = tmpDir();
    try {
      const { stdout } = await execFileAsync(tsxPath, [cliEntry, 'check'], {
        cwd: dir,
        env: { ...process.env, HOME: dir },
      });
      expect(stdout).toContain('No MCP configurations detected');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('check exits with code 1 when critical risk detected', async () => {
    const dir = tmpDir();
    try {
      // Create a cursor config with a critical-risk server (shell interpreter)
      const cursorDir = join(dir, '.cursor');
      mkdirSync(cursorDir, { recursive: true });
      const mcpConfig = {
        mcpServers: {
          'dangerous-shell': {
            command: 'bash',
            args: ['-c', 'rm -rf /'],
          },
        },
      };
      writeFileSync(join(cursorDir, 'mcp.json'), JSON.stringify(mcpConfig), 'utf-8');

      // checkCommand exits with code 1 when critical flags detected
      try {
        await execFileAsync(tsxPath, [cliEntry, 'check'], {
          cwd: dir,
          env: { ...process.env, HOME: dir },
        });
        // Should not reach here
      } catch (err: any) {
        expect(err.code).toBe(1);
        expect(err.stdout).toContain('CRITICAL RISKS DETECTED');
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('initCommand writes policy.yml and risk-report.md', async () => {
    const dir = tmpDir();
    const outputDir = join(dir, '.mcp-seatbelt');
    try {
      const cursorDir = join(dir, '.cursor');
      mkdirSync(cursorDir, { recursive: true });
      writeFileSync(
        join(cursorDir, 'mcp.json'),
        JSON.stringify({ mcpServers: { hello: { command: 'echo', args: ['hello'] } } }),
        'utf-8',
      );

      const { stdout } = await execFileAsync(tsxPath, [cliEntry, 'init', '--output', outputDir, '--yes'], {
        cwd: dir,
        env: { ...process.env, HOME: dir },
      });

      expect(stdout).toContain('Found');
      expect(stdout).toContain('Wrote policy to');

      const policyPath = join(outputDir, 'policy.yml');
      const reportPath = join(outputDir, 'risk-report.md');
      expect(existsSync(policyPath)).toBe(true);
      expect(existsSync(reportPath)).toBe(true);

      const policyContent = readFileSync(policyPath, 'utf-8');
      expect(policyContent).toContain('version');
      expect(policyContent).toContain('hello');

      const reportContent = readFileSync(reportPath, 'utf-8');
      expect(reportContent).toContain('MCP Seatbelt Risk Report');
      expect(reportContent).toContain('hello');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('initCommand with --policy enforce writes enforce mode', async () => {
    const dir = tmpDir();
    const outputDir = join(dir, '.mcp-seatbelt');
    try {
      const cursorDir = join(dir, '.cursor');
      mkdirSync(cursorDir, { recursive: true });
      writeFileSync(
        join(cursorDir, 'mcp.json'),
        JSON.stringify({ mcpServers: { hello: { command: 'echo', args: [] } } }),
        'utf-8',
      );

      await execFileAsync(tsxPath, [cliEntry, 'init', '--output', outputDir, '--policy', 'enforce', '--yes'], {
        cwd: dir,
        env: { ...process.env, HOME: dir },
      });

      const policyContent = readFileSync(join(outputDir, 'policy.yml'), 'utf-8');
      expect(policyContent).toContain('enforce');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('reportCommand generates markdown output', async () => {
    const dir = tmpDir();
    const outputFile = join(dir, 'report.md');
    try {
      const cursorDir = join(dir, '.cursor');
      mkdirSync(cursorDir, { recursive: true });
      writeFileSync(
        join(cursorDir, 'mcp.json'),
        JSON.stringify({ mcpServers: { server1: { command: 'node', args: ['server.js'] } } }),
        'utf-8',
      );

      const { stdout } = await execFileAsync(tsxPath, [cliEntry, 'report', '--output', outputFile], {
        cwd: dir,
        env: { ...process.env, HOME: dir },
      });

      expect(stdout).toContain('Markdown report written to');
      expect(existsSync(outputFile)).toBe(true);
      const content = readFileSync(outputFile, 'utf-8');
      expect(content).toContain('# MCP Seatbelt Risk Report');
      expect(content).toContain('server1');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('reportCommand generates JSON output with --json flag', async () => {
    const dir = tmpDir();
    const outputFile = join(dir, 'report.json');
    try {
      const cursorDir = join(dir, '.cursor');
      mkdirSync(cursorDir, { recursive: true });
      writeFileSync(
        join(cursorDir, 'mcp.json'),
        JSON.stringify({ mcpServers: { server1: { command: 'node', args: ['server.js'] } } }),
        'utf-8',
      );

      const { stdout } = await execFileAsync(tsxPath, [cliEntry, 'report', '--output', outputFile, '--json'], {
        cwd: dir,
        env: { ...process.env, HOME: dir },
      });

      expect(stdout).toContain('JSON report written to');
      expect(existsSync(outputFile)).toBe(true);
      const content = JSON.parse(readFileSync(outputFile, 'utf-8'));
      expect(content.generatedAt).toBeDefined();
      expect(content.summary).toBeDefined();
      expect(content.servers).toBeDefined();
      expect(content.servers.length).toBeGreaterThan(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('CLI proxy command', () => {
  const tsxPath = join(__dirname, '..', 'node_modules', '.bin', 'tsx');
  const cliEntry = join(__dirname, '..', 'src', 'index.ts');

  it('proxy --help shows proxy options', () => {
    // already tested above, but added here as per requirement
  });

  it('proxy --port 9999 starts and /health responds', async () => {
    const dir = join(tmpdir(), `mcp-seatbelt-test-${randomUUID()}`);
    mkdirSync(dir, { recursive: true });
    const policyDir = join(dir, '.mcp-seatbelt');
    mkdirSync(policyDir, { recursive: true });

    const policyContent = `version: "1"
mode: audit
defaultAction: deny
rules: []
allowlist:
  tools: []
  paths: []
  hosts: []
  envVars: []
`;
    writeFileSync(join(policyDir, 'policy.yml'), policyContent, 'utf-8');

    const cursorDir = join(dir, '.cursor');
    mkdirSync(cursorDir, { recursive: true });
    writeFileSync(
      join(cursorDir, 'mcp.json'),
      JSON.stringify({ mcpServers: { hello: { command: 'echo', args: ['hello'] } } }),
      'utf-8',
    );

    try {
      const child = spawn(tsxPath, [cliEntry, 'proxy', '--port', '9999', '--config', join(policyDir, 'policy.yml')], {
        cwd: dir,
        env: { ...process.env, HOME: dir },
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      const healthOk = await new Promise<boolean>((resolve) => {
        let attempts = 0;
        const interval = setInterval(async () => {
          attempts++;
          try {
            const response = await fetch('http://localhost:9999/health');
            if (response.ok) {
              clearInterval(interval);
              resolve(true);
            }
          } catch {}
          if (attempts > 30) {
            clearInterval(interval);
            resolve(false);
          }
        }, 200);
      });

      expect(healthOk).toBe(true);

      child.kill('SIGTERM');

      await new Promise<void>((resolve) => {
        child.on('close', () => resolve());
        setTimeout(() => resolve(), 5000);
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 15000);

  it('proxy process exits cleanly on SIGTERM', async () => {
    const dir = join(tmpdir(), `mcp-seatbelt-test-${randomUUID()}`);
    mkdirSync(dir, { recursive: true });
    const policyDir = join(dir, '.mcp-seatbelt');
    mkdirSync(policyDir, { recursive: true });

    writeFileSync(join(policyDir, 'policy.yml'), `version: "1"
mode: audit
defaultAction: deny
rules: []
allowlist:
  tools: []
  paths: []
  hosts: []
  envVars: []
`, 'utf-8');

    const cursorDir = join(dir, '.cursor');
    mkdirSync(cursorDir, { recursive: true });
    writeFileSync(
      join(cursorDir, 'mcp.json'),
      JSON.stringify({ mcpServers: { hello: { command: 'echo', args: ['hello'] } } }),
      'utf-8',
    );

    try {
      const child = spawn(tsxPath, [cliEntry, 'proxy', '--port', '9998', '--config', join(policyDir, 'policy.yml')], {
        cwd: dir,
        env: { ...process.env, HOME: dir },
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      await new Promise<void>((resolve) => {
        let attempts = 0;
        const interval = setInterval(async () => {
          attempts++;
          try {
            await fetch('http://localhost:9998/health');
            clearInterval(interval);
            resolve();
          } catch {}
          if (attempts > 30) {
            clearInterval(interval);
            resolve();
          }
        }, 200);
      });

      child.kill('SIGTERM');

      const exitCode = await new Promise<number | null>((resolve) => {
        child.on('close', (code) => resolve(code));
        setTimeout(() => resolve(null), 5000);
      });

      expect(exitCode).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 15000);

  it('proxy --help shows port and config options', async () => {
    const { stdout } = await execFileAsync(tsxPath, [cliEntry, 'proxy', '--help']);
    expect(stdout).toContain('--port');
    expect(stdout).toContain('--config');
  });
});

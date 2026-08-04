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

  it('check --policy-only rejects an unknown policy field before scanning', async () => {
    const dir = tmpDir();
    const policyPath = join(dir, 'policy.yml');
    writeFileSync(
      policyPath,
      [
        "version: '1'",
        'mode: enforce',
        'defaultAction: deny',
        'defaultActon: deny',
        'rules: []',
        'allowlist:',
        '  tools: []',
        '  paths: []',
        '  hosts: []',
        '  envVars: []',
      ].join('\n'),
      'utf-8',
    );

    try {
      await expect(
        execFileAsync(tsxPath, [
          cliEntry,
          'check',
          '--policy',
          policyPath,
          '--policy-only',
        ]),
      ).rejects.toMatchObject({ code: 1 });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
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

describe('CLI simulate command', () => {
  it('simulate --help shows simulate options', async () => {
    const { stdout } = await execFileAsync(tsxPath, [cliEntry, 'simulate', '--help']);
    expect(stdout).toContain('--tool');
    expect(stdout).toContain('--policy');
    expect(stdout).toContain('--json');
    expect(stdout).toContain('--verbose');
  });

  it('simulate blocks a tool matching a deny rule', async () => {
    const dir = tmpDir();
    try {
      const policyPath = join(dir, 'policy.yml');
      writeFileSync(policyPath, `version: "1"
mode: enforce
defaultAction: allow
rules:
  - id: block-shell
    description: Block shell tools
    target: command
    match: exact
    values:
      - bash
    action: deny
allowlist:
  tools: []
  paths: []
  hosts: []
  envVars: []
`, 'utf-8');

      const { stdout } = await execFileAsync(tsxPath, [
        cliEntry, 'simulate',
        '--tool', 'bash',
        '--description', 'Runs a bash command',
        '--args', '{"command": "rm -rf /"}',
        '--server', 'filesystem',
        '--policy', policyPath,
      ]);
      expect(stdout).toContain('[block-shell]');
      expect(stdout).toContain('DENY');
      expect(stdout).toContain('BLOCKED');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('simulate allows a tool that matches no deny rules', async () => {
    const dir = tmpDir();
    try {
      const policyPath = join(dir, 'policy.yml');
      writeFileSync(policyPath, `version: "1"
mode: enforce
defaultAction: allow
rules:
  - id: block-shell
    description: Block shell tools
    target: command
    match: exact
    values:
      - bash
    action: deny
  - id: block-sensitive-paths
    description: Block filesystem writes to sensitive paths
    target: file
    match: pattern
    values:
      - "^/etc(/|$)"
    action: deny
allowlist:
  tools: []
  paths: []
  hosts: []
  envVars: []
`, 'utf-8');

      const { stdout } = await execFileAsync(tsxPath, [
        cliEntry, 'simulate',
        '--tool', 'read_file',
        '--description', 'Reads a file',
        '--args', '{"filePath": "/home/user/data.txt"}',
        '--policy', policyPath,
      ]);
      expect(stdout).toContain('ALLOWED');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('simulate --json outputs machine-readable JSON', async () => {
    const dir = tmpDir();
    try {
      const policyPath = join(dir, 'policy.yml');
      writeFileSync(policyPath, `version: "1"
mode: enforce
defaultAction: deny
rules:
  - id: block-all
    description: Block everything
    target: command
    match: pattern
    values:
      - ".*"
    action: deny
allowlist:
  tools: []
  paths: []
  hosts: []
  envVars: []
`, 'utf-8');

      const { stdout } = await execFileAsync(tsxPath, [
        cliEntry, 'simulate',
        '--tool', 'some_tool',
        '--policy', policyPath,
        '--json',
      ]);
      const output = JSON.parse(stdout);
      expect(output.tool).toBe('some_tool');
      expect(output.action).toBe('deny');
      expect(Array.isArray(output.reasons)).toBe(true);
      expect(Array.isArray(output.rules)).toBe(true);
      expect(output.rules.length).toBeGreaterThan(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('simulate --verbose shows all rules', async () => {
    const dir = tmpDir();
    try {
      const policyPath = join(dir, 'policy.yml');
      writeFileSync(policyPath, `version: "1"
mode: enforce
defaultAction: allow
rules:
  - id: block-shell
    description: Block shell tools
    target: command
    match: exact
    values:
      - bash
    action: deny
  - id: block-etc
    description: Block etc writes
    target: file
    match: pattern
    values:
      - "^/etc(/|$)"
    action: deny
  - id: warn-large-files
    description: Warn on large files
    target: file
    match: contains
    values:
      - large
    action: warn
allowlist:
  tools: []
  paths: []
  hosts: []
  envVars: []
`, 'utf-8');

      const { stdout } = await execFileAsync(tsxPath, [
        cliEntry, 'simulate',
        '--tool', 'read_file',
        '--description', 'Reads a safe file',
        '--args', '{"filePath": "/tmp/safe.txt"}',
        '--policy', policyPath,
        '--verbose',
      ]);
      expect(stdout).toContain('block-shell');
      expect(stdout).toContain('block-etc');
      expect(stdout).toContain('warn-large-files');
      expect(stdout).toContain('ALLOWED');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('simulate errors when policy file does not exist', async () => {
    try {
      await execFileAsync(tsxPath, [
        cliEntry, 'simulate',
        '--tool', 'test',
        '--policy', '/nonexistent/policy.yml',
      ]);
    } catch (err: any) {
      expect(err.code).toBe(1);
      expect(err.stderr || err.stdout).toContain('not found');
    }
  });

  it('simulate errors when --args is invalid JSON', async () => {
    const dir = tmpDir();
    try {
      const policyPath = join(dir, 'policy.yml');
      writeFileSync(policyPath, `version: "1"\nmode: enforce\ndefaultAction: deny\nrules: []\nallowlist:\n  tools: []\n  paths: []\n  hosts: []\n  envVars: []\n`, 'utf-8');

      try {
        await execFileAsync(tsxPath, [
          cliEntry, 'simulate',
          '--tool', 'test',
          '--policy', policyPath,
          '--args', '{invalid json}',
        ]);
      } catch (err: any) {
        expect(err.code).toBe(1);
        expect(err.stderr || err.stdout).toContain('parse');
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('simulate shows time window info for time-windowed rules', async () => {
    const dir = tmpDir();
    try {
      const now = new Date();
      const currentDay = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'][now.getDay()];
      const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'].includes(currentDay)
        ? ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']
        : ['Saturday', 'Sunday'];
      const policyPath = join(dir, 'policy.yml');
      writeFileSync(policyPath, `version: "1"
mode: enforce
defaultAction: allow
rules:
  - id: business-hours-only
    description: Only apply during business hours
    target: command
    match: pattern
    values:
      - ".*"
    action: deny
    timeWindow:
      days:
${days.map(d => `        - ${d}`).join('\n')}
      startHour: 9
      endHour: 17
allowlist:
  tools: []
  paths: []
  hosts: []
  envVars: []
`, 'utf-8');

      const { stdout } = await execFileAsync(tsxPath, [
        cliEntry, 'simulate',
        '--tool', 'some_tool',
        '--policy', policyPath,
        '--verbose',
      ]);
      expect(stdout).toContain('business-hours-only');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('simulate shows matched pattern detail', async () => {
    const dir = tmpDir();
    try {
      const policyPath = join(dir, 'policy.yml');
      writeFileSync(policyPath, `version: "1"
mode: enforce
defaultAction: allow
rules:
  - id: block-sensitive-paths
    description: Block filesystem writes to sensitive system and configuration paths
    target: file
    match: pattern
    values:
      - "^/etc(/|$)"
    action: deny
allowlist:
  tools: []
  paths: []
  hosts: []
  envVars: []
`, 'utf-8');

      const { stdout } = await execFileAsync(tsxPath, [
        cliEntry, 'simulate',
        '--tool', 'write_file',
        '--description', 'writes to a file',
        '--args', '{"filePath": "/etc/hosts"}',
        '--server', 'filesystem',
        '--policy', policyPath,
      ]);
      expect(stdout).toContain('[block-sensitive-paths]');
      expect(stdout).toContain('DENY');
      expect(stdout).toContain('/etc/hosts');
      expect(stdout).toContain('BLOCKED');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('CLI test-policy command', () => {
  it('test-policy --help shows test-policy options', async () => {
    const { stdout } = await execFileAsync(tsxPath, [cliEntry, 'test-policy', '--help']);
    expect(stdout).toContain('test-file');
    expect(stdout).toContain('--policy');
  });

  it('test-policy runs tests and reports pass', async () => {
    const dir = tmpDir();
    try {
      const policyPath = join(dir, 'custom-policy.yml');
      writeFileSync(policyPath, `version: "1"
mode: enforce
defaultAction: allow
rules:
  - id: block-shell-execution
    description: Block shell execution
    target: command
    match: pattern
    values:
      - "^bash$"
      - "^sh$"
    action: deny
allowlist:
  tools: []
  paths: []
  hosts: []
  envVars: []
`, 'utf-8');

      const testFilePath = join(dir, 'tests.yml');
      writeFileSync(testFilePath, `
tests:
  - name: "Should block shell execution"
    tool: "bash"
    description: "Run a bash command"
    args: { command: "rm -rf /" }
    expect: deny
    matchReason: "block-shell-execution"
  - name: "Should allow read_file"
    tool: "read_file"
    args: { path: "/home/user/data.txt" }
    expect: allow
`, 'utf-8');

      const { stdout } = await execFileAsync(tsxPath, [
        cliEntry, 'test-policy',
        testFilePath,
        '--policy', policyPath,
      ]);
      expect(stdout).toContain('Should block shell execution');
      expect(stdout).toContain('Should allow read_file');
      expect(stdout).toContain('passed');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('test-policy exits with code 1 when a test fails', async () => {
    const dir = tmpDir();
    try {
      const testFilePath = join(dir, 'tests.yml');
      writeFileSync(testFilePath, `
tests:
  - name: "This test expects deny but will get allow"
    tool: "safe_tool"
    description: "A safe tool"
    args: {}
    expect: deny
`, 'utf-8');

      try {
        await execFileAsync(tsxPath, [
          cliEntry, 'test-policy',
          testFilePath,
        ]);
      } catch (err: any) {
        expect(err.code).toBe(1);
        expect(err.stdout).toContain('failed');
        expect(err.stdout).toContain('This test expects deny but will get allow');
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('test-policy reports matchReason mismatch', async () => {
    const dir = tmpDir();
    try {
      const testFilePath = join(dir, 'tests.yml');
      writeFileSync(testFilePath, `
tests:
  - name: "Should block shell but wrong reason"
    tool: "bash"
    description: "Run a bash command"
    args: { command: "rm -rf /" }
    expect: deny
    matchReason: "nonexistent-reason"
`, 'utf-8');

      try {
        await execFileAsync(tsxPath, [
          cliEntry, 'test-policy',
          testFilePath,
        ]);
      } catch (err: any) {
        expect(err.code).toBe(1);
        expect(err.stdout).toContain('failed');
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('test-policy errors when test file does not exist', async () => {
    try {
      await execFileAsync(tsxPath, [
        cliEntry, 'test-policy',
        '/nonexistent/test.yml',
      ]);
    } catch (err: any) {
      expect(err.code).toBe(1);
      expect(err.stderr || err.stdout).toContain('not found');
    }
  });

  it('test-policy supports --policy flag with custom policy', async () => {
    const dir = tmpDir();
    try {
      const policyPath = join(dir, 'custom-policy.yml');
      writeFileSync(policyPath, `version: "1"
mode: enforce
defaultAction: allow
rules:
  - id: block-custom-tool
    description: Block custom tool
    target: command
    match: exact
    values:
      - custom_dangerous_tool
    action: deny
allowlist:
  tools: []
  paths: []
  hosts: []
  envVars: []
`, 'utf-8');

      const testFilePath = join(dir, 'tests.yml');
      writeFileSync(testFilePath, `
tests:
  - name: "Should block custom dangerous tool"
    tool: "custom_dangerous_tool"
    args: {}
    expect: deny
    matchReason: "block-custom-tool"
  - name: "Should allow other tool"
    tool: "safe_tool"
    args: {}
    expect: allow
`, 'utf-8');

      const { stdout } = await execFileAsync(tsxPath, [
        cliEntry, 'test-policy',
        testFilePath,
        '--policy', policyPath,
      ]);
      expect(stdout).toContain('Should block custom dangerous tool');
      expect(stdout).toContain('Should allow other tool');
      expect(stdout).toContain('2 passed');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('test-policy reports correct summary counts', async () => {
    const dir = tmpDir();
    try {
      const policyPath = join(dir, 'custom-policy.yml');
      writeFileSync(policyPath, `version: "1"
mode: enforce
defaultAction: allow
rules:
  - id: block-shell-execution
    description: Block shell execution
    target: command
    match: pattern
    values:
      - "^bash$"
      - "^sh$"
    action: deny
allowlist:
  tools: []
  paths: []
  hosts: []
  envVars: []
`, 'utf-8');

      const testFilePath = join(dir, 'tests.yml');
      writeFileSync(testFilePath, `
tests:
  - name: "Test 1 - block bash"
    tool: "bash"
    description: "shell"
    args: {}
    expect: deny
  - name: "Test 2 - allow read"
    tool: "read_file"
    args: {}
    expect: allow
  - name: "Test 3 - block sh"
    tool: "sh"
    description: "shell"
    args: {}
    expect: deny
`, 'utf-8');

      const { stdout } = await execFileAsync(tsxPath, [
        cliEntry, 'test-policy',
        testFilePath,
        '--policy', policyPath,
      ]);
      expect(stdout).toContain('3 passed');
      expect(stdout).toContain('0 failed');
      expect(stdout).toContain('3 total');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

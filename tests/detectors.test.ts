import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

let tempDir: string;

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: vi.fn(),
  };
});

import { homedir } from 'node:os';
import { detectAll, detectByClient } from '../src/detectors/index.js';
import { assessRisk } from '../src/detectors/risk.js';
import type { McpServerConfig } from '../src/types.js';

function writeJson(filePath: string, data: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

describe('detectAll', () => {
  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-seatbelt-test-'));
    vi.mocked(homedir).mockReturnValue(tempDir);
    vi.spyOn(process, 'cwd').mockReturnValue(tempDir);
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('returns empty array when no configs exist', async () => {
    const results = await detectAll();
    expect(results).toEqual([]);
  });

  it('detects claude-desktop config', async () => {
    writeJson(
      path.join(tempDir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      {
        mcpServers: {
          'safe-server': {
            command: 'my-mcp-app',
            args: ['--config', '/tmp/config.json'],
          },
        },
      },
    );

    const results = await detectAll();
    expect(results).toHaveLength(1);
    expect(results[0].client).toBe('claude-desktop');
    expect(results[0].servers).toHaveLength(1);
    expect(results[0].servers[0].name).toBe('safe-server');
    expect(results[0].servers[0].command).toBe('my-mcp-app');
    expect(results[0].servers[0].args).toEqual(['--config', '/tmp/config.json']);
  });

  it('detects cursor config', async () => {
    writeJson(path.join(tempDir, '.cursor', 'mcp.json'), {
      mcpServers: {
        'cursor-server': {
          command: 'my-cursor-mcp',
          args: ['server.py'],
        },
      },
    });

    const results = await detectAll();
    expect(results).toHaveLength(1);
    expect(results[0].client).toBe('cursor');
    expect(results[0].servers).toHaveLength(1);
    expect(results[0].servers[0].name).toBe('cursor-server');
  });

  it('detects windsurf config', async () => {
    writeJson(path.join(tempDir, '.codeium', 'windsurf', 'mcp.json'), {
      mcpServers: {
        'windsurf-server': {
          command: 'my-windsurf-mcp',
          args: ['server.js'],
        },
      },
    });

    const results = await detectAll();
    expect(results).toHaveLength(1);
    expect(results[0].client).toBe('windsurf');
  });

  it('detects project .mcp.json config', async () => {
    writeJson(path.join(tempDir, '.mcp.json'), {
      mcpServers: {
        'project-server': {
          command: 'my-project-mcp',
          args: ['./mcp-server.js'],
        },
      },
    });

    const results = await detectAll();
    expect(results).toHaveLength(1);
    expect(results[0].client).toBe('project');
    expect(results[0].servers[0].name).toBe('project-server');
  });

  it('detects project mcp.json config', async () => {
    writeJson(path.join(tempDir, 'mcp.json'), {
      mcpServers: {
        'root-server': {
          command: 'my-root-mcp',
          args: ['server.js'],
        },
      },
    });

    const results = await detectAll();
    expect(results).toHaveLength(1);
    expect(results[0].client).toBe('project');
    expect(results[0].servers[0].name).toBe('root-server');
  });

  it('detects multiple clients simultaneously', async () => {
    writeJson(
      path.join(tempDir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      {
        mcpServers: {
          'claude-srv': { command: 'my-claude-app', args: ['srv.js'] },
        },
      },
    );
    writeJson(path.join(tempDir, '.cursor', 'mcp.json'), {
      mcpServers: {
        'cursor-srv': { command: 'my-cursor-app', args: ['app.py'] },
      },
    });

    const results = await detectAll();
    expect(results).toHaveLength(2);
    const clients = results.map((r) => r.client).sort();
    expect(clients).toEqual(['claude-desktop', 'cursor']);
  });

  it('deduplicates servers by command+args+name', async () => {
    writeJson(path.join(tempDir, '.mcp.json'), {
      mcpServers: {
        'dup-server': { command: 'my-app', args: ['server.js'] },
      },
    });
    writeJson(path.join(tempDir, 'mcp.json'), {
      mcpServers: {
        'dup-server': { command: 'my-app', args: ['server.js'] },
      },
    });

    const results = await detectAll();
    expect(results).toHaveLength(1);
    expect(results[0].servers).toHaveLength(1);
    expect(results[0].servers[0].name).toBe('dup-server');
  });

  it('handles malformed JSON gracefully', async () => {
    const configPath = path.join(tempDir, '.cursor', 'mcp.json');
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, '{ invalid json!!! }');

    const results = await detectAll();
    expect(results).toHaveLength(0);
  });

  it('skips config files that do not exist', async () => {
    const results = await detectAll();
    expect(Array.isArray(results)).toBe(true);
    expect(results).toHaveLength(0);
  });

  it('assigns risk assessments to detected servers', async () => {
    writeJson(path.join(tempDir, '.cursor', 'mcp.json'), {
      mcpServers: {
        'dangerous-server': {
          command: 'bash',
          args: ['-c', 'echo hello'],
        },
      },
    });

    const results = await detectAll();
    expect(results).toHaveLength(1);
    expect(results[0].servers[0].risk.level).not.toBe('low');
    expect(results[0].servers[0].risk.flags.length).toBeGreaterThan(0);
  });

  it('handles servers without args gracefully', async () => {
    writeJson(path.join(tempDir, '.cursor', 'mcp.json'), {
      mcpServers: {
        'no-args-server': {
          command: 'simple-server',
        },
      },
    });

    const results = await detectAll();
    expect(results).toHaveLength(1);
    expect(results[0].servers[0].args).toEqual([]);
    expect(results[0].servers[0].command).toBe('simple-server');
  });
});

describe('assessRisk', () => {
  function makeServer(overrides: Partial<McpServerConfig> = {}): McpServerConfig {
    return {
      name: 'test-server',
      command: 'my-safe-app',
      args: [],
      transport: 'stdio',
      risk: { score: 0, level: 'low', flags: [] },
      ...overrides,
    };
  }

  it('returns low risk for safe stdio server with no dangerous args', () => {
    const server = makeServer({
      command: 'my-safe-app',
      args: ['./safe-server.js'],
      transport: 'stdio',
    });

    const risk = assessRisk(server);
    expect(risk.level).toBe('low');
    expect(risk.score).toBe(0);
    expect(risk.flags).toHaveLength(0);
  });

  it('returns critical risk for shell interpreter commands', () => {
    for (const cmd of ['bash', 'sh', 'zsh', 'powershell']) {
      const server = makeServer({ command: cmd, args: ['-c', 'echo hi'] });
      const risk = assessRisk(server);
      expect(risk.flags.some((f) => f.rule === 'shell-interpreter')).toBe(true);
    }
  });

  it('returns critical risk for no-sandbox flags', () => {
    const server = makeServer({
      command: 'chromium',
      args: ['--no-sandbox', 'server.js'],
    });

    const risk = assessRisk(server);
    expect(risk.flags.some((f) => f.rule === 'no-sandbox')).toBe(true);
  });

  it('returns high risk for raw network tools', () => {
    const server = makeServer({ command: 'curl', args: ['https://example.com'] });
    const risk = assessRisk(server);
    expect(risk.flags.some((f) => f.rule === 'network-tool')).toBe(true);
  });

  it('returns medium risk for non-stdio transport', () => {
    const server = makeServer({
      command: 'my-app',
      transport: 'http',
      url: 'https://api.example.com/mcp',
    });

    const risk = assessRisk(server);
    expect(risk.flags.some((f) => f.rule === 'network-transport')).toBe(true);
  });

  it('returns high risk for process spawning patterns in args', () => {
    const server = makeServer({
      command: 'my-app',
      args: ['--exec', 'child_process'],
    });

    const risk = assessRisk(server);
    expect(risk.flags.some((f) => f.rule === 'process-spawn')).toBe(true);
  });

  it('returns critical risk for destructive filesystem patterns', () => {
    const server = makeServer({
      command: 'my-app',
      args: ['rm -rf', '/tmp/data'],
    });

    const risk = assessRisk(server);
    expect(risk.flags.some((f) => f.rule === 'destructive-fs')).toBe(true);
  });

  it('returns high risk for sensitive environment variable names', () => {
    const server = makeServer({
      command: 'my-app',
      env: {
        'x-token': 'sk-abc123',
        'db-password': 'secret',
      },
    });

    const risk = assessRisk(server);
    expect(risk.flags.some((f) => f.rule === 'sensitive-env')).toBe(true);
  });

  it('returns medium risk for package runner commands', () => {
    for (const cmd of ['npx', 'uvx', 'pipx']) {
      const server = makeServer({ command: cmd, args: ['some-package'] });
      const risk = assessRisk(server);
      expect(risk.flags.some((f) => f.rule === 'package-runner')).toBe(true);
    }
  });

  it('returns critical risk for privilege escalation patterns', () => {
    const server = makeServer({
      command: 'sudo',
      args: ['chmod', '777', '/etc/hosts'],
    });

    const risk = assessRisk(server);
    expect(risk.flags.some((f) => f.rule === 'privilege-escalation')).toBe(true);
  });

  it('returns medium risk for sensitive path references', () => {
    const server = makeServer({
      command: 'my-app',
      args: ['--config', '/etc/app/config.yml'],
    });

    const risk = assessRisk(server);
    expect(risk.flags.some((f) => f.rule === 'sensitive-paths')).toBe(true);
  });

  it('accumulates multiple risk flags and computes cumulative score', () => {
    const server = makeServer({
      command: 'sh',
      args: ['-c', 'rm -rf /tmp/stuff && chmod 777 /etc/hosts'],
      transport: 'http',
      url: 'https://evil.com',
      env: { 'my-secret': 'abc' },
    });

    const risk = assessRisk(server);

    expect(risk.flags.length).toBeGreaterThanOrEqual(5);
    expect(risk.level).toBe('critical');

    const ruleNames = risk.flags.map((f) => f.rule);
    expect(ruleNames).toContain('shell-interpreter');
    expect(ruleNames).toContain('destructive-fs');
    expect(ruleNames).toContain('privilege-escalation');
    expect(ruleNames).toContain('network-transport');
    expect(ruleNames).toContain('sensitive-env');
  });
});

describe('detectByClient', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-seatbelt-test-'));
    vi.mocked(homedir).mockReturnValue(tempDir);
    vi.spyOn(process, 'cwd').mockReturnValue(tempDir);
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('detectByClient("cursor") returns cursor configs', async () => {
    writeJson(path.join(tempDir, '.cursor', 'mcp.json'), {
      mcpServers: {
        'cursor-server': { command: 'my-cursor-mcp', args: ['server.js'] },
      },
    });

    const results = await detectByClient('cursor');
    expect(results).toHaveLength(1);
    expect(results[0].client).toBe('cursor');
    expect(results[0].servers[0].name).toBe('cursor-server');
  });

  it('detectByClient("unknown") returns empty array', async () => {
    writeJson(path.join(tempDir, '.cursor', 'mcp.json'), {
      mcpServers: {
        'test-server': { command: 'echo', args: ['hi'] },
      },
    });

    const results = await detectByClient('nonexistent-client');
    expect(results).toHaveLength(0);
  });

  it('detectByClient("claude-desktop") works', async () => {
    writeJson(
      path.join(tempDir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      {
        mcpServers: {
          'claude-srv': { command: 'my-claude-app', args: ['srv.js'] },
        },
      },
    );

    const results = await detectByClient('claude-desktop');
    expect(results).toHaveLength(1);
    expect(results[0].client).toBe('claude-desktop');
  });

  it('detectByClient("windsurf") works', async () => {
    writeJson(path.join(tempDir, '.codeium', 'windsurf', 'mcp.json'), {
      mcpServers: {
        'wind-srv': { command: 'my-wind-mcp', args: ['srv.js'] },
      },
    });

    const results = await detectByClient('windsurf');
    expect(results).toHaveLength(1);
    expect(results[0].client).toBe('windsurf');
  });

  it('detectByClient("project") works', async () => {
    writeJson(path.join(tempDir, 'mcp.json'), {
      mcpServers: {
        'proj-srv': { command: 'my-proj-mcp', args: ['srv.js'] },
      },
    });

    const results = await detectByClient('project');
    expect(results).toHaveLength(1);
    expect(results[0].client).toBe('project');
  });

  it('detectByClient("vscode") works', async () => {
    writeJson(path.join(tempDir, '.vscode', 'mcp.json'), {
      mcpServers: {
        'vs-srv': { command: 'my-vs-mcp', args: ['srv.js'] },
      },
    });

    const results = await detectByClient('vscode');
    expect(results).toHaveLength(1);
    expect(results[0].client).toBe('vscode');
  });

  it('detectByClient filters correctly when multiple clients exist', async () => {
    writeJson(path.join(tempDir, '.cursor', 'mcp.json'), {
      mcpServers: { 'c-srv': { command: 'my-cursor-app', args: ['app.py'] } },
    });
    writeJson(
      path.join(tempDir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      {
        mcpServers: { 'cl-srv': { command: 'my-claude-app', args: ['srv.js'] } },
      },
    );

    const cursorResults = await detectByClient('cursor');
    expect(cursorResults).toHaveLength(1);
    expect(cursorResults[0].client).toBe('cursor');

    const claudeResults = await detectByClient('claude-desktop');
    expect(claudeResults).toHaveLength(1);
    expect(claudeResults[0].client).toBe('claude-desktop');
  });
});

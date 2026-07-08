import { describe, it, expect } from 'vitest';
import { generateMarkdownReport, generateJsonReport } from '../src/report/generator.js';
import type { McpClientConfig, McpServerConfig } from '../src/types.js';
import { assessRisk } from '../src/detectors/risk.js';

function makeServer(
  name: string,
  overrides: Partial<McpServerConfig> = {},
): McpServerConfig {
  const base: McpServerConfig = {
    name,
    command: 'my-safe-app',
    args: ['./server.js'],
    transport: 'stdio',
    risk: { score: 0, level: 'low', flags: [] },
    ...overrides,
  };
  base.risk = assessRisk(base);
  return base;
}

describe('generateMarkdownReport', () => {
  it('generates a report with a single safe server', () => {
    const configs: McpClientConfig[] = [
      {
        client: 'cursor',
        path: '/home/user/.cursor/mcp.json',
        servers: [
          {
            ...makeServer('safe-server'),
            risk: { score: 0, level: 'low', flags: [] },
          },
        ],
      },
    ];

    const report = generateMarkdownReport(configs);

    expect(report).toContain('# MCP Seatbelt Risk Report');
    expect(report).toContain('## Summary');
    expect(report).toContain('Total Servers');
    expect(report).toContain('safe-server');
    expect(report).toContain('cursor');
    expect(report).toContain('🟢 LOW');
  });

  it('generates a report with a high-risk server', () => {
    const configs: McpClientConfig[] = [
      {
        client: 'claude-desktop',
        path: '/config.json',
        servers: [
          makeServer('dangerous-server', {
            command: 'bash',
            args: ['-c', 'rm -rf /tmp/data'],
          }),
        ],
      },
    ];

    const report = generateMarkdownReport(configs);

    expect(report).toContain('dangerous-server');
    expect(report).toContain('shell-interpreter');
    expect(report).toContain('destructive-fs');
    expect(report).toContain('## Recommendations');
  });

  it('generates a report with multiple servers', () => {
    const configs: McpClientConfig[] = [
      {
        client: 'cursor',
        path: '/cursor.json',
        servers: [
          {
            ...makeServer('safe-1'),
            risk: { score: 0, level: 'low', flags: [] },
          },
        ],
      },
      {
        client: 'vscode',
        path: '/vscode.json',
        servers: [
          makeServer('risky-1', {
            command: 'curl',
            args: ['https://evil.com'],
          }),
          makeServer('safe-2', {
            command: 'my-safe-app',
            args: ['server.js'],
          }),
        ],
      },
    ];

    const report = generateMarkdownReport(configs);

    expect(report).toContain('Total Servers | 3');
    expect(report).toContain('safe-1');
    expect(report).toContain('safe-2');
    expect(report).toContain('risky-1');
  });

  it('includes risk flags and tool breakdown per server', () => {
    const configs: McpClientConfig[] = [
      {
        client: 'claude-desktop',
        path: '/config.json',
        servers: [
          makeServer('bash-server', {
            command: 'bash',
            args: ['-c', 'echo hi'],
          }),
        ],
      },
    ];

    const report = generateMarkdownReport(configs);
    expect(report).toContain('### Risk Flags');
    expect(report).toContain('### Tool Breakdown');
    expect(report).toContain('Policy Action');
  });

  it('handles empty configs array', () => {
    const configs: McpClientConfig[] = [];
    const report = generateMarkdownReport(configs);

    expect(report).toContain('Total Servers | 0');
    expect(report).toContain('No MCP servers detected');
  });

  it('includes recommendations section with next steps', () => {
    const configs: McpClientConfig[] = [
      {
        client: 'cursor',
        path: '/cursor.json',
        servers: [
          {
            ...makeServer('test'),
            risk: { score: 0, level: 'low', flags: [] },
          },
        ],
      },
    ];

    const report = generateMarkdownReport(configs);
    expect(report).toContain('### Next Steps');
    expect(report).toContain('.mcp-seatbelt/policy.yml');
  });

  it('includes critical recommendations for high-risk servers', () => {
    const configs: McpClientConfig[] = [
      {
        client: 'test',
        path: '/test.json',
        servers: [
          makeServer('server', {
            command: 'bash',
            args: ['-c', 'sudo rm -rf /etc/hosts'],
            env: { API_KEY: 'secret' },
          }),
        ],
      },
    ];

    const report = generateMarkdownReport(configs);
    expect(report).toContain('### Critical');
  });

  it('shows correct counts for high and low risk servers', () => {
    const configs: McpClientConfig[] = [
      {
        client: 'test',
        path: '/test.json',
        servers: [
          makeServer('critical-srv', {
            command: 'bash',
            args: ['-c', 'rm -rf /'],
          }),
        ],
      },
    ];

    const report = generateMarkdownReport(configs);
    expect(report).toContain('High / Critical Risk | 1');
    expect(report).toContain('Low Risk | 0');
  });
});

describe('generateJsonReport', () => {
  it('generates JSON report with correct structure', () => {
    const configs: McpClientConfig[] = [
      {
        client: 'cursor',
        path: '/cursor.json',
        servers: [
          {
            ...makeServer('json-server'),
            risk: { score: 5, level: 'low', flags: [] },
          },
        ],
      },
    ];

    const report = generateJsonReport(configs);

    expect(report.generatedAt).toBeDefined();
    expect(typeof report.generatedAt).toBe('string');
    expect(report.summary.totalServers).toBe(1);
    expect(report.summary.highRisk).toBe(0);
    expect(report.summary.mediumRisk).toBe(0);
    expect(report.summary.lowRisk).toBe(1);
    expect(report.summary.blockedCalls).toBe(0);
    expect(report.summary.allowedCalls).toBe(0);
    expect(report.summary.warnedCalls).toBe(0);
    expect(report.servers).toHaveLength(1);
    expect(report.servers[0].name).toBe('json-server');
    expect(report.servers[0].client).toBe('cursor');
    expect(report.servers[0].proxied).toBe(true);
    expect(Array.isArray(report.recommendations)).toBe(true);
  });

  it('includes risk flags in server reports', () => {
    const configs: McpClientConfig[] = [
      {
        client: 'claude-desktop',
        path: '/config.json',
        servers: [
          makeServer('risky', {
            command: 'bash',
            args: ['--no-sandbox', '-c', 'exit'],
          }),
        ],
      },
    ];

    const report = generateJsonReport(configs);
    expect(report.servers[0].risk.flags.length).toBeGreaterThan(0);
    expect(report.servers[0].risk.level).toBe('critical');
    expect(report.servers[0].tools.length).toBeGreaterThan(0);
  });

  it('counts risk levels correctly across multiple servers', () => {
    const lowServer1 = {
      ...makeServer('low-1'),
      risk: { score: 0, level: 'low' as const, flags: [] },
    };

    const lowServer2 = {
      ...makeServer('low-2'),
      risk: { score: 5, level: 'low' as const, flags: [] },
    };

    const configs: McpClientConfig[] = [
      {
        client: 'test',
        path: '/test.json',
        servers: [
          lowServer1,
          makeServer('critical-1', {
            command: 'bash',
            args: ['-c', 'rm -rf /'],
          }),
          makeServer('high-1', {
            command: 'curl',
            args: ['--exec', 'subprocess'],
          }),
          lowServer2,
        ],
      },
    ];

    const report = generateJsonReport(configs);
    expect(report.summary.totalServers).toBe(4);
    expect(report.summary.highRisk).toBe(2);
    expect(report.summary.lowRisk).toBe(2);
  });

  it('returns empty result for empty configs', () => {
    const report = generateJsonReport([]);

    expect(report.summary.totalServers).toBe(0);
    expect(report.summary.highRisk).toBe(0);
    expect(report.summary.mediumRisk).toBe(0);
    expect(report.summary.lowRisk).toBe(0);
    expect(report.servers).toHaveLength(0);
    expect(report.recommendations).toHaveLength(0);
  });

  it('includes tool reports with policy actions', () => {
    const configs: McpClientConfig[] = [
      {
        client: 'test',
        path: '/test.json',
        servers: [
          makeServer('server', {
            command: 'bash',
            args: ['-c', 'echo hi'],
          }),
        ],
      },
    ];

    const report = generateJsonReport(configs);
    const server = report.servers[0];

    for (const tool of server.tools) {
      expect(typeof tool.name).toBe('string');
      expect(typeof tool.description).toBe('string');
      expect(['allow', 'deny', 'warn']).toContain(tool.policyAction);
      expect(Array.isArray(tool.riskFlags)).toBe(true);
    }
  });
});

import type { McpClientConfig, PolicyConfig } from '../types.js';
import { dump } from 'js-yaml';

export const DEFAULT_POLICY: PolicyConfig = {
  version: '1',
  mode: 'enforce',
  defaultAction: 'deny',
  defaultTimeoutMs: 30000,
  rules: [
    {
      id: 'block-shell-execution',
      description: 'Block tools that invoke shell interpreters directly',
      target: 'command',
      match: 'pattern',
      values: [
        '^bash$',
        '^sh$',
        '^zsh$',
        '^cmd$',
        '^powershell$',
        '^pwsh$',
        '^/bin/bash$',
        '^/bin/sh$',
        '^/bin/zsh$',
        '^/usr/bin/bash$',
        '^/usr/bin/sh$',
        '^/usr/bin/zsh$',
        '\\bbash\\s+-c\\b',
        '\\bsh\\s+-c\\b',
        '\\bzsh\\s+-c\\b',
        '\\bcmd\\.exe\\s+/c\\b',
        '\\bpowershell\\s+-Command\\b',
        '\\bpwsh\\s+-Command\\b',
      ],
      action: 'deny',
      timeoutMs: 10000,
      compliance: [
        { framework: 'soc2', controls: ['CC6.1', 'CC6.6', 'CC7.2'] },
        { framework: 'hipaa', controls: ['164.312(a)(1)'] },
        { framework: 'gdpr', controls: ['Art_32'] },
      ],
    },
    {
      id: 'block-sensitive-paths',
      description: 'Block filesystem writes to sensitive system and configuration paths',
      target: 'file',
      match: 'pattern',
      values: [
        '^/etc(/|$)',
        '^/root(/|$)',
        '^/home/[^/]+/\\.ssh(/|$)',
        '^/home/[^/]+/\\.aws(/|$)',
        '^~/\\.ssh(/|$)',
        '^~/\\.aws(/|$)',
        '^/var(/|$)',
        '^/usr(/|$)',
        '^/System(/|$)',
        '^C:\\\\Windows',
        '^C:\\\\Program Files',
        '^%SystemRoot%',
        '^%ProgramFiles%',
      ],
      action: 'deny',
      compliance: [
        { framework: 'soc2', controls: ['CC6.1', 'CC6.8'] },
        { framework: 'hipaa', controls: ['164.312(a)(1)'] },
        { framework: 'iso27001', controls: ['A.9.4'] },
      ],
    },
    {
      id: 'block-credential-access',
      description: 'Block tools whose descriptions indicate credential or secret access',
      target: 'command',
      match: 'contains',
      values: ['password', 'secret', 'token', 'api_key', 'credential', 'private key'],
      action: 'deny',
      compliance: [
        { framework: 'soc2', controls: ['CC6.1'] },
        { framework: 'iso27001', controls: ['A.9.2'] },
      ],
    },
    {
      id: 'redact-credentials',
      description: 'Redact arguments whose key names contain credential-like patterns (password, secret, token, key, credential)',
      target: 'command',
      match: 'contains',
      values: ['password', 'secret', 'token', 'key', 'credential'],
      action: 'redact',
      timeoutMs: 5000,
    },
    {
      id: 'block-private-network',
      description: 'Block outbound network requests to private and loopback address ranges',
      target: 'network',
      match: 'pattern',
      values: [
        '^https?://10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}',
        '^https?://172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}',
        '^https?://192\\.168\\.\\d{1,3}\\.\\d{1,3}',
        '^https?://127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}',
        '^https?://localhost',
        '^https?://\\[::1\\]',
        '\\b10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b',
        '\\b172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}\\b',
        '\\b192\\.168\\.\\d{1,3}\\.\\d{1,3}\\b',
        '\\b127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b',
      ],
      action: 'deny',
      compliance: [
        { framework: 'soc2', controls: ['CC6.6'] },
        { framework: 'hipaa', controls: ['164.312(e)(1)'] },
      ],
    },
    {
      id: 'block-process-execution',
      description: 'Block tools that spawn child processes or evaluate arbitrary code',
      target: 'process',
      match: 'pattern',
      values: [
        '\\bexec\\b',
        '\\bspawn\\b',
        '\\bfork\\b',
        '\\bsystem\\b',
        '\\beval\\b',
        '\\bchild_process\\b',
        '\\bexecSync\\b',
        '\\bspawnSync\\b',
        '\\bexecFile\\b',
        '\\bexecFileSync\\b',
      ],
      action: 'deny',
      timeoutMs: 15000,
    },
    {
      id: 'allow-filesystem-writes-business-hours',
      description: 'Allow filesystem writes only during business hours (Mon-Fri, 9-17)',
      target: 'file',
      match: 'pattern',
      values: ['^\\.?(/|[A-Z]:\\\\)'],
      action: 'allow',
      timeWindow: {
        days: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'],
        startHour: 9,
        endHour: 17,
      },
    },
    {
      id: 'allow-workspace-filesystem',
      description: 'Allow filesystem access only within /workspace',
      target: 'file',
      match: 'pattern',
      values: ['/workspace/'],
      action: 'allow',
      argConstraints: [
        { argName: 'filePath', constraint: 'startsWith', values: ['/workspace/'] },
        { argName: 'path', constraint: 'startsWith', values: ['/workspace/'] },
      ],
    },
    {
      id: 'block-credential-leakage',
      description: 'Scan MCP server responses for leaked credentials',
      target: 'command',
      match: 'contains',
      values: ['dlp-scan'],
      action: 'redact',
    },
  ],
  allowlist: {
    tools: [],
    paths: [],
    hosts: [],
    envVars: [],
  },
  // allowSampling: true — sampling/createMessage allows MCP servers to request
  // LLM completions from the AI client. Blocking would break most MCP server
  // functionality. Set to false in high-security environments where server-
  // initiated LLM calls are an exfiltration concern.
  //
  // honeytokens — When mode is "audit", honeytoken injection is enabled by default
  // (plants decoy credentials in responses to detect exfiltration). Disabled
  // automatically in "enforce" mode unless explicitly enabled via --inject-honeytokens.
  allowSampling: true,
};

export const DEFAULT_TEMPLATES: Record<string, PolicyConfig> = {
  'minimal-workstation': {
    version: '1',
    mode: 'enforce',
    defaultAction: 'allow',
    allowSampling: false,
    rules: [
      {
        id: 'block-shell-execution',
        description: 'Block tools that invoke shell interpreters directly',
        target: 'command',
        match: 'pattern',
        values: [
          '^bash$',
          '^sh$',
          '^zsh$',
          '^cmd$',
          '^powershell$',
          '^pwsh$',
          '\\bbash\\s+-c\\b',
          '\\bsh\\s+-c\\b',
          '\\bzsh\\s+-c\\b',
        ],
        action: 'deny',
      },
      {
        id: 'block-credential-access',
        description: 'Block tools whose descriptions indicate credential or secret access',
        target: 'command',
        match: 'contains',
        values: ['password', 'secret', 'token', 'api_key', 'credential', 'private key'],
        action: 'deny',
      },
    ],
    allowlist: {
      tools: [],
      paths: [],
      hosts: [],
      envVars: [],
    },
  },

  'pci-compliance': {
    version: '1',
    mode: 'enforce',
    defaultAction: 'deny',
    allowSampling: false,
    rules: [
      {
        id: 'block-shell-execution',
        description: 'Block tools that invoke shell interpreters directly',
        target: 'command',
        match: 'pattern',
        values: [
          '^bash$',
          '^sh$',
          '^zsh$',
          '^cmd$',
          '^powershell$',
          '^pwsh$',
          '\\bbash\\s+-c\\b',
          '\\bsh\\s+-c\\b',
          '\\bzsh\\s+-c\\b',
        ],
        action: 'deny',
      },
      {
        id: 'block-credential-access',
        description: 'Block tools whose descriptions indicate credential or secret access',
        target: 'command',
        match: 'contains',
        values: ['password', 'secret', 'token', 'api_key', 'credential', 'private key'],
          action: 'deny',
          compliance: [
            { framework: 'pci-dss', controls: ['7.2.1', '7.2.2'] },
          ],
        },
        {
          id: 'block-cardholder-data-paths',
        description: 'Block access to paths containing cardholder data per PCI DSS',
        target: 'file',
        match: 'pattern',
        values: [
          '\\b(chd|cardholder|pan|credit[_\\-]?card)\\b',
          '\\bprimary[_\\-]?account[_\\-]?number\\b',
          '\\bcvv\\b',
          '\\bcvc\\b',
          '\\bccv\\b',
          '\\btrack[_\\-]?[12]\\b',
        ],
          action: 'deny',
          compliance: [
            { framework: 'pci-dss', controls: ['3.4', '3.4.1'] },
          ],
        },
        {
          id: 'block-pan-patterns',
        description: 'Block card PAN patterns (Luhn-able number sequences)',
        target: 'command',
        match: 'pattern',
        values: [
          '\\b[45]\\d{3}[\\s\\-]?\\d{4}[\\s\\-]?\\d{4}[\\s\\-]?\\d{4}\\b',
          '\\b3\\d{3}[\\s\\-]?\\d{6}[\\s\\-]?\\d{5}\\b',
        ],
          action: 'deny',
          compliance: [
            { framework: 'pci-dss', controls: ['3.4', '3.4.1'] },
          ],
        },
        {
          id: 'block-audit-trail-tampering',
        description: 'Block modification of audit trails and log files per PCI DSS Requirement 10',
        target: 'file',
        match: 'pattern',
        values: [
          '\\baudit[_\\-]?log\\b',
          '\\bsecurity[_\\-]?log\\b',
          '\\baccess[_\\-]?log\\b',
        ],
        action: 'deny',
        compliance: [
          { framework: 'pci-dss', controls: ['10.1', '10.2', '10.5'] },
        ],
      },
    ],
    allowlist: {
      tools: [],
      paths: [],
      hosts: [],
      envVars: [],
    },
  },

  'strict-production': {
    version: '1',
    mode: 'enforce',
    defaultAction: 'deny',
    allowSampling: false,
    rules: [
      {
        id: 'block-all-tools',
        description: 'Block all tool invocations by default in strict production mode',
        target: 'command',
        match: 'pattern',
        values: ['.*'],
        action: 'deny',
      },
      {
        id: 'deny-unknown-network',
        description: 'Block all network requests in strict production mode',
        target: 'network',
        match: 'pattern',
        values: ['.*'],
        action: 'deny',
      },
      {
        id: 'deny-all-filesystem',
        description: 'Block all filesystem operations in strict production mode',
        target: 'file',
        match: 'pattern',
        values: ['.*'],
        action: 'deny',
      },
    ],
    allowlist: {
      tools: [],
      paths: [],
      hosts: [],
      envVars: [],
    },
  },
};

export function generateDefaultPolicy(configs: McpClientConfig[], mode: string = "audit"): PolicyConfig {
  const allTools = new Set<string>();
  const allHosts = new Set<string>();

  for (const config of configs) {
    for (const server of config.servers) {
      allTools.add(server.name);
      if (server.url) {
        try {
          const host = new URL(server.url).hostname;
          allHosts.add(host);
        } catch {
          // ignore invalid URLs
        }
      }
    }
  }

  return {
    version: "0.1.0",
    mode: mode as "audit" | "enforce",
    defaultAction: "deny",
    defaultTimeoutMs: DEFAULT_POLICY.defaultTimeoutMs,
    rules: DEFAULT_POLICY.rules,
    allowlist: {
      tools: [...allTools],
      paths: [],
      hosts: [...allHosts],
      envVars: [],
    },
    allowSampling: DEFAULT_POLICY.allowSampling,
  };
}

export function generateDefaultPolicyFile(): string {
  const policyForYaml = {
    version: DEFAULT_POLICY.version,
    mode: DEFAULT_POLICY.mode,
    defaultAction: DEFAULT_POLICY.defaultAction,
    defaultTimeoutMs: DEFAULT_POLICY.defaultTimeoutMs,
    rules: DEFAULT_POLICY.rules.map((rule) => ({
      id: rule.id,
      description: rule.description,
      target: rule.target,
      match: rule.match,
      values: rule.values,
      action: rule.action,
      ...(rule.timeoutMs !== undefined ? { timeoutMs: rule.timeoutMs } : {}),
      ...(rule.timeWindow ? { timeWindow: rule.timeWindow } : {}),
      ...(rule.argConstraints ? { argConstraints: rule.argConstraints } : {}),
    })),
    allowlist: DEFAULT_POLICY.allowlist,
    allowSampling: DEFAULT_POLICY.allowSampling,
  };

  return [
    '# mcp-seatbelt default policy',
    '# Generated by mcp-seatbelt --policy-defaults',
    '#',
    '# mode: audit | enforce',
    '#   audit   - log policy violations but allow all calls',
    '#   enforce - block denied calls and warn on uncertain calls',
    '#',
    '# defaultAction: allow | deny',
    '#   allow - permit calls that do not match any rule',
    '#   deny  - block calls that do not match any rule (recommended)',
    '#',
    '# Rules target: command | file | network | env | process',
    '# Rules match:  exact | pattern | contains',
    '# Rules action: allow | deny | warn',
    '#',
    '# timeWindow (optional): restrict rule to specific days/hours',
    '#   days: list of day names (Monday-Sunday)',
    '#   startHour/endHour: 0-23 hour range',
    '#',
    '# contextCondition (optional): restrict rule by client or rate',
    '#   clientIn: list of client names to match',
    '#   maxRequestsPerMinute: rate-limiting threshold',
    '',
    dump(policyForYaml, { indent: 2, lineWidth: -1, noRefs: true }),
  ].join('\n');
}

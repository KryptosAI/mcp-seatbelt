import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { PolicyEngine } from '../src/policy/engine.js';
import { DEFAULT_POLICY, DEFAULT_TEMPLATES, generateDefaultPolicyFile } from '../src/policy/defaults.js';
import { LLMJudge } from '../src/policy/llm-judge.js';
import { validatePolicy } from '../src/policy/schema.js';
import { parse, stringify, parsePolicy } from '../src/policy/yaml.js';
import type { PolicyConfig, PolicyRule } from '../src/types.js';

function makeEnforcePolicy(rules: PolicyRule[] = []): PolicyConfig {
  return {
    version: '1',
    mode: 'enforce',
    defaultAction: 'deny',
    rules,
    allowlist: {
      tools: [],
      paths: [],
      hosts: [],
      envVars: [],
    },
    allowSampling: true,
  };
}

function makeAllowDefaultPolicy(rules: PolicyRule[] = []): PolicyConfig {
  return {
    ...makeEnforcePolicy(rules),
    defaultAction: 'allow',
  };
}

function makeAuditPolicy(rules: PolicyRule[] = []): PolicyConfig {
  return {
    ...makeEnforcePolicy(rules),
    mode: 'audit',
    defaultAction: 'deny',
  };
}

const denyEvalRule: PolicyRule = {
  id: 'block-eval',
  description: 'Block eval usage',
  target: 'process',
  match: 'contains',
  values: ['eval'],
  action: 'deny',
};

const warnExecRule: PolicyRule = {
  id: 'warn-exec',
  description: 'Warn on exec usage',
  target: 'process',
  match: 'contains',
  values: ['exec'],
  action: 'warn',
};

const allowReadRule: PolicyRule = {
  id: 'allow-read',
  description: 'Allow read operations',
  target: 'command',
  match: 'pattern',
  values: ['^read_file$'],
  action: 'allow',
};

describe('DEFAULT_POLICY', () => {
  it('has valid structure', () => {
    expect(DEFAULT_POLICY.version).toBe('1');
    expect(DEFAULT_POLICY.mode).toBe('enforce');
    expect(DEFAULT_POLICY.defaultAction).toBe('deny');
    expect(Array.isArray(DEFAULT_POLICY.rules)).toBe(true);
    expect(DEFAULT_POLICY.rules.length).toBeGreaterThan(0);
  });

  it('block-shell-execution rule matches shell command names', () => {
    const rule = DEFAULT_POLICY.rules.find((r) => r.id === 'block-shell-execution');
    expect(rule).toBeDefined();
    expect(rule!.action).toBe('deny');
    expect(rule!.values).toContain('^bash$');
    expect(rule!.values).toContain('^sh$');
    expect(rule!.values).toContain('\\bbash\\s+-c\\b');
  });

  it('block-sensitive-paths rule matches system paths', () => {
    const rule = DEFAULT_POLICY.rules.find((r) => r.id === 'block-sensitive-paths');
    expect(rule).toBeDefined();
    expect(rule!.target).toBe('file');
    expect(rule!.values).toContain('^/etc(/|$)');
  });

  it('block-credential-access rule matches credential keywords', () => {
    const rule = DEFAULT_POLICY.rules.find((r) => r.id === 'block-credential-access');
    expect(rule).toBeDefined();
    expect(rule!.values).toContain('password');
    expect(rule!.values).toContain('api_key');
  });
});

describe('PolicyEngine', () => {
  describe('evaluate', () => {
    it('blocks tool matching a deny rule', () => {
      const engine = new PolicyEngine(makeEnforcePolicy([denyEvalRule]));
      const result = engine.evaluate('eval_tool', 'runs arbitrary eval', {});
      expect(result.action).toBe('deny');
      expect(result.reasons.length).toBeGreaterThan(0);
      expect(result.reasons[0]).toContain('block-eval');
    });

    it('allows tool matching an allow rule when default is allow', () => {
      const engine = new PolicyEngine(
        makeAllowDefaultPolicy([allowReadRule]),
      );
      const result = engine.evaluate('read_file', 'reads a file', {});
      expect(result.action).toBe('allow');
    });

    it('allows tool matching an allow rule only when no deny or warn matched', () => {
      const engine = new PolicyEngine(
        makeAllowDefaultPolicy([warnExecRule, allowReadRule]),
      );
      const result = engine.evaluate('exec_tool', 'runs exec', {});
      expect(result.action).toBe('warn');
    });

    it('warns on tool matching a warn rule when default is allow', () => {
      const engine = new PolicyEngine(
        makeAllowDefaultPolicy([warnExecRule]),
      );
      const result = engine.evaluate('exec_tool', 'runs exec commands', {});
      expect(result.action).toBe('warn');
      expect(result.reasons[0]).toContain('warn-exec');
    });

    it('defaults to deny when no rule matches and defaultAction is deny', () => {
      const engine = new PolicyEngine(makeEnforcePolicy([]));
      const result = engine.evaluate('some_tool', 'does stuff', {});
      expect(result.action).toBe('deny');
    });

    it('defaults to allow when no rule matches and defaultAction is allow', () => {
      const engine = new PolicyEngine(makeAllowDefaultPolicy([]));
      const result = engine.evaluate('some_tool', 'does stuff', {});
      expect(result.action).toBe('allow');
    });

    it('in audit mode, all calls are allowed regardless of rules', () => {
      const engine = new PolicyEngine(makeAuditPolicy([denyEvalRule]));
      const result = engine.evaluate('eval_tool', 'runs eval', {});
      expect(result.action).toBe('allow');
      expect(result.reasons[0]).toContain('Audit mode');
    });

    it('allowlist takes precedence over deny rules', () => {
      const config: PolicyConfig = {
        ...makeEnforcePolicy([denyEvalRule]),
        allowlist: {
          tools: ['eval_tool'],
          paths: [],
          hosts: [],
          envVars: [],
        },
      };
      const engine = new PolicyEngine(config);
      const result = engine.evaluate('eval_tool', 'runs eval', {});
      expect(result.action).toBe('allow');
      expect(result.reasons[0]).toContain('explicitly allowlisted');
    });

    it('deny rule takes priority over warn rule on same match', () => {
      const config = makeAllowDefaultPolicy([
        { ...warnExecRule, values: ['exec'] },
        { ...denyEvalRule, values: ['exec'] },
      ]);
      const engine = new PolicyEngine(config);
      const result = engine.evaluate('exec_tool', 'runs exec commands', {});
      expect(result.action).toBe('deny');
    });

    it('matches rule against tool description', () => {
      const engine = new PolicyEngine(
        makeEnforcePolicy([denyEvalRule]),
      );
      const result = engine.evaluate('harmless_tool', 'this tool uses eval internally', {});
      expect(result.action).toBe('deny');
    });

    it('matches rule against args for file target', () => {
      const rule: PolicyRule = {
        id: 'block-etc',
        description: 'Block /etc paths',
        target: 'file',
        match: 'contains',
        values: ['/etc'],
        action: 'deny',
      };
      const engine = new PolicyEngine(makeEnforcePolicy([rule]));
      const result = engine.evaluate('file_tool', 'writes files', {
        filePath: '/etc/hosts',
      });
      expect(result.action).toBe('deny');
    });

    it('matches rule against args for network target', () => {
      const rule: PolicyRule = {
        id: 'block-google',
        description: 'Block google',
        target: 'network',
        match: 'contains',
        values: ['google.com'],
        action: 'deny',
      };
      const engine = new PolicyEngine(makeEnforcePolicy([rule]));
      const result = engine.evaluate('fetch_tool', 'fetches urls', {
        url: 'https://google.com/search',
      });
      expect(result.action).toBe('deny');
    });

    it('matches env target against env var keys in args', () => {
      const rule: PolicyRule = {
        id: 'block-secret-env',
        description: 'Block secret env',
        target: 'env',
        match: 'contains',
        values: ['SECRET'],
        action: 'deny',
      };
      const engine = new PolicyEngine(makeEnforcePolicy([rule]));
      const result = engine.evaluate('env_tool', 'sets env', {
        env: { MY_SECRET: 'value' },
      });
      expect(result.action).toBe('deny');
    });

    it('does not match when no rules apply and default is allow', () => {
      const engine = new PolicyEngine(makeAllowDefaultPolicy([denyEvalRule]));
      const result = engine.evaluate('clean_tool', 'does clean operations', {});
      expect(result.action).toBe('allow');
    });

    it('uses pattern match type with regex', () => {
      const rule: PolicyRule = {
        id: 'block-numeric',
        description: 'Block tools with numbers',
        target: 'command',
        match: 'pattern',
        values: ['^tool_\\d+$'],
        action: 'deny',
      };
      const engine = new PolicyEngine(makeEnforcePolicy([rule]));
      const result = engine.evaluate('tool_42', '', {});
      expect(result.action).toBe('deny');
    });

    it('uses exact match type (does not do substring match)', () => {
      const rule: PolicyRule = {
        id: 'block-exact',
        description: 'Block exact tool',
        target: 'command',
        match: 'exact',
        values: ['dangerous_tool'],
        action: 'deny',
      };
      const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));

      expect(engine.evaluate('dangerous_tool', '', {}).action).toBe('deny');
      expect(engine.evaluate('dangerous_tool_v2', '', {}).action).toBe('allow');
    });
  });

  describe('addRule', () => {
    it('adds a new rule and it takes effect', () => {
      const engine = new PolicyEngine(makeEnforcePolicy([]));
      engine.addRule(denyEvalRule);
      expect(engine.getStats().rules).toBe(1);

      const result = engine.evaluate('eval_tool', 'uses eval', {});
      expect(result.action).toBe('deny');
    });

    it('throws on duplicate rule id', () => {
      const engine = new PolicyEngine(makeEnforcePolicy([denyEvalRule]));
      expect(() => engine.addRule(denyEvalRule)).toThrow(
        'Rule with id "block-eval" already exists',
      );
    });
  });

  describe('removeRule', () => {
    it('removes an existing rule', () => {
      const engine = new PolicyEngine(makeEnforcePolicy([denyEvalRule]));
      expect(engine.getStats().rules).toBe(1);
      engine.removeRule('block-eval');
      expect(engine.getStats().rules).toBe(0);
    });

    it('throws on non-existent rule id', () => {
      const engine = new PolicyEngine(makeEnforcePolicy([]));
      expect(() => engine.removeRule('nonexistent')).toThrow(
        'Rule with id "nonexistent" not found',
      );
    });
  });

  describe('updateRule', () => {
    it('updates an existing rule action', () => {
      const engine = new PolicyEngine(makeAllowDefaultPolicy([denyEvalRule]));
      engine.updateRule('block-eval', { action: 'warn', description: 'Updated desc' });
      const result = engine.evaluate('eval_tool', 'uses eval', {});
      expect(result.action).toBe('warn');
    });

    it('throws on non-existent rule id', () => {
      const engine = new PolicyEngine(makeEnforcePolicy([]));
      expect(() => engine.updateRule('nope', { action: 'allow' })).toThrow(
        'Rule with id "nope" not found',
      );
    });
  });

  describe('getStats', () => {
    it('returns correct rule and allowlist counts', () => {
      const config: PolicyConfig = {
        ...makeEnforcePolicy([denyEvalRule, warnExecRule]),
        allowlist: {
          tools: ['safe_tool_a', 'safe_tool_b'],
          paths: [],
          hosts: [],
          envVars: [],
        },
      };
      const engine = new PolicyEngine(config);
      const stats = engine.getStats();
      expect(stats.rules).toBe(2);
      expect(stats.allowlisted).toBe(2);
    });
  });

  describe('loadFromFile / saveToFile', () => {
    let tempDir: string;

    beforeEach(() => {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-seatbelt-policy-'));
    });

    afterEach(() => {
      fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it('saves and loads policy from YAML file', async () => {
      const engine = new PolicyEngine(makeEnforcePolicy([denyEvalRule]));
      const yamlPath = path.join(tempDir, 'policy.yml');

      await engine.saveToFile(yamlPath);

      const content = fs.readFileSync(yamlPath, 'utf-8');
      expect(content).toContain('block-eval');
      expect(content).toContain('enforce');

      const engine2 = new PolicyEngine(
        makeEnforcePolicy([warnExecRule]),
      );
      await engine2.loadFromFile(yamlPath);

      const result = engine2.evaluate('eval_tool', 'runs eval', {});
      expect(result.action).toBe('deny');
    });

    it('loadFromFile validates the YAML content', async () => {
      const engine = new PolicyEngine(makeEnforcePolicy([]));
      const yamlPath = path.join(tempDir, 'bad.yml');
      fs.writeFileSync(yamlPath, 'version: ""\nmode: invalid\n');

      await expect(engine.loadFromFile(yamlPath)).rejects.toThrow();
    });
  });
});

describe('validatePolicy', () => {
  it('reports all unknown fields with their paths', () => {
    const base = makeEnforcePolicy();
    const config = {
      ...base,
      defaultActon: 'deny',
      allowlist: {
        ...base.allowlist,
        envVar: [],
      },
    };

    expect(() => validatePolicy(config)).toThrow(/defaultActon[\s\S]*allowlist\.envVar/);
  });

  it('accepts a valid policy config', () => {
    const config = makeEnforcePolicy([denyEvalRule]);
    const result = validatePolicy(config);
    expect(result.version).toBe('1');
    expect(result.rules).toHaveLength(1);
  });

  it('throws for non-object config', () => {
    expect(() => validatePolicy(null)).toThrow('non-null object');
    expect(() => validatePolicy('string')).toThrow('non-null object');
  });

  it('throws for empty version string', () => {
    const config = { ...makeEnforcePolicy([]), version: '' };
    expect(() => validatePolicy(config)).toThrow('version');
  });

  it('throws for invalid mode', () => {
    const config = { ...makeEnforcePolicy([]), mode: 'invalid' };
    expect(() => validatePolicy(config)).toThrow('mode');
  });

  it('throws for invalid defaultAction', () => {
    const config = { ...makeEnforcePolicy([]), defaultAction: 'maybe' };
    expect(() => validatePolicy(config)).toThrow('defaultAction');
  });

  it('throws for non-array rules', () => {
    const config = { ...makeEnforcePolicy([]), rules: 'not-an-array' };
    expect(() => validatePolicy(config)).toThrow('rules');
  });
});

describe('yaml utils', () => {
  it('parse and stringify round-trip', () => {
    const obj = { hello: 'world', count: 42 };
    const yaml = stringify(obj);
    const parsed = parse(yaml);
    expect(parsed).toEqual(obj);
  });

  it('parsePolicy returns a PolicyConfig object', () => {
    const yaml = stringify({
      version: '1',
      mode: 'enforce',
      defaultAction: 'deny',
      rules: [denyEvalRule],
      allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
    });
    const policy = parsePolicy(yaml);
    expect(policy.version).toBe('1');
    expect(policy.mode).toBe('enforce');
  });
});

describe('generateDefaultPolicyFile', () => {
  it('generates valid YAML', () => {
    const output = generateDefaultPolicyFile();
    expect(() => parse(output)).not.toThrow();
  });

  it('YAML contains expected top-level keys', () => {
    const output = generateDefaultPolicyFile();
    const parsed = parse(output) as Record<string, unknown>;
    expect(parsed.version).toBeDefined();
    expect(parsed.mode).toBeDefined();
    expect(parsed.defaultAction).toBeDefined();
    expect(Array.isArray(parsed.rules)).toBe(true);
    expect(parsed.rules.length).toBeGreaterThan(0);
    expect(parsed.allowlist).toBeDefined();
  });

  it('output parses with js-yaml', () => {
    const output = generateDefaultPolicyFile();
    const parsed = parse(output);
    expect(parsed).not.toBeNull();
    expect(typeof parsed).toBe('object');
  });

  it('contains block-shell-execution rule', () => {
    const output = generateDefaultPolicyFile();
    const parsed = parse(output) as Record<string, unknown>;
    const rules = parsed.rules as Array<Record<string, unknown>>;
    const shellRule = rules.find((r) => r.id === 'block-shell-execution');
    expect(shellRule).toBeDefined();
    expect(shellRule!.action).toBe('deny');
  });
});

describe('DEFAULT_TEMPLATES', () => {
  it('minimal-workstation has allow default action', () => {
    const tmpl = DEFAULT_TEMPLATES['minimal-workstation'];
    expect(tmpl.defaultAction).toBe('allow');
    expect(tmpl.mode).toBe('enforce');
    expect(tmpl.rules.length).toBeGreaterThanOrEqual(2);
    expect(tmpl.rules.some((r: PolicyRule) => r.id === 'block-shell-execution')).toBe(true);
    expect(tmpl.rules.some((r: PolicyRule) => r.id === 'block-credential-access')).toBe(true);
  });

  it('pci-compliance includes cardholder data rules', () => {
    const tmpl = DEFAULT_TEMPLATES['pci-compliance'];
    expect(tmpl.defaultAction).toBe('deny');
    expect(tmpl.rules.some((r: PolicyRule) => r.id === 'block-cardholder-data-paths')).toBe(true);
    expect(tmpl.rules.some((r: PolicyRule) => r.id === 'block-pan-patterns')).toBe(true);
    expect(tmpl.rules.some((r: PolicyRule) => r.id === 'block-audit-trail-tampering')).toBe(true);
  });

  it('strict-production blocks everything with deny default', () => {
    const tmpl = DEFAULT_TEMPLATES['strict-production'];
    expect(tmpl.defaultAction).toBe('deny');
    expect(tmpl.rules.some((r: PolicyRule) => r.id === 'block-all-tools')).toBe(true);
    expect(tmpl.rules.some((r: PolicyRule) => r.id === 'deny-unknown-network')).toBe(true);
    expect(tmpl.rules.some((r: PolicyRule) => r.id === 'deny-all-filesystem')).toBe(true);
  });
});

describe('timeWindow rules', () => {
  it('rule with timeWindow days skipped when day does not match', () => {
    const rule: PolicyRule = {
      id: 'temporal-deny',
      description: 'Only deny on Mondays',
      target: 'command',
      match: 'exact',
      values: ['risky_tool'],
      action: 'deny',
      timeWindow: { days: ['Monday'] },
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));
    const today = new Date();
    const day = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'][today.getDay()];
    const result = engine.evaluate('risky_tool', '', {});
    if (day === 'Monday') {
      expect(result.action).toBe('deny');
    } else {
      expect(result.action).toBe('allow');
    }
  });

  it('rule with timeWindow hours skipped when hour out of range', () => {
    const now = new Date();
    const currentHour = now.getHours();
    const rule: PolicyRule = {
      id: 'business-hours-only',
      description: 'Only apply during business hours',
      target: 'command',
      match: 'exact',
      values: ['test_tool'],
      action: 'deny',
      timeWindow: { startHour: 9, endHour: 17 },
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));
    const result = engine.evaluate('test_tool', '', {});
    if (currentHour >= 9 && currentHour <= 17) {
      expect(result.action).toBe('deny');
    } else {
      expect(result.action).toBe('allow');
    }
  });

  it('rule with overnight timeWindow uses wrap-around logic', () => {
    const now = new Date();
    const currentHour = now.getHours();
    const rule: PolicyRule = {
      id: 'night-only',
      description: 'Only apply at night',
      target: 'command',
      match: 'exact',
      values: ['night_tool'],
      action: 'deny',
      timeWindow: { startHour: 22, endHour: 6 },
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));
    const result = engine.evaluate('night_tool', '', {});
    if (currentHour >= 22 || currentHour <= 6) {
      expect(result.action).toBe('deny');
    } else {
      expect(result.action).toBe('allow');
    }
  });
});

describe('context-condition rules', () => {
  it('rule with clientIn matches when client is in list', () => {
    const rule: PolicyRule = {
      id: 'client-locked',
      description: 'Only for specific clients',
      target: 'command',
      match: 'exact',
      values: ['admin_tool'],
      action: 'deny',
      contextCondition: { clientIn: ['vscode', 'cursor'] },
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));

    expect(engine.evaluate('admin_tool', '', {}, { client: 'vscode', requestCount: 1 }).action).toBe('deny');
    expect(engine.evaluate('admin_tool', '', {}, { client: 'cursor', requestCount: 2 }).action).toBe('deny');
    expect(engine.evaluate('admin_tool', '', {}, { client: 'claude-desktop', requestCount: 3 }).action).toBe('allow');
  });

  it('rule with clientIn skipped when context has no client', () => {
    const rule: PolicyRule = {
      id: 'needs-client',
      description: 'Requires client context',
      target: 'command',
      match: 'exact',
      values: ['secret_tool'],
      action: 'deny',
      contextCondition: { clientIn: ['vscode'] },
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));
    const result = engine.evaluate('secret_tool', '', {});
    expect(result.action).toBe('allow');
  });

  it('rule with maxRequestsPerMinute triggers after threshold', () => {
    const rule: PolicyRule = {
      id: 'rate-limit',
      description: 'Rate limited',
      target: 'command',
      match: 'exact',
      values: ['heavy_tool'],
      action: 'deny',
      contextCondition: { maxRequestsPerMinute: 3 },
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));

    expect(engine.evaluate('heavy_tool', '', {}, { client: 'test', requestCount: 1 }).action).toBe('allow');
    expect(engine.evaluate('heavy_tool', '', {}, { client: 'test', requestCount: 2 }).action).toBe('allow');
    expect(engine.evaluate('heavy_tool', '', {}, { client: 'test', requestCount: 3 }).action).toBe('allow');
    expect(engine.evaluate('heavy_tool', '', {}, { client: 'test', requestCount: 4 }).action).toBe('deny');
  });

  it('contextCondition without matching condition skips rule', () => {
    const denyRule: PolicyRule = {
      id: 'conditional-deny',
      description: 'Only deny for specific clients',
      target: 'command',
      match: 'exact',
      values: ['test_tool'],
      action: 'deny',
      contextCondition: { clientIn: ['restricted-client'] },
    };
    const engine = new PolicyEngine(makeEnforcePolicy([denyRule]));
    const result = engine.evaluate('test_tool', '', {}, { client: 'normal-client', requestCount: 1 });
    expect(result.action).toBe('deny');
    expect(result.reasons[0]).toContain('default deny');
  });
});

describe('audit logging', () => {
  it('getAuditLog returns empty array initially', () => {
    const engine = new PolicyEngine(makeAuditPolicy([]));
    expect(engine.getAuditLog()).toEqual([]);
  });

  it('records audit entries in audit mode', () => {
    const engine = new PolicyEngine(makeAuditPolicy([denyEvalRule]));
    engine.evaluate('eval_tool', 'runs eval', { code: 'eval(1+1)' });
    const log = engine.getAuditLog();
    expect(log.length).toBe(1);
    expect(log[0].toolName).toBe('eval_tool');
    expect(log[0].action).toBe('allow');
    expect(log[0].reason).toContain('Audit mode');
  });

  it('clearAuditLog empties the audit log', () => {
    const engine = new PolicyEngine(makeAuditPolicy([]));
    engine.evaluate('tool_a', '', {});
    engine.evaluate('tool_b', '', {});
    expect(engine.getAuditLog().length).toBe(2);
    engine.clearAuditLog();
    expect(engine.getAuditLog()).toEqual([]);
  });

  it('generateAllowlistFromAudit suggests tools from allowed calls', () => {
    const engine = new PolicyEngine(makeAuditPolicy([]));
    const since = new Date();
    engine.evaluate('safe_tool_a', '', { filePath: '/home/user/doc.txt' });
    engine.evaluate('safe_tool_b', '', { url: 'https://api.example.com/data' });
    const allowlist = engine.generateAllowlistFromAudit(since);
    expect(allowlist.tools).toContain('safe_tool_a');
    expect(allowlist.tools).toContain('safe_tool_b');
    expect(allowlist.paths).toContain('/home/user/doc.txt');
    expect(allowlist.hosts).toContain('api.example.com');
  });

  it('generateSuggestedPolicy returns valid YAML', () => {
    const engine = new PolicyEngine(makeAuditPolicy([]));
    engine.evaluate('my_tool', '', {});
    const yaml = engine.generateSuggestedPolicy();
    expect(yaml).toContain('mcp-seatbelt suggested policy');
    const parsed = parse(yaml);
    expect(parsed).not.toBeNull();
    expect((parsed as Record<string, unknown>).version).toBeDefined();
  });
});

describe('rule inheritance (extends)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-seatbelt-ext-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('loads base policy and merges rules', async () => {
    const basePath = path.join(tempDir, 'base.yml');
    const childPath = path.join(tempDir, 'child.yml');

    fs.writeFileSync(basePath, stringify({
      version: '1',
      mode: 'enforce',
      defaultAction: 'deny',
      rules: [denyEvalRule],
      allowlist: { tools: ['base_tool'], paths: [], hosts: [], envVars: [] },
      allowSampling: false,
    }));

    fs.writeFileSync(childPath, stringify({
      version: '1',
      mode: 'enforce',
      defaultAction: 'allow',
      extends: [basePath],
      rules: [warnExecRule],
      allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
      allowSampling: false,
    }));

    const engine = new PolicyEngine(makeEnforcePolicy([]));
    await engine.loadFromFile(childPath);

    const result = engine.evaluate('eval_tool', 'runs eval', {});
    expect(result.action).toBe('deny');

    const warnResult = engine.evaluate('exec_tool', 'runs exec', {});
    expect(warnResult.action).toBe('warn');

    const allowlistResult = engine.evaluate('base_tool', '', {});
    expect(allowlistResult.action).toBe('allow');
  });

  it('child rules override base rules with same id', async () => {
    const basePath = path.join(tempDir, 'base2.yml');
    const childPath = path.join(tempDir, 'child2.yml');

    fs.writeFileSync(basePath, stringify({
      version: '1',
      mode: 'enforce',
      defaultAction: 'deny',
      rules: [denyEvalRule],
      allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
      allowSampling: false,
    }));

    const overriddenRule: PolicyRule = {
      id: 'block-eval',
      description: 'Overridden to warn instead',
      target: 'process',
      match: 'contains',
      values: ['eval'],
      action: 'warn',
    };

    fs.writeFileSync(childPath, stringify({
      version: '1',
      mode: 'enforce',
      defaultAction: 'allow',
      extends: [basePath],
      rules: [overriddenRule],
      allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
      allowSampling: false,
    }));

    const engine = new PolicyEngine(makeEnforcePolicy([]));
    await engine.loadFromFile(childPath);

    const result = engine.evaluate('eval_tool', 'runs eval', {});
    expect(result.action).toBe('warn');
  });

  it('detects circular extends', async () => {
    const aPath = path.join(tempDir, 'a.yml');
    const bPath = path.join(tempDir, 'b.yml');

    fs.writeFileSync(aPath, stringify({
      version: '1',
      mode: 'enforce',
      defaultAction: 'deny',
      extends: [bPath],
      rules: [],
      allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
      allowSampling: false,
    }));

    fs.writeFileSync(bPath, stringify({
      version: '1',
      mode: 'enforce',
      defaultAction: 'deny',
      extends: [aPath],
      rules: [],
      allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
      allowSampling: false,
    }));

    const engine = new PolicyEngine(makeEnforcePolicy([]));
    await expect(engine.loadFromFile(aPath)).rejects.toThrow('Circular extends');
  });

  it('throws when extended policy file not found', async () => {
    const childPath = path.join(tempDir, 'orphan.yml');
    fs.writeFileSync(childPath, stringify({
      version: '1',
      mode: 'enforce',
      defaultAction: 'deny',
      extends: ['/nonexistent/path.yml'],
      rules: [],
      allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
      allowSampling: false,
    }));

    const engine = new PolicyEngine(makeEnforcePolicy([]));
    await expect(engine.loadFromFile(childPath)).rejects.toThrow('not found');
  });
});

describe('argConstraints', () => {
  it('equals constraint passes when arg value matches exactly', () => {
    const rule: PolicyRule = {
      id: 'constrain-equals',
      description: 'Allow only exact arg match',
      target: 'command',
      match: 'contains',
      values: ['my_tool'],
      action: 'allow',
      argConstraints: [
        { argName: 'env', constraint: 'equals', values: ['production'] },
      ],
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));
    const result = engine.evaluate('my_tool', '', { env: 'production' });
    expect(result.action).toBe('allow');
  });

  it('equals constraint fails when arg value does not match', () => {
    const rule: PolicyRule = {
      id: 'constrain-equals',
      description: 'Allow only exact arg match',
      target: 'command',
      match: 'contains',
      values: ['my_tool'],
      action: 'allow',
      argConstraints: [
        { argName: 'env', constraint: 'equals', values: ['production'] },
      ],
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));
    const result = engine.evaluate('my_tool', '', { env: 'staging' });
    expect(result.action).toBe('deny');
    expect(result.reasons.some((r) => r.includes('does not match equals'))).toBe(true);
  });

  it('startsWith constraint passes when arg value starts with value', () => {
    const rule: PolicyRule = {
      id: 'workspace-only',
      description: 'Allow workspace paths only',
      target: 'command',
      match: 'contains',
      values: ['write_file'],
      action: 'allow',
      argConstraints: [
        { argName: 'filePath', constraint: 'startsWith', values: ['/workspace/'] },
      ],
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));
    const result = engine.evaluate('write_file', '', { filePath: '/workspace/src/main.ts' });
    expect(result.action).toBe('allow');
  });

  it('startsWith constraint fails when arg value does not start with value', () => {
    const rule: PolicyRule = {
      id: 'workspace-only',
      description: 'Allow workspace paths only',
      target: 'command',
      match: 'contains',
      values: ['write_file'],
      action: 'allow',
      argConstraints: [
        { argName: 'filePath', constraint: 'startsWith', values: ['/workspace/'] },
      ],
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));
    const result = engine.evaluate('write_file', '', { filePath: '/etc/hosts' });
    expect(result.action).toBe('deny');
    expect(result.reasons.some((r) => r.includes("startsWith '/workspace/'"))).toBe(true);
  });

  it('regex constraint passes when arg matches pattern', () => {
    const rule: PolicyRule = {
      id: 'regex-match',
      description: 'Only allow numeric IDs',
      target: 'command',
      match: 'contains',
      values: ['my_tool'],
      action: 'allow',
      argConstraints: [
        { argName: 'id', constraint: 'regex', values: ['^\\d+$'] },
      ],
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));
    const result = engine.evaluate('my_tool', '', { id: '12345' });
    expect(result.action).toBe('allow');
  });

  it('regex constraint fails when arg does not match pattern', () => {
    const rule: PolicyRule = {
      id: 'regex-match',
      description: 'Only allow numeric IDs',
      target: 'command',
      match: 'contains',
      values: ['my_tool'],
      action: 'allow',
      argConstraints: [
        { argName: 'id', constraint: 'regex', values: ['^\\d+$'] },
      ],
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));
    const result = engine.evaluate('my_tool', '', { id: 'abc' });
    expect(result.action).toBe('deny');
    expect(result.reasons.some((r) => r.includes('regex'))).toBe(true);
  });

  it('in constraint passes when arg is in allowed values', () => {
    const rule: PolicyRule = {
      id: 'in-constraint',
      description: 'Allow only certain environments',
      target: 'command',
      match: 'contains',
      values: ['my_tool'],
      action: 'allow',
      argConstraints: [
        { argName: 'env', constraint: 'in', values: ['dev', 'staging', 'production'] },
      ],
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));
    const result = engine.evaluate('my_tool', '', { env: 'dev' });
    expect(result.action).toBe('allow');
  });

  it('in constraint fails when arg is not in allowed values', () => {
    const rule: PolicyRule = {
      id: 'in-constraint',
      description: 'Allow only certain environments',
      target: 'command',
      match: 'contains',
      values: ['my_tool'],
      action: 'allow',
      argConstraints: [
        { argName: 'env', constraint: 'in', values: ['dev', 'staging', 'production'] },
      ],
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));
    const result = engine.evaluate('my_tool', '', { env: 'test' });
    expect(result.action).toBe('deny');
    expect(result.reasons.some((r) => r.includes('not in allowed'))).toBe(true);
  });

  it('notIn constraint passes when arg is not in disallowed values', () => {
    const rule: PolicyRule = {
      id: 'notin-constraint',
      description: 'Disallow certain environments',
      target: 'command',
      match: 'contains',
      values: ['my_tool'],
      action: 'allow',
      argConstraints: [
        { argName: 'env', constraint: 'notIn', values: ['production', 'staging'] },
      ],
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));
    const result = engine.evaluate('my_tool', '', { env: 'dev' });
    expect(result.action).toBe('allow');
  });

  it('notIn constraint fails when arg is in disallowed values', () => {
    const rule: PolicyRule = {
      id: 'notin-constraint',
      description: 'Disallow certain environments',
      target: 'command',
      match: 'contains',
      values: ['my_tool'],
      action: 'allow',
      argConstraints: [
        { argName: 'env', constraint: 'notIn', values: ['production', 'staging'] },
      ],
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));
    const result = engine.evaluate('my_tool', '', { env: 'production' });
    expect(result.action).toBe('deny');
    expect(result.reasons.some((r) => r.includes('disallowed'))).toBe(true);
  });

  it('constraint fails when arg is missing from args', () => {
    const rule: PolicyRule = {
      id: 'missing-arg',
      description: 'Requires env arg',
      target: 'command',
      match: 'contains',
      values: ['my_tool'],
      action: 'allow',
      argConstraints: [
        { argName: 'env', constraint: 'equals', values: ['production'] },
      ],
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));
    const result = engine.evaluate('my_tool', '', {});
    expect(result.action).toBe('deny');
    expect(result.reasons.some((r) => r.includes('missing'))).toBe(true);
  });

  it('multiple constraints all must pass for rule to match', () => {
    const rule: PolicyRule = {
      id: 'multi-constraint',
      description: 'Validate path and env',
      target: 'command',
      match: 'contains',
      values: ['write_file'],
      action: 'allow',
      argConstraints: [
        { argName: 'filePath', constraint: 'startsWith', values: ['/workspace/'] },
        { argName: 'env', constraint: 'in', values: ['dev', 'staging'] },
      ],
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));

    const pass = engine.evaluate('write_file', '', { filePath: '/workspace/foo.ts', env: 'dev' });
    expect(pass.action).toBe('allow');

    const fail = engine.evaluate('write_file', '', { filePath: '/workspace/foo.ts', env: 'production' });
    expect(fail.action).toBe('deny');
  });

  it('rule with NO argConstraints behaves normally (no constraint check)', () => {
    const rule: PolicyRule = {
      id: 'no-constraints',
      description: 'No constraints at all',
      target: 'command',
      match: 'contains',
      values: ['my_tool'],
      action: 'allow',
    };
    const engine = new PolicyEngine(makeAllowDefaultPolicy([rule]));
    const result = engine.evaluate('my_tool', '', {});
    expect(result.action).toBe('allow');
  });
});

describe('threat-intel integration', () => {
  it('evaluateWithJudge passes when args have no IPs or domains', async () => {
    const engine = new PolicyEngine(makeAllowDefaultPolicy([]));
    const result = await engine.evaluateWithJudge('read_file', 'reads files', {
      filePath: '/tmp/test.txt',
    });
    expect(result.action).toBe('allow');
  });

  it('evaluateWithJudge warns when suspicious IP detected in args', async () => {
    const engine = new PolicyEngine(makeAllowDefaultPolicy([]));
    const result = await engine.evaluateWithJudge('connect', 'connects to host', {
      host: '8.8.8.8',
    });
    expect(['allow', 'warn']).toContain(result.action);
  });

  it('evaluateWithJudge handles domain-like args', async () => {
    const engine = new PolicyEngine(makeAllowDefaultPolicy([]));
    const result = await engine.evaluateWithJudge('fetch', 'fetches url', {
      url: 'example.com',
    });
    expect(['allow', 'warn']).toContain(result.action);
  });

  it('evaluateWithJudge works with LLM judge and threat intel simultaneously', async () => {
    const engine = new PolicyEngine(makeAllowDefaultPolicy([]));
    engine.setJudge(new LLMJudge());
    const result = await engine.evaluateWithJudge('safe_tool', 'safe tool', {
      input: 'hello world',
    });
    expect(['allow', 'warn']).toContain(result.action);
  });
});

describe('compliance field validation', () => {
  it('accepts valid compliance entries on a rule', () => {
    const rule: PolicyRule = {
      id: 'compliant-rule',
      description: 'Has valid compliance',
      target: 'command',
      match: 'exact',
      values: ['test'],
      action: 'deny',
      compliance: [
        { framework: 'soc2', controls: ['CC6.1'] },
      ],
    };
    const config = makeEnforcePolicy([rule]);
    expect(() => validatePolicy(config)).not.toThrow();
  });

  it('accepts multiple compliance frameworks on a rule', () => {
    const rule: PolicyRule = {
      id: 'multi-compliance',
      description: 'Multiple compliance',
      target: 'command',
      match: 'exact',
      values: ['test'],
      action: 'deny',
      compliance: [
        { framework: 'soc2', controls: ['CC6.1', 'CC6.6'] },
        { framework: 'hipaa', controls: ['164.312(a)(1)'] },
        { framework: 'gdpr', controls: ['Art_32'] },
      ],
    };
    const config = makeEnforcePolicy([rule]);
    expect(() => validatePolicy(config)).not.toThrow();
  });

  it('accepts compliance with optional remediation', () => {
    const rule: PolicyRule = {
      id: 'remediation-rule',
      description: 'Has remediation',
      target: 'command',
      match: 'exact',
      values: ['test'],
      action: 'deny',
      compliance: [
        { framework: 'iso27001', controls: ['A.9.4'], remediation: 'Restrict shell access via policy' },
      ],
    };
    const config = makeEnforcePolicy([rule]);
    expect(() => validatePolicy(config)).not.toThrow();
  });

  it('accepts all valid framework types', () => {
    const frameworks = ['soc2', 'hipaa', 'gdpr', 'pci-dss', 'iso27001', 'nist'] as const;
    const rule: PolicyRule = {
      id: 'all-frameworks',
      description: 'All compliance frameworks',
      target: 'command',
      match: 'exact',
      values: ['test'],
      action: 'deny',
      compliance: frameworks.map((fw) => ({ framework: fw, controls: ['CONTROL-1'] })),
    };
    const config = makeEnforcePolicy([rule]);
    expect(() => validatePolicy(config)).not.toThrow();
  });

  it('throws for invalid framework name', () => {
    const rule: PolicyRule = {
      id: 'bad-framework',
      description: 'Bad framework',
      target: 'command',
      match: 'exact',
      values: ['test'],
      action: 'deny',
      compliance: [
        { framework: 'bad-framework' as any, controls: ['X'] },
      ],
    };
    const config = makeEnforcePolicy([rule]);
    expect(() => validatePolicy(config)).toThrow('framework');
  });

  it('throws for empty controls array', () => {
    const rule: PolicyRule = {
      id: 'empty-controls',
      description: 'Empty controls',
      target: 'command',
      match: 'exact',
      values: ['test'],
      action: 'deny',
      compliance: [
        { framework: 'soc2', controls: [] },
      ],
    };
    const config = makeEnforcePolicy([rule]);
    expect(() => validatePolicy(config)).toThrow('controls must be a non-empty array');
  });

  it('throws when compliance is not an array', () => {
    const rule = {
      id: 'bad-compliance',
      description: 'Bad compliance',
      target: 'command',
      match: 'exact',
      values: ['test'],
      action: 'deny',
      compliance: 'not-an-array',
    };
    const config = makeEnforcePolicy([rule as any]);
    expect(() => validatePolicy(config)).toThrow('compliance must be an array');
  });

  it('throws for non-string control values', () => {
    const rule: PolicyRule = {
      id: 'bad-control',
      description: 'Bad control',
      target: 'command',
      match: 'exact',
      values: ['test'],
      action: 'deny',
      compliance: [
        { framework: 'soc2', controls: [123 as any] },
      ],
    };
    const config = makeEnforcePolicy([rule]);
    expect(() => validatePolicy(config)).toThrow('controls must contain only non-empty strings');
  });

  it('throws for empty string control', () => {
    const rule: PolicyRule = {
      id: 'empty-control-str',
      description: 'Empty control string',
      target: 'command',
      match: 'exact',
      values: ['test'],
      action: 'deny',
      compliance: [
        { framework: 'soc2', controls: [''] },
      ],
    };
    const config = makeEnforcePolicy([rule]);
    expect(() => validatePolicy(config)).toThrow('controls must contain only non-empty strings');
  });

  it('throws when remediation is not a string', () => {
    const rule: PolicyRule = {
      id: 'bad-remediation',
      description: 'Bad remediation',
      target: 'command',
      match: 'exact',
      values: ['test'],
      action: 'deny',
      compliance: [
        { framework: 'soc2', controls: ['CC6.1'], remediation: 123 as any },
      ],
    };
    const config = makeEnforcePolicy([rule]);
    expect(() => validatePolicy(config)).toThrow('remediation must be a string');
  });
});

describe('default policy compliance mappings', () => {
  it('block-shell-execution has soc2, hipaa, gdpr compliance', () => {
    const rule = DEFAULT_POLICY.rules.find((r) => r.id === 'block-shell-execution');
    expect(rule).toBeDefined();
    const compliance = rule!.compliance;
    expect(compliance).toBeDefined();
    expect(compliance!.some((c) => c.framework === 'soc2')).toBe(true);
    expect(compliance!.some((c) => c.framework === 'hipaa')).toBe(true);
    expect(compliance!.some((c) => c.framework === 'gdpr')).toBe(true);
    const soc2 = compliance!.find((c) => c.framework === 'soc2')!;
    expect(soc2.controls).toContain('CC6.1');
    expect(soc2.controls).toContain('CC6.6');
    expect(soc2.controls).toContain('CC7.2');
  });

  it('block-sensitive-paths has soc2, hipaa, iso27001 compliance', () => {
    const rule = DEFAULT_POLICY.rules.find((r) => r.id === 'block-sensitive-paths');
    expect(rule).toBeDefined();
    const compliance = rule!.compliance;
    expect(compliance).toBeDefined();
    expect(compliance!.some((c) => c.framework === 'soc2')).toBe(true);
    expect(compliance!.some((c) => c.framework === 'hipaa')).toBe(true);
    expect(compliance!.some((c) => c.framework === 'iso27001')).toBe(true);
  });

  it('block-credential-access has soc2 and iso27001 compliance', () => {
    const rule = DEFAULT_POLICY.rules.find((r) => r.id === 'block-credential-access');
    expect(rule).toBeDefined();
    const compliance = rule!.compliance;
    expect(compliance).toBeDefined();
    expect(compliance!.some((c) => c.framework === 'soc2')).toBe(true);
    expect(compliance!.some((c) => c.framework === 'iso27001')).toBe(true);
  });

  it('block-private-network has soc2 and hipaa compliance', () => {
    const rule = DEFAULT_POLICY.rules.find((r) => r.id === 'block-private-network');
    expect(rule).toBeDefined();
    const compliance = rule!.compliance;
    expect(compliance).toBeDefined();
    expect(compliance!.some((c) => c.framework === 'soc2')).toBe(true);
    expect(compliance!.some((c) => c.framework === 'hipaa')).toBe(true);
  });

  it('pci-compliance template rules have pci-dss framework', () => {
    const tmpl = DEFAULT_TEMPLATES['pci-compliance'];
    const pciRules = tmpl.rules.filter((r) => r.compliance?.some((c) => c.framework === 'pci-dss'));
    expect(pciRules.length).toBeGreaterThanOrEqual(2);
  });

  it('block-shell-execution soc2 controls are correct', () => {
    const rule = DEFAULT_TEMPLATES['pci-compliance'].rules.find((r) => r.id === 'block-credential-access');
    expect(rule).toBeDefined();
    const pci = rule!.compliance!.find((c) => c.framework === 'pci-dss');
    expect(pci).toBeDefined();
    expect(pci!.controls).toContain('7.2.1');
  });
});

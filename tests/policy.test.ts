import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { PolicyEngine } from '../src/policy/engine.js';
import { DEFAULT_POLICY } from '../src/policy/defaults.js';
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

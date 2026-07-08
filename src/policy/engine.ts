import type { PolicyConfig, PolicyRule } from '../types.js';
import { load, dump } from 'js-yaml';
import { readFile, writeFile } from 'node:fs/promises';
import { validatePolicy } from './schema.js';

interface EvaluateResult {
  action: 'allow' | 'deny' | 'warn';
  reasons: string[];
}

interface EngineStats {
  rules: number;
  allowlisted: number;
}

export class PolicyEngine {
  private config: PolicyConfig;

  constructor(config: PolicyConfig) {
    this.config = structuredClone(config);
  }

  evaluate(toolName: string, toolDescription: string, args: Record<string, unknown>): EvaluateResult {
    if (this.config.allowlist.tools.includes(toolName)) {
      return { action: 'allow', reasons: [`Tool "${toolName}" is explicitly allowlisted`] };
    }

    if (this.config.mode === 'audit') {
      return { action: 'allow', reasons: ['Audit mode: all calls allowed'] };
    }

    let action: 'allow' | 'deny' | 'warn' = this.config.defaultAction;
    const reasons: string[] = [];

    for (const rule of this.config.rules) {
      if (this.ruleMatches(rule, toolName, toolDescription, args)) {
        reasons.push(`[${rule.id}] ${rule.description}`);

        if (rule.action === 'deny') {
          action = 'deny';
          break;
        }
        if (rule.action === 'warn' && action !== 'deny') {
          action = 'warn';
        }
        if (rule.action === 'allow' && action !== 'deny' && action !== 'warn') {
          action = 'allow';
        }
      }
    }

    if (reasons.length === 0) {
      reasons.push(
        action === 'deny'
          ? 'No matching allow rule found (default deny)'
          : 'No matching rule found',
      );
    }

    return { action, reasons };
  }

  addRule(rule: PolicyRule): void {
    const existing = this.config.rules.findIndex((r) => r.id === rule.id);
    if (existing !== -1) {
      throw new Error(`Rule with id "${rule.id}" already exists`);
    }
    this.config.rules.push(rule);
  }

  removeRule(id: string): void {
    const index = this.config.rules.findIndex((r) => r.id === id);
    if (index === -1) {
      throw new Error(`Rule with id "${id}" not found`);
    }
    this.config.rules.splice(index, 1);
  }

  updateRule(id: string, partial: Partial<PolicyRule>): void {
    const index = this.config.rules.findIndex((r) => r.id === id);
    if (index === -1) {
      throw new Error(`Rule with id "${id}" not found`);
    }
    this.config.rules[index] = { ...this.config.rules[index], ...partial };
  }

  async loadFromFile(yamlPath: string): Promise<void> {
    const content = await readFile(yamlPath, 'utf-8');
    const parsed = load(content) as unknown;
    this.config = validatePolicy(parsed);
  }

  async saveToFile(yamlPath: string): Promise<void> {
    const yaml = dump(
      {
        version: this.config.version,
        mode: this.config.mode,
        defaultAction: this.config.defaultAction,
        rules: this.config.rules,
        allowlist: this.config.allowlist,
      },
      { indent: 2, lineWidth: -1, noRefs: true },
    );
    await writeFile(yamlPath, yaml, 'utf-8');
  }

  getStats(): EngineStats {
    return {
      rules: this.config.rules.length,
      allowlisted: this.config.allowlist.tools.length,
    };
  }

  private ruleMatches(
    rule: PolicyRule,
    toolName: string,
    toolDescription: string,
    args: Record<string, unknown>,
  ): boolean {
    const argStrings = this.collectArgStrings(args);

    for (const value of rule.values) {
      switch (rule.target) {
        case 'command':
          if (
            this.matchesString(toolName, value, rule.match) ||
            this.matchesString(toolDescription, value, rule.match)
          ) {
            return true;
          }
          break;

        case 'file':
          if (argStrings.some((arg) => this.matchesString(arg, value, rule.match))) {
            return true;
          }
          break;

        case 'network':
          if (argStrings.some((arg) => this.matchesString(arg, value, rule.match))) {
            return true;
          }
          break;

        case 'env':
          if (argStrings.some((arg) => this.matchesString(arg, value, rule.match))) {
            return true;
          }
          // Also check env var keys if args includes env object
          if (this.matchesEnvVars(args, value, rule.match)) {
            return true;
          }
          break;

        case 'process':
          if (
            this.matchesString(toolName, value, rule.match) ||
            this.matchesString(toolDescription, value, rule.match) ||
            argStrings.some((arg) => this.matchesString(arg, value, rule.match))
          ) {
            return true;
          }
          break;
      }
    }

    return false;
  }

  private matchesString(input: string, value: string, matchType: string): boolean {
    switch (matchType) {
      case 'exact':
        return input === value;

      case 'pattern':
        try {
          return new RegExp(value, 'i').test(input);
        } catch {
          return false;
        }

      case 'contains':
        return input.toLowerCase().includes(value.toLowerCase());

      default:
        return false;
    }
  }

  private matchesEnvVars(
    args: Record<string, unknown>,
    pattern: string,
    matchType: string,
  ): boolean {
    const env = args.env || args.environment || args.envVars;
    if (env && typeof env === 'object') {
      const keys = Object.keys(env as Record<string, unknown>);
      return keys.some((key) => this.matchesString(key, pattern, matchType));
    }
    return false;
  }

  private collectArgStrings(args: Record<string, unknown>): string[] {
    const result: string[] = [];

    for (const value of Object.values(args)) {
      if (typeof value === 'string') {
        result.push(value);
      } else if (Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === 'string') {
            result.push(item);
          } else if (item && typeof item === 'object') {
            result.push(JSON.stringify(item));
          }
        }
      } else if (value && typeof value === 'object' && !Array.isArray(value)) {
        // Flatten nested object values but skip env-like objects (handled separately)
        for (const v of Object.values(value as Record<string, unknown>)) {
          if (typeof v === 'string') {
            result.push(v);
          }
        }
      }
    }

    return result;
  }
}

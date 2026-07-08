import type { PolicyConfig, PolicyRule } from '../types.js';
import { load, dump } from 'js-yaml';
import { readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve, dirname, isAbsolute } from 'node:path';
import { validatePolicy } from './schema.js';

export interface EvaluateResult {
  action: 'allow' | 'deny' | 'warn' | 'redact';
  reasons: string[];
  redactedKeys?: string[];
}

export interface EvaluateContext {
  client: string;
  requestCount: number;
}

export interface AuditEntry {
  toolName: string;
  description: string;
  args: Record<string, unknown>;
  action: 'allow' | 'deny' | 'warn' | 'redact';
  timestamp: string;
  reason: string;
  context?: EvaluateContext;
}

interface EngineStats {
  rules: number;
  allowlisted: number;
}

const DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

export class PolicyEngine {
  private config: PolicyConfig;
  private auditLog: AuditEntry[] = [];
  private requestTimestamps: Map<string, number[]> = new Map();

  constructor(config: PolicyConfig) {
    this.config = structuredClone(config);
  }

  evaluate(toolName: string, toolDescription: string, args: Record<string, unknown>, _context?: EvaluateContext): EvaluateResult {
    const reasons: string[] = [];
    const redactedKeys = new Set<string>();

    for (const rule of this.config.rules) {
      if (rule.action === 'redact') {
        if (rule.timeWindow && !this.isWithinTimeWindow(rule.timeWindow)) continue;
        const keys = this.getRedactKeys(args, rule);
        for (const key of keys) {
          redactedKeys.add(key);
          if (!reasons.some((r) => r.startsWith(`[${rule.id}]`))) {
            reasons.push(`[${rule.id}] ${rule.description}`);
          }
        }
      }
    }

    if (this.config.allowlist.tools.includes(toolName)) {
      return {
        action: 'allow',
        reasons: [`Tool "${toolName}" is explicitly allowlisted`],
      };
    }

    if (this.config.mode === 'audit') {
      const action: EvaluateResult['action'] = redactedKeys.size > 0 ? 'redact' : 'allow';
      if (reasons.length === 0 && action === 'allow') {
        reasons.push('Audit mode: all calls allowed');
      }
      this.recordAudit(toolName, toolDescription, args, action, reasons.join('; '), _context);
      return {
        action,
        reasons,
        redactedKeys: redactedKeys.size > 0 ? [...redactedKeys] : undefined,
      };
    }

    let action: 'allow' | 'deny' | 'warn' | 'redact' = this.config.defaultAction as 'allow' | 'deny' | 'warn';

    for (const rule of this.config.rules) {
      if (rule.action === 'redact') continue;

      if (rule.timeWindow && !this.isWithinTimeWindow(rule.timeWindow)) continue;

      if (this.ruleMatches(rule, toolName, toolDescription, args)) {
        if (rule.contextCondition && !this.matchesContextCondition(rule, _context)) continue;

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

    if (redactedKeys.size > 0 && action !== 'deny') {
      action = 'redact';
    }

    if (reasons.length === 0) {
      reasons.push(
        action === 'deny'
          ? 'No matching allow rule found (default deny)'
          : 'No matching rule found',
      );
    }

    return {
      action,
      reasons,
      redactedKeys: redactedKeys.size > 0 ? [...redactedKeys] : undefined,
    };
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
    this.config = await this.resolveAndLoad(yamlPath, new Set<string>());
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

  isSamplingAllowed(): boolean {
    return this.config.allowSampling !== false;
  }

  getAuditLog(): AuditEntry[] {
    return [...this.auditLog];
  }

  clearAuditLog(): void {
    this.auditLog = [];
  }

  getStats(): EngineStats {
    return {
      rules: this.config.rules.length,
      allowlisted: this.config.allowlist.tools.length,
    };
  }

  generateAllowlistFromAudit(since: Date): {
    tools: string[];
    paths: string[];
    hosts: string[];
  } {
    const sinceTs = since.getTime();
    const entries = this.auditLog.filter(
      (e) => new Date(e.timestamp).getTime() >= sinceTs,
    );

    const tools = new Set<string>();
    const paths = new Set<string>();
    const hosts = new Set<string>();

    for (const entry of entries) {
      if (entry.action === 'deny' || entry.action === 'warn') continue;
      tools.add(entry.toolName);

      for (const value of Object.values(entry.args)) {
        if (typeof value === 'string') {
          if (value.startsWith('/') || value.includes('\\')) {
            paths.add(value);
          }
          try {
            const url = new URL(value);
            hosts.add(url.hostname);
          } catch {}
        }
      }
    }

    return {
      tools: [...tools].sort(),
      paths: [...paths].sort(),
      hosts: [...hosts].sort(),
    };
  }

  generateSuggestedPolicy(): string {
    const allowlist = this.generateAllowlistFromAudit(new Date(0));

    const suggested = {
      version: this.config.version,
      mode: 'enforce',
      defaultAction: 'deny',
      rules: this.config.rules,
      allowlist: {
        tools: allowlist.tools,
        paths: allowlist.paths,
        hosts: allowlist.hosts,
        envVars: this.config.allowlist.envVars,
      },
      allowSampling: this.config.allowSampling,
    };

    const header = [
      '# mcp-seatbelt suggested policy',
      '# Generated from audit log observations',
      '',
    ].join('\n');

    return header + dump(suggested, { indent: 2, lineWidth: -1, noRefs: true });
  }

  private recordAudit(
    toolName: string,
    toolDescription: string,
    args: Record<string, unknown>,
    action: EvaluateResult['action'],
    reason: string,
    context?: EvaluateContext,
  ): void {
    this.auditLog.push({
      toolName,
      description: toolDescription,
      args,
      action,
      timestamp: new Date().toISOString(),
      reason,
      context,
    });
  }

  private isWithinTimeWindow(
    timeWindow: PolicyRule['timeWindow'],
  ): boolean {
    if (!timeWindow) return true;

    const now = new Date();

    if (timeWindow.days && timeWindow.days.length > 0) {
      const currentDay = DAY_NAMES[now.getDay()];
      if (
        !timeWindow.days.some(
          (d) => d.toLowerCase() === currentDay.toLowerCase(),
        )
      ) {
        return false;
      }
    }

    if (
      timeWindow.startHour !== undefined ||
      timeWindow.endHour !== undefined
    ) {
      const currentHour = now.getHours();
      const start = timeWindow.startHour ?? 0;
      const end = timeWindow.endHour ?? 23;

      if (start <= end) {
        if (currentHour < start || currentHour > end) return false;
      } else {
        if (currentHour < start && currentHour > end) return false;
      }
    }

    return true;
  }

  private matchesContextCondition(
    rule: PolicyRule,
    context?: EvaluateContext,
  ): boolean {
    if (!rule.contextCondition) return true;

    if (
      rule.contextCondition.clientIn &&
      rule.contextCondition.clientIn.length > 0
    ) {
      const client = context?.client;
      if (
        !client ||
        !rule.contextCondition.clientIn.some(
          (c) => c.toLowerCase() === client.toLowerCase(),
        )
      ) {
        return false;
      }
    }

    if (rule.contextCondition.maxRequestsPerMinute !== undefined) {
      const key = `${context?.client ?? 'unknown'}:${context?.client ?? 'default'}`;
      if (!this.requestTimestamps.has(key)) {
        this.requestTimestamps.set(key, []);
      }
      const timestamps = this.requestTimestamps.get(key)!;
      const oneMinuteAgo = Date.now() - 60000;
      const recent = timestamps.filter((t) => t > oneMinuteAgo);
      recent.push(Date.now());
      this.requestTimestamps.set(key, recent);

      if (recent.length <= rule.contextCondition.maxRequestsPerMinute) {
        return false;
      }
    }

    return true;
  }

  private async resolveAndLoad(
    filePath: string,
    visited: Set<string>,
  ): Promise<PolicyConfig> {
    const resolved = resolve(filePath);
    if (visited.has(resolved)) {
      throw new Error(`Circular extends detected: ${resolved}`);
    }
    visited.add(resolved);

    const content = await readFile(resolved, 'utf-8');
    const parsed = load(content) as Record<string, unknown> | null;
    if (!parsed || typeof parsed !== 'object') {
      throw new Error(`Invalid policy file: ${resolved}`);
    }

    const baseDir = dirname(resolved);
    const extendsPaths: string[] = Array.isArray(parsed.extends)
      ? (parsed.extends as unknown[]).filter((p): p is string => typeof p === 'string')
      : [];

    const baseConfigs: PolicyConfig[] = [];
    for (const extPath of extendsPaths) {
      const fullPath = isAbsolute(extPath)
        ? extPath
        : resolve(baseDir, extPath);

      if (!existsSync(fullPath)) {
        throw new Error(`Extended policy file not found: ${fullPath}`);
      }

      const baseConfig = await this.resolveAndLoad(fullPath, new Set(visited));
      baseConfigs.push(baseConfig);
    }

    const currentConfig = validatePolicy(parsed);

    if (baseConfigs.length === 0) {
      return currentConfig;
    }

    return this.mergeConfigs(baseConfigs, currentConfig);
  }

  private mergeConfigs(
    baseConfigs: PolicyConfig[],
    currentConfig: PolicyConfig,
  ): PolicyConfig {
    const mergedRules: PolicyRule[] = [];

    for (const base of baseConfigs) {
      for (const rule of base.rules) {
        if (!mergedRules.some((r) => r.id === rule.id)) {
          mergedRules.push(rule);
        }
      }
    }

    for (const rule of currentConfig.rules) {
      const index = mergedRules.findIndex((r) => r.id === rule.id);
      if (index !== -1) {
        mergedRules[index] = rule;
      } else {
        mergedRules.push(rule);
      }
    }

    const mergedAllowlist = {
      tools: [
        ...new Set([
          ...baseConfigs.flatMap((b) => b.allowlist.tools),
          ...currentConfig.allowlist.tools,
        ]),
      ],
      paths: [
        ...new Set([
          ...baseConfigs.flatMap((b) => b.allowlist.paths),
          ...currentConfig.allowlist.paths,
        ]),
      ],
      hosts: [
        ...new Set([
          ...baseConfigs.flatMap((b) => b.allowlist.hosts),
          ...currentConfig.allowlist.hosts,
        ]),
      ],
      envVars: [
        ...new Set([
          ...baseConfigs.flatMap((b) => b.allowlist.envVars),
          ...currentConfig.allowlist.envVars,
        ]),
      ],
    };

    return {
      version: currentConfig.version,
      mode: currentConfig.mode,
      defaultAction: currentConfig.defaultAction,
      rules: mergedRules,
      allowlist: mergedAllowlist,
      allowSampling: currentConfig.allowSampling,
    };
  }

  private getRedactKeys(args: Record<string, unknown>, rule: PolicyRule): string[] {
    const keys: string[] = [];
    for (const key of Object.keys(args)) {
      for (const value of rule.values) {
        if (this.matchesString(key, value, rule.match)) {
          keys.push(key);
          break;
        }
      }
    }
    return keys;
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

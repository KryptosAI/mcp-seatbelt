import type { ArgConstraint, PolicyConfig, PolicyRule } from '../types.js';
import { load, dump } from 'js-yaml';
import { readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve, dirname, isAbsolute } from 'node:path';
import { validatePolicy } from './schema.js';
import type { AuditTrail, AuditEntryInput } from '../audit.js';
import type { JudgeResult } from './llm-judge.js';
import { checkThreatIntel } from './threat-intel.js';

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

export interface ToolProfile {
  toolName: string;
  totalCalls: number;
  hourDistribution: number[];
  typicalArgs: Map<string, { count: number; values: Set<string> }>;
  avgArgSize: number;
  firstSeen: string;
  lastSeen: string;
}

export interface Deviation {
  type: 'new_args' | 'size_anomaly' | 'hour_anomaly' | 'new_tool';
  severity: 'info' | 'warn';
  toolName: string;
  detail: string;
}

const DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

/**
 * Compiled, match-ready form of a single rule value. Precomputing the
 * lowercase form (contains) and RegExp (pattern) once per rule avoids
 * re-allocating them on every evaluate() call.
 */
interface CompiledValue {
  raw: string;
  lower: string | null;
  regex: RegExp | null;
}

interface CompiledRule {
  rule: PolicyRule;
  values: CompiledValue[];
  hits: number;
  order: number;
}

// Shared cache so identical patterns across rules compile exactly once.
const REGEX_CACHE = new Map<string, RegExp | null>();
const REGEX_CACHE_MAX = 512;

function getCachedRegex(source: string, flags: string): RegExp | null {
  const key = `${flags}:${source}`;
  const cached = REGEX_CACHE.get(key);
  if (cached !== undefined) return cached;

  let re: RegExp | null = null;
  try {
    re = new RegExp(source, flags);
  } catch {
    re = null;
  }

  if (REGEX_CACHE.size >= REGEX_CACHE_MAX) {
    const oldest = REGEX_CACHE.keys().next();
    if (!oldest.done) REGEX_CACHE.delete(oldest.value);
  }
  REGEX_CACHE.set(key, re);
  return re;
}

function compileValue(raw: string, matchType: string): CompiledValue {
  return {
    raw,
    lower: matchType === 'contains' ? raw.toLowerCase() : null,
    regex: matchType === 'pattern' ? getCachedRegex(raw, 'i') : null,
  };
}

export class BehavioralBaseline {
  profiles: Map<string, ToolProfile> = new Map();
  private readonly BASELINE_WINDOW = 100;

  observe(toolName: string, args: Record<string, unknown>): void {
    let profile = this.profiles.get(toolName);
    const now = new Date();
    const nowIso = now.toISOString();

    if (!profile) {
      profile = {
        toolName,
        totalCalls: 0,
        hourDistribution: new Array(24).fill(0) as number[],
        typicalArgs: new Map(),
        avgArgSize: 0,
        firstSeen: nowIso,
        lastSeen: nowIso,
      };
      this.profiles.set(toolName, profile);
    }

    profile.totalCalls++;
    profile.hourDistribution[now.getHours()]++;
    profile.lastSeen = nowIso;

    const argSize = JSON.stringify(args).length;
    profile.avgArgSize =
      (profile.avgArgSize * (profile.totalCalls - 1) + argSize) / profile.totalCalls;

    for (const key of Object.keys(args)) {
      let entry = profile.typicalArgs.get(key);
      if (!entry) {
        entry = { count: 0, values: new Set() };
        profile.typicalArgs.set(key, entry);
      }
      entry.count++;
      const val = args[key];
      if (typeof val === 'string' && val.length < 100) {
        if (entry.values.size < 10) {
          entry.values.add(val);
        }
      }
    }
  }

  detectDeviation(toolName: string, args: Record<string, unknown>): Deviation[] {
    const profile = this.profiles.get(toolName);
    const deviations: Deviation[] = [];

    if (!profile) {
      return [{ type: 'new_tool', severity: 'info', toolName, detail: `First time seeing tool "${toolName}"` }];
    }

    if (profile.totalCalls < this.BASELINE_WINDOW) return [];

    const newKeys = Object.keys(args).filter((k) => !profile!.typicalArgs.has(k));
    if (newKeys.length > 0) {
      deviations.push({
        type: 'new_args',
        severity: 'warn',
        toolName,
        detail: `New argument keys never seen before: [${newKeys.join(', ')}]`,
      });
    }

    const argSize = JSON.stringify(args).length;
    if (profile.avgArgSize > 0 && argSize > profile.avgArgSize * 3) {
      deviations.push({
        type: 'size_anomaly',
        severity: 'warn',
        toolName,
        detail: `Arg size ${argSize} bytes exceeds 3x average (${profile.avgArgSize.toFixed(0)})`,
      });
    }

    const currentHour = new Date().getHours();
    if (profile.totalCalls > 10) {
      const mean = profile.totalCalls / 24;
      let variance = 0;
      for (let i = 0; i < 24; i++) {
        variance += Math.pow(profile.hourDistribution[i] - mean, 2);
      }
      variance /= 24;
      const stdDev = Math.sqrt(variance);
      const callsThisHour = profile.hourDistribution[currentHour];

      if (callsThisHour === 0 && profile.hourDistribution.some((h: number) => h > 0)) {
        deviations.push({
          type: 'hour_anomaly',
          severity: 'info',
          toolName,
          detail: `Call at hour ${currentHour}:00 — no prior calls at this hour`,
        });
      } else if (stdDev > 0 && Math.abs(callsThisHour - mean) > 2 * stdDev + 1) {
        deviations.push({
          type: 'hour_anomaly',
          severity: 'info',
          toolName,
          detail: `Call frequency at hour ${currentHour}:00 outside 2σ of normal (${mean.toFixed(1)} ± ${(2 * stdDev).toFixed(1)})`,
        });
      }
    }

    return deviations;
  }

  generateReport(): string {
    const lines: string[] = [];
    const entries = [...this.profiles.entries()].sort((a, b) => b[1].totalCalls - a[1].totalCalls);

    if (entries.length === 0) {
      return 'No behavioral data collected.\n';
    }

    lines.push('Behavioral Baseline Report');
    lines.push('=========================\n');

    for (const [name, profile] of entries) {
      const normalHours: string[] = [];
      const maxCalls = Math.max(...profile.hourDistribution, 1);
      for (let i = 0; i < 24; i++) {
        if (profile.hourDistribution[i] > maxCalls * 0.1) {
          normalHours.push(`${i}:00`);
        }
      }
      const hoursStr = normalHours.length > 0 ? normalHours.join(', ') : 'no pattern';

      const topArgs = [...profile.typicalArgs.entries()]
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 5)
        .map(([k]) => k);

      lines.push(`Tool: ${name}`);
      lines.push(`  Calls: ${profile.totalCalls.toLocaleString()}`);
      lines.push(`  Normal hours: ${hoursStr}`);
      lines.push(`  Typical args: [${topArgs.join(', ')}]`);
      lines.push(`  Avg arg size: ${profile.avgArgSize.toFixed(0)} bytes`);
      lines.push(`  First seen: ${profile.firstSeen}`);
      lines.push(`  Last seen: ${profile.lastSeen}`);
      lines.push('');
    }

    return lines.join('\n');
  }
}

export class PolicyEngine {
  private config: PolicyConfig;
  private auditLog: AuditEntry[] = [];
  private requestTimestamps: Map<string, number[]> = new Map();
  private auditTrail: AuditTrail | null = null;
  private judgeImpl: import('./llm-judge.js').LLMJudge | null = null;
  private baseliner: BehavioralBaseline = new BehavioralBaseline();

  // Lazily built compiled view of config.rules. `compiledRules` preserves
  // config order (used by order-sensitive paths); `sortedMatchRules` is the
  // frequency-ordered evaluation view for the enforce loop.
  private static readonly RESORT_INTERVAL = 2048;
  private compiledRules: CompiledRule[] | null = null;
  private compiledRedactRules: CompiledRule[] = [];
  private sortedMatchRules: CompiledRule[] = [];
  private evalsUntilResort = PolicyEngine.RESORT_INTERVAL;

  constructor(config: PolicyConfig) {
    this.config = structuredClone(config);
  }

  private invalidateCompiled(): void {
    this.compiledRules = null;
  }

  private getCompiled(): void {
    if (this.compiledRules !== null) return;

    const all: CompiledRule[] = this.config.rules.map((rule, i) => ({
      rule,
      values: rule.values.map((v) => compileValue(v, rule.match)),
      hits: 0,
      order: i,
    }));

    this.compiledRules = all;
    this.compiledRedactRules = all.filter((c) => c.rule.action === 'redact');
    this.sortedMatchRules = all.filter((c) => c.rule.action !== 'redact');
    this.evalsUntilResort = PolicyEngine.RESORT_INTERVAL;
  }

  setAuditTrail(trail: AuditTrail): void {
    this.auditTrail = trail;
  }

  evaluate(toolName: string, toolDescription: string, args: Record<string, unknown>, _context?: EvaluateContext): EvaluateResult {
    const reasons: string[] = [];
    const redactedKeys = new Set<string>();
    this.getCompiled();

    for (const cr of this.compiledRedactRules) {
      const rule = cr.rule;
      if (rule.timeWindow && !this.isWithinTimeWindow(rule.timeWindow)) continue;
      const keys = this.getRedactKeys(args, cr);
      for (const key of keys) {
        redactedKeys.add(key);
        if (!reasons.some((r) => r.startsWith(`[${rule.id}]`))) {
          reasons.push(`[${rule.id}] ${rule.description}`);
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
      this.baseliner.observe(toolName, args);
      this.recordAudit(toolName, toolDescription, args, action, reasons.join('; '), _context);
      return {
        action,
        reasons,
        redactedKeys: redactedKeys.size > 0 ? [...redactedKeys] : undefined,
      };
    }

    let action: 'allow' | 'deny' | 'warn' | 'redact' = this.config.defaultAction as 'allow' | 'deny' | 'warn';

    // Collect arg strings once per call instead of once per rule.
    const toolNameLower = toolName.toLowerCase();
    const toolDescLower = toolDescription.toLowerCase();
    const argStrings = this.collectArgStrings(args);
    const argStringsLower = argStrings.map((s) => s.toLowerCase());

    for (const cr of this.sortedMatchRules) {
      const rule = cr.rule;

      if (rule.timeWindow && !this.isWithinTimeWindow(rule.timeWindow)) continue;

      if (this.ruleMatchesCompiled(cr, toolName, toolNameLower, toolDescription, toolDescLower, argStrings, argStringsLower, args)) {
        cr.hits++;

        if (rule.contextCondition && !this.matchesContextCondition(rule, _context)) continue;

        if (rule.argConstraints && rule.argConstraints.length > 0) {
          const constraintResult = this.checkArgConstraints(rule.argConstraints, args);
          if (!constraintResult.passed) {
            reasons.push(`[${rule.id}] ${rule.description}`);
            reasons.push(constraintResult.reason);
            action = 'deny';
            break;
          }
        }

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

    // Periodically re-order rules so the most frequently matched ones are
    // evaluated first. The final action is order-invariant (any matching deny
    // wins and short-circuits; otherwise warn > allow), so this only affects
    // evaluation cost, not outcomes.
    if (--this.evalsUntilResort <= 0) {
      this.evalsUntilResort = PolicyEngine.RESORT_INTERVAL;
      this.sortedMatchRules.sort((a, b) => b.hits - a.hits || a.order - b.order);
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

    const deviations = this.baseliner.detectDeviation(toolName, args);
    for (const d of deviations) {
      reasons.push(`[baseline] ${d.type}: ${d.detail}`);
    }

    this.baseliner.observe(toolName, args);

    return {
      action,
      reasons,
      redactedKeys: redactedKeys.size > 0 ? [...redactedKeys] : undefined,
    };
  }

  setJudge(judge: import('./llm-judge.js').LLMJudge): void {
    this.judgeImpl = judge;
  }

  async evaluateWithJudge(
    toolName: string,
    toolDescription: string,
    args: Record<string, unknown>,
    context?: EvaluateContext,
  ): Promise<EvaluateResult> {
    const result = this.evaluate(toolName, toolDescription, args, context);

    const tiResults = await checkThreatIntel(args);
    if (tiResults.some((r) => r.malicious)) {
      result.reasons.push('[threat-intel] Known malicious indicator detected in arguments');
      if (result.action === 'allow') result.action = 'warn';
    }

    if (!this.judgeImpl || result.action === 'deny') {
      return result;
    }

    const judgeResult = await this.judgeImpl.evaluate({
      toolName,
      description: toolDescription,
      args,
    });

    const escalated = this.judgeImpl.escalate(result.action, judgeResult);

    if (escalated !== result.action) {
      result.reasons.push(`[judge] Escalated from ${result.action} to ${escalated}: ${judgeResult.reasoning}`);
      result.action = escalated;
    }

    return result;
  }

  getBaseliner(): BehavioralBaseline {
    return this.baseliner;
  }

  addRule(rule: PolicyRule): void {
    const existing = this.config.rules.findIndex((r) => r.id === rule.id);
    if (existing !== -1) {
      throw new Error(`Rule with id "${rule.id}" already exists`);
    }
    this.config.rules.push(rule);
    this.invalidateCompiled();
  }

  removeRule(id: string): void {
    const index = this.config.rules.findIndex((r) => r.id === id);
    if (index === -1) {
      throw new Error(`Rule with id "${id}" not found`);
    }
    this.config.rules.splice(index, 1);
    this.invalidateCompiled();
  }

  updateRule(id: string, partial: Partial<PolicyRule>): void {
    const index = this.config.rules.findIndex((r) => r.id === id);
    if (index === -1) {
      throw new Error(`Rule with id "${id}" not found`);
    }
    this.config.rules[index] = { ...this.config.rules[index], ...partial };
    this.invalidateCompiled();
  }

  async loadFromFile(yamlPath: string): Promise<void> {
    this.config = await this.resolveAndLoad(yamlPath, new Set<string>());
    this.invalidateCompiled();
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

  getConfig(): PolicyConfig {
    return this.config;
  }

  isSamplingAllowed(): boolean {
    return this.config.allowSampling !== false;
  }

  getEffectiveTimeout(toolName: string, toolDescription: string, args: Record<string, unknown>, fallbackMs: number = 30000): number {
    this.getCompiled();
    const toolNameLower = toolName.toLowerCase();
    const toolDescLower = toolDescription.toLowerCase();
    const argStrings = this.collectArgStrings(args);
    const argStringsLower = argStrings.map((s) => s.toLowerCase());

    // Iterate compiledRules (original config order): when multiple rules with
    // timeoutMs match, the first configured rule must win, so the
    // frequency-sorted view cannot be used here.
    for (const cr of this.compiledRules!) {
      const rule = cr.rule;
      if (rule.action === 'redact') continue;
      if (rule.timeoutMs === undefined) continue;
      if (rule.timeWindow && !this.isWithinTimeWindow(rule.timeWindow)) continue;
      if (this.ruleMatchesCompiled(cr, toolName, toolNameLower, toolDescription, toolDescLower, argStrings, argStringsLower, args)) {
        return rule.timeoutMs;
      }
    }
    return this.config.defaultTimeoutMs ?? fallbackMs;
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
    const entry: AuditEntry = {
      toolName,
      description: toolDescription,
      args,
      action,
      timestamp: new Date().toISOString(),
      reason,
      context,
    };
    this.auditLog.push(entry);

    if (this.auditTrail) {
      this.auditTrail.append(entry).catch((err) => {
        console.error(`[mcp-seatbelt:audit] Failed to write audit entry: ${err instanceof Error ? err.message : 'Unknown error'}`);
      });
    }
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

  private getRedactKeys(args: Record<string, unknown>, cr: CompiledRule): string[] {
    const keys: string[] = [];
    const matchType = cr.rule.match;
    for (const key of Object.keys(args)) {
      const keyLower = key.toLowerCase();
      for (const cv of cr.values) {
        if (this.matchCompiledValue(cv, matchType, key, keyLower)) {
          keys.push(key);
          break;
        }
      }
    }
    return keys;
  }

  private matchCompiledValue(cv: CompiledValue, matchType: string, input: string, inputLower: string): boolean {
    switch (matchType) {
      case 'exact':
        return input === cv.raw;
      case 'pattern':
        return cv.regex !== null && cv.regex.test(input);
      case 'contains':
        return cv.lower !== null && inputLower.includes(cv.lower);
      default:
        return false;
    }
  }

  private matchAnyArg(cv: CompiledValue, matchType: string, argStrings: string[], argStringsLower: string[]): boolean {
    for (let i = 0; i < argStrings.length; i++) {
      if (this.matchCompiledValue(cv, matchType, argStrings[i], argStringsLower[i])) {
        return true;
      }
    }
    return false;
  }

  private ruleMatchesCompiled(
    cr: CompiledRule,
    toolName: string,
    toolNameLower: string,
    toolDescription: string,
    toolDescLower: string,
    argStrings: string[],
    argStringsLower: string[],
    args: Record<string, unknown>,
  ): boolean {
    const rule = cr.rule;
    const matchType = rule.match;

    for (const cv of cr.values) {
      switch (rule.target) {
        case 'command':
          if (
            this.matchCompiledValue(cv, matchType, toolName, toolNameLower) ||
            this.matchCompiledValue(cv, matchType, toolDescription, toolDescLower)
          ) {
            return true;
          }
          break;

        case 'file':
        case 'network':
          if (this.matchAnyArg(cv, matchType, argStrings, argStringsLower)) {
            return true;
          }
          break;

        case 'env':
          if (this.matchAnyArg(cv, matchType, argStrings, argStringsLower)) {
            return true;
          }
          if (this.matchesEnvVarsCompiled(cv, matchType, args)) {
            return true;
          }
          break;

        case 'process':
          if (
            this.matchCompiledValue(cv, matchType, toolName, toolNameLower) ||
            this.matchCompiledValue(cv, matchType, toolDescription, toolDescLower) ||
            this.matchAnyArg(cv, matchType, argStrings, argStringsLower)
          ) {
            return true;
          }
          break;
      }
    }

    return false;
  }

  private matchesEnvVarsCompiled(
    cv: CompiledValue,
    matchType: string,
    args: Record<string, unknown>,
  ): boolean {
    const env = args.env || args.environment || args.envVars;
    if (env && typeof env === 'object') {
      const keys = Object.keys(env as Record<string, unknown>);
      return keys.some((key) => this.matchCompiledValue(cv, matchType, key, key.toLowerCase()));
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

  private checkArgConstraints(
    constraints: ArgConstraint[],
    args: Record<string, unknown>,
  ): { passed: boolean; reason: string } {
    for (const c of constraints) {
      const argValue = args[c.argName];
      if (argValue === undefined) {
        return {
          passed: false,
          reason: `Arg '${c.argName}' is missing (required by constraint)`,
        };
      }

      const strValue = typeof argValue === 'string' ? argValue : JSON.stringify(argValue);

      switch (c.constraint) {
        case 'equals':
          if (!c.values.some((v: string) => strValue === v)) {
            return {
              passed: false,
              reason: `Arg '${c.argName}'='${strValue}' does not match equals constraint`,
            };
          }
          break;

        case 'startsWith':
          if (!c.values.some((v: string) => strValue.startsWith(v))) {
            return {
              passed: false,
              reason: `Arg '${c.argName}'='${strValue}' does not match startsWith '${c.values.join("', '")}'`,
            };
          }
          break;

        case 'regex':
          if (!c.values.some((v: string) => {
            const re = getCachedRegex(v, '');
            return re !== null && re.test(strValue);
          })) {
            return {
              passed: false,
              reason: `Arg '${c.argName}'='${strValue}' does not match regex constraint`,
            };
          }
          break;

        case 'in':
          if (!c.values.includes(strValue)) {
            return {
              passed: false,
              reason: `Arg '${c.argName}'='${strValue}' is not in allowed values`,
            };
          }
          break;

        case 'notIn':
          if (c.values.includes(strValue)) {
            return {
              passed: false,
              reason: `Arg '${c.argName}'='${strValue}' is in disallowed values`,
            };
          }
          break;
      }
    }

    return { passed: true, reason: '' };
  }
}

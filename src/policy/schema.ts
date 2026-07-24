import type { PolicyConfig, PolicyRule } from '../types.js';
import { validatePolicyStructure } from './json-schema.js';

const VALID_TARGETS = ['command', 'file', 'network', 'env', 'process'] as const;
const VALID_MATCHES = ['exact', 'pattern', 'contains'] as const;
const VALID_ACTIONS = ['allow', 'deny', 'warn', 'redact'] as const;
const VALID_MODES = ['audit', 'enforce'] as const;

export function validatePolicy(config: unknown): PolicyConfig {
  if (!config || typeof config !== 'object') {
    throw new Error('Policy config must be a non-null object');
  }
  validatePolicyStructure(config);

  const obj = config as Record<string, unknown>;

  if (typeof obj.version !== 'string' || obj.version.trim() === '') {
    throw new Error(`Policy version must be a non-empty string, got ${JSON.stringify(obj.version)}`);
  }

  if (!VALID_MODES.includes(obj.mode as typeof VALID_MODES[number])) {
    throw new Error(`Policy mode must be one of ${VALID_MODES.join(', ')}, got ${JSON.stringify(obj.mode)}`);
  }

  if (obj.defaultAction !== 'allow' && obj.defaultAction !== 'deny') {
    throw new Error(`Policy defaultAction must be "allow" or "deny", got ${JSON.stringify(obj.defaultAction)}`);
  }

  if (obj.defaultTimeoutMs !== undefined && obj.defaultTimeoutMs !== null) {
    if (typeof obj.defaultTimeoutMs !== 'number' || obj.defaultTimeoutMs <= 0 || !Number.isInteger(obj.defaultTimeoutMs)) {
      throw new Error(`Policy defaultTimeoutMs must be a positive integer, got ${JSON.stringify(obj.defaultTimeoutMs)}`);
    }
  }

  if (!Array.isArray(obj.rules)) {
    throw new Error('Policy rules must be an array');
  }

  for (let i = 0; i < obj.rules.length; i++) {
    validateRule(obj.rules[i], i);
  }

  if (!obj.allowlist || typeof obj.allowlist !== 'object') {
    throw new Error('Policy allowlist must be an object');
  }

  const allowlist = obj.allowlist as Record<string, unknown>;

  if (!Array.isArray(allowlist.tools)) {
    throw new Error('Policy allowlist.tools must be an array');
  }
  if (!allowlist.tools.every((item: unknown) => typeof item === 'string')) {
    throw new Error('Policy allowlist.tools must contain only strings');
  }

  if (!Array.isArray(allowlist.paths)) {
    throw new Error('Policy allowlist.paths must be an array');
  }
  if (!allowlist.paths.every((item: unknown) => typeof item === 'string')) {
    throw new Error('Policy allowlist.paths must contain only strings');
  }

  if (!Array.isArray(allowlist.hosts)) {
    throw new Error('Policy allowlist.hosts must be an array');
  }
  if (!allowlist.hosts.every((item: unknown) => typeof item === 'string')) {
    throw new Error('Policy allowlist.hosts must contain only strings');
  }

  if (!Array.isArray(allowlist.envVars)) {
    throw new Error('Policy allowlist.envVars must be an array');
  }
  if (!allowlist.envVars.every((item: unknown) => typeof item === 'string')) {
    throw new Error('Policy allowlist.envVars must contain only strings');
  }

  const notifications = validateNotifications(obj.notifications);

  validateTimeoutMs(obj.defaultTimeoutMs, 'Policy defaultTimeoutMs');

  return {
    version: obj.version,
    mode: obj.mode as PolicyConfig['mode'],
    defaultAction: obj.defaultAction as PolicyConfig['defaultAction'],
    rules: obj.rules as PolicyRule[],
    allowlist: {
      tools: allowlist.tools as string[],
      paths: allowlist.paths as string[],
      hosts: allowlist.hosts as string[],
      envVars: allowlist.envVars as string[],
    },
    allowSampling: typeof obj.allowSampling === 'boolean' ? obj.allowSampling : true,
    ...(Array.isArray(obj.extends) ? { extends: obj.extends as string[] } : {}),
    ...(typeof obj.defaultTimeoutMs === 'number' ? { defaultTimeoutMs: obj.defaultTimeoutMs as number } : {}),
    ...(notifications ? { notifications } : {}),
  };
}

function validateNotifications(input: unknown): PolicyConfig['notifications'] | undefined {
  if (input === undefined || input === null) return undefined;
  if (typeof input !== 'object') {
    throw new Error('Policy notifications must be a non-null object or absent');
  }
  const n = input as Record<string, unknown>;
  if (n.webhooks === undefined || n.webhooks === null) return { webhooks: undefined };
  if (!Array.isArray(n.webhooks)) {
    throw new Error('Policy notifications.webhooks must be an array');
  }
  const webhooks = n.webhooks.map((wh, i) => {
    if (!wh || typeof wh !== 'object') {
      throw new Error(`Policy notifications.webhooks[${i}] must be a non-null object`);
    }
    const w = wh as Record<string, unknown>;
    if (typeof w.url !== 'string' || w.url.trim() === '') {
      throw new Error(`Policy notifications.webhooks[${i}].url must be a non-empty string`);
    }
    if (!Array.isArray(w.events)) {
      throw new Error(`Policy notifications.webhooks[${i}].events must be an array`);
    }
    const validEvents = ['deny' as const, 'warn' as const, 'redact' as const];
    for (const evt of w.events) {
      if (!validEvents.includes(evt as typeof validEvents[number])) {
        throw new Error(`Policy notifications.webhooks[${i}].events must contain only "deny", "warn", or "redact"; got ${JSON.stringify(evt)}`);
      }
    }
    if (w.format !== undefined && !['slack', 'discord', 'json'].includes(w.format as string)) {
      throw new Error(`Policy notifications.webhooks[${i}].format must be "slack", "discord", or "json"; got ${JSON.stringify(w.format)}`);
    }
    return {
      url: w.url as string,
      events: w.events as Array<"deny" | "warn" | "redact">,
      format: w.format as "slack" | "discord" | "json" | undefined,
    };
  });
  return { webhooks };
}

function validateRule(rule: unknown, index: number): asserts rule is PolicyRule {
  if (!rule || typeof rule !== 'object') {
    throw new Error(`Policy rule[${index}] must be a non-null object`);
  }

  const r = rule as Record<string, unknown>;

  if (typeof r.id !== 'string' || r.id.trim() === '') {
    throw new Error(`Policy rule[${index}].id must be a non-empty string, got ${JSON.stringify(r.id)}`);
  }

  if (typeof r.description !== 'string' || r.description.trim() === '') {
    throw new Error(`Policy rule[${index}].description must be a non-empty string, got ${JSON.stringify(r.description)}`);
  }

  if (!VALID_TARGETS.includes(r.target as typeof VALID_TARGETS[number])) {
    throw new Error(
      `Policy rule[${index}].target must be one of ${VALID_TARGETS.join(', ')}, got ${JSON.stringify(r.target)}`,
    );
  }

  if (!VALID_MATCHES.includes(r.match as typeof VALID_MATCHES[number])) {
    throw new Error(
      `Policy rule[${index}].match must be one of ${VALID_MATCHES.join(', ')}, got ${JSON.stringify(r.match)}`,
    );
  }

  if (!Array.isArray(r.values)) {
    throw new Error(`Policy rule[${index}].values must be an array`);
  }
  if (!r.values.every((v: unknown) => typeof v === 'string' && v.trim() !== '')) {
    throw new Error(`Policy rule[${index}].values must contain only non-empty strings`);
  }

  if (!VALID_ACTIONS.includes(r.action as typeof VALID_ACTIONS[number])) {
    throw new Error(
      `Policy rule[${index}].action must be one of ${VALID_ACTIONS.join(', ')}, got ${JSON.stringify(r.action)}`,
    );
  }

  if (r.timeWindow !== undefined && r.timeWindow !== null) {
    const tw = r.timeWindow as Record<string, unknown>;

    if (tw.days !== undefined) {
      if (!Array.isArray(tw.days)) {
        throw new Error(`Policy rule[${index}].timeWindow.days must be an array`);
      }
      const validDays = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
      const lowerValid = validDays.map((d) => d.toLowerCase());
      for (const day of tw.days) {
        if (typeof day !== 'string' || !lowerValid.includes(day.toLowerCase())) {
          throw new Error(
            `Policy rule[${index}].timeWindow.days must contain valid day names, got ${JSON.stringify(day)}`,
          );
        }
      }
    }

    if (tw.startHour !== undefined) {
      if (typeof tw.startHour !== 'number' || tw.startHour < 0 || tw.startHour > 23 || !Number.isInteger(tw.startHour)) {
        throw new Error(`Policy rule[${index}].timeWindow.startHour must be an integer 0-23`);
      }
    }

    if (tw.endHour !== undefined) {
      if (typeof tw.endHour !== 'number' || tw.endHour < 0 || tw.endHour > 23 || !Number.isInteger(tw.endHour)) {
        throw new Error(`Policy rule[${index}].timeWindow.endHour must be an integer 0-23`);
      }
    }
  }

  if (r.contextCondition !== undefined && r.contextCondition !== null) {
    const cc = r.contextCondition as Record<string, unknown>;

    if (cc.clientIn !== undefined) {
      if (!Array.isArray(cc.clientIn)) {
        throw new Error(`Policy rule[${index}].contextCondition.clientIn must be an array`);
      }
      if (!cc.clientIn.every((v: unknown) => typeof v === 'string')) {
        throw new Error(`Policy rule[${index}].contextCondition.clientIn must contain only strings`);
      }
    }

    if (cc.maxRequestsPerMinute !== undefined) {
      if (typeof cc.maxRequestsPerMinute !== 'number' || cc.maxRequestsPerMinute <= 0 || !Number.isInteger(cc.maxRequestsPerMinute)) {
        throw new Error(`Policy rule[${index}].contextCondition.maxRequestsPerMinute must be a positive integer`);
      }
    }
  }

  if (r.timeoutMs !== undefined && r.timeoutMs !== null) {
    if (typeof r.timeoutMs !== 'number' || r.timeoutMs <= 0 || !Number.isInteger(r.timeoutMs)) {
      throw new Error(`Policy rule[${index}].timeoutMs must be a positive integer`);
    }
  }

  if (r.argConstraints !== undefined && r.argConstraints !== null) {
    if (!Array.isArray(r.argConstraints)) {
      throw new Error(`Policy rule[${index}].argConstraints must be an array`);
    }
    const VALID_CONSTRAINTS = ['equals', 'startsWith', 'regex', 'in', 'notIn'];
    for (let ci = 0; ci < r.argConstraints.length; ci++) {
      const ac = (r.argConstraints as Array<Record<string, unknown>>)[ci];
      if (!ac || typeof ac !== 'object') {
        throw new Error(`Policy rule[${index}].argConstraints[${ci}] must be a non-null object`);
      }
      if (typeof ac.argName !== 'string' || ac.argName.trim() === '') {
        throw new Error(`Policy rule[${index}].argConstraints[${ci}].argName must be a non-empty string`);
      }
      if (!VALID_CONSTRAINTS.includes(ac.constraint as string)) {
        throw new Error(
          `Policy rule[${index}].argConstraints[${ci}].constraint must be one of ${VALID_CONSTRAINTS.join(', ')}, got ${JSON.stringify(ac.constraint)}`,
        );
      }
      if (!Array.isArray(ac.values) || !ac.values.every((v: unknown) => typeof v === 'string' && v.trim() !== '')) {
        throw new Error(`Policy rule[${index}].argConstraints[${ci}].values must contain only non-empty strings`);
      }
    }
  }

  validateTimeoutMs(r.timeoutMs, `Policy rule[${index}].timeoutMs`);

  validateCompliance(r.compliance, index);
}

function validateTimeoutMs(value: unknown, field: string): void {
  if (value === undefined) return;
  if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0) {
    throw new Error(`${field} must be a positive integer`);
  }
  if (value < 100) {
    throw new Error(`${field} must be at least 100ms`);
  }
  if (value > 300000) {
    throw new Error(`${field} must be at most 300000ms (5 minutes)`);
  }
}

const VALID_FRAMEWORKS = ['soc2', 'hipaa', 'gdpr', 'pci-dss', 'iso27001', 'nist'] as const;

function validateCompliance(input: unknown, ruleIndex: number): void {
  if (input === undefined || input === null) return;
  if (!Array.isArray(input)) {
    throw new Error(`Policy rule[${ruleIndex}].compliance must be an array`);
  }
  for (let ci = 0; ci < input.length; ci++) {
    const item = (input as Array<Record<string, unknown>>)[ci];
    if (!item || typeof item !== 'object') {
      throw new Error(`Policy rule[${ruleIndex}].compliance[${ci}] must be a non-null object`);
    }
    if (!VALID_FRAMEWORKS.includes(item.framework as typeof VALID_FRAMEWORKS[number])) {
      throw new Error(
        `Policy rule[${ruleIndex}].compliance[${ci}].framework must be one of ${VALID_FRAMEWORKS.join(', ')}, got ${JSON.stringify(item.framework)}`,
      );
    }
    if (!Array.isArray(item.controls) || item.controls.length === 0) {
      throw new Error(`Policy rule[${ruleIndex}].compliance[${ci}].controls must be a non-empty array`);
    }
    if (!item.controls.every((c: unknown) => typeof c === 'string' && c.trim() !== '')) {
      throw new Error(`Policy rule[${ruleIndex}].compliance[${ci}].controls must contain only non-empty strings`);
    }
    if (item.remediation !== undefined && typeof item.remediation !== 'string') {
      throw new Error(`Policy rule[${ruleIndex}].compliance[${ci}].remediation must be a string`);
    }
  }
}

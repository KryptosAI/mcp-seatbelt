import type { PolicyConfig, PolicyRule } from '../types.js';

const VALID_TARGETS = ['command', 'file', 'network', 'env', 'process'] as const;
const VALID_MATCHES = ['exact', 'pattern', 'contains'] as const;
const VALID_ACTIONS = ['allow', 'deny', 'warn', 'redact'] as const;
const VALID_MODES = ['audit', 'enforce'] as const;

export function validatePolicy(config: unknown): PolicyConfig {
  if (!config || typeof config !== 'object') {
    throw new Error('Policy config must be a non-null object');
  }

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
  };
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
}

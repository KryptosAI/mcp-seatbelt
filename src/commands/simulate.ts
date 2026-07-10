import { readFileSync, existsSync } from "node:fs";
import chalk from "chalk";
import type { PolicyConfig, PolicyRule } from "../types.js";
import { parsePolicy } from "../policy/yaml.js";
import { PolicyEngine } from "../policy/engine.js";

const DAY_NAMES = [
  "Sunday",
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
];

function isWithinTimeWindow(
  timeWindow: PolicyRule["timeWindow"],
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

function collectArgStrings(args: Record<string, unknown>): string[] {
  const result: string[] = [];

  for (const value of Object.values(args)) {
    if (typeof value === "string") {
      result.push(value);
    } else if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === "string") {
          result.push(item);
        } else if (item && typeof item === "object") {
          result.push(JSON.stringify(item));
        }
      }
    } else if (value && typeof value === "object" && !Array.isArray(value)) {
      for (const v of Object.values(value as Record<string, unknown>)) {
        if (typeof v === "string") {
          result.push(v);
        }
      }
    }
  }

  return result;
}

function matchesString(
  input: string,
  value: string,
  matchType: string,
): boolean {
  switch (matchType) {
    case "exact":
      return input === value;
    case "pattern":
      try {
        return new RegExp(value, "i").test(input);
      } catch {
        return false;
      }
    case "contains":
      return input.toLowerCase().includes(value.toLowerCase());
    default:
      return false;
  }
}

interface RuleMatchDetail {
  matched: boolean;
  matchDetail?: string;
}

function ruleMatches(
  rule: PolicyRule,
  toolName: string,
  toolDescription: string,
  args: Record<string, unknown>,
): RuleMatchDetail {
  const argStrings = collectArgStrings(args);

  for (const value of rule.values) {
    switch (rule.target) {
      case "command":
        if (matchesString(toolName, value, rule.match)) {
          return {
            matched: true,
            matchDetail: `Matched ${rule.match}: ${value} against tool name "${toolName}"`,
          };
        }
        if (matchesString(toolDescription, value, rule.match)) {
          return {
            matched: true,
            matchDetail: `Matched ${rule.match}: ${value} against description "${toolDescription.slice(0, 60)}"`,
          };
        }
        break;

      case "file":
      case "network": {
        const matchedArg = argStrings.find((arg) =>
          matchesString(arg, value, rule.match),
        );
        if (matchedArg) {
          return {
            matched: true,
            matchDetail: `Matched ${rule.match}: ${value} against arg value "${matchedArg}"`,
          };
        }
        break;
      }

      case "env": {
        const matchedArg = argStrings.find((arg) =>
          matchesString(arg, value, rule.match),
        );
        if (matchedArg) {
          return {
            matched: true,
            matchDetail: `Matched ${rule.match}: ${value} against arg value "${matchedArg}"`,
          };
        }
        const env = args.env || args.environment || args.envVars;
        if (env && typeof env === "object") {
          const keys = Object.keys(env as Record<string, unknown>);
          const matchedKey = keys.find((key) =>
            matchesString(key, value, rule.match),
          );
          if (matchedKey) {
            return {
              matched: true,
              matchDetail: `Matched ${rule.match}: ${value} against env var key "${matchedKey}"`,
            };
          }
        }
        break;
      }

      case "process":
        if (matchesString(toolName, value, rule.match)) {
          return {
            matched: true,
            matchDetail: `Matched ${rule.match}: ${value} against tool name "${toolName}"`,
          };
        }
        if (matchesString(toolDescription, value, rule.match)) {
          return {
            matched: true,
            matchDetail: `Matched ${rule.match}: ${value} against description "${toolDescription.slice(0, 60)}"`,
          };
        }
        const procArg = argStrings.find((arg) =>
          matchesString(arg, value, rule.match),
        );
        if (procArg) {
          return {
            matched: true,
            matchDetail: `Matched ${rule.match}: ${value} against arg value "${procArg}"`,
          };
        }
        break;
    }
  }

  return { matched: false };
}

const ACTION_COLORS: Record<string, typeof chalk.green> = {
  allow: chalk.green,
  deny: chalk.red,
  warn: chalk.yellow,
  redact: chalk.magenta,
};

const RESULT_COLORS: Record<string, typeof chalk.green> = {
  allow: chalk.green,
  deny: chalk.red,
  warn: chalk.yellow,
  redact: chalk.magenta,
  BLOCKED: chalk.red,
  ALLOWED: chalk.green,
  WARNED: chalk.yellow,
  REDACTED: chalk.magenta,
};

export interface SimulateOptions {
  tool: string;
  description?: string;
  args?: string;
  server?: string;
  policy: string;
  json?: boolean;
  verbose?: boolean;
}

export async function simulateCommand(opts: SimulateOptions): Promise<void> {
  if (!existsSync(opts.policy)) {
    console.error(chalk.red(`Policy file not found: ${opts.policy}`));
    process.exit(1);
  }

  const raw = readFileSync(opts.policy, "utf-8");
  const policyConfig = parsePolicy(raw);
  const engine = new PolicyEngine(policyConfig);

  let args: Record<string, unknown> = {};
  if (opts.args) {
    try {
      args = JSON.parse(opts.args);
    } catch {
      console.error(chalk.red(`Failed to parse --args as JSON: ${opts.args}`));
      process.exit(1);
    }
  }

  const toolDescription = opts.description ?? "";

  const result = engine.evaluate(toolDescription ? opts.tool : opts.tool, toolDescription, args, {
    client: opts.server ?? "simulate",
    requestCount: 1,
  });

  if (opts.json) {
    const output: Record<string, unknown> = {
      tool: opts.tool,
      description: toolDescription,
      args,
      server: opts.server ?? "simulate",
      action: result.action,
      reasons: result.reasons,
      redactedKeys: result.redactedKeys,
      rules: [],
    };

    for (const rule of policyConfig.rules) {
      if (rule.action === "redact") continue;

      const detail = ruleMatches(rule, opts.tool, toolDescription, args);
      const inWindow = isWithinTimeWindow(rule.timeWindow);
      const wasApplied = result.reasons.some((r) => r.startsWith(`[${rule.id}]`));

      output.rules = [
        ...((output.rules as unknown[]) || []),
        {
          id: rule.id,
          description: rule.description,
          action: rule.action,
          target: rule.target,
          match: rule.match,
          hasTimeWindow: !!rule.timeWindow,
          inTimeWindow: inWindow,
          matched: detail.matched,
          applied: wasApplied,
          matchDetail: detail.matchDetail ?? null,
        },
      ];
    }

    console.log(JSON.stringify(output, null, 2));
    return;
  }

  for (const rule of policyConfig.rules) {
    if (rule.action === "redact") continue;

    const detail = ruleMatches(rule, opts.tool, toolDescription, args);
    const hasTimeWindow = !!rule.timeWindow;
    const inWindow = isWithinTimeWindow(rule.timeWindow);
    const wasApplied = result.reasons.some((r) => r.startsWith(`[${rule.id}]`));

    if (!opts.verbose && !wasApplied && !(hasTimeWindow && !inWindow && detail.matched)) {
      continue;
    }

    const actionColor = ACTION_COLORS[rule.action] ?? chalk.white;
    let line = `[${rule.id}] ${actionColor(rule.action.toUpperCase())} — ${rule.description}`;

    if (hasTimeWindow && !inWindow) {
      line += chalk.dim(" — Not applied (outside time window)");
    }

    console.log(line);

    if (detail.matched && detail.matchDetail) {
      console.log(chalk.dim(`  ${detail.matchDetail}`));
    }
  }

  console.log();

  const resultLabel =
    result.action === "deny"
      ? "BLOCKED"
      : result.action === "warn"
        ? "WARNED"
        : result.action === "redact"
          ? "REDACTED"
          : "ALLOWED";
  const resultColor = RESULT_COLORS[resultLabel] ?? chalk.white;
  console.log(`Result: ${resultColor(resultLabel)}`);
}

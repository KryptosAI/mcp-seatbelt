import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import chalk from "chalk";
import { load as yamlLoad } from "js-yaml";
import type { PolicyConfig, PolicyRule, RiskReport } from "../types.js";

function loadPolicyFile(filePath: string): PolicyConfig | null {
  try {
    const raw = readFileSync(filePath, "utf-8");

    if (filePath.endsWith(".json")) {
      const json = JSON.parse(raw) as RiskReport;
      const rules: PolicyRule[] = (json.recommendations || []).map((rec, i) => ({
        id: `report-${i}`,
        description: rec,
        target: "command" as const,
        match: "contains" as const,
        values: [rec],
        action: "warn" as const,
      }));

      return {
        version: "1",
        mode: "enforce",
        defaultAction: "deny",
        rules,
        allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
        allowSampling: true,
      };
    }

    const parsed = yamlLoad(raw) as unknown;
    const doc = parsed as Record<string, unknown>;

    if (!doc || typeof doc !== "object") {
      return null;
    }

    return {
      version: (doc.version as string) || "1",
      mode: (doc.mode as "audit" | "enforce") || "enforce",
      defaultAction: (doc.defaultAction as "allow" | "deny") || "deny",
      rules: (doc.rules as PolicyRule[]) || [],
      allowlist: doc.allowlist as PolicyConfig["allowlist"] || {
        tools: [],
        paths: [],
        hosts: [],
        envVars: [],
      },
      allowSampling: (doc.allowSampling as boolean) ?? true,
    };
  } catch {
    return null;
  }
}

function loadRiskReport(filePath: string): RiskReport | null {
  try {
    const raw = readFileSync(filePath, "utf-8");
    return JSON.parse(raw) as RiskReport;
  } catch {
    return null;
  }
}

interface DiffResult {
  added: string[];
  removed: string[];
  modified: string[];
  riskScoreChanges: { name: string; oldScore: number; newScore: number }[];
}

function diffPolicies(oldPolicy: PolicyConfig, newPolicy: PolicyConfig): DiffResult {
  const oldRuleIds = new Set(oldPolicy.rules.map((r) => r.id));
  const newRuleIds = new Set(newPolicy.rules.map((r) => r.id));

  const added = newPolicy.rules
    .filter((r) => !oldRuleIds.has(r.id))
    .map((r) => r.id);

  const removed = oldPolicy.rules
    .filter((r) => !newRuleIds.has(r.id))
    .map((r) => r.id);

  const modified: string[] = [];

  for (const newRule of newPolicy.rules) {
    if (!oldRuleIds.has(newRule.id)) continue;
    const oldRule = oldPolicy.rules.find((r) => r.id === newRule.id);
    if (!oldRule) continue;

    if (
      oldRule.action !== newRule.action ||
      oldRule.target !== newRule.target ||
      oldRule.description !== newRule.description ||
      JSON.stringify(oldRule.values.sort()) !== JSON.stringify(newRule.values.sort())
    ) {
      modified.push(newRule.id);
    }
  }

  return {
    added,
    removed,
    modified,
    riskScoreChanges: [],
  };
}

function diffReports(oldReport: RiskReport, newReport: RiskReport): DiffResult {
  const oldServerNames = new Set(oldReport.servers.map((s) => s.name));
  const newServerNames = new Set(newReport.servers.map((s) => s.name));

  const added = newReport.servers
    .filter((s) => !oldServerNames.has(s.name))
    .map((s) => s.name);

  const removed = oldReport.servers
    .filter((s) => !newServerNames.has(s.name))
    .map((s) => s.name);

  const modified: string[] = [];
  const riskScoreChanges: { name: string; oldScore: number; newScore: number }[] = [];

  for (const newServer of newReport.servers) {
    if (!oldServerNames.has(newServer.name)) continue;
    const oldServer = oldReport.servers.find((s) => s.name === newServer.name);
    if (!oldServer) continue;

    if (oldServer.risk.score !== newServer.risk.score) {
      riskScoreChanges.push({
        name: newServer.name,
        oldScore: oldServer.risk.score,
        newScore: newServer.risk.score,
      });
    }

    const oldFlags = new Set(oldServer.risk.flags.map((f) => f.rule));
    const newFlags = new Set(newServer.risk.flags.map((f) => f.rule));

    if (
      oldFlags.size !== newFlags.size ||
      ![...oldFlags].every((f) => newFlags.has(f)) ||
      ![...newFlags].every((f) => oldFlags.has(f))
    ) {
      modified.push(newServer.name);
    }
  }

  return { added, removed, modified, riskScoreChanges };
}

function reportResults(result: DiffResult, oldFile: string, newFile: string): void {
  const header = `\n${chalk.bold("Diff:")} ${chalk.dim(oldFile)} ${chalk.dim("→")} ${chalk.dim(newFile)}\n`;
  console.log(header);

  if (result.added.length > 0) {
    console.log(chalk.green.bold(`+ ${result.added.length} added:`));
    for (const item of result.added) {
      console.log(chalk.green(`  + ${item}`));
    }
    console.log();
  }

  if (result.removed.length > 0) {
    console.log(chalk.red.bold(`- ${result.removed.length} removed:`));
    for (const item of result.removed) {
      console.log(chalk.red(`  - ${item}`));
    }
    console.log();
  }

  if (result.modified.length > 0) {
    console.log(chalk.yellow.bold(`~ ${result.modified.length} modified:`));
    for (const item of result.modified) {
      console.log(chalk.yellow(`  ~ ${item}`));
    }
    console.log();
  }

  if (result.riskScoreChanges.length > 0) {
    console.log(chalk.magenta.bold(`Risk Score Changes:`));
    for (const change of result.riskScoreChanges) {
      const diff = change.newScore - change.oldScore;
      const arrow = diff > 0 ? chalk.red(`↑ +${diff}`) : diff < 0 ? chalk.green(`↓ ${diff}`) : chalk.dim("= 0");
      console.log(`  ${change.name}: ${change.oldScore} → ${change.newScore} ${arrow}`);
    }
    console.log();
  }

  if (
    result.added.length === 0 &&
    result.removed.length === 0 &&
    result.modified.length === 0 &&
    result.riskScoreChanges.length === 0
  ) {
    console.log(chalk.dim("No differences found.\n"));
  }
}

export interface DiffOptions {
  oldFile: string;
  newFile: string;
}

export async function diffCommand(opts: DiffOptions): Promise<void> {
  const { oldFile, newFile } = opts;

  const oldPath = resolve(oldFile);
  const newPath = resolve(newFile);

  if (!existsSync(oldPath)) {
    console.error(chalk.red(`File not found: ${oldPath}`));
    process.exit(1);
  }

  if (!existsSync(newPath)) {
    console.error(chalk.red(`File not found: ${newPath}`));
    process.exit(1);
  }

  let result: DiffResult;

  const oldReport = loadRiskReport(oldPath);
  const newReport = loadRiskReport(newPath);

  if (oldReport && newReport) {
    result = diffReports(oldReport, newReport);
  } else {
    const oldPolicy = loadPolicyFile(oldPath);
    const newPolicy = loadPolicyFile(newPath);

    if (!oldPolicy) {
      console.error(chalk.red(`Failed to parse: ${oldPath}`));
      process.exit(1);
    }

    if (!newPolicy) {
      console.error(chalk.red(`Failed to parse: ${newPath}`));
      process.exit(1);
    }

    result = diffPolicies(oldPolicy, newPolicy);
  }

  reportResults(result, oldPath, newPath);
}

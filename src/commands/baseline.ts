import { readFileSync, existsSync } from "node:fs";
import chalk from "chalk";
import { parsePolicy } from "../policy/yaml.js";
import { PolicyEngine, BehavioralBaseline } from "../policy/engine.js";
import type { AuditEntry } from "../policy/engine.js";

export interface BaselineOptions {
  auditFile?: string;
}

export async function baselineCommand(opts: BaselineOptions): Promise<void> {
  console.log(chalk.cyan("\n📊 Behavioral Baseline Report\n"));

  let auditEntries: AuditEntry[] = [];

  if (opts.auditFile) {
    if (!existsSync(opts.auditFile)) {
      console.error(chalk.red(`Audit file not found: ${opts.auditFile}`));
      process.exit(1);
    }
    try {
      const raw = readFileSync(opts.auditFile, "utf-8");
      auditEntries = JSON.parse(raw) as AuditEntry[];
    } catch {
      console.error(chalk.red(`Failed to parse audit file: ${opts.auditFile}`));
      process.exit(1);
    }
  }

  const baseliner = new BehavioralBaseline();

  for (const entry of auditEntries) {
    baseliner.observe(entry.toolName, entry.args);
  }

  const report = baseliner.generateReport();
  console.log(report);

  const anomalies: { toolName: string; detail: string }[] = [];

  for (const [toolName] of baseliner.profiles) {
    const deviations = baseliner.detectDeviation(toolName, {});
    for (const d of deviations) {
      anomalies.push({ toolName, detail: d.detail });
    }
  }

  if (anomalies.length > 0) {
    console.log(chalk.yellow.bold("Anomalies detected:\n"));
    const anomalyTools = new Set(anomalies.map((a) => a.toolName));
    console.log(chalk.yellow(`  ${anomalyTools.size} tool(s) behaving abnormally\n`));
    for (const a of anomalies.slice(0, 20)) {
      console.log(chalk.dim(`  ${a.toolName}: ${a.detail}`));
    }
    if (anomalies.length > 20) {
      console.log(chalk.dim(`  ... and ${anomalies.length - 20} more anomalies`));
    }
    console.log();
  }

  if (auditEntries.length === 0) {
    console.log(chalk.dim("No audit data provided. Run the proxy in audit mode to collect data.\n"));
    console.log(chalk.dim("Usage: mcp-seatbelt baseline --audit-file audit.json\n"));
  }
}

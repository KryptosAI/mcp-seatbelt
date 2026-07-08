import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import chalk from "chalk";
import { detectAll } from "../detectors/index.js";
import { generateMarkdownReport, generateJsonReport } from "../report/generator.js";
import { generateSarifReport } from "../report/sarif.js";

export interface ReportOptions {
  output: string;
  json: boolean;
  sarif?: boolean;
}

export async function reportCommand(opts: ReportOptions): Promise<void> {
  console.log(chalk.cyan("\n📊 Generating MCP risk report...\n"));

  const configs = await detectAll();

  if (configs.length === 0) {
    console.log(chalk.yellow("No MCP configurations detected."));
    return;
  }

  mkdirSync(dirname(opts.output), { recursive: true });

  if (opts.sarif) {
    const sarifOutput = opts.output.replace(/\.[^.]+$/, ".sarif.json");
    const report = generateSarifReport(configs);
    writeFileSync(sarifOutput, JSON.stringify(report, null, 2), "utf-8");
    console.log(chalk.green(`✓ SARIF report written to ${sarifOutput}`));
  } else if (opts.json) {
    const report = generateJsonReport(configs);
    writeFileSync(opts.output, JSON.stringify(report, null, 2), "utf-8");
    console.log(chalk.green(`✓ JSON report written to ${opts.output}`));
  } else {
    const report = generateMarkdownReport(configs);
    writeFileSync(opts.output, report, "utf-8");
    console.log(chalk.green(`✓ Markdown report written to ${opts.output}`));
  }

  const allServers = configs.flatMap((c) => c.servers);
  const critical = allServers.filter((s) => s.risk.level === "critical").length;
  const high = allServers.filter((s) => s.risk.level === "high").length;
  const medium = allServers.filter((s) => s.risk.level === "medium").length;

  console.log(chalk.dim(`  Servers: ${allServers.length} | Critical: ${critical} | High: ${high} | Medium: ${medium}\n`));
}

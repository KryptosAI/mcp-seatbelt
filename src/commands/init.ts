import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import chalk from "chalk";
import { detectAll } from "../detectors/index.js";
import { generateDefaultPolicy } from "../policy/defaults.js";
import { generateMarkdownReport } from "../report/generator.js";
import { stringify as yamlStringify } from "../policy/yaml.js";

export interface InitOptions {
  output: string;
  policy: string;
}

export async function initCommand(opts: InitOptions): Promise<void> {
  const { output, policy: policyMode } = opts;

  console.log(chalk.cyan("\n🔍 Scanning for MCP configurations...\n"));

  const configs = detectAll();

  if (configs.length === 0) {
    console.log(chalk.yellow("No MCP configurations detected."));
    console.log(chalk.dim("  Supported clients: Cursor, Claude Desktop, VS Code, Windsurf, project-local configs\n"));
    return;
  }

  const allServers = configs.flatMap((c) => c.servers);

  console.log(chalk.green(`Found ${configs.length} client config(s) with ${allServers.length} server(s)\n`));

  console.log(chalk.bold("Risk Summary:"));
  console.log("┌──────────────────────┬────────┬──────────┬──────────┐");
  console.log("│ Server               │ Client │ Risk     │ Flags    │");
  console.log("├──────────────────────┼────────┼──────────┼──────────┤");

  const levelColor = {
    critical: chalk.red,
    high: chalk.red,
    medium: chalk.yellow,
    low: chalk.green,
  };

  for (const config of configs) {
    for (const server of config.servers) {
      const colorFn = levelColor[server.risk.level];
      const name = server.name.padEnd(20).slice(0, 20);
      const client = config.client.padEnd(6).slice(0, 6);
      const level = server.risk.level.padEnd(8);
      const flags = String(server.risk.flags.length).padEnd(8);
      console.log(
        `│ ${name} │ ${client} │ ${colorFn(level)} │ ${flags}│`,
      );
    }
  }
  console.log("└──────────────────────┴────────┴──────────┴──────────┘\n");

  const policy = generateDefaultPolicy(configs, policyMode);

  mkdirSync(output, { recursive: true });

  writeFileSync(join(output, "policy.yml"), yamlStringify(policy), "utf-8");
  writeFileSync(join(output, "risk-report.md"), generateMarkdownReport(configs), "utf-8");

  console.log(chalk.green(`✓ Wrote policy to ${join(output, "policy.yml")}`));
  console.log(chalk.green(`✓ Wrote risk report to ${join(output, "risk-report.md")}\n`));

  console.log(chalk.bold("Next steps:"));
  console.log(chalk.dim("  1."), chalk.cyan("Start the proxy:"), "mcp-seatbelt proxy");
  console.log(chalk.dim("  2."), chalk.cyan("Review policy:"), `cat ${join(output, "policy.yml")}`);
  console.log(chalk.dim("  3."), chalk.cyan("Update your MCP client config to point to proxy URLs"));
  console.log();
}

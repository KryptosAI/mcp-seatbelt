import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import chalk from "chalk";
import { detectAll } from "../detectors/index.js";
import { generateDefaultPolicy } from "../policy/defaults.js";
import { generateMarkdownReport } from "../report/generator.js";
import { stringify as yamlStringify } from "../policy/yaml.js";
import * as readline from "node:readline";

export interface InitOptions {
  output: string;
  policy: string;
  yes?: boolean;
}

function promptYesNo(question: string, defaultYes = true): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  const suffix = defaultYes ? " [Y/n] " : " [y/N] ";
  return new Promise((resolve) => {
    rl.question(question + suffix, (answer) => {
      rl.close();
      const trimmed = answer.trim().toLowerCase();
      if (trimmed === "") resolve(defaultYes);
      else if (trimmed === "y" || trimmed === "yes") resolve(true);
      else resolve(false);
    });
  });
}

export async function initCommand(opts: InitOptions): Promise<void> {
  const { output, policy: policyMode, yes: skipPrompt = false } = opts;

  console.log(chalk.cyan("\n🔍 Scanning for MCP configurations...\n"));

  const configs = await detectAll();

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

  const cursorConfigs = configs.filter((c) => c.client === "cursor");

  if (cursorConfigs.length > 0) {
    console.log(chalk.bold("Update Cursor MCP configs?"));
    console.log(chalk.dim("  Add proxy URLs to your Cursor mcp.json so mcp-seatbelt can intercept tool calls.\n"));

    const shouldUpdate = skipPrompt || await promptYesNo("Update Cursor MCP config with proxy URLs?");

    if (shouldUpdate) {
      for (const config of cursorConfigs) {
        if (!existsSync(config.path)) continue;

        try {
          const raw = readFileSync(config.path, "utf-8");
          const json = JSON.parse(raw) as Record<string, unknown>;
          const mcpServers = (json.mcpServers || {}) as Record<string, Record<string, unknown>>;

          let updated = false;
          for (const server of config.servers) {
            if (mcpServers[server.name]) {
              mcpServers[server.name].url = `http://localhost:9420/${server.name}`;
              updated = true;
            }
          }

          if (updated) {
            writeFileSync(config.path + ".backup", raw, "utf-8");
            writeFileSync(config.path, JSON.stringify(json, null, 2) + "\n", "utf-8");
            console.log(chalk.green(`✓ Updated ${config.path}`));
            console.log(chalk.dim(`  Backup saved to ${config.path}.backup`));
          }
        } catch (err) {
          console.log(chalk.red(`✗ Failed to update ${config.path}: ${err instanceof Error ? err.message : String(err)}`));
        }
      }
      console.log();
    }
  }

  const nonCursorConfigs = configs.filter((c) => c.client !== "cursor");
  if (nonCursorConfigs.length > 0) {
    console.log(chalk.bold("Proxy URLs for other clients:"));
    console.log(chalk.dim("  Add these URLs to your client configs to use the proxy:\n"));
    for (const config of nonCursorConfigs) {
      console.log(chalk.dim(`  ${config.client} (${config.path}):`));
      for (const server of config.servers) {
        console.log(chalk.cyan(`    ${server.name}: http://localhost:9420/${server.name}`));
      }
    }
    console.log();
  }

  console.log(chalk.bold("Next steps:"));
  console.log(chalk.dim("  1."), chalk.cyan("Start the proxy:"), "mcp-seatbelt proxy");
  console.log(chalk.dim("  2."), chalk.cyan("Review policy:"), `cat ${join(output, "policy.yml")}`);
  console.log(chalk.dim("  3."), chalk.cyan("Update your MCP client config to point to proxy URLs"));
  console.log();
}

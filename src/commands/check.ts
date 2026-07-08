import chalk from "chalk";
import { detectAll } from "../detectors/index.js";

export async function checkCommand(): Promise<void> {
  console.log(chalk.cyan("\n🔍 Quick MCP risk check...\n"));

  const configs = await detectAll();

  if (configs.length === 0) {
    console.log(chalk.yellow("No MCP configurations detected."));
    process.exit(0);
  }

  const allServers = configs.flatMap((c) => c.servers);

  const levelColor = {
    critical: chalk.red,
    high: chalk.red,
    medium: chalk.yellow,
    low: chalk.green,
  };

  console.log(chalk.bold("Risk Summary:"));
  console.log("┌──────────────────────┬────────┬──────────┬──────────┐");
  console.log("│ Server               │ Client │ Risk     │ Flags    │");
  console.log("├──────────────────────┼────────┼──────────┼──────────┤");

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

  const criticalFlags = allServers.flatMap((s) => s.risk.flags).filter((f) => f.severity === "critical");
  const highFlags = allServers.flatMap((s) => s.risk.flags).filter((f) => f.severity === "high");

  if (criticalFlags.length > 0) {
    console.log(chalk.red.bold("╔════════════════════════════════════════════╗"));
    console.log(chalk.red.bold("║  ⚠️  CRITICAL RISKS DETECTED              ║"));
    console.log(chalk.red.bold("╠════════════════════════════════════════════╣"));
    for (const flag of criticalFlags) {
      console.log(chalk.red(`║  • ${flag.description.padEnd(40).slice(0, 40)} ║`));
    }
    console.log(chalk.red.bold("╚════════════════════════════════════════════╝\n"));
  }

  if (highFlags.length > 0) {
    console.log(chalk.yellow("High-risk flags:"));
    for (const flag of highFlags) {
      console.log(chalk.yellow(`  • ${flag.description}`));
    }
    console.log();
  }

  const totalServers = allServers.length;
  const criticalServers = allServers.filter((s) => s.risk.level === "critical").length;
  const highServers = allServers.filter((s) => s.risk.level === "high").length;

  console.log(
    chalk.dim(
      `Total: ${totalServers} server(s) | ` +
        `Critical: ${criticalServers} | High: ${highServers} | ` +
        `Medium: ${allServers.filter((s) => s.risk.level === "medium").length} | ` +
        `Low: ${allServers.filter((s) => s.risk.level === "low").length}`,
    ),
  );
  console.log();

  if (criticalFlags.length > 0 || criticalServers > 0) {
    console.log(chalk.red("Exiting with code 1 due to critical risks."));
    console.log(chalk.dim("Run 'mcp-seatbelt init' to generate a policy and proxy.\n"));
    process.exit(1);
  }

  console.log(chalk.green("No critical risks found.\n"));
  process.exit(0);
}

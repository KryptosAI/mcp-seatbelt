#!/usr/bin/env node
import { Command } from "commander";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(
  readFileSync(join(__dirname, "..", "package.json"), "utf-8"),
) as { version: string };

const program = new Command();

program
  .name("mcp-seatbelt")
  .description("Runtime guardrails for AI agent MCP tools")
  .version(pkg.version);

program
  .command("init")
  .description("Detect MCP configs, assess risk, generate policy")
  .option("-o, --output <path>", "Output directory", ".mcp-seatbelt")
  .option("--policy <mode>", "Policy mode: audit or enforce", "audit")
  .action(async (opts) => {
    const { initCommand } = await import("./commands/init.js");
    await initCommand({
      output: opts.output as string,
      policy: opts.policy as string,
    });
  });

program
  .command("proxy")
  .description("Start the MCP Seatbelt proxy with policy enforcement")
  .option("-p, --port <port>", "Proxy port", "9420")
  .option("-c, --config <path>", "Policy config path", ".mcp-seatbelt/policy.yml")
  .action(async (opts) => {
    const { proxyCommand } = await import("./commands/proxy.js");
    await proxyCommand({
      port: opts.port as string,
      config: opts.config as string,
    });
  });

program
  .command("report")
  .description("Generate a risk report from detected MCP configs")
  .option("-o, --output <path>", "Output file", ".mcp-seatbelt/report.md")
  .option("--json", "Output JSON instead of markdown")
  .action(async (opts) => {
    const { reportCommand } = await import("./commands/report.js");
    await reportCommand({
      output: opts.output as string,
      json: Boolean(opts.json),
    });
  });

program
  .command("check")
  .description("Quick check: detect configs and show risk summary (no files written)")
  .action(async () => {
    const { checkCommand } = await import("./commands/check.js");
    await checkCommand();
  });

program.parse();

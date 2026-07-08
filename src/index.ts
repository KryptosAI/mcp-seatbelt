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
  .option("--yes", "Skip prompts and update client configs automatically")
  .action(async (opts) => {
    const { initCommand } = await import("./commands/init.js");
    await initCommand({
      output: opts.output as string,
      policy: opts.policy as string,
      yes: Boolean(opts.yes),
    });
  });

program
  .command("proxy")
  .description("Start the MCP Seatbelt proxy with policy enforcement")
  .option("-p, --port <port>", "Proxy port", "9420")
  .option("-c, --config <path>", "Policy config path", ".mcp-seatbelt/policy.yml")
  .option("--auth-key <key>", "Require API key via Authorization: Bearer <key>")
  .option("--rate-limit <n>", "Max requests per minute per client IP", "100")
  .action(async (opts) => {
    const { proxyCommand } = await import("./commands/proxy.js");
    await proxyCommand({
      port: opts.port as string,
      config: opts.config as string,
      authKey: opts.authKey as string | undefined,
      rateLimit: opts.rateLimit as string | undefined,
    });
  });

program
  .command("report")
  .description("Generate a risk report from detected MCP configs")
  .option("-o, --output <path>", "Output file", ".mcp-seatbelt/report.md")
  .option("--json", "Output JSON instead of markdown")
  .option("--sarif", "Output SARIF 2.1.0 JSON")
  .action(async (opts) => {
    const { reportCommand } = await import("./commands/report.js");
    await reportCommand({
      output: opts.output as string,
      json: Boolean(opts.json),
      sarif: Boolean(opts.sarif),
    });
  });

program
  .command("check")
  .description("Quick check: detect configs and show risk summary (no files written)")
  .action(async () => {
    const { checkCommand } = await import("./commands/check.js");
    await checkCommand();
  });

program
  .command("diff")
  .description("Compare two policy YAML files or risk-report JSON files")
  .argument("<old>", "Old policy or report file")
  .argument("<new>", "New policy or report file")
  .action(async (oldFile: string, newFile: string) => {
    const { diffCommand } = await import("./commands/diff.js");
    await diffCommand({ oldFile, newFile });
  });

program
  .command("dashboard")
  .description("Start a live dashboard web UI at http://localhost:9421")
  .option("-p, --port <port>", "Dashboard port", "9421")
  .action(async (opts) => {
    const { dashboardCommand } = await import("./commands/dashboard.js");
    await dashboardCommand({ port: opts.port as string });
  });

program
  .command("import-observatory")
  .description("Import mcp-observatory scan results and output suggested policy rules")
  .argument("[artifact-path]", "Path to observatory artifact JSON file (auto-discovers if omitted)")
  .option("-b, --base <path>", "Base path to search for observatory artifacts", process.cwd())
  .action(async (artifactPath: string | undefined, opts) => {
    const { importObservatoryCommand } = await import("./commands/import-observatory.js");
    await importObservatoryCommand({
      artifactPath: artifactPath as string | undefined,
      base: opts.base as string,
    });
  });

program.parse();

export { ProxyServer, interceptRequest, filterToolsListResponse, filterResourcesListResponse, filterPromptsListResponse, SseClient } from './proxy/index.js';
export type { RegisteredServer, MCPRequest, MCPResponse } from './proxy/index.js';
export { PolicyEngine } from './policy/engine.js';
export type { EvaluateContext } from './policy/engine.js';
export { validatePolicy } from './policy/schema.js';
export { DEFAULT_POLICY, DEFAULT_TEMPLATES, generateDefaultPolicy, generateDefaultPolicyFile } from './policy/defaults.js';
export { detectAll, parseMcpServers } from './detectors/index.js';
export { assessRisk } from './detectors/risk.js';
export * from './types.js';

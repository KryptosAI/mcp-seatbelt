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
  .option("--audit-file <path>", "Path for signed audit log", ".mcp-seatbelt/audit.jsonl")
  .option("--audit-secret <secret>", "Secret for audit log HMAC (or SEATBELT_AUDIT_SECRET env)")
  .option("--judge", "Enable LLM-as-judge semantic analysis (default: heuristic, no API needed)")
  .option("--judge-model <model>", "LLM model for judge API calls")
  .option("--judge-key <key>", "API key for judge (or set OPENAI_API_KEY / ANTHROPIC_API_KEY)")
  .option("--dlp", "Enable DLP response scanning (default: true)")
  .option("--no-dlp", "Disable DLP response scanning")
  .option("--watch", "Enable hot reload via file watcher + SIGHUP (default: true when not in CI)")
  .option("--no-watch", "Disable hot reload")
  .option("--stats", "Periodically print proxy stats to stdout")
  .action(async (opts) => {
    const { proxyCommand } = await import("./commands/proxy.js");
    const isCI = process.env.CI !== undefined;
    await proxyCommand({
      port: opts.port as string,
      config: opts.config as string,
      authKey: opts.authKey as string | undefined,
      rateLimit: opts.rateLimit as string | undefined,
      auditFile: opts.auditFile as string | undefined,
      auditSecret: opts.auditSecret as string | undefined,
      judge: Boolean(opts.judge),
      judgeModel: opts.judgeModel as string | undefined,
      judgeKey: opts.judgeKey as string | undefined,
      dlp: (opts.dlp as boolean | undefined) ?? true,
      watch: opts.watch !== undefined ? opts.watch : !isCI,
      stats: Boolean(opts.stats),
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
  .option("--policy <path>", "Path to policy YAML file for simulate endpoint")
  .action(async (opts) => {
    const { dashboardCommand } = await import("./commands/dashboard.js");
    await dashboardCommand({
      port: opts.port as string,
      policyPath: opts.policy as string | undefined,
    });
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

program
  .command("baseline")
  .description("Generate a behavioral baseline report from audit log observations")
  .option("--audit-file <path>", "Path to audit log JSON file")
  .action(async (opts) => {
    const { baselineCommand } = await import("./commands/baseline.js");
    await baselineCommand({
      auditFile: opts.auditFile as string | undefined,
    });
  });

program
  .command("verify-audit")
  .description("Verify a signed audit log file")
  .argument("<path>", "Path to audit log file (.audit.jsonl)")
  .requiredOption("--secret <secret>", "HMAC secret (or SEATBELT_AUDIT_SECRET env)")
  .action(async (auditPath: string, opts) => {
    const { verifyAuditFile } = await import("./audit.js");
    const secret = opts.secret as string || process.env.SEATBELT_AUDIT_SECRET;
    if (!secret) {
      console.error("Error: --secret is required or set SEATBELT_AUDIT_SECRET env var");
      process.exit(1);
    }
    const result = await verifyAuditFile(auditPath, secret);
    console.log(`Verified ${result.total.toLocaleString()} entries. ${result.tampered} tampered.`);
    if (result.tampered > 0) {
      process.exit(1);
    }
  });

program
  .command("benchmark")
  .description("Run performance benchmarks against the proxy")
  .option("-p, --port <port>", "Proxy port", "9420")
  .option("-n, --requests <n>", "Number of requests to send", "1000")
  .option("-c, --concurrency <n>", "Number of concurrent requests", "10")
  .option("--warmup <n>", "Number of warmup requests before measuring", "100")
  .action(async (opts) => {
    const { benchmarkCommand } = await import("./commands/benchmark.js");
    await benchmarkCommand({
      port: opts.port as string,
      requests: parseInt(opts.requests, 10),
      concurrency: parseInt(opts.concurrency, 10),
      warmup: parseInt(opts.warmup, 10),
    });
  });

program
  .command("simulate")
  .description("Simulate a tool call against the policy and show evaluation trace")
  .requiredOption("--tool <name>", "Tool name to simulate")
  .option("--description <text>", "Tool description")
  .option("--args <json>", "Tool arguments as JSON string", "{}")
  .option("--server <name>", "Server/client name", "simulate")
  .option("--policy <path>", "Path to policy YAML file", ".mcp-seatbelt/policy.yml")
  .option("--json", "Output machine-readable JSON")
  .option("--verbose", "Show all rules evaluated, not just matching ones")
  .action(async (opts) => {
    const { simulateCommand } = await import("./commands/simulate.js");
    await simulateCommand({
      tool: opts.tool as string,
      description: opts.description as string | undefined,
      args: opts.args as string,
      server: opts.server as string,
      policy: opts.policy as string,
      json: Boolean(opts.json),
      verbose: Boolean(opts.verbose),
    });
  });

program
  .command("test-policy")
  .description("Run policy tests from a test YAML file")
  .argument("<test-file>", "Path to test YAML file")
  .option("--policy <path>", "Path to policy YAML file (uses default if omitted)")
  .action(async (testFile: string, opts) => {
    const { testPolicyCommand } = await import("./commands/test-policy.js");
    await testPolicyCommand({
      testFile,
      policy: opts.policy as string | undefined,
    });
  });

program.parse();

export { ProxyServer, interceptRequest, filterToolsListResponse, filterResourcesListResponse, filterPromptsListResponse, scanResponse, SseClient } from './proxy/index.js';
export type { RegisteredServer, MCPRequest, MCPResponse, RedactionLog, ScanResult } from './proxy/index.js';
export { PolicyEngine, BehavioralBaseline } from './policy/engine.js';
export type { EvaluateContext, Deviation, ToolProfile } from './policy/engine.js';
export { LLMJudge } from './policy/llm-judge.js';
export type { JudgeConfig, JudgeResult } from './policy/llm-judge.js';
export { validatePolicy } from './policy/schema.js';
export { DEFAULT_POLICY, DEFAULT_TEMPLATES, generateDefaultPolicy, generateDefaultPolicyFile } from './policy/defaults.js';
export { detectAll, parseMcpServers } from './detectors/index.js';
export { assessRisk } from './detectors/risk.js';
export { AuditTrail } from './audit.js';
export * from './types.js';

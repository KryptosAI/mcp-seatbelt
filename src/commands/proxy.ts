import { readFileSync, existsSync, watch } from "node:fs";
import path from "node:path";
import chalk from "chalk";
import { parsePolicy } from "../policy/yaml.js";
import { detectAll } from "../detectors/index.js";
import { ProxyServer } from "../proxy/index.js";
import { PolicyEngine } from "../policy/engine.js";
import { AuditTrail } from "../audit.js";
import { LLMJudge } from "../policy/llm-judge.js";

export interface ProxyOptions {
  port: string;
  config: string;
  authKey?: string;
  rateLimit?: string;
  auditFile?: string;
  auditSecret?: string;
  judge?: boolean;
  judgeModel?: string;
  judgeKey?: string;
  dlp?: boolean;
  watch?: boolean;
  stats?: boolean;
}

export async function proxyCommand(opts: ProxyOptions): Promise<void> {
  const configPath = path.resolve(opts.config);

  if (!existsSync(configPath)) {
    console.error(chalk.red(`Policy config not found: ${configPath}`));
    console.log(chalk.dim("Run 'mcp-seatbelt init' first to generate a policy."));
    process.exit(1);
  }

  const raw = readFileSync(configPath, "utf-8");
  const policyConfig = parsePolicy(raw);
  const policy = new PolicyEngine(policyConfig);

  if (opts.judge) {
    const judge = new LLMJudge({
      provider: opts.judgeKey ? (process.env.MCP_SEATBELT_JUDGE_PROVIDER as "openai" | "anthropic" | undefined) || "openai" : "local",
      model: opts.judgeModel,
      apiKey: opts.judgeKey || process.env.OPENAI_API_KEY || process.env.ANTHROPIC_API_KEY,
    });
    policy.setJudge(judge);
  }

  const auditSecret = opts.auditSecret || process.env.SEATBELT_AUDIT_SECRET;
  if (opts.auditFile && auditSecret) {
    const trail = new AuditTrail(opts.auditFile, auditSecret);
    policy.setAuditTrail(trail);
    console.log(chalk.dim(`Audit trail: ${opts.auditFile}`));
  }

  console.log(chalk.cyan("\n🔐 MCP Seatbelt Proxy"));
  console.log(chalk.dim(`Mode: ${policyConfig.mode} | Port: ${opts.port}`));
  if (opts.authKey) {
    console.log(chalk.dim(`API key auth: enabled`));
  }
  if (opts.rateLimit) {
    console.log(chalk.dim(`Rate limit: ${opts.rateLimit} req/min`));
  }
  if (opts.judge) {
    console.log(chalk.dim(`LLM judge: enabled (${opts.judgeKey ? 'API mode' : 'heuristic mode'})`));
  }
  if (opts.watch) {
    console.log(chalk.dim(`Hot reload: enabled`));
  }
  if (opts.stats) {
    console.log(chalk.dim(`Stats: enabled (every 5s)`));
  }
  console.log();

  const configs = await detectAll();
  const allServers = configs.flatMap((c) => c.servers);

  if (allServers.length === 0) {
    console.log(chalk.yellow("No MCP servers detected to proxy."));
    process.exit(0);
  }

  const rateLimitNum = opts.rateLimit ? parseInt(opts.rateLimit, 10) : undefined;

  if (opts.authKey) {
    process.env.MCP_SEATBELT_API_KEY = opts.authKey;
  }

  const proxy = new ProxyServer(policy, parseInt(opts.port, 10), {
    apiKey: opts.authKey,
    rateLimit: rateLimitNum,
    dlp: opts.dlp ?? true,
  });

  for (const config of configs) {
    for (const server of config.servers) {
      proxy.register(server, config.client);
    }
  }

  await proxy.start();

  const levelColor: Record<string, typeof chalk.red> = {
    critical: chalk.red,
    high: chalk.red,
    medium: chalk.yellow,
    low: chalk.green,
  };

  console.log(chalk.bold("Proxied Servers:"));
  console.log("┌──────────────────────┬──────────────────────────────────┬──────────┐");
  console.log("│ Server               │ Proxy URL                        │ Risk     │");
  console.log("├──────────────────────┼──────────────────────────────────┼──────────┤");

  for (const srv of proxy.getServers()) {
    const name = srv.name.padEnd(20).slice(0, 20);
    const url = srv.proxyUrl.padEnd(32).slice(0, 32);
    const colorFn = levelColor[srv.risk] || chalk.white;
    const risk = srv.risk.padEnd(8);
    console.log(`│ ${name} │ ${url} │ ${colorFn(risk)} │`);
  }

  console.log("└──────────────────────┴──────────────────────────────────┴──────────┘\n");

  console.log(chalk.bold("Update your MCP client config to use these proxy URLs:"));
  console.log();

  for (const srv of proxy.getServers()) {
    console.log(chalk.dim(`  ${srv.name}:`), chalk.cyan(srv.proxyUrl));
  }

  console.log();
  console.log(chalk.green(`Proxy running on port ${opts.port}. Press Ctrl+C to stop.\n`));

  let watcher: ReturnType<typeof watch> | null = null;
  let statsInterval: ReturnType<typeof setInterval> | null = null;
  let reloadGate = false;

  const reloadPolicy = () => {
    if (reloadGate) return;
    reloadGate = true;

    try {
      setTimeout(() => { reloadGate = false; }, 500);

      const rawReload = readFileSync(configPath, "utf-8");
      const newConfig = parsePolicy(rawReload);
      const ruleCount = proxy.reloadPolicy(newConfig);
      console.log(chalk.cyan(`[mcp-seatbelt] Policy reloaded (${ruleCount} rules)`));
    } catch (err) {
      reloadGate = false;
      console.error(chalk.red(`[mcp-seatbelt] Policy reload failed: ${err instanceof Error ? err.message : String(err)}`));
    }
  };

  if (opts.watch) {
    watcher = watch(configPath, (eventType) => {
      if (eventType === "change") {
        reloadPolicy();
      }
    });
  }

  if (opts.stats) {
    statsInterval = setInterval(() => {
      const s = proxy.getStats();
      const lat = proxy.getLatencyStats();
      const serverCount = proxy.getServers().length;
      const now = new Date().toTimeString().slice(0, 8);
      console.log(
        `[${now}] proxying ${serverCount} servers | ${lat.throughput} req/s | p50=${lat.p50}ms p95=${lat.p95}ms | ${s.blocked} blocked | ${s.warned} warned`,
      );
    }, 5000);
  }

  const shutdown = () => {
    console.log(chalk.dim("\nShutting down proxy..."));
    if (watcher) { watcher.close(); }
    if (statsInterval) { clearInterval(statsInterval); }
    proxy.stop();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  process.on("SIGUSR1", () => {
    console.log(chalk.dim("[mcp-seatbelt] SIGUSR1 received — reloading policy"));
    reloadPolicy();
  });
  process.on("SIGHUP", () => {
    console.log(chalk.dim("[mcp-seatbelt] SIGHUP received — reloading policy"));
    reloadPolicy();
  });
}
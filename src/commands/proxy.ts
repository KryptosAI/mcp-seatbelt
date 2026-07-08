import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import chalk from "chalk";
import { parsePolicy } from "../policy/yaml.js";
import { detectAll } from "../detectors/index.js";
import { ProxyServer } from "../proxy/index.js";
import { PolicyEngine } from "../policy/engine.js";

export interface ProxyOptions {
  port: string;
  config: string;
  authKey?: string;
  rateLimit?: string;
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

  console.log(chalk.cyan("\n🔐 MCP Seatbelt Proxy"));
  console.log(chalk.dim(`Mode: ${policyConfig.mode} | Port: ${opts.port}`));
  if (opts.authKey) {
    console.log(chalk.dim(`API key auth: enabled`));
  }
  if (opts.rateLimit) {
    console.log(chalk.dim(`Rate limit: ${opts.rateLimit} req/min`));
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

  const shutdown = () => {
    console.log(chalk.dim("\nShutting down proxy..."));
    proxy.stop();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

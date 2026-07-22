/**
 * Benchmark proxy runner. Started as a child process by run-benchmarks.ts so
 * that proxy memory (RSS) can be measured in isolation from the load driver.
 *
 * Scenarios:
 *   1-rule          minimal policy (1 rule), DLP off
 *   7-rules         default-sized policy (7 rules), DLP off
 *   20-rules        heavy policy (20 rules), DLP off
 *   7-rules-dlp     7 rules with DLP response scanning enabled
 *   7-rules-schema  7 rules with compiled JSON-schema arg validation
 */
import { ProxyServer } from "../src/proxy/server.js";
import { PolicyEngine } from "../src/policy/engine.js";
import { DEFAULT_POLICY } from "../src/policy/defaults.js";
import { compileToolSchema } from "../src/security/schema-validator.js";
import type { PolicyConfig, PolicyRule } from "../src/types.js";

function arg(name: string): string {
  const idx = process.argv.indexOf(`--${name}`);
  const value = idx >= 0 ? process.argv[idx + 1] : undefined;
  if (!value) {
    console.error(`Missing required argument --${name}`);
    process.exit(1);
  }
  return value;
}

const scenario = arg("scenario");
const port = parseInt(arg("port"), 10);
const upstream = arg("upstream");

function extraRules(count: number): PolicyRule[] {
  const templates: PolicyRule[] = [
    {
      id: "bench-block-env-access",
      description: "Block access to environment variables",
      target: "env",
      match: "pattern",
      values: ["^AWS_", "^AZURE_", "^GCP_", "^SECRET"],
      action: "deny",
    },
    {
      id: "bench-block-outbound-ssh",
      description: "Block outbound SSH",
      target: "network",
      match: "pattern",
      values: ["^ssh://", "\\bscp\\b", "\\bsftp\\b"],
      action: "deny",
    },
    {
      id: "bench-warn-large-reads",
      description: "Warn on bulk file reads",
      target: "file",
      match: "contains",
      values: ["bulk", "archive", "backup"],
      action: "warn",
    },
    {
      id: "bench-block-dns-tunnel",
      description: "Block DNS tunneling patterns",
      target: "network",
      match: "pattern",
      values: ["\\bnslookup\\b", "\\bdig\\b", "\\bhost\\b"],
      action: "deny",
    },
    {
      id: "bench-block-crypto-miners",
      description: "Block crypto miner process names",
      target: "process",
      match: "contains",
      values: ["xmrig", "minerd", "cgminer"],
      action: "deny",
    },
    {
      id: "bench-block-temp-exec",
      description: "Block execution from temp directories",
      target: "file",
      match: "pattern",
      values: ["^/tmp/", "^/var/tmp/", "^C:\\\\Temp"],
      action: "deny",
    },
    {
      id: "bench-block-package-install",
      description: "Block package manager invocation",
      target: "command",
      match: "pattern",
      values: ["\\bnpm\\s+install\\b", "\\bpip\\s+install\\b", "\\bapt(-get)?\\s+install\\b", "\\bbrew\\s+install\\b"],
      action: "deny",
    },
    {
      id: "bench-block-cloud-metadata",
      description: "Block cloud instance metadata endpoints",
      target: "network",
      match: "pattern",
      values: ["169\\.254\\.169\\.254", "metadata\\.google\\.internal"],
      action: "deny",
    },
    {
      id: "bench-redact-api-responses",
      description: "Redact keys that look like API tokens",
      target: "command",
      match: "contains",
      values: ["api_token", "access_token", "refresh_token"],
      action: "redact",
    },
    {
      id: "bench-block-registry-writes",
      description: "Block Windows registry modification",
      target: "command",
      match: "pattern",
      values: ["\\breg\\s+add\\b", "\\bregedit\\b"],
      action: "deny",
    },
    {
      id: "bench-block-log-deletion",
      description: "Block deletion of log files",
      target: "file",
      match: "pattern",
      values: ["\\.log$", "\\bjournalctl\\b"],
      action: "deny",
    },
  ];
  return templates.slice(0, count);
}

function buildPolicy(name: string): PolicyConfig {
  const base = structuredClone(DEFAULT_POLICY);
  base.mode = "enforce";
  base.defaultAction = "allow";
  base.allowSampling = true;
  base.allowlist = { tools: [], paths: [], hosts: [], envVars: [] };

  if (name === "1-rule") {
    base.rules = base.rules.slice(0, 1);
  } else if (name.startsWith("7-rules")) {
    base.rules = base.rules.slice(0, 7);
  } else if (name === "20-rules") {
    base.rules = [...base.rules, ...extraRules(20 - base.rules.length)];
  } else {
    throw new Error(`Unknown scenario: ${name}`);
  }
  return base;
}

const dlp = scenario === "7-rules-dlp";
const policy = buildPolicy(scenario);
const engine = new PolicyEngine(policy);

if (scenario === "7-rules-schema") {
  compileToolSchema("bench-tool", {
    type: "object",
    properties: { benchmark: { type: "boolean" } },
    additionalProperties: true,
  });
}

const proxy = new ProxyServer(engine, port, {
  rateLimit: 100_000_000,
  dlp,
  injectHoneytokens: false,
});

proxy.register(
  {
    name: "bench",
    command: "bench-upstream",
    args: [],
    transport: "http",
    url: upstream,
    risk: { score: 0, level: "low", flags: [] },
  },
  "benchmark",
);

await proxy.start();
console.log("READY");

const shutdown = async () => {
  try {
    await proxy.stop();
  } catch {
    // ignore
  }
  process.exit(0);
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

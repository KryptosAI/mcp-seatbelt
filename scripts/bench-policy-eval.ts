/**
 * Microbenchmark of PolicyEngine.evaluate() in isolation (no HTTP, no proxy).
 * Measures per-call policy evaluation latency for 1, 7, and 20 rule policies.
 *
 *   npx tsx scripts/bench-policy-eval.ts [--iterations 100000]
 */
import { PolicyEngine } from "../src/policy/engine.js";
import { DEFAULT_POLICY } from "../src/policy/defaults.js";
import { compileToolSchema, validateToolArgs } from "../src/security/schema-validator.js";
import type { PolicyConfig, PolicyRule } from "../src/types.js";

function opt(name: string, fallback: number): number {
  const idx = process.argv.indexOf(`--${name}`);
  const value = idx >= 0 ? parseInt(process.argv[idx + 1] ?? "", 10) : NaN;
  return Number.isFinite(value) ? value : fallback;
}

const ITERATIONS = opt("iterations", 100_000);

function extraRules(count: number): PolicyRule[] {
  const base: PolicyRule[] = [
    { id: "x-env", description: "env", target: "env", match: "pattern", values: ["^AWS_", "^SECRET"], action: "deny" },
    { id: "x-ssh", description: "ssh", target: "network", match: "pattern", values: ["^ssh://", "\\bscp\\b"], action: "deny" },
    { id: "x-bulk", description: "bulk", target: "file", match: "contains", values: ["bulk", "archive"], action: "warn" },
    { id: "x-dns", description: "dns", target: "network", match: "pattern", values: ["\\bnslookup\\b", "\\bdig\\b"], action: "deny" },
    { id: "x-miner", description: "miner", target: "process", match: "contains", values: ["xmrig", "minerd"], action: "deny" },
    { id: "x-tmp", description: "tmp", target: "file", match: "pattern", values: ["^/tmp/", "^/var/tmp/"], action: "deny" },
    { id: "x-pkg", description: "pkg", target: "command", match: "pattern", values: ["\\bnpm\\s+install\\b", "\\bpip\\s+install\\b"], action: "deny" },
    { id: "x-meta", description: "meta", target: "network", match: "pattern", values: ["169\\.254\\.169\\.254"], action: "deny" },
    { id: "x-token", description: "token", target: "command", match: "contains", values: ["api_token", "access_token"], action: "redact" },
    { id: "x-reg", description: "reg", target: "command", match: "pattern", values: ["\\breg\\s+add\\b"], action: "deny" },
    { id: "x-log", description: "log", target: "file", match: "pattern", values: ["\\.log$"], action: "deny" },
  ];
  return base.slice(0, count);
}

function buildPolicy(ruleCount: number): PolicyConfig {
  const config = structuredClone(DEFAULT_POLICY);
  config.mode = "enforce";
  config.defaultAction = "allow";
  config.allowlist = { tools: [], paths: [], hosts: [], envVars: [] };
  config.rules = ruleCount <= config.rules.length
    ? config.rules.slice(0, ruleCount)
    : [...config.rules, ...extraRules(ruleCount - config.rules.length)];
  return config;
}

function bench(name: string, fn: () => void): { p50us: number; p95us: number; p99us: number; avgUs: number } {
  // warmup
  for (let i = 0; i < 5_000; i++) fn();

  const samples: number[] = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const start = process.hrtime.bigint();
    fn();
    samples.push(Number(process.hrtime.bigint() - start) / 1_000); // microseconds
  }
  samples.sort((a, b) => a - b);
  const at = (p: number) => samples[Math.min(samples.length - 1, Math.floor(samples.length * p))];
  const avg = samples.reduce((s, v) => s + v, 0) / samples.length;
  return {
    p50us: parseFloat(at(0.5).toFixed(3)),
    p95us: parseFloat(at(0.95).toFixed(3)),
    p99us: parseFloat(at(0.99).toFixed(3)),
    avgUs: parseFloat(avg.toFixed(3)),
  };
}

const args = { benchmark: true };
const description = "Instant benchmark tool that returns a fixed response";

console.log(`\nPolicyEngine.evaluate() microbenchmark (${ITERATIONS.toLocaleString()} iterations, µs per call)\n`);

for (const ruleCount of [1, 7, 20]) {
  const engine = new PolicyEngine(buildPolicy(ruleCount));
  const stats = bench(`${ruleCount} rules`, () => {
    engine.evaluate("bench-tool", description, args);
  });
  console.log(
    `${String(ruleCount).padStart(2)} rules   p50=${stats.p50us}µs  p95=${stats.p95us}µs  p99=${stats.p99us}µs  avg=${stats.avgUs}µs`,
  );
}

compileToolSchema("bench-tool", {
  type: "object",
  properties: { benchmark: { type: "boolean" } },
  additionalProperties: true,
});
const schemaStats = bench("schema", () => {
  validateToolArgs("bench-tool", args);
});
console.log(`\nJSON-schema arg validation (compiled AJV): p50=${schemaStats.p50us}µs  p95=${schemaStats.p95us}µs  p99=${schemaStats.p99us}µs  avg=${schemaStats.avgUs}µs\n`);

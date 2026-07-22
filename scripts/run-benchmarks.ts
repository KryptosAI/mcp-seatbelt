/**
 * Benchmark orchestrator for mcp-seatbelt.
 *
 * Runs the full benchmark matrix and writes results to
 * scripts/benchmark-results.json:
 *
 *   baseline          direct HTTP to the instant upstream (no proxy)
 *   1-rule            proxy with 1 policy rule, DLP off
 *   7-rules           proxy with 7 policy rules, DLP off
 *   20-rules          proxy with 20 policy rules, DLP off
 *   7-rules-dlp       proxy with 7 rules, DLP response scanning on
 *   7-rules-schema    proxy with 7 rules, JSON-schema arg validation on
 *
 * The proxy for each scenario runs as a separate child process so RSS memory
 * can be attributed to the proxy alone. Usage:
 *
 *   npx tsx scripts/run-benchmarks.ts [--requests 1000] [--concurrency 10] [--warmup 100]
 */
import { spawn, execFile, type ChildProcess } from "node:child_process";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));

function opt(name: string, fallback: number): number {
  const idx = process.argv.indexOf(`--${name}`);
  const value = idx >= 0 ? parseInt(process.argv[idx + 1] ?? "", 10) : NaN;
  return Number.isFinite(value) ? value : fallback;
}

const REQUESTS = opt("requests", 1000);
const CONCURRENCY = opt("concurrency", 10);
const WARMUP = opt("warmup", 100);

const UPSTREAM_PORT = 19577;
const PROXY_BASE_PORT = 19420;

interface RunResult {
  scenario: string;
  requests: number;
  concurrency: number;
  wallSec: number;
  reqPerSec: number;
  p50: number;
  p95: number;
  p99: number;
  avg: number;
  min: number;
  max: number;
  errors: number;
  rssIdleMb?: number;
  rssPeakMb?: number;
  rssLoadedMb?: number;
}

function startChild(script: string, args: string[]): { child: ChildProcess; ready: Promise<void> } {
  const child = spawn("npx", ["tsx", join(__dirname, script), ...args], {
    stdio: ["ignore", "pipe", "inherit"],
  });

  const ready = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${script} did not become ready in 30s`)), 30_000);
    child.stdout?.on("data", (chunk: Buffer) => {
      if (chunk.toString().includes("READY")) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`${script} exited early with code ${code}`));
    });
  });

  return { child, ready };
}

async function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null) return;
  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve();
    }, 5_000);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    child.kill("SIGTERM");
  });
}

async function rssMb(pid: number): Promise<number> {
  const { stdout } = await execFileAsync("ps", ["-o", "rss=", "-p", String(pid)]);
  return parseFloat((parseInt(stdout.trim(), 10) / 1024).toFixed(1));
}

function startPeakSampler(pid: number): { stop: () => number } {
  let peak = 0;
  const timer = setInterval(async () => {
    try {
      const rss = await rssMb(pid);
      if (rss > peak) peak = rss;
    } catch {
      // process gone
    }
  }, 50);
  return {
    stop: () => {
      clearInterval(timer);
      return peak;
    },
  };
}

function percentile(sorted: number[], p: number): number {
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
}

async function runLoad(url: string, requests: number, concurrency: number): Promise<{ latencies: number[]; errors: number; wallSec: number }> {
  const latencies: number[] = [];
  let errors = 0;

  const send = async (): Promise<void> => {
    const start = process.hrtime.bigint();
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "tools/call",
          params: { name: "bench-tool", arguments: { benchmark: true } },
          id: 1,
        }),
      });
      const body = (await response.json()) as { error?: unknown };
      if (!response.ok || body.error) errors++;
    } catch {
      errors++;
    }
    latencies.push(Number(process.hrtime.bigint() - start) / 1_000_000);
  };

  const wallStart = Date.now();
  for (let i = 0; i < requests; i += concurrency) {
    const batch = Math.min(concurrency, requests - i);
    await Promise.all(Array.from({ length: batch }, () => send()));
  }
  const wallSec = (Date.now() - wallStart) / 1000;

  return { latencies, errors, wallSec };
}

function summarize(scenario: string, latencies: number[], errors: number, wallSec: number): RunResult {
  const sorted = [...latencies].sort((a, b) => a - b);
  const count = sorted.length;
  const avg = sorted.reduce((s, v) => s + v, 0) / count;
  return {
    scenario,
    requests: count,
    concurrency: CONCURRENCY,
    wallSec: parseFloat(wallSec.toFixed(2)),
    reqPerSec: parseFloat((count / wallSec).toFixed(1)),
    p50: parseFloat(percentile(sorted, 0.5).toFixed(2)),
    p95: parseFloat(percentile(sorted, 0.95).toFixed(2)),
    p99: parseFloat(percentile(sorted, 0.99).toFixed(2)),
    avg: parseFloat(avg.toFixed(2)),
    min: parseFloat(sorted[0].toFixed(2)),
    max: parseFloat(sorted[count - 1].toFixed(2)),
    errors,
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function main(): Promise<void> {
  console.log(`\nBenchmark matrix: ${REQUESTS} requests, concurrency ${CONCURRENCY}, warmup ${WARMUP}\n`);

  const upstream = startChild("bench-upstream.ts", ["--port", String(UPSTREAM_PORT)]);
  await upstream.ready;
  console.log(`Upstream ready on :${UPSTREAM_PORT} (pid ${upstream.child.pid})`);

  const results: RunResult[] = [];

  // Baseline: direct to upstream, no proxy.
  await runLoad(`http://localhost:${UPSTREAM_PORT}/`, WARMUP, CONCURRENCY);
  const base = await runLoad(`http://localhost:${UPSTREAM_PORT}/`, REQUESTS, CONCURRENCY);
  const baseResult = summarize("baseline", base.latencies, base.errors, base.wallSec);
  results.push(baseResult);
  console.log(`baseline        ${baseResult.reqPerSec} req/s  p50=${baseResult.p50}ms p95=${baseResult.p95}ms p99=${baseResult.p99}ms errors=${baseResult.errors}`);

  const scenarios = ["1-rule", "7-rules", "20-rules", "7-rules-dlp", "7-rules-schema"];
  let proxyPort = PROXY_BASE_PORT;

  for (const scenario of scenarios) {
    const runner = startChild("bench-proxy-runner.ts", [
      "--scenario", scenario,
      "--port", String(proxyPort),
      "--upstream", `http://localhost:${UPSTREAM_PORT}/`,
    ]);
    await runner.ready;
    await sleep(750);

    const idle = await rssMb(runner.child.pid!);

    await runLoad(`http://localhost:${proxyPort}/bench`, WARMUP, CONCURRENCY);
    const sampler = startPeakSampler(runner.child.pid!);
    const load = await runLoad(`http://localhost:${proxyPort}/bench`, REQUESTS, CONCURRENCY);

    const loaded = await rssMb(runner.child.pid!);
    const peak = Math.max(sampler.stop(), loaded);

    const result = summarize(scenario, load.latencies, load.errors, load.wallSec);
    result.rssIdleMb = idle;
    result.rssPeakMb = peak;
    result.rssLoadedMb = loaded;
    results.push(result);
    console.log(`${scenario.padEnd(15)} ${result.reqPerSec} req/s  p50=${result.p50}ms p95=${result.p95}ms p99=${result.p99}ms errors=${result.errors}  rss idle=${idle}MB peak=${peak}MB end=${loaded}MB`);

    await stopChild(runner.child);
    proxyPort++;
  }

  await stopChild(upstream.child);

  const outPath = join(__dirname, "benchmark-results.json");
  writeFileSync(
    outPath,
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        requests: REQUESTS,
        concurrency: CONCURRENCY,
        warmup: WARMUP,
        results,
      },
      null,
      2,
    ),
  );
  console.log(`\nResults written to ${outPath}\n`);

  const totalErrors = results.reduce((s, r) => s + r.errors, 0);
  if (totalErrors > 0) {
    console.error(`WARNING: ${totalErrors} failed requests across all scenarios`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

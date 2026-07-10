import chalk from "chalk";

export interface BenchmarkOptions {
  port: string;
  requests: number;
  concurrency: number;
  warmup: number;
}

interface BenchmarkResult {
  totalRequests: number;
  totalTimeMs: number;
  reqPerSec: number;
  p50: number;
  p95: number;
  p99: number;
  avg: number;
  max: number;
}

async function sendRequest(port: string, serverName: string, toolName: string): Promise<number> {
  const startNs = process.hrtime.bigint();
  const response = await fetch(`http://localhost:${port}/${serverName}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "tools/call",
      params: { name: toolName, arguments: { benchmark: true } },
      id: Date.now(),
    }),
  });
  await response.json();
  const endNs = process.hrtime.bigint();
  return Number(endNs - startNs) / 1_000_000;
}

async function runBatch(
  port: string,
  serverName: string,
  toolName: string,
  count: number,
  concurrency: number,
): Promise<number[]> {
  const latencies: number[] = [];

  for (let i = 0; i < count; i += concurrency) {
    const batchSize = Math.min(concurrency, count - i);
    const promises = Array.from({ length: batchSize }, () =>
      sendRequest(port, serverName, toolName).then((lat) => latencies.push(lat)).catch(() => {}),
    );
    await Promise.all(promises);
  }

  return latencies;
}

function computeStats(latencies: number[]): BenchmarkResult {
  const sorted = [...latencies].sort((a, b) => a - b);
  const count = sorted.length;

  const p50 = sorted[Math.floor(count * 0.5)];
  const p95 = sorted[Math.floor(count * 0.95)];
  const p99 = sorted[Math.floor(count * 0.99)];
  const avg = sorted.reduce((sum, v) => sum + v, 0) / count;
  const max = sorted[count - 1];
  const totalTimeMs = sorted.reduce((sum, v) => sum + v, 0);

  return {
    totalRequests: count,
    totalTimeMs: parseFloat(totalTimeMs.toFixed(2)),
    reqPerSec: parseFloat((count / (totalTimeMs / 1000)).toFixed(1)),
    p50: parseFloat(p50.toFixed(2)),
    p95: parseFloat(p95.toFixed(2)),
    p99: parseFloat(p99.toFixed(2)),
    avg: parseFloat(avg.toFixed(2)),
    max: parseFloat(max.toFixed(2)),
  };
}

export async function benchmarkCommand(opts: BenchmarkOptions): Promise<void> {
  const { port, requests, concurrency, warmup } = opts;

  console.log(chalk.cyan("\n⚡ mcp-seatbelt Benchmark"));
  console.log(chalk.dim(`Target: http://localhost:${port} | Requests: ${requests} | Concurrency: ${concurrency} | Warmup: ${warmup}\n`));

  try {
    await fetch(`http://localhost:${port}/health`);
  } catch {
    console.error(chalk.red(`Failed to connect to proxy at http://localhost:${port}/health`));
    console.error(chalk.dim("Make sure the proxy is running: mcp-seatbelt proxy\n"));
    process.exit(1);
  }

  const response = await fetch(`http://localhost:${port}/health`);
  const health = await response.json() as { stats: { allowed: number; blocked: number } };
  const initialAllowed = health.stats.allowed;

  if (warmup > 0) {
    console.log(chalk.dim(`Warming up with ${warmup} requests...`));
    const warmupName = `bench-warmup-${Date.now()}`;

    const warmupMock = await fetch(`http://localhost:${port}/${warmupName}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "tools/call",
        params: { name: "warmup", arguments: {} },
        id: 1,
      }),
    });
    const warmupBody = await warmupMock.json();

    if (warmupBody?.error?.code === -32601) {
      console.log(chalk.yellow("No registered MCP servers found on proxy. Run mcp-seatbelt proxy first to register real servers.\n"));
      console.log(chalk.dim("Benchmark uses registered MCP servers. To test raw proxy throughput, register at least one server.\n"));
      process.exit(1);
    }

    await runBatch(port, warmupName, "warmup", warmup, concurrency);
    console.log(chalk.dim("Warmup complete.\n"));
  }

  const benchName = `bench-${Date.now()}`;

  await fetch(`http://localhost:${port}/${benchName}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "tools/call",
      params: { name: "bench", arguments: {} },
      id: 1,
    }),
  }).catch(() => {});

  console.log(chalk.bold(`Running ${requests} requests with ${concurrency} concurrent...`));

  const startWall = Date.now();
  const latencies = await runBatch(port, benchName, "bench", requests, concurrency);
  const elapsedSec = (Date.now() - startWall) / 1000;

  const stats = computeStats(latencies);

  console.log();
  console.log(chalk.bold("Results:"));
  console.log(chalk.green(`${requests} requests in ${elapsedSec.toFixed(1)}s → ${(requests / elapsedSec).toFixed(0)} req/s avg, p95 latency ${stats.p95}ms`));
  console.log();
  console.log(chalk.dim(`  p50: ${stats.p50}ms | p95: ${stats.p95}ms | p99: ${stats.p99}ms`));
  console.log(chalk.dim(`  avg: ${stats.avg}ms | max: ${stats.max}ms | min: ${latencies.length > 0 ? Math.min(...latencies).toFixed(2) : "N/A"}ms`));
  console.log();

  const finalResponse = await fetch(`http://localhost:${port}/health`);
  const finalHealth = await finalResponse.json() as { stats: { allowed: number } };
  const processedByProxy = finalHealth.stats.allowed - initialAllowed;
  console.log(chalk.dim(`Proxy processed ${processedByProxy} requests, dropped ${requests - processedByProxy} at policy layer.`));
  console.log();
}
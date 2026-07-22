# Performance Benchmarks

Measured 2026-07-22 with mcp-seatbelt 0.4.1. All scenarios completed with **zero failed requests**.

## Test environment

| Component | Value |
|---|---|
| CPU | Apple M3 (8 cores) |
| RAM | 24 GB |
| OS | macOS 26.5.2 (Darwin arm64) |
| Node.js | v22.23.1 |
| mcp-seatbelt | 0.4.1 |

## Methodology

- **Upstream**: `scripts/bench-upstream.ts` — an MCP-over-HTTP server that responds instantly to `tools/list` and `tools/call`, so measurements reflect proxy + policy overhead, not upstream work.
- **Isolation**: each scenario runs the proxy as a separate child process (`scripts/bench-proxy-runner.ts`); load is driven from the parent (`scripts/run-benchmarks.ts`). Proxy RSS is sampled externally via `ps` (idle, peak every 50 ms during load, and post-load).
- **Load shape**: 100 warmup requests, then 1,000 measurement requests at concurrency 10 (`tools/call` with `{"benchmark": true}`). Numbers below are **medians of 3 runs**. Run-to-run variance was roughly ±10%.
- **Baseline**: identical load sent directly to the upstream server with no proxy in the path.
- All scenarios run in `enforce` mode with `defaultAction: allow`, honeytokens off, no LLM judge, no API key, no rate limiting. Benchmark arguments contain no IPs or domains, so threat-intel never makes external calls.

## End-to-end results (1,000 requests, concurrency 10)

| Scenario | Throughput | p50 | p95 | p99 |
|---|---|---|---|---|
| Baseline (no proxy) | 4,310 req/s | 1.87 ms | 2.73 ms | 2.98 ms |
| Proxy, 1 rule | 1,898 req/s | 4.12 ms | 6.91 ms | 8.16 ms |
| Proxy, 7 rules (default) | 1,894 req/s | 3.93 ms | 6.62 ms | 7.85 ms |
| Proxy, 20 rules (heavy) | 2,083 req/s | 3.87 ms | 5.79 ms | 6.62 ms |
| Proxy, 7 rules + DLP | 1,876 req/s | 3.96 ms | 6.76 ms | 13.56 ms |
| Proxy, 7 rules + schema validation | 2,096 req/s | 3.87 ms | 5.87 ms | 7.20 ms |

**Reading the numbers:**

- The proxy adds **~2 ms per call** at p50 over the no-proxy baseline (~3.9 ms vs ~1.9 ms) and sustains **~1,900–2,100 req/s** (~45–50% of baseline throughput) in a single process.
- Going from 1 → 20 rules does not measurably change end-to-end latency: per-rule cost (~0.2 µs, see microbenchmark) is far below the HTTP noise floor.
- **DLP** adds ~0.1 ms on average per response. The 13.56 ms p99 above is a single-run GC/tail outlier; the other two runs measured 7.07 ms and 7.15 ms.
- **Schema validation** with a pre-compiled AJV validator is free at this resolution (see below).

## Sustained load (10,000 requests per scenario)

Confirms throughput stability and the memory profile under prolonged load:

| Scenario | Throughput | p50 | RSS idle | RSS peak |
|---|---|---|---|---|
| Baseline (no proxy) | 4,933 req/s | 1.66 ms | — | — |
| Proxy, 1 rule | 2,157 req/s | 3.90 ms | 74.6 MB | 74.6 MB |
| Proxy, 7 rules | 2,086 req/s | 3.97 ms | 74.2 MB | 74.2 MB |
| Proxy, 20 rules | 2,187 req/s | 3.88 ms | 74.3 MB | 74.3 MB |
| Proxy, 7 rules + DLP | 2,038 req/s | 3.96 ms | 74.0 MB | 74.0 MB |
| Proxy, 7 rules + schema | 2,113 req/s | 3.97 ms | 74.4 MB | 74.4 MB |

**Memory profile is flat**: ~74 MB RSS at idle with no measurable growth at peak or after 10,000 requests in any scenario.

## Policy evaluation microbenchmark

`PolicyEngine.evaluate()` measured in isolation (100,000 iterations, µs per call) via `scripts/bench-policy-eval.ts`:

| Policy size | p50 | p95 | p99 | avg |
|---|---|---|---|---|
| 1 rule | 3.71 µs | 4.33 µs | 5.21 µs | 3.91 µs |
| 7 rules | 6.58 µs | 7.67 µs | 12.04 µs | 6.97 µs |
| 20 rules | 8.46 µs | 9.83 µs | 14.75 µs | 8.94 µs |

Compiled JSON-schema argument validation (AJV): **< 1 µs per call** (below timer resolution at p50).

Policy evaluation scales sub-linearly with rule count (~+0.25 µs per additional rule) and is never the bottleneck: transport I/O dominates end-to-end latency.

## Reproduce

```bash
npm install && npm run build

# Full matrix (baseline + 5 scenarios), writes scripts/benchmark-results.json
npx tsx scripts/run-benchmarks.ts --requests 1000 --concurrency 10 --warmup 100

# Policy evaluation microbenchmark
npx tsx scripts/bench-policy-eval.ts

# Against your own running proxy (auto-detects the first registered server)
mcp-seatbelt proxy &
mcp-seatbelt benchmark --requests 1000 --concurrency 10
```

Results vary with hardware, Node version, and upstream server latency. Treat these numbers as a single data point (Apple M3, instant upstream) rather than a guarantee.

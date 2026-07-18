# MCP Servers Are the Next Software Supply Chain Threat — Here's How to Protect Yours

**47,000+ MCP repositories on GitHub. Most have never been security audited.**

236 ★ on GitHub · 1,582 downloads/week on npm

Let that sink in.

AI agents are connecting to MCP (Model Context Protocol) servers at an accelerating pace. Claude, Cursor, opencode — agents everywhere are being given tool access through MCP servers. But here's the uncomfortable truth: **there is no security review process for the servers your agents trust.**

---

## The Problem: Blind Trust at Runtime

Here's how it works today. You find an MCP server on GitHub. It looks useful. You add it to your agent's config. The agent connects to it. Done.

What just happened:

- Your agent now has access to every tool that server exposes
- Those tools can read files, execute commands, make network calls, access APIs
- **You have no idea what the server actually does**

MCP servers are not sandboxed. They run as the same user as your agent. A single malicious tool — or just a poorly written one — can exfiltrate data, modify your system, or leak your API keys.

This isn't theoretical. The attack surface is real and growing daily.

---

## A Real Example: The Kubernetes MCP Server

Let's make this concrete. The `kubernetes-mcp-server` is one of the more popular MCP servers — it gives your agent direct access to your Kubernetes cluster.

We ran it through `mcp-observatory`, our open-source security scanner. Here's what came back:

```
$ npx @kryptosai/mcp-observatory scan kubernetes-mcp-server

┌─────────────────────────────────────────────────────────┐
│              MCP Observatory Scan Report                │
├─────────────────────────────────────────────────────────┤
│  Server: kubernetes-mcp-server                         │
│  Safety Score: 72/100                                  │
├──────────┬──────────────────────────────────────────────┤
│  HIGH    │ Tool outputs include raw cluster credentials │
│  HIGH    │ Unvalidated user input passed to kubectl     │
│  HIGH    │ No rate limiting on pod exec operations      │
│  MEDIUM  │ Access token logged in plaintext             │
│  MEDIUM  │ Overly permissive default RBAC role          │
│  WARN    │ No tool description audit trail              │
├──────────┴──────────────────────────────────────────────┤
│  Tests run: 23  │  Passed: 15  │  Failed: 6  │  Warned: 2 │
└─────────────────────────────────────────────────────────┘
```

Three HIGH severity findings. This server can expose your entire cluster if misconfigured — and it ships that way by default.

Now ask yourself: how many MCP servers have you connected to your agent without running anything like this scan?

---

## The Solution: Scan Before You Trust, Enforce at Runtime

We built two tools to close this gap:

### mcp-observatory — CI-Native Security Testing

An open-source scanner that analyzes MCP servers for security issues across 474 tests covering:

- **Input validation** — does the server sanitize what users send to tools?
- **Tool exposure** — does it expose more tools than it should?
- **Credential hygiene** — are secrets being leaked in tool outputs or logs?
- **Permission scope** — does the server ask for more access than it needs?
- **Output safety** — can tool responses contain dangerous content?

It runs in CI, it runs locally, and it takes seconds.

### mcp-seatbelt — Runtime Enforcement

Scanning is great. But what about when a server updates? Or when you add a new one?

`mcp-seatbelt` sits between your agent and your MCP servers, enforcing security policies at runtime:

- Blocks tools that don't meet your safety threshold
- Strips dangerous output patterns before they reach your agent
- Alerts when a server's behavior changes
- Works as a transparent proxy — no changes to your agent config

Think of it as `npm audit` meets a WAF, but for AI agent tool calls.

---

## Quick Start: Secure Your Agents in 3 Commands

```bash
# 1. Scan any MCP server
npx @kryptosai/mcp-observatory scan <your-mcp-server>

# 2. Enforce policies at runtime (blocks unsafe tool calls)
npx @kryptosai/mcp-seatbelt enforce --policy strict

# 3. Add to CI (GitHub Actions example)
# Just drop this into .github/workflows/mcp-security.yml
- uses: KryptosAI/mcp-observatory-action@v1
  with:
    servers: './mcp-servers/*'
    min-score: 80
```

That's it. Your agents now refuse to talk to unsafe MCP servers, and your CI pipeline catches regressions before they hit production.

---

## The Industry Needs This Yesterday

MCP is an incredible protocol. It's the bridge that lets AI agents interact with the real world — APIs, databases, filesystems, browsers. The ecosystem is exploding, and that's exactly why we need security infrastructure now, before something big happens.

PyPI has `pip-audit`. npm has `npm audit`. Docker images have scanners like Trivy and Grype.

**MCP servers have nothing.** Until now.

We're open-sourcing both tools because security infrastructure shouldn't be proprietary. If your agent connects to MCP servers, these tools should be in your stack.

---

**Links:**

- [mcp-observatory on GitHub](https://github.com/KryptosAI/mcp-observatory)
- [mcp-seatbelt on GitHub](https://github.com/KryptosAI/mcp-seatbelt)
- [MCP Server Safety Index](https://observatory.mcp.security)

*Start scanning. Your agent's tool chain depends on it.*

Follow [@KryptosAI](https://github.com/KryptosAI) on GitHub for updates.

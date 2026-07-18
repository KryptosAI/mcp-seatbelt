# ProductHunt Launch Copy

**Product Name:** MCP Security Platform

**Tagline (60 chars):**
Scan and secure your AI agent's MCP servers in seconds.

**Description (260 chars):**
Open-source security platform for MCP servers. Run 348 tests in CI, enforce at runtime. 236 ★ · 1,582 weekly downloads. Built for teams running AI agents in production. Works with Claude, Cursor, and any MCP agent.

---

## First Comment (Maker's Comment)

Hey ProductHunt 👋

I'm Will from KryptosAI. Two months ago we audited our own AI agent infrastructure and the results scared us. 14 MCP servers connected to our agents — some internal, some from GitHub. Credential leaks, injection vulnerabilities, tools exposing far more access than they needed. And we're a security company.

So we scanned 126 public MCP servers. The results: 72% have medium+ severity findings. Average safety score: 64/100. Not great.

We built the MCP Security Platform — two tools that work together:

**mcp-observatory** — CI-native security scanner. 348 tests across input validation, credential hygiene, permission scoping, and output safety. Attack simulation engine exercises tools with adversarial inputs. Currently at 236 ★ on GitHub.

**mcp-seatbelt** (v0.3.0) — runtime enforcement proxy. Sits between your agent and MCP servers. Blocks unsafe tool calls, strips dangerous outputs, alerts on behavioral drift.

1,582 weekly downloads on npm. Both Apache 2.0. We built this because security infrastructure for the AI tool chain shouldn't be proprietary. The MCP ecosystem is where npm was in 2012 — growing explosively, zero security tooling. We're fixing that before the inevitable supply chain attack.

Try it: `npx @kryptosai/mcp-observatory scan .` — results are always surprising.

⭐ Star the repos, open issues, send PRs. Let's make MCP safe.

— Will & the KryptosAI team

---

**Topics:** Developer Tools, Security, Open Source, AI

**Suggested Launch Date:** This week

**Creator:** KryptosAI

# HackerNews Show HN Post

**Title:** Show HN: mcp-observatory — CI-native security testing for MCP servers (236★, 348 tests)

---

MCP servers are the tools AI agents connect to at runtime. 47,000+ repos on GitHub, most unaudited. One malicious tool = data exfiltrated, credentials leaked.

**mcp-observatory** scans any MCP server with 348 security tests — input validation, credential hygiene, permission scope, tool exposure, output safety. The attack simulation engine exercises each tool with adversarial inputs, not just linting. Found 3 HIGHs in the Kubernetes MCP server alone.

**mcp-seatbelt** (v0.3.0) — the enforcement companion. A transparent proxy that blocks unsafe tool calls, strips dangerous outputs, and alerts on behavioral drift at runtime. Scan with observatory, enforce with seatbelt.

Both Apache 2.0. 1,582 weekly downloads. We built this because MCP server security is entirely unaddressed.

- [mcp-observatory](https://github.com/KryptosAI/mcp-observatory)
- [mcp-seatbelt](https://github.com/KryptosAI/mcp-seatbelt)

# Reddit Post — r/programming

**Title:** We scanned 126 MCP servers for security vulnerabilities. 72% had at least one medium or higher finding.

---

The MCP (Model Context Protocol) safety index findings surprised us. For those not familiar: MCP is the open standard for connecting AI agents to external tools and data sources. When you give Claude or Cursor access to your filesystem, a database, or an API, it goes through an MCP server. There are tens of thousands of these servers on GitHub now, and the ecosystem is growing fast.

We built a security scanner called `mcp-observatory` and ran it against 126 publicly available MCP servers. Here's the safety index breakdown:

- **72%** had at least one medium or higher severity finding
- **41%** exposed more tools than necessary for their stated purpose
- **28%** leaked credentials or tokens in tool output or logs
- **19%** had insufficient input validation that could lead to injection
- The average safety score across all servers was **64/100**

The full results are public in our [Safety Index](https://observatory.mcp.security).

The tool itself is open source and runs 348 tests covering input validation, credential hygiene, permission scoping, tool exposure, and output safety. It also includes an attack simulation engine that actually exercises the server with adversarial inputs — it's not just static analysis.

To scan your own MCP server:

```bash
npx @kryptosai/mcp-observatory scan <path-to-your-server>
```

We also built `mcp-seatbelt` (v0.3.0) for runtime enforcement — it sits as a proxy between your agent and MCP servers and blocks unsafe tool calls.

Why this matters: AI agents are getting more autonomous and more connected. If we don't build security infrastructure for the tool chain now, we're going to have a very bad time later. The npm ecosystem learned this the hard way. Let's not repeat it with MCP.

Both repos are Apache 2.0 licensed:

- [github.com/KryptosAI/mcp-observatory](https://github.com/KryptosAI/mcp-observatory)
- [github.com/KryptosAI/mcp-seatbelt](https://github.com/KryptosAI/mcp-seatbelt)

Happy to answer questions.

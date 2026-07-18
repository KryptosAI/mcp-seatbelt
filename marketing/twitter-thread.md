# Twitter/X Thread — MCP Security Platform Launch

---

**Tweet 1/6**
Your AI agent connects to MCP servers with zero security checks.

47,000+ MCP repos on GitHub. Most unaudited. One malicious tool = credentials stolen, data exfiltrated, system compromised.

MCP security is the biggest blind spot in AI right now. 🧵

---

**Tweet 2/6**
We built two open-source tools to fix this:

🔍 mcp-observatory — CI-native scanner. 348 security tests. Attack simulation engine exercises each tool.

🛡️ mcp-seatbelt — runtime proxy. Blocks unsafe tool calls before they reach your agent.

Scan then enforce. Simple.

---

**Tweet 3/6**
Real example: the Kubernetes MCP server scored 72/100.

3 HIGH findings — raw credential exposure, kubectl injection, unrestricted pod exec.

This is a popular server. People connect it to production clusters. Yikes.

---

**Tweet 4/6**
Try it yourself in 30 seconds:

```bash
npx @kryptosai/mcp-observatory scan <your-server>
npx @kryptosai/mcp-seatbelt start --policy strict
```

Drop the GitHub Action in CI, set a min score, and never ship an unsafe MCP server again.

---

**Tweet 5/6**
Both tools are Apache 2.0. 100% open source.

⭐ Star the repos, scan your servers, open issues, send PRs.

🔗 github.com/KryptosAI/mcp-observatory
🔗 github.com/KryptosAI/mcp-seatbelt

---

**Tweet 6/6**
236 ★ · 1,582 weekly downloads · seatbelt v0.3.0

MCP security shouldn't be optional. Let's fix this before something breaks.

Follow @KryptosAI on GitHub for updates.

---

**📸 Images to include with this thread:**
- Demo GIF (`docs/demo.gif`): terminal recording showing `init → proxy → blocked call`
- Dashboard screenshot: observatory scan results or seatbelt live dashboard
- Social preview (`content/social-preview.svg`): as the link preview card

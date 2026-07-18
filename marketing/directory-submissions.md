# Directory Submission Checklist

Status of MCP security tools across MCP directories, tool registries, and developer platforms.

---

## Submission Status

| Directory | URL | Observatory | Seatbelt | Status |
|-----------|-----|-------------|----------|--------|
| MCP Registry | [registry.modelcontextprotocol.io](https://registry.modelcontextprotocol.io) | Listed ✅ | Not listed | Submit seatbelt |
| Glama.ai | [glama.ai/mcp/servers](https://glama.ai/mcp/servers) | Listed ✅ | `glama.json` exists ✅ | No action needed |
| Smithery.ai | [smithery.ai](https://smithery.ai) | Listed ✅ | `smithery.yaml` exists ✅ | No action needed |
| MCP Market | [mcpmarket.com](https://mcpmarket.com) | Listed ✅ | Not listed | Submit seatbelt |
| MCP Hub China | [mcp-hub.cn](https://mcp-hub.cn) | Listed ✅ | Not listed | Submit seatbelt |
| OpenTools | [opentools.ai](https://opentools.ai) | Listed ✅ | Not listed | Submit seatbelt |
| MCP.so | [mcp.so](https://mcp.so) | Listed ✅ | Listed ✅ | No action needed |
| AlternativeTo | [alternativeto.net](https://alternativeto.net) | Submitted ✅ | Submitted ✅ | Awaiting approval |
| DevHunt | [devhunt.org](https://devhunt.org) | Submitted ✅ | Submitted ✅ | Awaiting approval |

---

## Submission Details

### MCP Registry (`registry.modelcontextprotocol.io`)

- **Submit:** mcp-seatbelt
- **Submission URL:** [Create an issue](https://github.com/modelcontextprotocol/registry/issues/new?template=add-server.yml)
- **Needed:** GitHub repo URL, short description, category (Security), transport type (proxy)
- **Description:** "Runtime guardrails for AI agent tools. Scans, proxies, and enforces policy on MCP tool calls before they reach your system."

### Glama.ai (`glama.ai/mcp/servers`)

- **Status:** Both listed via `glama.json` in each repo's root
- **Action:** Verify `glama.json` is up to date with current descriptions and tags

### Smithery.ai (`smithery.ai`)

- **Status:** Both listed via `smithery.yaml` in each repo's root
- **Action:** Verify `smithery.yaml` is up to date

### MCP Market (`mcpmarket.com`)

- **Submit:** mcp-seatbelt
- **Submission URL:** [Submit tool](https://mcpmarket.com/submit)
- **Needed:** Repo URL, name, description, tags (security, proxy, cli), icon/logo URL
- **Description:** "Runtime guardrails for AI agent tools — 8+ client support, policy engine, live dashboard, SARIF reports."

### MCP Hub China (`mcp-hub.cn`)

- **Submit:** mcp-seatbelt
- **Submission URL:** [Submit](https://mcp-hub.cn/submit) (may require Chinese translation)
- **Needed:** Repo URL, name, description (EN + ZH), tags
- **ZH Description:** "AI代理工具的运行时防护 — 支持8+客户端、策略引擎、实时仪表盘、SARIF报告。"

### OpenTools (`opentools.ai`)

- **Submit:** mcp-seatbelt
- **Submission URL:** [Submit tool](https://opentools.ai/submit)
- **Needed:** Repo URL, name, description, category (Security), icon/logo
- **Description:** "Runtime guardrails for AI agent tools that sits between the agent and MCP servers, blocking dangerous tool calls before they hit your system."

### MCP.so (`mcp.so`)

- **Status:** Both listed
- **Action:** None needed. Verified both tools appear in directory.

### AlternativeTo (`alternativeto.net`)

- **Submit:** Both mcp-observatory and mcp-seatbelt ✅ Submitted
- **Status:** Awaiting approval
- **Submission URL:** [Suggest software](https://alternativeto.net/suggest/)
- **Note:** Already submitted with descriptions below; pending review.

### DevHunt (`devhunt.org`)

- **Submit:** Both mcp-observatory and mcp-seatbelt ✅ Submitted
- **Status:** Awaiting approval
- **Submission URL:** [Submit project](https://devhunt.org/submit)

---

## Submission Order

Recommended order for maximum discoverability:

1. ~~MCP.so~~ — Listed ✅
2. **MCP Registry** — Official registry, submit seatbelt
3. ~~MCP Market~~ — Both listed ✅
4. ~~OpenTools~~ — Both listed ✅
5. ~~MCP Hub China~~ — Both listed ✅
6. ~~AlternativeTo~~ — Submitted ✅
7. ~~DevHunt~~ — Submitted ✅

Glama.ai and Smithery.ai require no action (already listed via repo config files).

---

## Template: Submission Description

Use this template for all directory submissions:

> **mcp-seatbelt** provides runtime guardrails for AI agent tools. It sits between the AI agent (Cursor, Claude, VS Code, etc.) and every MCP server, evaluating each tool call against a policy you control before it reaches your filesystem, shell, or network.
>
> - Proxy with JSON-RPC 2.0 interception
> - Policy engine with regex/exact/contains matching
> - 13 built-in risk rules covering shells, credentials, paths, and network
> - Live dashboard, SARIF 2.1.0 reports, CI/CD CLI
> - Integrates with mcp-observatory to convert static analysis findings into runtime rules

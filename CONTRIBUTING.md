# Contributing to mcp-seatbelt

Thanks for your interest in improving MCP security tooling.

## Getting Started

### Prerequisites

- Node.js >= 22
- npm >= 10

### Setup

```bash
git clone https://github.com/anomalyco/mcp-seatbelt.git
cd mcp-seatbelt
npm install
```

### Development

```bash
npm run dev        # runs the CLI with tsx
npm run build      # compiles TypeScript to dist/
npm run test       # runs the test suite
npm run typecheck  # checks TypeScript types without emitting
npm run lint       # runs ESLint (not yet fully configured)
```

## Project Structure

```
mcp-seatbelt/
├── src/
│   ├── index.ts            # CLI entry point (commander)
│   ├── types.ts            # All shared TypeScript types
│   ├── commands/           # CLI subcommand implementations
│   │   ├── init.ts         # mcp-seatbelt init
│   │   ├── check.ts        # mcp-seatbelt check
│   │   ├── proxy.ts        # mcp-seatbelt proxy
│   │   ├── report.ts       # mcp-seatbelt report
│   │   ├── diff.ts         # mcp-seatbelt diff
│   │   ├── dashboard.ts    # mcp-seatbelt dashboard
│   │   └── import-observatory.ts  # mcp-seatbelt import-observatory
│   ├── detectors/          # MCP config detectors per client
│   │   ├── index.ts        # detectAll(), parseMcpServers()
│   │   ├── risk.ts         # assessRisk() — risk scoring engine
│   │   ├── cursor.ts       # Cursor IDE
│   │   ├── claude-desktop.ts   # Claude Desktop
│   │   ├── chatgpt-desktop.ts  # ChatGPT Desktop
│   │   ├── vscode.ts       # VS Code + Copilot Chat
│   │   ├── codex.ts        # OpenAI Codex
│   │   └── jetbrains.ts    # JetBrains IDEs
│   ├── policy/             # Policy engine
│   │   ├── engine.ts       # PolicyEngine class
│   │   ├── schema.ts       # validatePolicy()
│   │   ├── defaults.ts     # DEFAULT_POLICY, generateDefaultPolicy()
│   │   └── yaml.ts         # YAML parse/stringify helpers
│   ├── proxy/              # Runtime proxy
│   │   ├── index.ts        # Re-exports
│   │   ├── server.ts       # ProxyServer, StdioClient, HttpClient, SseClient
│   │   └── intercept.ts    # Request interception and response filtering
│   ├── report/             # Report generators
│   │   ├── generator.ts    # Markdown + JSON reports
│   │   └── sarif.ts        # SARIF 2.1.0 report
│   └── integrations/       # External tool bridges
│       └── observatory.ts  # mcp-observatory bridge
├── tests/                  # Vitest test suite
├── templates/              # Policy template shipped with the package
└── .github/workflows/      # CI/CD (GitHub Actions)
```

## Architecture

### How the proxy works

1. **Detect** — `detectAll()` scans the filesystem for MCP configs from all supported clients
2. **Assess** — `assessRisk()` scores each server with 13 risk rules
3. **Wrap** — `ProxyServer` starts an Express HTTP server. Each registered server gets a URL path (`/serverName`)
4. **Enforce** — `interceptRequest()` evaluates every `tools/call` against the `PolicyEngine`. Denied calls return an error. Warned calls pass through with a log message.
5. **Filter** — `filterToolsListResponse()` strips denied tools from `tools/list` so the agent never sees them.

### How policies are evaluated

Rules are checked sequentially. The first matching rule's action takes priority:
- `deny` > `warn` > `allow`
- The `allowlist.tools` bypasses all rules
- In `audit` mode, all calls are allowed but flagged

## Adding a New Detector

1. Create `src/detectors/<client>.ts`
2. Export an async function `detectX(): Promise<McpClientConfig[]>`
3. Register it in `src/detectors/index.ts` `detectAll()`
4. Add tests in `tests/detectors.test.ts`
5. Add to README supported clients list

Each detector follows the same pattern:
- Check platform-specific config paths
- Parse JSON configs looking for `mcpServers` key
- Run `assessRisk()` on each parsed server
- Return typed `McpClientConfig[]`

## Adding a New Risk Rule

1. Add an entry to the `RISK_RULES` array in `src/detectors/risk.ts`
2. Each rule has a `check` function that inspects `McpServerConfig`
3. Each rule has a `rule` ID, `description`, and `severity`
4. Add tests for the new rule in `tests/detectors.test.ts`
5. If the rule should be enforced by default, add it to `DEFAULT_POLICY` in `src/policy/defaults.ts`

## Testing

```bash
npm test              # run all tests
npm run test:watch    # watch mode
```

Tests are written with Vitest. Test files mirror the source structure:

- `tests/policy.test.ts` — PolicyEngine, validation, YAML utils
- `tests/detectors.test.ts` — Config detection, risk assessment
- `tests/proxy.test.ts` — Request interception, response filtering
- `tests/proxy-server.test.ts` — ProxyServer lifecycle, HTTP endpoints
- `tests/report.test.ts` — Report generation (markdown + JSON)
- `tests/cli.test.ts` — CLI arg parsing and integration tests

## Code Style

- TypeScript with strict mode
- ES modules (`"type": "module"`)
- 2-space indentation (see `.editorconfig`)
- No semicolons (consistent with existing code)
- Single quotes for strings
- `chalk` for terminal output coloring
- `js-yaml` for YAML parsing/serialization

## Pull Request Process

1. Fork the repo and create a feature branch
2. Add or update tests for your changes
3. Run `npm run typecheck` and ensure no errors
4. Run `npm test` and ensure all tests pass
5. Open a PR against `main`
6. PR description should explain what changed and why

## Security

If you discover a security issue in mcp-seatbelt itself, please do **not** open a public issue. Instead, report it to the maintainers privately.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

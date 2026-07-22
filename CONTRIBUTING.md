# Contributing to mcp-seatbelt

Thanks for your interest in improving MCP security tooling.

## Getting Started

### Prerequisites

- Node.js >= 22
- npm >= 10

### Setup

```bash
git clone https://github.com/KryptosAI/mcp-seatbelt.git
cd mcp-seatbelt
npm install
```

### Development

```bash
npm run dev        # runs the CLI with tsx
npm run build      # compiles TypeScript to dist/
npm run test       # runs the test suite
npm run typecheck  # checks TypeScript types without emitting
```

## Project Structure

```
mcp-seatbelt/
├── src/
│   ├── index.ts            # CLI entry point (commander)
│   ├── types.ts            # All shared TypeScript types
│   ├── audit.ts            # Signed audit log (HMAC)
│   ├── owasp-mapping.ts    # OWASP LLM Top 10 & compliance taxonomy
│   ├── commands/           # CLI subcommand implementations
│   │   ├── init.ts         # mcp-seatbelt init
│   │   ├── check.ts        # mcp-seatbelt check
│   │   ├── proxy.ts        # mcp-seatbelt proxy
│   │   ├── report.ts       # mcp-seatbelt report
│   │   ├── diff.ts         # mcp-seatbelt diff
│   │   ├── dashboard.ts    # mcp-seatbelt dashboard
│   │   ├── import-observatory.ts  # mcp-seatbelt import-observatory
│   │   ├── fuzz.ts         # mcp-seatbelt fuzz
│   │   ├── rbac-init.ts    # mcp-seatbelt rbac-init
│   │   ├── simulate.ts     # mcp-seatbelt simulate
│   │   ├── test-policy.ts  # mcp-seatbelt test-policy
│   │   ├── benchmark.ts    # mcp-seatbelt benchmark
│   │   └── baseline.ts     # mcp-seatbelt baseline
│   ├── detectors/          # MCP config detectors per client
│   │   ├── index.ts        # detectAll(), parseMcpServers()
│   │   ├── risk.ts         # assessRisk() — risk scoring engine
│   │   ├── cursor.ts       # Cursor IDE
│   │   ├── claude-desktop.ts   # Claude Desktop
│   │   ├── chatgpt-desktop.ts  # ChatGPT Desktop
│   │   ├── vscode.ts       # VS Code + Copilot Chat
│   │   ├── codex.ts        # OpenAI Codex
│   │   └── jetbrains.ts    # JetBrains IDEs
│   ├── policy/             # Policy engine & security
│   │   ├── engine.ts       # PolicyEngine class
│   │   ├── schema.ts       # validatePolicy()
│   │   ├── defaults.ts     # DEFAULT_POLICY, generateDefaultPolicy()
│   │   ├── yaml.ts         # YAML parse/stringify helpers
│   │   ├── rbac.ts         # Casbin RBAC (initRBAC, checkAccess)
│   │   ├── threat-intel.ts # ThreatFox IOC lookup
│   │   └── llm-judge.ts    # LLM-as-judge semantic analysis
│   ├── security/           # Defense-in-depth security modules
│   │   ├── index.ts        # Re-exports
│   │   ├── attack-chains.ts    # XState multi-step attack tracking
│   │   ├── honeytokens.ts      # Decoy credential injection & detection
│   │   ├── forensics.ts        # Signed .mcpcap.json session capture
│   │   ├── fuzzer.ts           # JSON Schema fuzzing for policy bypass
│   │   └── schema-validator.ts # AJV schema validation & path safety
│   ├── proxy/              # Runtime proxy
│   │   ├── index.ts        # Re-exports
│   │   ├── server.ts       # ProxyServer, StdioClient, HttpClient, SseClient
│   │   ├── intercept.ts    # Request interception and response filtering
│   │   └── notifications.ts # MCP notification handler
│   ├── report/             # Report generators
│   │   ├── generator.ts    # Markdown + JSON reports
│   │   └── sarif.ts        # SARIF 2.1.0 report
│   └── integrations/       # External tool bridges
│       └── observatory.ts  # mcp-observatory bridge
├── tests/                  # Vitest test suite (18 files, 485 tests)
├── scripts/                # Benchmark harness (run-benchmarks.ts, bench-*.ts)
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
- `tests/integration.test.ts` — End-to-end proxy + policy integration
- `tests/rbac.test.ts` — Casbin RBAC initialization and access checks
- `tests/threat-intel.test.ts` — ThreatFox IOC lookup
- `tests/llm-judge.test.ts` — LLM-as-judge semantic analysis
- `tests/attack-chains.test.ts` — Attack chain state machine
- `tests/honeytokens.test.ts` — Honeytoken injection and detection
- `tests/forensics.test.ts` — Forensic session capture
- `tests/schema-validator.test.ts` — Schema validation and path safety
- `tests/audit.test.ts` — Signed audit log
- `tests/notifications.test.ts` — MCP notification handling
- `tests/schema-notifications.test.ts` — Schema notification handling
- `tests/baseline.test.ts` — Behavioral baseline reports

## Code Style

- TypeScript with strict mode
- ES modules (`"type": "module"`)
- 2-space indentation (see `.editorconfig`)
- Prefer no semicolons (TypeScript's ASI handles this)
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

### PR Template

When opening a pull request, please include:

- **What** — a clear description of the change
- **Why** — the motivation behind the change (reference an issue if applicable)
- **How** — a brief overview of the implementation approach
- **Testing** — how the change was tested and any new test coverage added
- **Checklist**:
  - [ ] `npm run typecheck` passes
  - [ ] `npm test` passes
  - [ ] New behavior is covered by tests
  - [ ] Documentation is updated (README, API.md, CONTRIBUTING.md as appropriate)

### Issue Templates

When filing an issue, use one of the following templates:

- **Bug Report** — unexpected behavior, crashes, or incorrect output. Include steps to reproduce, expected vs actual behavior, and environment details (OS, Node version, mcp-seatbelt version).
- **Feature Request** — describe the feature, the problem it solves, and any proposed approach.
- **Security Vulnerability** — do **not** open a public issue. See the [Security](#security) section below.

## Security

If you discover a security issue in mcp-seatbelt itself, please do **not** open a public issue. Instead:

- Email **william@banksey.com** with details of the vulnerability
- Include steps to reproduce, affected versions, and any proposed mitigations
- See [`SECURITY.md`](./SECURITY.md) for our full security policy, supported versions, and responsible disclosure timeline

## Code of Conduct

This project adopts the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to uphold its standards. All contributors and maintainers are expected to foster a welcoming and respectful community.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

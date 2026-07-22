import type { PolicyEngine, EvaluateContext } from '../policy/engine.js';
import { notifyPolicyEvent } from './notifications.js';

export interface RedactionLog {
  type: string;
  path: string;
}

export interface ScanResult {
  response: MCPResponse;
  redactedCount: number;
  redactions: RedactionLog[];
}

export interface MCPRequest {
  jsonrpc: string;
  method: string;
  params?: {
    name?: string;
    arguments?: Record<string, unknown>;
    uri?: string;
    [key: string]: unknown;
  };
  id?: number | string | null;
}

export interface MCPResponse {
  jsonrpc: string;
  method?: string;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
  id?: number | string | null;
}

export function interceptRequest(
  request: MCPRequest,
  policy: PolicyEngine,
  serverName: string,
  context?: EvaluateContext,
  toolDescription?: string,
): MCPResponse | null {
  if (request.method === 'initialize') {
    return null;
  }

  if (request.method.startsWith('notifications/')) {
    return handleNotification(request, policy, serverName);
  }

  if (request.method === 'tools/call') {
    const toolName = request.params?.name;
    if (!toolName) {
      return {
        jsonrpc: '2.0',
        error: {
          code: -32602,
          message: 'Invalid params: missing tool name',
        },
        id: request.id ?? undefined,
      };
    }

    const result = policy.evaluate(toolName, toolDescription ?? '', request.params?.arguments ?? {}, context);

    if (result.action === 'deny' || result.action === 'warn' || result.action === 'redact') {
      notifyPolicyEvent(policy.getConfig(), {
        server: serverName,
        tool: toolName,
        args: request.params?.arguments ?? {},
        reasons: result.reasons,
        action: result.action,
        timestamp: new Date().toISOString(),
      });
    }

    if (result.action === 'deny') {
      const reason = result.reasons.join('; ');
      return {
        jsonrpc: '2.0',
        error: {
          code: -32001,
          message: 'Blocked by MCP Seatbelt: ' + reason,
          data: { reasons: result.reasons },
        },
        id: request.id ?? undefined,
      };
    }

    if (result.action === 'redact' && result.redactedKeys && request.params?.arguments) {
      for (const key of result.redactedKeys) {
        delete request.params.arguments[key];
      }
      console.warn(
        `[mcp-seatbelt:redact] Redacted args [${result.redactedKeys.join(', ')}] from ${serverName}/${toolName}`,
      );
    }

    if (result.action === 'warn') {
      console.warn(
        `[mcp-seatbelt:warn] ${serverName}/${toolName}: ${result.reasons.join('; ')}`,
      );
    }

    return null;
  }

  if (request.method === 'resources/read') {
    const uri = request.params?.uri;
    if (!uri || typeof uri !== 'string') {
      return {
        jsonrpc: '2.0',
        error: {
          code: -32602,
          message: 'Invalid params: missing resource URI',
        },
        id: request.id ?? undefined,
      };
    }

    const result = policy.evaluate(uri, '', request.params ?? {}, context);

    if (result.action === 'deny' || result.action === 'warn' || result.action === 'redact') {
      notifyPolicyEvent(policy.getConfig(), {
        server: serverName,
        tool: `resources/read:${uri}`,
        args: request.params ?? {},
        reasons: result.reasons,
        action: result.action,
        timestamp: new Date().toISOString(),
      });
    }

    if (result.action === 'deny') {
      const reason = result.reasons.join('; ');
      return {
        jsonrpc: '2.0',
        error: {
          code: -32001,
          message: 'Blocked by MCP Seatbelt: ' + reason,
          data: { reasons: result.reasons },
        },
        id: request.id ?? undefined,
      };
    }

    if (result.action === 'warn') {
      console.warn(
        `[mcp-seatbelt:warn] ${serverName}/resources/read "${uri}": ${result.reasons.join('; ')}`,
      );
    }

    return null;
  }

  if (request.method === 'resources/subscribe') {
    const uri = request.params?.uri;
    if (!uri || typeof uri !== 'string') {
      return {
        jsonrpc: '2.0',
        error: {
          code: -32602,
          message: 'Invalid params: missing resource URI',
        },
        id: request.id ?? undefined,
      };
    }

    const result = policy.evaluate(uri, '', request.params ?? {}, context);

    if (result.action === 'deny' || result.action === 'warn' || result.action === 'redact') {
      notifyPolicyEvent(policy.getConfig(), {
        server: serverName,
        tool: `resources/subscribe:${uri}`,
        args: request.params ?? {},
        reasons: result.reasons,
        action: result.action,
        timestamp: new Date().toISOString(),
      });
    }

    if (result.action === 'deny') {
      const reason = result.reasons.join('; ');
      return {
        jsonrpc: '2.0',
        error: {
          code: -32001,
          message: 'Blocked by MCP Seatbelt: ' + reason,
          data: { reasons: result.reasons },
        },
        id: request.id ?? undefined,
      };
    }

    if (result.action === 'warn') {
      console.warn(
        `[mcp-seatbelt:warn] ${serverName}/resources/subscribe "${uri}": ${result.reasons.join('; ')}`,
      );
    }

    return null;
  }

  if (request.method === 'prompts/get') {
    const promptName = request.params?.name;
    if (!promptName || typeof promptName !== 'string') {
      return {
        jsonrpc: '2.0',
        error: {
          code: -32602,
          message: 'Invalid params: missing prompt name',
        },
        id: request.id ?? undefined,
      };
    }

    const result = policy.evaluate(promptName, '', request.params ?? {}, context);

    if (result.action === 'deny' || result.action === 'warn' || result.action === 'redact') {
      notifyPolicyEvent(policy.getConfig(), {
        server: serverName,
        tool: `prompts/get:${promptName}`,
        args: request.params ?? {},
        reasons: result.reasons,
        action: result.action,
        timestamp: new Date().toISOString(),
      });
    }

    if (result.action === 'deny') {
      const reason = result.reasons.join('; ');
      return {
        jsonrpc: '2.0',
        error: {
          code: -32001,
          message: 'Blocked by MCP Seatbelt: ' + reason,
          data: { reasons: result.reasons },
        },
        id: request.id ?? undefined,
      };
    }

    if (result.action === 'warn') {
      console.warn(
        `[mcp-seatbelt:warn] ${serverName}/prompts/get "${promptName}": ${result.reasons.join('; ')}`,
      );
    }

    return null;
  }

  if (request.method === 'completion/complete') {
    console.log(
      `[mcp-seatbelt:info] ${serverName} completion/complete — allowed (reference data, usually safe)`,
    );
    return null;
  }

  if (request.method === 'sampling/createMessage') {
    if (!policy.isSamplingAllowed()) {
      return {
        jsonrpc: '2.0',
        error: {
          code: -32001,
          message: 'Blocked by MCP Seatbelt: sampling/createMessage disabled by policy',
        },
        id: request.id ?? undefined,
      };
    }

    console.log(
      `[mcp-seatbelt:audit] ${serverName} sampling/createMessage allowed (sampling enabled)`,
    );
    return null;
  }

  return null;
}

function handleNotification(
  request: MCPRequest,
  policy: PolicyEngine,
  serverName: string,
): MCPResponse | null {
  if (request.method === 'notifications/tools/list_changed') {
    console.log(
      `[mcp-seatbelt:info] ${serverName} notified tools/list changed — tool description cache should be rebuilt`,
    );
    return null;
  }

  if (request.method === 'notifications/resources/updated') {
    console.log(
      `[mcp-seatbelt:info] ${serverName} notified resources/updated (logged, not blocked)`,
    );
    return null;
  }

  if (request.method === 'notifications/prompts/list_changed') {
    console.log(
      `[mcp-seatbelt:info] ${serverName} notified prompts/list changed (logged, not blocked)`,
    );
    return null;
  }

  if (request.method === 'notifications/sampling/createMessage') {
    const params = request.params;
    const hasUserData =
      params &&
      (params.messages !== undefined ||
        params.includeContext !== undefined ||
        params.maxTokens !== undefined ||
        params.modelPreferences !== undefined);

    if (hasUserData) {
      console.warn(
        `[mcp-seatbelt:warn] ${serverName} attempted notifications/sampling/createMessage with data — blocked (exfiltration risk)`,
      );
      return {
        jsonrpc: '2.0',
        error: {
          code: -32001,
          message: 'Blocked by MCP Seatbelt: sampling notification blocked (exfiltration risk)',
        },
        id: request.id ?? undefined,
      };
    }
    return null;
  }

  return null;
}

export function filterToolsListResponse(
  response: MCPResponse,
  policy: PolicyEngine,
  serverName: string,
  context?: EvaluateContext,
): MCPResponse {
  if (!response.result || typeof response.result !== 'object') {
    return response;
  }

  const result = response.result as Record<string, unknown>;
  const tools = result.tools;
  if (!Array.isArray(tools)) {
    return response;
  }

  const filteredTools = tools.filter((tool: unknown) => {
    if (typeof tool !== 'object' || tool === null) return true;
    const t = tool as Record<string, unknown>;
    const toolName = t.name;
    if (typeof toolName !== 'string') return true;

    const description =
      typeof t.description === 'string' ? t.description : '';

    const evalResult = policy.evaluate(toolName, description, {}, context);

    if (evalResult.action === 'deny') {
      console.warn(
        `[mcp-seatbelt:warn] Filtered tool "${toolName}" from ${serverName} tools/list: ${evalResult.reasons.join('; ')}`,
      );
    }

    return evalResult.action !== 'deny';
  });

  return {
    ...response,
    result: {
      ...result,
      tools: filteredTools,
    },
  };
}

export function filterResourcesListResponse(
  response: MCPResponse,
  policy: PolicyEngine,
  serverName: string,
  context?: EvaluateContext,
): MCPResponse {
  if (!response.result || typeof response.result !== 'object') {
    return response;
  }

  const result = response.result as Record<string, unknown>;
  const resources = result.resources;
  if (!Array.isArray(resources)) {
    return response;
  }

  const filteredResources = resources.filter((resource: unknown) => {
    if (typeof resource !== 'object' || resource === null) return true;
    const r = resource as Record<string, unknown>;
    const resourceName = r.name ?? r.uri;
    if (typeof resourceName !== 'string') return true;

    const evalResult = policy.evaluate(resourceName, '', {}, context);

    if (evalResult.action === 'deny') {
      console.warn(
        `[mcp-seatbelt:warn] Filtered resource "${resourceName}" from ${serverName} resources/list: ${evalResult.reasons.join('; ')}`,
      );
    }

    return evalResult.action !== 'deny';
  });

  return {
    ...response,
    result: {
      ...result,
      resources: filteredResources,
    },
  };
}

export function filterPromptsListResponse(
  response: MCPResponse,
  policy: PolicyEngine,
  serverName: string,
  context?: EvaluateContext,
): MCPResponse {
  if (!response.result || typeof response.result !== 'object') {
    return response;
  }

  const result = response.result as Record<string, unknown>;
  const prompts = result.prompts;
  if (!Array.isArray(prompts)) {
    return response;
  }

  const filteredPrompts = prompts.filter((prompt: unknown) => {
    if (typeof prompt !== 'object' || prompt === null) return true;
    const p = prompt as Record<string, unknown>;
    const promptName = p.name;
    if (typeof promptName !== 'string') return true;

    const description =
      typeof p.description === 'string' ? p.description : '';

    const evalResult = policy.evaluate(promptName, description, {}, context);

    if (evalResult.action === 'deny') {
      console.warn(
        `[mcp-seatbelt:warn] Filtered prompt "${promptName}" from ${serverName} prompts/list: ${evalResult.reasons.join('; ')}`,
      );
    }

    return evalResult.action !== 'deny';
  });

  return {
    ...response,
    result: {
      ...result,
      prompts: filteredPrompts,
    },
  };
}

const SECRET_PATTERNS: Array<{ type: string; pattern: RegExp }> = [
  { type: 'aws-access-key', pattern: /AKIA[0-9A-Z]{16}/g },
  { type: 'github-token', pattern: /ghp_[0-9a-zA-Z]{36}/g },
  { type: 'openai-key', pattern: /sk-[a-zA-Z0-9]{32,}/g },
  { type: 'private-key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { type: 'api-key', pattern: /(?:api[_-]?key|apikey|api[_-]?secret|auth[_-]?token|bearer)\s*[:=]\s*['"]?([a-zA-Z0-9._\-]{20,})['"]?/gi },
  { type: 'generic-secret', pattern: /(?:(?:secret|password|token|key|credential)[\s:=]+['"][^'"]+['"])/gi },
];

/**
 * Single combined pre-filter. Every detailed pattern above requires one of
 * these literal anchors, so if none are present the string cannot contain a
 * detectable secret and the six full scans can be skipped. Clean strings (the
 * overwhelming majority) cost one regex test instead of six.
 */
const SECRET_PREFILTER = /AKIA|ghp_|sk-|-----BEGIN|api[_-]?key|apikey|api[_-]?secret|auth[_-]?token|bearer|secret|password|token|key|credential/i;

const BASE64_BLOB = /^[A-Za-z0-9+/=\r\n]+$/;

/**
 * Heuristic binary detection: large strings that are pure base64 (or contain
 * NUL bytes) are binary payloads (images, archives, key material in encoded
 * form). Plain-text secret patterns can never match inside them, so scanning
 * is wasted work — and it is the most expensive work DLP does.
 */
function isBinaryBlob(value: string): boolean {
  if (value.includes('\u0000')) return true;
  return BASE64_BLOB.test(value);
}

const MIN_BLOB_LENGTH = 1024;

function deepScanStrings(obj: unknown, path: string, callback: (path: string, value: string) => string | undefined): unknown {
  if (typeof obj === 'string') {
    const result = callback(path, obj);
    if (result !== undefined) return result;
    return obj;
  }

  if (Array.isArray(obj)) {
    let changed = false;
    const result = obj.map((item, i) => {
      const newVal = deepScanStrings(item, `${path}[${i}]`, callback);
      if (newVal !== item) changed = true;
      return newVal;
    });
    return changed ? result : obj;
  }

  if (obj && typeof obj === 'object') {
    let changed = false;
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      const newVal = deepScanStrings(value, path ? `${path}.${key}` : key, callback);
      if (newVal !== value) changed = true;
      (result as Record<string, unknown>)[key] = newVal;
    }
    return changed ? result : obj;
  }

  return obj;
}

export function scanResponse(
  response: MCPResponse,
  _policy: PolicyEngine,
): ScanResult {
  const redactions: RedactionLog[] = [];

  const redact = (path: string, value: string): string | undefined => {
    // Skip binary payloads (base64 blobs, embedded NULs): plain-text secret
    // patterns cannot match inside encoded data, so scanning is pure cost.
    if (value.length >= MIN_BLOB_LENGTH && isBinaryBlob(value)) return undefined;

    // Fast reject: one combined test instead of six full scans for clean text.
    if (!SECRET_PREFILTER.test(value)) return undefined;

    let modified = value;
    for (const { type, pattern } of SECRET_PATTERNS) {
      // Reuse the module-level compiled patterns. match()/replace() reset
      // lastIndex to 0 for /g regexes, so this is equivalent to the previous
      // per-string clone without the allocations.
      pattern.lastIndex = 0;
      const matches = modified.match(pattern);
      if (matches) {
        pattern.lastIndex = 0;
        modified = modified.replace(pattern, `[REDACTED-${type}]`);
        for (const _match of matches) {
          redactions.push({ type, path });
        }
      }
    }
    if (modified !== value) return modified;
    return undefined;
  };

  const sanitized = deepScanStrings(response, '', redact) as MCPResponse;

  return {
    response: sanitized,
    redactedCount: redactions.length,
    redactions,
  };
}

import type { PolicyEngine, EvaluateContext } from '../policy/engine.js';

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

    if (result.action === 'deny') {
      const reason = result.reasons.join('; ');
      return {
        jsonrpc: '2.0',
        error: {
          code: -32001,
          message: 'Blocked by MCP Seatbelt: ' + reason,
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

    if (result.action === 'deny') {
      const reason = result.reasons.join('; ');
      return {
        jsonrpc: '2.0',
        error: {
          code: -32001,
          message: 'Blocked by MCP Seatbelt: ' + reason,
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

    if (result.action === 'deny') {
      const reason = result.reasons.join('; ');
      return {
        jsonrpc: '2.0',
        error: {
          code: -32001,
          message: 'Blocked by MCP Seatbelt: ' + reason,
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

    if (result.action === 'deny') {
      const reason = result.reasons.join('; ');
      return {
        jsonrpc: '2.0',
        error: {
          code: -32001,
          message: 'Blocked by MCP Seatbelt: ' + reason,
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

import type { PolicyEngine } from '../policy/engine.js';

export interface MCPRequest {
  jsonrpc: string;
  method: string;
  params?: {
    name?: string;
    arguments?: Record<string, unknown>;
    [key: string]: unknown;
  };
  id?: number | string | null;
}

export interface MCPResponse {
  jsonrpc: string;
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
): MCPResponse | null {
  if (request.method === 'initialize') {
    return null;
  }

  if (request.method.startsWith('notifications/')) {
    return null;
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

    const result = policy.evaluate(toolName, '', request.params?.arguments ?? {});

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
        `[mcp-seatbelt:warn] ${serverName}/${toolName}: ${result.reasons.join('; ')}`,
      );
    }

    return null;
  }

  return null;
}

export function filterToolsListResponse(
  response: MCPResponse,
  policy: PolicyEngine,
  serverName: string,
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

    const evalResult = policy.evaluate(toolName, description, {});

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

    const evalResult = policy.evaluate(resourceName, '', {});

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

    const evalResult = policy.evaluate(promptName, description, {});

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

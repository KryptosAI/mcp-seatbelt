import { describe, it, expect, afterEach, vi } from 'vitest';
import { PolicyEngine } from '../src/policy/engine.js';
import {
  interceptRequest,
  filterToolsListResponse,
  filterResourcesListResponse,
  filterPromptsListResponse,
} from '../src/proxy/intercept.js';
import type { MCPRequest, MCPResponse } from '../src/proxy/intercept.js';
import type { PolicyConfig, PolicyRule } from '../src/types.js';

function makeEnforceConfig(rules: PolicyRule[] = []): PolicyConfig {
  return {
    version: '1',
    mode: 'enforce',
    defaultAction: 'deny',
    rules,
    allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
    allowSampling: true,
  };
}

function makeAllowConfig(rules: PolicyRule[] = []): PolicyConfig {
  return {
    ...makeEnforceConfig(rules),
    defaultAction: 'allow',
  };
}

const denyEvalRule: PolicyRule = {
  id: 'block-eval',
  description: 'Block eval',
  target: 'process',
  match: 'contains',
  values: ['eval'],
  action: 'deny',
};

describe('interceptRequest', () => {
  it('returns null for initialize method (always allowed)', () => {
    const policy = new PolicyEngine(makeEnforceConfig([denyEvalRule]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'initialize',
      id: 1,
    };
    const result = interceptRequest(request, policy, 'test-server');
    expect(result).toBeNull();
  });

  it('returns null for notification methods (always allowed)', () => {
    const policy = new PolicyEngine(makeEnforceConfig([]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    };
    const result = interceptRequest(request, policy, 'test-server');
    expect(result).toBeNull();
  });

  it('returns null for unknown methods (passes through)', () => {
    const policy = new PolicyEngine(makeEnforceConfig([]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'resources/list',
      id: 2,
    };
    const result = interceptRequest(request, policy, 'test-server');
    expect(result).toBeNull();
  });

  it('blocks tools/call with a denied tool', () => {
    const policy = new PolicyEngine(makeEnforceConfig([denyEvalRule]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        name: 'unsafe_eval',
        arguments: { code: 'eval(...)' },
      },
      id: 3,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).not.toBeNull();
    expect(result!.error).toBeDefined();
    expect(result!.error!.code).toBe(-32001);
    expect(result!.error!.message).toContain('Blocked by MCP Seatbelt');
    expect(result!.error!.message).toContain('block-eval');
    expect(result!.id).toBe(3);
  });

  it('allows tools/call with an allowed tool', () => {
    const policy = new PolicyEngine(makeAllowConfig([]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        name: 'safe_read',
        arguments: { path: '/tmp/test.txt' },
      },
      id: 4,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).toBeNull();
  });

  it('returns error for tools/call with missing tool name', () => {
    const policy = new PolicyEngine(makeEnforceConfig([]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        arguments: { some: 'data' },
      },
      id: 5,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).not.toBeNull();
    expect(result!.error!.code).toBe(-32602);
    expect(result!.error!.message).toContain('missing tool name');
  });

  it('returns error when params is undefined for tools/call', () => {
    const policy = new PolicyEngine(makeEnforceConfig([]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      id: 6,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).not.toBeNull();
    expect(result!.error!.code).toBe(-32602);
  });

  it('handles request with no id (returns response with undefined id)', () => {
    const policy = new PolicyEngine(makeEnforceConfig([denyEvalRule]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        name: 'dangerous_tool',
      },
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).not.toBeNull();
    expect(result!.id).toBeUndefined();
  });

  it('passes tools/call arguments to policy engine for evaluation', () => {
    const fileRule: PolicyRule = {
      id: 'block-etc',
      description: 'Block /etc paths',
      target: 'file',
      match: 'contains',
      values: ['/etc'],
      action: 'deny',
    };
    const policy = new PolicyEngine(makeEnforceConfig([fileRule]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        name: 'write_file',
        arguments: { filePath: '/etc/hosts' },
      },
      id: 7,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).not.toBeNull();
    expect(result!.error!.code).toBe(-32001);
  });
});

describe('interceptRequest warn path', () => {
  it('returns null for tools/call with warn action (allows through)', () => {
    const warnRule: PolicyRule = {
      id: 'warn-suspicious',
      description: 'Warn about suspicious operations',
      target: 'process',
      match: 'contains',
      values: ['suspicious'],
      action: 'warn',
    };
    const policy = new PolicyEngine(makeAllowConfig([warnRule]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        name: 'suspicious_operation',
        arguments: { data: 'test' },
      },
      id: 10,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).toBeNull();
  });

  it('returns null for tools/call when default is allow and no rules match', () => {
    const policy = new PolicyEngine({
      version: '1',
      mode: 'enforce',
      defaultAction: 'allow',
      rules: [],
      allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
      allowSampling: true,
    });
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        name: 'any_tool',
        arguments: { x: 1 },
      },
      id: 11,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).toBeNull();
  });

  it('returns null for tools/call when mode is audit (even with matching deny rule)', () => {
    const policy = new PolicyEngine({
      version: '1',
      mode: 'audit',
      defaultAction: 'deny',
      rules: [denyEvalRule],
      allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
      allowSampling: true,
    });
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        name: 'eval_code',
        arguments: { code: 'dangerous' },
      },
      id: 12,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).toBeNull();
  });

  it('returns error when params is empty object for tools/call (no name)', () => {
    const policy = new PolicyEngine(makeEnforceConfig([]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {},
      id: 400,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).not.toBeNull();
    expect(result!.error!.code).toBe(-32602);
    expect(result!.error!.message).toContain('missing tool name');
  });

  it('passes through prompts/list without blocking', () => {
    const policy = new PolicyEngine(makeEnforceConfig([denyEvalRule]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'prompts/list',
      id: 500,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).toBeNull();
  });
});

describe('filterToolsListResponse', () => {
  it('filters out denied tools from tools/list response', () => {
    const policy = new PolicyEngine(makeAllowConfig([denyEvalRule]));

    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        tools: [
          { name: 'safe_tool', description: 'a safe tool' },
          { name: 'eval_tool', description: 'runs eval' },
          { name: 'other_tool', description: 'another tool' },
        ],
      },
      id: 1,
    };

    const filtered = filterToolsListResponse(response, policy, 'test-server');
    expect(filtered.result).toBeDefined();

    const tools = (filtered.result as Record<string, unknown>).tools as Array<Record<string, unknown>>;
    expect(tools).toHaveLength(2);
    expect(tools.map((t) => t.name)).toEqual(['safe_tool', 'other_tool']);
  });

  it('passes through response with non-object result', () => {
    const policy = new PolicyEngine(makeEnforceConfig([denyEvalRule]));
    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: 'just a string',
      id: 1,
    };

    const filtered = filterToolsListResponse(response, policy, 'test-server');
    expect(filtered).toBe(response);
  });

  it('passes through response with non-array tools', () => {
    const policy = new PolicyEngine(makeEnforceConfig([denyEvalRule]));
    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        tools: 'not-an-array',
        other: 'data',
      },
      id: 1,
    };

    const filtered = filterToolsListResponse(response, policy, 'test-server');
    expect(filtered).toBe(response);
  });

  it('preserves non-tool fields in the result', () => {
    const policy = new PolicyEngine(makeAllowConfig([]));
    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        tools: [{ name: 'only_tool', description: '' }],
        nextCursor: 'abc123',
      },
      id: 1,
    };

    const filtered = filterToolsListResponse(response, policy, 'test-server');
    const result = filtered.result as Record<string, unknown>;
    expect(result.nextCursor).toBe('abc123');
    expect((result.tools as Array<unknown>)).toHaveLength(1);
  });

  it('keeps tools with warn action in the list', () => {
    const warnRule: PolicyRule = {
      id: 'warn-tool',
      description: 'Warn on suspicious tool',
      target: 'command',
      match: 'contains',
      values: ['suspicious'],
      action: 'warn',
    };
    const policy = new PolicyEngine(makeAllowConfig([warnRule]));

    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        tools: [
          { name: 'suspicious_tool', description: 'might be bad' },
          { name: 'normal_tool', description: 'fine' },
        ],
      },
      id: 1,
    };

    const filtered = filterToolsListResponse(response, policy, 'test-server');
    const tools = (filtered.result as Record<string, unknown>).tools as Array<Record<string, unknown>>;
    expect(tools).toHaveLength(2);
  });

  it('keeps tools with null description when default is allow', () => {
    const policy = new PolicyEngine(makeAllowConfig([]));
    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        tools: [
          { name: 'tool_without_desc' },
        ],
      },
      id: 1,
    };

    const filtered = filterToolsListResponse(response, policy, 'test-server');
    const tools = (filtered.result as Record<string, unknown>).tools as Array<Record<string, unknown>>;
    expect(tools).toHaveLength(1);
  });

  it('returns empty tools array when ALL tools are denied', () => {
    const policy = new PolicyEngine(makeEnforceConfig([denyEvalRule]));
    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        tools: [
          { name: 'bad_eval', description: 'runs eval' },
          { name: 'evil_eval', description: 'executes eval' },
          { name: 'unsafe_eval', description: 'evaluates code' },
        ],
      },
      id: 100,
    };

    const filtered = filterToolsListResponse(response, policy, 'test-server');
    const tools = (filtered.result as Record<string, unknown>).tools as Array<Record<string, unknown>>;
    expect(tools).toHaveLength(0);
    expect(filtered.id).toBe(100);
  });

  it('preserves response id and jsonrpc when filtering denied tools', () => {
    const policy = new PolicyEngine(makeAllowConfig([denyEvalRule]));
    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        tools: [
          { name: 'bad_eval', description: 'runs eval' },
          { name: 'good_tool', description: 'safe' },
        ],
      },
      id: 200,
    };

    const filtered = filterToolsListResponse(response, policy, 'test-server');
    expect(filtered.jsonrpc).toBe('2.0');
    expect(filtered.id).toBe(200);
    const tools = (filtered.result as Record<string, unknown>).tools as Array<Record<string, unknown>>;
    expect(tools).toHaveLength(1);
    expect(tools[0].name).toBe('good_tool');
  });

  it('returns response unchanged when tools array is already empty', () => {
    const policy = new PolicyEngine(makeEnforceConfig([denyEvalRule]));
    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        tools: [],
      },
      id: 300,
    };

    const filtered = filterToolsListResponse(response, policy, 'test-server');
    const tools = (filtered.result as Record<string, unknown>).tools as Array<Record<string, unknown>>;
    expect(tools).toHaveLength(0);
    expect(filtered.id).toBe(300);
  });
});

describe('MCPRequest / MCPResponse type alignment', () => {
  it('MCPRequest accepts a valid tools/call request', () => {
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        name: 'my_tool',
        arguments: { key: 'value' },
      },
      id: 42,
    };

    expect(request.jsonrpc).toBe('2.0');
    expect(request.method).toBe('tools/call');
    expect(request.params?.name).toBe('my_tool');
    expect(request.params?.arguments).toEqual({ key: 'value' });
    expect(request.id).toBe(42);
  });

  it('MCPResponse accepts a success result', () => {
    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: { tools: [{ name: 'test' }] },
      id: 1,
    };

    expect(response.jsonrpc).toBe('2.0');
    expect(response.result).toBeDefined();
    expect(response.error).toBeUndefined();
  });

  it('MCPResponse accepts an error result', () => {
    const response: MCPResponse = {
      jsonrpc: '2.0',
      error: {
        code: -32001,
        message: 'Blocked by MCP Seatbelt',
      },
      id: null,
    };

    expect(response.error?.code).toBe(-32001);
    expect(response.error?.message).toContain('Blocked');
    expect(response.id).toBeNull();
  });
});

describe('filterResourcesListResponse', () => {
  const denySecretRule: PolicyRule = {
    id: 'block-secret',
    description: 'Block secret resources',
    target: 'command',
    match: 'contains',
    values: ['secret'],
    action: 'deny',
  };

  it('passes through all resources when no policy rules match', () => {
    const policy = new PolicyEngine(makeAllowConfig([]));

    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        resources: [
          { name: 'public-doc', uri: 'file:///docs/public.md' },
          { name: 'readme', uri: 'file:///docs/readme.md' },
        ],
      },
      id: 1,
    };

    const filtered = filterResourcesListResponse(response, policy, 'test-server');
    const resources = (filtered.result as Record<string, unknown>).resources as Array<Record<string, unknown>>;
    expect(resources).toHaveLength(2);
    expect(resources.map((r) => r.name)).toEqual(['public-doc', 'readme']);
  });

  it('removes denied resources from the list', () => {
    const policy = new PolicyEngine(makeAllowConfig([denySecretRule]));

    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        resources: [
          { name: 'public-doc', uri: 'file:///docs/public.md' },
          { name: 'secret-keys', uri: 'file:///etc/secrets.env' },
          { name: 'readme', uri: 'file:///docs/readme.md' },
        ],
      },
      id: 2,
    };

    const filtered = filterResourcesListResponse(response, policy, 'test-server');
    const resources = (filtered.result as Record<string, unknown>).resources as Array<Record<string, unknown>>;
    expect(resources).toHaveLength(2);
    expect(resources.map((r) => r.name)).toEqual(['public-doc', 'readme']);
  });

  it('returns empty array when all resources are denied', () => {
    const policy = new PolicyEngine(makeEnforceConfig([denySecretRule]));

    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        resources: [
          { name: 'secret-1', uri: 'file:///secrets/a.env' },
          { name: 'top-secret', uri: 'file:///secrets/b.env' },
        ],
      },
      id: 3,
    };

    const filtered = filterResourcesListResponse(response, policy, 'test-server');
    const resources = (filtered.result as Record<string, unknown>).resources as Array<Record<string, unknown>>;
    expect(resources).toHaveLength(0);
  });

  it('preserves id and jsonrpc structure in filtered response', () => {
    const policy = new PolicyEngine(makeAllowConfig([denySecretRule]));

    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        resources: [
          { name: 'public', uri: 'file:///docs/public.md' },
          { name: 'secret', uri: 'file:///secrets/keys.env' },
        ],
        nextCursor: 'page2',
      },
      id: 100,
    };

    const filtered = filterResourcesListResponse(response, policy, 'test-server');
    expect(filtered.jsonrpc).toBe('2.0');
    expect(filtered.id).toBe(100);
    const result = filtered.result as Record<string, unknown>;
    expect(result.nextCursor).toBe('page2');
    const resources = result.resources as Array<Record<string, unknown>>;
    expect(resources).toHaveLength(1);
    expect(resources[0].name).toBe('public');
  });

  it('passes through response with non-object result unchanged', () => {
    const policy = new PolicyEngine(makeEnforceConfig([denySecretRule]));
    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: 'string result',
      id: 1,
    };

    const filtered = filterResourcesListResponse(response, policy, 'test-server');
    expect(filtered).toBe(response);
  });

  it('passes through response with non-array resources unchanged', () => {
    const policy = new PolicyEngine(makeEnforceConfig([denySecretRule]));
    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: { resources: 'not-an-array' },
      id: 1,
    };

    const filtered = filterResourcesListResponse(response, policy, 'test-server');
    expect(filtered).toBe(response);
  });

  it('matches resources by uri when name is absent', () => {
    const policy = new PolicyEngine(makeAllowConfig([denySecretRule]));
    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        resources: [
          { uri: 'file:///secret/file.txt' },
          { uri: 'file:///public/file.txt' },
        ],
      },
      id: 99,
    };

    const filtered = filterResourcesListResponse(response, policy, 'test-server');
    const resources = (filtered.result as Record<string, unknown>).resources as Array<Record<string, unknown>>;
    expect(resources).toHaveLength(1);
    expect(resources[0].uri).toBe('file:///public/file.txt');
  });
});

describe('resources/read interception', () => {
  const fileRule: PolicyRule = {
    id: 'block-etc-read',
    description: 'Block reading /etc paths',
    target: 'file',
    match: 'contains',
    values: ['/etc'],
    action: 'deny',
  };

  it('blocks resources/read with denied URI', () => {
    const policy = new PolicyEngine(makeEnforceConfig([fileRule]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'resources/read',
      params: { uri: 'file:///etc/hosts' },
      id: 10,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).not.toBeNull();
    expect(result!.error!.code).toBe(-32001);
    expect(result!.error!.message).toContain('block-etc-read');
  });

  it('allows resources/read with allowed URI', () => {
    const policy = new PolicyEngine(makeAllowConfig([fileRule]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'resources/read',
      params: { uri: 'file:///tmp/safe.txt' },
      id: 11,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).toBeNull();
  });

  it('returns error for resources/read with missing URI', () => {
    const policy = new PolicyEngine(makeEnforceConfig([]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'resources/read',
      params: {},
      id: 12,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).not.toBeNull();
    expect(result!.error!.code).toBe(-32602);
    expect(result!.error!.message).toContain('missing resource URI');
  });
});

describe('resources/subscribe interception', () => {
  const secretRule: PolicyRule = {
    id: 'block-secret-subscribe',
    description: 'Block subscribe to secret paths',
    target: 'file',
    match: 'contains',
    values: ['secret'],
    action: 'deny',
  };

  it('blocks resources/subscribe with denied URI', () => {
    const policy = new PolicyEngine(makeEnforceConfig([secretRule]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'resources/subscribe',
      params: { uri: 'file:///secret/data' },
      id: 20,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).not.toBeNull();
    expect(result!.error!.code).toBe(-32001);
    expect(result!.error!.message).toContain('block-secret-subscribe');
  });
});

describe('prompts/get interception', () => {
  const blockPromptRule: PolicyRule = {
    id: 'block-danger-prompt',
    description: 'Block dangerous prompts',
    target: 'command',
    match: 'contains',
    values: ['dangerous'],
    action: 'deny',
  };

  it('blocks prompts/get with denied prompt name', () => {
    const policy = new PolicyEngine(makeEnforceConfig([blockPromptRule]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'prompts/get',
      params: { name: 'dangerous_prompt' },
      id: 30,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).not.toBeNull();
    expect(result!.error!.code).toBe(-32001);
    expect(result!.error!.message).toContain('block-danger-prompt');
  });

  it('allows prompts/get with safe prompt name', () => {
    const policy = new PolicyEngine(makeAllowConfig([blockPromptRule]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'prompts/get',
      params: { name: 'safe_prompt' },
      id: 31,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).toBeNull();
  });
});

describe('sampling/createMessage interception', () => {
  it('blocks sampling/createMessage when allowSampling is false', () => {
    const config: PolicyConfig = {
      ...makeEnforceConfig([]),
      allowSampling: false,
    };
    const policy = new PolicyEngine(config);
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'sampling/createMessage',
      params: { messages: [], maxTokens: 100 },
      id: 40,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).not.toBeNull();
    expect(result!.error!.code).toBe(-32001);
    expect(result!.error!.message).toContain('sampling/createMessage disabled');
  });

  it('allows sampling/createMessage passthrough when allowSampling is true', () => {
    const config: PolicyConfig = {
      ...makeEnforceConfig([]),
      allowSampling: true,
    };
    const policy = new PolicyEngine(config);
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'sampling/createMessage',
      params: { messages: [], maxTokens: 100 },
      id: 41,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).toBeNull();
  });
});

describe('notifications filtering', () => {
  it('passes through notifications/tools/list_changed and logs', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const policy = new PolicyEngine(makeEnforceConfig([]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'notifications/tools/list_changed',
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).toBeNull();
    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining('tools/list changed'),
    );
    logSpy.mockRestore();
  });

  it('passes through notifications/resources/updated and logs', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const policy = new PolicyEngine(makeEnforceConfig([]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'notifications/resources/updated',
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).toBeNull();
    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining('resources/updated'),
    );
    logSpy.mockRestore();
  });

  it('passes through notifications/prompts/list_changed and logs', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const policy = new PolicyEngine(makeEnforceConfig([]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'notifications/prompts/list_changed',
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).toBeNull();
    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining('prompts/list changed'),
    );
    logSpy.mockRestore();
  });

  it('blocks notifications/sampling/createMessage with user data', () => {
    const policy = new PolicyEngine(makeEnforceConfig([]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'notifications/sampling/createMessage',
      params: { messages: ['some user data'], maxTokens: 100 },
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).not.toBeNull();
    expect(result!.error!.code).toBe(-32001);
    expect(result!.error!.message).toContain('exfiltration risk');
  });

  it('passes through unknown notification types', () => {
    const policy = new PolicyEngine(makeEnforceConfig([]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).toBeNull();
  });
});

describe('completion/complete interception', () => {
  it('passes through completion/complete and logs', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const policy = new PolicyEngine(makeEnforceConfig([]));
    const request: MCPRequest = {
      jsonrpc: '2.0',
      method: 'completion/complete',
      params: { ref: { type: 'ref/prompt', name: 'test' } },
      id: 50,
    };

    const result = interceptRequest(request, policy, 'test-server');
    expect(result).toBeNull();
    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining('completion/complete'),
    );
    logSpy.mockRestore();
  });
});

describe('filterPromptsListResponse', () => {
  const denyDangerousRule: PolicyRule = {
    id: 'block-danger',
    description: 'Block dangerous prompts',
    target: 'command',
    match: 'contains',
    values: ['dangerous'],
    action: 'deny',
  };

  it('passes through all prompts when no policy rules match', () => {
    const policy = new PolicyEngine(makeAllowConfig([]));

    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        prompts: [
          { name: 'greeting', description: 'A friendly greeting' },
          { name: 'farewell', description: 'A polite goodbye' },
        ],
      },
      id: 1,
    };

    const filtered = filterPromptsListResponse(response, policy, 'test-server');
    const prompts = (filtered.result as Record<string, unknown>).prompts as Array<Record<string, unknown>>;
    expect(prompts).toHaveLength(2);
    expect(prompts.map((p) => p.name)).toEqual(['greeting', 'farewell']);
  });

  it('removes denied prompts from the list', () => {
    const policy = new PolicyEngine(makeAllowConfig([denyDangerousRule]));

    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        prompts: [
          { name: 'greeting', description: 'Hello' },
          { name: 'dangerous_prompt', description: 'Does dangerous stuff' },
          { name: 'farewell', description: 'Goodbye' },
        ],
      },
      id: 2,
    };

    const filtered = filterPromptsListResponse(response, policy, 'test-server');
    const prompts = (filtered.result as Record<string, unknown>).prompts as Array<Record<string, unknown>>;
    expect(prompts).toHaveLength(2);
    expect(prompts.map((p) => p.name)).toEqual(['greeting', 'farewell']);
  });

  it('returns empty array when all prompts are denied', () => {
    const policy = new PolicyEngine(makeEnforceConfig([denyDangerousRule]));

    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        prompts: [
          { name: 'dangerous_a', description: 'Bad' },
          { name: 'dangerous_b', description: 'Also bad' },
        ],
      },
      id: 3,
    };

    const filtered = filterPromptsListResponse(response, policy, 'test-server');
    const prompts = (filtered.result as Record<string, unknown>).prompts as Array<Record<string, unknown>>;
    expect(prompts).toHaveLength(0);
  });

  it('preserves id and jsonrpc in filtered response', () => {
    const policy = new PolicyEngine(makeAllowConfig([denyDangerousRule]));

    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        prompts: [
          { name: 'safe_prompt', description: 'Fine' },
          { name: 'dangerous_x', description: 'Not fine' },
        ],
      },
      id: 200,
    };

    const filtered = filterPromptsListResponse(response, policy, 'test-server');
    expect(filtered.jsonrpc).toBe('2.0');
    expect(filtered.id).toBe(200);
    const prompts = (filtered.result as Record<string, unknown>).prompts as Array<Record<string, unknown>>;
    expect(prompts).toHaveLength(1);
    expect(prompts[0].name).toBe('safe_prompt');
  });

  it('passes through response with non-object result unchanged', () => {
    const policy = new PolicyEngine(makeEnforceConfig([denyDangerousRule]));
    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: 'some string',
      id: 1,
    };

    const filtered = filterPromptsListResponse(response, policy, 'test-server');
    expect(filtered).toBe(response);
  });

  it('passes through response with non-array prompts unchanged', () => {
    const policy = new PolicyEngine(makeEnforceConfig([denyDangerousRule]));
    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: { prompts: 'not-an-array' },
      id: 1,
    };

    const filtered = filterPromptsListResponse(response, policy, 'test-server');
    expect(filtered).toBe(response);
  });

  it('matches prompts by description for deny rules', () => {
    const policy = new PolicyEngine(makeAllowConfig([denyDangerousRule]));
    const response: MCPResponse = {
      jsonrpc: '2.0',
      result: {
        prompts: [
          { name: 'helper', description: 'A dangerous operation that should be blocked' },
          { name: 'utility', description: 'Safe utility' },
        ],
      },
      id: 99,
    };

    const filtered = filterPromptsListResponse(response, policy, 'test-server');
    const prompts = (filtered.result as Record<string, unknown>).prompts as Array<Record<string, unknown>>;
    expect(prompts).toHaveLength(1);
    expect(prompts[0].name).toBe('utility');
  });
});

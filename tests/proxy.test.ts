import { describe, it, expect } from 'vitest';
import { PolicyEngine } from '../src/policy/engine.js';
import {
  interceptRequest,
  filterToolsListResponse,
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

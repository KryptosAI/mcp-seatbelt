import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { initRBAC, checkAccess, getEnforcer, resetRBAC } from '../src/policy/rbac.js';

describe('RBAC', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-seatbelt-rbac-'));
    resetRBAC();
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
    resetRBAC();
  });

  async function setupRBAC(modelContent: string, policyContent: string) {
    const modelPath = path.join(tempDir, 'rbac_model.conf');
    const policyPath = path.join(tempDir, 'rbac_policy.csv');

    fs.writeFileSync(modelPath, modelContent);
    fs.writeFileSync(policyPath, policyContent);

    await initRBAC(modelPath, policyPath);
  }

  const defaultModel = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && r.act == p.act
`;

  it('allows admin agent to execute any tool', async () => {
    const policyCsv = [
      'p, admin, *, execute',
      'g, cursor_admin, admin',
    ].join('\n');

    await setupRBAC(defaultModel, policyCsv);

    const result = await checkAccess('cursor_admin', 'bash', 'execute');
    expect(result).toBe(true);
  });

  it('allows agent with specific tool permission', async () => {
    const policyCsv = [
      'p, agent, read_file, execute',
      'p, agent, write_file, execute',
      'g, claude_safe, agent',
    ].join('\n');

    await setupRBAC(defaultModel, policyCsv);

    expect(await checkAccess('claude_safe', 'read_file', 'execute')).toBe(true);
    expect(await checkAccess('claude_safe', 'write_file', 'execute')).toBe(true);
  });

  it('denies agent for tool not in their policy', async () => {
    const policyCsv = [
      'p, agent, read_file, execute',
      'g, claude_safe, agent',
    ].join('\n');

    await setupRBAC(defaultModel, policyCsv);

    expect(await checkAccess('claude_safe', 'bash', 'execute')).toBe(false);
  });

  it('denies unknown agent without role', async () => {
    const policyCsv = [
      'p, admin, *, execute',
      'g, cursor_admin, admin',
    ].join('\n');

    await setupRBAC(defaultModel, policyCsv);

    expect(await checkAccess('rogue_agent', 'read_file', 'execute')).toBe(false);
  });

  it('wildcard tool permission works', async () => {
    const policyCsv = [
      'p, admin, *, execute',
      'g, super_agent, admin',
    ].join('\n');

    await setupRBAC(defaultModel, policyCsv);

    expect(await checkAccess('super_agent', 'any_tool', 'execute')).toBe(true);
    expect(await checkAccess('super_agent', 'bash', 'execute')).toBe(true);
    expect(await checkAccess('super_agent', 'read_file', 'execute')).toBe(true);
  });

  it('returns true when enforcer is not initialized (no RBAC configured)', async () => {
    resetRBAC();
    const result = await checkAccess('any_agent', 'any_tool', 'execute');
    expect(result).toBe(true);
  });

  it('getEnforcer returns null before init', async () => {
    resetRBAC();
    expect(getEnforcer()).toBeNull();
  });

  it('getEnforcer returns enforcer after init', async () => {
    const policyCsv = [
      'p, admin, *, execute',
      'g, cursor_admin, admin',
    ].join('\n');

    await setupRBAC(defaultModel, policyCsv);
    expect(getEnforcer()).not.toBeNull();
  });

  it('enforces role-based group membership', async () => {
    const policyCsv = [
      'p, read_only, read_file, execute',
      'p, read_only, search, execute',
      'p, write_access, write_file, execute',
      'p, write_access, delete_file, execute',
      'g, editor_user, write_access',
      'g, editor_user, read_only',
    ].join('\n');

    await setupRBAC(defaultModel, policyCsv);

    expect(await checkAccess('editor_user', 'read_file', 'execute')).toBe(true);
    expect(await checkAccess('editor_user', 'write_file', 'execute')).toBe(true);
    expect(await checkAccess('editor_user', 'bash', 'execute')).toBe(false);
  });

  it('handles multiple agents with different roles', async () => {
    const policyCsv = [
      'p, admin, *, execute',
      'p, reader, read_file, execute',
      'g, cursor_admin, admin',
      'g, claude_safe, reader',
    ].join('\n');

    await setupRBAC(defaultModel, policyCsv);

    expect(await checkAccess('cursor_admin', 'bash', 'execute')).toBe(true);
    expect(await checkAccess('cursor_admin', 'delete_file', 'execute')).toBe(true);
    expect(await checkAccess('claude_safe', 'read_file', 'execute')).toBe(true);
    expect(await checkAccess('claude_safe', 'delete_file', 'execute')).toBe(false);
  });

  it('denies access for incorrect action', async () => {
    const policyCsv = [
      'p, admin, *, execute',
      'g, cursor_admin, admin',
    ].join('\n');

    await setupRBAC(defaultModel, policyCsv);

    expect(await checkAccess('cursor_admin', 'bash', 'delete')).toBe(false);
  });

  it('prefix wildcard matches tools with common prefix', async () => {
    const policyCsv = [
      'p, agent, read_*, execute',
      'g, reader_agent, agent',
    ].join('\n');

    await setupRBAC(defaultModel, policyCsv);

    expect(await checkAccess('reader_agent', 'read_file', 'execute')).toBe(true);
    expect(await checkAccess('reader_agent', 'read_config', 'execute')).toBe(true);
    expect(await checkAccess('reader_agent', 'write_file', 'execute')).toBe(false);
  });
});

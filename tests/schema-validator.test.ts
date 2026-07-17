import { describe, it, expect, afterEach } from 'vitest';
import {
  compileToolSchema,
  validateToolArgs,
  validatePathSafety,
  clearSchemaCache,
  getSchemaCount,
} from '../src/security/schema-validator.js';

describe('schema-validator', () => {
  afterEach(() => {
    clearSchemaCache();
  });

  describe('compileToolSchema', () => {
    it('compiles a valid JSON Schema and stores the validator', () => {
      compileToolSchema('test_tool', {
        type: 'object',
        properties: {
          name: { type: 'string' },
          count: { type: 'number', minimum: 1 },
        },
        required: ['name'],
        additionalProperties: false,
      });

      expect(getSchemaCount()).toBe(1);
    });

    it('handles invalid schema gracefully', () => {
      compileToolSchema('bad_tool', { type: 'invalid_type' } as any);
      expect(getSchemaCount()).toBe(0);
    });
  });

  describe('validateToolArgs', () => {
    it('returns valid=true when no schema is registered', () => {
      const result = validateToolArgs('unknown_tool', { foo: 'bar' });
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it('validates correct args against a schema', () => {
      compileToolSchema('echo', {
        type: 'object',
        properties: {
          message: { type: 'string' },
        },
        required: ['message'],
        additionalProperties: false,
      });

      const result = validateToolArgs('echo', { message: 'hello' });
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it('returns errors for missing required fields', () => {
      compileToolSchema('echo', {
        type: 'object',
        properties: {
          message: { type: 'string' },
        },
        required: ['message'],
        additionalProperties: false,
      });

      const result = validateToolArgs('echo', {});
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some((e) => e.includes("must have required property"))).toBe(true);
    });

    it('returns errors for wrong types', () => {
      compileToolSchema('echo', {
        type: 'object',
        properties: {
          count: { type: 'number' },
        },
        required: ['count'],
        additionalProperties: false,
      });

      const result = validateToolArgs('echo', { count: 'not-a-number' });
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('must be number'))).toBe(true);
    });

    it('returns errors for additional properties when not allowed', () => {
      compileToolSchema('echo', {
        type: 'object',
        properties: {
          message: { type: 'string' },
        },
        required: ['message'],
        additionalProperties: false,
      });

      const result = validateToolArgs('echo', { message: 'hello', evil: 'data' });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  describe('validatePathSafety', () => {
    it('returns safe=true for benign args', () => {
      const result = validatePathSafety({ filePath: '/workspace/project/src/index.ts' });
      expect(result.safe).toBe(true);
      expect(result.violations).toEqual([]);
    });

    it('detects path traversal with ../', () => {
      const result = validatePathSafety({ filePath: '/workspace/../etc/passwd' });
      expect(result.safe).toBe(false);
      expect(result.violations.length).toBe(1);
      expect(result.violations[0]).toContain('path traversal');
    });

    it('detects path traversal with ..\\', () => {
      const result = validatePathSafety({ filePath: 'C:\\Users\\..\\Windows\\System32' });
      expect(result.safe).toBe(false);
      expect(result.violations.length).toBe(1);
      expect(result.violations[0]).toContain('path traversal');
    });

    it('detects sensitive path /etc/', () => {
      const result = validatePathSafety({ filePath: '/etc/shadow' });
      expect(result.safe).toBe(false);
      expect(result.violations[0]).toContain('sensitive path');
    });

    it('detects sensitive path /root/', () => {
      const result = validatePathSafety({ filePath: '/root/.bashrc' });
      expect(result.safe).toBe(false);
      expect(result.violations[0]).toContain('sensitive path');
    });

    it('detects sensitive path C:\\Windows', () => {
      const result = validatePathSafety({ filePath: 'C:\\Windows\\System32\\config' });
      expect(result.safe).toBe(false);
      expect(result.violations[0]).toContain('sensitive path');
    });

    it('detects null byte injection', () => {
      const result = validatePathSafety({ filePath: '/workspace/legal\0malicious.sh' });
      expect(result.safe).toBe(false);
      expect(result.violations[0]).toContain('null byte injection');
    });

    it('detects multiple violations in different args', () => {
      const result = validatePathSafety({
        path1: '/etc/hosts',
        path2: '../secret.key',
      });
      expect(result.safe).toBe(false);
      expect(result.violations.length).toBe(2);
    });

    it('ignores non-string values', () => {
      const result = validatePathSafety({
        count: 42,
        flag: true,
        items: ['a', 'b'],
        filePath: '/workspace/ok.ts',
      } as Record<string, unknown>);
      expect(result.safe).toBe(true);
    });

    it('returns safe=true for empty args', () => {
      const result = validatePathSafety({});
      expect(result.safe).toBe(true);
    });
  });

  describe('clearSchemaCache and getSchemaCount', () => {
    it('clearSchemaCache removes all validators', () => {
      compileToolSchema('a', { type: 'object' });
      compileToolSchema('b', { type: 'object' });
      expect(getSchemaCount()).toBe(2);

      clearSchemaCache();
      expect(getSchemaCount()).toBe(0);
    });

    it('getSchemaCount returns 0 initially', () => {
      expect(getSchemaCount()).toBe(0);
    });
  });
});

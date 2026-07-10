import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { AuditTrail, verifyAuditFile, computeHmacStatic } from '../src/audit.js';
import type { AuditEntryInput, SignedAuditEntry } from '../src/audit.js';

function makeEntry(overrides: Partial<AuditEntryInput> = {}): AuditEntryInput {
  return {
    toolName: 'test_tool',
    description: 'A test tool',
    args: { filePath: '/tmp/test.txt' },
    action: 'deny',
    timestamp: new Date().toISOString(),
    reason: '[block-test] Test block reason',
    ...overrides,
  };
}

describe('AuditTrail', () => {
  let tempDir: string;
  let logPath: string;
  const secret = 'test-secret-key-123';

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-seatbelt-audit-'));
    logPath = path.join(tempDir, 'audit.jsonl');
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  describe('append', () => {
    it('creates the log file and writes a JSON line with HMAC', async () => {
      const trail = new AuditTrail(logPath, secret);
      await trail.append(makeEntry());

      expect(fs.existsSync(logPath)).toBe(true);
      const content = fs.readFileSync(logPath, 'utf-8').trim();
      expect(content).toBeTruthy();

      const parsed = JSON.parse(content) as SignedAuditEntry;
      expect(parsed._seq).toBe(0);
      expect(parsed._hmac).toBeTruthy();
      expect(parsed._hmac.length).toBe(64);
      expect(parsed.toolName).toBe('test_tool');
      expect(parsed.action).toBe('deny');
    });

    it('writes multiple entries sequentially with incrementing sequence numbers', async () => {
      const trail = new AuditTrail(logPath, secret);
      await trail.append(makeEntry({ toolName: 'tool_a' }));
      await trail.append(makeEntry({ toolName: 'tool_b' }));
      await trail.append(makeEntry({ toolName: 'tool_c' }));

      const content = fs.readFileSync(logPath, 'utf-8').trim();
      const lines = content.split('\n').filter(Boolean);
      expect(lines).toHaveLength(3);

      const entries = lines.map((l) => JSON.parse(l) as SignedAuditEntry);
      expect(entries[0]._seq).toBe(0);
      expect(entries[1]._seq).toBe(1);
      expect(entries[2]._seq).toBe(2);
      expect(entries[0].toolName).toBe('tool_a');
      expect(entries[1].toolName).toBe('tool_b');
      expect(entries[2].toolName).toBe('tool_c');
    });

    it('creates parent directories if they do not exist', async () => {
      const deepLogPath = path.join(tempDir, 'deep', 'nested', 'audit.jsonl');
      const trail = new AuditTrail(deepLogPath, secret);
      await trail.append(makeEntry());

      expect(fs.existsSync(deepLogPath)).toBe(true);
    });

    it('fire-and-forget does not throw even on concurrent calls', async () => {
      const trail = new AuditTrail(logPath, secret);
      const promises = [];
      for (let i = 0; i < 50; i++) {
        promises.push(trail.append(makeEntry({ toolName: `tool_${i}` })));
      }
      await Promise.all(promises);

      const content = fs.readFileSync(logPath, 'utf-8').trim();
      const lines = content.split('\n').filter(Boolean);
      expect(lines).toHaveLength(50);
    });
  });

  describe('verify', () => {
    it('returns valid true for an empty file (no entries)', async () => {
      const trail = new AuditTrail(logPath, secret);
      const result = await trail.verify();
      expect(result.valid).toBe(true);
      expect(result.total).toBe(0);
      expect(result.tampered).toBe(0);
    });

    it('returns valid true when all HMACs match', async () => {
      const trail = new AuditTrail(logPath, secret);
      await trail.append(makeEntry({ toolName: 'tool_a' }));
      await trail.append(makeEntry({ toolName: 'tool_b' }));

      const result = await trail.verify();
      expect(result.valid).toBe(true);
      expect(result.total).toBe(2);
      expect(result.tampered).toBe(0);
    });

    it('detects tampered entries', async () => {
      const trail = new AuditTrail(logPath, secret);
      await trail.append(makeEntry({ toolName: 'tool_a' }));

      const content = fs.readFileSync(logPath, 'utf-8');
      const parsed = JSON.parse(content.trim()) as SignedAuditEntry;
      parsed.toolName = 'tampered_tool';
      fs.writeFileSync(logPath, JSON.stringify(parsed) + '\n');

      const result = await trail.verify();
      expect(result.valid).toBe(false);
      expect(result.total).toBe(1);
      expect(result.tampered).toBe(1);
    });

    it('detects tampered HMAC value', async () => {
      const trail = new AuditTrail(logPath, secret);
      await trail.append(makeEntry());

      const content = fs.readFileSync(logPath, 'utf-8');
      const parsed = JSON.parse(content.trim()) as SignedAuditEntry;
      parsed._hmac = '0'.repeat(64);
      fs.writeFileSync(logPath, JSON.stringify(parsed) + '\n');

      const result = await trail.verify();
      expect(result.tampered).toBe(1);
    });

    it('detects mixed tampered and valid entries', async () => {
      const trail = new AuditTrail(logPath, secret);
      await trail.append(makeEntry({ toolName: 'good_1' }));
      await trail.append(makeEntry({ toolName: 'good_2' }));
      await trail.append(makeEntry({ toolName: 'bad_target' }));

      const lines = fs.readFileSync(logPath, 'utf-8').trim().split('\n');
      const entries = lines.map((l) => JSON.parse(l) as SignedAuditEntry);
      entries[1].toolName = 'tampered';
      fs.writeFileSync(logPath, entries.map((e) => JSON.stringify(e)).join('\n') + '\n');

      const result = await trail.verify();
      expect(result.total).toBe(3);
      expect(result.tampered).toBe(1);
    });

    it('verify is deterministic with the same secret', async () => {
      const trail = new AuditTrail(logPath, secret);
      await trail.append(makeEntry({ toolName: 'det_test' }));

      const r1 = await trail.verify();
      const r2 = await trail.verify();
      expect(r1).toEqual(r2);
    });
  });

  describe('query', () => {
    it('returns empty array for empty log', async () => {
      const trail = new AuditTrail(logPath, secret);
      const results = await trail.query({});
      expect(results).toEqual([]);
    });

    it('filters by tool name', async () => {
      const trail = new AuditTrail(logPath, secret);
      await trail.append(makeEntry({ toolName: 'bash' }));
      await trail.append(makeEntry({ toolName: 'read_file' }));
      await trail.append(makeEntry({ toolName: 'bash' }));

      const results = await trail.query({ tool: 'bash' });
      expect(results).toHaveLength(2);
      expect(results.every((r) => r.toolName === 'bash')).toBe(true);
    });

    it('filters by action', async () => {
      const trail = new AuditTrail(logPath, secret);
      await trail.append(makeEntry({ toolName: 'a', action: 'deny' }));
      await trail.append(makeEntry({ toolName: 'b', action: 'allow' }));
      await trail.append(makeEntry({ toolName: 'c', action: 'deny' }));

      const results = await trail.query({ action: 'deny' });
      expect(results).toHaveLength(2);
      expect(results.every((r) => r.action === 'deny')).toBe(true);
    });

    it('filters by multiple criteria', async () => {
      const trail = new AuditTrail(logPath, secret);
      await trail.append(makeEntry({ toolName: 'bash', action: 'deny' }));
      await trail.append(makeEntry({ toolName: 'bash', action: 'allow' }));
      await trail.append(makeEntry({ toolName: 'read', action: 'deny' }));

      const results = await trail.query({ tool: 'bash', action: 'deny' });
      expect(results).toHaveLength(1);
    });
  });
});

describe('verifyAuditFile', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-seatbelt-verify-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('returns valid for a non-existent file', async () => {
    const result = await verifyAuditFile(path.join(tempDir, 'nope.jsonl'), 'secret');
    expect(result.valid).toBe(true);
    expect(result.total).toBe(0);
  });

  it('verifies an existing file', async () => {
    const logPath = path.join(tempDir, 'test.jsonl');
    const secret = 'verify-secret';
    const trail = new AuditTrail(logPath, secret);
    await trail.append(makeEntry({ toolName: 'test' }));

    const result = await verifyAuditFile(logPath, secret);
    expect(result.valid).toBe(true);
    expect(result.total).toBe(1);
  });
});

describe('computeHmacStatic', () => {
  it('produces a 64-character hex string', () => {
    const entry = makeEntry();
    const hmac = computeHmacStatic(0, entry, 'secret');
    expect(hmac).toHaveLength(64);
    expect(/^[0-9a-f]+$/.test(hmac)).toBe(true);
  });

  it('produces different hashes for different entries', () => {
    const e1 = makeEntry({ toolName: 'a' });
    const e2 = makeEntry({ toolName: 'b' });
    const h1 = computeHmacStatic(0, e1, 'secret');
    const h2 = computeHmacStatic(0, e2, 'secret');
    expect(h1).not.toBe(h2);
  });

  it('produces different hashes for different sequences', () => {
    const entry = makeEntry();
    const h0 = computeHmacStatic(0, entry, 'secret');
    const h1 = computeHmacStatic(1, entry, 'secret');
    expect(h0).not.toBe(h1);
  });

  it('produces same hash for same input', () => {
    const entry = makeEntry();
    const h1 = computeHmacStatic(5, entry, 'secret');
    const h2 = computeHmacStatic(5, entry, 'secret');
    expect(h1).toBe(h2);
  });
});

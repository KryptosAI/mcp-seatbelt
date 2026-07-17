import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdir, rm, readFile, access } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import {
  startSessionCapture,
  captureRequest,
  captureResponse,
  saveSession,
  stopSessionCapture,
  getActiveSession,
  setSessionDir,
  getSessionDir,
} from '../src/security/forensics.js';

describe('forensics', () => {
  let tmpDir: string;

  beforeEach(async () => {
    stopSessionCapture();
    tmpDir = path.join(os.tmpdir(), `mcp-seatbelt-forensics-test-${randomUUID().slice(0, 8)}`);
    setSessionDir(tmpDir);
  });

  afterEach(async () => {
    stopSessionCapture();
    try { await rm(tmpDir, { recursive: true, force: true }); } catch {}
  });

  describe('startSessionCapture', () => {
    it('starts a new session with a UUID', async () => {
      const sessionId = await startSessionCapture();
      expect(sessionId).toBeTruthy();
      expect(typeof sessionId).toBe('string');
    });

    it('creates the sessions directory', async () => {
      await startSessionCapture();
      const dir = getSessionDir();
      await access(dir);
    });

    it('returns unique session IDs for each call', async () => {
      const id1 = await startSessionCapture();
      stopSessionCapture();
      const id2 = await startSessionCapture();
      expect(id1).not.toBe(id2);
    });
  });

  describe('captureRequest and captureResponse', () => {
    it('are no-ops when no session is active', () => {
      expect(() => captureRequest({ test: 1 })).not.toThrow();
      expect(() => captureResponse({ test: 2 })).not.toThrow();
    });

    it('capture events in the active session', async () => {
      await startSessionCapture();

      captureRequest({ jsonrpc: '2.0', method: 'tools/call', id: 1 });
      captureResponse({ jsonrpc: '2.0', result: { ok: true }, id: 1 });

      const session = getActiveSession();
      expect(session).not.toBeNull();
      expect(session!.events).toHaveLength(2);

      expect(session!.events[0].direction).toBe('request');
      expect(session!.events[0].payload).toEqual({ jsonrpc: '2.0', method: 'tools/call', id: 1 });

      expect(session!.events[1].direction).toBe('response');
      expect(session!.events[1].payload).toEqual({ jsonrpc: '2.0', result: { ok: true }, id: 1 });
    });

    it('events include timestamps', async () => {
      await startSessionCapture();

      const before = Date.now();
      captureRequest({});
      const after = Date.now();

      const session = getActiveSession();
      expect(session!.events[0].timestamp).toBeGreaterThanOrEqual(before);
      expect(session!.events[0].timestamp).toBeLessThanOrEqual(after);
    });
  });

  describe('saveSession', () => {
    it('saves session to a JSON file and returns the path', async () => {
      await startSessionCapture();
      captureRequest({ jsonrpc: '2.0', method: 'initialize', id: 1 });
      captureResponse({ jsonrpc: '2.0', result: {}, id: 1 });

      const filepath = await saveSession();
      expect(filepath).toBeTruthy();
      expect(filepath!.endsWith('.mcpcap.json')).toBe(true);

      const content = JSON.parse(await readFile(filepath!, 'utf-8'));
      expect(content.eventCount).toBe(2);
      expect(content.events).toHaveLength(2);
      expect(content.sessionId).toBeTruthy();
      expect(content.startedAt).toBeGreaterThan(0);
      expect(content.endedAt).toBeGreaterThan(0);

      expect(getActiveSession()).toBeNull();
    });

    it('returns null when no session is active', async () => {
      const result = await saveSession();
      expect(result).toBeNull();
    });

    it('returns null when session has no events', async () => {
      await startSessionCapture();
      const result = await saveSession();
      expect(result).toBeNull();
    });

    it('clears the active session after saving', async () => {
      await startSessionCapture();
      captureRequest({});
      await saveSession();
      expect(getActiveSession()).toBeNull();
    });
  });

  describe('stopSessionCapture', () => {
    it('stops the active session without saving', async () => {
      await startSessionCapture();
      captureRequest({});
      stopSessionCapture();
      expect(getActiveSession()).toBeNull();
    });

    it('is safe to call when no session is active', () => {
      stopSessionCapture();
      expect(getActiveSession()).toBeNull();
    });
  });

  describe('setSessionDir / getSessionDir', () => {
    it('returns the custom session directory after set', () => {
      setSessionDir('/custom/path');
      expect(getSessionDir()).toBe('/custom/path');
    });
  });

  describe('end-to-end', () => {
    it('captures and saves a full session', async () => {
      await startSessionCapture();

      const requests = Array.from({ length: 5 }, (_, i) => ({
        jsonrpc: '2.0',
        method: 'tools/call',
        params: { name: `tool-${i}` },
        id: i,
      }));
      const responses = requests.map((r) => ({
        jsonrpc: '2.0',
        result: { output: `result-${r.id}` },
        id: r.id,
      }));

      let idx = 0;
      for (const req of requests) {
        captureRequest(req);
        captureResponse(responses[idx++]);
      }

      const filepath = await saveSession();
      expect(filepath).toBeTruthy();

      const saved = JSON.parse(await readFile(filepath!, 'utf-8'));
      expect(saved.sessionId).toBeTruthy();
      expect(saved.eventCount).toBe(10);
      expect(saved.events).toHaveLength(10);

      const reqEvents = saved.events.filter((e: any) => e.direction === 'request');
      const resEvents = saved.events.filter((e: any) => e.direction === 'response');
      expect(reqEvents).toHaveLength(5);
      expect(resEvents).toHaveLength(5);

      for (let i = 0; i < 5; i++) {
        expect(reqEvents[i].payload.method).toBe('tools/call');
        expect(resEvents[i].payload.result.output).toBe(`result-${i}`);
      }
    });
  });
});

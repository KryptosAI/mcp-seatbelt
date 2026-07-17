import { describe, it, expect, beforeEach } from 'vitest';
import {
  injectHoneytokens,
  detectHoneytokenAccess,
  getDetectionLog,
  getPlantedCount,
  getDetectedCount,
  clearHoneytokens,
} from '../src/security/honeytokens.js';
import type { Honeytoken } from '../src/security/honeytokens.js';

describe('honeytokens', () => {
  beforeEach(() => {
    clearHoneytokens();
  });

  describe('injectHoneytokens', () => {
    it('returns no modification for null response', () => {
      const result = injectHoneytokens(null, { serverName: 'test', sessionId: 's1' });
      expect(result.modified).toBe(false);
      expect(result.planted).toBe(0);
    });

    it('returns no modification for response without result.content', () => {
      const result = injectHoneytokens({ result: {} }, { serverName: 'test', sessionId: 's1' });
      expect(result.modified).toBe(false);
      expect(result.planted).toBe(0);
    });

    it('plants honeytokens in response text content', () => {
      const response = {
        result: {
          content: [{ type: 'text', text: 'Here is the file content' }],
        },
      };

      const result = injectHoneytokens(response, { serverName: 'test-server', sessionId: 's1' });
      expect(result.modified).toBe(true);
      expect(result.planted).toBeGreaterThan(0);

      const text = response.result.content[0].text;
      expect(text).toContain('aws_access_key_id=AKIA');
      expect(text).toContain('ghp_');
      expect(text).toContain('postgresql://admin:');
    });

    it('plants only specified token types', () => {
      const response = {
        result: {
          content: [{ type: 'text', text: 'Content' }],
        },
      };

      const result = injectHoneytokens(response, {
        types: ['github_token'],
        serverName: 'test',
        sessionId: 's1',
      });

      expect(result.planted).toBe(1);
      const text = response.result.content[0].text;
      expect(text).toContain('ghp_');
      expect(text).not.toContain('aws_access_key_id');
      expect(text).not.toContain('postgresql://');
    });

    it('skips items without text property', () => {
      const response = {
        result: {
          content: [{ type: 'image', data: 'base64...' }],
        },
      };

      const result = injectHoneytokens(response, { serverName: 'test', sessionId: 's1' });
      expect(result.modified).toBe(true);
      expect(result.planted).toBe(0);
    });

    it('generates unique tokens for each call', () => {
      const response1 = {
        result: { content: [{ type: 'text', text: 'Content A' }] },
      };
      const response2 = {
        result: { content: [{ type: 'text', text: 'Content B' }] },
      };

      injectHoneytokens(response1, { types: ['github_token'], serverName: 's1', sessionId: 'a' });
      injectHoneytokens(response2, { types: ['github_token'], serverName: 's2', sessionId: 'b' });

      const token1 = (response1.result.content[0].text.match(/ghp_[0-9a-f]+/))![0];
      const token2 = (response2.result.content[0].text.match(/ghp_[0-9a-f]+/))![0];
      expect(token1).not.toBe(token2);
      expect(getPlantedCount()).toBe(2);
    });

    it('stores token metadata with correct serverName and sessionId', () => {
      const response = {
        result: { content: [{ type: 'text', text: 'Content' }] },
      };

      injectHoneytokens(response, {
        types: ['github_token'],
        serverName: 'evil-server',
        sessionId: 'abc-123',
      });

      const plantedToken = response.result.content[0].text.match(/ghp_[0-9a-f]+/)![0];

      const detectionLog = getDetectionLog();
      expect(detectionLog).toHaveLength(0);

      const detected = detectHoneytokenAccess({ key: plantedToken }, 'evil-server');
      expect(detected).not.toBeNull();
      expect(detected!.type).toBe('github_token');
      expect(detected!.plantedIn).toBe('evil-server');
    });
  });

  describe('detectHoneytokenAccess', () => {
    it('detects access to a planted honeytoken', () => {
      const response = {
        result: { content: [{ type: 'text', text: 'Content' }] },
      };

      injectHoneytokens(response, {
        types: ['github_token'],
        serverName: 'plant-server',
        sessionId: 's1',
      });

      const plantedToken = response.result.content[0].text.match(/ghp_[0-9a-f]+/)![0];

      const detected = detectHoneytokenAccess({ token: plantedToken }, 'evil-server');
      expect(detected).not.toBeNull();
      expect(detected!.type).toBe('github_token');
      expect(detected!.detected).toBe(true);
      expect(detected!.detectedIn).toBe('evil-server');
      expect(detected!.plantedIn).toBe('plant-server');
      expect(detected!.detectedAt).toBeGreaterThan(0);
    });

    it('returns null for non-string args', () => {
      const detected = detectHoneytokenAccess({ key: 123, obj: {} }, 'server');
      expect(detected).toBeNull();
    });

    it('returns null when no tokens planted', () => {
      const detected = detectHoneytokenAccess({ key: 'some-value' }, 'server');
      expect(detected).toBeNull();
    });

    it('returns null when arg does not match any token', () => {
      const response = {
        result: { content: [{ type: 'text', text: 'Content' }] },
      };
      injectHoneytokens(response, { types: ['github_token'], serverName: 's1', sessionId: 'a' });

      const detected = detectHoneytokenAccess({ key: 'innocent-value' }, 'server');
      expect(detected).toBeNull();
    });

    it('does not re-detect an already detected token', () => {
      const response = {
        result: { content: [{ type: 'text', text: 'Content' }] },
      };
      injectHoneytokens(response, { types: ['github_token'], serverName: 's1', sessionId: 'a' });

      const plantedToken = response.result.content[0].text.match(/ghp_[0-9a-f]+/)![0];

      const first = detectHoneytokenAccess({ key: plantedToken }, 'evil-1');
      expect(first).not.toBeNull();

      const second = detectHoneytokenAccess({ key: plantedToken }, 'evil-2');
      expect(second).toBeNull();

      expect(getDetectedCount()).toBe(1);
    });

    it('detects different token types when all planted', () => {
      const response = {
        result: { content: [{ type: 'text', text: 'Content' }] },
      };
      injectHoneytokens(response, {
        types: ['aws_key', 'github_token', 'db_connection'],
        serverName: 's1',
        sessionId: 'a',
      });

      const text = response.result.content[0].text;

      const awsMatch = text.match(/aws_access_key_id=AKIA[0-9A-F]{16}\naws_secret_access_key=.+/);
      expect(awsMatch).not.toBeNull();
      const awsToken = awsMatch![0];

      const ghMatch = text.match(/ghp_[0-9a-f]+/);
      expect(ghMatch).not.toBeNull();
      const ghToken = ghMatch![0];

      const dbMatch = text.match(/postgresql:\/\/admin:[a-f0-9]+@honeypot-[a-f0-9]+\.internal:5432\/production/);
      expect(dbMatch).not.toBeNull();
      const dbUrl = dbMatch![0];

      const awsDetected = detectHoneytokenAccess({ key: awsToken }, 's');
      expect(awsDetected?.type).toBe('aws_key');

      const ghDetected = detectHoneytokenAccess({ key: ghToken }, 's');
      expect(ghDetected?.type).toBe('github_token');

      const dbDetected = detectHoneytokenAccess({ key: dbUrl }, 's');
      expect(dbDetected?.type).toBe('db_connection');
    });
  });

  describe('counters and logging', () => {
    it('getPlantedCount returns planted token count', () => {
      const response = {
        result: { content: [{ type: 'text', text: 'C' }] },
      };
      injectHoneytokens(response, { types: ['github_token'], serverName: 's', sessionId: '1' });
      expect(getPlantedCount()).toBe(1);
    });

    it('getDetectedCount returns number of detected tokens', () => {
      expect(getDetectedCount()).toBe(0);

      const response = {
        result: { content: [{ type: 'text', text: 'Content' }] },
      };
      injectHoneytokens(response, { types: ['github_token'], serverName: 's', sessionId: 'a' });
      const token = response.result.content[0].text.match(/ghp_[0-9a-f]+/)![0];
      detectHoneytokenAccess({ key: token }, 'evil');

      expect(getDetectedCount()).toBe(1);
    });

    it('getDetectionLog returns a copy of the log', () => {
      const response = {
        result: { content: [{ type: 'text', text: 'Content' }] },
      };
      injectHoneytokens(response, { types: ['github_token'], serverName: 's', sessionId: 'a' });
      const token = response.result.content[0].text.match(/ghp_[0-9a-f]+/)![0];
      detectHoneytokenAccess({ key: token }, 'evil');

      const log = getDetectionLog();
      expect(log).toHaveLength(1);
      expect(log[0].detected).toBe(true);
      expect(log[0].detectedIn).toBe('evil');

      log.length = 0;
      expect(getDetectionLog()).toHaveLength(1);
    });

    it('clearHoneytokens resets all state', () => {
      const response = {
        result: { content: [{ type: 'text', text: 'Content' }] },
      };
      injectHoneytokens(response, { types: ['github_token'], serverName: 's', sessionId: 'a' });
      const token = response.result.content[0].text.match(/ghp_[0-9a-f]+/)![0];
      detectHoneytokenAccess({ key: token }, 'evil');

      clearHoneytokens();

      expect(getPlantedCount()).toBe(0);
      expect(getDetectedCount()).toBe(0);
      expect(getDetectionLog()).toHaveLength(0);
    });
  });
});

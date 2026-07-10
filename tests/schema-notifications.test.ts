import { describe, it, expect } from 'vitest';
import { validatePolicy } from '../src/policy/schema.js';
import type { PolicyConfig } from '../src/types.js';

function makeBasePolicy(): PolicyConfig {
  return {
    version: '1',
    mode: 'enforce',
    defaultAction: 'deny',
    rules: [],
    allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
    allowSampling: true,
  };
}

describe('validatePolicy notifications', () => {
  it('accepts valid notifications with webhooks', () => {
    const config = {
      ...makeBasePolicy(),
      notifications: {
        webhooks: [
          {
            url: 'https://hooks.slack.com/services/T/B/Q',
            events: ['deny', 'warn'],
            format: 'slack',
          },
        ],
      },
    };
    const result = validatePolicy(config);
    expect(result.notifications?.webhooks).toHaveLength(1);
    expect(result.notifications?.webhooks?.[0].url).toBe('https://hooks.slack.com/services/T/B/Q');
    expect(result.notifications?.webhooks?.[0].events).toEqual(['deny', 'warn']);
  });

  it('returns undefined notifications when not provided', () => {
    const config = makeBasePolicy();
    const result = validatePolicy(config);
    expect(result.notifications).toBeUndefined();
  });

  it('accepts empty webhooks array', () => {
    const config = {
      ...makeBasePolicy(),
      notifications: { webhooks: [] },
    };
    const result = validatePolicy(config);
    expect(result.notifications?.webhooks).toEqual([]);
  });

  it('accepts notifications without format (defaults to json)', () => {
    const config = {
      ...makeBasePolicy(),
      notifications: {
        webhooks: [
          {
            url: 'https://example.com/hook',
            events: ['deny'],
          },
        ],
      },
    };
    const result = validatePolicy(config);
    expect(result.notifications?.webhooks?.[0].format).toBeUndefined();
  });

  it('throws for non-object notifications', () => {
    const config = {
      ...makeBasePolicy(),
      notifications: 'not-an-object',
    };
    expect(() => validatePolicy(config)).toThrow('notifications must be a non-null object');
  });

  it('throws for non-array webhooks', () => {
    const config = {
      ...makeBasePolicy(),
      notifications: { webhooks: 'not-an-array' },
    };
    expect(() => validatePolicy(config)).toThrow('notifications.webhooks must be an array');
  });

  it('throws for webhook with empty url', () => {
    const config = {
      ...makeBasePolicy(),
      notifications: {
        webhooks: [{ url: '', events: ['deny'] }],
      },
    };
    expect(() => validatePolicy(config)).toThrow('url must be a non-empty string');
  });

  it('throws for webhook with non-array events', () => {
    const config = {
      ...makeBasePolicy(),
      notifications: {
        webhooks: [{ url: 'https://example.com', events: 'not-array' }],
      },
    };
    expect(() => validatePolicy(config)).toThrow('events must be an array');
  });

  it('throws for webhook with invalid event value', () => {
    const config = {
      ...makeBasePolicy(),
      notifications: {
        webhooks: [{ url: 'https://example.com', events: ['invalid_event'] }],
      },
    };
    expect(() => validatePolicy(config)).toThrow('events must contain only "deny", "warn", or "redact"');
  });

  it('throws for webhook with invalid format', () => {
    const config = {
      ...makeBasePolicy(),
      notifications: {
        webhooks: [{ url: 'https://example.com', events: ['deny'], format: 'teams' }],
      },
    };
    expect(() => validatePolicy(config)).toThrow('format must be "slack", "discord", or "json"');
  });

  it('accepts redact events in webhooks', () => {
    const config = {
      ...makeBasePolicy(),
      notifications: {
        webhooks: [
          { url: 'https://example.com', events: ['redact'] },
        ],
      },
    };
    const result = validatePolicy(config);
    expect(result.notifications?.webhooks?.[0].events).toEqual(['redact']);
  });
});

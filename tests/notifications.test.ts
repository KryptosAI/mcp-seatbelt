import { describe, it, expect, vi, afterEach } from 'vitest';
import { fireWebhook, notifyPolicyEvent } from '../src/proxy/notifications.js';
import type { NotificationEvent } from '../src/proxy/notifications.js';
import type { PolicyConfig, WebhookConfig } from '../src/types.js';

function makeEvent(overrides: Partial<NotificationEvent> = {}): NotificationEvent {
  return {
    server: 'test-server',
    tool: 'dangerous_tool',
    args: { filePath: '/etc/hosts' },
    reasons: ['[block-eval] Block eval usage'],
    action: 'deny',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

function makePolicy(webhooks: WebhookConfig[] = []): PolicyConfig {
  return {
    version: '1',
    mode: 'enforce',
    defaultAction: 'deny',
    rules: [],
    allowlist: { tools: [], paths: [], hosts: [], envVars: [] },
    allowSampling: true,
    notifications: webhooks.length > 0 ? { webhooks } : undefined,
  };
}

describe('fireWebhook', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('sends a POST request to the webhook URL with JSON payload', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchSpy);

    const webhook: WebhookConfig = {
      url: 'https://hooks.slack.com/test',
      events: ['deny'],
      format: 'json',
    };

    await fireWebhook(webhook, makeEvent());

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy).toHaveBeenCalledWith('https://hooks.slack.com/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: expect.any(String),
    });

    const body = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(body.event).toBe('deny');
    expect(body.server).toBe('test-server');
    expect(body.tool).toBe('dangerous_tool');
  });

  it('uses slack format when specified', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchSpy);

    const webhook: WebhookConfig = {
      url: 'https://hooks.slack.com/test',
      events: ['deny'],
      format: 'slack',
    };

    await fireWebhook(webhook, makeEvent());

    const body = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(body.text).toContain('DENY');
    expect(body.blocks).toBeDefined();
    expect(body.blocks[0].type).toBe('section');
    expect(body.attachments).toBeDefined();
    expect(body.attachments[0].color).toBe('#ff0000');
  });

  it('uses discord format when specified', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchSpy);

    const webhook: WebhookConfig = {
      url: 'https://discord.com/api/webhooks/test',
      events: ['deny'],
      format: 'discord',
    };

    await fireWebhook(webhook, makeEvent());

    const body = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(body.embeds).toBeDefined();
    expect(body.embeds[0].title).toContain('DENY');
    expect(body.embeds[0].color).toBe(0xff0000);
  });

  it('defaults to json format when not specified', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchSpy);

    const webhook: WebhookConfig = {
      url: 'https://example.com/webhook',
      events: ['deny'],
    };

    await fireWebhook(webhook, makeEvent());

    const body = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(body.event).toBe('deny');
    expect(body.server).toBe('test-server');
  });

  it('logs success message on ok response', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchSpy);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await fireWebhook(
      { url: 'https://example.com', events: ['deny'] },
      makeEvent(),
    );

    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Sent deny notification'));
    logSpy.mockRestore();
  });

  it('logs error on non-ok response', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: false, status: 500, statusText: 'Internal Server Error' });
    vi.stubGlobal('fetch', fetchSpy);
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await fireWebhook(
      { url: 'https://example.com', events: ['deny'] },
      makeEvent(),
    );

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('HTTP 500'));
    errorSpy.mockRestore();
  });

  it('logs error on fetch failure', async () => {
    const fetchSpy = vi.fn().mockRejectedValue(new Error('Connection refused'));
    vi.stubGlobal('fetch', fetchSpy);
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await fireWebhook(
      { url: 'https://example.com', events: ['deny'] },
      makeEvent(),
    );

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('Connection refused'));
    errorSpy.mockRestore();
  });
});

describe('notifyPolicyEvent', () => {
  it('does nothing when no notifications config', () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);

    const policy = makePolicy([]);
    notifyPolicyEvent(policy, makeEvent());

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('does nothing when no webhooks configured', () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);

    const policy: PolicyConfig = {
      ...makePolicy([]),
      notifications: {},
    };
    notifyPolicyEvent(policy, makeEvent());

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('fires webhooks whose events include the action', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchSpy);

    const policy = makePolicy([
      { url: 'https://hooks.slack.com/deny', events: ['deny'], format: 'json' },
      { url: 'https://hooks.slack.com/warn', events: ['warn'], format: 'json' },
    ]);

    notifyPolicyEvent(policy, makeEvent({ action: 'deny' }));

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy).toHaveBeenCalledWith(
      'https://hooks.slack.com/deny',
      expect.any(Object),
    );
  });

  it('does not fire webhooks whose events do not include the action', () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchSpy);

    const policy = makePolicy([
      { url: 'https://hooks.slack.com/warn', events: ['warn'], format: 'json' },
    ]);

    notifyPolicyEvent(policy, makeEvent({ action: 'deny' }));

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('fires multiple matching webhooks', () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchSpy);

    const policy = makePolicy([
      { url: 'https://hooks.slack.com/a', events: ['deny', 'warn'] },
      { url: 'https://discord.com/api/webhooks/b', events: ['deny'] },
    ]);

    notifyPolicyEvent(policy, makeEvent({ action: 'deny' }));

    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });
});

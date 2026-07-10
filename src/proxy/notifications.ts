import type { PolicyConfig, WebhookConfig } from '../types.js';

export interface NotificationEvent {
  server: string;
  tool: string;
  args: Record<string, unknown>;
  reasons: string[];
  action: 'deny' | 'warn' | 'redact';
  timestamp: string;
}

export async function fireWebhook(webhook: WebhookConfig, event: NotificationEvent): Promise<void> {
  const payload = formatPayload(webhook.format || 'json', event);
  try {
    const response = await fetch(webhook.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (response.ok) {
      console.log(`[mcp-seatbelt:webhook] Sent ${event.action} notification for ${event.server}/${event.tool}`);
    } else {
      console.error(`[mcp-seatbelt:webhook] HTTP ${response.status} ${response.statusText}`);
    }
  } catch (err) {
    console.error(`[mcp-seatbelt:webhook] Error: ${err instanceof Error ? err.message : 'Unknown error'}`);
  }
}

function formatPayload(format: string, event: NotificationEvent): unknown {
  switch (format) {
    case 'slack':
      return formatSlack(event);
    case 'discord':
      return formatDiscord(event);
    default:
      return formatJson(event);
  }
}

function formatJson(event: NotificationEvent): unknown {
  return {
    event: event.action,
    server: event.server,
    tool: event.tool,
    reasons: event.reasons,
    timestamp: event.timestamp,
  };
}

function formatSlack(event: NotificationEvent): unknown {
  const emoji = event.action === 'deny' ? ':no_entry:' : event.action === 'warn' ? ':warning:' : ':lock:';
  return {
    text: `${emoji} MCP Seatbelt: *${event.action.toUpperCase()}* — ${event.server}/${event.tool}`,
    blocks: [
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `${emoji} *MCP Seatbelt ${event.action.toUpperCase()}*\n*Server:* ${event.server}\n*Tool:* ${event.tool}\n*Reason:* ${event.reasons.join('; ')}`,
        },
      },
    ],
    attachments: [
      {
        color: event.action === 'deny' ? '#ff0000' : event.action === 'warn' ? '#ffa500' : '#ffff00',
        fields: [
          { title: 'Action', value: event.action, short: true },
          { title: 'Server', value: event.server, short: true },
          { title: 'Tool', value: event.tool, short: true },
          { title: 'Timestamp', value: event.timestamp, short: true },
        ],
      },
    ],
  };
}

function formatDiscord(event: NotificationEvent): unknown {
  const color = event.action === 'deny' ? 0xff0000 : event.action === 'warn' ? 0xffa500 : 0xffff00;
  return {
    embeds: [
      {
        title: `MCP Seatbelt: ${event.action.toUpperCase()}`,
        color,
        fields: [
          { name: 'Server', value: event.server, inline: true },
          { name: 'Tool', value: event.tool, inline: true },
          { name: 'Reasons', value: event.reasons.join('; ') },
        ],
        timestamp: event.timestamp,
      },
    ],
  };
}

export function notifyPolicyEvent(policy: PolicyConfig, event: NotificationEvent): void {
  if (!policy.notifications?.webhooks) return;
  for (const webhook of policy.notifications.webhooks) {
    if (webhook.events.includes(event.action)) {
      fireWebhook(webhook, event);
    }
  }
}

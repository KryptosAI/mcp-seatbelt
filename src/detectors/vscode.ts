import { homedir } from 'node:os';
import { join } from 'node:path';
import { readdirSync, existsSync } from 'node:fs';
import { readFile, access } from 'node:fs/promises';
import type { McpClientConfig, McpServerConfig } from '../types.js';
import { assessRisk } from './risk.js';

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function parseConfigFile(path: string, client: string): Promise<McpClientConfig | null> {
  if (!(await fileExists(path))) return null;
  try {
    const content = await readFile(path, 'utf-8');
    const json = JSON.parse(content);
    const servers: McpServerConfig[] = [];

    const serverEntries = json.mcpServers ?? json;

    for (const [name, config] of Object.entries(serverEntries)) {
      if (typeof config !== 'object' || config === null || name === 'mcpServers') continue;
      const c = config as Record<string, unknown>;
      if (!c.command && !c.cmd) continue;

      const server: McpServerConfig = {
        name,
        command: (c.command as string) || (c.cmd as string) || '',
        args: Array.isArray(c.args) ? c.args as string[] : [],
        env: c.env && typeof c.env === 'object' ? c.env as Record<string, string> : undefined,
        transport: (c.transport as McpServerConfig['transport']) || 'stdio',
        url: typeof c.url === 'string' ? c.url : undefined,
        risk: { score: 0, level: 'low', flags: [] },
      };
      server.risk = assessRisk(server);
      servers.push(server);
    }

    if (servers.length === 0) return null;
    return { client, path, servers };
  } catch {
    return null;
  }
}

function findCopilotChatMcpConfigs(home: string): string[] {
  const extensionsDir = join(home, '.vscode/extensions');
  try {
    const entries = readdirSync(extensionsDir);
    return entries
      .filter(e => e.startsWith('github.copilot-chat-'))
      .map(e => join(extensionsDir, e, 'mcp.json'))
      .filter(p => existsSync(p));
  } catch {
    return [];
  }
}

export async function detectVSCode(): Promise<McpClientConfig[]> {
  const home = homedir();
  const paths = [
    join(home, '.vscode/mcp.json'),
    join(home, '.vscode/mcp-servers.json'),
    join(process.cwd(), '.vscode/mcp.json'),
    join(process.cwd(), '.vscode/mcp-servers.json'),
    ...findCopilotChatMcpConfigs(home),
  ];

  const results: McpClientConfig[] = [];
  const seen = new Set<string>();

  for (const path of paths) {
    if (seen.has(path)) continue;
    seen.add(path);

    let clientName = 'vscode';
    if (path.includes('github.copilot-chat')) {
      clientName = 'vscode-copilot';
    }

    const config = await parseConfigFile(path, clientName);
    if (config) results.push(config);
  }

  return results;
}

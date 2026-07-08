import { homedir, platform } from 'node:os';
import { join } from 'node:path';
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

export async function detectClaudeDesktop(): Promise<McpClientConfig[]> {
  const home = homedir();
  const plat = platform();

  let configPath: string;
  if (plat === 'darwin') {
    configPath = join(home, 'Library/Application Support/Claude/claude_desktop_config.json');
  } else if (plat === 'win32') {
    configPath = join(process.env.APPDATA || join(home, 'AppData/Roaming'), 'Claude/claude_desktop_config.json');
  } else {
    configPath = join(home, '.config/Claude/claude_desktop_config.json');
  }

  const config = await parseConfigFile(configPath, 'claude-desktop');
  return config ? [config] : [];
}

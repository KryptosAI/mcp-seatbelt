import { homedir, platform } from "node:os";
import { join } from "node:path";
import { readFile, access } from "node:fs/promises";
import type { McpClientConfig, McpServerConfig } from "../types.js";
import { assessRisk } from "./risk.js";

const JETBRAINS_PRODUCTS = [
  "IntelliJIdea",
  "WebStorm",
  "PyCharm",
  "GoLand",
  "Rider",
  "PhpStorm",
];

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
    const content = await readFile(path, "utf-8");
    const json = JSON.parse(content);

    const servers: McpServerConfig[] = [];

    const serverEntries = json.mcpServers ?? json;

    for (const [name, config] of Object.entries(serverEntries)) {
      if (typeof config !== "object" || config === null || name === "mcpServers") continue;
      const c = config as Record<string, unknown>;
      if (!c.command && !c.cmd) continue;

      const server: McpServerConfig = {
        name,
        command: (c.command as string) || (c.cmd as string) || "",
        args: Array.isArray(c.args) ? (c.args as string[]) : [],
        env: c.env && typeof c.env === "object" ? (c.env as Record<string, string>) : undefined,
        transport: (c.transport as McpServerConfig["transport"]) || "stdio",
        url: typeof c.url === "string" ? c.url : undefined,
        risk: { score: 0, level: "low", flags: [] },
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

function getJetBrainsBasePath(): string {
  const home = homedir();
  const plat = platform();

  if (plat === "darwin") {
    return join(home, "Library", "Application Support", "JetBrains");
  } else if (plat === "win32") {
    return join(process.env.APPDATA || join(home, "AppData", "Roaming"), "JetBrains");
  } else {
    return join(home, ".config", "JetBrains");
  }
}

function getJetBrainsSharedConfigPath(): string {
  const home = homedir();
  return join(home, ".config", "JetBrains", "mcp-servers.json");
}

export async function detectJetBrains(): Promise<McpClientConfig[]> {
  const results: McpClientConfig[] = [];
  const base = getJetBrainsBasePath();

  for (const product of JETBRAINS_PRODUCTS) {
    const productConfigPath = join(base, product, "mcp.json");
    const config = await parseConfigFile(productConfigPath, `jetbrains-${product.toLowerCase()}`);
    if (config) results.push(config);
  }

  const sharedConfigPath = getJetBrainsSharedConfigPath();
  const sharedConfig = await parseConfigFile(sharedConfigPath, "jetbrains-shared");
  if (sharedConfig) results.push(sharedConfig);

  return results;
}

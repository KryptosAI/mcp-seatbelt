import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { McpClientConfig, McpServerConfig } from "../types.js";
import { assessRisk } from "./risk.js";
import { detectCursor } from "./cursor.js";
import { detectClaudeDesktop } from "./claude-desktop.js";
import { detectChatGPTDesktop } from "./chatgpt-desktop.js";
import { detectVSCode } from "./vscode.js";
import { detectCodex } from "./codex.js";

export function parseMcpServers(raw: Record<string, unknown>): McpServerConfig[] {
  const mcpServers = raw.mcpServers as Record<string, Record<string, unknown>> | undefined;
  if (!mcpServers) return [];
  return Object.entries(mcpServers).map(([name, cfg]) => {
    const args = (cfg.args as string[]) || [];
    return {
      name,
      command: (cfg.command as string) || (cfg.cmd as string) || (args[0] as string) || "unknown",
      args: (cfg.command || cfg.cmd) ? args : args.slice(1),
      env: cfg.env as Record<string, string> | undefined,
      transport: ((cfg.transport as string) || "stdio") as "stdio" | "http" | "sse",
      url: cfg.url as string | undefined,
      risk: { score: 0, level: "low", flags: [] },
    };
  });
}

export async function detectAll(): Promise<McpClientConfig[]> {
  const results: McpClientConfig[] = [];

  const detectorResults = await Promise.allSettled([
    detectCursor(),
    detectClaudeDesktop(),
    detectChatGPTDesktop(),
    detectVSCode(),
    detectCodex(),
  ]);

  for (const result of detectorResults) {
    if (result.status === "fulfilled") {
      results.push(...result.value);
    }
  }

  const home = homedir();
  const extraLocations: { client: string; paths: string[] }[] = [
    {
      client: "windsurf",
      paths: [join(home, ".codeium", "windsurf", "mcp.json")],
    },
    {
      client: "project",
      paths: [
        join(process.cwd(), ".mcp", "config.json"),
        join(process.cwd(), ".mcp.json"),
        join(process.cwd(), "mcp.json"),
      ],
    },
  ];

  for (const { client, paths } of extraLocations) {
    for (const path of paths) {
      if (!existsSync(path)) continue;
      try {
        const raw = JSON.parse(readFileSync(path, "utf-8"));
        const servers = parseMcpServers(raw)
          .map((srv) => ({ ...srv, risk: assessRisk(srv) }));
        if (servers.length > 0) {
          results.push({ client, path, servers });
        }
      } catch {
        continue;
      }
    }
  }

  const seen = new Set<string>();
  const deduped: McpClientConfig[] = [];

  for (const config of results) {
    const dedupedServers = config.servers.filter((srv) => {
      const key = `${srv.command}|${srv.args.join(",")}|${srv.name}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    if (dedupedServers.length > 0) {
      deduped.push({ ...config, servers: dedupedServers });
    }
  }

  return deduped;
}

export async function detectByClient(clientName: string): Promise<McpClientConfig[]> {
  const all = await detectAll();
  return all.filter((c) => c.client === clientName);
}

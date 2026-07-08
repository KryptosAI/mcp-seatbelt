import { existsSync, readFileSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { McpClientConfig, McpServerConfig } from "../types.js";
import { assessRisk } from "./risk.js";

function tryGlob(patternDir: string, pattern: string): string[] {
  try {
    const entries = readdirSync(patternDir, { withFileTypes: false }) as string[];
    return entries
      .filter((e) => e.endsWith(pattern.replace("*", "")))
      .map((e) => join(patternDir, e));
  } catch {
    return [];
  }
}

function parseMcpServers(raw: Record<string, unknown>): McpServerConfig[] {
  const mcpServers = raw.mcpServers as Record<string, Record<string, unknown>> | undefined;
  if (!mcpServers) return [];
  return Object.entries(mcpServers).map(([name, cfg]) => {
    const args = (cfg.args as string[]) || [];
    return {
      name,
      command: (cfg.command as string) || (args[0] as string) || "unknown",
      args: cfg.command ? args : args.slice(1),
      env: cfg.env as Record<string, string> | undefined,
      transport: ((cfg.transport as string) || "stdio") as "stdio" | "http" | "sse",
      url: cfg.url as string | undefined,
      risk: { score: 0, level: "low", flags: [] },
    };
  });
}

export function detectAll(): McpClientConfig[] {
  const results: McpClientConfig[] = [];
  const home = homedir();

  const locations: { client: string; paths: string[] }[] = [
    {
      client: "cursor",
      paths: [join(home, ".cursor", "mcp.json")],
    },
    {
      client: "claude-desktop",
      paths: [
        join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
        join(home, ".config", "claude", "config.json"),
      ],
    },
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

  const vscodeStorage = join(home, "Library", "Application Support", "Code", "User", "globalStorage");
  const vscodePaths = tryGlob(vscodeStorage, "mcp_servers.json").map((dir) =>
    join(dir, "mcp_servers.json"),
  );
  if (vscodePaths.length > 0) {
    locations.push({ client: "vscode", paths: vscodePaths });
  }

  const seen = new Set<string>();

  for (const { client, paths } of locations) {
    for (const path of paths) {
      if (!existsSync(path)) continue;
      try {
        const raw = JSON.parse(readFileSync(path, "utf-8"));
        const servers = parseMcpServers(raw)
          .map((srv) => ({ ...srv, risk: assessRisk(srv) }))
          .filter((srv) => {
            const key = `${srv.command}|${srv.args.join(",")}|${srv.name}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
          });

        if (servers.length > 0) {
          results.push({ client, path, servers });
        }
      } catch {
        continue;
      }
    }
  }

  return results;
}

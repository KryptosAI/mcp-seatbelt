import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { PolicyConfig, PolicyRule } from "../types.js";

interface ObservatoryFinding {
  id: string;
  severity: "low" | "medium" | "high" | "critical";
  title: string;
  description: string;
  tool?: string;
  path?: string;
  host?: string;
  envVar?: string;
}

interface ObservatoryArtifact {
  version: string;
  generatedAt: string;
  findings: ObservatoryFinding[];
}

function normaliseSeverity(raw: string | undefined): ObservatoryFinding["severity"] {
  const s = (raw || "low").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  return "low";
}

function readObservatoryJson(artifactPath: string): ObservatoryArtifact | null {
  try {
    const raw = readFileSync(artifactPath, "utf-8");
    const parsed = JSON.parse(raw);
    const seen = new Set<string>();
    const findings: ObservatoryFinding[] = [];

    function addFinding(f: Record<string, unknown>) {
      const rid = (f.ruleId || f.id || f.itemType || "") as string;
      const rtool = (f.toolName || f.tool || f.itemName || "") as string;
      const key = `${rid}|${rtool}`;
      if (!key || key === "|") {
        findings.push({
          id: "unknown",
          severity: normaliseSeverity(f.severity as string | undefined),
          title: "finding",
          description: (f.message || f.issue || f.description || "") as string,
          tool: rtool || undefined,
          path: f.path as string | undefined,
          host: f.host as string | undefined,
          envVar: f.envVar as string | undefined,
        });
        return;
      }
      if (seen.has(key)) return;
      seen.add(key);

      findings.push({
        id: rid,
        severity: normaliseSeverity(f.severity as string | undefined),
        title: (f.ruleId || f.title || f.id || f.itemType || "finding") as string,
        description: (f.message || f.issue || f.description || "") as string,
        tool: rtool || undefined,
        path: f.path as string | undefined,
        host: f.host as string | undefined,
        envVar: f.envVar as string | undefined,
      });
    }

    if (parsed.checks && Array.isArray(parsed.checks)) {
      for (const check of parsed.checks as Record<string, unknown>[]) {
        if (check.evidence && Array.isArray(check.evidence)) {
          for (const ev of check.evidence as Record<string, unknown>[]) {
            if (ev.findings && Array.isArray(ev.findings)) {
              for (const f of ev.findings as Record<string, unknown>[]) {
                addFinding(f);
              }
            }
          }
        }
      }
    }

    if (parsed.findings && Array.isArray(parsed.findings)) {
      for (const f of parsed.findings as Record<string, unknown>[]) {
        addFinding(f);
      }
    }

    if (findings.length === 0) return null;

    return {
      version: parsed.version || "unknown",
      generatedAt: parsed.generatedAt || new Date().toISOString(),
      findings,
    };
  } catch {
    return null;
  }
}

function ruleIdToTarget(ruleId: string): PolicyRule["target"] | null {
  const id = ruleId.toLowerCase();

  const exact: Record<string, PolicyRule["target"]> = {
    "shell-injection": "process",
    "broad-filesystem": "file",
    "credential-pattern": "env",
    "credential-exposure": "env",
    "tool-poisoning": "process",
    "network-access": "network",
    "url-access": "network",
    "env-access": "env",
    "process-exec": "process",
    "process-spawn": "process",
    "file-access": "file",
    "file-read": "file",
    "file-write": "file",
    "host-access": "network",
    "secret-leak": "env",
    "key-exposure": "env",
  };

  if (exact[id]) return exact[id];

  if (id.includes("shell") || id.includes("inject") || id.includes("exec") ||
      id.includes("spawn") || id.includes("process") || id.includes("poison") ||
      id.includes("command")) return "process";

  if (id.includes("file") || id.includes("path") || id.includes("dir") ||
      id.includes("fs")) return "file";

  if (id.includes("network") || id.includes("url") || id.includes("http") ||
      id.includes("host") || id.includes("dns") || id.includes("socket")) return "network";

  if (id.includes("env") || id.includes("credential") || id.includes("secret") ||
      id.includes("key") || id.includes("token") || id.includes("password")) return "env";

  return null;
}

function findingToTarget(finding: ObservatoryFinding): PolicyRule["target"] {
  const byRuleId = ruleIdToTarget(finding.id);
  if (byRuleId) return byRuleId;

  if (finding.tool) return "command";

  const desc = finding.description.toLowerCase();
  if (finding.path || desc.includes("file") || desc.includes("directory") || desc.includes("path")) {
    return "file";
  }
  if (finding.host || desc.includes("url") || desc.includes("network") || desc.includes("host") || desc.includes("http")) {
    return "network";
  }
  if (finding.envVar || desc.includes("env") || desc.includes("environment") || desc.includes("secret") || desc.includes("credential")) {
    return "env";
  }
  if (desc.includes("process") || desc.includes("spawn") || desc.includes("exec") || desc.includes("fork")) {
    return "process";
  }
  return "command";
}

function findingToValues(finding: ObservatoryFinding): string[] {
  const values: string[] = [];

  if (finding.tool) {
    values.push(finding.tool);
  }
  if (finding.path) {
    values.push(finding.path);
  }
  if (finding.host) {
    values.push(finding.host);
  }
  if (finding.envVar) {
    values.push(finding.envVar);
  }

  if (values.length === 0) {
    values.push(finding.id);
    values.push(finding.title);
  }

  return values;
}

function severityToAction(severity: ObservatoryFinding["severity"]): PolicyRule["action"] {
  if (severity === "critical" || severity === "high") {
    return "deny";
  }
  if (severity === "medium") {
    return "warn";
  }
  return "allow";
}

export function generateOverviewReason(artifactPath: string): string {
  const artifact = readObservatoryJson(artifactPath);
  if (!artifact || artifact.findings.length === 0) return "No observatory findings in artifact";

  const severityCounts: Record<string, number> = {};
  const toolSet = new Set<string>();

  for (const f of artifact.findings) {
    severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
    if (f.tool) toolSet.add(f.tool);
  }

  const parts: string[] = [];

  const highCount = (severityCounts.critical || 0) + (severityCounts.high || 0);
  if (highCount) parts.push(`${highCount} high/critical finding(s)`);
  if (severityCounts.medium) parts.push(`${severityCounts.medium} medium finding(s)`);
  if (severityCounts.low) parts.push(`${severityCounts.low} low finding(s)`);

  const tools = Array.from(toolSet).slice(0, 3);
  if (tools.length) parts.push(`affected tools: ${tools.join(", ")}`);

  const artifactType = artifact.version !== "unknown" ? `v${artifact.version}` : "";
  const header = artifactType ? `Observatory artifact ${artifactType}: ` : "Observatory artifact: ";

  return header + (parts.length ? parts.join("; ") : `${artifact.findings.length} finding(s) total`);
}

export function importObservatoryResults(artifactPath: string): PolicyRule[] {
  const artifact = readObservatoryJson(artifactPath);
  if (!artifact) return [];

  return artifact.findings.map((finding, index) => ({
    id: `observatory-${finding.id || `finding-${index}`}`.replace(/[^a-zA-Z0-9_-]/g, "-"),
    description: finding.title || finding.description,
    target: findingToTarget(finding),
    match: "contains" as const,
    values: findingToValues(finding),
    action: severityToAction(finding.severity),
  }));
}

export function mergeObservatoryPolicy(
  seatbeltPolicy: PolicyConfig,
  observatoryArtifactPath: string,
): PolicyConfig {
  const observatoryRules = importObservatoryResults(observatoryArtifactPath);

  const existingIds = new Set(seatbeltPolicy.rules.map((r) => r.id));
  const newRules = observatoryRules.filter((r) => !existingIds.has(r.id));

  return {
    ...seatbeltPolicy,
    rules: [...seatbeltPolicy.rules, ...newRules],
  };
}

export function discoverObservatoryArtifacts(basePath?: string): string[] {
  const searchPaths = basePath
    ? [basePath]
    : [process.cwd(), join(process.cwd(), ".mcp-observatory"), join(process.cwd(), ".mcp-observatory-metrics")];

  const artifacts: string[] = [];

  const runDirs = [
    ...searchPaths.map((p) => join(p, ".mcp-observatory", "runs")),
    ...searchPaths.map((p) => join(p, ".mcp-observatory-metrics")),
    ...searchPaths,
  ];

  const seen = new Set<string>();

  for (const dir of runDirs) {
    try {
      if (!existsSync(dir)) continue;

      const entries = readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        if (entry.isFile() && entry.name.endsWith(".json")) {
          const fullPath = join(dir, entry.name);
          if (seen.has(fullPath)) continue;
          seen.add(fullPath);

          const artifact = readObservatoryJson(fullPath);
          if (artifact) {
            artifacts.push(fullPath);
          }
        }

        if (entry.isDirectory()) {
          const subEntries = readdirSync(join(dir, entry.name), { withFileTypes: true });
          for (const sub of subEntries) {
            if (sub.isFile() && sub.name.endsWith(".json")) {
              const fullPath = join(dir, entry.name, sub.name);
              if (seen.has(fullPath)) continue;
              seen.add(fullPath);

              const artifact = readObservatoryJson(fullPath);
              if (artifact) {
                artifacts.push(fullPath);
              }
            }
          }
        }
      }
    } catch {
      continue;
    }
  }

  return artifacts;
}

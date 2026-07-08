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

function readObservatoryJson(artifactPath: string): ObservatoryArtifact | null {
  try {
    const raw = readFileSync(artifactPath, "utf-8");
    const parsed = JSON.parse(raw);

    if (!parsed.findings || !Array.isArray(parsed.findings)) {
      return null;
    }

    return {
      version: parsed.version || "unknown",
      generatedAt: parsed.generatedAt || new Date().toISOString(),
      findings: parsed.findings,
    };
  } catch {
    return null;
  }
}

function findingToTarget(finding: ObservatoryFinding): PolicyRule["target"] {
  if (finding.tool || finding.description.toLowerCase().includes("tool") || finding.description.toLowerCase().includes("command")) {
    return "command";
  }
  if (finding.path || finding.description.toLowerCase().includes("file") || finding.description.toLowerCase().includes("directory") || finding.description.toLowerCase().includes("path")) {
    return "file";
  }
  if (finding.host || finding.description.toLowerCase().includes("url") || finding.description.toLowerCase().includes("network") || finding.description.toLowerCase().includes("host") || finding.description.toLowerCase().includes("http")) {
    return "network";
  }
  if (finding.envVar || finding.description.toLowerCase().includes("env") || finding.description.toLowerCase().includes("environment") || finding.description.toLowerCase().includes("secret") || finding.description.toLowerCase().includes("credential")) {
    return "env";
  }
  if (finding.description.toLowerCase().includes("process") || finding.description.toLowerCase().includes("spawn") || finding.description.toLowerCase().includes("exec") || finding.description.toLowerCase().includes("fork")) {
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

function severityToAction(severity: ObservatoryFinding["severity"]): "deny" | "warn" {
  if (severity === "critical" || severity === "high") {
    return "deny";
  }
  return "warn";
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

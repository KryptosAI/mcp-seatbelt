import type { McpClientConfig, RiskFlag } from "../types.js";
import { assessRisk } from "../detectors/risk.js";
import { OWASP_LLM_TAXONOMY_ENTRIES, COMPLIANCE_TAXONOMY_ENTRIES } from "../owasp-mapping.js";

export interface SARIFLog {
  version: "2.1.0";
  $schema: string;
  runs: SARIFRun[];
}

interface SARIFRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SARIFRule[];
    };
  };
  results: SARIFResult[];
  artifacts: SARIFArtifact[];
  taxonomies?: SARIFTaxonomy[];
}

interface SARIFTaxonomy {
  name: string;
  version?: string;
  organization?: string;
  shortDescription: { text: string };
  taxa: SARIFTaxon[];
}

interface SARIFTaxon {
  id: string;
  name: string;
  shortDescription?: { text: string };
  properties?: Record<string, string>;
}

interface SARIFRule {
  id: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri: string;
  properties: {
    severity: string;
    category: string;
  };
}

interface SARIFResult {
  ruleId: string;
  ruleIndex: number;
  level: "error" | "warning" | "note";
  message: {
    text: string;
    markdown?: string;
  };
  locations: SARIFLocation[];
  properties?: Record<string, string>;
}

interface SARIFLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
    };
    region: {
      startLine: number;
      startColumn: number;
    };
  };
}

interface SARIFArtifact {
  location: {
    uri: string;
  };
  description?: {
    text: string;
  };
  contents?: {
    text: string;
  };
}

function riskLevelToSARIFLevel(level: string): "error" | "warning" | "note" {
  switch (level) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "note";
    default:
      return "warning";
  }
}

function flagIdToRuleIndex(rules: SARIFRule[], flag: RiskFlag): number {
  let idx = rules.findIndex((r) => r.id === flag.rule);
  if (idx === -1) {
    idx = rules.length;
    rules.push({
      id: flag.rule,
      shortDescription: { text: flag.rule },
      fullDescription: { text: flag.description },
      helpUri: `https://github.com/anomalyco/mcp-seatbelt#risk-rule-${flag.rule}`,
      properties: {
        severity: flag.severity,
        category: "security",
      },
    });
  }
  return idx;
}

export function generateSarifReport(configs: McpClientConfig[]): SARIFLog {
  const rules: SARIFRule[] = [];
  const results: SARIFResult[] = [];
  const artifacts: SARIFArtifact[] = [];
  const seenArtifacts = new Set<string>();

  for (const config of configs) {
    if (!seenArtifacts.has(config.path)) {
      seenArtifacts.add(config.path);
      const artifactIndex = artifacts.length;
      artifacts.push({
        location: { uri: config.path },
        description: { text: `MCP config for client: ${config.client}` },
      });
    }

    for (const server of config.servers) {
      const risk = server.risk.score === 0 ? assessRisk(server) : server.risk;

      for (const flag of risk.flags) {
        const ruleIndex = flagIdToRuleIndex(rules, flag);
        const level = riskLevelToSARIFLevel(flag.severity);

        results.push({
          ruleId: flag.rule,
          ruleIndex,
          level,
          message: {
            text: `[${flag.severity.toUpperCase()}] ${flag.description}`,
            markdown: `**${config.client}** → \`${server.name}\`\n\n${flag.description}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: config.path,
                },
                region: {
                  startLine: 1,
                  startColumn: 1,
                },
              },
            },
          ],
          properties: {
            client: config.client,
            server: server.name,
            command: server.command,
            transport: server.transport,
          },
        });
      }

      if (risk.flags.length === 0) {
        const ruleIndex = 0;
        results.push({
          ruleId: "MCP-SAFE",
          ruleIndex: ruleIndex,
          level: "note",
          message: {
            text: `Server "${server.name}" has no detected risk flags`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: config.path,
                },
                region: {
                  startLine: 1,
                  startColumn: 1,
                },
              },
            },
          ],
          properties: {
            client: config.client,
            server: server.name,
            command: server.command,
            transport: server.transport,
          },
        });
      }
    }
  }

  if (!rules.some((r) => r.id === "MCP-SAFE")) {
    rules.unshift({
      id: "MCP-SAFE",
      shortDescription: { text: "MCP-SAFE" },
      fullDescription: { text: "No risk flags detected for this MCP server" },
      helpUri: "https://github.com/anomalyco/mcp-seatbelt",
      properties: {
        severity: "low",
        category: "security",
      },
    });
    for (const result of results) {
      if (result.ruleId === "MCP-SAFE") {
        result.ruleIndex = 0;
      } else {
        result.ruleIndex += 1;
      }
    }
  }

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-seatbelt",
            version: "0.1.0",
            informationUri: "https://github.com/anomalyco/mcp-seatbelt",
            rules,
          },
        },
        results,
        artifacts,
        taxonomies: [
          {
            name: "OWASP LLM Top 10",
            version: "1.0",
            organization: "OWASP",
            shortDescription: { text: "OWASP Top 10 for LLM Applications" },
            taxa: OWASP_LLM_TAXONOMY_ENTRIES.map((entry) => ({
              id: entry.id,
              name: entry.title,
              shortDescription: { text: `${entry.id}: ${entry.title}` },
              properties: { severity: entry.severity },
            })),
          },
          {
            name: "Compliance Frameworks",
            shortDescription: { text: "Compliance framework mappings" },
            taxa: COMPLIANCE_TAXONOMY_ENTRIES.map((entry) => ({
              id: entry.id,
              name: entry.title,
              shortDescription: { text: `${entry.id}: ${entry.title}` },
              properties: { framework: entry.framework },
            })),
          },
        ],
      },
    ],
  };
}

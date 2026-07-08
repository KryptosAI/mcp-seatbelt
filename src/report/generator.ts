import type { McpClientConfig, RiskReport, ServerReport, ToolReport, RiskFlag } from "../types.js";
import { assessRisk } from "../detectors/risk.js";
import { generateDefaultPolicy } from "../policy/defaults.js";

function renderRiskLabel(level: string): string {
  const labels: Record<string, string> = {
    critical: "🔴 CRITICAL",
    high: "🟠 HIGH",
    medium: "🟡 MEDIUM",
    low: "🟢 LOW",
  };
  return labels[level] || level.toUpperCase();
}

function buildServerReport(config: McpClientConfig): ServerReport[] {
  return config.servers.map((srv) => {
    const risk = srv.risk.score === 0 ? assessRisk(srv) : srv.risk;
    const policy = generateDefaultPolicy([config]);
    const toolReports: ToolReport[] = risk.flags.map((flag) => ({
      name: srv.name,
      description: flag.description,
      riskFlags: [flag],
      policyAction: policy.rules[0]?.action || "warn" as const,
    }));

    if (toolReports.length === 0) {
      toolReports.push({
        name: srv.name,
        description: `Command: ${srv.command} ${srv.args.join(" ")}`,
        riskFlags: [],
        policyAction: "allow",
      });
    }

    return {
      name: srv.name,
      client: config.client,
      risk,
      tools: toolReports,
      proxied: true,
    };
  });
}

export function generateMarkdownReport(configs: McpClientConfig[]): string {
  const allServers = configs.flatMap((c) => buildServerReport(c));
  const highRisk = allServers.filter((s) => s.risk.level === "high" || s.risk.level === "critical").length;
  const mediumRisk = allServers.filter((s) => s.risk.level === "medium").length;
  const lowRisk = allServers.filter((s) => s.risk.level === "low").length;
  const allFlags: RiskFlag[] = allServers.flatMap((s) => s.risk.flags);

  let report = "";

  report += `# MCP Seatbelt Risk Report\n\n`;
  report += `**Generated:** ${new Date().toISOString()}\n\n`;

  report += `## Summary\n\n`;
  report += `| Metric | Count |\n`;
  report += `|--------|-------|\n`;
  report += `| Total Servers | ${allServers.length} |\n`;
  report += `| High / Critical Risk | ${highRisk} |\n`;
  report += `| Medium Risk | ${mediumRisk} |\n`;
  report += `| Low Risk | ${lowRisk} |\n`;
  report += `| Total Risk Flags | ${allFlags.length} |\n`;
  report += `\n`;

  for (const server of allServers) {
    report += `## ${server.name}\n\n`;
    report += `- **Client:** ${server.client}\n`;
    report += `- **Risk Level:** ${renderRiskLabel(server.risk.level)} (score: ${server.risk.score})\n`;
    report += `- **Proxied:** ${server.proxied ? "Yes" : "No"}\n\n`;

    if (server.risk.flags.length > 0) {
      report += `### Risk Flags\n\n`;
      for (const flag of server.risk.flags) {
        report += `- **${flag.rule}** [${flag.severity.toUpperCase()}]: ${flag.description}\n`;
      }
      report += `\n`;
    }

    if (server.tools.length > 0) {
      report += `### Tool Breakdown\n\n`;
      report += `| Tool | Risk Flags | Policy Action |\n`;
      report += `|------|------------|---------------|\n`;
      for (const tool of server.tools) {
        const flagCount = tool.riskFlags.length;
        report += `| ${tool.name} | ${flagCount} | ${tool.policyAction} |\n`;
      }
      report += `\n`;
    }
  }

  report += `## Recommendations\n\n`;

  const criticalFlags = allFlags.filter((f) => f.severity === "critical");
  const highFlags = allFlags.filter((f) => f.severity === "high");

  if (criticalFlags.length > 0) {
    report += `### Critical\n\n`;
    for (const flag of criticalFlags) {
      report += `- ${flag.description}\n`;
    }
    report += `\n`;
  }

  if (highFlags.length > 0) {
    report += `### High Priority\n\n`;
    for (const flag of highFlags) {
      report += `- ${flag.description}\n`;
    }
    report += `\n`;
  }

  if (allServers.length > 0) {
    report += `### Next Steps\n\n`;
    report += `1. Review the policy at \`.mcp-seatbelt/policy.yml\`\n`;
    report += `2. Start the proxy with \`mcp-seatbelt proxy\`\n`;
    report += `3. Update your MCP client config to point to the proxy URLs\n`;
  } else {
    report += `No MCP servers detected. Run \`mcp-seatbelt init\` to scan for configurations.\n`;
  }

  return report;
}

export function generateJsonReport(configs: McpClientConfig[]): RiskReport {
  const allServers = configs.flatMap((c) => buildServerReport(c));
  const highRisk = allServers.filter((s) => s.risk.level === "high" || s.risk.level === "critical").length;
  const mediumRisk = allServers.filter((s) => s.risk.level === "medium").length;
  const lowRisk = allServers.filter((s) => s.risk.level === "low").length;

  return {
    generatedAt: new Date().toISOString(),
    summary: {
      totalServers: allServers.length,
      highRisk,
      mediumRisk,
      lowRisk,
      blockedCalls: 0,
      allowedCalls: 0,
      warnedCalls: 0,
    },
    servers: allServers,
    recommendations: allServers
      .flatMap((s) => s.risk.flags)
      .map((f) => `[${f.severity.toUpperCase()}] ${f.description}`),
  };
}

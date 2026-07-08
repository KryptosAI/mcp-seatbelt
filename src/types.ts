export interface McpClientConfig {
  client: string;
  path: string;
  servers: McpServerConfig[];
}

export interface McpServerConfig {
  name: string;
  command: string;
  args: string[];
  env?: Record<string, string>;
  transport: "stdio" | "http" | "sse" | "streamable-http";
  url?: string;
  risk: RiskAssessment;
}

export interface RiskAssessment {
  score: number;
  level: "low" | "medium" | "high" | "critical";
  flags: RiskFlag[];
}

export interface RiskFlag {
  rule: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
}

export interface PolicyRule {
  id: string;
  description: string;
  target: "command" | "file" | "network" | "env" | "process";
  match: "exact" | "pattern" | "contains";
  values: string[];
  action: "allow" | "deny" | "warn" | "redact";
  timeWindow?: { days?: string[]; startHour?: number; endHour?: number };
  contextCondition?: { clientIn?: string[]; maxRequestsPerMinute?: number };
}

export interface PolicyConfig {
  version: string;
  mode: "audit" | "enforce";
  defaultAction: "allow" | "deny";
  rules: PolicyRule[];
  allowlist: {
    tools: string[];
    paths: string[];
    hosts: string[];
    envVars: string[];
  };
  allowSampling: boolean;
  extends?: string[];
}

export interface RiskReport {
  generatedAt: string;
  summary: {
    totalServers: number;
    highRisk: number;
    mediumRisk: number;
    lowRisk: number;
    blockedCalls: number;
    allowedCalls: number;
    warnedCalls: number;
  };
  servers: ServerReport[];
  recommendations: string[];
}

export interface ServerReport {
  name: string;
  client: string;
  risk: RiskAssessment;
  tools: ToolReport[];
  proxied: boolean;
}

export interface ToolReport {
  name: string;
  description: string;
  riskFlags: RiskFlag[];
  policyAction: "allow" | "deny" | "warn" | "redact";
}

export interface ProxyStats {
  totalRequests: number;
  blocked: number;
  allowed: number;
  warned: number;
  redacted: number;
  startTime: string;
  uptime: number;
}

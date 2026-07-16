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

export interface ArgConstraint {
  argName: string;
  constraint: "equals" | "startsWith" | "regex" | "in" | "notIn";
  values: string[];
}

export interface PolicyRule {
  id: string;
  description: string;
  target: "command" | "file" | "network" | "env" | "process";
  match: "exact" | "pattern" | "contains";
  values: string[];
  action: "allow" | "deny" | "warn" | "redact";
  argConstraints?: ArgConstraint[];
  timeWindow?: { days?: string[]; startHour?: number; endHour?: number };
  contextCondition?: { clientIn?: string[]; maxRequestsPerMinute?: number };
  timeoutMs?: number;
}

export interface WebhookConfig {
  url: string;
  events: Array<"deny" | "warn" | "redact">;
  format?: "slack" | "discord" | "json";
}

export interface PolicyConfig {
  version: string;
  mode: "audit" | "enforce";
  defaultAction: "allow" | "deny";
  defaultTimeoutMs?: number;
  rules: PolicyRule[];
  allowlist: {
    tools: string[];
    paths: string[];
    hosts: string[];
    envVars: string[];
  };
  allowSampling: boolean;
  extends?: string[];
  notifications?: {
    webhooks?: WebhookConfig[];
  };
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
  redactedCount: number;
  timedOut: number;
  startTime: string;
  uptime: number;
}

export interface ProxyServerOptions {
  apiKey?: string;
  rateLimit?: number;
  dlp?: boolean;
  defaultTimeoutMs?: number;
}

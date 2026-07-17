import type { McpServerConfig, RiskAssessment, RiskFlag } from "../types.js";
import { mapRiskToOWASP } from "../owasp-mapping.js";

const RISK_RULES: {
  check: (srv: McpServerConfig) => boolean;
  rule: string;
  description: string;
  severity: RiskFlag["severity"];
}[] = [
  {
    check: (srv) => /^(\/.*\/)?(bash|sh|zsh|fish|pwsh|powershell|cmd|python|perl|ruby)$/.test(srv.command),
    rule: "shell-interpreter",
    description: "Server uses a shell interpreter as its command",
    severity: "critical",
  },
  {
    check: (srv) => {
      if (!/^(docker|\/.*\/docker)$/.test(srv.command)) return false;
      const allArgs = srv.args.join(" ");
      return /(--privileged|-v\s+\/:\/host|-v\s+\/etc:\/etc|--network=host|--pid=host|--cap-add=ALL)/.test(allArgs);
    },
    rule: "docker-container",
    description: "Docker container running with dangerous privileged flags",
    severity: "high",
  },
  {
    check: (srv) => srv.args.some((a) =>
      /(--no-sandbox|--disable-web-security|--allow-running-insecure-content|--unsafely-treat-insecure-origin-as-secure)/.test(a),
    ),
    rule: "no-sandbox",
    description: "Server runs with security sandboxing disabled",
    severity: "critical",
  },
  {
    check: (srv) => /^(curl|wget|nc|ncat|netcat|socat|telnet)$/.test(srv.command),
    rule: "network-tool",
    description: "Server is a raw network tool capable of arbitrary connections",
    severity: "high",
  },
  {
    check: (srv) => srv.transport !== "stdio",
    rule: "network-transport",
    description: "Server uses a non-stdio transport",
    severity: "medium",
  },
  {
    check: (srv) => {
      const allArgs = srv.args.join(" ");
      return /\b(eval|exec|spawn|fork|child_process|subprocess)\b/i.test(allArgs);
    },
    rule: "process-spawn",
    description: "Server arguments suggest process spawning capabilities",
    severity: "high",
  },
  {
    check: (srv) => {
      const allArgs = srv.args.join(" ");
      return /\b(rm\s+-rf|rmdir|del\s+\/F|format\b|dd\s+if=)/i.test(allArgs);
    },
    rule: "destructive-fs",
    description: "Server has destructive filesystem operation patterns in arguments",
    severity: "critical",
  },
  {
    check: (srv) => {
      const allArgs = srv.args.join(" ");
      return /(https?:\/\/|\bapi\b|\bendpoint\b|\burl\b)/i.test(allArgs);
    },
    rule: "remote-access",
    description: "Server has remote URL patterns in arguments",
    severity: "medium",
  },
  {
    check: (srv) => {
      const envKeys = srv.env ? Object.keys(srv.env) : [];
      return envKeys.some((k) =>
        /\b(TOKEN|SECRET|KEY|PASSWORD|PASSWD|AUTH|CREDENTIAL|PRIVATE)\b/i.test(k),
      );
    },
    rule: "sensitive-env",
    description: "Server environment contains sensitive credential-like variable names",
    severity: "high",
  },
  {
    check: (srv) => srv.command === "npx" || srv.command === "uvx" || srv.command === "pipx",
    rule: "package-runner",
    description: "Server uses a package runner",
    severity: "medium",
  },
  {
    check: (srv) => {
      if (srv.command !== "npx" && srv.command !== "uvx") return false;
      const riskyPatterns = [
        "shell", "bash", "exec", "spawn", "child_process", "fs-extra",
        "rimraf", "node-fetch", "axios", "puppeteer", "playwright",
        "electron", "vm2", "eval", "vm", "process",
      ];
      const firstArg = srv.args[0] || "";
      return riskyPatterns.some((p) => firstArg.toLowerCase().includes(p));
    },
    rule: "risky-package",
    description: "Package runner with a package known for shell/filesystem/network access",
    severity: "high",
  },
  {
    check: (srv) => {
      const allArgs = srv.args.join(" ");
      return /\b(chmod|chown|sudo|su\b)/i.test(allArgs);
    },
    rule: "privilege-escalation",
    description: "Server has privilege escalation patterns in arguments",
    severity: "critical",
  },
  {
    check: (srv) => {
      const allText = `${srv.command} ${srv.args.join(" ")}`;
      return /(home|~|\/etc\/|\/var\/|\/tmp\/|\/Users\/)/i.test(allText);
    },
    rule: "sensitive-paths",
    description: "Server references sensitive filesystem paths",
    severity: "medium",
  },
];

const SEVERITY_SCORES: Record<RiskFlag["severity"], number> = {
  critical: 40,
  high: 25,
  medium: 10,
  low: 5,
};

export function assessRisk(server: McpServerConfig): RiskAssessment {
  const flags: RiskFlag[] = [];

  for (const rule of RISK_RULES) {
    if (rule.check(server)) {
      const owaspTags = mapRiskToOWASP(rule.rule);
      flags.push({
        rule: rule.rule,
        description: rule.description,
        severity: rule.severity,
        ...(owaspTags.length > 0 ? { owasp: owaspTags } : {}),
      });
    }
  }

  const score = flags.reduce((sum, f) => sum + SEVERITY_SCORES[f.severity], 0);

  let level: RiskAssessment["level"];
  if (score >= 60) level = "critical";
  else if (score >= 30) level = "high";
  else if (score >= 10) level = "medium";
  else level = "low";

  return { score, level, flags };
}

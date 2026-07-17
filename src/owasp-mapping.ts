export const OWASP_LLM_MAPPING: Record<string, { id: string; title: string; severity: string }> = {
  "shell-interpreter": { id: "LLM06", title: "Excessive Agency", severity: "critical" },
  "destructive-fs": { id: "LLM06", title: "Excessive Agency", severity: "high" },
  "no-sandbox": { id: "LLM06", title: "Excessive Agency", severity: "critical" },
  "sensitive-env": { id: "LLM02", title: "Sensitive Information Disclosure", severity: "high" },
  "remote-access": { id: "LLM08", title: "Vector Embedding Weaknesses", severity: "medium" },
  "network-tool": { id: "LLM06", title: "Excessive Agency", severity: "high" },
  "package-runner": { id: "LLM09", title: "Supply Chain Vulnerabilities", severity: "medium" },
  "risky-package": { id: "LLM09", title: "Supply Chain Vulnerabilities", severity: "high" },
  "privilege-escalation": { id: "LLM04", title: "Model Denial of Service", severity: "high" },
  "docker-container": { id: "LLM06", title: "Excessive Agency", severity: "high" },
  "network-transport": { id: "LLM03", title: "Training Data Poisoning", severity: "medium" },
  "process-spawn": { id: "LLM06", title: "Excessive Agency", severity: "high" },
  "sensitive-paths": { id: "LLM02", title: "Sensitive Information Disclosure", severity: "medium" },
};

export function mapRiskToOWASP(riskRuleId: string): string[] {
  const match = OWASP_LLM_MAPPING[riskRuleId];
  return match ? [match.id] : [];
}

export const OWASP_LLM_TAXONOMY_ENTRIES = [
  { id: "LLM01", title: "Prompt Injection", severity: "critical" },
  { id: "LLM02", title: "Sensitive Information Disclosure", severity: "high" },
  { id: "LLM03", title: "Training Data Poisoning", severity: "medium" },
  { id: "LLM04", title: "Model Denial of Service", severity: "high" },
  { id: "LLM05", title: "Supply Chain Vulnerabilities", severity: "medium" },
  { id: "LLM06", title: "Excessive Agency", severity: "critical" },
  { id: "LLM07", title: "System Prompt Leakage", severity: "medium" },
  { id: "LLM08", title: "Vector Embedding Weaknesses", severity: "medium" },
  { id: "LLM09", title: "Supply Chain Vulnerabilities", severity: "medium" },
  { id: "LLM10", title: "Insecure Plugin Design", severity: "high" },
];

export const COMPLIANCE_TAXONOMY_ENTRIES = [
  { id: "SOC2", title: "SOC 2 Trust Services Criteria", framework: "soc2" },
  { id: "HIPAA", title: "HIPAA Security Rule", framework: "hipaa" },
  { id: "GDPR", title: "GDPR Data Protection", framework: "gdpr" },
  { id: "PCIDSS", title: "PCI DSS Payment Card Security", framework: "pci-dss" },
  { id: "ISO27001", title: "ISO 27001 Information Security", framework: "iso27001" },
  { id: "NIST", title: "NIST Cybersecurity Framework", framework: "nist" },
];

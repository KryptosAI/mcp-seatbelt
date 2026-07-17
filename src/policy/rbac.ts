import { newEnforcer, Enforcer } from "casbin";
import path from "node:path";

let enforcer: Enforcer | null = null;

export async function initRBAC(modelPath?: string, policyPath?: string): Promise<void> {
  const m = modelPath ?? path.join(process.cwd(), ".mcp-seatbelt", "rbac_model.conf");
  const p = policyPath ?? path.join(process.cwd(), ".mcp-seatbelt", "rbac_policy.csv");
  enforcer = await newEnforcer(m, p);
}

export async function checkAccess(agentId: string, toolName: string, action: string): Promise<boolean> {
  if (!enforcer) return true;
  return enforcer.enforce(agentId, toolName, action);
}

export function getEnforcer(): Enforcer | null { return enforcer; }

export function resetRBAC(): void { enforcer = null; }

import { mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import chalk from "chalk";

const __dirname = dirname(fileURLToPath(import.meta.url));

const RBAC_MODEL = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`;

const RBAC_POLICY = `p, admin, *, execute
p, viewer, tools/list, execute
p, viewer, resources/list, execute
p, viewer, prompts/list, execute

g, agent_admin, admin
g, agent_viewer, viewer
`;

export interface RbacInitOptions {
  output: string;
}

export async function rbacInitCommand(opts: RbacInitOptions): Promise<void> {
  const { output } = opts;

  mkdirSync(output, { recursive: true });

  const modelPath = join(output, "rbac_model.conf");
  const policyPath = join(output, "rbac_policy.csv");

  writeFileSync(modelPath, RBAC_MODEL, "utf-8");
  writeFileSync(policyPath, RBAC_POLICY, "utf-8");

  console.log(chalk.green("\nRBAC configuration initialized"));
  console.log(chalk.dim(`  Model: ${modelPath}`));
  console.log(chalk.dim(`  Policy: ${policyPath}`));
  console.log();
  console.log(chalk.bold("Usage:"));
  console.log(chalk.dim("  1. Start proxy with RBAC: mcp-seatbelt proxy --rbac"));
  console.log(chalk.dim("  2. Edit roles in rbac_policy.csv"));
  console.log();
}

import { readFileSync, existsSync } from "node:fs";
import chalk from "chalk";
import { parsePolicy } from "../policy/yaml.js";
import { PolicyEngine } from "../policy/engine.js";
import { fuzzTool } from "../security/fuzzer.js";

export interface FuzzOptions {
  policy: string;
  iterations: number;
  json?: boolean;
}

export async function fuzzCommand(opts: FuzzOptions): Promise<void> {
  if (!existsSync(opts.policy)) {
    console.error(chalk.red(`Policy file not found: ${opts.policy}`));
    process.exit(1);
  }

  const raw = readFileSync(opts.policy, "utf-8");
  const policyConfig = parsePolicy(raw);
  const engine = new PolicyEngine(policyConfig);

  const toolNames = [
    "bash", "sh", "zsh", "python", "node", "eval_tool", "exec_tool",
    "read_file", "write_file", "http_request", "curl", "fetch",
    "env_access", "process_spawn", "system_exec", "dangerous_tool",
    "wget", "powershell", "cmd", "safe_tool", "admin_tool",
  ];

  console.log(chalk.cyan("\nFuzzing policy rules...\n"));
  console.log(chalk.dim(`Policy: ${opts.policy} | Iterations per tool: ${opts.iterations}\n`));

  const results = [];
  let totalTested = 0;
  let totalBlocked = 0;
  let totalAllowed = 0;
  let totalBypasses = 0;

  for (const toolName of toolNames) {
    const result = await fuzzTool(toolName, undefined, engine, {
      iterations: opts.iterations,
    });
    results.push(result);
    totalTested += result.totalTested;
    totalBlocked += result.blocked;
    totalAllowed += result.allowed;
    totalBypasses += result.bypasses.length;
  }

  if (opts.json) {
    console.log(JSON.stringify({
      summary: { totalTested, totalBlocked, totalAllowed, totalBypasses },
      results,
    }, null, 2));
    return;
  }

  console.log("┌──────────────────────────────┬──────────┬──────────┬──────────┬──────────┐");
  console.log("│ Tool                         │ Tested   │ Blocked  │ Allowed  │ Bypasses │");
  console.log("├──────────────────────────────┼──────────┼──────────┼──────────┼──────────┤");

  for (const r of results) {
    const name = r.toolName.padEnd(28).slice(0, 28);
    const tested = String(r.totalTested).padStart(8);
    const blocked = String(r.blocked).padStart(8);
    const allowed = String(r.allowed).padStart(8);
    const bypasses = r.bypasses.length > 0
      ? chalk.red(String(r.bypasses.length).padStart(8))
      : String(r.bypasses.length).padStart(8);
    console.log(`│ ${name} │ ${tested} │ ${blocked} │ ${allowed} │ ${bypasses} │`);
  }

  console.log("└──────────────────────────────┴──────────┴──────────┴──────────┴──────────┘\n");

  if (totalBypasses > 0) {
    console.log(chalk.red.bold(`Total bypasses found: ${totalBypasses}\n`));
    for (const r of results) {
      for (const b of r.bypasses) {
        console.log(chalk.red(`  [${r.toolName}] ${b.description}`));
        console.log(chalk.dim(`    Payload: ${b.payload}`));
      }
    }
    console.log();
  } else {
    console.log(chalk.green.bold(`Tested ${totalTested} inputs, ${totalBlocked} blocked, ${totalBypasses} bypasses found\n`));
  }
}

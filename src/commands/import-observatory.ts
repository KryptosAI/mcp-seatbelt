import { existsSync } from "node:fs";
import chalk from "chalk";
import {
  importObservatoryResults,
  discoverObservatoryArtifacts,
} from "../integrations/observatory.js";
import { stringify as yamlStringify } from "../policy/yaml.js";

export interface ImportObservatoryOptions {
  artifactPath?: string;
  base: string;
}

export async function importObservatoryCommand(opts: ImportObservatoryOptions): Promise<void> {
  const { artifactPath, base } = opts;

  console.log(chalk.cyan("\n🔍 Importing mcp-observatory findings...\n"));

  let paths: string[];

  if (artifactPath) {
    if (!existsSync(artifactPath)) {
      console.error(chalk.red(`Artifact not found: ${artifactPath}`));
      process.exit(1);
    }
    paths = [artifactPath];
  } else {
    paths = discoverObservatoryArtifacts(base);

    if (paths.length === 0) {
      console.log(chalk.yellow("No mcp-observatory artifacts found."));
      console.log(chalk.dim(`  Searched: ${base}, .mcp-observatory/runs/, .mcp-observatory-metrics/\n`));
      process.exit(0);
    }
  }

  for (const path of paths) {
    console.log(chalk.dim(`Processing: ${path}`));

    const rules = importObservatoryResults(path);

    if (rules.length === 0) {
      console.log(chalk.yellow(`  No valid findings in ${path}`));
      continue;
    }

    console.log(chalk.green(`  Found ${rules.length} rule(s):`));

    for (const rule of rules) {
      const severityLabel =
        rule.action === "deny"
          ? chalk.red(rule.action.toUpperCase())
          : chalk.yellow(rule.action.toUpperCase());
      console.log(
        `    ${chalk.bold(rule.id)} [${severityLabel}] → ${rule.description}`,
      );
    }

    console.log();
  }

  if (paths.length === 1) {
    const allRules = importObservatoryResults(paths[0]);
    if (allRules.length > 0) {
      const policySection = {
        rules: allRules,
      };

      console.log(chalk.bold("Suggested policy rules (YAML):\n"));
      console.log(chalk.dim(yamlStringify(policySection)));

      console.log(
        chalk.dim(
          "\nCopy these rules into your .mcp-seatbelt/policy.yml to enforce them.\n",
        ),
      );
    }
  } else {
    console.log(
      chalk.dim(
        `Processed ${paths.length} artifact(s). Use import-observatory <path> for YAML output of a single file.\n`,
      ),
    );
  }
}

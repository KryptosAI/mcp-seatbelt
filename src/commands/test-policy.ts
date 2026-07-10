import { readFileSync, existsSync } from "node:fs";
import chalk from "chalk";
import { load as yamlLoad } from "js-yaml";
import { parsePolicy } from "../policy/yaml.js";
import { PolicyEngine } from "../policy/engine.js";
import { DEFAULT_POLICY } from "../policy/defaults.js";
import type { PolicyConfig } from "../types.js";

interface TestCase {
  name: string;
  tool: string;
  description?: string;
  args?: Record<string, unknown>;
  expect: "allow" | "deny" | "warn" | "redact";
  matchReason?: string;
}

interface TestFile {
  tests: TestCase[];
}

export interface TestPolicyOptions {
  testFile: string;
  policy?: string;
}

function getActionLabel(action: string): string {
  switch (action) {
    case "deny":
      return "BLOCKED";
    case "warn":
      return "WARNED";
    case "redact":
      return "REDACTED";
    case "allow":
      return "ALLOWED";
    default:
      return action.toUpperCase();
  }
}

export async function testPolicyCommand(opts: TestPolicyOptions): Promise<void> {
  if (!existsSync(opts.testFile)) {
    console.error(chalk.red(`Test file not found: ${opts.testFile}`));
    process.exit(1);
  }

  let policyConfig: PolicyConfig;

  if (opts.policy) {
    if (!existsSync(opts.policy)) {
      console.error(chalk.red(`Policy file not found: ${opts.policy}`));
      process.exit(1);
    }
    const raw = readFileSync(opts.policy, "utf-8");
    policyConfig = parsePolicy(raw);
  } else {
    policyConfig = structuredClone(DEFAULT_POLICY);
  }

  const engine = new PolicyEngine(policyConfig);

  let testFile: TestFile;
  try {
    const raw = readFileSync(opts.testFile, "utf-8");
    const parsed = yamlLoad(raw) as unknown;
    if (!parsed || typeof parsed !== "object") {
      console.error(chalk.red("Invalid test file: expected YAML object with 'tests' array"));
      process.exit(1);
    }
    const doc = parsed as Record<string, unknown>;
    if (!Array.isArray(doc.tests)) {
      console.error(chalk.red("Invalid test file: missing 'tests' array"));
      process.exit(1);
    }
    testFile = { tests: doc.tests as TestCase[] };
  } catch (err) {
    console.error(chalk.red(`Failed to parse test file: ${err instanceof Error ? err.message : String(err)}`));
    process.exit(1);
  }

  let passed = 0;
  let failed = 0;

  console.log(chalk.cyan("\n🧪 Running policy tests...\n"));

  for (const test of testFile.tests) {
    const args = test.args ?? {};
    const desc = test.description ?? "";

    const result = engine.evaluate(test.tool, desc, args, {
      client: "test-policy",
      requestCount: 1,
    });

    let testPassed = true;
    const failures: string[] = [];

    if (result.action !== test.expect) {
      testPassed = false;
      failures.push(
        `Expected action ${chalk.green(test.expect)} but got ${chalk.red(result.action)}`,
      );
    }

    if (test.matchReason !== undefined) {
      const reasonMatch = result.reasons.some((r) =>
        r.toLowerCase().includes(test.matchReason!.toLowerCase()),
      );
      if (!reasonMatch) {
        testPassed = false;
        failures.push(
          `Expected reason to contain "${test.matchReason}" but got: ${result.reasons.join("; ")}`,
        );
      }
    }

    if (testPassed) {
      passed++;
      console.log(
        `${chalk.green("✓")} ${test.name} — ${chalk.green(getActionLabel(result.action))}`,
      );
    } else {
      failed++;
      console.log(`${chalk.red("✗")} ${test.name}`);
      for (const failure of failures) {
        console.log(`  ${chalk.red(failure)}`);
      }
    }
  }

  console.log(
    `\n${chalk.bold(passed)}${chalk.green(" passed")}, ${chalk.bold(failed)}${chalk.red(" failed")}, ${chalk.bold(testFile.tests.length)} total\n`,
  );

  if (failed > 0) {
    process.exit(1);
  }
}

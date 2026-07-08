import yaml from "js-yaml";
import type { PolicyConfig } from "../types.js";
import { validatePolicy } from "./schema.js";

export function parse(raw: string): unknown {
  return yaml.load(raw);
}

export function stringify(obj: unknown): string {
  return yaml.dump(obj, {
    indent: 2,
    lineWidth: 120,
    noRefs: true,
    sortKeys: false,
  });
}

export function parsePolicy(raw: string): PolicyConfig {
  const parsed = parse(raw);
  return validatePolicy(parsed);
}

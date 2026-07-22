import Ajv, { type ValidateFunction } from "ajv";
import { createHash } from "node:crypto";

const ajv = new Ajv({ allErrors: true, strict: false });

interface CachedValidator {
  hash: string;
  validate: ValidateFunction;
}

// Keyed by tool name; the stored hash lets us skip recompilation when the
// same schema is re-registered and recompile when the schema actually changed.
const validatorCache = new Map<string, CachedValidator>();

function schemaHash(schema: object): string {
  return createHash("sha1").update(JSON.stringify(schema)).digest("hex");
}

export function compileToolSchema(toolName: string, schema: object): void {
  try {
    const hash = schemaHash(schema);
    const existing = validatorCache.get(toolName);
    if (existing && existing.hash === hash) {
      return;
    }
    const validate = ajv.compile(schema);
    validatorCache.set(toolName, { hash, validate });
  } catch (err) {
    console.error(`[mcp-seatbelt:schema] Invalid schema for tool '${toolName}': ${err instanceof Error ? err.message : 'Unknown error'}`);
  }
}

export function validateToolArgs(toolName: string, args: unknown): { valid: boolean; errors: string[] } {
  const entry = validatorCache.get(toolName);
  if (!entry) return { valid: true, errors: [] };

  const { validate } = entry;
  const valid = validate(args);
  const errors: string[] = [];

  if (!valid && validate.errors) {
    for (const err of validate.errors) {
      const path = err.instancePath || "args";
      errors.push(`${path}: ${err.message}`);
    }
  }

  return { valid, errors };
}

export function validatePathSafety(args: Record<string, unknown>): { safe: boolean; violations: string[] } {
  const violations: string[] = [];

  for (const [key, value] of Object.entries(args)) {
    if (typeof value !== "string") continue;

    if (value.includes("../") || value.includes("..\\")) {
      violations.push(`${key}: path traversal detected ("${value}")`);
    }
    if (value.startsWith("/etc/") || value.startsWith("/root/") || value.startsWith("C:\\Windows")) {
      violations.push(`${key}: sensitive path ("${value}")`);
    }
    if (value.includes("\0")) {
      violations.push(`${key}: null byte injection detected`);
    }
  }

  return { safe: violations.length === 0, violations };
}

export function clearSchemaCache(): void {
  validatorCache.clear();
}

export function getSchemaCount(): number {
  return validatorCache.size;
}

import Ajv, { type ValidateFunction } from "ajv";

const ajv = new Ajv({ allErrors: true, strict: false });

const validatorCache = new Map<string, ValidateFunction>();

export function compileToolSchema(toolName: string, schema: object): void {
  try {
    const validate = ajv.compile(schema);
    validatorCache.set(toolName, validate);
  } catch (err) {
    console.error(`[mcp-seatbelt:schema] Invalid schema for tool '${toolName}': ${err instanceof Error ? err.message : 'Unknown error'}`);
  }
}

export function validateToolArgs(toolName: string, args: unknown): { valid: boolean; errors: string[] } {
  const validate = validatorCache.get(toolName);
  if (!validate) return { valid: true, errors: [] };

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

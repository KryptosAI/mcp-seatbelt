import Ajv, { type ErrorObject } from "ajv";

const stringArray = { type: "array", items: { type: "string" } } as const;

export const POLICY_JSON_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["version", "mode", "defaultAction", "rules", "allowlist"],
  properties: {
    version: { type: "string", minLength: 1 },
    mode: { enum: ["audit", "enforce"] },
    defaultAction: { enum: ["allow", "deny"] },
    defaultTimeoutMs: { type: "integer", minimum: 1 },
    allowSampling: { type: "boolean" },
    extends: stringArray,
    rules: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "description", "target", "match", "values", "action"],
        properties: {
          id: { type: "string", minLength: 1 },
          description: { type: "string", minLength: 1 },
          target: { enum: ["command", "file", "network", "env", "process"] },
          match: { enum: ["exact", "pattern", "contains"] },
          values: stringArray,
          action: { enum: ["allow", "deny", "warn", "redact"] },
          timeoutMs: { type: "integer", minimum: 1 },
          argConstraints: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: false,
              required: ["argName", "constraint", "values"],
              properties: {
                argName: { type: "string", minLength: 1 },
                constraint: { enum: ["equals", "startsWith", "regex", "in", "notIn"] },
                values: stringArray,
              },
            },
          },
          timeWindow: {
            type: "object",
            additionalProperties: false,
            properties: {
              days: stringArray,
              startHour: { type: "integer", minimum: 0, maximum: 23 },
              endHour: { type: "integer", minimum: 0, maximum: 23 },
            },
          },
          contextCondition: {
            type: "object",
            additionalProperties: false,
            properties: {
              clientIn: stringArray,
              maxRequestsPerMinute: { type: "integer", minimum: 1 },
            },
          },
          compliance: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: false,
              required: ["framework", "controls"],
              properties: {
                framework: {
                  enum: ["soc2", "hipaa", "gdpr", "pci-dss", "iso27001", "nist"],
                },
                controls: stringArray,
                remediation: { type: "string" },
              },
            },
          },
        },
      },
    },
    allowlist: {
      type: "object",
      additionalProperties: false,
      required: ["tools", "paths", "hosts", "envVars"],
      properties: {
        tools: stringArray,
        paths: stringArray,
        hosts: stringArray,
        envVars: stringArray,
      },
    },
    notifications: {
      type: "object",
      additionalProperties: false,
      properties: {
        webhooks: {
          type: "array",
          items: {
            type: "object",
            additionalProperties: false,
            required: ["url", "events"],
            properties: {
              url: { type: "string", minLength: 1 },
              events: {
                type: "array",
                items: { enum: ["deny", "warn", "redact"] },
              },
              format: { enum: ["slack", "discord", "json"] },
            },
          },
        },
      },
    },
  },
} as const;

const ajv = new Ajv({ allErrors: true, strict: false });
const validateStructure = ajv.compile(POLICY_JSON_SCHEMA);

function pointerPath(pointer: string): string {
  const segments = pointer
    .split("/")
    .slice(1)
    .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"));
  return segments.reduce(
    (path, segment) =>
      /^\d+$/.test(segment)
        ? `${path}[${segment}]`
        : path
          ? `${path}.${segment}`
          : segment,
    "",
  );
}

function formatError(error: ErrorObject): string {
  let path = pointerPath(error.instancePath);
  if (error.keyword === "type") {
    if (path.endsWith(".compliance")) {
      return `${path}: compliance must be an array`;
    }
    if (/\.controls\[\d+\]$/.test(path)) {
      return `${path}: controls must contain only non-empty strings`;
    }
    if (path.endsWith(".remediation")) {
      return `${path}: remediation must be a string`;
    }
  }
  if (error.keyword === "required") {
    const missing = (error.params as { missingProperty: string }).missingProperty;
    path = path ? `${path}.${missing}` : missing;
  } else if (error.keyword === "additionalProperties") {
    const extra = (error.params as { additionalProperty: string }).additionalProperty;
    path = path ? `${path}.${extra}` : extra;
  }
  return `${path || "policy"}: ${error.message ?? "is invalid"}`;
}

export function validatePolicyStructure(config: unknown): void {
  if (validateStructure(config)) return;
  const errors = (validateStructure.errors ?? []).map(formatError);
  throw new Error(`Policy schema validation failed:\n- ${errors.join("\n- ")}`);
}

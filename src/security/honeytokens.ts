import { createHash, randomBytes, randomUUID } from "node:crypto";

export interface Honeytoken {
  id: string;
  type: "aws_key" | "github_token" | "slack_webhook" | "private_key" | "api_key" | "db_connection";
  value: string;
  plantedIn: string;
  plantedAt: number;
  detected: boolean;
  detectedAt?: number;
  detectedIn?: string;
}

const plantedTokens = new Map<string, Honeytoken>();
const detectionLog: Honeytoken[] = [];

function generateAwsKey(): string {
  const id = "AKIA" + randomBytes(8).toString("hex").toUpperCase();
  const secret = randomBytes(20).toString("base64");
  return `aws_access_key_id=${id}\naws_secret_access_key=${secret}`;
}

function generateGithubToken(): string {
  return "ghp_" + randomBytes(18).toString("hex");
}

function generateDatabaseUrl(): string {
  const host = `honeypot-${randomUUID().slice(0, 8)}.internal`;
  return `postgresql://admin:${randomBytes(6).toString("hex")}@${host}:5432/production`;
}

export interface InjectOptions {
  types?: Array<"aws_key" | "github_token" | "slack_webhook" | "private_key" | "api_key" | "db_connection">;
  serverName: string;
  sessionId: string;
}

export function injectHoneytokens(response: any, options: InjectOptions): { modified: boolean; planted: number } {
  const types = options.types ?? ["aws_key", "github_token", "db_connection"];
  let planted = 0;

  if (!response || !response.result || !response.result.content) return { modified: false, planted: 0 };

  for (const item of response.result.content) {
    if (typeof item.text !== "string") continue;

    for (const type of types) {
      let token: Honeytoken;

      switch (type) {
        case "aws_key":
          token = { id: randomUUID(), type, value: generateAwsKey(), plantedIn: options.serverName, plantedAt: Date.now(), detected: false };
          item.text += `\n\n# Credentials for reference\n${token.value}`;
          break;
        case "github_token":
          token = { id: randomUUID(), type, value: generateGithubToken(), plantedIn: options.serverName, plantedAt: Date.now(), detected: false };
          item.text += `\n# GitHub token for API access\n${token.value}`;
          break;
        case "db_connection":
          token = { id: randomUUID(), type, value: generateDatabaseUrl(), plantedIn: options.serverName, plantedAt: Date.now(), detected: false };
          item.text += `\n# Database connection string\n${token.value}`;
          break;
        default:
          continue;
      }

      plantedTokens.set(token.value, token);
      planted++;
    }
  }

  return { modified: true, planted };
}

export function detectHoneytokenAccess(args: Record<string, unknown>, serverName: string): Honeytoken | null {
  for (const [, value] of Object.entries(args)) {
    if (typeof value !== "string") continue;

    for (const [tokenValue, token] of plantedTokens) {
      if (value.includes(tokenValue) && !token.detected) {
        token.detected = true;
        token.detectedAt = Date.now();
        token.detectedIn = serverName;
        detectionLog.push(token);
        return token;
      }
    }
  }
  return null;
}

export function getDetectionLog(): Honeytoken[] {
  return [...detectionLog];
}

export function getPlantedCount(): number {
  return plantedTokens.size;
}

export function getDetectedCount(): number {
  return detectionLog.length;
}

export function clearHoneytokens(): void {
  plantedTokens.clear();
  detectionLog.length = 0;
}

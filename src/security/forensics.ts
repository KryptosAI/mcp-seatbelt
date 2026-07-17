import { appendFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";

export interface ForensicEvent {
  timestamp: number;
  direction: "request" | "response";
  payload: unknown;
}

export interface SessionCapture {
  sessionId: string;
  startedAt: number;
  events: ForensicEvent[];
}

let activeSession: SessionCapture | null = null;
const DEFAULT_SESSION_DIR = path.join(process.cwd(), ".mcp-seatbelt", "sessions");
let sessionDir = DEFAULT_SESSION_DIR;

export function setSessionDir(dir: string): void {
  sessionDir = dir;
}

export function getSessionDir(): string {
  return sessionDir;
}

export async function startSessionCapture(): Promise<string> {
  const sessionId = randomUUID();
  activeSession = {
    sessionId,
    startedAt: Date.now(),
    events: [],
  };

  if (!existsSync(sessionDir)) {
    await mkdir(sessionDir, { recursive: true });
  }

  return sessionId;
}

export function captureRequest(request: unknown): void {
  if (!activeSession) return;
  activeSession.events.push({
    timestamp: Date.now(),
    direction: "request",
    payload: request,
  });
}

export function captureResponse(response: unknown): void {
  if (!activeSession) return;
  activeSession.events.push({
    timestamp: Date.now(),
    direction: "response",
    payload: response,
  });
}

export function getActiveSession(): SessionCapture | null {
  return activeSession;
}

export async function saveSession(): Promise<string | null> {
  if (!activeSession || activeSession.events.length === 0) return null;

  if (!existsSync(sessionDir)) {
    await mkdir(sessionDir, { recursive: true });
  }

  const filepath = path.join(sessionDir, `${activeSession.sessionId}.mcpcap.json`);
  await appendFile(filepath, JSON.stringify({
    sessionId: activeSession.sessionId,
    startedAt: activeSession.startedAt,
    endedAt: Date.now(),
    eventCount: activeSession.events.length,
    events: activeSession.events,
  }, null, 2));

  const savedId = activeSession.sessionId;
  activeSession = null;
  return filepath;
}

export function stopSessionCapture(): void {
  activeSession = null;
}

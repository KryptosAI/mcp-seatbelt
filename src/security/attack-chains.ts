import { createMachine, interpret, type AnyActorRef } from "xstate";

export interface CallEvent {
  toolName: string;
  args: Record<string, unknown>;
  sessionId: string;
  timestamp: number;
}

const attackChainMachine = createMachine({
  id: "attack-chain",
  initial: "idle",
  states: {
    idle: {
      on: {
        READ_SENSITIVE: "reconnaissance",
        SHELL_EXEC: "execution",
        NETWORK_CALL: "exfiltration_attempt",
      },
    },
    reconnaissance: {
      on: {
        WRITE_SSH: "persistence",
        NETWORK_CALL: "exfiltration_attempt",
        READ_SENSITIVE: "reconnaissance",
      },
      after: { 300_000: "idle" },
    },
    execution: {
      on: {
        WRITE_SYSTEM: "persistence",
        NETWORK_CALL: "exfiltration_attempt",
      },
      after: { 300_000: "idle" },
    },
    persistence: {
      on: {
        NETWORK_CALL: "exfiltration_attempt",
        EXEC_PROCESS: "execution",
      },
      after: { 300_000: "idle" },
    },
    exfiltration_attempt: {
      on: {
        LARGE_FILE_READ: "exfiltration_confirmed",
      },
      after: { 300_000: "idle" },
    },
    exfiltration_confirmed: {
      type: "final",
    },
  },
});

const sessions = new Map<string, AnyActorRef>();

function classifyEvent(call: CallEvent): string | null {
  const { toolName, args } = call;

  const pathArg = typeof args["path"] === "string" ? args["path"] : "";
  const filePathArg = typeof args["filePath"] === "string" ? args["filePath"] : "";
  const sensitivePath = pathArg + filePathArg;

  if (toolName.includes("read") && (sensitivePath.includes("/etc") || sensitivePath.includes("passwd") || sensitivePath.includes("shadow")))
    return "READ_SENSITIVE";
  if (toolName.includes("shell") || toolName.includes("exec") || toolName === "bash" || toolName === "sh")
    return "SHELL_EXEC";
  if (toolName.includes("write") && (sensitivePath.includes(".ssh") || sensitivePath.includes("authorized_keys")))
    return "WRITE_SSH";
  if (toolName.includes("http") || toolName.includes("fetch") || toolName.includes("request") || toolName.includes("curl"))
    return "NETWORK_CALL";
  if (toolName.includes("read") && typeof args["size"] === "number" && args["size"] > 1000000)
    return "LARGE_FILE_READ";
  if (toolName.includes("write") && (sensitivePath.includes("/etc") || sensitivePath.includes("/System")))
    return "WRITE_SYSTEM";
  if (toolName.includes("exec") || toolName.includes("spawn") || toolName.includes("fork"))
    return "EXEC_PROCESS";

  return null;
}

export function trackCall(call: CallEvent): { alert: boolean; state: string } {
  let sessionService = sessions.get(call.sessionId);
  if (!sessionService) {
    sessionService = interpret(attackChainMachine).start();
    sessions.set(call.sessionId, sessionService);
  }

  const eventType = classifyEvent(call);
  if (eventType) {
    sessionService.send({ type: eventType });
  }

  const snapshot = sessionService.getSnapshot();
  const currentState = String(snapshot.value);
  const alert = currentState === "exfiltration_confirmed";

  if (alert && eventType === "LARGE_FILE_READ") {
    console.error(`[mcp-seatbelt:attack-chain] Detected: idle→recon→exfil for session ${call.sessionId}`);
  }

  return { alert, state: currentState };
}

export function cleanupSession(sessionId: string): void {
  const svc = sessions.get(sessionId);
  if (svc) {
    svc.stop();
  }
  sessions.delete(sessionId);
}

export function getSessionCount(): number {
  return sessions.size;
}

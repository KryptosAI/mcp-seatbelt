export { ProxyServer, StdioClient, HttpClient, SseClient, StreamableHttpClient } from "./server.js";
export type { RegisteredServer } from "./server.js";
export type { ProxyServerOptions } from "../types.js";
export {
  interceptRequest,
  filterToolsListResponse,
  filterResourcesListResponse,
  filterPromptsListResponse,
  scanResponse,
} from "./intercept.js";
export type { MCPRequest, MCPResponse, RedactionLog, ScanResult } from "./intercept.js";
export { injectHoneytokens, detectHoneytokenAccess, getDetectionLog, getPlantedCount, getDetectedCount } from "../security/honeytokens.js";
export type { Honeytoken, InjectOptions } from "../security/honeytokens.js";
export { startSessionCapture, captureRequest, captureResponse, saveSession, stopSessionCapture } from "../security/forensics.js";
export type { ForensicEvent, SessionCapture } from "../security/forensics.js";

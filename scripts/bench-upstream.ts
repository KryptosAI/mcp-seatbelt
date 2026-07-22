/**
 * Instant-response MCP upstream server used by the benchmark harness.
 * Responds immediately to initialize, tools/list, and tools/call so that
 * measurements reflect proxy + policy overhead rather than upstream latency.
 */
import http from "node:http";

function arg(name: string, fallback: string): string {
  const idx = process.argv.indexOf(`--${name}`);
  return idx >= 0 && process.argv[idx + 1] ? process.argv[idx + 1] : fallback;
}

const port = parseInt(arg("port", "19577"), 10);

const TOOL = {
  name: "bench-tool",
  description: "Instant benchmark tool that returns a fixed response",
  inputSchema: {
    type: "object",
    properties: { benchmark: { type: "boolean" } },
    additionalProperties: true,
  },
};

const server = http.createServer((req, res) => {
  if (req.method !== "POST") {
    res.writeHead(405, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "method not allowed" }));
    return;
  }

  const chunks: Buffer[] = [];
  req.on("data", (c: Buffer) => chunks.push(c));
  req.on("end", () => {
    let id: unknown = null;
    let method = "";
    try {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
        id?: unknown;
        method?: string;
      };
      id = body.id ?? null;
      method = body.method ?? "";
    } catch {
      // fall through to method-not-found
    }

    let result: unknown;
    let error: unknown;
    switch (method) {
      case "initialize":
        result = {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "bench-upstream", version: "0.0.0" },
        };
        break;
      case "tools/list":
        result = { tools: [TOOL] };
        break;
      case "tools/call":
        result = { content: [{ type: "text", text: "ok" }] };
        break;
      default:
        error = { code: -32601, message: `Method not found: ${method}` };
    }

    const payload = JSON.stringify({
      jsonrpc: "2.0",
      ...(error ? { error } : { result }),
      id,
    });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(payload);
  });
});

server.listen(port, () => {
  console.log(`READY ${port}`);
});

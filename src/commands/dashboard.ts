import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import chalk from "chalk";
import { parsePolicy } from "../policy/yaml.js";
import { PolicyEngine } from "../policy/engine.js";

interface DashboardStats {
  status: "running" | "stopped";
  totalRequests: number;
  blocked: number;
  allowed: number;
  warned: number;
  uptime: number;
  startTime: string;
  connectedClients: string[];
  recentBlockedCalls: { tool: string; server: string; reason: string; time: string; args?: string; owasp?: string[]; compliance?: string[] }[];
  latency?: { p50: number; p95: number; p99: number; avg: number; max: number; count: number; throughput: number };
}

let currentStats: DashboardStats = {
  status: "stopped",
  totalRequests: 0,
  blocked: 0,
  allowed: 0,
  warned: 0,
  uptime: 0,
  startTime: new Date().toISOString(),
  connectedClients: [],
  recentBlockedCalls: [],
};

export function updateDashboardStats(stats: Partial<DashboardStats>): void {
  Object.assign(currentStats, stats);
  currentStats.uptime = Date.now() - new Date(currentStats.startTime).getTime();
}

export function addBlockedCall(tool: string, server: string, reason: string, args?: string, owasp?: string[], compliance?: string[]): void {
  currentStats.recentBlockedCalls.unshift({
    tool,
    server,
    reason,
    time: new Date().toISOString(),
    args,
    owasp,
    compliance,
  });
  if (currentStats.recentBlockedCalls.length > 50) {
    currentStats.recentBlockedCalls = currentStats.recentBlockedCalls.slice(0, 50);
  }
}

function renderDashboardPage(): string {
  const uptimeSeconds = Math.floor(currentStats.uptime / 1000);
  const hours = Math.floor(uptimeSeconds / 3600);
  const minutes = Math.floor((uptimeSeconds % 3600) / 60);
  const seconds = uptimeSeconds % 60;

  const statusColor = currentStats.status === "running" ? "#22c55e" : "#ef4444";
  const statusText = currentStats.status.toUpperCase();

  const blockRate = currentStats.totalRequests > 0
    ? ((currentStats.blocked / currentStats.totalRequests) * 100).toFixed(1)
    : "0.0";

  const recentBlocksHtml = currentStats.recentBlockedCalls.length > 0
    ? currentStats.recentBlockedCalls
      .slice(0, 20)
      .map(
        (call) => {
          const owaspTags = call.owasp && call.owasp.length > 0
            ? call.owasp.map((o) => `<span class="badge badge-owasp">${escapeHtml(o)}</span>`).join(" ")
            : `<span class="dim">—</span>`;
          const complianceTags = call.compliance && call.compliance.length > 0
            ? call.compliance.map((c) => `<span class="badge badge-compliance">${escapeHtml(c)}</span>`).join(" ")
            : `<span class="dim">—</span>`;
          return `
    <tr>
      <td class="mono">${escapeHtml(call.tool)}</td>
      <td>${escapeHtml(call.server)}</td>
      <td class="dim">${escapeHtml(call.reason.slice(0, 80))}</td>
      <td>${owaspTags}</td>
      <td>${complianceTags}</td>
      <td class="dim">${new Date(call.time).toLocaleTimeString()}</td>
      <td><button class="simulate-btn" onclick="simulateBlock('${escapeHtml(call.tool)}', '${escapeHtml(call.server)}')" title="Simulate this call">▶</button></td>
    </tr>`;
        },
      )
      .join("\n")
    : `<tr><td colspan="7" class="dim" style="text-align:center">No blocked calls recorded</td></tr>`;

  const clientsHtml = currentStats.connectedClients.length > 0
    ? currentStats.connectedClients
      .map((c) => `<span class="badge">${escapeHtml(c)}</span>`)
      .join(" ")
    : `<span class="dim">No clients connected</span>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>mcp-seatbelt Dashboard</title>
<style>
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --text-dim: #8b949e;
    --accent: #58a6ff;
    --green: #22c55e;
    --red: #ef4444;
    --yellow: #f59e0b;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    padding: 0;
  }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  .header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 16px 24px; background: var(--surface); border-bottom: 1px solid var(--border);
  }
  .title { font-size: 20px; font-weight: 700; }
  .title span { color: var(--accent); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 24px 0; }
  .card {
    background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px;
  }
  .card-label { font-size: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
  .card-value { font-size: 28px; font-weight: 700; }
  .card-value.green { color: var(--green); }
  .card-value.red { color: var(--red); }
  .card-value.yellow { color: var(--yellow); }
  .card-value.blue { color: var(--accent); }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; }
  th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
  th { font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-dim); }
  .mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 13px; }
  .dim { color: var(--text-dim); font-size: 13px; }
  .badge {
    display: inline-block; background: var(--surface); border: 1px solid var(--border);
    padding: 4px 10px; border-radius: 12px; font-size: 12px; margin: 2px;
  }
  .badge-owasp { background: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.3); color: #fca5a5; }
  .badge-compliance { background: rgba(88, 166, 255, 0.15); border-color: rgba(88, 166, 255, 0.3); color: #58a6ff; }
  .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 8px; }
  .status-dot.running { background: var(--green); }
  .status-dot.stopped { background: var(--red); }
  .section-title { font-size: 16px; font-weight: 600; margin: 24px 0 12px; }
  .bar-container { height: 8px; background: var(--border); border-radius: 4px; margin: 8px 0 16px; overflow: hidden; display: flex; }
  .bar-allowed { background: var(--green); height: 100%; }
  .bar-warned { background: var(--yellow); height: 100%; }
  .bar-blocked { background: var(--red); height: 100%; }
  footer { text-align: center; padding: 24px; color: var(--text-dim); font-size: 12px; border-top: 1px solid var(--border); margin-top: 32px; }
  .refresh-indicator { font-size: 11px; color: var(--text-dim); margin-left: 12px; }
  .simulate-btn {
    background: var(--surface); border: 1px solid var(--border); color: var(--accent);
    padding: 2px 8px; border-radius: 4px; cursor: pointer; font-size: 12px;
  }
  .simulate-btn:hover { background: var(--border); }
  #simulate-modal {
    display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(0,0,0,0.6); z-index: 1000; align-items: center; justify-content: center;
  }
  #simulate-modal.open { display: flex; }
  #simulate-modal .modal-content {
    background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    padding: 24px; max-width: 600px; width: 90%; max-height: 80vh; overflow-y: auto;
  }
  #simulate-modal .modal-close {
    float: right; background: none; border: none; color: var(--text-dim);
    font-size: 20px; cursor: pointer;
  }
  #simulate-modal .simulate-result { margin-top: 16px; padding: 12px; background: var(--bg); border-radius: 4px; font-size: 13px; }
  #simulate-modal .simulate-result .rule-line { margin: 4px 0; }
  #simulate-modal .simulate-result .rule-deny { color: var(--red); }
  #simulate-modal .simulate-result .rule-allow { color: var(--green); }
  #simulate-modal .simulate-result .rule-warn { color: var(--yellow); }
  #simulate-modal .simulate-result .rule-redact { color: #c084fc; }
  #simulate-modal .simulate-actions { margin-top: 16px; }
  #simulate-modal .simulate-actions button {
    background: var(--accent); border: none; color: var(--bg);
    padding: 8px 16px; border-radius: 4px; cursor: pointer; font-weight: 600;
    margin-right: 8px;
  }
</style>
</head>
<body>
<div class="header">
  <div class="title">🔐 <span>mcp-seatbelt</span> Dashboard</div>
  <div>
    <span class="status-dot ${currentStats.status === "running" ? "running" : "stopped"}"></span>
    <span style="color:${statusColor};font-weight:600">${statusText}</span>
    <span class="refresh-indicator" id="refresh-msg">auto-refresh 5s</span>
  </div>
</div>
<div class="container">
  <div class="grid">
    <div class="card">
      <div class="card-label">Total Requests</div>
      <div class="card-value blue">${currentStats.totalRequests.toLocaleString()}</div>
    </div>
    <div class="card">
      <div class="card-label">Blocked</div>
      <div class="card-value red">${currentStats.blocked.toLocaleString()}</div>
    </div>
    <div class="card">
      <div class="card-label">Allowed</div>
      <div class="card-value green">${currentStats.allowed.toLocaleString()}</div>
    </div>
    <div class="card">
      <div class="card-label">Warned</div>
      <div class="card-value yellow">${currentStats.warned.toLocaleString()}</div>
    </div>
    <div class="card">
      <div class="card-label">Block Rate</div>
      <div class="card-value">${blockRate}%</div>
    </div>
    <div class="card">
      <div class="card-label">Uptime</div>
      <div class="card-value">${hours}h ${minutes}m ${seconds}s</div>
    </div>
    <div class="card">
      <div class="card-label">Throughput</div>
      <div class="card-value blue">${currentStats.latency?.throughput ?? 0} req/s</div>
    </div>
    <div class="card">
      <div class="card-label">P50 Latency</div>
      <div class="card-value ${(currentStats.latency?.p50 ?? 0) > 50 ? 'yellow' : 'green'}">${currentStats.latency?.p50 ?? 0}ms</div>
    </div>
    <div class="card">
      <div class="card-label">P95 Latency</div>
      <div class="card-value ${(currentStats.latency?.p95 ?? 0) > 100 ? 'red' : (currentStats.latency?.p95 ?? 0) > 50 ? 'yellow' : 'green'}">${currentStats.latency?.p95 ?? 0}ms</div>
    </div>
    <div class="card">
      <div class="card-label">P99 Latency</div>
      <div class="card-value ${(currentStats.latency?.p99 ?? 0) > 200 ? 'red' : (currentStats.latency?.p99 ?? 0) > 50 ? 'yellow' : 'green'}">${currentStats.latency?.p99 ?? 0}ms</div>
    </div>
  </div>

  <div class="bar-container">
    ${currentStats.totalRequests > 0 ? `
    <div class="bar-allowed" style="width: ${((currentStats.allowed / currentStats.totalRequests) * 100).toFixed(1)}%"></div>
    <div class="bar-warned" style="width: ${((currentStats.warned / currentStats.totalRequests) * 100).toFixed(1)}%"></div>
    <div class="bar-blocked" style="width: ${((currentStats.blocked / currentStats.totalRequests) * 100).toFixed(1)}%"></div>
    ` : ''}
  </div>

  <div class="section-title">Connected Clients</div>
  <div>${clientsHtml}</div>

  <div class="section-title">Recent Blocked Calls</div>
  <table>
    <thead>
      <tr>
        <th>Tool</th>
        <th>Server</th>
        <th>Reason</th>
        <th>OWASP</th>
        <th>Compliance</th>
        <th>Time</th>
        <th>Sim</th>
      </tr>
    </thead>
    <tbody>
      ${recentBlocksHtml}
    </tbody>
  </table>
</div>
<footer>
  mcp-seatbelt dashboard · <span id="poll-time"></span> · <a href="/api/stats" style="color:var(--accent)">API</a>
</footer>
<div id="simulate-modal">
  <div class="modal-content">
    <button class="modal-close" onclick="document.getElementById('simulate-modal').classList.remove('open')">&times;</button>
    <h3 style="margin:0 0 16px">Policy Simulation</h3>
    <div><strong>Tool:</strong> <span id="sim-tool"></span></div>
    <div style="margin-top:4px"><strong>Server:</strong> <span id="sim-server"></span></div>
    <div id="simulate-result" class="simulate-result" style="display:none"></div>
    <div class="simulate-actions">
      <button onclick="runSimulation()">Run Simulation</button>
      <button onclick="document.getElementById('simulate-modal').classList.remove('open')" style="background:var(--border);color:var(--text)">Close</button>
    </div>
  </div>
</div>
<script>
  function formatTime() { return new Date().toLocaleTimeString(); }
  document.getElementById('poll-time').textContent = 'last updated ' + formatTime();

  let currentSimTool = '';
  let currentSimServer = '';

  function simulateBlock(tool, server) {
    currentSimTool = tool;
    currentSimServer = server;
    document.getElementById('sim-tool').innerHTML = '<code>' + tool + '</code>';
    document.getElementById('sim-server').textContent = server;
    document.getElementById('simulate-result').style.display = 'none';
    document.getElementById('simulate-modal').classList.add('open');
  }

  async function runSimulation() {
    const resultEl = document.getElementById('simulate-result');
    resultEl.style.display = 'block';
    resultEl.innerHTML = '<em>Running simulation...</em>';
    try {
      const resp = await fetch('/' + encodeURIComponent(currentSimServer) + '/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool: currentSimTool, description: '', args: {} })
      });
      if (resp.ok) {
        const data = await resp.json();
        let html = '<strong>Action:</strong> <span class="rule-' + data.action + '">' + data.action.toUpperCase() + '</span><br>';
        if (data.reasons && data.reasons.length > 0) {
          html += '<div style="margin-top:8px"><strong>Reasons:</strong></div>';
          data.reasons.forEach(function(r) { html += '<div class="rule-line">' + r + '</div>'; });
        }
        if (data.rules && data.rules.length > 0) {
          html += '<div style="margin-top:8px"><strong>Rules Evaluated:</strong></div>';
          data.rules.forEach(function(r) {
            var cls = 'rule-' + r.action;
            html += '<div class="rule-line ' + cls + '">[' + r.id + '] ' + r.action.toUpperCase() + ' — ' + r.description;
            if (r.hasTimeWindow && !r.matched) html += ' (outside time window)';
            html += '</div>';
          });
        }
        resultEl.innerHTML = html;
      } else {
        resultEl.innerHTML = '<span style="color:var(--red)">Simulation failed: explain endpoint not available. Start the proxy first.</span>';
      }
    } catch(e) {
      resultEl.innerHTML = '<span style="color:var(--red)">Error: explain endpoint not reachable. Make sure the proxy server is running.</span>';
    }
  }

  setInterval(() => {
    fetch('/api/stats')
      .then(r => r.json())
      .then(data => {
        if (JSON.stringify(data) !== sessionStorage.getItem('lastStats')) {
          sessionStorage.setItem('lastStats', JSON.stringify(data));
          location.reload();
        }
        document.getElementById('refresh-msg').textContent = 'auto-refresh 5s · checked ' + formatTime();
      })
      .catch(() => {
        document.getElementById('refresh-msg').textContent = 'polling... ' + formatTime();
      });
  }, 5000);
</script>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export interface DashboardOptions {
  port: string;
  proxyUrl?: string;
  policyPath?: string;
}

let dashboardEngine: PolicyEngine | null = null;

export function setDashboardPolicy(policyPath: string): void {
  if (existsSync(policyPath)) {
    const raw = readFileSync(policyPath, "utf-8");
    const config = parsePolicy(raw);
    dashboardEngine = new PolicyEngine(config);
  }
}

export async function dashboardCommand(opts: DashboardOptions): Promise<void> {
  const port = parseInt(opts.port, 10) || 9421;

  if (opts.policyPath) {
    setDashboardPolicy(opts.policyPath);
  }

  currentStats.status = "running";
  currentStats.startTime = new Date().toISOString();
  currentStats.connectedClients = ["proxy"];

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    if (req.url === "/api/stats" || req.url?.startsWith("/api/stats")) {
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      });
      res.end(JSON.stringify(currentStats));
      return;
    }

    if (req.url === "/api/events" || req.url?.startsWith("/api/events")) {
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Access-Control-Allow-Origin": "*",
      });

      const sendEvent = () => {
        res.write(`data: ${JSON.stringify(currentStats)}\n\n`);
      };

      sendEvent();
      const interval = setInterval(sendEvent, 2000);

      req.on("close", () => {
        clearInterval(interval);
      });
      return;
    }

    if (req.method === "POST" && req.url && req.url.endsWith("/explain")) {
      const serverName = req.url.replace(/^\/+/, "").replace(/\/explain$/, "");
      let body = "";
      req.on("data", (chunk: Buffer) => {
        body += chunk.toString();
      });
      req.on("end", () => {
        try {
          const data = JSON.parse(body || "{}") as Record<string, any>;
          const tool = data.tool || data.name || serverName;
          const description = data.description || "";
          const args = data.args || data.arguments || {};

          const engine = dashboardEngine;

          if (!engine) {
            res.writeHead(200, {
              "Content-Type": "application/json",
              "Access-Control-Allow-Origin": "*",
            });
            res.end(JSON.stringify({
              server: serverName,
              tool,
              description,
              action: "error",
              reasons: ["No policy loaded in dashboard. Pass --policy-path to load a policy."],
              rules: [],
            }));
            return;
          }

          const evalResult = engine.evaluate(tool, description, args, {
            client: serverName,
            requestCount: 1,
          });

          const rulesEvaluated = engine.getConfig().rules
            .filter((r) => r.action !== "redact")
            .map((rule) => {
              const wasApplied = evalResult.reasons.some((r) =>
                r.startsWith(`[${rule.id}]`),
              );
              return {
                id: rule.id,
                description: rule.description,
                action: rule.action,
                target: rule.target,
                match: rule.match,
                matched: wasApplied,
                hasTimeWindow: !!rule.timeWindow,
              };
            });

          res.writeHead(200, {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          });
          res.end(JSON.stringify({
            server: serverName,
            tool,
            description,
            args,
            action: evalResult.action,
            reasons: evalResult.reasons,
            redactedKeys: evalResult.redactedKeys,
            rules: rulesEvaluated,
          }));
        } catch (err) {
          res.writeHead(400, {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          });
          res.end(JSON.stringify({ error: "Invalid request body" }));
        }
      });
      return;
    }

    if (req.url === "/" || req.url === "/index.html") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderDashboardPage());
      return;
    }

    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not Found");
  });

  return new Promise((resolve) => {
    server.listen(port, () => {
      console.log(chalk.cyan("\n📊 mcp-seatbelt Dashboard"));
      console.log(chalk.dim(`Serving at:`), chalk.green(`http://localhost:${port}`));
      console.log(chalk.dim("Press Ctrl+C to stop.\n"));
      resolve();
    });

    const shutdown = () => {
      currentStats.status = "stopped";
      console.log(chalk.dim("\nShutting down dashboard..."));
      server.close(() => {
        process.exit(0);
      });
    };

    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  });
}

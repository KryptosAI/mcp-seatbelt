import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import chalk from "chalk";

interface DashboardStats {
  status: "running" | "stopped";
  totalRequests: number;
  blocked: number;
  allowed: number;
  warned: number;
  uptime: number;
  startTime: string;
  connectedClients: string[];
  recentBlockedCalls: { tool: string; server: string; reason: string; time: string }[];
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

export function addBlockedCall(tool: string, server: string, reason: string): void {
  currentStats.recentBlockedCalls.unshift({
    tool,
    server,
    reason,
    time: new Date().toISOString(),
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
        (call) => `
    <tr>
      <td class="mono">${escapeHtml(call.tool)}</td>
      <td>${escapeHtml(call.server)}</td>
      <td class="dim">${escapeHtml(call.reason.slice(0, 80))}</td>
      <td class="dim">${new Date(call.time).toLocaleTimeString()}</td>
    </tr>`,
      )
      .join("\n")
    : `<tr><td colspan="4" class="dim" style="text-align:center">No blocked calls recorded</td></tr>`;

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
        <th>Time</th>
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
<script>
  function formatTime() { return new Date().toLocaleTimeString(); }
  document.getElementById('poll-time').textContent = 'last updated ' + formatTime();
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
}

export async function dashboardCommand(opts: DashboardOptions): Promise<void> {
  const port = parseInt(opts.port, 10) || 9421;

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

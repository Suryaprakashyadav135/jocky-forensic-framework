const OFFLINE_HTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>JOCKY Command Center</title>
<meta http-equiv="refresh" content="10">
<style>
  body {
    background: #0a0e1a; color: #c9d1d9;
    font-family: 'SF Mono', 'Consolas', monospace;
    padding: 40px 20px; margin: 0; min-height: 100vh;
  }
  .wrap { max-width: 620px; margin: 0 auto; }
  h1 {
    color: #58a6ff; font-size: 20px;
    border-bottom: 1px solid #21262d;
    padding-bottom: 12px; margin-bottom: 30px;
    letter-spacing: 0.5px;
  }
  .panel {
    background: #0d1117; border: 1px solid #21262d;
    border-radius: 6px; padding: 26px;
  }
  .status {
    display: flex; align-items: center; gap: 10px;
    color: #d29922; font-weight: bold; font-size: 13px;
    letter-spacing: 0.5px; margin-bottom: 16px;
  }
  .dot {
    width: 12px; height: 12px; border-radius: 50%;
    background: #d29922; box-shadow: 0 0 10px #d29922;
    animation: pulse 1.6s ease-in-out infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
  }
  p { line-height: 1.7; font-size: 13px; margin-bottom: 12px; }
  .dim { color: #8b949e; }
  ol { margin-left: 20px; margin-bottom: 16px; font-size: 13px;
       line-height: 1.8; color: #8b949e; }
  code {
    display: inline-block; background: #161b22;
    border: 1px solid #21262d; border-radius: 3px;
    padding: 3px 8px; color: #3fb950; font-size: 12px;
    font-family: inherit; margin-top: 4px;
  }
  .footer {
    color: #6e7681; font-size: 11px;
    margin-top: 22px; padding-top: 16px;
    border-top: 1px solid #21262d; text-align: center;
  }
</style>
</head>
<body>
<div class="wrap">
  <h1>JOCKY &mdash; Forensic Command Center</h1>
  <div class="panel">
    <div class="status">
      <span class="dot"></span>
      NO END DEVICES CONNECTED
    </div>
    <p>End devices are currently offline. There are no active agents
       reporting to this command center.</p>
    <p class="dim">End devices will appear here automatically once:</p>
    <ol>
      <li>The backend server is started</li>
      <li>Agents are set up on the target endpoints</li>
      <li>Agents begin sending findings to this dashboard</li>
    </ol>
    <p class="dim">To start the backend:</p>
    <code>python3 src/mock_cdn_server.py</code>
    <p class="dim" style="margin-top:14px;">To connect an agent:</p>
    <code>python3 src/jocky_agent.py</code>
  </div>
  <div class="footer">
    This page refreshes every 10 seconds.<br>
    The live dashboard will load automatically once end devices connect.
  </div>
</div>
</body>
</html>`;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const TUNNEL_URL = "https://c2.jocky.dpdns.org";
    const backendUrl = new URL(url.pathname + url.search, TUNNEL_URL);
    const newRequest = new Request(backendUrl.toString(), {
      method: request.method,
      headers: request.headers,
      body: request.method === "GET" || request.method === "HEAD"
        ? undefined
        : request.body,
      redirect: "manual",
    });

    try {
      const response = await fetch(newRequest);
      if (response.status === 502 || response.status === 503 || response.status === 504) {
        const accept = request.headers.get("Accept") || "";
        if (accept.includes("text/html")) {
          return new Response(OFFLINE_HTML, {
            status: 200,
            headers: { "Content-Type": "text/html;charset=UTF-8" },
          });
        }
        return response;
      }
      return response;
    } catch (err) {
      const accept = request.headers.get("Accept") || "";
      if (accept.includes("text/html")) {
        return new Response(OFFLINE_HTML, {
          status: 200,
          headers: { "Content-Type": "text/html;charset=UTF-8" },
        });
      }
      return new Response(
        JSON.stringify({ error: "backend unreachable" }),
        { status: 502, headers: { "Content-Type": "application/json" } }
      );
    }
  },
};

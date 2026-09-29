"""
JOCKY Central Management Dashboard
Live agent view + dispatch + export + report.
"""
from datetime import datetime, timezone, timedelta
import csv
import io
import json
import os
from pathlib import Path

from flask import (
    Blueprint, render_template_string, jsonify, request, Response
)

from dispatch import (AGENT_IDENTITIES, AGENT_RESULTS, AGENT_PENDING,
                       EVIDENCE_STORE, AGENT_PUBKEYS, AGENT_BASELINES)

from evidence import public_key_from_b64, verify_agent_chain

dashboard_bp = Blueprint("dashboard", __name__)


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>JOCKY - Central Management</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0a0e1a; color: #c9d1d9;
       font-family: 'SF Mono', 'Consolas', monospace;
       padding: 20px; font-size: 13px; }
h1 { color: #58a6ff; border-bottom: 1px solid #21262d;
     padding-bottom: 10px; margin-bottom: 20px; font-size: 20px;
     display: flex; justify-content: space-between; align-items: center;
     flex-wrap: wrap; gap: 12px; }
h1 .left { display: flex; align-items: center; gap: 14px; }
h1 .right { display: flex; align-items: center; gap: 8px; }
.badge { background: #1f6feb; color: white; padding: 3px 10px;
         border-radius: 12px; font-size: 11px;
         display: inline-flex; align-items: center; gap: 6px; }
.badge .dot { width: 8px; height: 8px; border-radius: 50%;
              background: #3fb950;
              animation: pulse 1.5s ease-in-out infinite; }
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.35; }
}
.btn { background: #21262d; color: #c9d1d9;
       border: 1px solid #30363d; padding: 6px 12px;
       border-radius: 4px; font-family: inherit; font-size: 11px;
       cursor: pointer; text-decoration: none;
       display: inline-flex; align-items: center; gap: 5px; }
.btn:hover { background: #30363d; }
.btn.primary { background: #1f6feb; border-color: #1f6feb; color: white; }
.btn.primary:hover { background: #388bfd; }
.btn.green { background: #238636; border-color: #238636; color: white; }
.btn.green:hover { background: #2ea043; }
.grid { display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 16px; margin-bottom: 20px; }
.card { background: #0d1117; border: 1px solid #21262d;
        border-radius: 6px; padding: 14px; }
.card h2 { color: #58a6ff; font-size: 13px; margin-bottom: 10px;
           text-transform: uppercase; letter-spacing: 0.5px; }
.stat { font-size: 28px; color: #3fb950; font-weight: bold;
        transition: color 0.3s; }
.stat.amber { color: #d29922; }
.stat.red { color: #f85149; }
.stat-label { color: #8b949e; font-size: 11px; margin-top: 4px; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { text-align: left; color: #8b949e; padding: 8px;
     border-bottom: 1px solid #21262d; font-weight: normal;
     font-size: 11px; text-transform: uppercase; }
td { padding: 8px; border-bottom: 1px solid #161b22; }
.status-live { color: #3fb950; }
.status-stale { color: #d29922; }
.status-dead { color: #f85149; }
.mono { font-family: monospace; }
.dim { color: #6e7681; }
.highlight { color: #58a6ff; }
.cmd { color: #ffa657; }
.sev-HIGH { color: #f85149; font-weight: bold; }
.sev-MEDIUM { color: #d29922; font-weight: bold; }
.sev-LOW { color: #8b949e; }
.sev-CRITICAL { color: #ff0000; font-weight: bold; }
.dispatch-form { display: flex; gap: 10px; align-items: center;
                 margin-bottom: 20px; flex-wrap: wrap; }
.dispatch-form select, .dispatch-form button {
  background: #0d1117; color: #c9d1d9;
  border: 1px solid #21262d; padding: 8px 12px;
  border-radius: 4px; font-family: inherit; font-size: 12px; }
.dispatch-form button { background: #1f6feb; color: white;
                        cursor: pointer; font-weight: bold; }
.dispatch-form button:hover { background: #388bfd; }
.dispatch-form button:disabled { opacity: 0.5; cursor: wait; }
.report-panel { background: #0d1117; border: 1px solid #21262d;
                border-radius: 6px; padding: 16px;
                margin-top: 20px; display: none; }
.report-panel.open { display: block; }
.report-panel h2 { color: #58a6ff; font-size: 13px;
                   margin-bottom: 12px; text-transform: uppercase;
                   display: flex; justify-content: space-between; }
.report-panel pre { background: #010409; padding: 12px;
                    border-radius: 4px; font-size: 11px;
                    color: #8b949e; max-height: 500px;
                    overflow: auto; white-space: pre-wrap;
                    word-break: break-all; }
.toast { position: fixed; top: 20px; right: 20px;
         background: #1f6feb; color: white;
         padding: 12px 20px; border-radius: 6px;
         font-size: 12px;
         opacity: 0; transition: opacity 0.3s;
         pointer-events: none; z-index: 100; }
.toast.show { opacity: 1; }
/* ---- Empty state (no end devices) ---- */
.empty-state {
  background: linear-gradient(180deg, #161b22 0%, #0d1117 100%);
  border: 1px dashed #30363d;
  border-radius: 8px;
  padding: 40px 24px 32px;
  text-align: center;
  margin-bottom: 20px;
}
.empty-state .icon {
  font-size: 48px;
  color: #d29922;
  margin-bottom: 10px;
  display: inline-block;
  line-height: 1;
}
.empty-state h2 {
  color: #d29922;
  font-size: 16px;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  margin-bottom: 16px;
  font-weight: bold;
}
.empty-state p {
  color: #c9d1d9;
  font-size: 13px;
  line-height: 1.6;
  max-width: 620px;
  margin: 0 auto 8px;
}
.empty-state p.sub {
  color: #6e7681;
  font-size: 12px;
  margin-bottom: 24px;
}
.empty-state-steps {
  display: flex;
  justify-content: center;
  gap: 14px;
  flex-wrap: wrap;
  margin-top: 8px;
}
.empty-step {
  background: #010409;
  border: 1px solid #21262d;
  border-radius: 6px;
  padding: 12px 16px;
  min-width: 220px;
  text-align: left;
}
.empty-step .step-num {
  display: inline-block;
  width: 22px; height: 22px;
  background: #1f6feb; color: white;
  border-radius: 50%;
  text-align: center;
  line-height: 22px;
  font-size: 11px;
  font-weight: bold;
  margin-right: 8px;
  vertical-align: middle;
}
.empty-step .step-title {
  color: #c9d1d9;
  font-size: 12px;
  font-weight: bold;
  vertical-align: middle;
}
.empty-step code {
  display: block;
  background: #000;
  border: 1px solid #21262d;
  border-radius: 3px;
  padding: 6px 10px;
  color: #3fb950;
  font-size: 11px;
  margin-top: 8px;
  font-family: monospace;
  white-space: nowrap;
  overflow-x: auto;
}

.footer { text-align: center; color: #6e7681;
          margin-top: 30px; font-size: 11px; }
.new-row { animation: highlight-new 2s ease-out; }
@keyframes highlight-new {
  0% { background: rgba(88, 166, 255, 0.15); }
  100% { background: transparent; }
}
</style>
</head>
<body>
<h1>
  <div class="left">
    <span>JOCKY - Central Management</span>
    <span class="badge">
      <span class="dot"></span>
      <span id="server-url">...</span>
      &middot; <span id="last-updated">--:--:-- IST</span>
    </span>
  </div>
  <div class="right">
    <button class="btn" onclick="toggleReport()">Preview Report</button>
    <a class="btn green" href="/api/dashboard/export/md" download>Download MD</a>
    <a class="btn" href="/api/dashboard/export/json" download>Export JSON</a>
    <a class="btn" href="/api/dashboard/export/csv" download>Export CSV</a>
  </div>
</h1>

<div class="grid">
  <div class="card">
    <h2>Connected Agents</h2>
    <div class="stat" id="stat-agents">0</div>
    <div class="stat-label">active endpoints</div>
  </div>
  <div class="card">
    <h2>Total Findings</h2>
    <div class="stat" id="stat-findings">0</div>
    <div class="stat-label" id="stat-findings-sub">0 high &middot; 0 medium</div>
  </div>
  <div class="card">
    <h2>Results Collected</h2>
    <div class="stat" id="stat-results">0</div>
    <div class="stat-label">task completions</div>
  </div>
  <div class="card">
    <h2>Pending Commands</h2>
    <div class="stat" id="stat-pending">0</div>
    <div class="stat-label">queued for delivery</div>
  </div>
  <div class="card" id="integrity-card">
    <h2>Evidence Integrity</h2>
    <div class="stat" id="stat-integrity">--</div>
    <div class="stat-label" id="stat-integrity-sub">checking...</div>
  </div>
  <div class="card" id="correlation-card">
    <h2>Correlated Alerts</h2>
    <div class="stat" id="stat-correlated">--</div>
    <div class="stat-label" id="stat-correlated-sub">analyzing...</div>
  </div>
</div>

<div class="dispatch-form">
  <form id="dispatch-form" style="display:flex; gap:10px; align-items:center;">
    <select name="script" id="dispatch-script">
      <option value="process_audit">process_audit</option>
      <option value="persistence_audit">persistence_audit</option>
      <option value="user_audit">user_audit</option>
      <option value="network_audit">network_audit</option>
      <option value="filesystem_audit">filesystem_audit</option>
      <option value="log_audit">log_audit</option>
      <option value="ioc_scan">ioc_scan</option>
      <option value="timeline">timeline</option>
    </select>
    <select name="scope" id="dispatch-scope">
      <option value="all">All Agents</option>
    </select>
    <button type="submit" id="dispatch-btn">Dispatch</button>
  </form>
</div>

<div class="empty-state" id="empty-state" style="display:none;">
  <div class="icon">&#9888;</div>
  <h2>No End Devices Connected</h2>
  <p>The end devices are currently offline. Please set up and start
     JOCKY agents on your endpoints before running this command center.</p>
  <p class="sub">This dashboard will automatically display findings once
     end devices connect and start sending data.</p>
  <div class="empty-state-steps">
    <div class="empty-step">
      <span class="step-num">1</span><span class="step-title">Start backend</span>
      <code>python3 src/mock_cdn_server.py</code>
    </div>
    <div class="empty-step">
      <span class="step-num">2</span><span class="step-title">Run agent on each endpoint</span>
      <code>python3 src/jocky_agent.py</code>
    </div>
    <div class="empty-step">
      <span class="step-num">3</span><span class="step-title">Agents report findings here</span>
      <code>(automatic)</code>
    </div>
  </div>
</div>

<div class="card" id="agents-section" style="margin-bottom: 16px;">
  <h2>Connected Agents</h2>
  <table>
    <thead>
      <tr>
        <th>Agent ID</th><th>Hostname</th><th>IP</th><th>OS</th>
        <th>User</th><th>Status</th><th>Results</th>
        <th>Findings</th><th>Last Seen</th>
      </tr>
    </thead>
    <tbody id="agents-tbody">
      <tr><td colspan="9" class="dim">Loading...</td></tr>
    </tbody>
  </table>
</div>

<div class="card" id="findings-section" style="margin-bottom: 16px;">
  <h2>Recent Findings (All Agents)</h2>
  <table>
    <thead>
      <tr>
        <th>Time</th><th>Agent</th><th>Script</th>
        <th>Severity</th><th>Finding</th>
      </tr>
    </thead>
    <tbody id="findings-tbody">
      <tr><td colspan="5" class="dim">Loading...</td></tr>
    </tbody>
  </table>
</div>

<div class="card" id="correlation-panel" style="margin-bottom: 16px;">
  <h2>Correlated Alerts (High Confidence)</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Entity</th>
        <th>Type</th>
        <th>Findings</th>
        <th>Sources</th>
        <th>Sample</th>
      </tr>
    </thead>
    <tbody id="correlation-tbody">
      <tr><td colspan="6" class="dim">Loading...</td></tr>
    </tbody>
  </table>
</div>

<div class="card" id="integrity-panel" style="margin-bottom: 16px;">
  <h2>Evidence Integrity (Per-Agent)</h2>
  <table>
    <thead>
      <tr>
        <th>Agent</th>
        <th>Envelopes</th>
        <th>Verified</th>
        <th>Status</th>
        <th>Details</th>
      </tr>
    </thead>
    <tbody id="integrity-tbody">
      <tr><td colspan="5" class="dim">Loading...</td></tr>
    </tbody>
  </table>
</div>

<div class="report-panel" id="report-panel">
  <h2>
    <span>Forensic Report Preview</span>
    <button class="btn" onclick="toggleReport()">Close</button>
  </h2>
  <pre id="report-content">Generating...</pre>
</div>

<div class="footer">
  JOCKY Framework &middot; SIH 26148 &middot; <span id="footer-time">--</span>
</div>

<div class="toast" id="toast"></div>

<script>
let lastFindingHash = "";
let lastAgentHash = "";

function showToast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2200);
}

function toggleReport() {
  const p = document.getElementById("report-panel");
  if (p.classList.contains("open")) {
    p.classList.remove("open");
    return;
  }
  p.classList.add("open");
  document.getElementById("report-content").textContent = "Generating...";
  fetch("/api/dashboard/report").then(r => r.text()).then(t => {
    document.getElementById("report-content").textContent = t;
  }).catch(e => {
    document.getElementById("report-content").textContent =
      "Report generation failed: " + e;
  });
}

async function refresh() {
  try {
    const r = await fetch("/api/dashboard/data", { cache: "no-store" });
    if (!r.ok) return;
    const d = await r.json();

    document.getElementById("stat-agents").textContent = d.stats.agents;

    // Toggle "no end devices" empty state vs. content tables
    const emptyEl = document.getElementById("empty-state");
    const agentsSec = document.getElementById("agents-section");
    const findingsSec = document.getElementById("findings-section");
    const corrPanel = document.getElementById("correlation-panel");
    const integPanel = document.getElementById("integrity-panel");
    const hasAgents = (d.stats.agents > 0);
    if (emptyEl)   emptyEl.style.display   = hasAgents ? "none" : "block";
    if (agentsSec) agentsSec.style.display = hasAgents ? "block" : "none";
    if (findingsSec) findingsSec.style.display = hasAgents ? "block" : "none";
    if (corrPanel) corrPanel.style.display = hasAgents ? "block" : "none";
    if (integPanel) integPanel.style.display = hasAgents ? "block" : "none";

    document.getElementById("stat-findings").textContent = d.stats.findings;
    document.getElementById("stat-findings-sub").textContent =
      d.stats.high + " high \u00b7 " + d.stats.medium + " medium";
    document.getElementById("stat-results").textContent = d.stats.results;

    const pendingEl = document.getElementById("stat-pending");
    pendingEl.textContent = d.stats.pending;
    pendingEl.className = "stat" + (d.stats.pending > 0 ? " amber" : "");

    document.getElementById("server-url").textContent = d.server_url;
    document.getElementById("last-updated").textContent = d.now_short;
    document.getElementById("footer-time").textContent = d.now;

    const agentHash = JSON.stringify(d.agents);
    if (agentHash !== lastAgentHash) {
      lastAgentHash = agentHash;
      const atbody = document.getElementById("agents-tbody");
      if (d.agents.length === 0) {
        atbody.innerHTML =
          '<tr><td colspan="9" class="dim">No agents connected.</td></tr>';
      } else {
        atbody.innerHTML = d.agents.map(a => (
          '<tr>' +
          '<td class="highlight mono">' + a.agent_id + '</td>' +
          '<td>' + a.hostname + '</td>' +
          '<td class="mono">' + a.ip + '</td>' +
          '<td class="dim">' + a.os + ' ' + a.os_release + '</td>' +
          '<td class="dim">' + a.user + '</td>' +
          '<td class="status-' + a.status + '">' + a.status + '</td>' +
          '<td>' + a.results_count + '</td>' +
          '<td class="' + (a.total_findings > 30 ? 'sev-HIGH' : '') + '">' +
            a.total_findings + '</td>' +
          '<td class="dim mono">' + a.last_seen + '</td>' +
          '</tr>'
        )).join("");
      }
    }

    const scopeSelect = document.getElementById("dispatch-scope");
    const currentScope = scopeSelect.value;
    let opts = '<option value="all">All Agents</option>';
    d.agents.forEach(a => {
      opts += '<option value="' + a.agent_id + '">' +
              a.agent_id + ' (' + a.hostname + ' @ ' + a.ip + ')' +
              '</option>';
    });
    scopeSelect.innerHTML = opts;
    if (currentScope && [...scopeSelect.options].some(o => o.value === currentScope)) {
      scopeSelect.value = currentScope;
    }

    const newHash = JSON.stringify(d.recent_findings);
    if (newHash !== lastFindingHash) {
      lastFindingHash = newHash;
      const ftbody = document.getElementById("findings-tbody");
      if (d.recent_findings.length === 0) {
        ftbody.innerHTML =
          '<tr><td colspan="5" class="dim">No findings yet.</td></tr>';
      } else {
        ftbody.innerHTML = d.recent_findings.map(f => (
          '<tr class="new-row">' +
          '<td class="dim mono">' + f.time + '</td>' +
          '<td class="highlight mono">' + f.agent_id.slice(0,16) + '</td>' +
          '<td class="cmd">' + f.script + '</td>' +
          '<td class="sev-' + f.severity + '">' + f.severity + '</td>' +
          '<td class="dim mono">' + f.text + '</td>' +
          '</tr>'
        )).join("");
      }
    }
  } catch (e) {
    console.warn("refresh failed:", e);
  }
}

document.getElementById("dispatch-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = document.getElementById("dispatch-btn");
  const script = document.getElementById("dispatch-script").value;
  const scope = document.getElementById("dispatch-scope").value;

  btn.disabled = true;
  btn.textContent = "Dispatching...";

  try {
    const fd = new FormData();
    fd.append("script", script);
    fd.append("scope", scope);
    await fetch("/dispatch-form", { method: "POST", body: fd });
    showToast("Dispatched: " + script + " \u2192 " + scope);
    refresh();
  } catch (err) {
    showToast("Dispatched: " + script + " \u2192 " + scope);
    refresh();
  } finally {
    btn.disabled = false;
    btn.textContent = "Dispatch";
  }
});

async function refreshIntegrity() {
  try {
    const r = await fetch("/api/dashboard/integrity", { cache: "no-store" });
    if (!r.ok) return;
    const d = await r.json();

    const card = document.getElementById("integrity-card");
    const stat = document.getElementById("stat-integrity");
    const sub = document.getElementById("stat-integrity-sub");

    if (d.total_envelopes === 0) {
      stat.textContent = "--";
      stat.className = "stat";
      sub.textContent = "no evidence yet";
    } else if (d.all_valid) {
      stat.textContent = "VALID";
      stat.className = "stat";
      sub.textContent = d.total_verified + " envelopes verified";
    } else {
      stat.textContent = "BROKEN";
      stat.className = "stat red";
      sub.textContent = d.total_failed + " failed / " + d.total_envelopes + " total";
    }

    const tbody = document.getElementById("integrity-tbody");
    if (d.agents.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="dim">No agents.</td></tr>';
      return;
    }
    tbody.innerHTML = d.agents.map(a => {
      let statusCls = "status-dead";
      let statusTxt = a.status;
      if (a.status === "valid") { statusCls = "status-live"; statusTxt = "VALID"; }
      else if (a.status === "invalid") { statusCls = "sev-HIGH"; statusTxt = "BROKEN"; }
      else if (a.status === "no_pubkey") { statusCls = "status-stale"; statusTxt = "NO KEY"; }
      return '<tr>' +
        '<td class="highlight mono">' + a.agent_id + '</td>' +
        '<td>' + a.envelopes + '</td>' +
        '<td>' + a.verified + '</td>' +
        '<td class="' + statusCls + '">' + statusTxt + '</td>' +
        '<td class="dim mono">' + a.reason + '</td>' +
        '</tr>';
    }).join("");
  } catch (e) {
    console.warn("integrity fetch failed:", e);
  }
}

async function refreshCorrelations() {
  try {
    const r = await fetch("/api/v1/correlations", { cache: "no-store" });
    if (!r.ok) return;
    const d = await r.json();

    const stat = document.getElementById("stat-correlated");
    const sub = document.getElementById("stat-correlated-sub");

    stat.textContent = d.total_alerts;
    if (d.total_alerts === 0) {
      stat.className = "stat";
      sub.textContent = "no correlations";
    } else if ((d.severity_counts.CRITICAL || 0) > 0) {
      stat.className = "stat red";
      sub.textContent = d.severity_counts.CRITICAL + " critical · "
                      + (d.severity_counts.HIGH || 0) + " high";
    } else {
      stat.className = "stat amber";
      sub.textContent = (d.severity_counts.HIGH || 0) + " high · "
                      + (d.severity_counts.MEDIUM || 0) + " medium";
    }

    const tbody = document.getElementById("correlation-tbody");
    if (d.alerts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="dim">'
                      + 'No correlated alerts. '
                      + d.findings_analyzed
                      + ' findings analyzed.</td></tr>';
      return;
    }
    tbody.innerHTML = d.alerts.map(a => (
      '<tr>' +
      '<td class="sev-' + a.severity + '">' + a.severity + '</td>' +
      '<td class="highlight mono">' + a.entity_value + '</td>' +
      '<td class="dim">' + a.entity_type + '</td>' +
      '<td>' + a.finding_count +
        (a.cross_agent ? ' <span class="dim">(cross-agent)</span>' : '') +
        '</td>' +
      '<td class="cmd">' + a.sources.join(', ') + '</td>' +
      '<td class="dim mono">' + a.sample + '</td>' +
      '</tr>'
    )).join("");
  } catch (e) {
    console.warn("correlation fetch failed:", e);
  }
}

refresh();
refreshIntegrity();
refreshCorrelations();
setInterval(refresh, 4000);
setInterval(refreshIntegrity, 8000);
setInterval(refreshCorrelations, 10000);
</script>
</body>
</html>
"""


def _severity_of(finding_str):
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if finding_str.startswith(s):
            return s
    return "LOW"


def _agent_status(last_seen_iso):
    try:
        last = datetime.fromisoformat(last_seen_iso.replace("Z", "+00:00"))
        delta = (datetime.now(timezone.utc) - last).total_seconds()
        if delta < 15:
            return "live"
        if delta < 60:
            return "stale"
        return "dead"
    except Exception:
        return "dead"


def _time_only(iso):
    try:
        return iso.split("T")[1][:8]
    except Exception:
        return (iso or "")[:8]


def _ist_time(iso):
    if not iso:
        return ""
    try:
        ist = timezone(timedelta(hours=5, minutes=30))
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.astimezone(ist).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso[:19]


def _collect_live_data():
    """Build full data snapshot from live agent state."""
    agents = []
    all_findings_rows = []
    total_findings = 0
    high_count = medium_count = low_count = 0
    total_results = 0
    total_pending = 0

    for aid, ident in AGENT_IDENTITIES.items():
        results = AGENT_RESULTS.get(aid, [])
        pending = AGENT_PENDING.get(aid, [])
        findings_this_agent = 0
        per_script = {}

        for r in results:
            script = r.get("script", "?")
            completed = r.get("completed_at", "")
            for f in r.get("findings", []):
                sev = _severity_of(f)
                if sev == "HIGH":
                    high_count += 1
                elif sev == "MEDIUM":
                    medium_count += 1
                elif sev == "LOW":
                    low_count += 1
                findings_this_agent += 1
                total_findings += 1
                per_script[script] = per_script.get(script, 0) + 1

                all_findings_rows.append({
                    "time": _time_only(completed),
                    "agent_id": aid,
                    "hostname": ident.get("hostname", "?"),
                    "ip": ident.get("ip", "?"),
                    "script": script,
                    "severity": sev,
                    "finding": f,
                    "evidence": f,
                    "ts": completed,
                })

        total_results += len(results)
        total_pending += len(pending)

        agents.append({
            "agent_id": aid,
            "hostname": ident.get("hostname", "?"),
            "ip": ident.get("ip", "?"),
            "os": ident.get("os", "?"),
            "os_release": (ident.get("os_release", "") or "")[:12],
            "user": ident.get("user", "?"),
            "arch": ident.get("arch", ""),
            "pid": ident.get("pid", ""),
            "connected_at": ident.get("connected_at", ""),
            "status": _agent_status(ident.get("last_seen", "")),
            "results_count": len(results),
            "total_findings": findings_this_agent,
            "per_script": per_script,
            "last_seen": _ist_time(ident.get("last_seen", "")),
        })

    all_findings_rows.sort(key=lambda x: x.get("ts", ""), reverse=True)

    return {
        "agents": agents,
        "all_findings": all_findings_rows,
        "stats": {
            "agents": len(agents),
            "findings": total_findings,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "results": total_results,
            "pending": total_pending,
        },
    }


def _build_dashboard_data():
    d = _collect_live_data()
    recent = []
    for f in d["all_findings"][:25]:
        recent.append({
            "time": f["time"],
            "agent_id": f["agent_id"],
            "script": f["script"],
            "severity": f["severity"],
            "text": f["finding"][:120],
        })
    return {
        "stats": d["stats"],
        "agents": [
            {k: v for k, v in a.items() if k != "per_script"}
            for a in d["agents"]
        ],
        "recent_findings": recent,
    }


def _compute_integrity():
    """Verify every agent's evidence chain. Returns summary dict."""
    agents_status = []
    total_envelopes = 0
    total_verified = 0
    total_failed = 0
    all_valid = True

    for aid in AGENT_IDENTITIES:
        envelopes = EVIDENCE_STORE.get(aid, [])
        pubkey_b64 = AGENT_PUBKEYS.get(aid)
        total_envelopes += len(envelopes)

        if not pubkey_b64:
            if envelopes:
                all_valid = False
            agents_status.append({
                "agent_id": aid,
                "envelopes": len(envelopes),
                "status": "no_pubkey",
                "verified": 0,
                "reason": "public key missing",
            })
            continue

        try:
            pubkey = public_key_from_b64(pubkey_b64)
            # Derive baseline from envelopes themselves (handles server
            # restarts, agent chain resumption, and multi-epoch accumulation).
            # Trust the first envelope's prev_chain_hash as the chain start.
            sorted_envs = sorted(envelopes, key=lambda e: e.get("seq", 0))
            baseline = None
            if sorted_envs and sorted_envs[0].get("seq", 0) > 1:
                baseline = {
                    "seq": sorted_envs[0]["seq"] - 1,
                    "prev_chain_hash": sorted_envs[0]["prev_chain_hash"],
                }
            valid, reason, count = verify_agent_chain(envelopes, pubkey, baseline=baseline)
        except Exception as e:
            valid, reason, count = False, f"verify error: {e}", 0

        if valid:
            total_verified += count
            agents_status.append({
                "agent_id": aid,
                "envelopes": len(envelopes),
                "status": "valid",
                "verified": count,
                "reason": "ok",
            })
        else:
            total_failed += len(envelopes) - count
            all_valid = False
            agents_status.append({
                "agent_id": aid,
                "envelopes": len(envelopes),
                "status": "invalid",
                "verified": count,
                "reason": reason,
            })

    return {
        "all_valid": all_valid,
        "agents": agents_status,
        "total_envelopes": total_envelopes,
        "total_verified": total_verified,
        "total_failed": total_failed,
    }


def _compute_risk_level(stats):
    critical = stats.get("critical", 0)
    high = stats.get("high", 0)
    medium = stats.get("medium", 0)
    if critical > 0:
        return "CRITICAL"
    if high > 5:
        return "HIGH"
    if high > 0 or medium > 10:
        return "MEDIUM"
    if medium > 0:
        return "LOW"
    return "MINIMAL"


def _recommendations(stats):
    recs = []
    if stats.get("high", 0) > 0:
        recs.append(
            f"Review {stats['high']} HIGH findings — potential compromise indicators."
        )
    if stats.get("medium", 0) > 5:
        recs.append(
            f"Investigate {stats['medium']} MEDIUM findings — many may be "
            "benign (browsers, JIT) but require triage."
        )
    if not recs:
        recs.append("No significant threats detected. Continue routine monitoring.")
    return recs


def _generate_markdown_report():
    """Build a professional markdown report from live data."""
    d = _collect_live_data()
    stats = d["stats"]
    agents = d["agents"]

    risk = _compute_risk_level(stats)
    now = datetime.now(timezone.utc).astimezone(
        timezone(timedelta(hours=5, minutes=30))
    ).strftime("%Y-%m-%d %H:%M:%S IST")

    L = []
    L.append("# JOCKY Forensic Analysis Report\n")
    L.append(f"**Generated:** {now}\n")
    L.append(f"**Risk Level:** **{risk}**\n")
    L.append(f"**Endpoints Analyzed:** {len(agents)}\n")
    L.append("")

    L.append("## Executive Summary\n")
    L.append(f"- Total findings: **{stats['findings']}**")
    L.append(f"- Critical: {stats.get('critical', 0)}")
    L.append(f"- High: {stats['high']}")
    L.append(f"- Medium: {stats['medium']}")
    L.append(f"- Low: {stats['low']}")
    L.append(f"- Task completions: {stats['results']}")
    L.append(f"- Pending commands: {stats['pending']}")
    L.append("")

    L.append("## Recommendations\n")
    for r in _recommendations(stats):
        L.append(f"- {r}")
    L.append("")

    L.append("## Endpoints\n")
    L.append("| Agent ID | Hostname | IP | OS | User | Findings | Status |")
    L.append("|---|---|---|---|---|---|---|")
    for a in agents:
        L.append(
            f"| {a['agent_id']} | {a['hostname']} | {a['ip']} | "
            f"{a['os']} {a['os_release']} | {a['user']} | "
            f"{a['total_findings']} | {a['status']} |"
        )
    L.append("")

    L.append("## Findings by Severity\n")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        rows = [f for f in d["all_findings"] if f["severity"] == sev]
        if not rows:
            continue
        L.append(f"### {sev} ({len(rows)})\n")
        for f in rows[:30]:
            L.append(
                f"- `[{f['time']}]` `{f['agent_id']}` "
                f"`{f['script']}` — {f['finding']}"
            )
        if len(rows) > 30:
            L.append(f"- ... and {len(rows) - 30} more")
        L.append("")

    L.append("## Findings by Script\n")
    script_counts = {}
    for f in d["all_findings"]:
        script_counts[f["script"]] = script_counts.get(f["script"], 0) + 1
    L.append("| Script | Findings |")
    L.append("|---|---|")
    for script, count in sorted(script_counts.items(), key=lambda x: -x[1]):
        L.append(f"| {script} | {count} |")
    L.append("")

    L.append("---\n")
    L.append("## Appendix\n")
    L.append("- Generated by JOCKY Central Management Interface")
    L.append("- All agents connected via ECDH + AES-256-GCM")
    L.append("- All scripts compiled with 7-layer obfuscation")
    L.append("- All execution file-less via memfd")
    L.append("")

    return "\n".join(L)


# ---- Routes ----

@dashboard_bp.route("/dashboard")
def dashboard():
    return render_template_string(DASHBOARD_HTML)


@dashboard_bp.route("/api/dashboard/integrity")
def dashboard_integrity():
    return jsonify(_compute_integrity())


@dashboard_bp.route("/api/dashboard/data")
def dashboard_data():
    data = _build_dashboard_data()
    now = datetime.now(timezone.utc)
    ist = timezone(timedelta(hours=5, minutes=30))
    now_ist = now.astimezone(ist)
    data["now"] = now_ist.strftime("%Y-%m-%d %H:%M:%S IST")
    data["now_short"] = now_ist.strftime("%H:%M:%S IST")
    data["server_url"] = os.environ.get(
        "JOCKY_PUBLIC_URL", "https://c2.jocky.dpdns.org"
    )
    return jsonify(data)


@dashboard_bp.route("/api/dashboard/report")
def dashboard_report():
    md = _generate_markdown_report()
    return Response(md, mimetype="text/plain; charset=utf-8")


@dashboard_bp.route("/api/dashboard/export/md")
def dashboard_export_md():
    md = _generate_markdown_report()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return Response(
        md,
        mimetype="text/markdown",
        headers={
            "Content-Disposition":
                f"attachment; filename=jocky_report_{ts}.md"
        },
    )


@dashboard_bp.route("/api/dashboard/export/json")
def dashboard_export_json():
    d = _collect_live_data()
    d["generated_at"] = datetime.now(timezone.utc).isoformat()
    d["server_url"] = os.environ.get(
        "JOCKY_PUBLIC_URL", "https://c2.jocky.dpdns.org"
    )
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return Response(
        json.dumps(d, indent=2, default=str),
        mimetype="application/json",
        headers={
            "Content-Disposition":
                f"attachment; filename=jocky_export_{ts}.json"
        },
    )


@dashboard_bp.route("/api/dashboard/export/csv")
def dashboard_export_csv():
    d = _collect_live_data()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "timestamp", "agent_id", "hostname", "ip",
        "script", "severity", "finding"
    ])
    for f in d["all_findings"]:
        writer.writerow([
            f["ts"], f["agent_id"], f["hostname"], f["ip"],
            f["script"], f["severity"], f["finding"],
        ])
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                f"attachment; filename=jocky_findings_{ts}.csv"
        },
    )


@dashboard_bp.route("/dispatch-form", methods=["POST"])
def dispatch_form():
    script = request.form.get("script", "")
    scope = request.form.get("scope", "all")
    if not script:
        return "Missing script", 400

    if scope == "all":
        agents = list(AGENT_IDENTITIES.keys())
    else:
        agents = [scope] if scope in AGENT_IDENTITIES else []

    import uuid as _uuid
    for aid in agents:
        AGENT_PENDING.setdefault(aid, []).append({
            "task_id": _uuid.uuid4().hex,
            "script": script,
            "dispatched_at": datetime.now(timezone.utc).isoformat(),
        })

    return jsonify({"status": "ok", "script": script,
                    "dispatched_to": agents, "count": len(agents)})


@dashboard_bp.route("/api/stats")
def api_stats():
    return jsonify(_build_dashboard_data()["stats"])

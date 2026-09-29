"""
JOCKY Live Correlation Engine

Reads signed envelopes from the running server and cross-references
them to find high-confidence alerts. Operates on live agent data,
not disk logs.

Correlation rules:
  1. Same PID in >=2 findings          -> escalate to CRITICAL
  2. Same file path in >=2 findings    -> escalate to HIGH
  3. Same user in >=2 scripts          -> escalate to HIGH
  4. Same IP in >=2 findings           -> escalate to HIGH
  5. Same agent reports >=3 scripts    -> informational HIGH (busy endpoint)

Whitelist: known-good processes (browsers, JIT runtimes, system daemons)
are filtered from PID-based correlation to reduce noise.
"""
import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from dispatch import EVIDENCE_STORE, AGENT_IDENTITIES


# ---------- severity helpers ----------

SEVERITY_RANK = {
    "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4
}


def _severity_of(finding_str):
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if finding_str.startswith(s):
            return s
    return "LOW"


def _escalate(max_sev, jump=1):
    """Raise severity by `jump` levels, capped at CRITICAL."""
    rank = SEVERITY_RANK.get(max_sev, 0)
    new_rank = min(rank + jump, SEVERITY_RANK["CRITICAL"])
    for name, r in SEVERITY_RANK.items():
        if r == new_rank:
            return name
    return "HIGH"


# ---------- whitelist ----------

WHITELIST_PROCESS_NAMES = {
    # Browsers / JIT runtimes (all legitimately use RWX)
    "brave", "chrome", "chromium", "firefox", "node", "java",
    "python", "python3", "code", "electron", "wrapper-2.0",
    "chrome_crashpad", "gnome-shell", "plasmashell",
    # Desktop environment / GUI
    "Xorg", "Xwayland", "qterminal", "konsole", "gnome-terminal",
    "xfce4-terminal", "xterm", "kitty", "alacritty", "tilix",
    "Thunar", "blueman-applet", "blueman-manager", "nm-applet",
    "xfce4-panel", "mate-panel", "lxqt-panel", "kwin_x11",
    # System daemons with legitimate open FDs
    "systemd", "systemd-journald", "systemd-resolved",
    "systemd-logind", "systemd-udevd", "systemd-timesyncd",
    "dbus-daemon", "snapd", "networkd-dispatcher", "NetworkManager",
    "avahi-daemon", "cron", "rsyslogd", "polkitd", "udisksd",
    # Audio / media
    "pipewire", "pipewire-pulse", "wireplumber", "pulseaudio",
    # Common desktop services
    "gvfsd", "gvfs-udisks2-volume-monitor", "tracker-miner-fs",
    "evolution-source-registry", "at-spi-bus-launcher",
    # VMware tools (host-side, always present in VMs)
    "vmware-vmblock-fuse", "vmtoolsd", "vmware-user-suid-wrapper",
}


def _is_whitelisted_finding(finding_str):
    """True if finding is about a known-good process."""
    m = re.search(r"name=([a-zA-Z0-9_.\-]+)", finding_str)
    if m and m.group(1) in WHITELIST_PROCESS_NAMES:
        return True
    return False


# ---------- entity extraction ----------

PID_RE = re.compile(r"\bpid=(\d+)")
NAME_RE = re.compile(r"\bname=([a-zA-Z0-9_.\-]+)")
USER_RE = re.compile(r"\buser=([a-zA-Z0-9_\-]+)")
IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
PATH_RE = re.compile(r"(/[\w./\-]{3,})")


def _extract_entities(finding_str):
    """Return a set of (kind, value) pairs."""
    entities = set()

    for m in PID_RE.finditer(finding_str):
        entities.add(("pid", m.group(1)))
    for m in USER_RE.finditer(finding_str):
        entities.add(("user", m.group(1)))
    for m in IP_RE.finditer(finding_str):
        ip = m.group(1)
        # Skip localhost and private
        if not (ip.startswith("127.") or ip.startswith("0.") or ip.startswith("255.")):
            entities.add(("ip", ip))
    for m in PATH_RE.finditer(finding_str):
        p = m.group(1)
        # Filter to meaningful paths
        if any(p.startswith(prefix) for prefix in (
            "/tmp/", "/dev/shm/", "/var/tmp/", "/etc/", "/root/",
            "/home/", "/usr/local/", "/opt/",
        )):
            entities.add(("path", p))

    return entities


# ---------- correlation ----------

def _collect_findings():
    """Return list of dicts: {agent_id, script, finding, severity, ts}."""
    rows = []
    for agent_id, envelopes in EVIDENCE_STORE.items():
        for env in envelopes:
            finding = env.get("finding", "")
            if not finding:
                continue
            rows.append({
                "agent_id": agent_id,
                "script": env.get("script", "?"),
                "finding": finding,
                "severity": _severity_of(finding),
                "ts": env.get("timestamp", ""),
                "seq": env.get("seq", 0),
            })
    return rows


def compute_correlations():
    """
    Build the correlation report from live envelopes.
    Returns dict with alerts + stats.
    """
    findings = _collect_findings()
    total_findings = len(findings)

    # Entity -> list of findings that mention it
    entity_map = defaultdict(list)
    for f in findings:
        for kind, value in _extract_entities(f["finding"]):
            # Filter whitelisted process-based entities
            if kind == "pid" and _is_whitelisted_finding(f["finding"]):
                continue
            entity_map[(kind, value)].append(f)

    # Per-agent finding counts by script
    agent_script_counts = defaultdict(lambda: defaultdict(int))
    for f in findings:
        agent_script_counts[f["agent_id"]][f["script"]] += 1

    alerts = []

    # Correlation rule 1: same PID >= 2 findings
    for (kind, value), fs in entity_map.items():
        if len(fs) < 2:
            continue

        # Get the max severity among correlated findings
        max_sev = max((SEVERITY_RANK.get(f["severity"], 0) for f in fs),
                      default=0)
        max_sev_name = next(
            (n for n, r in SEVERITY_RANK.items() if r == max_sev), "LOW"
        )

        # Rule-specific escalation
        if kind == "pid":
            escalated = _escalate(max_sev_name, jump=1)
            severity = "CRITICAL" if max_sev >= 3 else escalated
        elif kind == "path":
            severity = _escalate(max_sev_name, jump=1)
        elif kind == "user":
            severity = _escalate(max_sev_name, jump=1)
        elif kind == "ip":
            severity = _escalate(max_sev_name, jump=0)
        else:
            severity = _escalate(max_sev_name, jump=0)

        sources = sorted(set(f["script"] for f in fs))
        agents = sorted(set(f["agent_id"] for f in fs))
        cross_agent = len(agents) >= 2

        # In our demo, all namespaces share the PID tree, so identical
        # PIDs across agents are NOT evidence of lateral movement.
        # Only escalate cross-agent if the entity is a path, user, or IP
        # (things that CAN legitimately differ across namespaces).
        if cross_agent and kind in ("path", "user", "ip"):
            severity = _escalate(severity, jump=1)
        elif cross_agent and kind == "pid":
            # PID across agents only suspicious if agent hostnames differ
            hostnames = set()
            for f in fs:
                aid = f["agent_id"]
                # Look up hostname via AGENT_IDENTITIES
                try:
                    from dispatch import AGENT_IDENTITIES as _AI
                    hostnames.add(_AI.get(aid, {}).get("hostname", aid))
                except Exception:
                    hostnames.add(aid)
            if len(hostnames) >= 2:
                severity = _escalate(severity, jump=1)

        alerts.append({
            "entity_type": kind,
            "entity_value": value,
            "severity": severity,
            "finding_count": len(fs),
            "sources": sources,
            "agents": agents,
            "cross_agent": cross_agent,
            "sample": fs[0]["finding"][:140],
            "evidence": [f["finding"][:120] for f in fs[:3]],
        })

    # Correlation rule 2: agent has >=3 scripts reporting (busy endpoint)
    for agent_id, scripts in agent_script_counts.items():
        if len(scripts) >= 3:
            alerts.append({
                "entity_type": "agent",
                "entity_value": agent_id,
                "severity": "HIGH",
                "finding_count": sum(scripts.values()),
                "sources": sorted(scripts.keys()),
                "agents": [agent_id],
                "cross_agent": False,
                "sample": f"Agent {agent_id} reported from {len(scripts)} scripts",
                "evidence": [],
            })

    # Sort: CRITICAL > HIGH > MEDIUM > LOW; then by finding_count desc
    alerts.sort(key=lambda a: (
        -SEVERITY_RANK.get(a["severity"], 0),
        -a["finding_count"]
    ))

    # Deduplicate identical alerts (same entity + same severity)
    seen = set()
    unique_alerts = []
    for a in alerts:
        key = (a["entity_type"], a["entity_value"], a["severity"])
        if key in seen:
            continue
        seen.add(key)
        unique_alerts.append(a)

    # Stats
    severity_counts = defaultdict(int)
    for a in unique_alerts:
        severity_counts[a["severity"]] += 1

    return {
        "alerts": unique_alerts[:50],   # cap for display
        "total_alerts": len(unique_alerts),
        "findings_analyzed": total_findings,
        "severity_counts": dict(severity_counts),
        "agents": len(AGENT_IDENTITIES),
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }

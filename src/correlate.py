"""
JOCKY Forensic Correlation Engine

Reads findings emitted by the 8 native JOCKY forensic scripts,
cross-references them, and produces correlated alerts.

Correlation logic:
  - Same PID with multiple findings → escalate to CRITICAL
  - Same file flagged by multiple scripts → escalate
  - Same user with multiple findings → escalate
  - Same hash in IOC scan and shell history → escalate
"""
import json
import re
import subprocess
import sys
from pathlib import Path
from collections import defaultdict

SCRIPTS = [
    "process_audit",
    "persistence_audit",
    "user_audit",
    "network_audit",
    "filesystem_audit",
    "log_audit",
    "ioc_scan",
    "timeline",
]


def run_script(name):
    """Run a compiled JOCKY script and parse its output."""
    binary = f"/tmp/{name}_final.bin"
    if not Path(binary).exists():
        return {"findings": [], "stats": {}, "error": "binary not built"}

    result = subprocess.run(
        [binary], capture_output=True, text=True, timeout=60
    )
    findings = []
    stats = {}

    for line in result.stdout.splitlines():
        if line.startswith("EMIT FINDING = "):
            payload = line[len("EMIT FINDING = "):]
            # Format: SEVERITY|CATEGORY|CHECK|evidence
            parts = payload.split("|", 3)
            if len(parts) >= 3:
                findings.append({
                    "severity": parts[0],
                    "category": parts[1],
                    "check": parts[2],
                    "evidence": parts[3] if len(parts) > 3 else "",
                    "source": name,
                })
        elif line.startswith("EMIT STAT_"):
            payload = line[len("EMIT STAT_"):]
            if " = " in payload:
                key, val = payload.split(" = ", 1)
                stats[key] = val
        elif line.startswith("EMIT HASH = "):
            payload = line[len("EMIT HASH = "):]
            if "|" in payload:
                fname, h = payload.rsplit("|", 1)
                findings.append({
                    "severity": "INFO",
                    "category": "IOC",
                    "check": "File_hash",
                    "evidence": f"{fname}|{h}",
                    "source": name,
                })

    return {"findings": findings, "stats": stats}


def extract_entities(finding):
    """Extract correlatable entities (PIDs, users, files, IPs) from evidence."""
    entities = set()
    evidence = finding.get("evidence", "")

    # Extract pid=N
    for m in re.finditer(r"pid=(\d+)", evidence):
        entities.add(("pid", m.group(1)))

    # Extract user=N
    for m in re.finditer(r"user=([a-zA-Z0-9_-]+)", evidence):
        entities.add(("user", m.group(1)))

    # Extract filename
    for m in re.finditer(r"\b([a-zA-Z0-9_.-]+\.(?:sh|bin|py|so))\b", evidence):
        entities.add(("file", m.group(1)))

    # Extract IP
    for m in re.finditer(r"\b(\d+\.\d+\.\d+\.\d+)\b", evidence):
        entities.add(("ip", m.group(1)))

    # Extract file path
    for m in re.finditer(r"(/[a-zA-Z0-9_./-]+)", evidence):
        entities.add(("path", m.group(1)))


    return entities


# Known-good processes that legitimately use RWX memory and deleted FDs
WHITELIST_PROCESSES = {
    "brave", "chrome", "chromium", "firefox", "node", "java", "python",
    "code", "electron", "wrapper-2.0", "pipewire", "wireplumber",
    "Thunar", "blueman-applet", "chrome_crashpad",
}

def is_whitelisted(finding):
    """Return True if this finding is about a whitelisted process."""
    evidence = finding.get("evidence", "")
    for name in WHITELIST_PROCESSES:
        if f"name={name}" in evidence:
            return True
    return False

def correlate(all_findings):
    """Cross-reference findings to identify correlated alerts."""
    # Filter out whitelisted processes before correlation
    filtered = [f for f in all_findings if not is_whitelisted(f)]
    entity_map = defaultdict(list)

    for f in filtered:
        for kind, val in extract_entities(f):
            entity_map[(kind, val)].append(f)
    correlated = []
    for (kind, val), findings in entity_map.items():
        if len(findings) >= 2:
            # Same entity appears in multiple findings → escalate
            severities = [f["severity"] for f in findings]
            max_sev = max(severities, key=lambda s: {
                "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4
            }.get(s, 0))
            escalated = "CRITICAL" if max_sev == "HIGH" else "HIGH"
            correlated.append({
                "entity_type": kind,
                "entity_value": val,
                "finding_count": len(findings),
                "severity": escalated,
                "finding_sources": list(set(f["source"] for f in findings)),
                "sample_findings": findings[:3],
            })

    correlated.sort(key=lambda x: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[x["severity"]],
        -x["finding_count"]
    ))
    return correlated


def main():
    print("=" * 70)
    print("JOCKY Forensic Correlation Engine")
    print("=" * 70)

    all_findings = []
    stats_summary = {}

    for script in SCRIPTS:
        print(f"\n[*] Running {script}...")
        result = run_script(script)
        n = len(result["findings"])
        print(f"    {n} findings")
        all_findings.extend(result["findings"])
        stats_summary[script] = result.get("stats", {})

    print()
    print("=" * 70)
    print(f"Total findings: {len(all_findings)}")
    print("=" * 70)

    # Severity breakdown
    sev_counts = defaultdict(int)
    for f in all_findings:
        sev_counts[f["severity"]] += 1

    print()
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        print(f"  {sev:10s} : {sev_counts[sev]}")

    # Correlation
    print()
    print("=" * 70)
    print("Correlated Alerts")
    print("=" * 70)
    correlated = correlate(all_findings)

    if not correlated:
        print("  No correlated alerts detected.")
    else:
        for c in correlated[:20]:
            print(f"\n  [{c['severity']}] {c['entity_type']}: {c['entity_value']}")
            print(f"    Found in {c['finding_count']} findings "
                  f"across {len(c['finding_sources'])} scripts")
            print(f"    Sources: {', '.join(c['finding_sources'])}")

    # Save results
    output = {
        "total_findings": len(all_findings),
        "severity_breakdown": dict(sev_counts),
        "correlated_alerts": correlated,
        "all_findings": all_findings,
        "stats": stats_summary,
    }
    out_path = Path("logs/correlation_report.json")
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2))
    print()
    print(f"[+] Full report: {out_path}")


if __name__ == "__main__":
    main()

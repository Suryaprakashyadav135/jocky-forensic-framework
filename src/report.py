"""JOCKY Forensic Report Generator"""
import json
import sys
from datetime import datetime
from pathlib import Path
from collections import defaultdict


def load_report(path="logs/correlation_report.json"):
    p = Path(path)
    if not p.exists():
        print(f"[!] No correlation report found at {path}")
        sys.exit(1)
    return json.loads(p.read_text())


def compute_risk_level(sev):
    if sev.get("CRITICAL", 0) > 0: return "CRITICAL", "[CRIT]"
    if sev.get("HIGH", 0) > 5: return "HIGH", "[HIGH]"
    if sev.get("HIGH", 0) > 0 or sev.get("MEDIUM", 0) > 10: return "MEDIUM", "[MED]"
    if sev.get("MEDIUM", 0) > 0: return "LOW", "[LOW]"
    return "MINIMAL", "[MIN]"


def recommendations(sev, correlated):
    recs = []
    if sev.get("CRITICAL", 0) > 0:
        recs.append("**Immediate action required** --- critical findings present.")
    if sev.get("HIGH", 0) > 0:
        recs.append(f"Review {sev['HIGH']} HIGH findings --- potential compromise.")
    if sev.get("MEDIUM", 0) > 5:
        recs.append(f"Investigate {sev['MEDIUM']} MEDIUM findings (browsers, JIT noise possible).")
    if len(correlated) > 0:
        recs.append(f"{len(correlated)} correlated alerts --- cross-referenced findings.")
    if not recs:
        recs.append("No significant threats detected.")
    return recs


def generate_report(report, output_path="reports/forensic_report.md"):
    findings = report["all_findings"]
    correlated = report["correlated_alerts"]
    sev = report["severity_breakdown"]
    risk, marker = compute_risk_level(sev)

    by_category = defaultdict(list)
    by_severity = defaultdict(list)
    for f in findings:
        if f["severity"] == "INFO": continue
        by_category[f["category"]].append(f)
        by_severity[f["severity"]].append(f)

    L = []
    L.append("# JOCKY Forensic Analysis Report\n")
    L.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    L.append(f"**Risk Level:** {marker} **{risk}**\n")

    L.append("\n## Executive Summary\n")
    L.append(f"- Total findings: **{report['total_findings']}**")
    L.append(f"- Critical: {sev.get('CRITICAL', 0)}")
    L.append(f"- High:     {sev.get('HIGH', 0)}")
    L.append(f"- Medium:   {sev.get('MEDIUM', 0)}")
    L.append(f"- Low:      {sev.get('LOW', 0)}")
    L.append(f"- Info:     {sev.get('INFO', 0)} (hashes, stats)")
    L.append(f"- Correlated alerts: **{len(correlated)}**")

    L.append("\n## Recommendations\n")
    for r in recommendations(sev, correlated):
        L.append(f"- {r}")

    if correlated:
        L.append("\n## Correlated Alerts\n")
        for c in correlated[:10]:
            L.append(f"\n### [{c['severity']}] {c['entity_type']}: {c['entity_value']}")
            L.append(f"- Appears in **{c['finding_count']}** findings")
            L.append(f"- Detected by: {', '.join(c['finding_sources'])}")

    for sev_name in ["HIGH", "MEDIUM"]:
        items = by_severity.get(sev_name, [])
        if items:
            L.append(f"\n## {sev_name} Severity Findings\n")
            L.append(f"*{len(items)} findings --- showing first 20*\n")
            for f in items[:20]:
                L.append(f"- `[{f['source']}]` {f['check']}: {f['evidence'][:120]}")

    L.append("\n## Findings by Category\n")
    for cat, items in sorted(by_category.items()):
        L.append(f"- **{cat}**: {len(items)} findings")

    L.append("\n---\n")
    L.append("## Appendix\n")
    L.append("- Scanned by 8 native JOCKY forensic scripts")
    L.append("- Full JSON: `logs/correlation_report.json`")
    L.append("- All scripts compiled with 7-layer obfuscation")
    L.append("- Zero plaintext forensic intent in any binary\n")

    output_path = Path(output_path)
    output_path.parent.mkdir(exist_ok=True)
    output_path.write_text("\n".join(L))
    return output_path


def main():
    print("[*] Loading correlation report...")
    report = load_report()
    print(f"    {report['total_findings']} findings")
    print("[*] Generating forensic report...")
    out = generate_report(report)
    print(f"[+] Report saved: {out}")
    print(f"    Size: {out.stat().st_size} bytes")


if __name__ == "__main__":
    main()

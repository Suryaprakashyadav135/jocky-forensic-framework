#!/usr/bin/env python3
"""
JOCKY Forensic Orchestrator

Single command that runs the complete forensic pipeline:
  1. Builds all 8 JOCKY forensic scripts (if not already built)
  2. Runs them via the correlation engine
  3. Generates the human-readable report
  4. Prints summary
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
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


def build_all(force=False):
    """Build every forensic script with full obfuscation."""
    print("=" * 70)
    print("STEP 1: Compiling forensic scripts with 7-layer obfuscation")
    print("=" * 70)

    for name in SCRIPTS:
        jky = ROOT / "jocky_scripts" / f"{name}.jky"
        binary = Path(f"/tmp/{name}_final.bin")

        if binary.exists() and not force:
            print(f"  [skip] {name} (already built)")
            continue

        print(f"  [build] {name}...")
        result = subprocess.run(
            [str(ROOT / "build_jocky.sh"), str(jky)],
            capture_output=True, text=True, cwd=ROOT
        )
        if result.returncode != 0:
            print(f"    BUILD FAILED for {name}")
            print(result.stderr[-500:])
            return False

    print()
    return True


def run_correlation():
    """Run the correlation engine."""
    print("=" * 70)
    print("STEP 2: Running correlation engine across all findings")
    print("=" * 70)
    result = subprocess.run(
        [sys.executable, str(ROOT / "src" / "correlate.py")],
        capture_output=False, cwd=ROOT
    )
    return result.returncode == 0


def generate_report():
    """Generate the forensic report."""
    print()
    print("=" * 70)
    print("STEP 3: Generating forensic report")
    print("=" * 70)
    result = subprocess.run(
        [sys.executable, str(ROOT / "src" / "report.py")],
        capture_output=False, cwd=ROOT
    )
    return result.returncode == 0


def print_summary():
    """Print final summary."""
    import json
    report_path = ROOT / "logs" / "correlation_report.json"
    if not report_path.exists():
        return

    report = json.loads(report_path.read_text())
    sev = report["severity_breakdown"]

    print()
    print("=" * 70)
    print("FORENSIC PIPELINE COMPLETE")
    print("=" * 70)
    print(f"  Scripts run:        {len(SCRIPTS)}")
    print(f"  Total findings:     {report['total_findings']}")
    print(f"  Critical:           {sev.get('CRITICAL', 0)}")
    print(f"  High:               {sev.get('HIGH', 0)}")
    print(f"  Medium:             {sev.get('MEDIUM', 0)}")
    print(f"  Low:                {sev.get('LOW', 0)}")
    print(f"  Info:               {sev.get('INFO', 0)}")
    print(f"  Correlated alerts:  {len(report['correlated_alerts'])}")
    print()
    print(f"  Full report:        reports/forensic_report.md")
    print(f"  Full JSON:          logs/correlation_report.json")
    print()


def main():
    force = "--force" in sys.argv

    print()
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 16 + "JOCKY FORENSIC SUITE" + " " * 32 + "║")
    print("║" + " " * 12 + "Complete Analysis Pipeline" + " " * 30 + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    if not build_all(force=force):
        sys.exit(1)

    if not run_correlation():
        sys.exit(1)

    if not generate_report():
        sys.exit(1)

    print_summary()


if __name__ == "__main__":
    main()

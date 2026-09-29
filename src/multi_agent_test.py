#!/usr/bin/env python3
"""Spawn N agents as subprocesses, dispatch a script, verify all report back."""
import os, subprocess, sys, time, requests
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = "http://127.0.0.1:8080"
N = 3


def main():
    # Sanity: server up?
    try:
        r = requests.get(f"{SERVER}/api/v1/agents", timeout=5)
        print(f"[test] server up: {r.json()['count']} existing agents")
    except Exception as e:
        print(f"[test] server not reachable: {e}")
        sys.exit(1)

    procs = []
    print(f"\n[test] spawning {N} agents as subprocesses...\n")
    for i in range(N):
        env = os.environ.copy()
        env["JOCKY_SERVER"] = SERVER
        env["JOCKY_AGENT_ID"] = f"ns-agent-{i+1}"
        env["JOCKY_JITTER_MIN"] = "2.0"
        env["JOCKY_JITTER_MAX"] = "4.0"
        env["JOCKY_ROOT"] = str(ROOT)
        p = subprocess.Popen(
            [sys.executable, "-u", str(ROOT / "src" / "jocky_agent.py")],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True,
        )
        procs.append(p)
        time.sleep(0.4)

    time.sleep(4)
    r = requests.get(f"{SERVER}/api/v1/agents", timeout=5).json()
    print(f"[test] {r['count']} agent(s) registered on server")
    for a in r["agents"]:
        print(f"  {a['agent_id']:20s} {a.get('hostname')} @ {a.get('ip')}")

    print(f"\n[test] dispatching process_audit.jky to all agents...")
    r = requests.post(f"{SERVER}/api/v1/dispatch",
                      json={"script": "process_audit"}, timeout=10).json()
    print(f"[test] dispatched to {r['count']} agent(s)")

    print(f"\n[test] waiting 90s for reports...")
    for _ in range(30):
        time.sleep(3)
        r = requests.get(f"{SERVER}/api/v1/agents", timeout=5).json()
        done = sum(1 for a in r["agents"] if a.get("results_count", 0) > 0)
        print(f"  ... {done}/{r['count']} agents reported")
        if done >= r["count"]:
            break

    print("\n[test] final results:")
    r = requests.get(f"{SERVER}/api/v1/agents", timeout=5).json()
    for a in r["agents"]:
        print(f"\n  {a['agent_id']} ({a.get('hostname')}): "
              f"{a.get('results_count',0)} results, "
              f"{a.get('total_findings',0)} findings")

    print("\n[test] stopping agents...")
    for p in procs:
        p.terminate()
    for p in procs:
        try: p.wait(timeout=3)
        except Exception: p.kill()

    print("[test] done")


if __name__ == "__main__":
    main()

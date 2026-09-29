import os
#!/usr/bin/env python3
"""JOCKY Dispatch CLI — analyst control plane."""
from datetime import datetime, timezone, timedelta
import argparse, requests, sys

SERVER = os.environ.get("JOCKY_SERVER", "http://127.0.0.1:8080")
TOKEN = os.environ.get("JOCKY_DISPATCH_TOKEN", "jky-disp-dev")



def _local(iso_str):
    """Convert UTC ISO string to IST for display (hardcoded +05:30)."""
    if not iso_str:
        return ""
    try:
        ist = timezone(timedelta(hours=5, minutes=30))
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.astimezone(ist).strftime("%Y-%m-%d %H:%M:%S IST")
    except Exception:
        return iso_str[:19]

def list_agents():
    data = requests.get(f"{SERVER}/api/v1/agents", timeout=5).json()
    agents = data["agents"]
    if not agents:
        print("No agents connected."); return
    print(f"\n{len(agents)} agent(s):\n")
    print(f"{'AGENT_ID':<24} {'HOSTNAME':<18} {'IP':<16} "
          f"{'OS':<8} {'FINDINGS':<9} {'LAST_SEEN'}")
    print("-" * 100)
    for a in agents:
        print(f"{a['agent_id']:<24} {(a.get('hostname') or ''):<18} "
              f"{(a.get('ip') or ''):<16} {(a.get('os') or ''):<8} "
              f"{a.get('total_findings',0):<9} {_local(a.get('last_seen'))}")
    print()


def dispatch(script, agents=None):
    p = {"script": script}
    if agents: p["agents"] = agents
    p["token"] = TOKEN
    data = requests.post(f"{SERVER}/api/v1/dispatch", json=p,
                         headers={"X-Jocky-Token": TOKEN}, timeout=10).json()
    print(f"\nDispatched: {data.get('script')} → {data.get('count')} agent(s)")
    for d in data.get("dispatched_to", []):
        print(f"  {d['agent_id']:<24} task={d['task_id'][:12]}")
    print()


def view(agent_id):
    data = requests.get(f"{SERVER}/api/v1/agents/{agent_id}", timeout=5).json()
    i = data["identity"]
    print(f"\n=== {agent_id} ===")
    for k in ["hostname", "ip", "os", "os_release", "user",
              "connected_at", "last_seen"]:
        print(f"  {k:14s}: {i.get(k)}")
    results = data.get("results", [])
    print(f"\n{len(results)} result(s):")
    for r in results:
        n = len(r.get("findings", []))
        print(f"  [{r.get('script','?'):20s}] {n:3d} findings  "
              f"{r.get('completed_at','')[:19]}")
        for f in r.get("findings", [])[:4]:
            print(f"      {f[:110]}")
        if n > 4:
            print(f"      ... +{n-4} more")
    print()


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("agents")
    d = sub.add_parser("dispatch")
    d.add_argument("script")
    d.add_argument("--agents", nargs="*")
    v = sub.add_parser("view")
    v.add_argument("agent_id")
    args = p.parse_args()
    if args.cmd == "agents": list_agents()
    elif args.cmd == "dispatch": dispatch(args.script, args.agents)
    elif args.cmd == "view": view(args.agent_id)
    else: p.print_help()


if __name__ == "__main__":
    main()

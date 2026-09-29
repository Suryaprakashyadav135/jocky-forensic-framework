"""
JOCKY Framework — Module 6: Multi-Client Simulator
Spawns N concurrent "endpoints" each with their own ECDH session.
For demo purposes — proves central management handles simultaneous clients.
"""

import sys
import random
import time
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from c2_channel import JockyC2Channel


ENDPOINT_NAMES = [
    "workstation-04", "laptop-hr-07", "srv-db-01",
    "srv-web-02", "workstation-fin-11", "laptop-dev-03",
]

# Per-endpoint command playlists
COMMAND_SETS = [
    [("collect_system_info", {}), ("list_processes", {"limit": 5}), ("check_persistence", {})],
    [("enumerate_network_connections", {"proto": "tcp"}), ("list_processes", {"limit": 8})],
    [("scan_forensic_artifacts", {"paths": ["/var/log", "/tmp", "/home"]}), ("collect_system_info", {})],
    [("collect_system_info", {}), ("check_persistence", {}), ("list_processes", {"limit": 10})],
    [("enumerate_network_connections", {"proto": "all"}), ("scan_forensic_artifacts", {"paths": ["/var/log"]})],
    [("list_processes", {"limit": 3}), ("collect_system_info", {})],
]


def run_endpoint(name: str, commands: list, jitter_max: float = 2.0):
    """One simulated endpoint with its own session."""
    ch = JockyC2Channel(
        cdn_front="http://127.0.0.1:8080",
        c2_backend="c2.hidden.internal",
        log_path=f"logs/c2_{name}.log",
    )

    print(f"  [{name}] establishing session...")
    if not ch.handshake():
        print(f"  [{name}] handshake failed — skipping")
        return

    for cmd, args in commands:
        time.sleep(random.uniform(0.3, jitter_max))
        resp = ch.send_command(cmd, args)
        status = resp.status
        print(f"  [{name}] {cmd:35s} → {status}")


def main():
    print("=" * 70)
    print("JOCKY Multi-Client Simulator")
    print("=" * 70)

    n = len(ENDPOINT_NAMES)
    print(f"\nSpawning {n} endpoints in parallel...\n")

    threads = []
    for i, name in enumerate(ENDPOINT_NAMES):
        cmds = COMMAND_SETS[i % len(COMMAND_SETS)]
        t = threading.Thread(target=run_endpoint, args=(name, cmds), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=30)

    print("\n[OK] All endpoints complete.")
    print("     Open http://127.0.0.1:8080/dashboard to see them.")


if __name__ == "__main__":
    main()

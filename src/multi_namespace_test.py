"""
JOCKY Framework --- Multi-Namespace Client Test

Simulates multiple forensic endpoints on distinct network namespaces.
Each namespace has its own network stack, its own IP address, and runs
its own JOCKY client. The C2 server sees real cross-network traffic
from distinct source IPs --- not localhost simulations.

This is a stronger demonstration than the mock multi-client simulator:
- Each client has a REAL network namespace (Linux kernel isolation)
- Each client has a REAL distinct IP address
- Traffic between namespaces and the server traverses veth pairs
- The server's connection log shows different remote addresses

Requirements: sudo (creates namespaces and veth interfaces).
"""

import os
import subprocess
import sys
import time
import json
import base64
import socket
import threading
from pathlib import Path

# Configuration
HOST_BRIDGE = "jky_br0"
HOST_IP = "192.168.100.1"
SUBNET = "192.168.100"
NETMASK = "24"
SERVER_PORT = 8080
N_NAMESPACES = 3

# Namespace-specific IPs
NS_IPS = [f"{SUBNET}.{10 + i}" for i in range(N_NAMESPACES)]
NS_NAMES = [f"jky_ns{i}" for i in range(N_NAMESPACES)]


def run(cmd, check=True, capture=True):
    """Run a shell command."""
    result = subprocess.run(
        cmd, shell=True, check=False,
        capture_output=capture, text=True,
    )
    if check and result.returncode != 0:
        print(f"[!] Command failed: {cmd}")
        print(f"    stderr: {result.stderr}")
        raise RuntimeError(f"Command failed: {cmd}")
    return result


def cleanup():
    """Remove all namespaces and bridge. Safe to call multiple times."""
    print("[*] Cleaning up previous namespaces and bridge")
    for ns in NS_NAMES:
        run(f"ip netns del {ns}", check=False)
    run(f"ip link del {HOST_BRIDGE}", check=False)


def setup_bridge():
    """Create the host-side bridge that namespaces connect to."""
    print(f"[*] Creating bridge {HOST_BRIDGE} at {HOST_IP}")
    run(f"ip link add {HOST_BRIDGE} type bridge")
    run(f"ip addr add {HOST_IP}/{NETMASK} dev {HOST_BRIDGE}")
    run(f"ip link set {HOST_BRIDGE} up")


def setup_namespace(i: int):
    """Create a network namespace with its own veth pair and IP."""
    ns = NS_NAMES[i]
    ns_ip = NS_IPS[i]
    veth_host = f"veth_h{i}"
    veth_ns = f"veth_n{i}"

    print(f"[*] Setting up namespace {ns} -> {ns_ip}")

    # Create namespace
    run(f"ip netns add {ns}")

    # Create veth pair
    run(f"ip link add {veth_host} type veth peer name {veth_ns}")
    run(f"ip link set {veth_ns} netns {ns}")
    run(f"ip link set {veth_host} master {HOST_BRIDGE}")
    run(f"ip link set {veth_host} up")

    # Configure namespace side
    run(f"ip netns exec {ns} ip link set lo up")
    run(f"ip netns exec {ns} ip link set {veth_ns} up")
    run(f"ip netns exec {ns} ip addr add {ns_ip}/{NETMASK} dev {veth_ns}")
    run(f"ip netns exec {ns} ip route add default via {HOST_IP}")


def run_client_in_namespace(i: int):
    """
    Launch a JOCKY client inside namespace i.
    The client will connect to the C2 server on the host bridge IP.
    """
    ns = NS_NAMES[i]
    # Build a Python one-liner that runs the client logic inside the namespace
    client_code = f'''
import sys
sys.path.insert(0, "/home/kali/Rudhra/Jocky/src")
from protocol import CommandRequest
from crypto import generate_keypair, derive_shared_secret, derive_aes_key, SecureSession
import requests, json, base64, time

URL = "http://{HOST_IP}:{SERVER_PORT}"

# Handshake
priv_C, pub_C = generate_keypair()
pub_C_b64 = base64.urlsafe_b64encode(pub_C).decode()
r = requests.post(f"{{URL}}/api/v1/handshake", json={{"pub": pub_C_b64, "ver": "1.0"}}, timeout=10)
body = r.json()
pub_S = base64.urlsafe_b64decode(body["pub"].encode())
sid = body["session_id"]
shared = derive_shared_secret(priv_C, pub_S)
aes_key = derive_aes_key(shared, salt=sid.encode())
session = SecureSession(aes_key, session_id=sid)
print(f"[ns-{i}] session {{sid[:12]}}")

# Send commands
for cmd in ["collect_system_info", "list_processes", "check_persistence"]:
    req = CommandRequest(command=cmd, args={{"limit": 3}} if cmd == "list_processes" else {{}})
    payload = req.to_dict()
    payload["_ctr"] = session.counter
    ct = session.encrypt(payload)
    r = requests.post(f"{{URL}}/api/v1/telemetry", json={{"d": ct}}, timeout=10)
    resp = session.decrypt(r.json()["response_ct"])
    print(f"[ns-{i}] {{cmd}} -> {{resp['status']}}")
    time.sleep(0.3)
'''
    # Write the client to a temp file
    client_path = f"/tmp/jky_client_ns{i}.py"
    with open(client_path, "w") as f:
        f.write(client_code)

    # Execute inside namespace asynchronously
    def _run():
        result = subprocess.run(
            f"ip netns exec {ns} python3 {client_path}",
            shell=True, capture_output=True, text=True,
        )
        # Print output prefixed by namespace
        for line in result.stdout.splitlines():
            print(f"  {line}")
        if result.stderr and "Traceback" in result.stderr:
            print(f"  [{ns} stderr] {result.stderr.splitlines()[-1]}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


def main():
    if os.geteuid() != 0:
        print("[!] This script must run as root (needs network namespace + bridge)")
        print(f"    Run: sudo python3 {__file__}")
        sys.exit(1)

    print("=" * 70)
    print("JOCKY Multi-Namespace Client Test")
    print("=" * 70)
    print(f"Server: {HOST_IP}:{SERVER_PORT}")
    print(f"Namespaces: {', '.join(NS_NAMES)}")
    print(f"IPs: {', '.join(NS_IPS)}")
    print()

    cleanup()

    try:
        setup_bridge()
        for i in range(N_NAMESPACES):
            setup_namespace(i)

        print()
        print("[*] Waiting for namespaces to settle...")
        time.sleep(1)

        # Verify namespaces reach the host
        print("[*] Verifying connectivity from each namespace")
        for i, ns in enumerate(NS_NAMES):
            result = run(f"ip netns exec {ns} ping -c 1 -W 1 {HOST_IP}",
                         check=False)
            if "1 received" in result.stdout:
                print(f"  ✓ {ns} -> {HOST_IP} OK")
            else:
                print(f"  ✗ {ns} -> {HOST_IP} FAILED")

        print()
        print("[*] Launching clients in parallel")
        threads = []
        for i in range(N_NAMESPACES):
            t = run_client_in_namespace(i)
            threads.append(t)

        # Wait for all clients
        for t in threads:
            t.join(timeout=30)

        print()
        print("[*] Clients done. Check the server's terminal for incoming sessions.")
        print("    Each session will have a distinct source IP (192.168.100.1x)")
        print()
        print("[*] Server logs should show:")
        print(f"    - {N_NAMESPACES} distinct ECDH handshakes")
        print(f"    - {N_NAMESPACES} × 3 = {N_NAMESPACES * 3} encrypted commands")
        print(f"    - Source IPs from {NS_IPS}")

    except Exception as e:
        print(f"[!] Error: {e}")

    finally:
        print()
        print("[*] Leaving namespaces up for inspection.")
        print("[*] To clean up: sudo ip netns list; sudo ip netns del <name>; sudo ip link del jky_br0")
        print()
        print("[*] To watch server activity while clients run:")
        print("    tail -f /home/kali/Rudhra/Jocky/logs/sessions.jsonl")


if __name__ == "__main__":
    main()

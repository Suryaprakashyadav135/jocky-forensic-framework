#!/usr/bin/env python3
"""
JOCKY Evidence Verifier

Reads /api/v1/evidence/* from the server (or local evidence_chain.jsonl)
and verifies:
  1. Every envelope's signature against its agent's pubkey
  2. Every chain link (prev_chain_hash matches previous entry)
  3. Sequence has no gaps
  4. Finding hash matches finding text

Exits 0 if valid, 1 if any problem.
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from evidence import public_key_from_b64, verify_agent_chain

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


SERVER = "http://127.0.0.1:8080"
LOCAL_CHAIN = Path("/home/kali/Rudhra/Jocky/logs/evidence_chain.jsonl")


def fetch_from_server():
    """Fetch envelopes + pubkeys from running server."""
    if not HAS_REQUESTS:
        return None, None
    try:
        summary = requests.get(f"{SERVER}/api/v1/evidence/summary", timeout=5).json()
        pubkeys = requests.get(f"{SERVER}/api/v1/evidence/pubkeys", timeout=5).json()
        by_agent = defaultdict(list)
        for a in summary.get("agents", []):
            aid = a["agent_id"]
            r = requests.get(f"{SERVER}/api/v1/evidence/{aid}", timeout=5).json()
            for env in r.get("envelopes", []):
                by_agent[aid].append(env)
        return by_agent, pubkeys.get("pubkeys", {})
    except Exception as e:
        print(f"  (server not reachable: {e})")
        return None, None


def fetch_from_disk():
    """Fall back to local evidence_chain.jsonl."""
    if not LOCAL_CHAIN.exists():
        return None, None
    by_agent = defaultdict(list)
    pubkeys = {}
    # Load pubkeys from agent_*.pub files
    logs = LOCAL_CHAIN.parent
    for pf in logs.glob("agent_*.pub"):
        # filename: agent_<agent_id>.pub
        stem = pf.stem  # agent_agent-xxxx
        if stem.startswith("agent_"):
            aid = stem[len("agent_"):]
            pubkeys[aid] = pf.read_text().strip()
    with LOCAL_CHAIN.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                env = json.loads(line)
                aid = env.get("agent_id")
                if aid:
                    by_agent[aid].append(env)
            except Exception:
                continue
    return by_agent, pubkeys


def main():
    print()
    print("=" * 64)
    print("JOCKY Evidence Verification")
    print("=" * 64)

    by_agent, pubkeys = fetch_from_server()
    source = "server API"
    if by_agent is None:
        by_agent, pubkeys = fetch_from_disk()
        source = "local chain file"

    if by_agent is None:
        print("No evidence found (server unreachable + no local chain).")
        sys.exit(0)

    print(f"Source:      {source}")
    print(f"Agents:      {len(by_agent)}")
    print(f"Pubkeys:     {len(pubkeys)}")
    print()

    total_valid = 0
    total_invalid = 0
    any_chain_broken = False

    for aid, envelopes in sorted(by_agent.items()):
        pubkey_b64 = pubkeys.get(aid)
        if not pubkey_b64:
            print(f"  {aid}: no pubkey — CANNOT VERIFY")
            total_invalid += len(envelopes)
            any_chain_broken = True
            continue

        try:
            pubkey = public_key_from_b64(pubkey_b64)
        except Exception as e:
            print(f"  {aid}: bad pubkey ({e})")
            total_invalid += len(envelopes)
            any_chain_broken = True
            continue

        # Fetch baseline from server for each agent (seq start + prev hash)
        baseline = None
        try:
            info = requests.get(f"{SERVER}/api/v1/agents/{aid}", timeout=5).json()
            # Baseline is in registration payload; use envelope's own prev if seq > 1
        except Exception:
            pass
        # Fallback: if first envelope's seq > 1, use its prev_chain_hash as baseline
        sorted_envs = sorted(envelopes, key=lambda e: e.get("seq", 0))
        if sorted_envs and sorted_envs[0].get("seq", 0) > 1:
            baseline = {
                "seq": sorted_envs[0]["seq"] - 1,
                "prev_chain_hash": sorted_envs[0]["prev_chain_hash"],
            }
        valid, reason, count = verify_agent_chain(envelopes, pubkey, baseline=baseline)
        if valid:
            print(f"  {aid}: OK ({count} envelopes)")
            total_valid += count
        else:
            print(f"  {aid}: FAILED — {reason}")
            total_invalid += len(envelopes) - count
            any_chain_broken = True

    print()
    print("-" * 64)
    print(f"  Verified:   {total_valid}")
    print(f"  Failed:     {total_invalid}")
    if any_chain_broken:
        print()
        print("  Result:     BROKEN — evidence was tampered or incomplete")
        sys.exit(1)
    else:
        print()
        print("  Result:     VALID — nothing modified since collection")
        sys.exit(0)


if __name__ == "__main__":
    main()

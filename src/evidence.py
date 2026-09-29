"""
JOCKY Evidence Integrity Layer

Cryptographic signing + hash chaining for forensic findings.

Design:
  - Each agent has an Ed25519 signing keypair (private, public).
  - Every finding gets a SHA-256 hash of the finding string.
  - The hash is combined with the previous entry's chain_hash and metadata
    (agent_id, seq, timestamp) to produce this entry's chain_hash.
  - The chain_hash is signed with the agent's private key.
  - Result: an envelope that is (a) tamper-evident, (b) non-repudiable.

Verification:
  - Recompute chain_hash from stored fields.
  - Verify signature against the agent's public key.
  - Verify prev_chain_hash matches the previous entry's chain_hash.
  - Verify seq is strictly sequential (no gaps).

Attack resistance:
  - Modify finding     -> finding_sha256 mismatch
  - Modify metadata    -> chain_hash mismatch
  - Reorder entries    -> prev_chain_hash mismatch
  - Delete entries     -> seq gap detected
  - Insert fake entry  -> signature fails (attacker lacks private key)
  - Repudiate finding  -> Ed25519 signature is non-repudiable
"""

import base64
import hashlib
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


GENESIS_HASH = "GENESIS"  # sentinel for the first entry in every agent chain


# ---------- key management ----------

def generate_signing_keypair():
    """Generate a fresh Ed25519 keypair.
    Returns (private_key_obj, public_bytes_32)."""
    private = Ed25519PrivateKey.generate()
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private, public_bytes


def public_key_to_b64(public_bytes: bytes) -> str:
    return base64.b64encode(public_bytes).decode()


def public_key_from_b64(b64: str) -> Ed25519PublicKey:
    raw = base64.b64decode(b64)
    return Ed25519PublicKey.from_public_bytes(raw)


# ---------- primitives ----------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign_bytes(private_key: Ed25519PrivateKey, data: bytes) -> str:
    """Return base64-encoded Ed25519 signature."""
    sig = private_key.sign(data)
    return base64.b64encode(sig).decode()


def verify_signature(public_key: Ed25519PublicKey, data: bytes,
                     sig_b64: str) -> bool:
    try:
        public_key.verify(base64.b64decode(sig_b64), data)
        return True
    except (InvalidSignature, Exception):
        return False


def compute_chain_hash(finding_sha256: str,
                       prev_chain_hash: str,
                       seq: int,
                       agent_id: str,
                       timestamp: str) -> str:
    """Deterministic hash combining all metadata for a chain link."""
    payload = (
        finding_sha256
        + prev_chain_hash
        + str(seq)
        + agent_id
        + timestamp
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# ---------- envelope ----------

def make_envelope(finding_str: str,
                  private_key: Ed25519PrivateKey,
                  agent_id: str,
                  seq: int,
                  prev_chain_hash: str,
                  task_id: str,
                  script: str,
                  timestamp: Optional[str] = None) -> dict:
    """Create a signed, chained evidence envelope for one finding."""
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    finding_hash = sha256_hex(finding_str.encode("utf-8"))
    chain_hash = compute_chain_hash(
        finding_hash, prev_chain_hash, seq, agent_id, ts
    )
    signature = sign_bytes(private_key, chain_hash.encode("utf-8"))
    return {
        "agent_id": agent_id,
        "seq": seq,
        "timestamp": ts,
        "task_id": task_id,
        "script": script,
        "finding": finding_str,
        "finding_sha256": finding_hash,
        "prev_chain_hash": prev_chain_hash,
        "chain_hash": chain_hash,
        "signature": signature,
    }


def verify_envelope(envelope: dict,
                    public_key: Ed25519PublicKey,
                    expected_prev_chain_hash: str) -> tuple:
    """
    Verify a single envelope.
    Returns (valid: bool, reason: str).
    """
    required = [
        "agent_id", "seq", "timestamp", "task_id", "script",
        "finding", "finding_sha256", "prev_chain_hash",
        "chain_hash", "signature",
    ]
    for field in required:
        if field not in envelope:
            return False, f"missing field: {field}"

    # 1. Finding hash
    recomputed = sha256_hex(envelope["finding"].encode("utf-8"))
    if recomputed != envelope["finding_sha256"]:
        return False, "finding_sha256 mismatch (finding text was modified)"

    # 2. prev_chain_hash matches expected
    if envelope["prev_chain_hash"] != expected_prev_chain_hash:
        return False, (
            f"prev_chain_hash mismatch "
            f"(expected {expected_prev_chain_hash[:12]}..., "
            f"got {envelope['prev_chain_hash'][:12]}...)"
        )

    # 3. chain_hash
    recomputed_chain = compute_chain_hash(
        envelope["finding_sha256"],
        envelope["prev_chain_hash"],
        envelope["seq"],
        envelope["agent_id"],
        envelope["timestamp"],
    )
    if recomputed_chain != envelope["chain_hash"]:
        return False, "chain_hash mismatch (metadata was modified)"

    # 4. Signature
    if not verify_signature(
        public_key,
        envelope["chain_hash"].encode("utf-8"),
        envelope["signature"],
    ):
        return False, "signature invalid (not signed by this agent)"

    return True, "ok"


def verify_agent_chain(envelopes: list,
                       public_key: Ed25519PublicKey,
                       baseline: dict = None) -> tuple:
    """
    Verify a full per-agent chain.
    Envelopes sorted by seq ascending. Optional `baseline` = {"seq": N,
    "prev_chain_hash": "..."} tells the verifier where the agent's chain
    started (for resumed/continued chains across server restarts).
    Returns (valid: bool, reason: str, entries_verified: int).
    """
    if not envelopes:
        return True, "no entries", 0

    sorted_envs = sorted(envelopes, key=lambda e: e.get("seq", 0))
    if baseline:
        expected_prev = baseline.get("prev_chain_hash") or GENESIS_HASH
        expected_seq = int(baseline.get("seq") or 0) + 1
    else:
        expected_prev = GENESIS_HASH
        expected_seq = 1
    count = 0

    for env in sorted_envs:
        # Seq must be strictly sequential (no gaps, no duplicates)
        if env.get("seq") != expected_seq:
            return False, (
                f"seq gap at entry {count}: expected {expected_seq}, "
                f"got {env.get('seq')}"
            ), count

        ok, reason = verify_envelope(env, public_key, expected_prev)
        if not ok:
            return False, f"entry seq={env.get('seq')}: {reason}", count

        expected_prev = env["chain_hash"]
        expected_seq += 1
        count += 1

    return True, "ok", count

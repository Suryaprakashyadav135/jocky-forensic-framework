"""
JOCKY Server Dispatch Layer
Agent registry + command queue + result store.
"""
import base64, json, os, uuid
from datetime import datetime, timezone
from pathlib import Path
from flask import Blueprint, request, jsonify

from crypto import generate_keypair, derive_shared_secret, derive_aes_key, SecureSession

import hmac as _hmac
import os as _os

# Auth secrets (env override in production)
DISPATCH_TOKEN = _os.environ.get("JOCKY_DISPATCH_TOKEN", "jky-disp-dev")
AGENT_ENROLL_KEY = _os.environ.get("JOCKY_AGENT_ENROLL_KEY", "jky-enroll-dev")

def _check_token(provided, expected):
    if not provided or not expected:
        return False
    return _hmac.compare_digest(str(provided), str(expected))

dispatch_bp = Blueprint("dispatch", __name__)

AGENT_SESSIONS = {}
AGENT_IDENTITIES = {}
AGENT_PENDING = {}
AGENT_RESULTS = {}

LOG_DIR = Path("logs")
AGENTS_LOG = LOG_DIR / "agents.jsonl"
DISPATCH_LOG = LOG_DIR / "dispatch.jsonl"


def _log(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(data, default=str) + "\n")



# Evidence integrity: store signed envelopes per agent
AGENT_BASELINES = {}          # agent_id -> {seq, prev_chain_hash}
AGENT_PUBKEYS = {}          # agent_id -> base64 pubkey
EVIDENCE_STORE = {}         # agent_id -> list of envelopes
EVIDENCE_LOG = LOG_DIR / "evidence_chain.jsonl"


def _store_evidence(agent_id, envelopes, pubkey_b64):
    """Append signed envelopes to per-agent chain + persist to disk."""
    if agent_id not in EVIDENCE_STORE:
        EVIDENCE_STORE[agent_id] = []
    if pubkey_b64 and agent_id not in AGENT_PUBKEYS:
        AGENT_PUBKEYS[agent_id] = pubkey_b64

    for env in envelopes or []:
        EVIDENCE_STORE[agent_id].append(env)
        _log(EVIDENCE_LOG, env)


def _find_agent(ciphertext):
    for aid, sess in AGENT_SESSIONS.items():
        try:
            return aid, sess.decrypt(ciphertext)
        except Exception:
            continue
    return None, None


@dispatch_bp.route("/api/v1/agent/register", methods=["POST"])
def agent_register():
    body = request.get_json(silent=True) or {}
    if not _check_token(body.get("enroll_key"), AGENT_ENROLL_KEY):
        return jsonify({"error": "enrollment key rejected"}), 403
    try:
        pub_C = base64.urlsafe_b64decode(body["pub"].encode())
        identity = body.get("identity", {})
        agent_id = identity.get("agent_id")
    except Exception as e:
        return jsonify({"error": f"bad request: {e}"}), 400
    if not agent_id:
        return jsonify({"error": "missing agent_id"}), 400

    priv_S, pub_S = generate_keypair()
    pub_S_b64 = base64.urlsafe_b64encode(pub_S).decode()
    shared = derive_shared_secret(priv_S, pub_C)
    sid = base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")
    aes_key = derive_aes_key(shared, salt=sid.encode())

    AGENT_SESSIONS[agent_id] = SecureSession(aes_key, session_id=sid)
    now = datetime.now(timezone.utc).isoformat()
    AGENT_IDENTITIES[agent_id] = {**identity, "connected_at": now,
                                  "last_seen": now, "session_id": sid}

    # Evidence integrity: capture agent signing pubkey + chain baseline
    agent_pubkey = body.get("agent_pubkey")
    if agent_pubkey:
        AGENT_PUBKEYS[agent_id] = agent_pubkey
        AGENT_BASELINES[agent_id] = {
            "seq": int(body.get("agent_seq") or 0),
            "prev_chain_hash": body.get("agent_prev_chain_hash") or "GENESIS",
        }
        print(f"[dispatch] agent pubkey registered: {agent_id} "
              f"(baseline seq={AGENT_BASELINES[agent_id]['seq']})", flush=True)
    AGENT_PENDING.setdefault(agent_id, [])
    AGENT_RESULTS.setdefault(agent_id, [])

    _log(AGENTS_LOG, {"event": "register", "ts": now, "agent_id": agent_id,
                      "identity": identity, "session_id": sid})
    print(f"\n[dispatch] agent registered: {agent_id} "
          f"({identity.get('hostname')} @ {identity.get('ip')})", flush=True)
    return jsonify({"pub": pub_S_b64, "session_id": sid}), 200


@dispatch_bp.route("/api/v1/agent/poll", methods=["POST"])
def agent_poll():
    body = request.get_json(silent=True) or {}
    ct = body.get("d", "")
    if not ct:
        return jsonify({"error": "no payload"}), 400
    aid, decoded = _find_agent(ct)
    if not aid:
        return jsonify({"error": "no session"}), 400
    AGENT_IDENTITIES[aid]["last_seen"] = datetime.now(timezone.utc).isoformat()
    cmds = list(AGENT_PENDING.get(aid, []))
    AGENT_PENDING[aid] = []
    resp_ct = AGENT_SESSIONS[aid].encrypt({"commands": cmds})
    return jsonify({"response_ct": resp_ct}), 200


@dispatch_bp.route("/api/v1/agent/report", methods=["POST"])
def agent_report():
    body = request.get_json(silent=True) or {}
    ct = body.get("d", "")
    aid, decoded = _find_agent(ct)
    if not aid:
        return jsonify({"error": "no session"}), 400
    result = decoded.get("result", {})
    AGENT_RESULTS.setdefault(aid, []).append(result)

    # Evidence integrity: store signed envelopes + agent pubkey
    pubkey_b64 = decoded.get("agent_pubkey") or result.get("agent_pubkey")
    envelopes = result.get("envelopes", [])
    if envelopes:
        _store_evidence(aid, envelopes, pubkey_b64)
        print(f"[dispatch] stored {len(envelopes)} signed envelopes from {aid}", flush=True)
    if pubkey_b64 and aid not in AGENT_PUBKEYS:
        AGENT_PUBKEYS[aid] = pubkey_b64
        print(f"[dispatch] registered pubkey for {aid}", flush=True)
    AGENT_IDENTITIES[aid]["last_seen"] = datetime.now(timezone.utc).isoformat()
    _log(DISPATCH_LOG, {"event": "report", "ts":
         datetime.now(timezone.utc).isoformat(),
         "agent_id": aid, "result": result})
    n = len(result.get("findings", []))
    print(f"\n[dispatch] result from {aid}: "
          f"{result.get('script')} → {n} findings", flush=True)
    return jsonify({"status": "ok"}), 200


@dispatch_bp.route("/api/v1/agent/heartbeat", methods=["POST"])
def agent_heartbeat():
    body = request.get_json(silent=True) or {}
    aid, _ = _find_agent(body.get("d", ""))
    if aid:
        AGENT_IDENTITIES[aid]["last_seen"] = datetime.now(timezone.utc).isoformat()
        return jsonify({"status": "ok"}), 200
    return jsonify({"status": "unknown"}), 200


@dispatch_bp.route("/api/v1/dispatch", methods=["POST"])
def dispatch_command():
    body = request.get_json(silent=True) or {}
    token = body.get("token") or request.headers.get("X-Jocky-Token")
    if not _check_token(token, DISPATCH_TOKEN):
        return jsonify({"error": "dispatch token rejected"}), 403
    script = body.get("script")
    agents = body.get("agents") or list(AGENT_IDENTITIES.keys())
    if not script:
        return jsonify({"error": "missing script"}), 400
    dispatched = []
    for aid in agents:
        if aid not in AGENT_IDENTITIES:
            continue
        task_id = uuid.uuid4().hex
        AGENT_PENDING.setdefault(aid, []).append({
            "task_id": task_id, "script": script,
            "dispatched_at": datetime.now(timezone.utc).isoformat(),
        })
        dispatched.append({"agent_id": aid, "task_id": task_id})
        _log(DISPATCH_LOG, {"event": "dispatch",
             "ts": datetime.now(timezone.utc).isoformat(),
             "agent_id": aid, "task_id": task_id, "script": script})
    print(f"\n[dispatch] {script} → {len(dispatched)} agent(s)", flush=True)
    return jsonify({"status": "ok", "script": script,
                    "dispatched_to": dispatched, "count": len(dispatched)}), 200


@dispatch_bp.route("/api/v1/correlations", methods=["GET"])
def get_correlations():
    """Compute live correlations across all signed envelopes."""
    # Import here to avoid circular dependency at module load
    from correlate_live import compute_correlations
    return jsonify(compute_correlations()), 200


@dispatch_bp.route("/api/v1/evidence/summary", methods=["GET"])
def evidence_summary():
    """Return evidence integrity summary for all agents."""
    summary = []
    for aid in AGENT_IDENTITIES:
        chain = EVIDENCE_STORE.get(aid, [])
        summary.append({
            "agent_id": aid,
            "envelopes": len(chain),
            "has_pubkey": aid in AGENT_PUBKEYS,
            "head_chain_hash": chain[-1]["chain_hash"] if chain else None,
            "last_seq": chain[-1]["seq"] if chain else 0,
        })
    return jsonify({
        "agents": summary,
        "total_envelopes": sum(s["envelopes"] for s in summary),
        "agents_with_keys": sum(1 for s in summary if s["has_pubkey"]),
    }), 200


@dispatch_bp.route("/api/v1/evidence/<agent_id>", methods=["GET"])
def evidence_agent(agent_id):
    """Return all envelopes for one agent."""
    if agent_id not in AGENT_IDENTITIES:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "agent_id": agent_id,
        "pubkey": AGENT_PUBKEYS.get(agent_id),
        "envelopes": EVIDENCE_STORE.get(agent_id, []),
    }), 200


@dispatch_bp.route("/api/v1/evidence/pubkeys", methods=["GET"])
def evidence_pubkeys():
    """Return all agent pubkeys (for third-party verification)."""
    return jsonify({
        "pubkeys": AGENT_PUBKEYS,
        "count": len(AGENT_PUBKEYS),
    }), 200


@dispatch_bp.route("/api/v1/agents", methods=["GET"])
def list_agents():
    out = []
    for aid, ident in AGENT_IDENTITIES.items():
        results = AGENT_RESULTS.get(aid, [])
        total = sum(len(r.get("findings", [])) for r in results)
        out.append({
            "agent_id": aid, "hostname": ident.get("hostname"),
            "ip": ident.get("ip"), "os": ident.get("os"),
            "os_release": ident.get("os_release"), "user": ident.get("user"),
            "connected_at": ident.get("connected_at"),
            "last_seen": ident.get("last_seen"),
            "session_id": ident.get("session_id"),
            "pending_commands": len(AGENT_PENDING.get(aid, [])),
            "results_count": len(results), "total_findings": total,
        })
    return jsonify({"agents": out, "count": len(out)}), 200


@dispatch_bp.route("/api/v1/agents/<agent_id>", methods=["GET"])
def get_agent(agent_id):
    if agent_id not in AGENT_IDENTITIES:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "identity": AGENT_IDENTITIES[agent_id],
        "pending": AGENT_PENDING.get(agent_id, []),
        "results": AGENT_RESULTS.get(agent_id, []),
    }), 200

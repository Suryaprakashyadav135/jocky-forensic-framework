"""

JOCKY Framework — Module 2c: Mock CDN + C2 Backend (Crypto v1.0)
ECDH handshake + AES-256-GCM decryption.
"""

from flask import Flask, request, jsonify
import base64
import json
import hashlib
import os
import platform
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
import sys
import sys as _sys

sys.path.insert(0, str(Path(__file__).parent))
from protocol import (
    CommandRequest, CommandResponse,
    COMMAND_REGISTRY, validate_command,
    PROTOCOL_VERSION,
)
from crypto import generate_keypair, derive_shared_secret, derive_aes_key, SecureSession
from dashboard import dashboard_bp
from dispatch import dispatch_bp
app = Flask(__name__)

C2_LOG = Path("logs/c2_backend.log")
TRAFFIC_LOG = Path("logs/traffic.log")
TASK_STORE = Path("logs/tasks.jsonl")
SESSION_STORE = Path("logs/sessions.jsonl")

C2_LOG.parent.mkdir(parents=True, exist_ok=True)

FRONT_DOMAIN = "127.0.0.1:8080"
BACKEND_DOMAIN = "c2.hidden.internal"

# In-memory session table (server-side)
SESSIONS: dict[str, SecureSession] = {}


# ---------- Command handlers (same as before) ----------
def cmd_collect_system_info(args):
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "arch": platform.machine(),
        "kernel": platform.release(),
        "python": platform.python_version(),
    }

def cmd_enumerate_network_connections(args):
    return {
        "proto": args.get("proto", "tcp"),
        "connections": [
            {"proto": "tcp", "local": "127.0.0.1:8080", "remote": "127.0.0.1:54321", "state": "ESTABLISHED"},
            {"proto": "tcp", "local": "0.0.0.0:22", "remote": "—", "state": "LISTEN"},
        ]
    }


def cmd_list_processes(args):
    return {
        "limit": args.get("limit", 20),
        "processes": [
            {"pid": 1, "name": "systemd", "user": "root"},
            {"pid": 842, "name": "sshd", "user": "root"},
            {"pid": 1204, "name": "bash", "user": "kali"},
        ][:args.get("limit", 20)],
    }

def cmd_check_persistence(args):
    return {
        "checked_locations": [
            "/etc/crontab", "~/.bashrc", "~/.profile",
            "/etc/systemd/system/", "~/.config/autostart/",
        ],
        "suspicious_entries": [],
        "note": "demo",
    }

# Real forensic handlers — replaces demo stubs
_sys.path.insert(0, str(Path(__file__).parent))

# Real forensic handlers — basic + deep
from forensic_real import REAL_HANDLERS as BASIC_HANDLERS
from forensic_deep import DEEP_HANDLERS, generate_report

COMMAND_HANDLERS = {**BASIC_HANDLERS, **DEEP_HANDLERS}


def cmd_generate_forensic_report(args):
    """Run all deep handlers, produce full analysis report."""
    import json as _json
    results = {}
    for name, handler in DEEP_HANDLERS.items():
        try:
            results[name] = handler(args)
        except Exception as e:
            results[name] = {"error": str(e), "count": 0}
    report = generate_report(results)
    return report


COMMAND_HANDLERS["generate_forensic_report"] = cmd_generate_forensic_report
def log_jsonl(path: Path, data: dict):
    with path.open("a") as f:
        f.write(json.dumps(data) + "\n")


# ---------- Handshake endpoint ----------
@app.route("/api/v1/handshake", methods=["POST"])
def handshake():
    body = request.get_json(silent=True) or {}
    try:
        pub_C = base64.urlsafe_b64decode(body["pub"].encode())
    except Exception as e:
        return jsonify({"error": f"bad pub key: {e}"}), 400

    priv_S, pub_S = generate_keypair()
    pub_S_b64 = base64.urlsafe_b64encode(pub_S).decode()

    shared = derive_shared_secret(priv_S, pub_C)
    sid = base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")
    aes_key = derive_aes_key(shared, salt=sid.encode())

    SESSIONS[sid] = SecureSession(aes_key, session_id=sid)

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": sid,

        "shared_secret_sha256": hashlib.sha256(shared).hexdigest()[:16],
    }
    log_jsonl(SESSION_STORE, entry)

    print("\n" + "=" * 70)
    print(f"[HANDSHAKE] New session: {sid}")
    print(f"  Shared secret sha256: {entry['shared_secret_sha256']}")

    return jsonify({"pub": pub_S_b64, "session_id": sid}), 200


# ---------- Command endpoint ----------
@app.route("/api/v1/telemetry", methods=["POST"])
@app.route("/api/v1/metrics", methods=["POST"])
@app.route("/api/v1/events", methods=["POST"])
def c2_endpoint():
    host_header = request.headers.get("Host", "")
    ua = request.headers.get("User-Agent", "")
    req_id = request.headers.get("X-Request-ID", "")

    body = request.get_json(silent=True) or {}
    ciphertext = body.get("d", "")

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
	"source_ip": request.remote_addr,
        "sni": FRONT_DOMAIN,
        "host_header": host_header,
	
        "endpoint": request.path,
        "user_agent": ua[:60],
        "request_id": req_id,
        "ciphertext_len": len(ciphertext),
        "ciphertext_hash": hashlib.sha256(ciphertext.encode()).hexdigest()[:16],
    }
    log_jsonl(TRAFFIC_LOG, entry)

    # Try every session to find which one decrypts
    decrypted = None
    matched_sid = None
    for sid, sess in SESSIONS.items():
        try:
            decrypted = sess.decrypt(ciphertext, expected_counter=None)
            matched_sid = sid
            break
        except Exception:
            continue

    if decrypted is None:
        print("\n[C2] Decryption failed — no matching session")
        return jsonify({"status": "error", "error": "decryption failed"}), 400

    # Build request from decrypted
    try:
        req = CommandRequest.from_dict(decrypted)
    except Exception as e:
        return jsonify({"status": "error", "error": f"bad request: {e}"}), 400

    print("\n" + "=" * 70)
    print(f"[C2 RECEIVED] {entry['ts']}")
    print(f"  SNI (outer)     : {entry['sni']}")
    print(f"  Host (inner)    : {entry['host_header']}")
    print(f"  Session ID      : {matched_sid}")
    print(f"  Task ID         : {req.task_id}")
    print(f"  Command         : {req.command}")
    print(f"  Args            : {req.args}")

    valid, msg = validate_command(req.command, req.args)
    if not valid:
        resp = CommandResponse(task_id=req.task_id, status="error", error=msg)
        ct_out = SESSIONS[matched_sid].encrypt(resp.to_dict())
        return jsonify({"response_ct": ct_out}), 200

    handler = COMMAND_HANDLERS.get(req.command)
    try:
        result = handler(req.args)
        resp = CommandResponse(task_id=req.task_id, status="complete", result=result)
        print(f"  Result          : {json.dumps(result)[:80]}...")
    except Exception as e:
        resp = CommandResponse(task_id=req.task_id, status="error", error=str(e))

    handler = COMMAND_HANDLERS.get(req.command)
    try:
        result = handler(req.args)
        resp = CommandResponse(task_id=req.task_id, status="complete", result=result)
        print(f"  Result          : {json.dumps(result)[:80]}...")
    except Exception as e:
        resp = CommandResponse(task_id=req.task_id, status="error", error=str(e))

    log_jsonl(C2_LOG, {**entry, "session_id": matched_sid, "response": resp.to_dict()})
    log_jsonl(TASK_STORE, {
        **resp.to_dict(),
        "session_id": matched_sid,
        "command": req.command,
        "args": req.args,
    })

    ct_out = SESSIONS[matched_sid].encrypt(resp.to_dict())
    return jsonify({"response_ct": ct_out}), 200


@app.route("/api/v1/commands", methods=["GET"])
def list_commands():
    return jsonify({"version": PROTOCOL_VERSION, "commands": COMMAND_REGISTRY})


@app.route("/static/<path:sub>", methods=["GET"])
@app.route("/assets/<path:sub>", methods=["GET"])
@app.route("/cdn-cgi/trace", methods=["GET"])
@app.route("/favicon.ico", methods=["GET"])
def dummy_cdn(sub=None):
    print(f"[DUMMY] {request.path}")
    return "", 204


@app.route("/", methods=["GET"])
def index():
    return jsonify({"service": "JOCKY C2 — Crypto v1.0"})


app.register_blueprint(dashboard_bp)
app.register_blueprint(dispatch_bp)

if __name__ == "__main__":
    print("=" * 70)
    print("JOCKY Mock CDN + C2 Backend — Crypto v1.0")
    print(f"  Front          : http://{FRONT_DOMAIN}")
    print(f"  Handshake      : POST /api/v1/handshake")
    print(f"  Commands       : POST /api/v1/{{telemetry,metrics,events}}")
    print(f"  Dashboard      : http://{FRONT_DOMAIN}/dashboard")
    print("=" * 70)
    app.run(host="0.0.0.0", port=8080, debug=False)

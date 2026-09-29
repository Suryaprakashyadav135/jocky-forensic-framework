#!/usr/bin/env python3
"""
JOCKY Persistent Agent
Runs on each endpoint. Connects to server, polls for commands,
executes forensic scripts file-less, reports findings back.
"""
import base64, io, json, os, platform, random, signal, socket, subprocess
import sys, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import urllib3.util.connection as _u3_conn
_u3_conn.HAS_IPV6 = False  # namespaces/VM have no working IPv6
import requests
from crypto import generate_keypair, derive_shared_secret, derive_aes_key, SecureSession

from evidence import (
    generate_signing_keypair, public_key_to_b64,
    make_envelope, GENESIS_HASH,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT = Path(os.environ.get("JOCKY_ROOT", Path(__file__).resolve().parent.parent))


class JockyAgent:
    def __init__(self, server_url, agent_id=None, jitter=(3.0, 8.0)):
        self.server_url = server_url.rstrip("/")
        self.agent_id = agent_id or f"agent-{uuid.uuid4().hex[:12]}"
        self.jitter = jitter
        self.session = None
        self.session_id = None
        self.running = True
        self.binary_cache = {}

        # Evidence integrity: signing key + chain state
        self.state_dir = Path("/home/kali/Rudhra/Jocky/logs")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.agent_key_path = self.state_dir / f"agent_{self.agent_id}.key"
        self.pubkey_path = self.state_dir / f"agent_{self.agent_id}.pub"
        self.state_path = self.state_dir / f"agent_{self.agent_id}.state"
        self.signing_key = None
        self.public_key_b64 = None
        self.chain_seq = 0
        self.prev_chain_hash = GENESIS_HASH
        self._load_or_generate_key()
        self._load_chain_state()

        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def _shutdown(self, *_):
        self.running = False

    def _load_or_generate_key(self):
        if self.agent_key_path.exists() and self.pubkey_path.exists():
            try:
                raw = self.agent_key_path.read_bytes()
                self.signing_key = Ed25519PrivateKey.from_private_bytes(raw)
                self.public_key_b64 = self.pubkey_path.read_text().strip()
                print(f"[agent] loaded signing key for {self.agent_id}", flush=True)
                return
            except Exception as e:
                print(f"[agent] key load failed: {e} -- regenerating", flush=True)

        priv, pub = generate_signing_keypair()
        raw_priv = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.agent_key_path.write_bytes(raw_priv)
        try:
            self.agent_key_path.chmod(0o600)
        except Exception:
            pass
        self.pubkey_path.write_text(public_key_to_b64(pub))
        self.signing_key = priv
        self.public_key_b64 = public_key_to_b64(pub)
        print(f"[agent] generated new signing key for {self.agent_id}", flush=True)

    def _load_chain_state(self):
        if self.state_path.exists():
            try:
                import json as _json
                data = _json.loads(self.state_path.read_text())
                self.chain_seq = int(data.get("seq", 0))
                self.prev_chain_hash = data.get("prev_chain_hash", GENESIS_HASH)
                print(f"[agent] resumed chain at seq={self.chain_seq}", flush=True)
            except Exception:
                pass

    def _save_chain_state(self):
        import json as _json
        self.state_path.write_text(_json.dumps({
            "seq": self.chain_seq,
            "prev_chain_hash": self.prev_chain_hash,
        }))

    def _sign_findings(self, findings, task_id, script):
        envelopes = []
        for f in findings:
            self.chain_seq += 1
            env = make_envelope(
                finding_str=f,
                private_key=self.signing_key,
                agent_id=self.agent_id,
                seq=self.chain_seq,
                prev_chain_hash=self.prev_chain_hash,
                task_id=task_id,
                script=script,
            )
            envelopes.append(env)
            self.prev_chain_hash = env["chain_hash"]
        self._save_chain_state()
        return envelopes

    def _identity(self):
        hostname = os.environ.get("JOCKY_HOSTNAME")
        if not hostname:
            try:
                hostname = socket.gethostname()
            except Exception:
                hostname = "unknown"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            ip = "127.0.0.1"
        return {
            "agent_id": self.agent_id,
            "hostname": hostname,
            "os": platform.system(),
            "os_release": platform.release(),
            "arch": platform.machine(),
            "ip": ip,
            "pid": os.getpid(),
            "user": os.environ.get("USER", "unknown"),
            "started_at": datetime.now(timezone.utc).isoformat(),
        }

    def register(self):
        priv_C, pub_C = generate_keypair()
        pub_C_b64 = base64.urlsafe_b64encode(pub_C).decode()
        identity = self._identity()
        r = requests.post(
            f"{self.server_url}/api/v1/agent/register",
            json={
                "pub": pub_C_b64,
                "identity": identity,
                "ver": "1.0",
                "enroll_key": os.environ.get("JOCKY_AGENT_ENROLL_KEY", "jky-enroll-dev"),
                "agent_pubkey": self.public_key_b64,
                "agent_seq": self.chain_seq,
                "agent_prev_chain_hash": self.prev_chain_hash,
            },
            timeout=15,
        )
        body = r.json()
        pub_S = base64.urlsafe_b64decode(body["pub"].encode())
        sid = body["session_id"]
        shared = derive_shared_secret(priv_C, pub_S)
        aes_key = derive_aes_key(shared, salt=sid.encode())
        self.session = SecureSession(aes_key, session_id=sid)
        self.session_id = sid
        print(f"[agent] registered: session={sid}", flush=True)
        print(f"[agent] identity: {identity['hostname']} @ {identity['ip']}", flush=True)
        return True

    def poll(self):
        if not self.session:
            return []
        payload = {"agent_id": self.agent_id, "_ctr": self.session.counter}
        try:
            ct = self.session.encrypt(payload)
            r = requests.post(
                f"{self.server_url}/api/v1/agent/poll",
                json={"d": ct}, timeout=10,
            )
            # Session invalid (server restarted) — re-register
            if r.status_code in (400, 401, 403):
                print(f"[agent] session invalid (HTTP {r.status_code}) — re-registering", flush=True)
                self.session = None
                try:
                    self.register()
                except Exception as e:
                    print(f"[agent] re-register failed: {e}", flush=True)
                return []
            body = r.json()
            if "response_ct" not in body:
                return []
            response = self.session.decrypt(body["response_ct"])
            return response.get("commands", [])
        except Exception as e:
            print(f"[agent] poll error: {e}", flush=True)
            return []

    def _compile(self, script_name):
        if script_name in self.binary_cache:
            b = self.binary_cache[script_name]
            if Path(b).exists():
                return b
        jky = ROOT / "jocky_scripts" / f"{script_name}.jky"
        if not jky.exists():
            print(f"[agent] script not found: {jky}", flush=True)
            return None
        print(f"[agent] compiling {script_name}...", flush=True)

        # Serialize builds across all agents (concurrent builds race on /tmp paths)
        import fcntl
        lock_path = "/tmp/jocky_build.lock"
        with open(lock_path, "w") as lock_fp:
            print(f"[agent] waiting for build lock...", flush=True)
            fcntl.flock(lock_fp, fcntl.LOCK_EX)
            print(f"[agent] acquired build lock", flush=True)
            try:
                result = subprocess.run(
                    ["bash", str(ROOT / "build_jocky.sh"), str(jky)],
                    capture_output=True, text=True, timeout=180, cwd=str(ROOT),
                )
            finally:
                fcntl.flock(lock_fp, fcntl.LOCK_UN)
                print(f"[agent] released build lock", flush=True)
        if result.returncode != 0:
            print(f"[agent] compile failed: {result.stderr[-300:]}", flush=True)
            return None
        binary = f"/tmp/{script_name}_final.bin"
        if not Path(binary).exists():
            return None
        self.binary_cache[script_name] = binary
        return binary

    def _execute_fileless_capture(self, binary_path):
        """Execute via memfd, redirect fd 1 to temp file, read output."""
        from memfd_exec import execute_from_memory
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tmp = tf.name
        saved = os.dup(1)
        fd = os.open(tmp, os.O_WRONLY)
        os.dup2(fd, 1)
        os.close(fd)
        try:
            execute_from_memory(binary_path, verbose=False)
        finally:
            os.dup2(saved, 1)
            os.close(saved)
        out = Path(tmp).read_bytes()
        os.unlink(tmp)
        return out.decode("utf-8", errors="replace")

    def execute(self, cmd):
        script = cmd.get("script")
        task_id = cmd.get("task_id")
        if not script:
            return {"task_id": task_id, "status": "error", "error": "no script"}
        print(f"[agent] executing {task_id[:8]}: {script}", flush=True)
        binary = self._compile(script)
        if not binary:
            return {"task_id": task_id, "status": "error",
                    "error": f"compile failed: {script}"}
        try:
            output = self._execute_fileless_capture(binary)
        except Exception as e:
            return {"task_id": task_id, "status": "error", "error": str(e)}

        findings, stats, hashes = [], {}, []
        for line in output.splitlines():
            if line.startswith("EMIT FINDING = "):
                findings.append(line[len("EMIT FINDING = "):])
            elif line.startswith("EMIT STAT_"):
                payload = line[len("EMIT STAT_"):]
                if " = " in payload:
                    k, v = payload.split(" = ", 1)
                    stats[k] = v
            elif line.startswith("EMIT HASH = "):
                hashes.append(line[len("EMIT HASH = "):])
        # Sign every finding with the agent's Ed25519 key
        envelopes = self._sign_findings(findings, task_id, script)

        return {
            "task_id": task_id, "status": "complete", "script": script,
            "findings": findings,
            "envelopes": envelopes,
            "stats": stats,
            "hash_count": len(hashes),
            "output_lines": len(output.splitlines()),
            "agent_pubkey": self.public_key_b64,
            "agent_seq_end": self.chain_seq,
            "agent_chain_head": self.prev_chain_hash,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

    def report(self, result):
        if not self.session:
            return
        try:
            payload = {
                "agent_id": self.agent_id,
                "_ctr": self.session.counter,
                "agent_pubkey": self.public_key_b64,
                "result": result,
            }
            ct = self.session.encrypt(payload)
            requests.post(f"{self.server_url}/api/v1/agent/report",
                          json={"d": ct}, timeout=10)
        except Exception as e:
            print(f"[agent] report error: {e}", flush=True)

    def heartbeat(self):
        if not self.session:
            return
        try:
            ct = self.session.encrypt({"agent_id": self.agent_id, "_ctr":
                                       self.session.counter})
            requests.post(f"{self.server_url}/api/v1/agent/heartbeat",
                          json={"d": ct}, timeout=5)
        except Exception:
            pass

    def run(self):
        print(f"[agent] starting: {self.agent_id}", flush=True)
        retries = 0
        while self.running and retries < 100:
            try:
                if self.register():
                    break
            except Exception as e:
                print(f"[agent] register failed: {e}", flush=True)
                retries += 1
                time.sleep(min(5 * retries, 30))
        if not self.session:
            print("[agent] failed to register", flush=True)
            return
        last_hb = time.time()
        while self.running:
            for cmd in self.poll():
                self.report(self.execute(cmd))
            if time.time() - last_hb > 30:
                self.heartbeat()
                last_hb = time.time()
            time.sleep(random.uniform(*self.jitter))
        print("[agent] shutdown", flush=True)


def main():
    url = os.environ.get("JOCKY_SERVER", "http://127.0.0.1:8080")
    aid = os.environ.get("JOCKY_AGENT_ID")
    jmin = float(os.environ.get("JOCKY_JITTER_MIN", "3.0"))
    jmax = float(os.environ.get("JOCKY_JITTER_MAX", "8.0"))
    JockyAgent(url, aid, (jmin, jmax)).run()


if __name__ == "__main__":
    main()

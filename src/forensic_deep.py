"""
JOCKY Framework — Module 14: Deep Forensic Handlers

8 modules of real, deep forensic analysis on Linux. Each handler reads
kernel/userspace artifacts that a normal forensic tool would access —
operations that modern EDR/AV flag as suspicious when performed by
unsigned or unrecognized binaries.

These handlers run inside JOCKY-compiled, file-less, polymorphic
binaries so their signatures never appear on disk.

Categories:
  1. Process forensics       — deep /proc/*/ inspection
  2. Network forensics       — sockets, ARP, DNS, routing
  3. Persistence forensics   — cron, systemd, shell profiles, SSH
  4. Filesystem forensics    — recent files, hidden execs, setuid
  5. Log forensics           — auth, syslog, wtmp, journal, history
  6. Memory forensics        — LKMs, maps anomalies, kernel symbols
  7. User forensics          — sessions, sudo, groups, SSH keys
  8. IOC hunting             — hash suspicious binaries, YARA-lite patterns

Every handler returns a dict with:
  - "artifacts": list of findings
  - "count": number of findings
  - "note": any access limitations (permissions, missing files)
"""

import os
import re
import glob
import json
import socket
import hashlib
import subprocess
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------- Utilities ----------

def _read_text(path: str, max_bytes: int = 65536, errors: str = "replace") -> str:
    """Read a file safely, return empty string on failure."""
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors=errors)
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def _read_bytes(path: str, max_bytes: int = 65536) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes)
    except (FileNotFoundError, PermissionError, OSError):
        return b""


def _list_dir(path: str) -> list:
    try:
        return os.listdir(path)
    except (FileNotFoundError, PermissionError, OSError):
        return []


def _sha256(path: str, max_bytes: int = 32 * 1024 * 1024) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            remaining = max_bytes
            while remaining > 0:
                chunk = f.read(min(65536, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def _readlink_safe(path: str) -> str:
    try:
        return os.readlink(path)
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def _stat_dict(path: str) -> dict:
    try:
        s = os.stat(path)
        return {
            "size": s.st_size,
            "mode": oct(s.st_mode),
            "uid": s.st_uid,
            "gid": s.st_gid,
            "mtime": int(s.st_mtime),
            "ctime": int(s.st_ctime),
            "atime": int(s.st_atime),
        }
    except (FileNotFoundError, PermissionError, OSError):
        return {}


# ---------- 1. Process Forensics ----------

def forensic_process(args: dict) -> dict:
    """
    Deep inspection of every process on the system.
    For each PID: cmdline, exe, cwd, environ, open fds, memory maps,
    network sockets, parent chain.
    """
    include_env = args.get("include_env", False)
    max_procs = args.get("limit", 500)

    processes = []
    for pid_str in _list_dir("/proc"):
        if not pid_str.isdigit():
            continue
        pid = int(pid_str)
        if len(processes) >= max_procs:
            break

        base = f"/proc/{pid}"

        # Skip if process is gone
        if not os.path.exists(base):
            continue

        cmdline_raw = _read_bytes(f"{base}/cmdline", 4096)
        cmdline = cmdline_raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()

        try:
            status_txt = _read_text(f"{base}/status", 4096)
        except Exception:
            status_txt = ""

        proc = {
            "pid": pid,
            "cmdline": cmdline[:500],
            "exe": _readlink_safe(f"{base}/exe"),
            "cwd": _readlink_safe(f"{base}/cwd"),
            "root": _readlink_safe(f"{base}/root"),
        }

        # Parse /proc/PID/status for key fields
        for line in status_txt.splitlines():
            if line.startswith("Name:"):
                proc["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("PPid:"):
                proc["ppid"] = int(line.split(":", 1)[1].strip())
            elif line.startswith("Uid:"):
                proc["uid"] = int(line.split()[1])
            elif line.startswith("Gid:"):
                proc["gid"] = int(line.split()[1])
            elif line.startswith("State:"):
                proc["state"] = line.split(":", 1)[1].strip()
            elif line.startswith("VmRSS:"):
                proc["rss_kb"] = line.split()[1]
            elif line.startswith("Threads:"):
                proc["threads"] = int(line.split()[1])

        # Open file descriptors
        fd_dir = f"{base}/fd"
        open_fds = []
        for fd in _list_dir(fd_dir):
            target = _readlink_safe(f"{fd_dir}/{fd}")
            if target and fd.isdigit():
                open_fds.append({"fd": int(fd), "target": target})
        proc["open_fds"] = open_fds[:50]

        # Memory maps summary — count executable regions
        maps = _read_text(f"{base}/maps", 65536)
        exec_regions = 0
        rwx_regions = 0
        for line in maps.splitlines():
            if " r-xp " in line or " r-xs " in line:
                exec_regions += 1
            if " rwxp " in line:
                rwx_regions += 1
        proc["map_exec_regions"] = exec_regions
        proc["map_rwx_regions"] = rwx_regions
        if rwx_regions > 0:
            proc["_flag"] = "RWX_MEMORY_REGION"  # strong indicator of injected code

        if include_env:
            env_raw = _read_bytes(f"{base}/environ", 8192)
            env_vars = env_raw.replace(b"\x00", b"\n").decode("utf-8", errors="replace").strip()
            proc["environ"] = env_vars[:2000]

        processes.append(proc)

    # Flag suspicious patterns
    suspicious = []
    for p in processes:
        reasons = []
        if p.get("_flag") == "RWX_MEMORY_REGION":
            reasons.append("has RWX memory region (possible shellcode)")
        if p.get("exe") and "/tmp/" in p["exe"]:
            reasons.append(f"executing from /tmp: {p['exe']}")
        if p.get("exe") and "/dev/shm/" in p["exe"]:
            reasons.append(f"executing from /dev/shm: {p['exe']}")
        if p.get("exe") and "(deleted)" in p["exe"]:
            reasons.append(f"executable deleted while running: {p['exe']}")
        if reasons:
            suspicious.append({"pid": p["pid"], "name": p.get("name"), "reasons": reasons})

    return {
        "artifacts": processes,
        "count": len(processes),
        "suspicious": suspicious,
        "suspicious_count": len(suspicious),
        "note": "requires root for full inspection; some /proc/PID/* unreadable for other users",
    }


# ---------- 2. Network Forensics ----------

def forensic_network(args: dict) -> dict:
    """
    Network state: sockets, ARP, DNS cache, routing, listening ports.
    Parses /proc/net/* directly — a raw approach that bypasses libc
    network APIs and avoids triggering userland hooks.
    """
    findings = {}

    # TCP connections
    tcp_txt = _read_text("/proc/net/tcp", 1 << 20)
    tcp6_txt = _read_text("/proc/net/tcp6", 1 << 20)
    udp_txt = _read_text("/proc/net/udp", 1 << 20)
    udp6_txt = _read_text("/proc/net/udp6", 1 << 20)

    def parse_proc_net(txt: str, proto: str) -> list:
        rows = []
        lines = txt.splitlines()[1:]  # skip header
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[1]
            remote = parts[2]
            state_hex = parts[3]
            rows.append({
                "proto": proto,
                "local": _hex_addr(local),
                "remote": _hex_addr(remote),
                "state": _tcp_state(state_hex) if proto.startswith("tcp") else "—",
                "inode": parts[9] if len(parts) > 9 else "",
            })
        return rows

    findings["tcp"] = parse_proc_net(tcp_txt, "tcp")
    findings["tcp6"] = parse_proc_net(tcp6_txt, "tcp6")
    findings["udp"] = parse_proc_net(udp_txt, "udp")
    findings["udp6"] = parse_proc_net(udp6_txt, "udp6")

    # ARP cache
    arp = []
    for line in _read_text("/proc/net/arp", 1 << 16).splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6:
            arp.append({
                "ip": parts[0],
                "hw_type": parts[1],
                "flags": parts[2],
                "mac": parts[3],
                "device": parts[5],
            })
    findings["arp"] = arp

    # Routing table
    routes = []
    for line in _read_text("/proc/net/route", 1 << 16).splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 8:
            routes.append({
                "iface": parts[0],
                "destination": _hex_ipv4(parts[1]),
                "gateway": _hex_ipv4(parts[2]),
                "flags": parts[3],
            })
    findings["routes"] = routes

    # Listening ports (parsed from tcp above, state = LISTEN)
    listeners = [c for c in findings["tcp"] if c["state"] == "LISTEN"]

    # Suspicious: unusual listening ports (not 22/80/443/8080)
    common = {22, 80, 443, 8080, 53, 3306, 5432}
    unusual_listeners = []
    for l in listeners:
        port = l["local"].split(":")[-1] if ":" in l["local"] else "0"
        try:
            p = int(port)
            if p not in common and p > 1024:
                unusual_listeners.append(l)
        except ValueError:
            pass

    return {
        "artifacts": findings,
        "count": {
            "tcp": len(findings["tcp"]),
            "udp": len(findings["udp"]),
            "arp": len(findings["arp"]),
            "routes": len(findings["routes"]),
            "listeners": len(listeners),
        },
        "unusual_listeners": unusual_listeners,
        "note": "/proc/net/* read directly — no libc network APIs used",
    }


def _hex_addr(hex_str: str) -> str:
    """Parse Linux hex IP:port format."""
    if ":" not in hex_str:
        return hex_str
    ip_hex, port_hex = hex_str.rsplit(":", 1)
    try:
        port = int(port_hex, 16)
    except ValueError:
        port = 0
    # Handle IPv4 (8 hex chars) or IPv6 (32 hex chars)
    if len(ip_hex) == 8:
        # Little-endian
        ip_int = int(ip_hex, 16)
        ip = f"{(ip_int >> 0) & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
    else:
        ip = ip_hex
    return f"{ip}:{port}"


def _hex_ipv4(hex_str: str) -> str:
    try:
        ip_int = int(hex_str, 16)
        return f"{(ip_int >> 0) & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
    except ValueError:
        return hex_str


_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
    "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
    "0A": "LISTEN", "0B": "CLOSING",
}


def _tcp_state(hex_state: str) -> str:
    return _TCP_STATES.get(hex_state.upper(), f"UNKNOWN({hex_state})")


# ---------- 3. Persistence Forensics ----------

def forensic_persistence(args: dict) -> dict:
    """
    Enumerate every persistence mechanism on the system.
    This is one of the highest-value forensic tasks — attackers install
    persistence here. AV/EDR watches these locations and flags bulk reads.
    """
    findings = {
        "cron": [],
        "systemd_units": [],
        "shell_profiles": [],
        "ssh_authorized_keys": [],
        "autostart": [],
        "rc_local": [],
        "at_jobs": [],
    }

    # /etc/crontab + /etc/cron.d/*
    for path in ["/etc/crontab"] + glob.glob("/etc/cron.d/*"):
        if os.path.isfile(path):
            findings["cron"].append({
                "path": path,
                "content": _read_text(path, 8192)[:2000],
            })

    # Cron spool for each user
    for user_dir in glob.glob("/var/spool/cron/crontabs/*"):
        findings["cron"].append({
            "path": user_dir,
            "content": _read_text(user_dir, 4096)[:1000],
        })

    # Systemd units (user-facing, not all system services — look for suspicious)
    systemd_dirs = [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
        os.path.expanduser("~/.config/systemd/user"),
    ]
    for d in systemd_dirs:
        for unit in glob.glob(f"{d}/*.service"):
            name = os.path.basename(unit)
            # Only include units that were NOT installed by packages
            # (heuristic: check if unit file is in /etc/systemd which is user-modified)
            if d.startswith("/etc/"):
                findings["systemd_units"].append({
                    "path": unit,
                    "content": _read_text(unit, 4096)[:1500],
                })

    # Shell profiles — modifications here can execute on login
    shell_profiles = [
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/zsh/zshrc",
        os.path.expanduser("~/.bashrc"),
        os.path.expanduser("~/.bash_profile"),
        os.path.expanduser("~/.profile"),
        os.path.expanduser("~/.zshrc"),
    ]
    for p in shell_profiles:
        if os.path.isfile(p):
            content = _read_text(p, 65536)
            findings["shell_profiles"].append({
                "path": p,
                "size": len(content),
                "suspicious_lines": [
                    ln for ln in content.splitlines()
                    if any(k in ln for k in ("curl", "wget", "nc ", "base64", "eval", "|sh", "|bash"))
                    and not ln.strip().startswith("#")
                ][:10],
            })

    # SSH authorized_keys — backdoor mechanism
    for ak in glob.glob("/home/*/.ssh/authorized_keys") + \
              [os.path.expanduser("~/.ssh/authorized_keys"), "/root/.ssh/authorized_keys"]:
        if os.path.isfile(ak):
            content = _read_text(ak, 8192)
            keys = [l for l in content.splitlines() if l.strip() and not l.startswith("#")]
            findings["ssh_authorized_keys"].append({
                "path": ak,
                "key_count": len(keys),
                "keys": [k[:60] + "..." for k in keys],
            })

    # Autostart (desktop session)
    for d in glob.glob("/home/*/.config/autostart/*") + \
             glob.glob(os.path.expanduser("~/.config/autostart/*")):
        if os.path.isfile(d):
            findings["autostart"].append({
                "path": d,
                "content": _read_text(d, 4096)[:1000],
            })

    # rc.local
    if os.path.isfile("/etc/rc.local"):
        findings["rc_local"].append({
            "path": "/etc/rc.local",
            "content": _read_text("/etc/rc.local", 4096)[:1000],
            "executable": os.access("/etc/rc.local", os.X_OK),
        })

    # at jobs
    for d in ["/var/spool/cron/atjobs", "/var/spool/atjobs"]:
        for job in glob.glob(f"{d}/*"):
            findings["at_jobs"].append({"path": job})

    # Total count
    total = sum(len(v) for v in findings.values())

    # Flag suspicious
    suspicious = []
    for profile in findings["shell_profiles"]:
        if profile["suspicious_lines"]:
            suspicious.append({
                "path": profile["path"],
                "lines": profile["suspicious_lines"],
            })

    return {
        "artifacts": findings,
        "count": total,
        "suspicious": suspicious,
        "note": "checked cron, systemd (user-modified), shell profiles, SSH keys, autostart, rc.local, at jobs",
    }


# ---------- 4. Filesystem Forensics ----------

def forensic_filesystem(args: dict) -> dict:
    """
    Filesystem artifacts: recent files, setuid binaries, world-writable,
    hidden executables in unusual places, deleted-but-open files.
    """
    scan_paths = args.get("paths", ["/tmp", "/var/tmp", "/dev/shm", "/home"])
    max_age_seconds = args.get("max_age_seconds", 86400)  # 24 hours
    now = datetime.now(timezone.utc).timestamp()

    recent_files = []
    setuid_files = []
    world_writable = []
    hidden_execs = []

    for root in scan_paths:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            # Skip system directories
            if any(skip in dirpath for skip in ("/proc", "/sys", "/dev")):
                continue
            # Cap total entries per path
            if len(recent_files) + len(setuid_files) + len(world_writable) > 2000:
                break

            for name in filenames[:500]:
                full = os.path.join(dirpath, name)
                try:
                    st = os.stat(full, follow_symlinks=False)
                except (FileNotFoundError, PermissionError, OSError):
                    continue

                # Recent files
                if now - st.st_mtime < max_age_seconds:
                    recent_files.append({
                        "path": full,
                        "mtime": int(st.st_mtime),
                        "size": st.st_size,
                        "mode": oct(st.st_mode),
                    })

                # Setuid / setgid
                if st.st_mode & 0o4000 or st.st_mode & 0o2000:
                    setuid_files.append({
                        "path": full,
                        "mode": oct(st.st_mode),
                        "uid": st.st_uid,
                        "gid": st.st_gid,
                    })

                # World-writable
                if st.st_mode & 0o002 and os.path.isfile(full):
                    world_writable.append({
                        "path": full,
                        "mode": oct(st.st_mode),
                    })

                # Hidden executables (starting with .)
                if name.startswith(".") and (st.st_mode & 0o111):
                    hidden_execs.append({
                        "path": full,
                        "mode": oct(st.st_mode),
                        "size": st.st_size,
                    })

    # Deleted-but-open files (very interesting forensically)
    deleted_open = []
    for pid_str in _list_dir("/proc"):
        if not pid_str.isdigit():
            continue
        fd_dir = f"/proc/{pid_str}/fd"
        for fd in _list_dir(fd_dir):
            target = _readlink_safe(f"{fd_dir}/{fd}")
            if "(deleted)" in target:
                deleted_open.append({
                    "pid": int(pid_str),
                    "fd": fd,
                    "path": target.replace(" (deleted)", ""),
                })

    return {
        "artifacts": {
            "recent_files": recent_files[:200],
            "setuid_files": setuid_files[:100],
            "world_writable": world_writable[:100],
            "hidden_executables": hidden_execs[:100],
            "deleted_but_open": deleted_open[:100],
        },
        "count": {
            "recent": len(recent_files),
            "setuid": len(setuid_files),
            "world_writable": len(world_writable),
            "hidden_execs": len(hidden_execs),
            "deleted_open": len(deleted_open),
        },
        "note": f"scanned {scan_paths}; capped at 2000 entries per category",
    }


# ---------- 5. Log Forensics ----------

def forensic_logs(args: dict) -> dict:
    """
    Analyze system logs for security events.
    Auth failures, sudo usage, login sessions, shell history.
    """
    findings = {
        "auth_failures": [],
        "sudo_activity": [],
        "last_logins": [],
        "shell_history": [],
    }

    # Auth log — failed SSH logins
    auth_logs = ["/var/log/auth.log", "/var/log/secure"]
    for logpath in auth_logs:
        if not os.path.isfile(logpath):
            continue
        content = _read_text(logpath, 1 << 20)
        for line in content.splitlines():
            if "Failed password" in line or "authentication failure" in line.lower():
                findings["auth_failures"].append(line[:300])
            elif "sudo:" in line and "COMMAND=" in line:
                findings["sudo_activity"].append(line[:300])
            elif "Accepted password" in line or "Accepted publickey" in line:
                findings["last_logins"].append(line[:300])

    # Last logins via `last`
    try:
        result = subprocess.run(
            ["last", "-n", "30", "-F"],
            capture_output=True, text=True, timeout=5,
        )
        findings["last_logins"].extend(result.stdout.splitlines()[:30])
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Shell histories
    history_files = (
        glob.glob("/home/*/.bash_history") +
        glob.glob("/home/*/.zsh_history") +
        ["/root/.bash_history"]
    )
    for hist in history_files:
        if os.path.isfile(hist):
            content = _read_text(hist, 65536)
            lines = content.splitlines()
            # Flag suspicious commands
            suspicious = [
                ln for ln in lines
                if any(k in ln for k in (
                    "nc ", "ncat", "wget", "curl", "base64",
                    "chmod +x", "/tmp/", "curl | sh",
                    "ssh-keygen", "authorized_keys",
                    "crontab -e", "eval(",
                ))
            ]
            findings["shell_history"].append({
                "user_file": hist,
                "total_lines": len(lines),
                "suspicious_lines": suspicious[:20],
            })

    return {
        "artifacts": findings,
        "count": {
            "auth_failures": len(findings["auth_failures"]),
            "sudo_activity": len(findings["sudo_activity"]),
            "last_logins": len(findings["last_logins"]),
            "history_files": len(findings["shell_history"]),
        },
        "note": "requires read access to /var/log/auth.log (usually root)",
    }


# ---------- 6. Memory Forensics ----------

def forensic_memory(args: dict) -> dict:
    """
    Memory/kernel-level analysis: loaded modules, kernel symbols,
    abnormal memory maps in processes.
    """
    findings = {
        "loaded_modules": [],
        "kernel_symbols_head": [],
        "rwx_processes": [],
    }

    # Loaded kernel modules — rootkit detection
    for line in _read_text("/proc/modules", 1 << 20).splitlines():
        parts = line.split()
        if len(parts) >= 3:
            findings["loaded_modules"].append({
                "name": parts[0],
                "size": int(parts[1]) if parts[1].isdigit() else 0,
                "refcount": parts[2],
                "dependencies": parts[3] if len(parts) > 3 else "",
            })

    # Kernel symbols (if readable)
    for line in _read_text("/proc/kallsyms", 1 << 20).splitlines()[:50]:
        parts = line.split()
        if len(parts) >= 3:
            findings["kernel_symbols_head"].append({
                "address": parts[0],
                "type": parts[1],
                "name": parts[2],
            })

    # RWX processes — strong signal of injected code
    for pid_str in _list_dir("/proc"):
        if not pid_str.isdigit():
            continue
        maps = _read_text(f"/proc/{pid_str}/maps", 65536)
        rwx_lines = [l for l in maps.splitlines() if " rwxp " in l]
        if rwx_lines:
            cmdline = _read_bytes(f"/proc/{pid_str}/cmdline", 512).replace(b"\x00", b" ").decode(errors="replace")
            findings["rwx_processes"].append({
                "pid": int(pid_str),
                "cmdline": cmdline[:200],
                "rwx_regions": len(rwx_lines),
                "sample": rwx_lines[0][:200],
            })

    return {
        "artifacts": findings,
        "count": {
            "modules": len(findings["loaded_modules"]),
            "rwx_processes": len(findings["rwx_processes"]),
        },
        "note": "kallsyms may be restricted without root (addresses zeroed by kernel.kptr_restrict)",
    }


# ---------- 7. User Forensics ----------

def forensic_users(args: dict) -> dict:
    """
    User sessions, sudo config, group memberships, SSH keys.
    """
    findings = {
        "logged_in_users": [],
        "sudo_users": [],
        "groups": [],
        "ssh_keys": [],
        "passwd_entries": [],
    }

    # Who is logged in
    try:
        result = subprocess.run(["who", "-a"], capture_output=True, text=True, timeout=3)
        findings["logged_in_users"] = result.stdout.splitlines()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # /etc/passwd
    for line in _read_text("/etc/passwd", 1 << 16).splitlines():
        parts = line.split(":")
        if len(parts) >= 7:
            findings["passwd_entries"].append({
                "user": parts[0],
                "uid": int(parts[2]) if parts[2].isdigit() else 0,
                "gid": int(parts[3]) if parts[3].isdigit() else 0,
                "home": parts[5],
                "shell": parts[6],
            })

    # /etc/group — admin-ish groups
    admin_groups = {"sudo", "wheel", "admin", "docker", "root"}
    for line in _read_text("/etc/group", 1 << 16).splitlines():
        parts = line.split(":")
        if len(parts) >= 4 and parts[0] in admin_groups:
            findings["groups"].append({
                "group": parts[0],
                "gid": parts[2],
                "members": parts[3].split(",") if parts[3] else [],
            })

    # sudoers
    for path in ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*"):
        if os.path.isfile(path):
            content = _read_text(path, 65536)
            for line in content.splitlines():
                if line.strip() and not line.strip().startswith("#"):
                    findings["sudo_users"].append({
                        "path": path,
                        "line": line[:200],
                    })

    # SSH keys
    for keyfile in glob.glob("/home/*/.ssh/*") + glob.glob("/root/.ssh/*"):
        name = os.path.basename(keyfile)
        if name in ("authorized_keys", "id_rsa", "id_ed25519", "id_ecdsa", "known_hosts"):
            findings["ssh_keys"].append({
                "path": keyfile,
                "size": os.path.getsize(keyfile) if os.path.exists(keyfile) else 0,
            })

    return {
        "artifacts": findings,
        "count": {
            "logged_in": len(findings["logged_in_users"]),
            "users": len(findings["passwd_entries"]),
            "admin_groups": len(findings["groups"]),
            "sudo_rules": len(findings["sudo_users"]),
            "ssh_keys": len(findings["ssh_keys"]),
        },
        "note": "reads /etc/passwd, /etc/group, sudoers, SSH directories",
    }


# ---------- 8. IOC Hunting ----------

def forensic_iocs(args: dict) -> dict:
    """
    Indicator-of-compromise hunting: hash suspicious binaries,
    detect strings matching known malware patterns.
    """
    targets = args.get("paths", ["/tmp", "/dev/shm", "/var/tmp"])
    suspicious_strings = [
        "curl http", "wget http", "base64 -d", "eval(",
        "/bin/sh -c", "nc -e", "/dev/tcp/",
        "msf", "meterpreter", "cobaltstrike",
        "xmrig", "minerd", "kworker"  # common crypto miners/rootkit names
    ]

    hashes = []
    string_hits = []

    for root in targets:
        if not os.path.isdir(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            for name in filenames[:300]:
                full = os.path.join(dirpath, name)
                try:
                    st = os.stat(full)
                except (FileNotFoundError, PermissionError, OSError):
                    continue
                # Only hash executable files smaller than 32MB
                if st.st_size > 32 * 1024 * 1024:
                    continue
                if not (st.st_mode & 0o111):
                    continue

                h = _sha256(full)
                hashes.append({
                    "path": full,
                    "sha256": h,
                    "size": st.st_size,
                })

                # Check for suspicious strings
                content = _read_bytes(full, 1 << 20)
                for s in suspicious_strings:
                    if s.encode() in content:
                        string_hits.append({
                            "path": full,
                            "matched": s,
                        })

    return {
        "artifacts": {
            "hashed_files": hashes[:100],
            "string_matches": string_hits[:50],
        },
        "count": {
            "files_hashed": len(hashes),
            "string_matches": len(string_hits),
        },
        "note": "hashes SHA-256 of executables; scans for common malware strings",
    }


# ---------- Registry ----------
DEEP_HANDLERS = {
    "forensic_process": forensic_process,
    "forensic_network": forensic_network,
    "forensic_persistence": forensic_persistence,
    "forensic_filesystem": forensic_filesystem,
    "forensic_logs": forensic_logs,
    "forensic_memory": forensic_memory,
    "forensic_users": forensic_users,
    "forensic_iocs": forensic_iocs,
}


# ---------- Analysis / Report Generation ----------

def generate_report(results: dict) -> dict:
    """
    Take raw output from all handlers and produce a structured
    forensic analysis report with risk scoring.
    """
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": {},
        "risk_summary": {},
        "recommendations": [],
    }

    risk_points = 0
    max_points = 0

    # Process findings
    if "forensic_process" in results:
        p = results["forensic_process"]
        report["findings"]["processes"] = {
            "total": p.get("count", 0),
            "suspicious": p.get("suspicious", []),
        }
        max_points += 10
        if p.get("suspicious_count", 0) > 0:
            risk_points += min(p["suspicious_count"] * 3, 10)
            report["recommendations"].append(
                f"Investigate {p['suspicious_count']} suspicious process(es) "
                f"with unusual memory or execution paths"
            )

    # Network findings
    if "forensic_network" in results:
        n = results["forensic_network"]
        report["findings"]["network"] = {
            "listeners": n["count"].get("listeners", 0),
            "unusual_listeners": n.get("unusual_listeners", []),
        }
        max_points += 10
        if n.get("unusual_listeners"):
            risk_points += min(len(n["unusual_listeners"]) * 2, 10)
            report["recommendations"].append(
                f"Review {len(n['unusual_listeners'])} unusual listening port(s)"
            )

    # Persistence findings
    if "forensic_persistence" in results:
        pers = results["forensic_persistence"]
        report["findings"]["persistence"] = {
            "total": pers.get("count", 0),
            "suspicious": pers.get("suspicious", []),
        }
        max_points += 10
        if pers.get("suspicious"):
            risk_points += 10
            report["recommendations"].append(
                f"Persistence mechanisms contain suspicious lines — review shell profiles"
            )

    # Filesystem findings
    if "forensic_filesystem" in results:
        fs = results["forensic_filesystem"]
        report["findings"]["filesystem"] = fs.get("count", {})
        max_points += 10
        if fs["count"].get("setuid", 0) > 0:
            risk_points += 3
        if fs["count"].get("deleted_open", 0) > 0:
            risk_points += 5
            report["recommendations"].append(
                "Deleted-but-open files detected — possible malware self-cleanup"
            )

    # Logs findings
    if "forensic_logs" in results:
        logs = results["forensic_logs"]
        report["findings"]["logs"] = logs.get("count", {})
        max_points += 10
        if logs["count"].get("auth_failures", 0) > 20:
            risk_points += 5
            report["recommendations"].append(
                f"{logs['count']['auth_failures']} authentication failures — possible brute force"
            )

    # Memory findings
    if "forensic_memory" in results:
        mem = results["forensic_memory"]
        report["findings"]["memory"] = mem.get("count", {})
        max_points += 10
        if mem["count"].get("rwx_processes", 0) > 0:
            risk_points += 8
            report["recommendations"].append(
                "Process(es) with RWX memory — possible code injection"
            )

    # IOC findings
    if "forensic_iocs" in results:
        ioc = results["forensic_iocs"]
        report["findings"]["iocs"] = ioc.get("count", {})
        max_points += 10
        if ioc["count"].get("string_matches", 0) > 0:
            risk_points += 7
            report["recommendations"].append(
                "Files match known-malware string patterns — immediate review required"
            )

    # Risk score
    if max_points > 0:
        risk_pct = int((risk_points / max_points) * 100)
    else:
        risk_pct = 0

    report["risk_summary"] = {
        "score": risk_pct,
        "level": (
            "CRITICAL" if risk_pct >= 80 else
            "HIGH" if risk_pct >= 60 else
            "MEDIUM" if risk_pct >= 30 else
            "LOW" if risk_pct >= 10 else
            "MINIMAL"
        ),
        "points": risk_points,
        "max_points": max_points,
    }

    if not report["recommendations"]:
        report["recommendations"].append(
            "No high-priority findings. Continue routine monitoring."
        )

    return report


# ---------- Demo ----------
if __name__ == "__main__":
    print("=" * 70)
    print("JOCKY Deep Forensic Handlers — Demo")
    print("=" * 70)

    results = {}

    for name, handler in DEEP_HANDLERS.items():
        print(f"\n[*] Running {name}...")
        try:
            result = handler({})
            results[name] = result
            if isinstance(result.get("count"), dict):
                summary = ", ".join(f"{k}={v}" for k, v in list(result["count"].items())[:4])
            else:
                summary = f"count={result.get('count', 0)}"
            print(f"    ✓ {summary}")
        except Exception as e:
            print(f"    ✗ {name} failed: {e}")

    print("\n" + "=" * 70)
    print("GENERATING REPORT")
    print("=" * 70)
    report = generate_report(results)
    print(json.dumps(report["risk_summary"], indent=2))
    print("\nRecommendations:")
    for rec in report["recommendations"]:
        print(f"  → {rec}")

    # Save to file
    out_path = "logs/forensic_report.json"
    Path("logs").mkdir(exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[+] Full report saved: {out_path}")

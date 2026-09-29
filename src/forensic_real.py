"""
JOCKY Framework — Module 10: Real Forensic Operations
Replaces demo stubs with actual system inspection via /proc, psutil, and os.
"""

import os
import socket
import platform
import time
import psutil
from pathlib import Path


def collect_system_info(args):
    """Real system information."""
    boot = psutil.boot_time()
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_release": platform.release(),
        "arch": platform.machine(),
        "kernel": platform.uname().release,
        "python": platform.python_version(),
        "uptime_seconds": int(time.time() - boot),
        "cpu_count": psutil.cpu_count(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_total_mb": round(psutil.virtual_memory().total / 1024 / 1024),
        "memory_used_mb": round(psutil.virtual_memory().used / 1024 / 1024),
        "users_logged_in": [u.name for u in psutil.users()],
    }


def enumerate_network_connections(args):
    """Real network connections via psutil."""
    proto = args.get("proto", "tcp").lower()
    kind = "inet"
    if proto == "udp":
        kind = "udp"

    connections = []
    for c in psutil.net_connections(kind=kind):
        if c.status == "NONE":
            state = "LISTEN"
        else:
            state = c.status
        connections.append({
            "proto": proto,
            "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—",
            "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "—",
            "state": state,
            "pid": c.pid,
        })

    return {
        "proto": proto,
        "count": len(connections),
        "connections": connections[:50],  # cap for output size
    }


def scan_forensic_artifacts(args):
    """Real filesystem scan for common forensic artifacts."""
    paths = args.get("paths", ["/var/log", "/tmp", "/home"])
    artifacts = []

    # Look for suspicious file types in target directories
    suspicious_exts = {".sh", ".py", ".pl", ".elf", ".bin", ".so"}
    suspicious_names = {"authorized_keys", "crontab", "rc.local", ".bash_history"}

    for p in paths:
        base = Path(p)
        if not base.exists():
            continue

        try:
            count = 0
            for f in base.rglob("*"):
                if count >= 500:
                    break
                count += 1
                if f.is_file():
                    if f.suffix in suspicious_exts or f.name in suspicious_names:
                        try:
                            stat = f.stat()
                            artifacts.append({
                                "path": str(f),
                                "size": stat.st_size,
                                "mtime": int(stat.st_mtime),
                                "mode": oct(stat.st_mode),
                            })
                        except (PermissionError, OSError):
                            continue
        except (PermissionError, OSError):
            continue

    return {
        "artifacts_found": len(artifacts),
        "scanned_paths": paths,
        "artifacts": artifacts[:30],
    }


def list_processes(args):
    """Real process enumeration."""
    limit = args.get("limit", 20)
    procs = []
    for p in psutil.process_iter(["pid", "name", "username", "cmdline", "create_time"]):
        try:
            info = p.info
            procs.append({
                "pid": info["pid"],
                "name": info["name"],
                "user": info["username"],
                "cmdline": " ".join(info["cmdline"] or [])[:80],
                "started": int(info["create_time"]) if info["create_time"] else 0,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    procs.sort(key=lambda x: x["pid"])
    return {"count": len(procs), "processes": procs[:limit]}


def check_persistence(args):
    """Real persistence location check."""
    locations = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/systemd/system",
        "/etc/rc.local",
        os.path.expanduser("~/.bashrc"),
        os.path.expanduser("~/.profile"),
        os.path.expanduser("~/.ssh/authorized_keys"),
        os.path.expanduser("~/.config/autostart"),
    ]

    results = []
    for loc in locations:
        p = Path(loc)
        if p.exists():
            try:
                stat = p.stat()
                results.append({
                    "path": loc,
                    "exists": True,
                    "is_dir": p.is_dir(),
                    "mtime": int(stat.st_mtime),
                    "size": stat.st_size if p.is_file() else None,
                })
            except (PermissionError, OSError):
                results.append({"path": loc, "exists": True, "error": "permission denied"})
        else:
            results.append({"path": loc, "exists": False})

    return {
        "checked": len(locations),
        "existing": sum(1 for r in results if r.get("exists")),
        "locations": results,
    }


REAL_HANDLERS = {
    "collect_system_info": collect_system_info,
    "enumerate_network_connections": enumerate_network_connections,
    "scan_forensic_artifacts": scan_forensic_artifacts,
    "list_processes": list_processes,
    "check_persistence": check_persistence,
}


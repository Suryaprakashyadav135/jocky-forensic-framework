"""
JOCKY Framework — Module 3: Structured Command Protocol
Defines the wire format for client-server communication.
"""

import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Any


PROTOCOL_VERSION = "1.0"


@dataclass
class CommandRequest:
    """What the client sends to the server."""
    command: str
    args: dict = field(default_factory=dict)
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    version: str = PROTOCOL_VERSION
    issued_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "CommandRequest":
        return cls(
            command=data["command"],
            args=data.get("args", {}),
            task_id=data.get("task_id", str(uuid.uuid4())),
            version=data.get("version", PROTOCOL_VERSION),
            issued_at=data.get("issued_at", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class CommandResponse:
    """What the server sends back."""
    task_id: str
    status: str          # "complete" | "pending" | "error"
    result: Any = None
    error: str = None
    completed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: str = PROTOCOL_VERSION

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "CommandResponse":
        return cls(
            task_id=data["task_id"],
            status=data["status"],
            result=data.get("result"),
            error=data.get("error"),
            completed_at=data.get("completed_at", datetime.now(timezone.utc).isoformat()),
            version=data.get("version", PROTOCOL_VERSION),
        )


# Command registry — defines what each command does and its schema
COMMAND_REGISTRY = {
    "collect_system_info": {
        "description": "Gather basic system information",
        "args": {},
        "returns": "hostname, os, arch, kernel, uptime",
    },
    "enumerate_network_connections": {
        "description": "List active network connections",
        "args": {"proto": "tcp|udp|all"},
        "returns": "list of connections",
    },
    "scan_forensic_artifacts": {
        "description": "Scan common paths for forensic artifacts",
        "args": {"paths": "list of directories"},
        "returns": "count of artifacts, scanned paths",
    },
    "list_processes": {
        "description": "Enumerate running processes",
        "args": {"limit": "int, default 20"},
        "returns": "list of processes",
    },
    "check_persistence": {
        "description": "Check common persistence locations",
        "args": {},
        "returns": "list of suspicious entries",
    },
    "forensic_process": {
        "description": "Deep process inspection: cmdline, env, fds, maps per PID",
        "args": {"include_env": "bool", "limit": "int"},
        "returns": "list of processes with artifacts",
    },
    "forensic_network": {
        "description": "Network sockets, ARP, routing, listening ports",
        "args": {},
        "returns": "tcp/udp/arp/routes/listeners",
    },
    "forensic_persistence": {
        "description": "Enumerate persistence mechanisms (cron, systemd, SSH, shell)",
        "args": {},
        "returns": "all persistence locations",
    },
    "forensic_filesystem": {
        "description": "Recent files, setuid, world-writable, hidden execs, deleted-open",
        "args": {"paths": "list", "max_age_seconds": "int"},
        "returns": "filesystem artifacts",
    },
    "forensic_logs": {
        "description": "Auth failures, sudo, logins, shell history",
        "args": {},
        "returns": "log analysis",
    },
    "forensic_memory": {
        "description": "Loaded LKMs, kernel symbols, RWX processes",
        "args": {},
        "returns": "memory/kernel artifacts",
    },
    "forensic_users": {
        "description": "Sessions, groups, sudoers, SSH keys",
        "args": {},
        "returns": "user activity",
    },
    "forensic_iocs": {
        "description": "Hash executables, detect malware strings",
        "args": {"paths": "list"},
        "returns": "hashed files, string matches",
    },
    "generate_forensic_report": {
        "description": "Run all 8 deep handlers, produce risk-scored report",
        "args": {},
        "returns": "structured forensic report with risk level",
    },
}


def validate_command(name: str, args: dict) -> tuple[bool, str]:
    """Validate a command request against the registry."""
    if name not in COMMAND_REGISTRY:
        return False, f"unknown command: {name}"
    spec = COMMAND_REGISTRY[name]
    # Only check that provided args are known keys
    for k in args:
        if spec["args"] and k not in spec["args"]:
            return False, f"unknown arg for {name}: {k}"
    return True, "ok"

"""Conservative adapter from Linux auditd SYSCALL records to B-SCAF events."""

from __future__ import annotations

from datetime import datetime, timezone
import re
import shlex
from typing import Any


# The common x86_64 values are intentionally explicit. Unmapped values are
# preserved as syscall_<number>, which policy normally drops.
X86_64_SYSCALLS = {
    2: "open", 42: "connect", 56: "clone", 57: "fork", 59: "execve",
    82: "rename", 87: "unlink", 90: "chmod", 101: "ptrace", 105: "setuid",
    257: "openat", 263: "unlinkat", 268: "fchmodat", 302: "prlimit64",
    308: "setns", 310: "process_vm_readv", 311: "process_vm_writev",
}
AUDIT_TIME = re.compile(r"audit\((?P<seconds>\d+(?:\.\d+)?):\d+\)")


def parse_syscall_line(line: str, host_id: str = "localhost") -> dict[str, Any] | None:
    """Parse one auditd `type=SYSCALL` line; return None for other record types."""
    if "type=SYSCALL" not in line:
        return None
    fields: dict[str, str] = {}
    for token in shlex.split(line):
        if "=" in token:
            key, value = token.split("=", 1)
            fields[key] = value.strip('"')
    required = ("syscall", "pid", "ppid", "uid")
    if any(key not in fields for key in required):
        raise ValueError("auditd SYSCALL record lacks syscall, pid, ppid or uid")
    match = AUDIT_TIME.search(line)
    if not match:
        raise ValueError("auditd SYSCALL record lacks an audit timestamp")
    timestamp = datetime.fromtimestamp(float(match.group("seconds")), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    number = int(fields["syscall"], 0)
    arguments = {key: fields[key] for key in ("a0", "a1", "a2", "a3") if key in fields}
    return {
        "timestamp": timestamp,
        "host_id": host_id,
        "pid": int(fields["pid"]),
        "ppid": int(fields["ppid"]),
        "uid": int(fields["uid"]),
        "syscall": X86_64_SYSCALLS.get(number, f"syscall_{number}"),
        "process": fields.get("exe", fields.get("comm", "")),
        "arguments": arguments,
        "return_code": int(fields.get("exit", "0")),
    }

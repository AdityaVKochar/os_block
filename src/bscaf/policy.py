"""Field minimization policy for system-call audit events."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from typing import Any

from .canonical import canonical_json, sha256_hex


DEFAULT_SYSCALLS = frozenset({
    "execve", "execveat", "openat", "open", "unlinkat", "unlink", "rename", "renameat", "renameat2",
    "connect", "bind", "chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat", "lchown",
    "setuid", "setreuid", "setresuid", "setgid", "setresgid", "ptrace",
    "init_module", "finit_module", "delete_module", "mount", "umount2",
})
SENSITIVE_ARGUMENT_KEYS = frozenset({"password", "passwd", "token", "secret", "authorization", "cookie", "api_key"})
# `--password=hunter2`, `token:abc` and similar inline secrets inside argv or proctitle strings.
INLINE_SECRET = re.compile(r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|authorization)([=:])\S+")


@dataclass(frozen=True)
class AuditPolicy:
    # None selects every system call; useful when profiling an unfamiliar dataset.
    allowed_syscalls: frozenset[str] | None = field(default_factory=lambda: DEFAULT_SYSCALLS)
    redact_argument_keys: frozenset[str] = field(default_factory=lambda: SENSITIVE_ARGUMENT_KEYS)
    max_argument_length: int = 512

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AuditPolicy":
        unknown = set(payload) - {"allowed_syscalls", "redact_argument_keys", "max_argument_length"}
        if unknown:
            raise ValueError(f"unknown policy fields: {', '.join(sorted(unknown))}")
        syscalls = payload.get("allowed_syscalls", sorted(DEFAULT_SYSCALLS))
        return cls(
            allowed_syscalls=None if syscalls is None or syscalls == "*" else frozenset(map(str, syscalls)),
            redact_argument_keys=frozenset(str(key).lower() for key in payload.get("redact_argument_keys", SENSITIVE_ARGUMENT_KEYS)),
            max_argument_length=int(payload.get("max_argument_length", 512)),
        )

    @classmethod
    def from_file(cls, path: Path) -> "AuditPolicy":
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_syscalls": None if self.allowed_syscalls is None else sorted(self.allowed_syscalls),
            "redact_argument_keys": sorted(self.redact_argument_keys),
            "max_argument_length": self.max_argument_length,
        }

    @property
    def version(self) -> str:
        """Short content hash recorded in every checkpoint that this policy produced."""
        return sha256_hex(canonical_json(self.to_dict()))[:16]

    def apply(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Return a minimized event, or None when policy does not select it."""
        if self.allowed_syscalls is not None and payload.get("syscall") not in self.allowed_syscalls:
            return None
        result = dict(payload)
        result["arguments"] = self._minimize(dict(result.get("arguments", {})))
        return result

    def _minimize(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                str(key): "[REDACTED]" if str(key).lower() in self.redact_argument_keys else self._minimize(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self._minimize(item) for item in value]
        if isinstance(value, str):
            value = INLINE_SECRET.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", value)
            if len(value) > self.max_argument_length:
                return value[: self.max_argument_length] + "...[TRUNCATED]"
        return value

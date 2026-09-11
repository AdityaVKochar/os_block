"""Field minimization policy for system-call audit events."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


DEFAULT_SYSCALLS = frozenset({"execve", "openat", "unlinkat", "connect", "chmod", "fchmodat", "setuid", "setresuid", "ptrace"})
SENSITIVE_ARGUMENT_KEYS = frozenset({"password", "token", "secret", "authorization", "cookie", "api_key"})


@dataclass(frozen=True)
class AuditPolicy:
    allowed_syscalls: frozenset[str] = field(default_factory=lambda: DEFAULT_SYSCALLS)
    redact_argument_keys: frozenset[str] = field(default_factory=lambda: SENSITIVE_ARGUMENT_KEYS)
    max_argument_length: int = 512

    def apply(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Return a minimized event, or None when policy does not select it."""
        if payload.get("syscall") not in self.allowed_syscalls:
            return None
        result = dict(payload)
        arguments = dict(result.get("arguments", {}))
        result["arguments"] = {
            str(key): "[REDACTED]" if str(key).lower() in self.redact_argument_keys else self._limit(value)
            for key, value in arguments.items()
        }
        return result

    def _limit(self, value: Any) -> Any:
        if isinstance(value, str) and len(value) > self.max_argument_length:
            return value[: self.max_argument_length] + "...[TRUNCATED]"
        return value

"""Data objects for audit events and checkpoint blocks."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .canonical import canonical_json, sha256_hex


GENESIS_HASH = "0" * 64


def _utc_timestamp(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    timestamp: str
    host_id: str
    pid: int
    ppid: int
    uid: int
    syscall: str
    process: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    return_code: int | None = None
    previous_event_hash: str = GENESIS_HASH
    event_hash: str = ""

    @classmethod
    def from_input(cls, payload: dict[str, Any], sequence: int, previous_hash: str) -> "AuditEvent":
        required = ("timestamp", "pid", "ppid", "uid", "syscall")
        missing = [field_name for field_name in required if field_name not in payload]
        if missing:
            raise ValueError(f"missing required event fields: {', '.join(missing)}")
        event = cls(
            sequence=sequence,
            timestamp=_utc_timestamp(str(payload["timestamp"])),
            host_id=str(payload.get("host_id", "localhost")),
            pid=int(payload["pid"]),
            ppid=int(payload["ppid"]),
            uid=int(payload["uid"]),
            syscall=str(payload["syscall"]),
            process=str(payload.get("process", "")),
            arguments=dict(payload.get("arguments", {})),
            return_code=(None if payload.get("return_code") is None else int(payload["return_code"])),
            previous_event_hash=previous_hash,
        )
        return cls(**{**asdict(event), "event_hash": event.calculate_hash()})

    def hash_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("event_hash")
        return payload

    def calculate_hash(self) -> str:
        return sha256_hex(canonical_json(self.hash_payload()))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AuditEvent":
        return cls(**payload)


@dataclass(frozen=True)
class Checkpoint:
    block_number: int
    previous_block_hash: str
    batch_id: str
    merkle_root: str
    first_sequence: int
    last_sequence: int
    event_count: int
    host_id: str
    created_at: str
    signer_id: str
    signature: str = ""
    block_hash: str = ""

    def unsigned_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("signature")
        payload.pop("block_hash")
        return payload

    def calculate_block_hash(self) -> str:
        return sha256_hex(canonical_json(self.unsigned_payload()))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Checkpoint":
        return cls(**payload)

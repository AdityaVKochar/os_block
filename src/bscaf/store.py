"""Append-only JSONL persistence for events and signed checkpoints."""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
from typing import Iterable, Iterator

try:  # POSIX advisory locking; Windows runs without an inter-process lock.
    import fcntl
except ImportError:  # pragma: no cover - exercised only on Windows
    fcntl = None

from .models import AuditEvent, Checkpoint


def _line(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


class AuditStore:
    def __init__(self, root: Path, durable: bool = True):
        self.root = root
        # fsync committed events and checkpoints; disable only for throughput experiments.
        self.durable = durable
        self.events_path = root / "events.jsonl"
        self.checkpoints_path = root / "checkpoints.jsonl"
        self.acks_path = root / "witness-acks.jsonl"
        self.ingest_state_path = root / "ingest-state.json"
        self.lock_path = root / ".lock"
        self.private_key_path = root / "signing-private.pem"
        self.public_key_path = root / "signing-public.pem"

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.events_path.touch(exist_ok=True)
        self.checkpoints_path.touch(exist_ok=True)

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Hold an exclusive advisory lock so two writers cannot interleave sequences."""
        self.root.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a") as handle:
            if fcntl is not None:
                fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(handle, fcntl.LOCK_UN)

    def sizes(self) -> tuple[int, int]:
        """Byte sizes of the two ledgers; a change means another writer appended."""
        return tuple(path.stat().st_size if path.exists() else 0 for path in (self.events_path, self.checkpoints_path))

    def _append(self, path: Path, payloads: Iterable[dict], durable: bool = False) -> None:
        text = "".join(_line(payload) for payload in payloads)
        if not text:
            return
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            if durable and self.durable:
                os.fsync(handle.fileno())

    def append_event(self, event: AuditEvent) -> None:
        self._append(self.events_path, [event.to_dict()])

    def append_events(self, events: Iterable[AuditEvent]) -> None:
        self._append(self.events_path, (event.to_dict() for event in events), durable=True)

    def append_checkpoint(self, checkpoint: Checkpoint) -> None:
        self._append(self.checkpoints_path, [checkpoint.to_dict()], durable=True)

    def append_ack(self, ack: dict) -> None:
        self._append(self.acks_path, [ack])

    def acks(self) -> Iterator[dict]:
        yield from self._read(self.acks_path, dict, "witness ack")

    def events(self) -> Iterator[AuditEvent]:
        yield from self._read(self.events_path, AuditEvent.from_dict, "event")

    def checkpoints(self) -> Iterator[Checkpoint]:
        yield from self._read(self.checkpoints_path, Checkpoint.from_dict, "checkpoint")

    @staticmethod
    def _read(path: Path, build, label: str) -> Iterator:
        if not path.exists():
            return
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if line.strip():
                    try:
                        yield build(json.loads(line))
                    except (json.JSONDecodeError, TypeError, ValueError) as exc:
                        raise ValueError(f"invalid {label} at line {line_number}: {exc}") from exc

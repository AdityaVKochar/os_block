"""Append-only JSONL persistence for events and signed checkpoints."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Iterator

from .models import AuditEvent, Checkpoint


class AuditStore:
    def __init__(self, root: Path):
        self.root = root
        self.events_path = root / "events.jsonl"
        self.checkpoints_path = root / "checkpoints.jsonl"
        self.private_key_path = root / "signing-private.pem"
        self.public_key_path = root / "signing-public.pem"

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.events_path.touch(exist_ok=True)
        self.checkpoints_path.touch(exist_ok=True)

    @staticmethod
    def _append(path: Path, payload: dict) -> None:
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()

    def append_event(self, event: AuditEvent) -> None:
        self._append(self.events_path, event.to_dict())

    def append_checkpoint(self, checkpoint: Checkpoint) -> None:
        self._append(self.checkpoints_path, checkpoint.to_dict())

    def events(self) -> Iterator[AuditEvent]:
        if not self.events_path.exists():
            return
        with self.events_path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if line.strip():
                    try:
                        yield AuditEvent.from_dict(json.loads(line))
                    except (json.JSONDecodeError, TypeError, ValueError) as exc:
                        raise ValueError(f"invalid event at line {line_number}: {exc}") from exc

    def checkpoints(self) -> Iterator[Checkpoint]:
        if not self.checkpoints_path.exists():
            return
        with self.checkpoints_path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if line.strip():
                    try:
                        yield Checkpoint.from_dict(json.loads(line))
                    except (json.JSONDecodeError, TypeError, ValueError) as exc:
                        raise ValueError(f"invalid checkpoint at line {line_number}: {exc}") from exc

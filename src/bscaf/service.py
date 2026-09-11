"""Audit pipeline orchestration: ingest, batch, sign, and verify."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canonical import canonical_json
from .crypto import create_keypair, sign, verify
from .merkle import merkle_root
from .models import GENESIS_HASH, AuditEvent, Checkpoint
from .store import AuditStore


class AuditService:
    def __init__(self, data_dir: Path, batch_size: int = 10, signer_id: str = "local-witness"):
        if batch_size < 1:
            raise ValueError("batch_size must be at least 1")
        self.store = AuditStore(data_dir)
        self.batch_size = batch_size
        self.signer_id = signer_id

    def initialize(self) -> None:
        self.store.initialize()
        if not self.store.private_key_path.exists() or not self.store.public_key_path.exists():
            create_keypair(self.store.private_key_path, self.store.public_key_path)

    def ingest(self, payload: dict[str, Any]) -> AuditEvent:
        self.initialize()
        events = list(self.store.events())
        previous_hash = events[-1].event_hash if events else GENESIS_HASH
        event = AuditEvent.from_input(payload, len(events) + 1, previous_hash)
        self.store.append_event(event)
        if len(events) % self.batch_size == self.batch_size - 1:
            self.commit_pending_batch()
        return event

    def commit_pending_batch(self) -> Checkpoint | None:
        self.initialize()
        events = list(self.store.events())
        checkpoints = list(self.store.checkpoints())
        committed_through = checkpoints[-1].last_sequence if checkpoints else 0
        pending = [event for event in events if event.sequence > committed_through]
        if not pending:
            return None
        if len(pending) < self.batch_size:
            return None
        return self._commit_batch(pending[:self.batch_size], checkpoints)

    def flush(self) -> Checkpoint | None:
        self.initialize()
        events = list(self.store.events())
        checkpoints = list(self.store.checkpoints())
        committed_through = checkpoints[-1].last_sequence if checkpoints else 0
        pending = [event for event in events if event.sequence > committed_through]
        if not pending:
            return None
        return self._commit_batch(pending, checkpoints)

    def _commit_batch(self, events: list[AuditEvent], checkpoints: list[Checkpoint]) -> Checkpoint:
        root = merkle_root([event.event_hash for event in events])
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        unsigned = Checkpoint(
            block_number=len(checkpoints) + 1,
            previous_block_hash=checkpoints[-1].block_hash if checkpoints else GENESIS_HASH,
            batch_id=f"{events[0].sequence}-{events[-1].sequence}",
            merkle_root=root,
            first_sequence=events[0].sequence,
            last_sequence=events[-1].sequence,
            event_count=len(events),
            host_id=events[0].host_id,
            created_at=now,
            signer_id=self.signer_id,
        )
        block_hash = unsigned.calculate_block_hash()
        signature = sign(self.store.private_key_path, canonical_json({**unsigned.unsigned_payload(), "block_hash": block_hash}))
        checkpoint = Checkpoint(**{**asdict(unsigned), "block_hash": block_hash, "signature": signature})
        self.store.append_checkpoint(checkpoint)
        return checkpoint

    def verify(self) -> dict[str, Any]:
        problems: list[dict[str, Any]] = []
        try:
            events = list(self.store.events())
            checkpoints = list(self.store.checkpoints())
        except ValueError as error:
            return {"valid": False, "events_checked": 0, "checkpoints_checked": 0, "problems": [{"type": "storage", "detail": str(error)}]}

        expected_previous = GENESIS_HASH
        expected_sequence = 1
        calculated_hashes: dict[int, str] = {}
        for event in events:
            if event.sequence != expected_sequence:
                problems.append({"type": "event-sequence", "sequence": event.sequence, "detail": "sequence is missing or reordered"})
            if event.previous_event_hash != expected_previous:
                problems.append({"type": "event-link", "sequence": event.sequence, "detail": "previous-event hash does not match"})
            calculated_hash = event.calculate_hash()
            if event.event_hash != calculated_hash:
                problems.append({"type": "event-hash", "sequence": event.sequence, "detail": "event contents were changed"})
            calculated_hashes[event.sequence] = calculated_hash
            expected_previous = calculated_hash
            expected_sequence += 1

        expected_block_hash = GENESIS_HASH
        committed_through = 0
        for checkpoint in checkpoints:
            if checkpoint.previous_block_hash != expected_block_hash:
                problems.append({"type": "block-link", "block": checkpoint.block_number, "detail": "previous-block hash does not match"})
            if checkpoint.block_hash != checkpoint.calculate_block_hash():
                problems.append({"type": "block-hash", "block": checkpoint.block_number, "detail": "checkpoint contents were changed"})
            signed = {**checkpoint.unsigned_payload(), "block_hash": checkpoint.block_hash}
            if not verify(self.store.public_key_path, canonical_json(signed), checkpoint.signature):
                problems.append({"type": "signature", "block": checkpoint.block_number, "detail": "Ed25519 signature is invalid"})
            batch = [event for event in events if checkpoint.first_sequence <= event.sequence <= checkpoint.last_sequence]
            if len(batch) != checkpoint.event_count:
                problems.append({"type": "batch-count", "block": checkpoint.block_number, "detail": "events are missing from the committed range"})
            elif merkle_root([calculated_hashes[event.sequence] for event in batch]) != checkpoint.merkle_root:
                problems.append({"type": "merkle-root", "block": checkpoint.block_number, "detail": "batch events do not match the committed root"})
            expected_block_hash = checkpoint.block_hash
            committed_through = max(committed_through, checkpoint.last_sequence)

        if events and committed_through < events[-1].sequence:
            problems.append({"type": "uncommitted-events", "detail": f"events after sequence {committed_through} have no checkpoint"})

        return {"valid": not problems, "events_checked": len(events), "checkpoints_checked": len(checkpoints), "problems": problems}

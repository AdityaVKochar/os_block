"""Audit pipeline orchestration: ingest, batch, sign, and verify."""

from __future__ import annotations

from bisect import bisect_right
from collections import Counter, deque
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
import time
from typing import Any, Iterable, Iterator

from .canonical import canonical_json
from .crypto import create_keypair, load_private_key, load_public_key, sign_with, verify_with
from .merkle import merkle_root
from .models import GENESIS_HASH, AuditEvent, Checkpoint, parse_timestamp
from .policy import AuditPolicy
from .store import AuditStore


@dataclass
class _TailState:
    """What ingest needs from the ledgers, loaded once instead of per event."""

    next_sequence: int = 1
    last_event_hash: str = GENESIS_HASH
    block_count: int = 0
    last_block_hash: str = GENESIS_HASH
    pending: list[AuditEvent] = field(default_factory=list)
    unwritten: list[AuditEvent] = field(default_factory=list)
    pending_since: float | None = None
    sizes: tuple[int, int] = (0, 0)


@dataclass
class IngestStats:
    accepted: int = 0
    ignored_by_policy: int = 0
    rejected: Counter = field(default_factory=Counter)
    checkpoints: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "ignored_by_policy": self.ignored_by_policy,
            "rejected": dict(self.rejected.most_common()),
            "checkpoints_created": self.checkpoints,
        }


class AuditService:
    def __init__(
        self,
        data_dir: Path,
        batch_size: int = 10,
        signer_id: str = "local-witness",
        policy: AuditPolicy | None = None,
        batch_seconds: float | None = None,
        durable: bool = True,
    ):
        if batch_size < 1:
            raise ValueError("batch_size must be at least 1")
        if batch_seconds is not None and batch_seconds <= 0:
            raise ValueError("batch_seconds must be positive")
        self.store = AuditStore(data_dir, durable=durable)
        self.batch_size = batch_size
        self.batch_seconds = batch_seconds
        self.signer_id = signer_id
        self.policy = policy or AuditPolicy()
        self._state: _TailState | None = None
        self._private_key = None
        self._ready = False

    def initialize(self) -> None:
        if self._ready:
            return
        self.store.initialize()
        if not self.store.private_key_path.exists() or not self.store.public_key_path.exists():
            create_keypair(self.store.private_key_path, self.store.public_key_path)
        self._ready = True

    # ----------------------------------------------------------------- ingest

    def ingest(self, payload: dict[str, Any]) -> AuditEvent | None:
        with self._writing() as state:
            return self._ingest_one(state, payload)

    def ingest_many(self, payloads: Iterable[dict[str, Any]], strict: bool = False) -> IngestStats:
        """Ingest a stream under one lock; invalid events are counted unless strict."""
        stats = IngestStats()
        with self._writing() as state:
            blocks_before = state.block_count
            for payload in payloads:
                try:
                    event = self._ingest_one(state, payload)
                except (TypeError, ValueError) as error:
                    if strict:
                        raise
                    stats.rejected[f"invalid event: {error}"] += 1
                    continue
                if event is None:
                    stats.ignored_by_policy += 1
                else:
                    stats.accepted += 1
            stats.checkpoints = state.block_count - blocks_before
        return stats

    def _ingest_one(self, state: _TailState, payload: dict[str, Any]) -> AuditEvent | None:
        minimized = self.policy.apply(payload)
        if minimized is None:
            return None
        event = AuditEvent.from_input(minimized, state.next_sequence, state.last_event_hash)
        if state.pending and self._closes_window(state.pending[0], event):
            self._commit(state, state.pending)
        state.pending.append(event)
        state.unwritten.append(event)
        if state.pending_since is None:
            state.pending_since = time.monotonic()
        state.next_sequence += 1
        state.last_event_hash = event.event_hash
        if len(state.pending) >= self.batch_size:
            self._commit(state, state.pending)
        return event

    def _closes_window(self, first: AuditEvent, incoming: AuditEvent) -> bool:
        """A block covers one host and, when time batching is on, at most T seconds of events."""
        if incoming.host_id != first.host_id:
            return True
        if self.batch_seconds is None:
            return False
        elapsed = (parse_timestamp(incoming.timestamp) - parse_timestamp(first.timestamp)).total_seconds()
        return elapsed >= self.batch_seconds

    def commit_due(self) -> Checkpoint | None:
        """Commit the pending batch when it has waited batch_seconds of wall-clock time (live tailing)."""
        if self.batch_seconds is None:
            return None
        with self._writing() as state:
            if state.pending and state.pending_since is not None and time.monotonic() - state.pending_since >= self.batch_seconds:
                return self._commit(state, state.pending)
        return None

    def commit_pending_batch(self) -> Checkpoint | None:
        with self._writing() as state:
            if len(state.pending) < self.batch_size:
                return None
            return self._commit(state, state.pending[: self.batch_size])

    def flush(self) -> Checkpoint | None:
        with self._writing() as state:
            if not state.pending:
                return None
            return self._commit(state, state.pending)

    @contextmanager
    def _writing(self) -> Iterator[_TailState]:
        self.initialize()
        with self.store.locked():
            state = self._state
            if state is None or state.sizes != self.store.sizes():
                state = self._state = self._load_state()
            try:
                yield state
            finally:
                self._write_events(state)
                state.sizes = self.store.sizes()

    def _load_state(self) -> _TailState:
        state = _TailState()
        committed_through = 0
        for checkpoint in self.store.checkpoints():
            state.block_count += 1
            state.last_block_hash = checkpoint.block_hash
            committed_through = checkpoint.last_sequence
        for event in self.store.events():
            state.next_sequence = event.sequence + 1
            state.last_event_hash = event.event_hash
            if event.sequence > committed_through:
                state.pending.append(event)
        state.pending_since = time.monotonic() if state.pending else None
        return state

    def _write_events(self, state: _TailState) -> None:
        if state.unwritten:
            self.store.append_events(state.unwritten)
            state.unwritten = []

    def _commit(self, state: _TailState, events: list[AuditEvent]) -> Checkpoint:
        events = list(events)
        # Events must be durable before a checkpoint that commits to them.
        self._write_events(state)
        if self._private_key is None:
            self._private_key = load_private_key(self.store.private_key_path)
        times = [parse_timestamp(event.timestamp) for event in events]
        unsigned = Checkpoint(
            block_number=state.block_count + 1,
            previous_block_hash=state.last_block_hash,
            batch_id=f"{events[0].sequence}-{events[-1].sequence}",
            merkle_root=merkle_root([event.event_hash for event in events]),
            first_sequence=events[0].sequence,
            last_sequence=events[-1].sequence,
            event_count=len(events),
            host_id=events[0].host_id,
            time_window_start=_iso(min(times)),
            time_window_end=_iso(max(times)),
            policy_version=self.policy.version,
            created_at=_iso(datetime.now(timezone.utc)),
            signer_id=self.signer_id,
        )
        block_hash = unsigned.calculate_block_hash()
        signature = sign_with(self._private_key, canonical_json({**unsigned.unsigned_payload(), "block_hash": block_hash}))
        checkpoint = replace(unsigned, block_hash=block_hash, signature=signature)
        self.store.append_checkpoint(checkpoint)
        state.block_count += 1
        state.last_block_hash = block_hash
        committed = {event.sequence for event in events}
        state.pending = [event for event in state.pending if event.sequence not in committed]
        state.pending_since = time.monotonic() if state.pending else None
        return checkpoint

    # ------------------------------------------------------------------ reads

    def inclusion_proof(self, sequence: int) -> dict[str, Any]:
        """Return a portable Merkle inclusion proof for one committed event."""
        from .merkle import inclusion_proof

        exists = any(item.sequence == sequence for item in self.store.events())
        if not exists:
            raise ValueError(f"event sequence {sequence} does not exist")
        checkpoint = next((item for item in self.store.checkpoints() if item.first_sequence <= sequence <= item.last_sequence), None)
        if checkpoint is None:
            raise ValueError(f"event sequence {sequence} has not been checkpointed")
        batch = [item for item in self.store.events() if checkpoint.first_sequence <= item.sequence <= checkpoint.last_sequence]
        event = next(item for item in batch if item.sequence == sequence)
        index = sequence - checkpoint.first_sequence
        return {
            "event": event.to_dict(),
            "leaf_hash": event.event_hash,
            "proof": [{"side": side, "hash": sibling} for side, sibling in inclusion_proof([item.event_hash for item in batch], index)],
            "checkpoint": checkpoint.to_dict(),
        }

    def checkpoints(self) -> list[Checkpoint]:
        """Expose committed blocks for replication without raw event records."""
        return list(self.store.checkpoints())

    def events(self) -> list[AuditEvent]:
        """Return normalized events for local audit and demonstration views."""
        return list(self.store.events())

    def search(
        self,
        syscall: str | None = None,
        pid: int | None = None,
        uid: int | None = None,
        host_id: str | None = None,
        text: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
        newest: bool = False,
    ) -> list[AuditEvent]:
        """Stream the event store and return matches (the first `limit`, or the last with newest=True)."""
        start = parse_timestamp(since) if since else None
        end = parse_timestamp(until) if until else None
        needle = text.lower() if text else None
        matches: deque[AuditEvent] | list[AuditEvent] = deque(maxlen=limit) if newest else []
        for event in self.store.events():
            if syscall and event.syscall != syscall:
                continue
            if pid is not None and pid not in (event.pid, event.ppid):
                continue
            if (uid is not None and event.uid != uid) or (host_id and event.host_id != host_id):
                continue
            if start or end:
                moment = parse_timestamp(event.timestamp)
                if (start and moment < start) or (end and moment > end):
                    continue
            if needle and needle not in (event.process + " " + canonical_json(event.arguments).decode("utf-8")).lower():
                continue
            matches.append(event)
            if not newest and len(matches) >= limit:
                break
        return list(matches)

    # ----------------------------------------------------------------- verify

    def verify(self) -> dict[str, Any]:
        """Check event links, batch roots, block links, signatures and block ranges in one pass."""
        problems: list[dict[str, Any]] = []
        warnings: list[dict[str, Any]] = []
        try:
            checkpoints = list(self.store.checkpoints())
            public_key = load_public_key(self.store.public_key_path) if checkpoints else None
            # Index checkpoint ranges so each event finds its block(s) in O(log n).
            order = sorted(range(len(checkpoints)), key=lambda index: checkpoints[index].first_sequence)
            starts = [checkpoints[index].first_sequence for index in order]
            reach: list[int] = []
            for index in order:
                reach.append(max(reach[-1] if reach else 0, checkpoints[index].last_sequence))
            batches: list[list[str]] = [[] for _ in checkpoints]

            expected_previous = GENESIS_HASH
            expected_sequence = 1
            events_checked = 0
            last_sequence = 0
            for event in self.store.events():
                events_checked += 1
                if event.sequence != expected_sequence:
                    problems.append({"type": "event-sequence", "sequence": event.sequence, "detail": "sequence is missing or reordered"})
                if event.previous_event_hash != expected_previous:
                    problems.append({"type": "event-link", "sequence": event.sequence, "detail": "previous-event hash does not match"})
                calculated_hash = event.calculate_hash()
                if event.event_hash != calculated_hash:
                    problems.append({"type": "event-hash", "sequence": event.sequence, "detail": "event contents were changed"})
                position = bisect_right(starts, event.sequence) - 1
                while position >= 0 and reach[position] >= event.sequence:
                    if checkpoints[order[position]].last_sequence >= event.sequence:
                        batches[order[position]].append(calculated_hash)
                    position -= 1
                expected_previous = calculated_hash
                expected_sequence += 1
                last_sequence = max(last_sequence, event.sequence)
        except ValueError as error:
            return _report([{"type": "storage", "detail": str(error)}], [], 0, 0)

        expected_block_hash = GENESIS_HASH
        expected_first = 1
        seen_batches: set[str] = set()
        committed_through = 0
        for index, checkpoint in enumerate(checkpoints):
            block = checkpoint.block_number
            if block != index + 1:
                problems.append({"type": "block-number", "block": block, "detail": f"expected block {index + 1}"})
            if checkpoint.previous_block_hash != expected_block_hash:
                problems.append({"type": "block-link", "block": block, "detail": "previous-block hash does not match"})
            if checkpoint.block_hash != checkpoint.calculate_block_hash():
                problems.append({"type": "block-hash", "block": block, "detail": "checkpoint contents were changed"})
            signed = {**checkpoint.unsigned_payload(), "block_hash": checkpoint.block_hash}
            if not verify_with(public_key, canonical_json(signed), checkpoint.signature):
                problems.append({"type": "signature", "block": block, "detail": "Ed25519 signature is invalid"})
            if checkpoint.batch_id in seen_batches:
                problems.append({"type": "replay", "block": block, "detail": f"batch {checkpoint.batch_id} was already committed"})
            elif checkpoint.first_sequence != expected_first:
                problems.append({"type": "block-range", "block": block, "detail": f"block starts at sequence {checkpoint.first_sequence}, expected {expected_first}"})
            seen_batches.add(checkpoint.batch_id)
            batch = batches[index]
            if len(batch) != checkpoint.event_count:
                problems.append({"type": "batch-count", "block": block, "detail": "events are missing from the committed range"})
            elif merkle_root(batch) != checkpoint.merkle_root:
                problems.append({"type": "merkle-root", "block": block, "detail": "batch events do not match the committed root"})
            expected_block_hash = checkpoint.block_hash
            expected_first = checkpoint.last_sequence + 1
            committed_through = max(committed_through, checkpoint.last_sequence)

        if last_sequence > committed_through:
            warnings.append({"type": "uncommitted-events", "detail": f"events after sequence {committed_through} have no checkpoint yet"})
        return _report(problems, warnings, events_checked, len(checkpoints))


def _report(problems: list[dict], warnings: list[dict], events_checked: int, checkpoints_checked: int) -> dict[str, Any]:
    verdict = "fail" if problems else ("partial" if warnings else "pass")
    return {
        "valid": not problems,
        "verdict": verdict,
        "events_checked": events_checked,
        "checkpoints_checked": checkpoints_checked,
        "first_problem": problems[0] if problems else None,
        "problems": problems,
        "warnings": warnings,
    }


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

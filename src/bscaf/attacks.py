"""Tampering scenarios from the brief's attack-test phase, applied to a copy of a store.

Each scenario edits a copied data directory the way an attacker with write
access (or, for `rewrite-and-resign`, with the stolen source signing key)
would, then the copy is verified locally and against the witnesses that hold
the original chain. Used by tests/test_attacks.py and scripts/attack_matrix.py.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
from pathlib import Path
import shutil
import tempfile
from typing import Any, Callable

from .canonical import canonical_json
from .crypto import load_private_key, sign_with
from .merkle import merkle_root
from .models import GENESIS_HASH, AuditEvent, Checkpoint
from .service import AuditService
from .store import AuditStore
from .witness import replicate, verify_with_witnesses


def _lines(path: Path) -> list[str]:
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _write(path: Path, lines: list[str]) -> None:
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")


def _middle_block(store: AuditStore) -> Checkpoint:
    checkpoints = list(store.checkpoints())
    return checkpoints[len(checkpoints) // 2]


def modify_event(store: AuditStore) -> None:
    lines = _lines(store.events_path)
    index = _middle_block(store).first_sequence - 1
    event = json.loads(lines[index])
    event["syscall"] = "unlinkat" if event["syscall"] != "unlinkat" else "openat"
    lines[index] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    _write(store.events_path, lines)


def delete_event(store: AuditStore) -> None:
    lines = _lines(store.events_path)
    del lines[_middle_block(store).first_sequence - 1]
    _write(store.events_path, lines)


def insert_event(store: AuditStore) -> None:
    lines = _lines(store.events_path)
    index = _middle_block(store).first_sequence - 1
    previous = AuditEvent.from_dict(json.loads(lines[index - 1])) if index else None
    forged = AuditEvent.from_input(
        {"timestamp": "2026-01-01T00:00:00Z", "pid": 4242, "ppid": 1, "uid": 0, "syscall": "execve", "process": "/tmp/implant"},
        previous.sequence + 1 if previous else 1,
        previous.event_hash if previous else GENESIS_HASH,
    )
    lines.insert(index, json.dumps(forged.to_dict(), sort_keys=True, separators=(",", ":")))
    _write(store.events_path, lines)


def reorder_events(store: AuditStore) -> None:
    lines = _lines(store.events_path)
    index = _middle_block(store).first_sequence - 1
    lines[index], lines[index + 1] = lines[index + 1], lines[index]
    _write(store.events_path, lines)


def modify_merkle_root(store: AuditStore) -> None:
    lines = _lines(store.checkpoints_path)
    index = _middle_block(store).block_number - 1
    block = json.loads(lines[index])
    block["merkle_root"] = "f" * 64
    lines[index] = json.dumps(block, sort_keys=True, separators=(",", ":"))
    _write(store.checkpoints_path, lines)


def replay_old_batch(store: AuditStore) -> None:
    lines = _lines(store.checkpoints_path)
    _write(store.checkpoints_path, lines + [lines[0]])


def truncate_tail(store: AuditStore) -> None:
    """Remove the newest block and its events: every remaining link still verifies locally."""
    checkpoints = list(store.checkpoints())
    last = checkpoints[-1]
    _write(store.checkpoints_path, _lines(store.checkpoints_path)[:-1])
    events = [line for line in _lines(store.events_path) if json.loads(line)["sequence"] < last.first_sequence]
    _write(store.events_path, events)


def rewrite_and_resign(store: AuditStore) -> None:
    """Attacker holding the source private key edits history and rebuilds every hash and signature."""
    events = list(store.events())
    target = _middle_block(store).first_sequence - 1
    rebuilt: list[AuditEvent] = []
    for index, event in enumerate(events):
        if index == target:
            event = replace(event, syscall="read", arguments={})
        previous = rebuilt[-1].event_hash if rebuilt else GENESIS_HASH
        event = replace(event, previous_event_hash=previous, event_hash="")
        rebuilt.append(replace(event, event_hash=event.calculate_hash()))
    _write(store.events_path, [json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":")) for event in rebuilt])
    key = load_private_key(store.private_key_path)
    hashes = {event.sequence: event.event_hash for event in rebuilt}
    blocks: list[Checkpoint] = []
    for block in store.checkpoints():
        unsigned = replace(
            block,
            previous_block_hash=blocks[-1].block_hash if blocks else GENESIS_HASH,
            merkle_root=merkle_root([hashes[sequence] for sequence in range(block.first_sequence, block.last_sequence + 1)]),
            signature="",
            block_hash="",
        )
        block_hash = unsigned.calculate_block_hash()
        signature = sign_with(key, canonical_json({**unsigned.unsigned_payload(), "block_hash": block_hash}))
        blocks.append(replace(unsigned, block_hash=block_hash, signature=signature))
    _write(store.checkpoints_path, [json.dumps(block.to_dict(), sort_keys=True, separators=(",", ":")) for block in blocks])


def forge_ack(store: AuditStore) -> None:
    lines = _lines(store.acks_path)
    ack = json.loads(lines[0])
    ack["block_number"] += 1000
    lines[0] = json.dumps(ack, sort_keys=True, separators=(",", ":"))
    _write(store.acks_path, lines)


def no_change(store: AuditStore) -> None:
    return None


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    tamper: Callable[[AuditStore], None]
    expected: str  # "local": caught without witnesses; "witness": caught only by witnesses; "partial"; "pass"
    offline_witnesses: int = 0


SCENARIOS = [
    Scenario("baseline", "untampered copy", no_change, "pass"),
    Scenario("modify-event", "change one committed event's system call", modify_event, "local"),
    Scenario("delete-event", "remove one committed event", delete_event, "local"),
    Scenario("insert-event", "insert a forged, correctly hashed event", insert_event, "local"),
    Scenario("reorder-events", "swap two adjacent committed events", reorder_events, "local"),
    Scenario("modify-merkle-root", "replace a stored batch Merkle root", modify_merkle_root, "local"),
    Scenario("replay-old-batch", "append a copy of an old signed checkpoint", replay_old_batch, "local"),
    Scenario("truncate-tail", "delete the newest block and its events", truncate_tail, "witness"),
    Scenario("rewrite-and-resign", "edit history and re-sign every block with the stolen source key", rewrite_and_resign, "witness"),
    Scenario("forge-ack", "alter a stored witness acknowledgement", forge_ack, "witness"),
    Scenario("witness-offline", "one witness unreachable; quorum still met", no_change, "pass", offline_witnesses=1),
    Scenario("witness-quorum-lost", "witnesses unreachable below quorum", no_change, "partial", offline_witnesses=2),
]

UNREACHABLE = "http://127.0.0.1:9"


def run_scenario(
    scenario: Scenario,
    source_dir: Path,
    witness_urls: list[str],
    witness_keys: dict[str, Path],
    quorum: int,
    signer_id: str,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as directory:
        copy = Path(directory) / "store"
        shutil.copytree(source_dir, copy, ignore=shutil.ignore_patterns(".lock"))
        service = AuditService(copy, signer_id=signer_id)
        scenario.tamper(service.store)
        local = service.verify()
        urls = [UNREACHABLE] * scenario.offline_witnesses + witness_urls[scenario.offline_witnesses:]
        full = verify_with_witnesses(local, service.checkpoints(), service.store.acks(), service.store.public_key_path, urls, witness_keys, quorum, signer_id, timeout=2.0)
        fork_rejected = None
        if scenario.name == "rewrite-and-resign":
            summary, _ = replicate(witness_urls, service.checkpoints(), [], quorum, timeout=2.0)
            fork_rejected = all(item["error"] and "conflicting block" in item["error"] for item in summary["witnesses"])
    detected_by = "local" if not local["valid"] else ("witness" if not full["valid"] else "-")
    outcome = full["verdict"] if detected_by == "-" else detected_by
    result = {
        "scenario": scenario.name,
        "description": scenario.description,
        "expected": scenario.expected,
        "local_verdict": local["verdict"],
        "local_problems": sorted({problem["type"] for problem in local["problems"]}),
        "witness_verdict": full["verdict"],
        "witness_problems": sorted({problem["type"] for problem in full["problems"]} - {problem["type"] for problem in local["problems"]}),
        "witness_warnings": sorted({warning["type"] for warning in full["warnings"]}),
        "detected_by": detected_by,
        "as_expected": outcome == scenario.expected,
    }
    if fork_rejected is not None:
        result["witnesses_rejected_rewritten_blocks"] = fork_rejected
    return result


def run_matrix(source_dir: Path, witness_urls: list[str], witness_keys: dict[str, Path], quorum: int, signer_id: str) -> list[dict[str, Any]]:
    return [run_scenario(scenario, source_dir, witness_urls, witness_keys, quorum, signer_id) for scenario in SCENARIOS]


def matrix_markdown(rows: list[dict[str, Any]]) -> str:
    lines = [
        "| Scenario | Attack | Local verdict | With witnesses | Detected by | Evidence | As expected |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        evidence = ", ".join(row["local_problems"] + row["witness_problems"]) or ", ".join(row["witness_warnings"]) or "-"
        lines.append(f"| {row['scenario']} | {row['description']} | {row['local_verdict']} | {row['witness_verdict']} | {row['detected_by']} | {evidence} | {'yes' if row['as_expected'] else '**NO**'} |")
    return "\n".join(lines)

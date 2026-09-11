"""Standalone verification for exported event inclusion proofs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import canonical_json
from .crypto import verify
from .merkle import verify_inclusion
from .models import AuditEvent, Checkpoint


def verify_exported_proof(payload: dict[str, Any], public_key_path: Path) -> dict[str, Any]:
    """Verify an event, its Merkle path, and its signed checkpoint offline."""
    problems: list[str] = []
    try:
        event = AuditEvent.from_dict(payload["event"])
        checkpoint = Checkpoint.from_dict(payload["checkpoint"])
        proof = [(item["side"], item["hash"]) for item in payload["proof"]]
    except (KeyError, TypeError, ValueError) as error:
        return {"valid": False, "problems": [f"invalid proof structure: {error}"]}
    if event.event_hash != event.calculate_hash():
        problems.append("event hash does not match event content")
    if payload.get("leaf_hash") != event.event_hash:
        problems.append("proof leaf differs from the event hash")
    if not verify_inclusion(event.event_hash, proof, checkpoint.merkle_root):
        problems.append("Merkle inclusion proof is invalid")
    if checkpoint.block_hash != checkpoint.calculate_block_hash():
        problems.append("checkpoint block hash is invalid")
    signed = {**checkpoint.unsigned_payload(), "block_hash": checkpoint.block_hash}
    if not verify(public_key_path, canonical_json(signed), checkpoint.signature):
        problems.append("checkpoint signature is invalid")
    return {"valid": not problems, "sequence": event.sequence, "block_number": checkpoint.block_number, "problems": problems}

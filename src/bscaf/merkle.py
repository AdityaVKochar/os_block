"""Merkle-tree construction and inclusion proof verification."""

from __future__ import annotations

from .canonical import sha256_hex


def _parent(left: str, right: str) -> str:
    return sha256_hex(bytes.fromhex(left) + bytes.fromhex(right))


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        raise ValueError("cannot create a Merkle root for an empty batch")
    level = leaves[:]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_parent(level[index], level[index + 1]) for index in range(0, len(level), 2)]
    return level[0]


def inclusion_proof(leaves: list[str], index: int) -> list[tuple[str, str]]:
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index is outside this batch")
    proof: list[tuple[str, str]] = []
    level = leaves[:]
    position = index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sibling_index = position - 1 if position % 2 else position + 1
        side = "left" if position % 2 else "right"
        proof.append((side, level[sibling_index]))
        position //= 2
        level = [_parent(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return proof


def verify_inclusion(leaf: str, proof: list[tuple[str, str]], root: str) -> bool:
    current = leaf
    for side, sibling in proof:
        current = _parent(sibling, current) if side == "left" else _parent(current, sibling)
    return current == root

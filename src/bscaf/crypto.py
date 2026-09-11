"""Ed25519 key management and signatures for checkpoint blocks."""

from __future__ import annotations

import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def create_keypair(private_path: Path, public_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def sign(private_path: Path, payload: bytes) -> str:
    key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("expected an Ed25519 private key")
    return base64.b64encode(key.sign(payload)).decode("ascii")


def verify(public_path: Path, payload: bytes, signature: str) -> bool:
    key = serialization.load_pem_public_key(public_path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("expected an Ed25519 public key")
    try:
        key.verify(base64.b64decode(signature), payload)
        return True
    except Exception:
        return False

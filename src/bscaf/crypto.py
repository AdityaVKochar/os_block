"""Ed25519 key management and signatures for checkpoint blocks."""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# When set, new private keys are encrypted with this passphrase and existing ones need it to load.
PASSPHRASE_ENV = "BSCAF_KEY_PASSPHRASE"


def _passphrase() -> bytes | None:
    value = os.environ.get(PASSPHRASE_ENV)
    return value.encode("utf-8") if value else None


def create_keypair(private_path: Path, public_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    passphrase = _passphrase()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption(),
    )
    # Create the private key owner-readable only, before any bytes are written.
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(private_bytes)
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_private_key(private_path: Path) -> Ed25519PrivateKey:
    data = private_path.read_bytes()
    passphrase = _passphrase() if b"ENCRYPTED" in data else None
    if b"ENCRYPTED" in data and passphrase is None:
        raise ValueError(f"{private_path} is encrypted; set {PASSPHRASE_ENV}")
    key = serialization.load_pem_private_key(data, password=passphrase)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("expected an Ed25519 private key")
    return key


def load_public_key(public_path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(public_path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("expected an Ed25519 public key")
    return key


def sign_with(key: Ed25519PrivateKey, payload: bytes) -> str:
    return base64.b64encode(key.sign(payload)).decode("ascii")


def verify_with(key: Ed25519PublicKey, payload: bytes, signature: str) -> bool:
    try:
        key.verify(base64.b64decode(signature, validate=True), payload)
        return True
    except (InvalidSignature, ValueError):
        return False


def sign(private_path: Path, payload: bytes) -> str:
    return sign_with(load_private_key(private_path), payload)


def verify(public_path: Path, payload: bytes, signature: str) -> bool:
    return verify_with(load_public_key(public_path), payload, signature)

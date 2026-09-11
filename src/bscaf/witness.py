"""Permissioned HTTP witness for independently retained checkpoints.

The witness receives checkpoint metadata only. Raw system-call events never
leave the source audit store through this protocol.
"""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from shutil import copyfile
from typing import Any
from urllib.request import Request, urlopen

from .canonical import canonical_json
from .crypto import verify
from .models import Checkpoint


class WitnessStore:
    def __init__(self, root: Path):
        self.root = root
        self.trusted_signers = root / "trusted-signers"
        self.checkpoints_path = root / "witness-checkpoints.jsonl"

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.trusted_signers.mkdir(exist_ok=True)
        self.checkpoints_path.touch(exist_ok=True)

    def trust_signer(self, signer_id: str, public_key_path: Path) -> Path:
        if not signer_id.replace("-", "").replace("_", "").isalnum():
            raise ValueError("signer ID may contain only letters, numbers, hyphens and underscores")
        self.initialize()
        destination = self.trusted_signers / f"{signer_id}.pem"
        copyfile(public_key_path, destination)
        return destination

    def accept(self, checkpoint_payload: dict[str, Any]) -> dict[str, Any]:
        self.initialize()
        checkpoint = Checkpoint.from_dict(checkpoint_payload)
        trusted_key = self.trusted_signers / f"{checkpoint.signer_id}.pem"
        if not trusted_key.exists():
            raise ValueError(f"untrusted signer: {checkpoint.signer_id}")
        if checkpoint.block_hash != checkpoint.calculate_block_hash():
            raise ValueError("checkpoint block hash is invalid")
        signed_payload = {**checkpoint.unsigned_payload(), "block_hash": checkpoint.block_hash}
        if not verify(trusted_key, canonical_json(signed_payload), checkpoint.signature):
            raise ValueError("checkpoint signature is invalid")
        known = self.checkpoints_path.read_text(encoding="utf-8").splitlines()
        if any(json.loads(line).get("block_hash") == checkpoint.block_hash for line in known if line.strip()):
            return {"accepted": True, "duplicate": True, "block_hash": checkpoint.block_hash}
        with self.checkpoints_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(checkpoint.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")
        return {"accepted": True, "duplicate": False, "block_hash": checkpoint.block_hash}


def replicate_checkpoint(url: str, checkpoint: Checkpoint, timeout: float = 5.0) -> dict[str, Any]:
    request = Request(
        url.rstrip("/") + "/checkpoints",
        data=canonical_json(checkpoint.to_dict()),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def serve_witness(root: Path, host: str, port: int) -> None:
    store = WitnessStore(root)
    store.initialize()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 (HTTP naming convention)
            if self.path != "/checkpoints":
                self.send_error(HTTPStatus.NOT_FOUND, "unknown endpoint")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 64 * 1024:
                    raise ValueError("request body must be between 1 and 65536 bytes")
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                result = store.accept(payload)
                body = canonical_json(result)
                self.send_response(HTTPStatus.CREATED)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (ValueError, json.JSONDecodeError, TypeError) as error:
                body = canonical_json({"accepted": False, "error": str(error)})
                self.send_response(HTTPStatus.BAD_REQUEST)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return

    ThreadingHTTPServer((host, port), Handler).serve_forever()

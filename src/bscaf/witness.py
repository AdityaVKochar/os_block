"""Permissioned witnesses that independently retain and acknowledge checkpoints.

A witness receives checkpoint metadata only; raw system-call events never
leave the source audit store through this protocol. Each witness:

* accepts blocks only from trusted source signers, with valid hashes and
  signatures, and only when they extend the chain it already holds;
* refuses (and records) a different block for a number it has seen, which is
  how a rewritten or forked source ledger is exposed;
* returns an Ed25519-signed acknowledgement so the source can prove quorum.

`replicate` pushes blocks to several witnesses, and `verify_with_witnesses`
compares the local ledger with every reachable witness copy, which detects
tail truncation and re-signing with a stolen source key that local
verification alone cannot see.
"""

from __future__ import annotations

from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from shutil import copyfile
import ssl
import threading
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlparse
from urllib.request import Request, urlopen

from .canonical import canonical_json
from .crypto import create_keypair, load_private_key, load_public_key, sign_with, verify_with
from .models import GENESIS_HASH, Checkpoint

ACK_FIELDS = ("witness_id", "signer_id", "block_number", "block_hash", "received_at")


class WitnessConflict(ValueError):
    """A different block was offered for a number the witness already holds."""


def _valid_id(value: str) -> str:
    if not value or not value.replace("-", "").replace("_", "").isalnum():
        raise ValueError("IDs may contain only letters, numbers, hyphens and underscores")
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def ack_payload(ack: dict[str, Any]) -> bytes:
    return canonical_json({key: ack[key] for key in ACK_FIELDS})


def verify_ack(ack: dict[str, Any], witness_public_key: Path) -> bool:
    try:
        return verify_with(load_public_key(witness_public_key), ack_payload(ack), ack["signature"])
    except (KeyError, TypeError, ValueError):
        return False


class WitnessStore:
    def __init__(self, root: Path, witness_id: str | None = None):
        self.root = root
        self.trusted_signers = root / "trusted-signers"
        self.checkpoints_path = root / "witness-checkpoints.jsonl"
        self.equivocations_path = root / "equivocations.jsonl"
        self.identity_path = root / "witness.json"
        self.private_key_path = root / "witness-private.pem"
        self.public_key_path = root / "witness-public.pem"
        self._requested_id = witness_id
        self._lock = threading.Lock()
        self._chains: dict[str, list[Checkpoint]] | None = None
        self._private_key = None
        self._witness_id: str | None = None

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.trusted_signers.mkdir(exist_ok=True)
        self.checkpoints_path.touch(exist_ok=True)
        if not self.identity_path.exists():
            identity = {"witness_id": _valid_id(self._requested_id or "witness")}
            self.identity_path.write_text(json.dumps(identity), encoding="utf-8")
        if not self.private_key_path.exists():
            create_keypair(self.private_key_path, self.public_key_path)

    @property
    def witness_id(self) -> str:
        if self._witness_id is None:
            self.initialize()
            self._witness_id = json.loads(self.identity_path.read_text(encoding="utf-8"))["witness_id"]
        return self._witness_id

    def trust_signer(self, signer_id: str, public_key_path: Path) -> Path:
        self.initialize()
        destination = self.trusted_signers / f"{_valid_id(signer_id)}.pem"
        copyfile(public_key_path, destination)
        return destination

    def _chain_index(self) -> dict[str, list[Checkpoint]]:
        if self._chains is None:
            self.initialize()
            chains: dict[str, list[Checkpoint]] = {}
            for line in self.checkpoints_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    checkpoint = Checkpoint.from_dict(json.loads(line))
                    chains.setdefault(checkpoint.signer_id, []).append(checkpoint)
            self._chains = chains
        return self._chains

    def ledger(self, signer_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [checkpoint.to_dict() for checkpoint in self._chain_index().get(signer_id, [])]

    def accept(self, checkpoint_payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            return self._accept(checkpoint_payload)

    def _accept(self, checkpoint_payload: dict[str, Any]) -> dict[str, Any]:
        self.initialize()
        checkpoint = Checkpoint.from_dict(checkpoint_payload)
        trusted_key = self.trusted_signers / f"{_valid_id(checkpoint.signer_id)}.pem"
        if not trusted_key.exists():
            raise ValueError(f"untrusted signer: {checkpoint.signer_id}")
        if checkpoint.block_hash != checkpoint.calculate_block_hash():
            raise ValueError("checkpoint block hash is invalid")
        signed_payload = {**checkpoint.unsigned_payload(), "block_hash": checkpoint.block_hash}
        if not verify_with(load_public_key(trusted_key), canonical_json(signed_payload), checkpoint.signature):
            raise ValueError("checkpoint signature is invalid")

        chain = self._chain_index().setdefault(checkpoint.signer_id, [])
        number = checkpoint.block_number
        if 1 <= number <= len(chain):
            held = chain[number - 1]
            if held.block_hash == checkpoint.block_hash:
                return self._ack(checkpoint, duplicate=True)
            evidence = {"signer_id": checkpoint.signer_id, "block_number": number, "held_block_hash": held.block_hash, "offered": checkpoint.to_dict(), "received_at": _now()}
            with self.equivocations_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n")
            raise WitnessConflict(f"conflicting block {number}: witness already holds {held.block_hash[:16]}")
        if number != len(chain) + 1:
            raise ValueError(f"block {number} does not follow witnessed block {len(chain)}")
        expected_previous = chain[-1].block_hash if chain else GENESIS_HASH
        if checkpoint.previous_block_hash != expected_previous:
            raise WitnessConflict(f"block {number} does not extend the witnessed chain")
        with self.checkpoints_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(checkpoint.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")
        chain.append(checkpoint)
        return self._ack(checkpoint, duplicate=False)

    def _ack(self, checkpoint: Checkpoint, duplicate: bool) -> dict[str, Any]:
        if self._private_key is None:
            self._private_key = load_private_key(self.private_key_path)
        ack = {
            "witness_id": self.witness_id,
            "signer_id": checkpoint.signer_id,
            "block_number": checkpoint.block_number,
            "block_hash": checkpoint.block_hash,
            "received_at": _now(),
        }
        return {**ack, "signature": sign_with(self._private_key, ack_payload(ack)), "accepted": True, "duplicate": duplicate}


# ---------------------------------------------------------------- client side


def _request(url: str, payload: dict | None = None, timeout: float = 5.0, context: ssl.SSLContext | None = None) -> dict[str, Any]:
    data = None if payload is None else canonical_json(payload)
    request = Request(url, data=data, headers={"Content-Type": "application/json"}, method="GET" if data is None else "POST")
    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        try:
            message = json.loads(error.read().decode("utf-8")).get("error")
        except (ValueError, AttributeError):
            message = None
        raise ValueError(message or f"HTTP {error.code}") from error


def replicate_checkpoint(url: str, checkpoint: Checkpoint, timeout: float = 5.0, context: ssl.SSLContext | None = None) -> dict[str, Any]:
    return _request(url.rstrip("/") + "/checkpoints", checkpoint.to_dict(), timeout, context)


def replicate(
    urls: Iterable[str],
    checkpoints: list[Checkpoint],
    known_acks: Iterable[dict],
    quorum: int,
    timeout: float = 5.0,
    context: ssl.SSLContext | None = None,
) -> tuple[dict[str, Any], list[dict]]:
    """Push blocks to every witness; return a quorum summary and the new acknowledgements."""
    acked = {(ack["witness_id"], ack["block_hash"]) for ack in known_acks}
    witnesses, new_acks = [], []
    for url in urls:
        summary: dict[str, Any] = {"url": url, "available": False, "witness_id": None, "acked_blocks": 0, "error": None}
        try:
            health = _request(url.rstrip("/") + "/health", timeout=timeout, context=context)
            summary.update(available=True, witness_id=health["witness_id"])
            for checkpoint in checkpoints:
                if (health["witness_id"], checkpoint.block_hash) not in acked:
                    ack = replicate_checkpoint(url, checkpoint, timeout, context)
                    new_acks.append({key: ack[key] for key in (*ACK_FIELDS, "signature")})
                summary["acked_blocks"] += 1
        except (OSError, URLError, ValueError, KeyError) as error:
            summary["error"] = str(getattr(error, "reason", error))
        witnesses.append(summary)
    complete = sum(1 for item in witnesses if item["available"] and item["acked_blocks"] == len(checkpoints) and not item["error"])
    return {"blocks": len(checkpoints), "quorum": quorum, "witnesses_complete": complete, "quorum_met": complete >= quorum, "witnesses": witnesses}, new_acks


def verify_with_witnesses(
    report: dict[str, Any],
    checkpoints: list[Checkpoint],
    acks: Iterable[dict],
    source_public_key: Path,
    urls: Iterable[str],
    witness_keys: dict[str, Path],
    quorum: int,
    signer_id: str,
    timeout: float = 5.0,
    context: ssl.SSLContext | None = None,
) -> dict[str, Any]:
    """Extend a local verification report with witness ledger comparison and ack checks."""
    problems = list(report["problems"])
    warnings = list(report["warnings"])
    source_key = load_public_key(source_public_key) if source_public_key.exists() else None
    witnesses = []
    for url in urls:
        entry: dict[str, Any] = {"url": url, "available": False, "witness_id": None, "blocks": 0, "consistent": None, "error": None}
        try:
            health = _request(url.rstrip("/") + "/health", timeout=timeout, context=context)
            remote = _request(url.rstrip("/") + f"/checkpoints?signer={quote(signer_id)}", timeout=timeout, context=context)["checkpoints"]
            entry.update(available=True, witness_id=health["witness_id"], blocks=len(remote))
        except (OSError, URLError, ValueError, KeyError) as error:
            entry["error"] = str(getattr(error, "reason", error))
            witnesses.append(entry)
            continue
        consistent = True
        for index, payload in enumerate(remote):
            block = Checkpoint.from_dict(payload)
            signed = canonical_json({**block.unsigned_payload(), "block_hash": block.block_hash})
            if source_key is None or block.block_hash != block.calculate_block_hash() or not verify_with(source_key, signed, block.signature):
                warnings.append({"type": "witness-untrusted", "witness": entry["witness_id"], "block": block.block_number, "detail": "witness copy is not signed by the source key; ignored"})
                consistent = False
                break
            if index >= len(checkpoints):
                problems.append({"type": "truncation", "witness": entry["witness_id"], "block": block.block_number, "detail": "witness holds a block that is missing from the local ledger"})
                consistent = False
                break
            if checkpoints[index].block_hash != block.block_hash:
                problems.append({"type": "witness-mismatch", "witness": entry["witness_id"], "block": block.block_number, "detail": "local block differs from the witnessed block (rewritten ledger)"})
                consistent = False
                break
        entry["consistent"] = consistent
        witnesses.append(entry)

    valid_acks: dict[str, set[str]] = {}
    for ack in acks:
        key = witness_keys.get(ack.get("witness_id", ""))
        if key is None:
            continue
        if not verify_ack(ack, key):
            problems.append({"type": "forged-ack", "witness": ack.get("witness_id"), "block": ack.get("block_number"), "detail": "witness acknowledgement signature is invalid"})
            continue
        valid_acks.setdefault(ack["block_hash"], set()).add(ack["witness_id"])
    under = [checkpoint.block_number for checkpoint in checkpoints if len(valid_acks.get(checkpoint.block_hash, ())) < quorum]
    if witness_keys and under:
        warnings.append({"type": "under-witnessed", "blocks": len(under), "first_block": under[0], "detail": f"{len(under)} block(s) have fewer than {quorum} valid witness acknowledgements"})

    # A witness is complete when it is reachable, consistent and holds every local block.
    complete = sum(1 for entry in witnesses if entry["available"] and entry["consistent"] and entry["blocks"] >= len(checkpoints))
    quorum_met = complete >= quorum
    notices: list[dict[str, Any]] = []
    for entry in witnesses:
        if not entry["available"]:
            (notices if quorum_met else warnings).append({"type": "witness-unavailable", "url": entry["url"], "detail": entry["error"]})
        elif entry["consistent"] and entry["blocks"] < len(checkpoints):
            (notices if quorum_met else warnings).append({"type": "unwitnessed-blocks", "witness": entry["witness_id"], "detail": f"witness holds {entry['blocks']} of {len(checkpoints)} blocks"})
    if not quorum_met:
        warnings.append({"type": "witness-quorum", "detail": f"{complete} complete, consistent witness(es) reachable; quorum is {quorum}"})

    verdict = "fail" if problems else ("partial" if warnings else "pass")
    return {
        **report,
        "valid": not problems,
        "verdict": verdict,
        "first_problem": problems[0] if problems else None,
        "problems": problems,
        "warnings": warnings,
        "notices": notices,
        "witness_quorum": {"required": quorum, "complete": complete, "met": quorum_met},
        "witnesses": witnesses,
    }


# ---------------------------------------------------------------- HTTP server


class _TLSThreadingHTTPServer(ThreadingHTTPServer):
    """HTTPS server whose TLS handshake runs in the request thread, so a slow client cannot stall accept()."""

    def __init__(self, address, handler, context: ssl.SSLContext):
        self.tls_context = context
        super().__init__(address, handler)

    def finish_request(self, request, client_address) -> None:
        try:
            request = self.tls_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        super().finish_request(request, client_address)


def make_witness_server(root: Path, host: str, port: int, tls: ssl.SSLContext | None = None) -> ThreadingHTTPServer:
    store = WitnessStore(root)
    store.initialize()

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
            body = canonical_json(payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 (HTTP naming convention)
            parsed = urlparse(self.path)
            if parsed.path == "/health":
                self._send(HTTPStatus.OK, {"status": "ok", "witness_id": store.witness_id})
            elif parsed.path == "/checkpoints":
                signer = parse_qs(parsed.query).get("signer", [""])[0]
                self._send(HTTPStatus.OK, {"witness_id": store.witness_id, "signer_id": signer, "checkpoints": store.ledger(signer)})
            else:
                self._send(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})

        def do_POST(self) -> None:  # noqa: N802 (HTTP naming convention)
            if self.path != "/checkpoints":
                self._send(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 64 * 1024:
                    raise ValueError("request body must be between 1 and 65536 bytes")
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                self._send(HTTPStatus.CREATED, store.accept(payload))
            except WitnessConflict as error:
                self._send(HTTPStatus.CONFLICT, {"accepted": False, "error": str(error)})
            except (ValueError, json.JSONDecodeError, TypeError) as error:
                self._send(HTTPStatus.BAD_REQUEST, {"accepted": False, "error": str(error)})

        def log_message(self, format: str, *args: Any) -> None:
            return

    return _TLSThreadingHTTPServer((host, port), Handler, tls) if tls else ThreadingHTTPServer((host, port), Handler)


def serve_witness(root: Path, host: str, port: int, tls: ssl.SSLContext | None = None) -> None:
    make_witness_server(root, host, port, tls).serve_forever()


def start_local_witnesses(
    base_dir: Path, count: int, signer_id: str, source_public_key: Path, tls: ssl.SSLContext | None = None
) -> tuple[list[str], dict[str, Path], list[ThreadingHTTPServer]]:
    """Run `count` witnesses on ephemeral localhost ports (tests, demos and experiments)."""
    urls, keys, servers = [], {}, []
    for index in range(1, count + 1):
        store = WitnessStore(base_dir / f"witness-{index}", witness_id=f"witness-{index}")
        store.trust_signer(signer_id, source_public_key)
        server = make_witness_server(store.root, "127.0.0.1", 0, tls)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        urls.append(f"{'https' if tls else 'http'}://127.0.0.1:{server.server_address[1]}")
        keys[store.witness_id] = store.public_key_path
        servers.append(server)
    return urls, keys, servers

"""Command-line entry point for the B-SCAF prototype."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Iterator

from .auditd import AuditdParser, event_order, follow_lines, open_lines, parse_timezone
from .policy import AuditPolicy
from .service import AuditService
from .witness import WitnessStore, replicate, serve_witness, verify_with_witnesses
from .proof import verify_exported_proof
from .ui import serve_ui


def _policy(args: argparse.Namespace) -> AuditPolicy:
    policy = AuditPolicy.from_file(Path(args.policy)) if args.policy else AuditPolicy()
    if args.all_syscalls:
        policy = AuditPolicy(allowed_syscalls=None, redact_argument_keys=policy.redact_argument_keys, max_argument_length=policy.max_argument_length)
    return policy


def _service(args: argparse.Namespace) -> AuditService:
    return AuditService(
        Path(args.data_dir),
        batch_size=args.batch_size,
        signer_id=args.signer_id,
        policy=_policy(args),
        batch_seconds=args.batch_seconds,
        durable=not args.no_fsync,
    )


def _print(payload: Any) -> None:
    print(json.dumps(payload, indent=2))


def _jsonl(path: str) -> Iterator[dict]:
    with open_lines(path) as handle:
        for number, line in enumerate(handle, start=1):
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(f"input line {number}: {error}") from error


class _IngestCursor:
    """Remembers the newest audit record per host so re-reading a log never duplicates events."""

    def __init__(self, path: Path, enabled: bool = True):
        self.path = path
        self.previous = json.loads(path.read_text(encoding="utf-8")) if path.exists() and enabled else {}
        self.latest = dict(self.previous)
        self.duplicates = 0

    def fresh(self, events: Iterator[dict]) -> Iterator[dict]:
        for event in events:
            order = list(event_order(event))
            if order <= self.previous.get(event["host_id"], [-1, -1]):
                self.duplicates += 1
                continue
            self.latest[event["host_id"]] = max(order, self.latest.get(event["host_id"], order))
            yield event

    def save(self) -> None:
        self.path.write_text(json.dumps(self.latest, sort_keys=True), encoding="utf-8")


def _ingest_auditd(service: AuditService, args: argparse.Namespace) -> dict[str, Any]:
    service.initialize()
    parser = AuditdParser(host_id=args.host_id, assume_tz=parse_timezone(args.assume_tz), strict=args.strict)
    cursor = _IngestCursor(service.store.ingest_state_path, enabled=not args.no_dedupe)
    totals = {"accepted": 0, "ignored_by_policy": 0, "invalid_events": {}, "checkpoints_created": 0}

    def ingest(events: list[dict]) -> None:
        stats = service.ingest_many(cursor.fresh(iter(events)), strict=args.strict).to_dict()
        for key in ("accepted", "ignored_by_policy", "checkpoints_created"):
            totals[key] += stats[key]
        for reason, count in stats["rejected"].items():
            totals["invalid_events"][reason] = totals["invalid_events"].get(reason, 0) + count
        cursor.save()

    if args.follow:
        pending: list[dict] = []
        try:
            for line in follow_lines(args.input):
                if line is not None:
                    pending.extend(parser.feed(line))
                    if len(pending) < 512:
                        continue
                else:
                    pending.extend(parser.finish())
                if pending:
                    ingest(pending)
                    pending = []
                service.commit_due()
        except KeyboardInterrupt:
            ingest(pending + parser.finish())
    else:
        with open_lines(args.input) as handle:
            # Exports are often newest-first; commit a finished file in audit order.
            ingest(sorted(parser.parse_lines(handle), key=event_order))
    return {**totals, "duplicates_skipped": cursor.duplicates, "policy_version": service.policy.version, **parser.stats()}


def main() -> None:
    parser = argparse.ArgumentParser(description="B-SCAF lightweight audit prototype")
    parser.add_argument("--data-dir", default="audit-data")
    parser.add_argument("--batch-size", type=int, default=10, help="commit a block every N events")
    parser.add_argument("--batch-seconds", type=float, help="also commit when a batch spans T seconds of events")
    parser.add_argument("--signer-id", default="local-witness")
    parser.add_argument("--policy", help="JSON policy file (allowed_syscalls, redact_argument_keys, max_argument_length)")
    parser.add_argument("--all-syscalls", action="store_true", help="keep every system call (redaction still applies)")
    parser.add_argument("--no-fsync", action="store_true", help="skip fsync on commit (benchmarking only)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    ingest = sub.add_parser("ingest", help="ingest newline-delimited JSON events")
    ingest.add_argument("--input", required=True, help="JSONL file, .gz file or - for stdin")
    auditd = sub.add_parser("ingest-auditd", help="ingest raw, enriched or ausearch -i audit logs")
    auditd.add_argument("--input", required=True, help="audit log, .gz rotation or - for stdin")
    auditd.add_argument("--host-id", help="host identifier (default: node= field or localhost)")
    auditd.add_argument("--assume-tz", default="UTC", help="timezone of ausearch -i local timestamps, e.g. +05:30")
    auditd.add_argument("--strict", action="store_true", help="stop at the first malformed record")
    auditd.add_argument("--follow", action="store_true", help="keep tailing the log (handles rotation); Ctrl+C to stop")
    auditd.add_argument("--no-dedupe", action="store_true", help="also ingest records older than the last ingested one for the host")
    sub.add_parser("flush")
    verify = sub.add_parser("verify", help="verify the local ledger, optionally against witnesses")
    verify.add_argument("--witness", action="append", default=[], help="witness base URL (repeatable)")
    verify.add_argument("--witness-key", action="append", default=[], help="WITNESS_ID=public-key.pem for checking acks (repeatable)")
    verify.add_argument("--quorum", type=int, default=1, help="consistent witnesses required for a pass verdict")
    verify.add_argument("--timeout", type=float, default=5.0)
    proof = sub.add_parser("proof")
    proof.add_argument("--sequence", type=int, required=True)
    proof_verify = sub.add_parser("proof-verify")
    proof_verify.add_argument("--input", required=True, help="proof JSON exported by the proof command")
    proof_verify.add_argument("--public-key", required=True, help="trusted source Ed25519 public key")
    sub.add_parser("status")
    sub.add_parser("policy", help="print the effective policy and its version")
    replicate_cmd = sub.add_parser("replicate", help="push checkpoints to witnesses and collect signed acks")
    replicate_cmd.add_argument("--url", action="append", required=True, help="witness base URL (repeatable)")
    replicate_cmd.add_argument("--quorum", type=int, default=1, help="witnesses that must hold every block")
    replicate_cmd.add_argument("--timeout", type=float, default=5.0)
    witness_init = sub.add_parser("witness-init", help="create a witness identity and signing key")
    witness_init.add_argument("--witness-dir", required=True)
    witness_init.add_argument("--witness-id", required=True)
    witness_trust = sub.add_parser("witness-trust")
    witness_trust.add_argument("--witness-dir", required=True)
    witness_trust.add_argument("--public-key", required=True)
    witness_trust.add_argument("--trusted-signer-id", required=True)
    witness_serve = sub.add_parser("witness-serve")
    witness_serve.add_argument("--witness-dir", required=True)
    witness_serve.add_argument("--host", default="127.0.0.1")
    witness_serve.add_argument("--port", type=int, default=8080)
    ui = sub.add_parser("ui", help="run the minimal local audit dashboard")
    ui.add_argument("--host", default="127.0.0.1")
    ui.add_argument("--port", type=int, default=8000)
    ui.add_argument("--no-browser", action="store_true", help="do not open the dashboard automatically")
    sub.add_parser("demo")
    bench = sub.add_parser("bench", help="compare plain logging, hash chain only and B-SCAF")
    bench.add_argument("--events", type=int, default=100_000)
    bench.add_argument("--source", choices=("real", "synthetic"), default="real")
    bench.add_argument("--dataset-dir", default="datasets/raw")
    bench.add_argument("--batch-sizes", default="10,100,1000")
    bench.add_argument("--batch-seconds", type=float, default=0.05, help="also run a time-batched configuration")
    bench.add_argument("--fsync", action="store_true", help="add durable (fsync) configurations")
    bench.add_argument("--witnesses", type=int, default=3, help="replicate the N=100 run to this many local witnesses")
    bench.add_argument("--out", default="results")
    args = parser.parse_args()
    try:
        service = _service(args)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    if args.command == "init":
        service.initialize()
        print(json.dumps({"initialized": str(Path(args.data_dir)), "policy_version": service.policy.version}))
    elif args.command == "ingest":
        try:
            stats = service.ingest_many(_jsonl(args.input), strict=True)
        except (TypeError, ValueError) as error:
            parser.error(str(error))
        print(json.dumps({"ingested": stats.accepted, "ignored_by_policy": stats.ignored_by_policy}))
    elif args.command == "ingest-auditd":
        try:
            _print(_ingest_auditd(service, args))
        except ValueError as error:
            parser.error(f"audit log: {error}")
    elif args.command == "flush":
        block = service.flush()
        _print({"checkpoint": None if block is None else block.to_dict()})
    elif args.command == "verify":
        report = service.verify()
        if args.witness:
            try:
                keys = {item.split("=", 1)[0]: Path(item.split("=", 1)[1]) for item in args.witness_key}
            except IndexError:
                parser.error("--witness-key must look like WITNESS_ID=path.pem")
            report = verify_with_witnesses(
                report, service.checkpoints(), service.store.acks(), service.store.public_key_path,
                args.witness, keys, args.quorum, args.signer_id, args.timeout,
            )
        _print(report)
        sys.exit(0 if report["valid"] else 1)
    elif args.command == "proof":
        _print(service.inclusion_proof(args.sequence))
    elif args.command == "proof-verify":
        payload = json.loads(Path(args.input).read_text(encoding="utf-8-sig"))
        result = verify_exported_proof(payload, Path(args.public_key))
        _print(result)
        sys.exit(0 if result["valid"] else 1)
    elif args.command == "status":
        _print({"data_dir": str(Path(args.data_dir)), "policy_version": service.policy.version, **service.verify()})
    elif args.command == "policy":
        _print({"version": service.policy.version, **service.policy.to_dict()})
    elif args.command == "replicate":
        summary, acks = replicate(args.url, service.checkpoints(), service.store.acks(), args.quorum, args.timeout)
        for ack in acks:
            service.store.append_ack(ack)
        _print({**summary, "new_acks": len(acks)})
        sys.exit(0 if summary["quorum_met"] else 2)
    elif args.command == "witness-init":
        store = WitnessStore(Path(args.witness_dir), witness_id=args.witness_id)
        store.initialize()
        print(json.dumps({"witness_id": store.witness_id, "public_key": str(store.public_key_path)}))
    elif args.command == "witness-trust":
        store = WitnessStore(Path(args.witness_dir))
        destination = store.trust_signer(args.trusted_signer_id, Path(args.public_key))
        print(json.dumps({"trusted_key": str(destination)}))
    elif args.command == "witness-serve":
        serve_witness(Path(args.witness_dir), args.host, args.port)
    elif args.command == "ui":
        serve_ui(service, args.host, args.port, open_browser=not args.no_browser)
    elif args.command == "bench":
        from .bench import results_markdown, run_cli

        print(results_markdown(run_cli(args)["results"]))
    elif args.command == "demo":
        events = [
            {"timestamp": "2026-09-11T10:00:00Z", "pid": 100, "ppid": 1, "uid": 1000, "syscall": "execve", "process": "/usr/bin/python3", "arguments": {"path": "/usr/bin/python3"}, "return_code": 0},
            {"timestamp": "2026-09-11T10:00:01Z", "pid": 100, "ppid": 1, "uid": 1000, "syscall": "openat", "process": "/usr/bin/python3", "arguments": {"path": "/etc/hosts"}, "return_code": 3},
            {"timestamp": "2026-09-11T10:00:02Z", "pid": 100, "ppid": 1, "uid": 1000, "syscall": "connect", "process": "/usr/bin/python3", "arguments": {"destination": "127.0.0.1:443"}, "return_code": 0},
        ]
        service.ingest_many(events)
        service.flush()
        _print(service.verify())


if __name__ == "__main__":
    main()

"""Command-line entry point for the B-SCAF prototype."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .auditd import parse_syscall_line
from .service import AuditService


def _service(args: argparse.Namespace) -> AuditService:
    return AuditService(Path(args.data_dir), batch_size=args.batch_size, signer_id=args.signer_id)


def main() -> None:
    parser = argparse.ArgumentParser(description="B-SCAF lightweight audit prototype")
    parser.add_argument("--data-dir", default="audit-data")
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--signer-id", default="local-witness")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    ingest = sub.add_parser("ingest")
    ingest.add_argument("--input", required=True, help="newline-delimited JSON event file")
    auditd = sub.add_parser("ingest-auditd")
    auditd.add_argument("--input", required=True, help="raw auditd log file containing SYSCALL records")
    auditd.add_argument("--host-id", default="localhost")
    sub.add_parser("flush")
    sub.add_parser("verify")
    proof = sub.add_parser("proof")
    proof.add_argument("--sequence", type=int, required=True)
    sub.add_parser("demo")
    args = parser.parse_args()
    service = _service(args)

    if args.command == "init":
        service.initialize()
        print(json.dumps({"initialized": str(Path(args.data_dir))}))
    elif args.command == "ingest":
        count = 0
        for number, line in enumerate(Path(args.input).read_text(encoding="utf-8").splitlines(), start=1):
            if line.strip():
                try:
                    if service.ingest(json.loads(line)) is not None:
                        count += 1
                except (json.JSONDecodeError, ValueError) as error:
                    parser.error(f"input line {number}: {error}")
        print(json.dumps({"ingested": count}))
    elif args.command == "ingest-auditd":
        accepted = 0
        ignored = 0
        for number, line in enumerate(Path(args.input).read_text(encoding="utf-8").splitlines(), start=1):
            try:
                event = parse_syscall_line(line, host_id=args.host_id)
                if event is None:
                    ignored += 1
                elif service.ingest(event) is None:
                    ignored += 1
                else:
                    accepted += 1
            except ValueError as error:
                parser.error(f"audit log line {number}: {error}")
        print(json.dumps({"ingested": accepted, "ignored": ignored}))
    elif args.command == "flush":
        block = service.flush()
        print(json.dumps({"checkpoint": None if block is None else block.to_dict()}, indent=2))
    elif args.command == "verify":
        print(json.dumps(service.verify(), indent=2))
    elif args.command == "proof":
        print(json.dumps(service.inclusion_proof(args.sequence), indent=2))
    elif args.command == "demo":
        events = [
            {"timestamp": "2026-09-11T10:00:00Z", "pid": 100, "ppid": 1, "uid": 1000, "syscall": "execve", "process": "/usr/bin/python3", "arguments": {"path": "/usr/bin/python3"}, "return_code": 0},
            {"timestamp": "2026-09-11T10:00:01Z", "pid": 100, "ppid": 1, "uid": 1000, "syscall": "openat", "process": "/usr/bin/python3", "arguments": {"path": "/etc/hosts"}, "return_code": 3},
            {"timestamp": "2026-09-11T10:00:02Z", "pid": 100, "ppid": 1, "uid": 1000, "syscall": "connect", "process": "/usr/bin/python3", "arguments": {"destination": "127.0.0.1:443"}, "return_code": 0},
        ]
        for event in events:
            service.ingest(event)
        service.flush()
        print(json.dumps(service.verify(), indent=2))


if __name__ == "__main__":
    main()

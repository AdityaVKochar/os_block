"""Run every tampering scenario against copies of an existing B-SCAF store.

Three local witnesses are started, the store's checkpoints are replicated to
them (quorum 2), and each scenario is verified locally and against witnesses.

Usage: python scripts/attack_matrix.py --data-dir audit-data [--signer-id local-witness] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile

from bscaf.attacks import matrix_markdown, run_matrix
from bscaf.service import AuditService
from bscaf.witness import replicate, start_local_witnesses


def attack_matrix(data_dir: Path, signer_id: str, witnesses: int = 3, quorum: int = 2) -> list[dict]:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        source = root / "source"
        shutil.copytree(data_dir, source, ignore=shutil.ignore_patterns(".lock", "witness-acks.jsonl"))
        service = AuditService(source, signer_id=signer_id)
        if len(service.checkpoints()) < 3:
            raise ValueError("the store needs at least three checkpoints")
        urls, keys, servers = start_local_witnesses(root / "witnesses", witnesses, signer_id, service.store.public_key_path)
        try:
            summary, acks = replicate(urls, service.checkpoints(), [], quorum)
            if not summary["quorum_met"]:
                raise RuntimeError(f"replication failed: {summary}")
            for ack in acks:
                service.store.append_ack(ack)
            return run_matrix(source, urls, keys, quorum, signer_id)
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--signer-id", default="local-witness")
    parser.add_argument("--json", help="also write the rows as JSON")
    args = parser.parse_args()
    rows = attack_matrix(Path(args.data_dir), args.signer_id)
    print(matrix_markdown(rows))
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2), encoding="utf-8")
    sys.exit(0 if all(row["as_expected"] for row in rows) else 1)


if __name__ == "__main__":
    main()

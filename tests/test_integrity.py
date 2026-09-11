from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from bscaf.merkle import inclusion_proof, merkle_root, verify_inclusion
from bscaf.service import AuditService


def event(index: int) -> dict:
    return {
        "timestamp": f"2026-09-11T10:00:0{index}Z",
        "pid": 100 + index,
        "ppid": 1,
        "uid": 1000,
        "syscall": "openat",
        "arguments": {"path": f"/tmp/file-{index}"},
        "return_code": 0,
    }


class IntegrityTests(unittest.TestCase):
    def test_merkle_inclusion_proof(self):
        leaves = [f"{i:064x}" for i in range(4)]
        root = merkle_root(leaves)
        self.assertTrue(verify_inclusion(leaves[2], inclusion_proof(leaves, 2), root))

    def test_clean_audit_verifies(self):
        with tempfile.TemporaryDirectory() as directory:
            service = AuditService(Path(directory), batch_size=2)
            service.ingest(event(1))
            service.ingest(event(2))
            service.ingest(event(3))
            service.flush()
            report = service.verify()
            self.assertTrue(report["valid"])
            self.assertEqual(report["events_checked"], 3)
            self.assertEqual(report["checkpoints_checked"], 2)

    def test_event_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = AuditService(root, batch_size=2)
            service.ingest(event(1))
            service.ingest(event(2))
            service.flush()
            events_path = root / "events.jsonl"
            lines = events_path.read_text(encoding="utf-8").splitlines()
            first = json.loads(lines[0])
            first["syscall"] = "unlinkat"
            lines[0] = json.dumps(first)
            events_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            report = service.verify()
            self.assertFalse(report["valid"])
            self.assertGreaterEqual({item["type"] for item in report["problems"]}, {"event-hash", "merkle-root"})


if __name__ == "__main__":
    unittest.main()

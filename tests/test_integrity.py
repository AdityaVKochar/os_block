from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from bscaf.merkle import inclusion_proof, merkle_root, verify_inclusion
from bscaf.auditd import parse_syscall_line
from bscaf.policy import AuditPolicy
from bscaf.witness import WitnessStore
from bscaf.proof import verify_exported_proof
from bscaf.ui import DASHBOARD_HTML, DashboardController


TEST_TEMP_ROOT = Path(__file__).resolve().parents[1] / ".test-temp"
TEST_TEMP_ROOT.mkdir(exist_ok=True)
tempfile.tempdir = str(TEST_TEMP_ROOT)
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

    def test_policy_redacts_and_filters_events(self):
        policy = AuditPolicy(allowed_syscalls=frozenset({"execve"}))
        accepted = policy.apply({**event(1), "syscall": "execve", "arguments": {"token": "very-secret", "path": "/usr/bin/id"}})
        self.assertEqual(accepted["arguments"]["token"], "[REDACTED]")
        self.assertIsNone(policy.apply(event(1)))

    def test_auditd_adapter_parses_syscall_record(self):
        line = 'type=SYSCALL msg=audit(1726048800.250:19): arch=c000003e syscall=59 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 pid=732 ppid=1 uid=1000 exe="/usr/bin/id"'
        parsed = parse_syscall_line(line, host_id="lab-host")
        self.assertEqual(parsed["syscall"], "execve")
        self.assertEqual(parsed["host_id"], "lab-host")
        self.assertEqual(parsed["process"], "/usr/bin/id")

    def test_inclusion_proof_is_returned_for_committed_event(self):
        with tempfile.TemporaryDirectory() as directory:
            service = AuditService(Path(directory), batch_size=2)
            service.ingest(event(1))
            service.ingest(event(2))
            proof = service.inclusion_proof(1)
            packed = [(item["side"], item["hash"]) for item in proof["proof"]]
            self.assertTrue(verify_inclusion(proof["leaf_hash"], packed, proof["checkpoint"]["merkle_root"]))

    def test_witness_accepts_only_trusted_signed_checkpoint(self):
        with tempfile.TemporaryDirectory() as source_dir, tempfile.TemporaryDirectory() as witness_dir:
            source = AuditService(Path(source_dir), batch_size=2, signer_id="source-host")
            source.ingest(event(1))
            source.ingest(event(2))
            checkpoint = source.checkpoints()[0]
            witness = WitnessStore(Path(witness_dir))
            witness.trust_signer("source-host", source.store.public_key_path)
            self.assertTrue(witness.accept(checkpoint.to_dict())["accepted"])
            altered = checkpoint.to_dict()
            altered["merkle_root"] = "f" * 64
            with self.assertRaisesRegex(ValueError, "block hash"):
                witness.accept(altered)

    def test_exported_proof_verifies_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            service = AuditService(Path(directory), batch_size=2)
            service.ingest(event(1))
            service.ingest(event(2))
            result = verify_exported_proof(service.inclusion_proof(1), service.store.public_key_path)
            self.assertTrue(result["valid"])

    def test_ui_controller_builds_valid_black_and_white_dashboard(self):
        with tempfile.TemporaryDirectory() as directory:
            controller = DashboardController(AuditService(Path(directory), batch_size=2))
            result = controller.add_demo_events()
            dashboard = controller.dashboard()
            self.assertIn("Added 3 demo events", result["message"])
            self.assertTrue(dashboard["report"]["valid"])
            self.assertEqual(len(dashboard["events"]), 3)
            self.assertEqual(len(dashboard["checkpoints"]), 2)
            self.assertIn("background:var(--paper)", DASHBOARD_HTML)
            self.assertNotIn("https://", DASHBOARD_HTML)


if __name__ == "__main__":
    unittest.main()

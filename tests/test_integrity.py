from __future__ import annotations

import json
import os
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


    def test_time_window_and_host_change_close_batches(self):
        with tempfile.TemporaryDirectory() as directory:
            service = AuditService(Path(directory), batch_size=100, batch_seconds=2)
            service.ingest_many([event(1), event(2), event(4), {**event(5), "host_id": "other"}])
            service.flush()
            blocks = service.checkpoints()
            self.assertEqual([(block.first_sequence, block.last_sequence, block.host_id) for block in blocks], [(1, 2, "localhost"), (3, 3, "localhost"), (4, 4, "other")])
            self.assertEqual((blocks[0].time_window_start, blocks[0].time_window_end), ("2026-09-11T10:00:01Z", "2026-09-11T10:00:02Z"))
            self.assertEqual(blocks[0].policy_version, service.policy.version)
            self.assertEqual(service.verify()["verdict"], "pass")

    def test_pending_events_give_partial_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            service = AuditService(Path(directory), batch_size=5)
            service.ingest(event(1))
            report = service.verify()
            self.assertTrue(report["valid"])
            self.assertEqual(report["verdict"], "partial")
            self.assertEqual(report["warnings"][0]["type"], "uncommitted-events")

    def test_new_service_instance_resumes_the_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            AuditService(Path(directory), batch_size=2).ingest(event(1))
            resumed = AuditService(Path(directory), batch_size=2)
            resumed.ingest(event(2))
            self.assertEqual([block.batch_id for block in resumed.checkpoints()], ["1-2"])
            self.assertEqual(resumed.verify()["verdict"], "pass")

    def test_policy_file_is_versioned_and_redacts_inline_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps({"allowed_syscalls": ["execve"], "max_argument_length": 25}), encoding="utf-8")
            policy = AuditPolicy.from_file(path)
            self.assertNotEqual(policy.version, AuditPolicy().version)
            result = policy.apply({**event(1), "syscall": "execve", "arguments": {"argv": ["mysql", "--password=hunter2"], "paths": [{"name": "x" * 40}]}})
            self.assertEqual(result["arguments"]["argv"][1], "--password=[REDACTED]")
            self.assertTrue(result["arguments"]["paths"][0]["name"].endswith("[TRUNCATED]"))
            self.assertIsNotNone(AuditPolicy(allowed_syscalls=None).apply({**event(1), "syscall": "splice"}))

    def test_private_key_is_owner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            service = AuditService(Path(directory))
            service.initialize()
            if os.name == "posix":
                self.assertEqual(service.store.private_key_path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()

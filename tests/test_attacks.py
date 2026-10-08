from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from bscaf.attacks import SCENARIOS, rewrite_and_resign, run_scenario
from bscaf.service import AuditService
from bscaf.witness import WitnessConflict, WitnessStore, replicate, start_local_witnesses, verify_ack

SIGNER = "source-host"


def event(index: int) -> dict:
    return {
        "timestamp": f"2026-09-11T10:{index // 60:02d}:{index % 60:02d}Z",
        "pid": 100 + index, "ppid": 1, "uid": 1000, "syscall": "openat",
        "arguments": {"path": f"/tmp/file-{index}"}, "return_code": 0,
    }


class AttackMatrixTests(unittest.TestCase):
    """Every tampering case from the brief, against a store replicated to three witnesses."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        cls.source = root / "source"
        service = AuditService(cls.source, batch_size=4, signer_id=SIGNER)
        service.ingest_many(event(index) for index in range(1, 15))
        service.flush()
        cls.urls, cls.keys, cls.servers = start_local_witnesses(root, 3, SIGNER, service.store.public_key_path)
        summary, acks = replicate(cls.urls, service.checkpoints(), [], quorum=2)
        assert summary["quorum_met"], summary
        for ack in acks:
            service.store.append_ack(ack)

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        cls.temp.cleanup()

    def test_every_scenario_is_detected_as_expected(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario.name):
                result = run_scenario(scenario, self.source, self.urls, self.keys, quorum=2, signer_id=SIGNER)
                self.assertTrue(result["as_expected"], result)

    def test_truncation_and_resigning_pass_locally_but_fail_with_witnesses(self):
        for name, evidence in (("truncate-tail", "truncation"), ("rewrite-and-resign", "witness-mismatch")):
            scenario = next(item for item in SCENARIOS if item.name == name)
            result = run_scenario(scenario, self.source, self.urls, self.keys, quorum=2, signer_id=SIGNER)
            self.assertEqual(result["local_verdict"], "pass")
            self.assertEqual(result["witness_verdict"], "fail")
            self.assertIn(evidence, result["witness_problems"])

    def test_witnesses_refuse_a_rewritten_chain(self):
        scenario = next(item for item in SCENARIOS if item.name == "rewrite-and-resign")
        result = run_scenario(scenario, self.source, self.urls, self.keys, quorum=2, signer_id=SIGNER)
        self.assertTrue(result["witnesses_rejected_rewritten_blocks"])

    def test_local_attacks_name_the_first_invalid_item(self):
        scenario = next(item for item in SCENARIOS if item.name == "modify-event")
        result = run_scenario(scenario, self.source, self.urls, self.keys, quorum=2, signer_id=SIGNER)
        self.assertIn("event-hash", result["local_problems"])
        self.assertIn("merkle-root", result["local_problems"])


class WitnessStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.source = AuditService(root / "source", batch_size=2, signer_id=SIGNER)
        self.source.ingest_many(event(index) for index in range(1, 7))
        self.witness = WitnessStore(root / "witness", witness_id="w1")
        self.witness.trust_signer(SIGNER, self.source.store.public_key_path)

    def tearDown(self):
        self.temp.cleanup()

    def test_acks_are_signed_and_duplicates_are_idempotent(self):
        first = self.source.checkpoints()[0]
        ack = self.witness.accept(first.to_dict())
        self.assertTrue(verify_ack(ack, self.witness.public_key_path))
        self.assertTrue(self.witness.accept(first.to_dict())["duplicate"])
        self.assertFalse(verify_ack({**ack, "block_number": 9}, self.witness.public_key_path))

    def test_blocks_must_arrive_in_chain_order(self):
        with self.assertRaisesRegex(ValueError, "does not follow"):
            self.witness.accept(self.source.checkpoints()[1].to_dict())

    def test_conflicting_block_is_refused_and_recorded(self):
        for checkpoint in self.source.checkpoints():
            self.witness.accept(checkpoint.to_dict())
        rewrite_and_resign(self.source.store)  # edits the middle block (block 2)
        rewritten = self.source.checkpoints()
        self.assertTrue(self.witness.accept(rewritten[0].to_dict())["duplicate"])
        with self.assertRaises(WitnessConflict):
            self.witness.accept(rewritten[1].to_dict())
        evidence = [json.loads(line) for line in self.witness.equivocations_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(evidence[0]["block_number"], 2)

    def test_witness_restarts_with_its_chain(self):
        for checkpoint in self.source.checkpoints():
            self.witness.accept(checkpoint.to_dict())
        restarted = WitnessStore(self.witness.root)
        self.assertEqual(len(restarted.ledger(SIGNER)), 3)
        self.assertEqual(restarted.witness_id, "w1")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from pathlib import Path
import unittest

from bscaf.bench import results_markdown, run_config, workload

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "auditd"


class BenchHarnessTests(unittest.TestCase):
    def test_every_mode_reports_metrics(self):
        configs = [
            {"label": "plain", "mode": "plain", "batch_size": 50, "fsync": False},
            {"label": "chain", "mode": "hash-chain", "batch_size": 50, "fsync": False},
            {"label": "bscaf", "mode": "bscaf", "batch_size": 50, "fsync": False, "witnesses": 2},
        ]
        results = [run_config({**config, "source": "synthetic", "events": 200}) for config in configs]
        self.assertEqual([row["events"] for row in results], [200, 200, 200])
        bscaf = results[2]
        self.assertEqual((bscaf["blocks"], bscaf["verify_verdict"], bscaf["proof_valid"], bscaf["replicate_quorum_met"]), (4, "pass", True, True))
        self.assertGreater(bscaf["bytes_per_event"], results[0]["bytes_per_event"])
        self.assertIn("| bscaf |", results_markdown(results))

    def test_real_workload_is_replayed_and_retimed(self):
        events = workload("real", 10, FIXTURES)
        self.assertEqual(len(events), 10)
        self.assertEqual(events[1]["timestamp"], "2026-01-01T00:00:00.001000Z")


if __name__ == "__main__":
    unittest.main()

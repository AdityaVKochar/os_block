from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "auditd" / "splunk_excerpts.log"
SRC = Path(__file__).resolve().parents[1] / "src"


def bscaf(data_dir: Path, *args: str) -> dict:
    result = subprocess.run(
        [sys.executable, "-m", "bscaf", "--data-dir", str(data_dir), *args],
        capture_output=True, text=True, env={"PYTHONPATH": str(SRC)}, check=False,
    )
    if result.returncode not in (0, 1):
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


class CliTests(unittest.TestCase):
    def test_reingesting_an_audit_log_skips_already_committed_records(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            first = bscaf(data, "--all-syscalls", "ingest-auditd", "--input", str(FIXTURE), "--host-id", "lab")
            second = bscaf(data, "--all-syscalls", "ingest-auditd", "--input", str(FIXTURE), "--host-id", "lab")
            self.assertEqual((first["accepted"], first["duplicates_skipped"]), (4, 0))
            self.assertEqual((second["accepted"], second["duplicates_skipped"]), (0, 4))
            bscaf(data, "flush")
            report = bscaf(data, "verify")
            self.assertEqual((report["verdict"], report["events_checked"]), ("pass", 4))

    def test_events_from_a_file_are_committed_in_audit_order(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            bscaf(data, "--all-syscalls", "ingest-auditd", "--input", str(FIXTURE), "--host-id", "lab")
            lines = (data / "events.jsonl").read_text(encoding="utf-8").splitlines()
            stamps = [json.loads(line)["timestamp"] for line in lines]
            self.assertEqual(stamps, sorted(stamps))


if __name__ == "__main__":
    unittest.main()

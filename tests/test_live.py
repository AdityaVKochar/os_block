from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from bscaf.crypto import PASSPHRASE_ENV
from bscaf.ebpf import EbpfParser, bpftrace_program, capture
from bscaf.policy import AuditPolicy
from bscaf.service import AuditService
from bscaf.tlsutil import client_context, create_dev_pki, server_context
from bscaf.witness import WitnessStore, make_witness_server, replicate, start_local_witnesses

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SRC = Path(__file__).resolve().parents[1] / "src"


class EbpfCollectorTests(unittest.TestCase):
    def parse_fixture(self):
        parser = EbpfParser(host_id="wsl", clock=lambda: 1_790_000_000.0)
        events = [event for line in (FIXTURES / "ebpf" / "capture.tsv").read_text(encoding="utf-8").splitlines() if (event := parser.feed(line))]
        return events, parser

    def test_capture_lines_become_events(self):
        events, parser = self.parse_fixture()
        self.assertEqual([event["syscall"] for event in events], ["execve", "connect", "execve", "openat", "rename", "chmod", "unlinkat", "connect"])
        ls = events[0]
        self.assertEqual((ls["process"], ls["arguments"]["argv"], ls["pid"], ls["ppid"]), ("/usr/bin/ls", ["ls", "-la", "/etc"], 14565, 14550))
        self.assertEqual(events[1]["arguments"]["destination"], "unix:/var/run/nscd/socket")
        self.assertEqual(events[1]["return_code"], -2)
        self.assertEqual(events[3]["arguments"]["access"], "write")
        self.assertTrue(events[3]["arguments"]["create"])
        self.assertEqual([path["name"] for path in events[4]["arguments"]["paths"]], ["/tmp/x", "/tmp/y"])
        self.assertEqual(events[5]["arguments"]["mode"], "0o600")
        self.assertEqual((events[7]["arguments"]["destination"], events[7]["uid"]), ("127.0.0.1:443", 1000))
        self.assertEqual(events[0]["timestamp"], "2026-09-21T14:13:20Z")
        self.assertEqual(parser.lost_events, 3)

    def test_program_covers_the_default_policy(self):
        program = bpftrace_program()
        for syscall in ("execve", "openat", "connect", "setuid", "ptrace", "finit_module"):
            self.assertIn(f"sys_exit_{syscall}", program)
            self.assertIn(syscall, AuditPolicy().allowed_syscalls)
        self.assertNotIn("[tid]", program)
        with self.assertRaises(ValueError):
            bpftrace_program(["read"])

    def test_capture_commits_blocks_from_a_tracer_stream(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "fake-bpftrace"
            fake.write_text(f"#!{sys.executable}\nimport sys\nsys.stdout.write(open({str(FIXTURES / 'ebpf' / 'capture.tsv')!r}).read())\n", encoding="utf-8")
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            service = AuditService(Path(directory) / "store", batch_size=3)
            result = capture(service, duration=10, host_id="wsl", bpftrace=str(fake))
            self.assertEqual((result["accepted"], result["lost_events"]), (8, 3))
            self.assertEqual(service.verify()["verdict"], "pass")
            self.assertEqual(len(service.checkpoints()), 3)


class SearchTests(unittest.TestCase):
    def test_filters_combine(self):
        with tempfile.TemporaryDirectory() as directory:
            service = AuditService(Path(directory), batch_size=100)
            parser = EbpfParser(host_id="wsl", clock=lambda: 1_790_000_000.0)
            for line in (FIXTURES / "ebpf" / "capture.tsv").read_text(encoding="utf-8").splitlines():
                event = parser.feed(line)
                if event:
                    service.ingest(event)
            self.assertEqual([event.syscall for event in service.search(text="/tmp/y")], ["execve", "rename", "chmod", "unlinkat"])  # argv of the python -c script names /tmp/y too
            self.assertEqual(len(service.search(syscall="connect", uid=1000)), 1)
            self.assertEqual([event.sequence for event in service.search(pid=14550, limit=2, newest=True)], [6, 7])
            self.assertEqual(service.search(since="2030-01-01T00:00:00Z"), [])


class KeyProtectionTests(unittest.TestCase):
    def test_passphrase_encrypts_the_signing_key(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {PASSPHRASE_ENV: "correct horse"}):
                service = AuditService(Path(directory), batch_size=1)
                service.ingest({"timestamp": "2026-10-16T10:00:00Z", "pid": 1, "ppid": 0, "uid": 0, "syscall": "execve"})
                self.assertIn(b"ENCRYPTED", service.store.private_key_path.read_bytes())
                self.assertEqual(service.verify()["verdict"], "pass")
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ValueError, PASSPHRASE_ENV):
                    AuditService(Path(directory), batch_size=1).ingest({"timestamp": "2026-10-16T10:00:01Z", "pid": 1, "ppid": 0, "uid": 0, "syscall": "execve"})


class MutualTlsTests(unittest.TestCase):
    def test_witnesses_over_mutual_tls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pki = create_dev_pki(root / "pki", ["127.0.0.1"])
            source = AuditService(root / "source", batch_size=2, signer_id="src")
            source.ingest_many({"timestamp": f"2026-10-16T10:00:0{i}Z", "pid": i, "ppid": 1, "uid": 0, "syscall": "execve"} for i in range(4))
            tls = server_context(pki["server"], pki["server_key"], client_ca=pki["ca"])
            urls, _, servers = start_local_witnesses(root / "w", 2, "src", source.store.public_key_path, tls)
            try:
                self.assertTrue(urls[0].startswith("https://"))
                good = client_context(pki["ca"], pki["client"], pki["client_key"])
                summary, acks = replicate(urls, source.checkpoints(), [], quorum=2, context=good)
                self.assertTrue(summary["quorum_met"], summary)
                self.assertEqual(len(acks), 4)
                anonymous = client_context(pki["ca"])
                refused, _ = replicate(urls, source.checkpoints(), [], quorum=1, context=anonymous)
                self.assertFalse(refused["quorum_met"])
            finally:
                for server in servers:
                    server.shutdown()
                    server.server_close()


class ReplicateOnCommitTests(unittest.TestCase):
    def test_ingest_auditd_pushes_new_blocks_to_witnesses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = AuditService(root / "data", signer_id="local-witness")
            source.initialize()
            store = WitnessStore(root / "w", witness_id="w1")
            store.trust_signer("local-witness", source.store.public_key_path)
            server = make_witness_server(store.root, "127.0.0.1", 0)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "bscaf", "--data-dir", str(root / "data"), "--batch-size", "2", "--all-syscalls",
                     "ingest-auditd", "--input", str(FIXTURES / "auditd" / "splunk_excerpts.log"), "--host-id", "lab",
                     "--replicate-url", f"http://127.0.0.1:{server.server_address[1]}"],
                    capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(SRC)}, check=True,
                )
                report = json.loads(result.stdout)
                self.assertEqual(report["replication"], {"blocks": 2, "witnesses_complete": 1, "quorum_met": True})
                self.assertEqual(len(store.ledger("local-witness")), 2)
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()

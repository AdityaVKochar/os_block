from __future__ import annotations

from datetime import timedelta, timezone
from pathlib import Path
import unittest

from bscaf.auditd import AuditdParser, AuditRecordError, parse_syscall_line, parse_timezone, tokenize


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "auditd" / "splunk_excerpts.log"


def parse(lines, **options):
    parser = AuditdParser(**options)
    return list(parser.parse_lines(lines)), parser


class RealAuditdFixtureTests(unittest.TestCase):
    def setUp(self):
        self.events, self.parser = parse(FIXTURE.read_text(encoding="utf-8").splitlines(), host_id="splunk")
        self.by_id = {event["arguments"]["audit_id"]: event for event in self.events}

    def test_every_syscall_group_becomes_one_event(self):
        self.assertEqual(len(self.events), 4)
        self.assertEqual(self.parser.records["SYSCALL"], 4)
        self.assertEqual(self.parser.rejected, {})

    def test_enriched_syscall_is_correlated_with_its_path_records(self):
        event = self.by_id["1722942252.642:3108"]
        self.assertEqual(event["syscall"], "rename")
        self.assertEqual(event["process"], "/usr/bin/crontab")
        self.assertEqual([path["name"] for path in event["arguments"]["paths"]], ["crontabs/", "crontabs/"])
        self.assertEqual(event["arguments"]["audit_key"], "cron")
        self.assertNotIn("a0", event["arguments"])

    def test_raw_record_keeps_numeric_identity(self):
        event = self.by_id["1777901306.991:7243"]
        self.assertEqual((event["syscall"], event["uid"], event["pid"], event["ppid"]), ("execve", 1000, 2675, 2674))
        self.assertEqual(event["timestamp"], "2026-05-04T13:28:26.991000Z")
        self.assertEqual(event["arguments"]["euid"], "0")

    def test_interpreted_record_uses_names_and_local_time(self):
        event = self.by_id["1744801102.147:103691"]
        self.assertEqual(event["syscall"], "execve")
        self.assertEqual(event["uid"], -1)
        self.assertEqual(event["arguments"]["uid_name"], "ubuntu")
        self.assertEqual(event["timestamp"], "2025-04-16T10:58:22.147000Z")
        shifted, _ = parse(FIXTURE.read_text(encoding="utf-8").splitlines()[4:5], assume_tz=parse_timezone("+05:30"))
        self.assertEqual(shifted[0]["timestamp"], "2025-04-16T05:28:22.147000Z")

    def test_records_without_syscall_are_counted_not_emitted(self):
        self.assertEqual(self.parser.orphan_records, 2)
        self.assertEqual(self.parser.records["SERVICE_STOP"], 1)


class SyntheticAuditdFormatTests(unittest.TestCase):
    """Formats absent from the public sample, written to match auditd's documented output."""

    BASE = "msg=audit(1726048800.250:{serial}): arch={arch} syscall={number} success=yes exit={exit} a0=3 a1=0 a2=0 a3=0 items=1 ppid=1 pid=732 auid=1000 uid=1000 comm={comm} exe={exe} key=(null)"

    def syscall(self, serial=19, arch="c000003e", number=59, exit="0", comm='"id"', exe='"/usr/bin/id"', node=""):
        prefix = f"node={node} " if node else ""
        return prefix + "type=SYSCALL " + self.BASE.format(serial=serial, arch=arch, number=number, exit=exit, comm=comm, exe=exe)

    def test_node_prefix_becomes_host_id(self):
        events, _ = parse([self.syscall(node="web-01")])
        self.assertEqual(events[0]["host_id"], "web-01")

    def test_hex_encoded_values_are_decoded(self):
        hex_exe = "/tmp/my tool".encode().hex().upper()
        events, _ = parse([
            self.syscall(exe=hex_exe),
            'type=EXECVE msg=audit(1726048800.250:19): argc=2 a0="cat" a1=2F746D702F612062',
            "type=PROCTITLE msg=audit(1726048800.250:19): proctitle=636174002F746D702F612062",
        ])
        self.assertEqual(events[0]["process"], "/tmp/my tool")
        self.assertEqual(events[0]["arguments"]["argv"], ["cat", "/tmp/a b"])
        self.assertEqual(events[0]["arguments"]["proctitle"], "cat /tmp/a b")

    def test_long_execve_arguments_are_reassembled(self):
        events, _ = parse([
            self.syscall(),
            'type=EXECVE msg=audit(1726048800.250:19): argc=2 a0="echo" a1_len=6 a1[0]="abc" a1[1]="def"',
        ])
        self.assertEqual(events[0]["arguments"]["argv"], ["echo", "abcdef"])

    def test_sockaddr_destination_is_decoded(self):
        events, _ = parse([
            self.syscall(number=42, exit="-115"),
            "type=SOCKADDR msg=audit(1726048800.250:19): saddr=020001BB7F0000010000000000000000",
            "type=EOE msg=audit(1726048800.250:19): ",
        ])
        self.assertEqual(events[0]["syscall"], "connect")
        self.assertEqual(events[0]["return_code"], -115)
        self.assertEqual(events[0]["arguments"]["destination"], "127.0.0.1:443")

    def test_architecture_selects_the_syscall_table(self):
        events, parser = parse([self.syscall(serial=1, arch="c00000b7", number=221), self.syscall(serial=2, arch="c00000b7", number=999)])
        self.assertEqual(events[0]["syscall"], "execve")
        self.assertEqual(events[1]["syscall"], "syscall_999@aarch64")
        self.assertEqual(parser.unmapped_syscalls, {"syscall_999@aarch64": 1})

    def test_interpreted_errno_exit_is_numeric(self):
        line = "type=SYSCALL msg=audit(04/16/2025 09:14:42.784:96444) : arch=x86_64 syscall=openat success=no exit=ENOENT(No such file or directory) items=1 ppid=1 pid=2 auid=ubuntu uid=root comm=cat exe=/usr/bin/cat key=(null)"
        events, _ = parse([line])
        self.assertEqual((events[0]["syscall"], events[0]["uid"], events[0]["return_code"]), ("openat", 0, -2))

    def test_malformed_lines_are_counted_unless_strict(self):
        lines = [self.syscall(serial=1), 'type=SYSCALL msg=audit(1726048800.250:2): syscall=59 comm="broken', "garbage line"]
        events, parser = parse(lines)
        self.assertEqual(len(events), 1)
        self.assertEqual(parser.rejected, {"unbalanced quote": 1, "not an audit record": 1})
        with self.assertRaises(AuditRecordError):
            parse(lines, strict=True)

    def test_interpreted_arguments_may_contain_a_lone_quote(self):
        lines = [
            "type=SYSCALL msg=audit(02/20/2025 13:07:05.666:110401) : arch=x86_64 syscall=execve success=yes exit=0 items=2 ppid=1 pid=2 auid=ubuntu uid=root comm=grep exe=/usr/bin/grep key=(null)",
            "type=EXECVE msg=audit(02/20/2025 13:07:05.666:110401) : argc=3 a0=grep a1=-L a2=\"\\|'\\|(",
        ]
        events, parser = parse(lines)
        self.assertEqual(parser.rejected, {})
        self.assertEqual(events[0]["arguments"]["argv"], ["grep", "-L", "\"\\|'\\|("])

    def test_missing_identity_rejects_the_event(self):
        events, parser = parse(["type=SYSCALL msg=audit(1726048800.250:7): arch=c000003e syscall=59 uid=0 pid=3"])
        self.assertEqual(events, [])
        self.assertEqual(parser.rejected, {"SYSCALL record lacks ppid": 1})

    def test_tokenizer_and_helpers(self):
        self.assertEqual(tokenize("a=1 b=\"x y\" c='m=n'"), {"a": ("1", False), "b": ("x y", True), "c": ("m=n", True)})
        self.assertEqual(parse_timezone("-07:00"), timezone(-timedelta(hours=7)))
        self.assertIsNone(parse_syscall_line("type=PATH msg=audit(1.0:1): name=x"))


if __name__ == "__main__":
    unittest.main()

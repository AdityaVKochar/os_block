"""Adapter from Linux auditd logs to B-SCAF events.

Handles the formats seen in real exported audit trails:

* raw `/var/log/audit/audit.log` records, optionally with a `node=` prefix;
* ENRICHED records (`log_format = ENRICHED`), whose interpreted fields follow
  a 0x1d separator;
* `ausearch -i` interpreted output (local date/time, syscall names, user names).

One kernel event is written as several records sharing `audit(<time>:<serial>)`
(SYSCALL, EXECVE, PATH, CWD, SOCKADDR, PROCTITLE, EOE). `AuditdParser` groups
them so a B-SCAF event carries file paths, argv and socket destinations rather
than raw register values.
"""

from __future__ import annotations

from collections import Counter, OrderedDict
from datetime import datetime, timedelta, timezone, tzinfo
import errno
import gzip
import ipaddress
import os
import re
import sys
import time
from typing import Any, Iterable, Iterator, TextIO


# Curated per-architecture tables covering the security-relevant calls the
# brief names plus common persistence, privilege and module operations.
X86_64_SYSCALLS = {
    2: "open", 41: "socket", 42: "connect", 43: "accept", 44: "sendto", 49: "bind", 50: "listen",
    54: "setsockopt", 55: "getsockopt", 56: "clone", 57: "fork", 58: "vfork", 59: "execve", 62: "kill",
    76: "truncate", 77: "ftruncate", 82: "rename", 83: "mkdir", 84: "rmdir", 85: "creat", 86: "link",
    87: "unlink", 88: "symlink", 90: "chmod", 91: "fchmod", 92: "chown", 93: "fchown", 94: "lchown",
    101: "ptrace", 105: "setuid", 106: "setgid", 113: "setreuid", 114: "setregid", 117: "setresuid",
    119: "setresgid", 122: "setfsuid", 123: "setfsgid", 157: "prctl", 161: "chroot", 165: "mount",
    166: "umount2", 169: "reboot", 175: "init_module", 176: "delete_module", 188: "setxattr",
    189: "lsetxattr", 190: "fsetxattr", 197: "removexattr", 198: "lremovexattr", 199: "fremovexattr",
    200: "tkill", 234: "tgkill", 257: "openat", 258: "mkdirat", 260: "fchownat", 263: "unlinkat",
    264: "renameat", 265: "linkat", 266: "symlinkat", 268: "fchmodat", 272: "unshare", 275: "splice",
    288: "accept4", 302: "prlimit64", 304: "open_by_handle_at", 308: "setns", 310: "process_vm_readv",
    311: "process_vm_writev", 313: "finit_module", 316: "renameat2", 319: "memfd_create", 321: "bpf",
    322: "execveat", 425: "io_uring_setup", 434: "pidfd_open", 437: "openat2", 452: "fchmodat2",
}
AARCH64_SYSCALLS = {
    5: "setxattr", 6: "lsetxattr", 7: "fsetxattr", 14: "removexattr", 15: "lremovexattr",
    16: "fremovexattr", 34: "mkdirat", 35: "unlinkat", 36: "symlinkat", 37: "linkat", 38: "renameat",
    39: "umount2", 40: "mount", 45: "truncate", 46: "ftruncate", 51: "chroot", 52: "fchmod",
    53: "fchmodat", 54: "fchownat", 55: "fchown", 56: "openat", 76: "splice", 97: "unshare",
    105: "init_module", 106: "delete_module", 117: "ptrace", 129: "kill", 130: "tkill", 131: "tgkill",
    142: "reboot", 143: "setregid", 144: "setgid", 145: "setreuid", 146: "setuid", 147: "setresuid",
    149: "setresgid", 167: "prctl", 198: "socket", 200: "bind", 201: "listen", 202: "accept",
    203: "connect", 206: "sendto", 208: "setsockopt", 209: "getsockopt", 220: "clone", 221: "execve",
    242: "accept4", 261: "prlimit64", 265: "open_by_handle_at", 268: "setns", 270: "process_vm_readv",
    271: "process_vm_writev", 273: "finit_module", 276: "renameat2", 279: "memfd_create", 280: "bpf",
    281: "execveat", 425: "io_uring_setup", 434: "pidfd_open", 437: "openat2", 452: "fchmodat2",
}
I386_SYSCALLS = {
    2: "fork", 5: "open", 8: "creat", 9: "link", 10: "unlink", 11: "execve", 15: "chmod", 21: "mount",
    26: "ptrace", 37: "kill", 38: "rename", 39: "mkdir", 40: "rmdir", 52: "umount2", 61: "chroot",
    83: "symlink", 102: "socketcall", 120: "clone", 128: "init_module", 129: "delete_module",
    190: "vfork", 198: "lchown", 203: "setreuid", 207: "fchown", 208: "setresuid", 210: "setresgid",
    212: "chown", 213: "setuid", 214: "setgid", 295: "openat", 298: "fchownat", 301: "unlinkat",
    302: "renameat", 306: "fchmodat", 350: "finit_module", 353: "renameat2", 356: "memfd_create",
    358: "execveat", 359: "socket", 361: "bind", 362: "connect", 364: "accept4",
}
SYSCALL_TABLES = {
    "c000003e": ("x86_64", X86_64_SYSCALLS),
    "c00000b7": ("aarch64", AARCH64_SYSCALLS),
    "40000003": ("i386", I386_SYSCALLS),
}
ARCH_NAMES = {name: table for name, table in SYSCALL_TABLES.values()}

HEADER = re.compile(r"^(?:node=(?P<node>\S+)\s+)?type=(?P<type>\S+)\s+msg=audit\((?P<stamp>[^)]*)\)\s*:\s?(?P<body>.*)$")
RAW_STAMP = re.compile(r"^(?P<seconds>\d+(?:\.\d+)?):(?P<serial>\d+)$")
KEY = re.compile(r"[A-Za-z0-9_\-\[\]]+")
HEX = re.compile(r"^(?:[0-9A-F]{2})+$")
ERRNO_NAME = re.compile(r"^-?(?P<name>[A-Z][A-Z0-9]*)")
# Fields the kernel hex-encodes when the value contains spaces, quotes or control characters.
HEX_ENCODED_FIELDS = frozenset({"exe", "comm", "name", "cwd", "proctitle", "key", "path"})
KNOWN_USERS = {"root": 0, "unset": -1, "nobody": 65534}
GROUPING_WINDOW = 256  # records of interleaved events kept open before the oldest is emitted


class AuditRecordError(ValueError):
    """A single malformed audit record; the reason is used as a statistics key."""


def tokenize(body: str, literal_quotes: bool = False) -> dict[str, tuple[str, bool]]:
    """Split `k=v k="quoted v" k='v'` into {key: (value, was_quoted)}; first occurrence wins.

    `ausearch -i` prints decoded arguments verbatim, so an argument such as
    `"\\|'` can open a quote it never closes; with literal_quotes that quote is
    read as part of an unquoted value instead of rejecting the record.
    """
    fields: dict[str, tuple[str, bool]] = {}
    index, length = 0, len(body)
    while index < length:
        while index < length and body[index].isspace():
            index += 1
        match = KEY.match(body, index)
        if not match or match.end() >= length or body[match.end()] != "=":
            # Not a key=value token (e.g. the tail of an interpreted value); skip one word.
            while index < length and not body[index].isspace():
                index += 1
            continue
        key, index = match.group(), match.end() + 1
        opens_quote = index < length and body[index] in "\"'"
        end = body.find(body[index], index + 1) if opens_quote else -1
        if opens_quote and end < 0 and not literal_quotes:
            raise AuditRecordError("unbalanced quote")
        if end >= 0:
            value, quoted, index = body[index + 1:end], True, end + 1
        else:
            end = index
            while end < length and not body[end].isspace():
                end += 1
            value, quoted, index = body[index:end], False, end
        fields.setdefault(key, (value, quoted))
    return fields


def _decode(key: str, value: str, quoted: bool, interpreted: bool) -> str:
    """Decode the kernel's hex encoding of unsafe strings (raw format only)."""
    if quoted or interpreted or value in ("(null)", "?"):
        return value
    base_key = key.split("[", 1)[0]
    if (base_key in HEX_ENCODED_FIELDS or re.fullmatch(r"a\d+", base_key)) and HEX.match(value):
        return bytes.fromhex(value).decode("utf-8", errors="replace")
    return value


def _int(value: str | None, field: str) -> int:
    if value is None:
        raise AuditRecordError(f"SYSCALL record lacks {field}")
    try:
        return int(value, 0)
    except ValueError as error:
        raise AuditRecordError(f"non-numeric {field}") from error


def _user(value: str | None, field: str) -> tuple[int, str | None]:
    """Numeric uid, or (-1, name) for interpreted user names that cannot be resolved offline."""
    if value is None:
        raise AuditRecordError(f"SYSCALL record lacks {field}")
    try:
        number = int(value, 0)
        return (-1 if number == 4294967295 else number), None
    except ValueError:
        return KNOWN_USERS.get(value, -1), value


def _return_code(value: str | None) -> int | None:
    """`exit=3`, `exit=-2` or interpreted `exit=ENOENT(No such file or directory)`."""
    if value is None:
        return None
    try:
        return int(value, 0)
    except ValueError:
        match = ERRNO_NAME.match(value)
        if match and hasattr(errno, match.group("name")):
            return -getattr(errno, match.group("name"))
        return None


def _sockaddr(fields: dict[str, tuple[str, bool]], body: str, interpreted: bool) -> str | None:
    if interpreted:
        address = re.search(r"\b(?:laddr|addr)=(\S+)", body)
        port = re.search(r"\blport=(\d+)", body)
        path = re.search(r"\bpath=(\S+)", body)
        if address:
            return f"{address.group(1)}:{port.group(1)}" if port else address.group(1)
        return f"unix:{path.group(1)}" if path else None
    raw = fields.get("saddr", ("", False))[0]
    if not HEX.match(raw) or len(raw) < 4:
        return None
    data = bytes.fromhex(raw)
    family = int.from_bytes(data[0:2], "little")
    if family == 2 and len(data) >= 8:
        return f"{ipaddress.IPv4Address(data[4:8])}:{int.from_bytes(data[2:4], 'big')}"
    if family == 10 and len(data) >= 24:
        return f"[{ipaddress.IPv6Address(data[8:24])}]:{int.from_bytes(data[2:4], 'big')}"
    if family == 1:
        path = data[2:].split(b"\x00", 1)[0] if data[2:3] != b"\x00" else b"@" + data[3:].split(b"\x00", 1)[0]
        return "unix:" + path.decode("utf-8", errors="replace")
    return f"family-{family}"


class AuditdParser:
    """Stream auditd lines into B-SCAF event dictionaries, keeping per-reason statistics."""

    def __init__(self, host_id: str | None = None, assume_tz: tzinfo = timezone.utc, strict: bool = False):
        self.host_id = host_id
        self.assume_tz = assume_tz
        self.strict = strict
        self.records = Counter()
        self.rejected = Counter()
        self.unmapped_syscalls = Counter()
        self.orphan_records = 0
        self.unresolved_users = 0
        self.duplicate_records = 0
        self.conflicting_duplicates = 0
        self._open: OrderedDict[tuple[str, str], dict[str, Any]] = OrderedDict()

    # -------------------------------------------------------------- records

    def _header(self, line: str) -> tuple[str, str, float, str, str | None, bool]:
        line = line.rstrip("\r\n")
        main, _, _enriched = line.partition("\x1d")
        match = HEADER.match(main)
        if not match:
            raise AuditRecordError("not an audit record")
        stamp = match.group("stamp")
        raw = RAW_STAMP.match(stamp)
        if raw:
            seconds, serial, interpreted = float(raw.group("seconds")), raw.group("serial"), False
        else:
            moment, _, serial = stamp.rpartition(":")
            try:
                parsed = datetime.strptime(moment.strip(), "%m/%d/%Y %H:%M:%S.%f")
            except ValueError as error:
                raise AuditRecordError("unrecognized audit timestamp") from error
            if not serial.isdigit():
                raise AuditRecordError("unrecognized audit timestamp")
            seconds, interpreted = parsed.replace(tzinfo=self.assume_tz).timestamp(), True
        return match.group("type"), serial, seconds, match.group("body"), match.group("node"), interpreted

    def feed(self, line: str) -> list[dict[str, Any]]:
        """Consume one log line; return any events completed by it."""
        if not line.strip():
            return []
        try:
            record_type, serial, seconds, body, node, interpreted = self._header(line)
            self.records[record_type] += 1
            key = (f"{seconds:.3f}", serial)
            if record_type == "EOE":
                group = self._open.pop(key, None)
                return [event for event in [self._finish(group)] if event]
            fields = tokenize(body, literal_quotes=interpreted)
        except AuditRecordError as error:
            if self.strict:
                raise
            self.rejected[str(error)] += 1
            return []
        group = self._open.get(key)
        if group is None:
            group = self._open[key] = {"serial": serial, "seconds": seconds, "node": node, "interpreted": interpreted, "records": []}
        group["records"].append((record_type, fields, body))
        completed: list[dict[str, Any]] = []
        while len(self._open) > GROUPING_WINDOW:
            _, oldest = self._open.popitem(last=False)
            completed.extend(event for event in [self._finish(oldest)] if event)
        return completed

    def finish(self) -> list[dict[str, Any]]:
        """Emit every still-open event (end of input or idle tail)."""
        groups, self._open = list(self._open.values()), OrderedDict()
        return [event for event in (self._finish(group) for group in groups) if event]

    def parse_lines(self, lines: Iterable[str]) -> Iterator[dict[str, Any]]:
        for line in lines:
            yield from self.feed(line)
        yield from self.finish()

    # --------------------------------------------------------------- events

    def _finish(self, group: dict[str, Any] | None) -> dict[str, Any] | None:
        if group is None:
            return None
        records = group["records"]
        syscall_records = [fields for record_type, fields, _ in records if record_type == "SYSCALL"]
        if not syscall_records:
            if any(record_type in {"EXECVE", "PATH", "CWD", "SOCKADDR", "PROCTITLE"} for record_type, _, _ in records):
                self.orphan_records += 1
            return None
        if len(syscall_records) > 1:
            # Exports sometimes repeat a record; differing copies of one audit ID are suspicious.
            self.duplicate_records += len(syscall_records) - 1
            self.conflicting_duplicates += sum(record != syscall_records[0] for record in syscall_records[1:])
        try:
            return self._build(group, syscall_records[0])
        except AuditRecordError as error:
            if self.strict:
                raise
            self.rejected[str(error)] += 1
            return None

    def _build(self, group: dict[str, Any], fields: dict[str, tuple[str, bool]]) -> dict[str, Any]:
        interpreted = group["interpreted"]

        def value(key: str) -> str | None:
            item = fields.get(key)
            return None if item is None else _decode(key, item[0], item[1], interpreted)

        syscall = self._syscall_name(value("syscall"), value("arch"))
        uid, uid_name = _user(value("uid"), "uid")
        arguments: dict[str, Any] = {"audit_id": f"{group['seconds']:.3f}:{group['serial']}"}
        if uid_name is not None:
            arguments["uid_name"] = uid_name
            self.unresolved_users += uid_name not in KNOWN_USERS
        for key in ("success", "euid", "auid", "comm", "tty", "ses"):
            if value(key) is not None:
                arguments[key] = value(key)
        if value("key") not in (None, "(null)"):
            arguments["audit_key"] = value("key")

        paths: list[dict[str, str]] = []
        for record_type, record, body in group["records"]:
            def field(key: str, record=record) -> str | None:
                item = record.get(key)
                return None if item is None else _decode(key, item[0], item[1], interpreted)

            if record_type == "CWD" and field("cwd") is not None:
                arguments["cwd"] = field("cwd")
            elif record_type == "PATH" and field("name") not in (None, "(null)"):
                paths.append({"name": field("name"), "nametype": field("nametype") or ""})
            elif record_type == "SOCKADDR":
                destination = _sockaddr(record, body, interpreted)
                if destination:
                    arguments["destination"] = destination
            elif record_type == "EXECVE" or (record_type == "PROCTITLE" and "argc" in record):
                arguments["argv"] = _argv(record, field)
            elif record_type == "PROCTITLE":
                if interpreted and "proctitle=" in body:
                    arguments["proctitle"] = body.split("proctitle=", 1)[1].strip()
                elif field("proctitle") is not None:
                    arguments["proctitle"] = field("proctitle").replace("\x00", " ").strip()
        if paths:
            arguments["paths"] = paths

        return {
            "timestamp": datetime.fromtimestamp(group["seconds"], tz=timezone.utc).isoformat().replace("+00:00", "Z"),
            "host_id": self.host_id or group["node"] or "localhost",
            "pid": _int(value("pid"), "pid"),
            "ppid": _int(value("ppid"), "ppid"),
            "uid": uid,
            "syscall": syscall,
            "process": value("exe") or value("comm") or "",
            "arguments": arguments,
            "return_code": _return_code(value("exit")),
        }

    def _syscall_name(self, number: str | None, arch: str | None) -> str:
        if number is None:
            raise AuditRecordError("SYSCALL record lacks syscall")
        if not number.lstrip("-").isdigit():
            return number  # interpreted output already names the call
        arch_name, table = SYSCALL_TABLES.get(arch or "", (arch or "unknown", ARCH_NAMES.get(arch or "")))
        name = table.get(int(number)) if table else None
        if name is None:
            name = f"syscall_{number}@{arch_name}"
            self.unmapped_syscalls[name] += 1
        return name

    def stats(self) -> dict[str, Any]:
        return {
            "records": dict(self.records.most_common()),
            "rejected": dict(self.rejected.most_common()),
            "orphan_records": self.orphan_records,
            "duplicate_syscall_records": self.duplicate_records,
            "conflicting_duplicate_records": self.conflicting_duplicates,
            "unresolved_user_names": self.unresolved_users,
            "unmapped_syscalls": dict(self.unmapped_syscalls.most_common()),
        }


def _argv(record: dict[str, tuple[str, bool]], field) -> list[str]:
    """Reassemble argv, including the `aN[i]` chunks used for long arguments."""
    count = int(field("argc") or 0)
    argv = []
    for index in range(count):
        if f"a{index}" in record:
            argv.append(field(f"a{index}"))
            continue
        chunks, part = [], 0
        while f"a{index}[{part}]" in record:
            chunks.append(field(f"a{index}[{part}]"))
            part += 1
        argv.append("".join(chunks))
    return argv


def parse_syscall_line(line: str, host_id: str = "localhost") -> dict[str, Any] | None:
    """Parse one standalone `type=SYSCALL` line; return None for other record types."""
    if "type=SYSCALL" not in line:
        return None
    parser = AuditdParser(host_id=host_id, strict=True)
    events = parser.feed(line) + parser.finish()
    if not events:
        raise ValueError("auditd SYSCALL record could not be parsed")
    return events[0]


def event_order(event: dict[str, Any]) -> tuple[float, int]:
    seconds, _, serial = event["arguments"]["audit_id"].partition(":")
    return float(seconds), int(serial)


def open_lines(path: str) -> TextIO:
    """Open an audit log, stdin (`-`) or a gzip-compressed rotation."""
    if path == "-":
        return sys.stdin
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def follow_lines(path: str, poll_seconds: float = 0.5) -> Iterator[str | None]:
    """Tail a log forever, reopening it after rotation; yields None whenever input is idle."""
    handle = open(path, encoding="utf-8", errors="replace")
    try:
        while True:
            line = handle.readline()
            if line:
                yield line
                continue
            yield None
            time.sleep(poll_seconds)
            try:
                current = os.stat(path)
            except FileNotFoundError:
                continue
            if current.st_ino != os.fstat(handle.fileno()).st_ino or current.st_size < handle.tell():
                handle.close()
                handle = open(path, encoding="utf-8", errors="replace")
    finally:
        handle.close()


def parse_timezone(value: str) -> tzinfo:
    """`UTC`, `+05:30` or `-0700` for interpreted (`ausearch -i`) local timestamps."""
    if value.upper() in ("UTC", "Z"):
        return timezone.utc
    match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", value)
    if not match:
        raise ValueError("timezone must be UTC or an offset such as +05:30")
    offset = timedelta(hours=int(match.group(2)), minutes=int(match.group(3)))
    return timezone(offset if match.group(1) == "+" else -offset)

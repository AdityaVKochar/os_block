"""Live eBPF collector built on bpftrace syscall tracepoints.

The generated bpftrace program records each selected system call when it
returns, so an event carries both its arguments (saved at entry, keyed by the
kernel thread ID `curtask->pid`, which unlike the `tid` builtin is valid inside
a container's PID namespace) and its return code. Output is one tab-separated line per call:

    B  syscall  tid  pid  ppid  uid  comm  ret  n1  n2  a1  a2

plus `A tid argv0 argv1 ...` (tab-separated) lines emitted at execve entry so the command line can be
attached to the matching execve. `parse_line` turns that stream into B-SCAF
event dictionaries and `capture` feeds them into an AuditService.

bpftrace needs root (CAP_BPF/CAP_SYS_ADMIN) and tracefs; the project runs it in
a privileged container (`scripts/live_capture.sh`), which observes every
process on the host kernel without installing anything on the host.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import os
import queue
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable, Iterable

from .auditd import decode_sockaddr

# syscall -> (enter assignments, kind). Kinds decide how n1/n2/a1/a2 map to event arguments.
SYSCALL_SPECS: dict[str, tuple[str, str]] = {
    "execve": ("@a1[curtask->pid] = str(args->filename);", "exec"),
    "execveat": ("@a1[curtask->pid] = str(args->filename);", "exec"),
    "openat": ("@a1[curtask->pid] = str(args->filename); @n1[curtask->pid] = args->flags;", "open"),
    "unlink": ("@a1[curtask->pid] = str(args->pathname);", "path"),
    "unlinkat": ("@a1[curtask->pid] = str(args->pathname);", "path"),
    "rename": ("@a1[curtask->pid] = str(args->oldname); @a2[curtask->pid] = str(args->newname);", "rename"),
    "renameat2": ("@a1[curtask->pid] = str(args->oldname); @a2[curtask->pid] = str(args->newname);", "rename"),
    "chmod": ("@a1[curtask->pid] = str(args->filename); @n1[curtask->pid] = args->mode;", "mode"),
    "fchmodat": ("@a1[curtask->pid] = str(args->filename); @n1[curtask->pid] = args->mode;", "mode"),
    "fchownat": ("@a1[curtask->pid] = str(args->filename); @n1[curtask->pid] = args->user; @n2[curtask->pid] = args->group;", "owner"),
    "connect": ("@b[curtask->pid] = buf(uptr(args->uservaddr), 28);", "socket"),
    "bind": ("@b[curtask->pid] = buf(uptr(args->umyaddr), 28);", "socket"),
    "setuid": ("@n1[curtask->pid] = args->uid;", "identity"),
    "setresuid": ("@n1[curtask->pid] = args->euid;", "identity"),
    "setgid": ("@n1[curtask->pid] = args->gid;", "identity"),
    "ptrace": ("@n1[curtask->pid] = args->request; @n2[curtask->pid] = args->pid;", "ptrace"),
    "finit_module": ("@a1[curtask->pid] = str(args->uargs); @n1[curtask->pid] = args->fd;", "module"),
    "delete_module": ("@a1[curtask->pid] = str(args->name_user);", "module"),
    "mount": ("@a1[curtask->pid] = str(args->dev_name); @a2[curtask->pid] = str(args->dir_name);", "mount"),
}
DEFAULT_EBPF_SYSCALLS = tuple(SYSCALL_SPECS)
OPEN_ACCESS = {0: "read", 1: "write", 2: "read-write"}
O_CREAT, O_TRUNC = 0o100, 0o1000


def bpftrace_program(syscalls: Iterable[str] = DEFAULT_EBPF_SYSCALLS) -> str:
    """bpftrace source; positional $1 is the collector's kernel PID so its own I/O is not traced."""
    self_filter = '(uint64)curtask->tgid != $1 && comm != "bpftrace"'
    lines = ["config = { max_strlen = 256 }"]
    for name in syscalls:
        if name not in SYSCALL_SPECS:
            raise ValueError(f"no eBPF tracepoint spec for {name}")
        assignments, kind = SYSCALL_SPECS[name]
        # Every map read at exit is written here first, so exit can always delete it.
        defaults = "@n1[curtask->pid] = 0; @n2[curtask->pid] = 0; " + (
            "" if kind == "socket" else '@a1[curtask->pid] = ""; @a2[curtask->pid] = ""; '
        )
        enter = f"tracepoint:syscalls:sys_enter_{name} /{self_filter}/ {{ @s[curtask->pid] = 1; {defaults}{assignments}"
        if kind == "exec":
            enter += ' printf("A\\t%d\\t", curtask->pid); join(args->argv, "\\t");'
        lines.append(enter + " }")
        if kind == "socket":
            fields, values, cleanup = "%rx\\t", "@b[curtask->pid]", "delete(@b[curtask->pid]);"
        else:
            fields, values, cleanup = "%s\\t%s", "@a1[curtask->pid], @a2[curtask->pid]", "delete(@a1[curtask->pid]); delete(@a2[curtask->pid]);"
        lines.append(
            f"tracepoint:syscalls:sys_exit_{name} /@s[curtask->pid]/ {{ "
            f'printf("B\\t{name}\\t%d\\t%d\\t%d\\t%d\\t%s\\t%d\\t%d\\t%d\\t{fields}\\n", '
            f"curtask->pid, curtask->tgid, curtask->real_parent->tgid, uid, comm, args->ret, @n1[curtask->pid], @n2[curtask->pid], {values}); "
            f"delete(@s[curtask->pid]); delete(@n1[curtask->pid]); delete(@n2[curtask->pid]); {cleanup} }}"
        )
    return "\n".join(lines) + "\n"


def kernel_tgid(bpftrace: str = "bpftrace", timeout: float = 20.0) -> int:
    """This process's PID as the kernel sees it (root PID namespace).

    Inside a container, os.getpid() is namespace-local while curtask->tgid in a
    probe is the kernel's ID, so the collector learns its own ID by opening a
    marker path while a one-shot probe reports who opened it.
    """
    marker = f"/tmp/bscaf-self-{os.getpid()}-{time.time_ns()}"
    probe = f'tracepoint:syscalls:sys_enter_openat /str(args->filename) == "{marker}"/ {{ printf("%d\\n", curtask->tgid); exit(); }}'
    process = subprocess.Popen([shutil.which(bpftrace) or bpftrace, "-B", "line", "-q", "-e", probe], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    found: list[int] = []

    def read() -> None:
        line = process.stdout.readline()
        if line.strip().isdigit():
            found.append(int(line))

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout
    while reader.is_alive() and time.monotonic() < deadline:
        try:
            os.open(marker, os.O_RDONLY)
        except FileNotFoundError:
            pass
        reader.join(0.2)
    process.kill()
    process.wait()
    return found[0] if found else os.getpid()


def _unescape_buf(text: str) -> bytes:
    r"""bpftrace prints buf() with %rx as `\x02\x00...`."""
    return bytes(int(chunk[:2], 16) for chunk in text.split("\\x")[1:] if len(chunk) >= 2)


class EbpfParser:
    """Turn bpftrace output lines into B-SCAF event dictionaries."""

    def __init__(self, host_id: str = "localhost", clock: Callable[[], float] = time.time):
        self.host_id = host_id
        self.clock = clock
        self.argv: dict[str, list[str]] = {}
        self.records = Counter()
        self.rejected = Counter()
        self.lost_events = 0

    def feed(self, line: str) -> dict[str, Any] | None:
        line = line.rstrip("\n")
        if not line:
            return None
        if line.startswith("Lost ") and "events" in line:
            # bpftrace reports perf-buffer overruns as "Lost N events".
            digits = "".join(character for character in line.split()[1] if character.isdigit())
            self.lost_events += int(digits or 0)
            return None
        parts = line.split("\t")
        if parts[0] == "A" and len(parts) >= 3:
            self.argv[parts[1]] = [item for item in parts[2:] if item]
            return None
        if parts[0] != "B" or len(parts) < 12:
            self.rejected["unrecognized collector line"] += 1
            return None
        try:
            return self._event(parts)
        except ValueError:
            self.rejected["malformed collector line"] += 1
            return None

    def _event(self, parts: list[str]) -> dict[str, Any]:
        _, syscall, tid, pid, ppid, uid, comm, ret, n1, n2, a1 = parts[:11]
        a2 = "\t".join(parts[11:])
        self.records[syscall] += 1
        kind = SYSCALL_SPECS[syscall][1]
        number1, number2 = int(n1), int(n2)
        arguments: dict[str, Any] = {"comm": comm, "tid": int(tid), "collector": "ebpf"}
        process = comm
        if kind == "exec":
            arguments["paths"] = [{"name": a1, "nametype": "NORMAL"}]
            argv = self.argv.pop(tid, None)
            if argv:
                arguments["argv"] = argv
            process = a1
        elif kind == "open":
            arguments["paths"] = [{"name": a1, "nametype": "NORMAL"}]
            arguments["access"] = OPEN_ACCESS.get(number1 & 3, "unknown")
            if number1 & O_CREAT:
                arguments["create"] = True
            if number1 & O_TRUNC:
                arguments["truncate"] = True
        elif kind == "path":
            arguments["paths"] = [{"name": a1, "nametype": "DELETE"}]
        elif kind == "module":
            arguments["module"] = a1 or f"fd:{number1}"
        elif kind == "rename":
            arguments["paths"] = [{"name": a1, "nametype": "DELETE"}, {"name": a2, "nametype": "CREATE"}]
        elif kind == "mode":
            arguments["paths"] = [{"name": a1, "nametype": "NORMAL"}]
            arguments["mode"] = oct(number1)
        elif kind == "owner":
            arguments["paths"] = [{"name": a1, "nametype": "NORMAL"}]
            arguments.update(owner_uid=number1, owner_gid=number2)
        elif kind == "socket":
            destination = decode_sockaddr(_unescape_buf(a1))
            if destination:
                arguments["destination"] = destination
        elif kind == "identity":
            arguments["target_id"] = number1
        elif kind == "ptrace":
            arguments.update(request=number1, target_pid=number2)
        elif kind == "mount":
            arguments.update(source=a1, target=a2)
        return {
            "timestamp": datetime.fromtimestamp(self.clock(), tz=timezone.utc).isoformat().replace("+00:00", "Z"),
            "host_id": self.host_id,
            "pid": int(pid),
            "ppid": int(ppid),
            "uid": int(uid),
            "syscall": syscall,
            "process": process,
            "arguments": arguments,
            "return_code": int(ret),
        }

    def stats(self) -> dict[str, Any]:
        return {"records": dict(self.records.most_common()), "rejected": dict(self.rejected), "lost_events": self.lost_events}


def capture(
    service,
    duration: float,
    host_id: str,
    syscalls: Iterable[str] = DEFAULT_EBPF_SYSCALLS,
    bpftrace: str = "bpftrace",
    on_commit: Callable[[], None] | None = None,
    chunk: int = 512,
) -> dict[str, Any]:
    """Trace for `duration` seconds (0 = until Ctrl+C), committing blocks as they close."""
    executable = shutil.which(bpftrace) or bpftrace
    # bpftrace warnings go to a file: an unread stderr pipe would eventually block the tracer.
    errors_file = tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace")
    process = subprocess.Popen(
        [executable, "-B", "line", "-q", "-e", bpftrace_program(syscalls), str(kernel_tgid(executable))],
        stdout=subprocess.PIPE, stderr=errors_file, text=True, errors="replace",
    )
    lines: queue.Queue[str | None] = queue.Queue()

    def pump() -> None:
        for line in process.stdout:
            lines.put(line)
        lines.put(None)

    threading.Thread(target=pump, daemon=True).start()
    parser = EbpfParser(host_id)
    totals = Counter()
    pending: list[dict[str, Any]] = []
    deadline = time.monotonic() + duration if duration else None
    blocks_before = len(service.checkpoints())

    def ingest() -> None:
        nonlocal pending
        if pending:
            stats = service.ingest_many(pending)
            totals.update(accepted=stats.accepted, ignored_by_policy=stats.ignored_by_policy)
            pending = []
        service.commit_due()
        if on_commit:
            on_commit()

    # SIGTERM ends the capture gracefully: the tracer stops and the last batch is committed.
    stop = threading.Event()
    previous_handler = None
    if threading.current_thread() is threading.main_thread():
        previous_handler = signal.signal(signal.SIGTERM, lambda *_: stop.set())
    finished = False
    try:
        while not finished and not stop.is_set() and (deadline is None or time.monotonic() < deadline):
            try:
                line = lines.get(timeout=0.25)
            except queue.Empty:
                ingest()
                continue
            if line is None:
                finished = True
                break
            event = parser.feed(line)
            if event is not None:
                pending.append(event)
            if len(pending) >= chunk:
                ingest()
    except KeyboardInterrupt:
        pass
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
        while True:
            try:
                line = lines.get(timeout=1)
            except queue.Empty:
                break
            if line is None:
                break
            event = parser.feed(line)
            if event is not None:
                pending.append(event)
        ingest()
        service.flush()
        if on_commit:
            on_commit()
        if previous_handler is not None:
            signal.signal(signal.SIGTERM, previous_handler)
    errors_file.seek(0)
    errors = errors_file.read()
    errors_file.close()
    if process.returncode not in (0, -15, 143) and not totals["accepted"]:
        raise RuntimeError(f"bpftrace failed: {errors.strip()[-500:]}")
    return {
        "accepted": totals["accepted"],
        "ignored_by_policy": totals["ignored_by_policy"],
        "checkpoints_created": len(service.checkpoints()) - blocks_before,
        "policy_version": service.policy.version,
        **parser.stats(),
    }

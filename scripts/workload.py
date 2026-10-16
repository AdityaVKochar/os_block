"""Repeatable host workload for the live evaluation (brief Phase 6).

Each iteration performs the security-relevant operations the brief names:
create and write a file (openat), rename it, chmod it, delete it (unlink),
start a process (execve of /bin/true) and open a TCP connection (connect).
Prints a JSON summary with the expected number of each system call.

Usage: python scripts/workload.py --iterations 1000
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time


def run(iterations: int) -> dict:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]

    def accept() -> None:
        while True:
            try:
                connection, _ = listener.accept()
                connection.close()
            except OSError:
                return

    threading.Thread(target=accept, daemon=True).start()
    workdir = Path(tempfile.mkdtemp(prefix="bscaf-workload-"))
    started = time.perf_counter()
    for index in range(iterations):
        path = workdir / f"file-{index}.txt"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("audit me\n")
        renamed = path.with_suffix(".done")
        os.rename(path, renamed)
        os.chmod(renamed, 0o600)
        os.unlink(renamed)
        subprocess.run(["/bin/true"], check=True)
        with socket.create_connection(("127.0.0.1", port)):
            pass
    elapsed = time.perf_counter() - started
    listener.close()
    workdir.rmdir()
    return {
        "pid": os.getpid(),
        "iterations": iterations,
        "seconds": elapsed,
        "workdir": str(workdir),
        "port": port,
        "expected": {"openat (create)": iterations, "rename": iterations, "chmod": iterations, "unlink": iterations, "execve": iterations, "connect": iterations},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--iterations", type=int, default=1000)
    args = parser.parse_args()
    print(json.dumps(run(args.iterations)))


if __name__ == "__main__":
    main()

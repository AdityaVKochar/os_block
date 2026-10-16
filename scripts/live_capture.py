"""Live evaluation: capture real system calls with eBPF while a repeatable workload runs.

Run in the privileged live container (it traces every process on the host kernel):

  docker build -t bscaf-live -f deploy/live/Dockerfile deploy/live
  docker run --rm --privileged --pid=host -v "$PWD":/app -w /app bscaf-live python scripts/live_capture.py

Phases, each repeated --runs times with the median reported:
  1. baseline        workload with no tracing;
  2. tracing only    workload while the bpftrace program runs and its output is discarded;
  3. B-SCAF          workload while `bscaf ingest-ebpf` captures, signs 1-second blocks and
                     replicates each block to three witnesses (quorum 2).
Then the captured ledger is verified locally and against the witnesses, checked for
completeness against what the workload actually did, and attacked with every scenario.
Writes results/live/live-summary.json and results/LIVE_REPORT.md.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import shutil
import signal
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SRC = ROOT / "src"
ENV = {**os.environ, "PYTHONPATH": str(SRC)}
SIGNER = "live-host"

from attack_matrix import attack_matrix  # noqa: E402

from bscaf.attacks import matrix_markdown  # noqa: E402
from bscaf.ebpf import bpftrace_program  # noqa: E402
from bscaf.models import parse_timestamp  # noqa: E402
from bscaf.service import AuditService  # noqa: E402
from bscaf.witness import start_local_witnesses, verify_with_witnesses  # noqa: E402


def ensure_tracefs() -> None:
    if not Path("/sys/kernel/tracing/events/syscalls").exists():
        subprocess.run(["mount", "-t", "tracefs", "nodev", "/sys/kernel/tracing"], check=True)


def cpu_seconds(pid: int) -> float:
    """utime + stime of a process and its reaped children, from /proc."""
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    ticks = sum(int(value) for value in fields[11:15])
    return ticks / os.sysconf("SC_CLK_TCK")


def tree_cpu(pid: int) -> float:
    total = 0.0
    for child in [pid] + [int(item) for item in Path(f"/proc/{pid}/task/{pid}/children").read_text().split()]:
        try:
            total += cpu_seconds(child)
        except (FileNotFoundError, ProcessLookupError):
            pass
    return total


def run_workload(iterations: int) -> dict:
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "workload.py"), "--iterations", str(iterations)], capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def wait_until(predicate, timeout: float, message: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.3)
    raise RuntimeError(message)


def start_collector(data_dir: Path, urls: list[str]) -> subprocess.Popen:
    command = [
        sys.executable, "-m", "bscaf", "--data-dir", str(data_dir), "--signer-id", SIGNER,
        "--batch-size", "5000", "--batch-seconds", "1",
        "ingest-ebpf", "--host-id", "wsl2-live", *[item for url in urls for item in ("--replicate-url", url)], "--quorum", "2",
    ]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=ENV)
    events = data_dir / "events.jsonl"

    def ready() -> bool:
        # Prove the probes are attached: a marker command must reach the ledger.
        subprocess.run(["/bin/echo", "bscaf-ready"], stdout=subprocess.DEVNULL)
        return events.exists() and "bscaf-ready" in events.read_text(encoding="utf-8", errors="replace")

    wait_until(ready, 60, "collector did not start capturing")
    return process


def stop(process: subprocess.Popen) -> str:
    process.send_signal(signal.SIGTERM)
    out, err = process.communicate(timeout=120)
    if process.returncode != 0:
        raise RuntimeError(f"collector failed: {err[-800:]}")
    return out


def completeness(service: AuditService, workload: dict) -> dict:
    """Count the workload's own operations in the ledger.

    The workload's PID inside the container differs from the kernel PID the
    collector records, so the kernel PID is taken from the events that touched
    the workload's private directory, then used for execve and connect.
    """
    workdir, port = workload["workdir"], workload["port"]
    events = list(service.store.events())
    owners = Counter(event.pid for event in events if any(path["name"].startswith(workdir) for path in event.arguments.get("paths", [])))
    pid = owners.most_common(1)[0][0] if owners else None
    observed = Counter()
    for event in events:
        names = [path["name"] for path in event.arguments.get("paths", [])]
        if event.pid == pid and any(name.startswith(workdir) for name in names):
            if event.syscall == "openat" and event.arguments.get("create"):
                observed["openat (create)"] += 1
            elif event.syscall in ("rename", "renameat2"):
                observed["rename"] += 1
            elif event.syscall in ("chmod", "fchmodat"):
                observed["chmod"] += 1
            elif event.syscall in ("unlink", "unlinkat"):
                observed["unlink"] += 1
        elif event.syscall == "execve" and event.ppid == pid and event.process == "/bin/true":
            observed["execve"] += 1
        elif event.syscall == "connect" and event.pid == pid and event.arguments.get("destination") == f"127.0.0.1:{port}":
            observed["connect"] += 1
    rows = {name: {"expected": expected, "captured": observed[name]} for name, expected in workload["expected"].items()}
    total_expected = sum(item["expected"] for item in rows.values())
    total_captured = sum(min(item["captured"], item["expected"]) for item in rows.values())
    return {"by_syscall": rows, "expected": total_expected, "captured": total_captured, "ratio": total_captured / total_expected, "workload_kernel_pid": pid}


def commit_delays(service: AuditService) -> list[float]:
    """Seconds from an event's capture timestamp to the creation of the block that signs it."""
    blocks = service.checkpoints()
    delays, index = [], 0
    for event in service.store.events():
        while blocks[index].last_sequence < event.sequence:
            index += 1
        delays.append((parse_timestamp(blocks[index].created_at) - parse_timestamp(event.timestamp)).total_seconds())
    return delays


def pct(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--out", default=str(ROOT / "results"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root in the privileged live container")
    ensure_tracefs()
    out = Path(args.out)
    work = out / "live"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)

    def step(message: str) -> None:
        print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)

    phases: dict[str, list[dict]] = {"baseline": [], "tracing only": [], "B-SCAF": []}
    run_workload(50)  # warm caches before timing

    step("baseline runs")
    for _ in range(args.runs):
        phases["baseline"].append(run_workload(args.iterations))

    step("tracing-only runs")
    program = work / "program.bt"
    program.write_text(bpftrace_program(), encoding="utf-8")
    for _ in range(args.runs):
        tracer = subprocess.Popen(["bpftrace", "-B", "line", "-q", str(program), "1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(6)  # probe attachment
        before = cpu_seconds(tracer.pid)
        result = run_workload(args.iterations)
        result["collector_cpu_seconds"] = cpu_seconds(tracer.pid) - before
        tracer.send_signal(signal.SIGINT)
        tracer.wait(timeout=30)
        phases["tracing only"].append(result)

    step("B-SCAF capture runs with three witnesses")
    stores = []
    for run in range(args.runs):
        data_dir = work / f"store-{run + 1}"
        source = AuditService(data_dir, signer_id=SIGNER)
        source.initialize()
        urls, keys, servers = start_local_witnesses(work / f"witnesses-{run + 1}", 3, SIGNER, source.store.public_key_path)
        collector = start_collector(data_dir, urls)
        before = tree_cpu(collector.pid)
        result = run_workload(args.iterations)
        result["collector_cpu_seconds"] = tree_cpu(collector.pid) - before
        time.sleep(2)  # let the last 1-second block close and replicate
        result["collector"] = json.loads(stop(collector))
        service = AuditService(data_dir, signer_id=SIGNER)
        local = service.verify()
        full = verify_with_witnesses(local, service.checkpoints(), service.store.acks(), service.store.public_key_path, urls, keys, 2, SIGNER)
        delays = commit_delays(service)
        result.update(
            verify_local=local["verdict"], verify_witnesses=full["verdict"], witness_quorum=full["witness_quorum"],
            events=local["events_checked"], blocks=local["checkpoints_checked"],
            completeness=completeness(service, result),
            commit_delay_ms_median=statistics.median(delays) * 1000, commit_delay_ms_p95=pct(delays, 0.95) * 1000,
            syscalls=dict(Counter(event.syscall for event in service.store.events()).most_common()),
            store_bytes=sum(path.stat().st_size for path in data_dir.glob("*.jsonl")),
        )
        for server in servers:
            server.shutdown()
            server.server_close()
        phases["B-SCAF"].append(result)
        stores.append(data_dir)

    step("attack matrix on the live ledger")
    attacks = attack_matrix(stores[0], SIGNER)

    def median(phase: str, key: str) -> float:
        return statistics.median(run[key] for run in phases[phase])

    baseline = median("baseline", "seconds")
    summary = {
        "generated": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "kernel": os.uname().release,
        "iterations": args.iterations,
        "runs": args.runs,
        "phases": phases,
        "overview": {
            phase: {
                "workload_seconds": median(phase, "seconds"),
                "slowdown_percent": 100 * (median(phase, "seconds") - baseline) / baseline,
                "collector_cpu_seconds": median(phase, "collector_cpu_seconds") if phase != "baseline" else 0.0,
            }
            for phase in phases
        },
        "attacks": attacks,
    }
    (work / "live-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out / "LIVE_REPORT.md").write_text(report(summary), encoding="utf-8")
    owner = ROOT.stat()
    subprocess.run(["chown", "-R", f"{owner.st_uid}:{owner.st_gid}", str(work), str(out / "LIVE_REPORT.md")], check=False)
    step(f"wrote {out / 'LIVE_REPORT.md'}")
    if any(run["verify_witnesses"] != "pass" for run in phases["B-SCAF"]) or not all(row["as_expected"] for row in attacks):
        sys.exit("unexpected verification or attack results")


def report(summary: dict) -> str:
    runs = summary["phases"]["B-SCAF"]
    first = runs[0]
    lines = [
        "# B-SCAF live-capture report",
        f"Generated {summary['generated']} by `scripts/live_capture.py` on kernel {summary['kernel']} (WSL2), "
        f"eBPF collector in a privileged container observing the whole host kernel. "
        f"Workload: {summary['iterations']} iterations of create/write, rename, chmod, delete, /bin/true and a TCP connect; "
        f"{summary['runs']} runs per phase, medians reported.",
        "## Overhead",
        "| Phase | Workload time (s) | Slowdown vs baseline | Collector CPU (s) |",
        "| --- | ---: | ---: | ---: |",
    ]
    for phase, row in summary["overview"].items():
        lines.append(f"| {phase} | {row['workload_seconds']:.2f} | {row['slowdown_percent']:+.1f}% | {row['collector_cpu_seconds']:.2f} |")
    lines += [
        "",
        "Tracing only = the bpftrace program attached with its output discarded (kernel-side cost). "
        "B-SCAF = capture, hash chain, Merkle batches, Ed25519 blocks every second, and replication of each block to three witnesses.",
        "## Capture, integrity and completeness (B-SCAF runs)",
        "| Run | Events captured | Blocks | Lost (perf buffer) | Commit delay p50 / p95 (ms) | Local verify | With witnesses | Workload calls captured |",
        "| --- | ---: | ---: | ---: | ---: | --- | --- | ---: |",
    ]
    for index, run in enumerate(runs, start=1):
        lines.append(
            f"| {index} | {run['events']:,} | {run['blocks']} | {run['collector']['lost_events']} | "
            f"{run['commit_delay_ms_median']:.0f} / {run['commit_delay_ms_p95']:.0f} | {run['verify_local']} | {run['verify_witnesses']} | "
            f"{run['completeness']['captured']:,} / {run['completeness']['expected']:,} ({100 * run['completeness']['ratio']:.1f}%) |"
        )
    lines += ["", "Workload system calls found in the ledger (run 1):", "", "| Operation | Performed | Captured |", "| --- | ---: | ---: |"]
    for name, row in first["completeness"]["by_syscall"].items():
        lines.append(f"| {name} | {row['expected']:,} | {row['captured']:,} |")
    lines += ["", "System calls in the run 1 ledger (the whole host, not only the workload): " + ", ".join(f"{name} {count:,}" for name, count in first["syscalls"].items()) + "."]
    lines += ["", "## Attack matrix on the live ledger", "", matrix_markdown(summary["attacks"]), ""]
    return "\n".join(lines)


if __name__ == "__main__":
    main()

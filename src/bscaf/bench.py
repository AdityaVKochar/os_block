"""Phase 6 evaluation: plain logging vs hash-chain-only vs B-SCAF.

Every configuration runs in a fresh child process so CPU time and peak memory
belong to that configuration alone. Events are replayed from the public auditd
dataset (or generated), re-timed to a fixed nominal arrival rate so time-based
batching is reproducible. Kernel-side auditd overhead is outside this harness:
it measures what B-SCAF adds after a record has been collected.
"""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timedelta, timezone
import itertools
import json
import multiprocessing
import os
from pathlib import Path
import resource
import statistics
import tempfile
import time
from typing import Any, Iterator

NOMINAL_RATE = 1000  # replayed events per second of event time
SYSCALLS = ["execve", "openat", "connect", "unlinkat", "fchmodat", "setuid", "ptrace", "renameat2"]


# ----------------------------------------------------------------- workload

def dataset_events(dataset_dir: Path) -> list[dict[str, Any]]:
    from .auditd import AuditdParser, event_order

    events: list[dict[str, Any]] = []
    for path in sorted(dataset_dir.rglob("*.log")):
        parser = AuditdParser(host_id="bench-host")
        with path.open(encoding="utf-8", errors="replace") as handle:
            events.extend(sorted(parser.parse_lines(handle), key=event_order))
    if not events:
        raise ValueError(f"no auditd SYSCALL events found under {dataset_dir}")
    return events


def synthetic_events(count: int) -> Iterator[dict[str, Any]]:
    for index in range(count):
        syscall = SYSCALLS[index % len(SYSCALLS)]
        yield {
            "timestamp": "2026-01-01T00:00:00Z", "host_id": "bench-host", "pid": 1000 + index % 500, "ppid": 1,
            "uid": index % 3 * 1000, "syscall": syscall, "process": f"/usr/bin/tool-{index % 37}",
            "arguments": {"paths": [{"name": f"/srv/data/file-{index}.txt", "nametype": "NORMAL"}], "success": "yes"},
            "return_code": 0,
        }


def workload(source: str, count: int, dataset_dir: Path | None) -> list[dict[str, Any]]:
    base = synthetic_events(count) if source == "synthetic" else itertools.cycle(dataset_events(dataset_dir))
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = []
    for index, event in enumerate(itertools.islice(base, count)):
        moment = start + timedelta(seconds=index / NOMINAL_RATE)
        events.append({**event, "timestamp": moment.isoformat().replace("+00:00", "Z")})
    return events


# ------------------------------------------------------------------- modes

def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))]


def _timed_stream(events: list[dict[str, Any]], yielded: list[float], latencies: list[float]) -> Iterator[dict[str, Any]]:
    """Yield events while recording how long the consumer spent on each one."""
    for event in events:
        before = time.perf_counter()
        yielded.append(before)
        yield event
        latencies.append(time.perf_counter() - before)


def _start() -> tuple[float, resource.struct_rusage]:
    return time.perf_counter(), resource.getrusage(resource.RUSAGE_SELF)


def _stop(clock: tuple[float, resource.struct_rusage]) -> dict[str, float]:
    started, before = clock
    after = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "ingest_seconds": time.perf_counter() - started,
        "ingest_cpu_seconds": (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime),
    }


def _dir_bytes(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*.jsonl"))


def _run_plain(events, directory: Path, config) -> dict[str, Any]:
    from .policy import AuditPolicy

    policy = AuditPolicy(allowed_syscalls=None)
    path = directory / "plain.jsonl"
    latencies, yielded = [], []
    clock = _start()
    with path.open("a", encoding="utf-8") as handle:
        for index, event in enumerate(_timed_stream(events, yielded, latencies), start=1):
            handle.write(json.dumps(policy.apply(event), sort_keys=True, separators=(",", ":")) + "\n")
            if config["fsync"] and index % config["batch_size"] == 0:
                handle.flush()
                os.fsync(handle.fileno())
    return {"latencies": latencies, **_stop(clock)}


def _run_chain(events, directory: Path, config) -> dict[str, Any]:
    from .models import GENESIS_HASH, AuditEvent
    from .policy import AuditPolicy

    policy = AuditPolicy(allowed_syscalls=None)
    path = directory / "chain.jsonl"
    latencies, yielded = [], []
    previous, sequence = GENESIS_HASH, 0
    clock = _start()
    with path.open("a", encoding="utf-8") as handle:
        for event in _timed_stream(events, yielded, latencies):
            sequence += 1
            record = AuditEvent.from_input(policy.apply(event), sequence, previous)
            previous = record.event_hash
            handle.write(json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")
            if config["fsync"] and sequence % config["batch_size"] == 0:
                handle.flush()
                os.fsync(handle.fileno())
    ingest = _stop(clock)
    started = time.perf_counter()
    previous = GENESIS_HASH
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            record = AuditEvent.from_dict(json.loads(line))
            assert record.previous_event_hash == previous and record.calculate_hash() == record.event_hash
            previous = record.event_hash
    return {"latencies": latencies, **ingest, "verify_seconds": time.perf_counter() - started}


def _run_bscaf(events, directory: Path, config) -> dict[str, Any]:
    from .policy import AuditPolicy
    from .proof import verify_exported_proof
    from .service import AuditService

    service = AuditService(directory / "store", batch_size=config["batch_size"], batch_seconds=config.get("batch_seconds"), policy=AuditPolicy(allowed_syscalls=None), durable=config["fsync"], signer_id="bench")
    service.initialize()
    commits: list[tuple[float, int]] = []
    original = service.store.append_checkpoint

    def record_commit(checkpoint):
        original(checkpoint)
        commits.append((time.perf_counter(), checkpoint.last_sequence))

    service.store.append_checkpoint = record_commit
    latencies, yielded = [], []
    clock = _start()
    service.ingest_many(_timed_stream(events, yielded, latencies))
    service.flush()
    ingest = _stop(clock)
    delays, block = [], 0
    for sequence, arrived in enumerate(yielded, start=1):
        while commits[block][1] < sequence:
            block += 1
        delays.append(commits[block][0] - arrived)

    result: dict[str, Any] = {"latencies": latencies, **ingest, "commit_delays": delays, "blocks": len(commits)}
    started = time.perf_counter()
    report = AuditService(directory / "store", signer_id="bench").verify()
    result["verify_seconds"] = time.perf_counter() - started
    result["verify_verdict"] = report["verdict"]
    started = time.perf_counter()
    proof = service.inclusion_proof(len(events) // 2 or 1)
    result["proof_export_seconds"] = time.perf_counter() - started
    started = time.perf_counter()
    result["proof_valid"] = verify_exported_proof(proof, service.store.public_key_path)["valid"]
    result["proof_verify_seconds"] = time.perf_counter() - started
    started = time.perf_counter()
    batch = [event for event in service.store.events() if event.sequence <= commits[0][1]]
    from .merkle import merkle_root
    merkle_root([event.calculate_hash() for event in batch])
    result["batch_verify_seconds"] = time.perf_counter() - started
    if config.get("witnesses"):
        from .witness import replicate, start_local_witnesses

        urls, _, servers = start_local_witnesses(directory / "witnesses", config["witnesses"], "bench", service.store.public_key_path)
        started = time.perf_counter()
        summary, _ = replicate(urls, service.checkpoints(), [], quorum=config["witnesses"])
        result["replicate_seconds"] = time.perf_counter() - started
        result["replicate_quorum_met"] = summary["quorum_met"]
        for server in servers:
            server.shutdown()
    return result


MODES = {"plain": _run_plain, "hash-chain": _run_chain, "bscaf": _run_bscaf}


def run_config(config: dict[str, Any]) -> dict[str, Any]:
    """Child-process entry point: build the workload, run one mode, report metrics."""
    events = workload(config["source"], config["events"], Path(config["dataset_dir"]) if config.get("dataset_dir") else None)
    count = len(events)
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        raw = MODES[config["mode"]](events, directory, config)
        rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        storage = _dir_bytes(directory / "store") if config["mode"] == "bscaf" else _dir_bytes(directory)
    latencies = [value * 1e6 for value in raw.pop("latencies")]
    delays = [value * 1e3 for value in raw.pop("commit_delays", [])]
    ingest_seconds = raw["ingest_seconds"]
    return {
        **{key: config[key] for key in ("label", "mode", "batch_size", "fsync") if key in config},
        "batch_seconds": config.get("batch_seconds"),
        "events": count,
        "events_per_second": count / ingest_seconds if ingest_seconds else 0.0,
        "latency_us_median": statistics.median(latencies),
        "latency_us_p95": _percentile(latencies, 0.95),
        "latency_us_p99": _percentile(latencies, 0.99),
        "commit_delay_ms_median": statistics.median(delays) if delays else None,
        "commit_delay_ms_p95": _percentile(delays, 0.95) if delays else None,
        "cpu_percent_of_wall": 100 * raw["ingest_cpu_seconds"] / ingest_seconds if ingest_seconds else 0.0,
        "peak_rss_mb": rss_after / 1024,
        "rss_growth_mb": (rss_after - rss_before) / 1024,
        "bytes_per_event": storage / count,
        **raw,
    }


def default_configs(batch_sizes: list[int], batch_seconds: float | None, fsync: bool, witnesses: int) -> list[dict[str, Any]]:
    configs = [
        {"label": "plain log", "mode": "plain", "batch_size": 100, "fsync": False},
        {"label": "hash chain only", "mode": "hash-chain", "batch_size": 100, "fsync": False},
    ]
    for size in batch_sizes:
        configs.append({"label": f"B-SCAF N={size}", "mode": "bscaf", "batch_size": size, "fsync": False, "witnesses": witnesses if size == 100 else 0})
    if batch_seconds:
        configs.append({"label": f"B-SCAF T={batch_seconds}s", "mode": "bscaf", "batch_size": 1_000_000, "batch_seconds": batch_seconds, "fsync": False})
    if fsync:
        configs += [
            {"label": "plain log + fsync/100", "mode": "plain", "batch_size": 100, "fsync": True},
            {"label": "B-SCAF N=100 + fsync", "mode": "bscaf", "batch_size": 100, "fsync": True},
        ]
    return configs


def run_benchmarks(configs: list[dict[str, Any]], source: str, events: int, dataset_dir: Path | None) -> list[dict[str, Any]]:
    context = multiprocessing.get_context("spawn")
    results = []
    for config in configs:
        payload = {**config, "source": source, "events": events, "dataset_dir": str(dataset_dir) if dataset_dir else None}
        with ProcessPoolExecutor(max_workers=1, mp_context=context) as pool:
            results.append(pool.submit(run_config, payload).result())
    return results


def _fmt(value: Any, digits: int = 1) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:,.{digits}f}"
    return f"{value:,}" if isinstance(value, int) else str(value)


def results_markdown(results: list[dict[str, Any]]) -> str:
    lines = [
        "| Configuration | Events/s | Latency p50 / p95 (µs) | Commit delay p50 / p95 (ms) | CPU % | Peak RSS (MB) | Bytes/event | Blocks | Full verify (s) | Proof verify (ms) | Replicate 3 witnesses (s) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in results:
        delay = "-" if row["commit_delay_ms_median"] is None else f"{_fmt(row['commit_delay_ms_median'], 2)} / {_fmt(row['commit_delay_ms_p95'], 2)}"
        proof = row.get("proof_verify_seconds")
        lines.append(
            f"| {row['label']} | {_fmt(row['events_per_second'], 0)} | {_fmt(row['latency_us_median'])} / {_fmt(row['latency_us_p95'])} | {delay} | "
            f"{_fmt(row['cpu_percent_of_wall'], 0)} | {_fmt(row['peak_rss_mb'])} | {_fmt(row['bytes_per_event'], 0)} | {_fmt(row.get('blocks'))} | "
            f"{_fmt(row.get('verify_seconds'), 2)} | {_fmt(None if proof is None else proof * 1e3, 2)} | {_fmt(row.get('replicate_seconds'), 2)} |"
        )
    return "\n".join(lines)


def run_cli(args) -> dict[str, Any]:
    dataset_dir = Path(args.dataset_dir) if args.source == "real" else None
    configs = default_configs([int(size) for size in args.batch_sizes.split(",")], args.batch_seconds, args.fsync, args.witnesses)
    started = time.time()
    results = run_benchmarks(configs, args.source, args.events, dataset_dir)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime(started))
    payload = {"source": args.source, "events": args.events, "nominal_rate": NOMINAL_RATE, "started": stamp, "results": results}
    (out / f"bench-{stamp}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (out / f"bench-{stamp}.md").write_text(results_markdown(results) + "\n", encoding="utf-8")
    return payload

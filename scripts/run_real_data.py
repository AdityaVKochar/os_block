"""End-to-end validation of B-SCAF on the public auditd dataset.

Runs inside the container (see README):
  1. download and checksum the pinned Splunk attack_data auditd logs;
  2. ingest every file through the real CLI, with the default policy and with --all-syscalls;
  3. verify both ledgers, export and independently verify five inclusion proofs;
  4. replicate to three witnesses (quorum 2), verify against them, then take witnesses offline;
  5. run the attack matrix on the real-data ledger;
  6. run the Phase 6 benchmark on the dataset replayed to --events events;
  7. write results/REAL_DATA_REPORT.md and results/real-data-summary.json.

Usage: python scripts/run_real_data.py [--events 100000] [--skip-bench]
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import platform
import random
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from attack_matrix import attack_matrix  # noqa: E402
from fetch_datasets import fetch  # noqa: E402

from bscaf.attacks import matrix_markdown  # noqa: E402
from bscaf.bench import NOMINAL_RATE, default_configs, results_markdown, run_benchmarks  # noqa: E402
from bscaf.service import AuditService  # noqa: E402
from bscaf.witness import start_local_witnesses  # noqa: E402

SIGNER = "dataset-source"
BASELINE = {
    "commit": "a61b866",
    "files_aborted": 11,
    "files_total": 100,
    "events_committed": 46,
    "note": "previous adapter: ausearch -i timestamps aborted the whole file; PATH/EXECVE/CWD records were ignored",
}


def bscaf(data_dir: Path, *args: str, ok=(0,)) -> dict:
    command = [sys.executable, "-m", "bscaf", "--data-dir", str(data_dir), "--signer-id", SIGNER, *args]
    result = subprocess.run(command, capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
    if result.returncode not in ok:
        raise RuntimeError(f"{' '.join(command)} failed ({result.returncode}): {result.stderr or result.stdout}")
    return json.loads(result.stdout)


def merge(total: dict, part: dict) -> None:
    for key, value in part.items():
        if isinstance(value, dict):
            bucket = total.setdefault(key, Counter())
            bucket.update(value)
        elif isinstance(value, int):
            total[key] = total.get(key, 0) + value


def ingest_dataset(files: list[Path], data_dir: Path, extra: list[str]) -> dict:
    totals: dict = {"files": 0, "files_failed": []}
    for path in files:
        technique = path.parent.parent.name
        host = f"{technique}-{path.stem}"[:60]
        try:
            stats = bscaf(data_dir, *extra, "ingest-auditd", "--input", str(path), "--host-id", host)
        except RuntimeError as error:
            totals["files_failed"].append(f"{path.name}: {error}")
            continue
        stats.pop("policy_version", None)
        merge(totals, stats)
        totals["files"] += 1
    bscaf(data_dir, *extra, "flush")
    return totals


def syscall_distribution(data_dir: Path) -> Counter:
    return Counter(event.syscall for event in AuditService(data_dir).events())


def proofs(data_dir: Path, out_dir: Path, count: int = 5) -> list[dict]:
    events = AuditService(data_dir).events()
    rng = random.Random(42)
    results = []
    for sequence in sorted(rng.sample([event.sequence for event in events], min(count, len(events)))):
        proof = bscaf(data_dir, "proof", "--sequence", str(sequence))
        proof_path = out_dir / f"proof-{sequence}.json"
        proof_path.write_text(json.dumps(proof), encoding="utf-8")
        checked = bscaf(data_dir, "proof-verify", "--input", str(proof_path), "--public-key", str(data_dir / "signing-public.pem"), ok=(0, 1))
        results.append({"sequence": sequence, "syscall": proof["event"]["syscall"], "path_length": len(proof["proof"]), "valid": checked["valid"]})
    return results


def witness_run(data_dir: Path, work: Path) -> dict:
    urls, keys, servers = start_local_witnesses(work / "witnesses", 3, SIGNER, data_dir / "signing-public.pem")
    key_args = [item for witness_id, path in keys.items() for item in ("--witness-key", f"{witness_id}={path}")]
    url_args = [item for url in urls for item in ("--witness", url)]
    replicated = bscaf(data_dir, "replicate", *[item for url in urls for item in ("--url", url)], "--quorum", "2", ok=(0, 2))
    steps = {"replicate": {key: replicated[key] for key in ("blocks", "witnesses_complete", "quorum_met", "new_acks")}}

    def check(label: str) -> None:
        report = bscaf(data_dir, "verify", *url_args, *key_args, "--quorum", "2", ok=(0, 1))
        steps[label] = {
            "verdict": report["verdict"],
            "complete_witnesses": report["witness_quorum"]["complete"],
            "warnings": sorted({item["type"] for item in report["warnings"]}),
            "notices": sorted({item["type"] for item in report["notices"]}),
        }

    check("all witnesses online")
    for index, label in ((0, "one witness offline"), (1, "two witnesses offline")):
        servers[index].shutdown()
        servers[index].server_close()
        check(label)
    servers[2].shutdown()
    servers[2].server_close()
    return steps


def table(rows: list[tuple], header: tuple) -> str:
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return "\n".join(lines)


def report_markdown(summary: dict) -> str:
    default, everything = summary["ingest"]["default"], summary["ingest"]["all_syscalls"]
    sections = [
        "# B-SCAF real-data validation report",
        f"Generated {summary['generated']} by `scripts/run_real_data.py` on Python {summary['environment']['python']} ({summary['environment']['platform']}).",
        "## Dataset",
        f"{summary['dataset']['files']} raw Linux auditd logs ({summary['dataset']['bytes']:,} bytes) from Splunk Attack Data, commit `{summary['dataset']['commit']}`, "
        "captured in Splunk Attack Range while executing MITRE ATT&CK techniques. Every file is checked against its pinned SHA-256 before use. "
        "The export mixes raw, ENRICHED and `ausearch -i` formats and mostly keeps one record type per file, so few SYSCALL records arrive with their PATH/EXECVE companions.",
        "## Before and after",
        table([
            ("Files ingested without aborting", f"{BASELINE['files_total'] - BASELINE['files_aborted']} / {BASELINE['files_total']}", f"{everything['files']} / {summary['dataset']['files']}"),
            ("Events committed (all system calls)", BASELINE["events_committed"], everything.get("accepted", 0)),
        ], ("Measure", f"Before (commit {BASELINE['commit']})", "Now")),
        f"Before: {BASELINE['note']}.",
        "## Ingestion",
        table([
            ("Files processed", default["files"], everything["files"]),
            ("Events committed", default.get("accepted", 0), everything.get("accepted", 0)),
            ("Ignored by policy", default.get("ignored_by_policy", 0), everything.get("ignored_by_policy", 0)),
            ("Duplicate SYSCALL records merged", default.get("duplicate_syscall_records", 0), everything.get("duplicate_syscall_records", 0)),
            ("Conflicting duplicates", default.get("conflicting_duplicate_records", 0), everything.get("conflicting_duplicate_records", 0)),
            ("Records without a SYSCALL (PATH/EXECVE/PROCTITLE only)", default.get("orphan_records", 0), everything.get("orphan_records", 0)),
            ("Events with unresolved user names", default.get("unresolved_user_names", 0), everything.get("unresolved_user_names", 0)),
            ("Rejected records", sum(default.get("rejected", {}).values()), sum(everything.get("rejected", {}).values())),
            ("Files failed", len(default["files_failed"]), len(everything["files_failed"])),
        ], ("", "Default policy", "--all-syscalls")),
        "Records by type: " + ", ".join(f"{name} {count:,}" for name, count in sorted(everything.get("records", {}).items(), key=lambda item: -item[1])) + ".",
        "Rejected reasons: " + (", ".join(f"{reason} ({count})" for reason, count in everything.get("rejected", {}).items()) or "none") + ".",
        "Unmapped system calls: " + (", ".join(f"{name} ({count})" for name, count in everything.get("unmapped_syscalls", {}).items()) or "none") + ".",
        "### Committed system calls",
        table(sorted(((name, summary["syscalls"]["default"].get(name, 0), count) for name, count in summary["syscalls"]["all"].items()), key=lambda row: -row[2]), ("System call", "Default policy", "--all-syscalls")),
        "## Verification",
        table([(name, report["verdict"], report["events_checked"], report["checkpoints_checked"], len(report["problems"])) for name, report in summary["verify"].items()], ("Ledger", "Verdict", "Events", "Blocks", "Problems")),
        "### Inclusion proofs (exported, then verified with only the public key)",
        table([(item["sequence"], item["syscall"], item["path_length"], "valid" if item["valid"] else "INVALID") for item in summary["proofs"]], ("Sequence", "System call", "Proof length", "Result")),
        "### Witness quorum (3 witnesses, quorum 2)",
        f"Replication: {summary['witnesses']['replicate']['blocks']} blocks, {summary['witnesses']['replicate']['witnesses_complete']} complete witnesses, quorum met: {summary['witnesses']['replicate']['quorum_met']}.",
        table([(label, step["verdict"], step["complete_witnesses"], ", ".join(step["warnings"]) or "-", ", ".join(step["notices"]) or "-") for label, step in summary["witnesses"].items() if label != "replicate"], ("Situation", "Verdict", "Complete witnesses", "Warnings", "Notices")),
        "## Attack matrix (on the --all-syscalls real-data ledger)",
        matrix_markdown(summary["attacks"]),
    ]
    if summary.get("bench"):
        bench = summary["bench"]
        sections += [
            "## Performance (Phase 6)",
            f"{bench['events']:,} events replayed from the dataset at a nominal {NOMINAL_RATE} events/s of event time; each configuration in its own process. "
            "Latency is B-SCAF processing time per event after collection; commit delay is arrival to signed checkpoint. "
            "Kernel-side auditd cost is not included. Absolute numbers depend on the host (here a container on WSL2).",
            results_markdown(bench["results"]),
        ]
    return "\n\n".join(sections) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--events", type=int, default=100_000, help="benchmark size")
    parser.add_argument("--skip-bench", action="store_true")
    parser.add_argument("--out", default=str(ROOT / "results"))
    args = parser.parse_args()
    out = Path(args.out)
    work = out / "real-data"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)

    def step(message: str) -> None:
        print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)

    manifest = json.loads((ROOT / "datasets" / "manifest.json").read_text(encoding="utf-8"))
    step("downloading dataset")
    files = sorted(fetch(ROOT / "datasets" / "manifest.json", ROOT / "datasets" / "raw"))
    stores = {"default": work / "store-default", "all": work / "store-all-syscalls"}
    summary: dict = {
        "generated": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "dataset": {"commit": manifest["commit"], "files": len(files), "bytes": sum(path.stat().st_size for path in files)},
        "ingest": {},
    }
    step("ingesting with the default policy")
    summary["ingest"]["default"] = ingest_dataset(files, stores["default"], [])
    step("ingesting with --all-syscalls")
    summary["ingest"]["all_syscalls"] = ingest_dataset(files, stores["all"], ["--all-syscalls"])
    summary["syscalls"] = {name: dict(syscall_distribution(path)) for name, path in stores.items()}
    step("verifying ledgers")
    summary["verify"] = {f"{name} policy": bscaf(path, "verify", ok=(0, 1)) for name, path in stores.items()}
    step("exporting and verifying proofs")
    summary["proofs"] = proofs(stores["all"], work)
    step("replicating to witnesses")
    summary["witnesses"] = witness_run(stores["all"], work)
    step("running the attack matrix")
    summary["attacks"] = attack_matrix(stores["all"], SIGNER)
    if not args.skip_bench:
        step(f"benchmarking {args.events:,} events")
        configs = default_configs([10, 100, 1000], 0.05, fsync=True, witnesses=3)
        summary["bench"] = {"events": args.events, "results": run_benchmarks(configs, "real", args.events, ROOT / "datasets" / "raw")}

    (out / "real-data-summary.json").write_text(json.dumps(summary, indent=2, default=dict), encoding="utf-8")
    (out / "REAL_DATA_REPORT.md").write_text(report_markdown(summary), encoding="utf-8")
    step(f"wrote {out / 'REAL_DATA_REPORT.md'}")
    failures = [row["scenario"] for row in summary["attacks"] if not row["as_expected"]]
    if failures or any(report["verdict"] != "pass" for report in summary["verify"].values()):
        sys.exit(f"unexpected results: {failures or summary['verify']}")


if __name__ == "__main__":
    main()

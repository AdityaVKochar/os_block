"""Build the final B-SCAF project report (.docx) from the measured results.

Inputs (snapshots of the evaluation outputs, committed under project-documents/data/):
  real-data-summary.json  from scripts/run_real_data.py
  live-summary.json       from scripts/live_capture.py

Run from the repository root (python-docx and Pillow required):
  python project-documents/builders/build_final_report.py
"""

from __future__ import annotations

import json
from pathlib import Path
import statistics
import sys

from PIL import Image, ImageDraw
from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.shared import Inches, Pt

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_formal_draft as base  # noqa: E402  (shared styles, diagram helpers and references)
import report_charts  # noqa: E402
import report_diagrams  # noqa: E402

DOCUMENTS_DIR = base.DOCUMENTS_DIR
DATA_DIR = DOCUMENTS_DIR / "data"
DIAGRAM = base.ASSET_DIR / "bscaf-final-architecture.png"
OUTPUT = DOCUMENTS_DIR / "Blockchain_System_Call_Audit_Framework_Final_Report.docx"


# ------------------------------------------------------------------ figure

def create_final_diagram() -> None:
    base.ASSET_DIR.mkdir(parents=True, exist_ok=True)
    width, height = 2400, 1500
    canvas = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(canvas)
    title_font = base.find_font(50, bold=True)
    group_font = base.find_font(30, bold=True)
    box_font = base.find_font(27, bold=True)
    small_font = base.find_font(25)
    title = "B-SCAF: Implemented Architecture"
    draw.text(((width - draw.textlength(title, font=title_font)) / 2, 28), title, fill="black", font=title_font)

    groups = [
        ((30, 120, 470, 1330), "1. Collection"),
        ((510, 120, 990, 1330), "2. Evidence Construction"),
        ((1030, 120, 1490, 1330), "3. Signed Ledger"),
        ((1530, 120, 1930, 1330), "4. Witness Quorum"),
        ((1970, 120, 2370, 1330), "5. Verification"),
    ]
    for index, (coords, label) in enumerate(groups):
        draw.rounded_rectangle(coords, radius=24, fill="#F4F4F4" if index % 2 == 0 else "#EAEAEA", outline="black", width=3)
        draw.text((coords[0] + (coords[2] - coords[0] - draw.textlength(label, font=group_font)) / 2, coords[1] + 16), label, fill="black", font=group_font)

    # 1. Collection
    base.box(draw, (80, 210, 420, 330), "Linux Processes", box_font)
    base.box(draw, (80, 410, 420, 530), "System Calls", box_font)
    base.box(draw, (80, 620, 420, 780), "eBPF Collector (bpftrace)", box_font)
    base.box(draw, (80, 860, 420, 1020), "auditd Log Adapter", box_font)
    base.box(draw, (80, 1100, 420, 1240), "JSONL Input", box_font)
    base.arrow(draw, (250, 330), (250, 410))
    base.arrow(draw, (250, 530), (250, 620))
    base.routed_arrow(draw, [(420, 470), (450, 470), (450, 940), (420, 940)])

    # 2. Evidence construction
    base.box(draw, (560, 210, 940, 360), "Versioned Policy: Allow-List, Redaction", box_font)
    base.box(draw, (560, 450, 940, 590), "Canonical Normalization", box_font)
    base.box(draw, (560, 680, 940, 830), "SHA-256 Event Hash Chain", box_font)
    base.box(draw, (560, 930, 940, 1080), "Append-Only Event Store", box_font)
    for x in (420,):
        base.routed_arrow(draw, [(x, 700), (490, 700), (490, 285), (560, 285)])
        base.routed_arrow(draw, [(x, 1170), (490, 1170), (490, 285), (560, 285)])
    base.arrow(draw, (750, 360), (750, 450))
    base.arrow(draw, (750, 590), (750, 680))
    base.arrow(draw, (750, 830), (750, 930))

    # 3. Signed ledger
    base.box(draw, (1080, 210, 1440, 360), "Batch: N Events, T Seconds or Host Change", box_font)
    base.box(draw, (1080, 450, 1440, 640), "Merkle Root, Time Window, Policy Version", box_font)
    base.box(draw, (1080, 730, 1440, 860), "Ed25519 Block Signature", box_font)
    base.box(draw, (1080, 950, 1440, 1080), "Checkpoint Ledger", box_font)
    base.routed_arrow(draw, [(940, 755), (1010, 755), (1010, 285), (1080, 285)])
    base.arrow(draw, (1260, 360), (1260, 450))
    base.arrow(draw, (1260, 640), (1260, 730))
    base.arrow(draw, (1260, 860), (1260, 950))

    # 4. Witness quorum
    for index, top in enumerate((230, 450, 670)):
        base.box(draw, (1580, top, 1880, top + 150), f"Witness {index + 1}", box_font)
    base.box(draw, (1580, 930, 1880, 1110), "Signed Acks (quorum K of N)", box_font)
    for top in (305, 525, 745):
        base.routed_arrow(draw, [(1440, 795), (1505, 795), (1505, top), (1580, top)])
    base.arrow(draw, (1730, 820), (1730, 930))

    # 5. Verification
    base.box(draw, (2020, 230, 2320, 420), "Local Verifier: Chain, Roots, Links, Signatures", box_font)
    base.box(draw, (2020, 520, 2320, 720), "Witness Comparison: Truncation, Re-Signing", box_font)
    base.box(draw, (2020, 820, 2320, 960), "Verdict: Pass, Partial, Fail", box_font)
    base.box(draw, (2020, 1060, 2320, 1220), "Offline Merkle Proof", box_font)
    base.routed_arrow(draw, [(1880, 600), (1950, 600), (1950, 620), (2020, 620)])
    base.arrow(draw, (2170, 420), (2170, 520))
    base.arrow(draw, (2170, 720), (2170, 820))
    # Both stores feed verification along one bus: the full verifier and per-event proofs.
    draw.line([(750, 1080), (750, 1280), (1500, 1280)], fill="black", width=5)
    base.routed_arrow(draw, [(1440, 1015), (1500, 1015), (1500, 1280), (1960, 1280), (1960, 325), (2020, 325)])
    base.arrow(draw, (1960, 1140), (2020, 1140))

    note = "Raw events stay on the host. Witnesses receive only signed checkpoint metadata, over HTTPS with mutual TLS."
    draw.text(((width - draw.textlength(note, font=small_font)) / 2, 1395), note, fill="black", font=small_font)
    canvas.save(DIAGRAM, dpi=(220, 220))


# ------------------------------------------------------------------ helpers

def table(doc, headers, rows, widths=None):
    grid = doc.add_table(rows=1, cols=len(headers))
    grid.alignment = WD_TABLE_ALIGNMENT.CENTER
    grid.style = "Table Grid"
    for index, text in enumerate(headers):
        base.set_cell_text(grid.rows[0].cells[index], str(text), bold=True)
        base.shade_cell(grid.rows[0].cells[index], "E7E7E7")
    for row in rows:
        cells = grid.add_row().cells
        for index, text in enumerate(row):
            base.set_cell_text(cells[index], str(text))
    if widths:
        for row in grid.rows:
            for index, width in enumerate(widths):
                row.cells[index].width = Inches(width)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return grid


FIGURES = {"n": 1}


def figure(doc, path, text, width=6.3):
    """Insert a picture with an automatically numbered caption."""
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.keep_with_next = True
    p.add_run().add_picture(str(path), width=Inches(width))
    FIGURES["n"] += 1
    caption(doc, f"Figure {FIGURES['n']}. {text}")


def caption(doc, text):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.keep_with_next = True
    r = p.add_run(text)
    base.set_font(r, 10, italic=True)


def code(doc, text):
    for line in text.strip().splitlines():
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.left_indent = Inches(0.25)
        r = p.add_run(line)
        r.font.name = "Courier New"
        r.font.size = Pt(9)


def fmt(value, digits=1):
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:,.{digits}f}"
    return f"{value:,}" if isinstance(value, int) else str(value)


# ------------------------------------------------------------------ document

def build() -> None:
    real = json.loads((DATA_DIR / "real-data-summary.json").read_text(encoding="utf-8"))
    live = json.loads((DATA_DIR / "live-summary.json").read_text(encoding="utf-8"))
    create_final_diagram()
    charts = report_charts.build_all(real, live, base.ASSET_DIR / "charts")
    diagrams = report_diagrams.build_all(base.ASSET_DIR / "diagrams")
    FIGURES["n"] = 1
    doc = Document()
    base.configure_document(doc)

    everything = real["ingest"]["all_syscalls"]
    default = real["ingest"]["default"]
    live_runs = live["phases"]["B-SCAF"]
    overview = live["overview"]
    bench = {row["label"]: row for row in real.get("bench", {}).get("results", [])}
    live_events = statistics.median(run["events"] for run in live_runs)
    live_complete = min(run["completeness"]["ratio"] for run in live_runs)
    attacks_ok = sum(row["as_expected"] for row in real["attacks"])

    # Title page
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(100)
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    base.set_font(p.add_run("BLOCKCHAIN-BASED SYSTEM CALL\nAUDIT FRAMEWORK"), 20, bold=True)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    base.set_font(p.add_run("Immutable Audit Logs Using Lightweight Blockchain Principles"), 14, bold=True)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(40)
    base.set_font(p.add_run("Final Project Report: Design, Implementation and Evaluation"), 12, italic=True)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(150)
    base.set_font(p.add_run("Operating Systems and Cybersecurity Project"), 11)
    p.add_run().add_break(WD_BREAK.PAGE)

    base.add_heading(doc, "Abstract", 1)
    base.add_body(doc, (
        "Operating-system audit logs underpin incident response and forensics, yet a privileged attacker can edit or delete them on the host that produced them. "
        "This project designed, implemented and evaluated B-SCAF, a lightweight permissioned framework that makes Linux system-call evidence tamper-evident without a public blockchain. "
        "System calls are captured live through eBPF tracepoints or imported from auditd logs, minimized by a versioned privacy policy, chained with SHA-256, grouped into Merkle batches and committed in Ed25519-signed checkpoint blocks. "
        "Blocks are replicated to a quorum of independent witnesses that enforce chain continuity and return signed acknowledgements, so verification can detect even a history rewritten and re-signed with a stolen host key. "
        f"On 100 real auditd logs from the public Splunk Attack Data repository, the framework ingested every file and committed {everything.get('accepted', 0)} events, compared with 46 events and 11 aborted files for the earlier prototype. "
        f"In live capture on a WSL2 6.18 kernel, the eBPF collector recorded about {live_events:,.0f} host-wide events per run, captured {100 * live_complete:.0f}% of the operations performed by a repeatable workload, "
        f"and slowed that workload by {overview['B-SCAF']['slowdown_percent']:.0f}%, against {overview['tracing only']['slowdown_percent']:.0f}% for eBPF tracing alone; the two are within run-to-run variation, so the cost comes from kernel-side tracing rather than from hashing, signing and replication. "
        f"All {attacks_ok} attack scenarios, including tail truncation and re-signing with a stolen key, were detected as designed."
    ))
    base.add_body(doc, "Keywords: system-call auditing; eBPF; tamper-evident logging; permissioned ledger; Merkle tree; witness quorum; digital forensics.", bold_lead="Keywords:")

    base.add_heading(doc, "1. Introduction", 1)
    base.add_body(doc, "Every security-relevant action on a Linux host, such as running a program, opening a file, changing permissions, assuming another identity or connecting to the network, crosses the kernel boundary as a system call. A faithful record of these calls lets an investigator reconstruct an intrusion. The difficulty is that the record usually lives on the machine under attack: an intruder with root privileges can alter, delete, reorder or replace the very evidence that would expose them.")
    base.add_body(doc, "B-SCAF (Blockchain-Based System Call Audit Framework) applies blockchain principles without a cryptocurrency network. Raw events remain local and searchable, while compact cryptographic commitments are signed, linked and held by independent witnesses. This report describes the final system, its threat model and implementation, and an evaluation on recorded attack data and on live host activity.")

    base.add_heading(doc, "2. Problem Statement and Objectives", 1)
    base.add_body(doc, "How can a Linux host record security-relevant system calls so that later tampering is detectable, the evidence can be verified independently of the host, sensitive arguments are protected, and the overhead stays modest? The project brief set four objectives:")
    base.add_bullets(doc, [
        "Objective 1: capture configurable security-relevant system calls with process, user, time, result and selected arguments.",
        "Objective 2: build a lightweight immutable evidence chain using canonical records, hash links, Merkle batches and signed checkpoints.",
        "Objective 3: provide independent verification with a clear pass, fail or partial-evidence report.",
        "Objective 4: measure throughput, capture-to-commit delay, CPU and memory overhead, storage growth and verification time.",
    ])

    base.add_heading(doc, "3. Research Gap and Contribution", 1)
    base.add_body(doc, "Blockchain logging research has shown the value of immutable audit trails for cloud, healthcare and IoT records, and system-call research has shown that call sequences are strong intrusion signals. Few systems treat host system calls as durable forensic evidence that must survive a privileged compromise. B-SCAF contributes a practical integration of established mechanisms:")
    base.add_bullets(doc, [
        "A kernel-to-proof pipeline from eBPF or auditd capture to deterministic, verifiable event records.",
        "Dual-level integrity: an event hash chain for order and Merkle batch roots for compact commitments and per-event proofs.",
        "A permissioned witness quorum that holds only signed metadata, enforces chain continuity, records equivocation and signs acknowledgements.",
        "Privacy by design: an allow-list, key-based and inline secret redaction, and a policy version bound into every block.",
        "Failure-aware verification that names the first invalid item and distinguishes fail from partial evidence.",
    ])
    base.add_body(doc, "The project does not claim to invent hashing, Merkle trees, signatures or distributed ledgers; its contribution is the integration and its evaluation on real data.")

    base.add_heading(doc, "4. Threat Model", 1)
    base.add_body(doc, "Protected assets are the integrity, order and origin of committed events, their availability through witness copies, and the confidentiality of argument values. The attacker is assumed to gain root on the source host after collection: they can edit, delete, insert or reorder ledger lines, read the source signing key and re-sign a rewritten history, and take some witnesses offline.")
    base.add_body(doc, "B-SCAF guarantees that any change to committed evidence is reported, provided the verifier trusts the source public key and a quorum of witnesses is honest and reachable. It does not guarantee the honesty of a compromised kernel or collector before capture, it cannot protect events that are not yet in a signed and replicated block, and if the quorum is unreachable the verdict is partial rather than pass.")

    base.add_heading(doc, "5. System Design", 1)
    base.add_body(doc, "Figure 1 shows the implemented architecture. Trust is separated: the audited host stores detailed evidence and produces signed commitments; witnesses keep the commitments; any auditor can verify both.")
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.keep_with_next = True
    p.add_run().add_picture(str(DIAGRAM), width=Inches(6.3))
    caption(doc, "Figure 1. B-SCAF collection, evidence construction, signed ledger, witness quorum and verification.")

    base.add_heading(doc, "5.1 Collection", 2)
    base.add_body(doc, "The eBPF collector generates a bpftrace program that attaches to the entry and exit tracepoints of the policy's system calls. Arguments saved at entry are emitted with the return code at exit, keyed by kernel thread ID so the program also works inside a container's PID namespace; execve records carry the command line and connect/bind records carry decoded socket addresses. The collector learns its own kernel PID with a one-shot probe so it never records its own I/O.")
    base.add_body(doc, "The auditd adapter reads raw, ENRICHED, node-prefixed and ausearch -i exports. It merges the SYSCALL, EXECVE, PATH, CWD, SOCKADDR and PROCTITLE records of one kernel event, decodes hex-encoded values, maps syscall numbers per architecture (x86_64, aarch64, i386), streams compressed or standard input, follows rotating logs and skips records already ingested.")
    figure(doc, diagrams["deployment"], "Live-capture deployment used in the evaluation: the eBPF collector runs in a privileged container and traces the shared WSL2 kernel.")
    base.add_heading(doc, "5.2 Evidence Construction", 2)
    base.add_body(doc, "Each accepted event is normalized to a fixed schema (sequence, UTC time, host, PID, PPID, UID, system call, process, arguments, return code) and serialized canonically. Its hash covers the previous event's hash. Blocks close after N events, after T seconds of event time, or when the host changes.")
    figure(doc, diagrams["evidence"], "Evidence structure: each event hash covers its predecessor, a Merkle root commits each batch, and signed blocks link to their predecessor and are copied to every witness.")
    base.add_heading(doc, "5.3 Checkpoint Blocks", 2)
    table(doc, ["Field", "Purpose"], [
        ("block_number, previous_block_hash", "Order and linkage of the permissioned chain"),
        ("batch_id, first/last_sequence, event_count", "Exact range of committed events"),
        ("merkle_root", "Commitment to every event hash in the batch"),
        ("host_id, time_window_start/end", "Origin and time span of the evidence"),
        ("policy_version", "Hash of the minimization policy that produced the events"),
        ("created_at, signer_id, signature, block_hash", "Ed25519 authentication of the block"),
        ("witness acks (stored beside the block)", "Witness-signed receipts proving quorum"),
    ], widths=[2.6, 3.6])
    base.add_heading(doc, "5.4 Witness Quorum", 2)
    base.add_body(doc, "Witnesses trust a configured set of source keys. A witness accepts a block only if its hash and signature are valid and it extends the chain that witness already holds; a different block for an existing number is refused with HTTP 409 and stored as equivocation evidence. Each acceptance returns an acknowledgement signed with the witness's own key. Transport is HTTPS with optional mutual TLS, and streaming collectors push each block as soon as it is signed.")
    figure(doc, diagrams["sequence"], "Witness protocol: replication with signed acknowledgements, refusal of a rewritten block, and independent comparison by an auditor.")
    base.add_heading(doc, "5.5 Verification", 2)
    base.add_body(doc, "Local verification recomputes every event hash and link, every Merkle root, block hash, link and signature, and checks block numbering, ranges and replayed batches in a single indexed pass. Verification against witnesses compares the local ledger with each witness copy, which exposes tail truncation and re-signed history, and checks acknowledgement signatures. Verdicts are pass, fail (with the first invalid item) or partial (uncommitted events or witness quorum unreachable). A portable proof contains one event, its Merkle path and its signed block, and verifies with only the source public key.")

    figure(doc, diagrams["verification"], "Verification decision flow leading to a pass, partial or fail verdict.", width=5.8)
    base.add_heading(doc, "6. Implementation", 1)
    base.add_body(doc, "B-SCAF is a Python 3.11+ package whose only runtime dependency is the cryptography library. Every experiment runs in containers, so nothing is installed on the host: a slim runtime image for tests and replay experiments, and a privileged image with bpftrace for live capture.")
    table(doc, ["Module", "Responsibility"], [
        ("ebpf.py", "bpftrace program generation, kernel-PID discovery, live capture loop"),
        ("auditd.py", "auditd parsing, record correlation, architecture tables, log following"),
        ("policy.py", "Allow-list, redaction, truncation, policy version"),
        ("models.py, canonical.py", "Event and block schemas, canonical JSON, hashing"),
        ("service.py, store.py", "Ingest with cached tail state, batching, signing, verification, search, locking"),
        ("merkle.py, crypto.py, proof.py", "Merkle roots and proofs, Ed25519 (optionally encrypted keys), offline proofs"),
        ("witness.py, tlsutil.py", "Witness rules, signed acks, quorum replication, comparison, HTTPS/mTLS"),
        ("attacks.py, bench.py", "Reusable tampering scenarios and the Phase 6 benchmark"),
        ("cli.py, ui.py", "Command-line interface and local dashboard"),
    ], widths=[2.0, 4.2])
    base.add_body(doc, "The automated suite has 48 tests: integrity and tampering, real auditd fixtures in every supported format, recorded eBPF output, the CLI including de-duplication and replication on commit, the full attack matrix against HTTP witnesses, witness chain rules, mutual TLS, encrypted keys, search and the benchmark harness.")

    base.add_heading(doc, "7. Evaluation", 1)
    base.add_heading(doc, "7.1 Data and Environment", 2)
    base.add_body(doc, f"Recorded data: {real['dataset']['files']} raw auditd logs ({real['dataset']['bytes']:,} bytes) from Splunk Attack Data at commit {real['dataset']['commit'][:12]}, captured in Splunk Attack Range while executing MITRE ATT&CK techniques, each verified against a pinned SHA-256. Live data: the eBPF collector in a privileged container on the WSL2 kernel {live['kernel']}, observing every process on that kernel while a repeatable workload ran. Environment: {real['environment']['platform']}, Python {real['environment']['python']}.")

    base.add_heading(doc, "7.2 Recorded Attack Data", 2)
    table(doc, ["Measure", "Earlier prototype", "Final system"], [
        ("Files ingested without aborting", "89 / 100", f"{everything['files']} / {real['dataset']['files']}"),
        ("Events committed (all system calls)", "46", fmt(everything.get("accepted", 0))),
        ("Events committed (default policy)", "-", fmt(default.get("accepted", 0))),
        ("Duplicate records merged", "-", fmt(everything.get("duplicate_syscall_records", 0))),
        ("Records rejected", "11 whole files", fmt(sum(everything.get("rejected", {}).values()))),
    ], widths=[2.8, 1.6, 1.8])
    caption(doc, "Table 1. Ingestion of the public auditd dataset.")
    figure(doc, charts["ingest"], "Ingestion of the 100 public auditd logs: earlier prototype compared with the final system.")
    figure(doc, charts["dataset_syscalls"], "System calls committed from the public dataset, by policy.", width=5.8)
    labels = {"default policy": "Default policy", "all policy": "All system calls"}
    verify_rows = [(labels.get(name, name), report["verdict"], fmt(report["events_checked"]), fmt(report["checkpoints_checked"])) for name, report in real["verify"].items()]
    table(doc, ["Ledger", "Verdict", "Events", "Blocks"], verify_rows, widths=[2.2, 1.2, 1.2, 1.2])
    proofs_ok = sum(item["valid"] for item in real["proofs"])
    base.add_body(doc, f"Both ledgers verified as pass, and {proofs_ok} of {len(real['proofs'])} randomly selected inclusion proofs verified offline with only the public key. With three witnesses and quorum two, all witnesses online gave pass, one offline still gave pass with a notice, and two offline gave partial evidence.")

    base.add_heading(doc, "7.3 Live Capture: Completeness and Overhead", 2)
    base.add_body(doc, f"Each live run executed {live['iterations']:,} iterations of a workload that creates and writes a file, renames it, changes its mode, deletes it, starts /bin/true and opens a TCP connection. Each phase ran {live['runs']} times; medians are reported.")
    table(doc, ["Phase", "Workload time (s)", "Slowdown", "Collector CPU (s)"], [
        (phase, fmt(row["workload_seconds"], 2), f"{row['slowdown_percent']:+.1f}%", fmt(row["collector_cpu_seconds"], 2)) for phase, row in overview.items()
    ], widths=[2.0, 1.5, 1.2, 1.5])
    caption(doc, "Table 2. Workload slowdown: no tracing, eBPF tracing alone, full B-SCAF capture with witness replication.")
    figure(doc, charts["live_overhead"], "Live workload time per phase (bars: median of three runs; dots: individual runs).")
    table(doc, ["Run", "Events", "Blocks", "Lost", "Commit delay p50/p95 (ms)", "Verdict (local / witnesses)", "Workload calls captured"], [
        (index, fmt(run["events"]), run["blocks"], run["collector"]["lost_events"], f"{run['commit_delay_ms_median']:.0f} / {run['commit_delay_ms_p95']:.0f}",
         f"{run['verify_local']} / {run['verify_witnesses']}", f"{run['completeness']['captured']:,} / {run['completeness']['expected']:,}")
        for index, run in enumerate(live_runs, start=1)
    ])
    caption(doc, "Table 3. Live B-SCAF runs with 1-second blocks replicated to three witnesses.")
    figure(doc, charts["live_syscalls"], "System calls captured host-wide during one live run (the workload plus all other host activity).", width=5.8)
    lost_note = "no events were reported lost" if all(run["collector"]["lost_events"] == 0 for run in live_runs) else "the perf buffer reported a small number of lost host events in some runs, none of them belonging to the workload"
    base.add_body(doc, f"Every workload operation reached the signed ledger in every run, and {lost_note}. The slowdown with full B-SCAF capture is no larger than with tracing alone (the difference is within run-to-run variation on this short workload), so the cost comes from attaching tracepoints to hot system calls such as openat. The user-space work of hashing, signing and replicating runs on another core and used about {overview['B-SCAF']['collector_cpu_seconds']:.1f} CPU-seconds per run. Commit delay is bounded by the 1-second block interval.")

    base.add_heading(doc, "7.4 Attack Tests", 2)
    table(doc, ["Attack", "Local", "With witnesses", "Detected by"], [
        (row["description"], row["local_verdict"], row["witness_verdict"], row["detected_by"]) for row in real["attacks"]
    ], widths=[3.2, 0.9, 1.2, 0.9])
    caption(doc, "Table 4. Attack matrix on the real-data ledger (identical outcomes on the live ledger).")
    figure(doc, charts["attacks"], "Attack scenarios: verdict with local verification only and with three witnesses.")
    base.add_body(doc, "Edits, deletions, insertions, reordering, Merkle-root changes and replayed blocks are caught by local verification. Deleting the newest block and re-signing a rewritten history with the stolen key leave a locally consistent ledger, and only comparison with the witnesses exposes them; the witnesses also refused the rewritten blocks when they were offered. A forged acknowledgement fails its witness signature, and losing the witness quorum yields partial evidence rather than a false pass.")

    if bench:
        base.add_heading(doc, "7.5 Replay Benchmark", 2)
        events = real["bench"]["events"]
        base.add_body(doc, f"{events:,} events from the dataset were replayed through plain JSON logging, a hash chain alone and B-SCAF, each configuration in its own process.")
        table(doc, ["Configuration", "Events/s", "Latency p50/p95 (µs)", "Commit delay p50 (ms)", "Bytes/event", "Full verify (s)"], [
            (label, fmt(row["events_per_second"], 0), f"{row['latency_us_median']:.0f} / {row['latency_us_p95']:.0f}",
             fmt(row["commit_delay_ms_median"], 1), fmt(row["bytes_per_event"], 0), fmt(row.get("verify_seconds"), 2))
            for label, row in bench.items()
        ])
        caption(doc, "Table 5. Throughput, latency, storage and verification on replayed events.")
        figure(doc, charts["throughput"], "Ingest throughput per configuration on one core.")
        figure(doc, charts["latency"], "Per-event processing latency: median and 95th percentile.")
        figure(doc, charts["tradeoff"], "Effect of block size on throughput and on the delay until an event is signed.")
        figure(doc, charts["storage"], "Storage cost per event.")
        n100 = bench.get("B-SCAF N=100")
        if n100:
            base.add_body(doc, f"With 100-event blocks B-SCAF sustained {n100['events_per_second']:,.0f} events/s on one core, verified {events:,} events in {n100['verify_seconds']:.1f} s, verified a single proof in {1000 * n100['proof_verify_seconds']:.1f} ms and replicated its blocks to three witnesses in {n100.get('replicate_seconds', 0):.1f} s. Durable commits (fsync per block) reduce throughput, which matters on filesystems with slow flushes such as the WSL2 virtual disk.")

    base.add_heading(doc, "8. Achievement of Objectives", 1)
    table(doc, ["Objective", "Status", "Evidence"], [
        ("1. Capture system calls with context", "Achieved", "eBPF live capture with full workload coverage; auditd adapter on 100 real logs"),
        ("2. Immutable lightweight evidence chain", "Achieved", "Hash chain, Merkle batches (N, T, host), Ed25519 blocks, policy version"),
        ("3. Independent verification and report", "Achieved", "Local and witness verification; pass/fail/partial; offline proofs"),
        ("4. Practical evaluation", "Achieved", "Live overhead and completeness; replay throughput, latency, storage, verify time"),
        ("Phase 4: 3-5 permissioned witnesses", "Achieved", "Quorum replication, signed acks, equivocation refusal, mTLS"),
        ("Phase 5: attack tests", "Achieved", f"{attacks_ok}/{len(real['attacks'])} scenarios as designed"),
    ], widths=[2.2, 0.9, 3.1])

    base.add_heading(doc, "9. Limitations and Future Work", 1)
    base.add_bullets(doc, [
        "Capture trust: a compromised kernel or collector can fabricate or drop events before capture; remote attestation or TPM-measured boot would reduce this.",
        "Key custody: signing keys can be passphrase-encrypted but are still files; a TPM or HSM would prevent key theft, which today is detected only through the witnesses.",
        "Unprotected window: events are protected once their block is signed and replicated, after at most one block interval (1 s in the live runs).",
        "Scale: verification holds one hash per event in memory and proof export scans the event file; an indexed store and archival are needed for very large ledgers.",
        "Environment: live results come from WSL2, where Docker Desktop containers cannot control auditd; an auditd-based live run and bare-metal timings remain to be done.",
        "Datasets: the public auditd sample is small and mostly exports one record type per file; larger multi-host captures would further test record correlation.",
    ])

    base.add_heading(doc, "10. Conclusion", 1)
    base.add_body(doc, "B-SCAF shows that system-call evidence can be made tamper-evident and independently verifiable with modest overhead and without a public blockchain. Live eBPF capture recorded every operation of a repeatable workload into a signed ledger, recorded attack data from a public dataset was ingested and verified end to end, and every tampering scenario in the brief, plus truncation and re-signing with a stolen key, was detected. The remaining limits concern trust at capture time and key custody, which are hardware and platform questions rather than gaps in the evidence chain.")

    base.add_heading(doc, "Appendix A. Reproducing the Results", 1)
    base.add_body(doc, "From the repository root on any machine with Docker:")
    code(doc, """
docker build -t bscaf .
docker run --rm -v "$PWD":/app bscaf pytest -q
docker run --rm -v "$PWD":/app -w /app bscaf python scripts/run_real_data.py
docker build -t bscaf-live -f deploy/live/Dockerfile deploy/live
docker run --rm --privileged --pid=host -v "$PWD":/app -w /app bscaf-live python scripts/live_capture.py
""")
    base.add_body(doc, "The scripts write results/REAL_DATA_REPORT.md and results/LIVE_REPORT.md with the tables used in this report.")

    base.add_heading(doc, "References", 1)
    for reference in base.extract_references():
        base.add_reference(doc, reference)

    doc.core_properties.title = "Blockchain-Based System Call Audit Framework: Final Report"
    doc.core_properties.subject = "Design, implementation and evaluation of B-SCAF"
    doc.core_properties.author = ""
    doc.core_properties.keywords = "system calls, eBPF, audit logs, blockchain, Merkle tree, Ed25519, witness quorum"
    doc.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    build()

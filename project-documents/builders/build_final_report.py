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
    workload_ops = live_runs[0]["completeness"]["expected"]
    attacks_ok = sum(row["as_expected"] for row in real["attacks"])
    lost = [run["collector"]["lost_events"] for run in live_runs]
    full_slowdown = overview["B-SCAF"]["slowdown_percent"]
    tracing_slowdown = overview["tracing only"]["slowdown_percent"]

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
        "System-call logs are often the best evidence an investigator has after a break-in. Unfortunately they usually sit on the very machine the attacker now controls, and anyone with root access can quietly rewrite them. "
        "In this project we built B-SCAF, a lightweight framework that makes such logs tamper-evident without relying on a public blockchain. "
        "B-SCAF records security-relevant system calls, either live through eBPF or from existing auditd logs, strips out sensitive values, links every record to the one before it with SHA-256, and seals small batches into Ed25519-signed blocks. "
        "Copies of each block go to independent witness machines, so even an attacker who steals the signing key and rewrites history gets caught. "
        f"We tested the system in two ways. On {real['dataset']['files']} real audit logs from the public Splunk Attack Data collection it ingested every file and committed {everything.get('accepted', 0)} events, where our first prototype managed 46 events and crashed on 11 files. "
        f"In live capture on a WSL2 kernel it recorded all {workload_ops:,} operations of a repeatable workload in every run ({100 * live_complete:.0f}% completeness), with roughly {live_events:,.0f} host-wide events captured per run. "
        f"Full capture slowed that deliberately system-call-heavy workload by about {full_slowdown:.0f}%, which is within run-to-run noise of the cost of kernel tracing alone ({tracing_slowdown:.0f}%). "
        f"All {attacks_ok} attack scenarios we tried, including deleting the newest block and re-signing a forged history, were detected."
    ))
    base.add_body(doc, "Keywords: system-call auditing; eBPF; tamper-evident logging; permissioned ledger; Merkle tree; witness quorum; digital forensics.", bold_lead="Keywords:")

    base.add_heading(doc, "1. Introduction", 1)
    base.add_body(doc, "Think about what an investigator has to work with after a server has been broken into. The most useful record is usually the trail of system calls: which programs ran, which files were opened or deleted, which permissions changed and where the machine connected to. Every one of these actions has to pass through the operating-system kernel, so the trail is very hard for malware to avoid.")
    base.add_body(doc, "The trouble is where that trail is kept. It is normally written to a file on the same machine, and anyone who gains root there can edit it, delete parts of it or replace it altogether. Sending logs to a central server helps if the machine dies, but then the administrator of that server becomes the person everyone has to trust.")
    base.add_body(doc, "B-SCAF (Blockchain-Based System Call Audit Framework) takes a different route. It borrows the ideas that make blockchains hard to tamper with, namely hashing, linked blocks, Merkle trees, digital signatures and several independent copies, and leaves out mining, tokens and public consensus. The raw events stay on the host, where they can still be searched, and only small signed summaries are shared with witnesses. This report walks through the design, the threat model, how we built the system, and how it behaved on recorded attack data and on live activity.")

    base.add_heading(doc, "2. Problem Statement and Objectives", 1)
    base.add_body(doc, "The question we set out to answer was this: how can a Linux machine record its security-relevant system calls so that later tampering is noticed, the evidence can be checked without trusting the machine, private details stay private, and normal work is not slowed down much? The project brief turned that into four objectives:")
    base.add_bullets(doc, [
        "Capture a configurable set of security-relevant system calls, together with the process, user, time, result and the important arguments.",
        "Build a lightweight, tamper-evident evidence chain from canonical records, hash links, Merkle batches and signed checkpoints.",
        "Let anyone verify the evidence independently and get a clear answer: pass, fail or partial evidence.",
        "Measure what it costs: throughput, delay until evidence is sealed, CPU and memory use, storage growth and verification time.",
    ])

    base.add_heading(doc, "3. Research Gap and Contribution", 1)
    base.add_body(doc, "There is plenty of work on blockchain-backed logging, but most of it protects cloud, healthcare or IoT records, and a lot of it puts more data on the chain than it needs to. There is also a large body of research that uses system-call sequences to detect intrusions, but it generally takes for granted that the data it learns from is genuine. We found very little that treats host system calls as forensic evidence that has to survive a root-level compromise.")
    base.add_body(doc, "What B-SCAF adds is the combination, built and measured end to end:")
    base.add_bullets(doc, [
        "capture straight from the kernel with eBPF, or from existing auditd logs, turned into records that always hash the same way;",
        "two layers of integrity: a hash chain that protects the order of events, and Merkle roots that seal each batch and allow proofs about single events;",
        "witnesses that keep only signed summaries, refuse conflicting versions of history and sign a receipt for every block they accept;",
        "privacy filtering before anything is stored, with the version of the filtering rules written into every block;",
        "verification that points to exactly where the evidence breaks, and says \"partial\" rather than \"pass\" when it cannot be sure.",
    ])
    base.add_body(doc, "None of these building blocks are new, and we do not claim they are. The contribution is putting them together for operating-system evidence and testing the result on real data.")

    base.add_heading(doc, "4. Threat Model", 1)
    base.add_body(doc, "We assume the worst realistic case. Some time after events have been recorded, an attacker gets root on the monitored machine. From there they can edit, delete, insert or reorder lines in the evidence files, read the signing key and use it to re-sign a rewritten history, and knock some of the witnesses offline.")
    base.add_body(doc, "Under those conditions B-SCAF promises one thing: any change to evidence that was already sealed will be reported, as long as the verifier has the genuine public key and enough witnesses (the quorum) are honest and reachable. It cannot vouch for events that a compromised kernel or collector invented or dropped before they were recorded. It cannot protect events that have not yet been sealed into a replicated block. And if too few witnesses can be reached, it reports partial evidence instead of a clean pass.")

    base.add_heading(doc, "5. System Design", 1)
    base.add_body(doc, "Figure 1 shows how the pieces fit together. The design splits trust three ways: the monitored host keeps the detailed evidence and produces signed summaries, the witnesses keep copies of those summaries, and an auditor can check both without having to trust either.")
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.keep_with_next = True
    p.add_run().add_picture(str(DIAGRAM), width=Inches(6.3))
    caption(doc, "Figure 1. B-SCAF collection, evidence construction, signed ledger, witness quorum and verification.")

    base.add_heading(doc, "5.1 Collecting System Calls", 2)
    base.add_body(doc, "Our first plan was to capture live events with auditd, the standard Linux audit daemon. That did not work in our environment: Docker Desktop containers cannot take control of the kernel's audit system, because the kernel only accepts audit commands from its initial process namespace. So we wrote a second collector based on eBPF.")
    base.add_body(doc, "The eBPF collector generates a small bpftrace program that hooks the entry and the exit of each system call in the policy. At entry it notes the arguments; at exit it prints them together with the return code, so every event is complete in a single line. execve records include the full command line, and connect and bind records include the decoded network address. One detail took some debugging: inside a container, a process's ID is not the ID the kernel reports, so the collector first runs a tiny probe to learn its own kernel ID and then filters itself out. Without that step it would happily record its own file writes.")
    base.add_body(doc, "The auditd adapter handles logs that already exist. Real audit logs turned out to be messier than the examples in the documentation. They come in raw, \"enriched\" and ausearch -i formats, a single kernel event is spread over several records, some values are hex-encoded, and system-call numbers differ between CPU architectures. The adapter groups the records of each event, decodes the values, uses the right system-call table for x86_64, aarch64 or i386, reads compressed files or standard input, can follow a log as it grows, and skips records it has already ingested.")
    figure(doc, diagrams["deployment"], "The live-capture setup used in the evaluation: the eBPF collector runs in a privileged container and traces the shared WSL2 kernel.")

    base.add_heading(doc, "5.2 Building the Evidence Chain", 2)
    base.add_body(doc, "Every event that passes the policy is turned into a fixed set of fields (sequence number, UTC time, host, process ID, parent process ID, user ID, system call, program, arguments and return code) and written out in a canonical form, so the same event always produces exactly the same bytes. Its SHA-256 hash includes the hash of the event before it, and that is what ties the evidence into a chain. Events are then grouped into batches. A batch closes when it reaches N events, when it spans T seconds, or when events from a different host arrive.")
    figure(doc, diagrams["evidence"], "How evidence is protected: each event hash covers the one before it, a Merkle root seals each batch, and signed blocks are linked to each other and copied to every witness.")

    base.add_heading(doc, "5.3 Checkpoint Blocks", 2)
    base.add_body(doc, "Each batch is sealed into a checkpoint block. The table below lists what a block contains; the Ed25519 signature covers all of it.")
    table(doc, ["Field", "Purpose"], [
        ("block_number, previous_block_hash", "Order and linkage of the permissioned chain"),
        ("batch_id, first/last_sequence, event_count", "Exact range of committed events"),
        ("merkle_root", "Commitment to every event hash in the batch"),
        ("host_id, time_window_start/end", "Origin and time span of the evidence"),
        ("policy_version", "Hash of the minimization policy that produced the events"),
        ("created_at, signer_id, signature, block_hash", "Ed25519 authentication of the block"),
        ("witness acks (stored beside the block)", "Witness-signed receipts proving quorum"),
    ], widths=[2.6, 3.6])

    base.add_heading(doc, "5.4 Witnesses", 2)
    base.add_body(doc, "A witness is a separate machine that keeps a copy of every block, but never the events themselves. It only accepts blocks from sources it has been told to trust, and only if the block is intact, correctly signed and continues the chain it already holds. If someone offers a different block for a number it has already seen, it refuses (HTTP 409) and keeps the conflicting block as evidence of the attempt. For every block it does accept, it sends back a receipt signed with its own key. Witnesses can run over HTTPS with mutual TLS, and the live collectors push each block to them as soon as it is sealed.")
    figure(doc, diagrams["sequence"], "The witness protocol: replication with signed receipts, refusal of a rewritten block, and an independent check by an auditor.")

    base.add_heading(doc, "5.5 Verification", 2)
    base.add_body(doc, "Verification happens in two stages. Locally, the verifier reads every event and every block once and recomputes everything: each event hash and link, each Merkle root, each block hash, link and signature, and the block numbering and ranges, which is also how it catches a replayed block. Then, if witnesses are given, it fetches each witness's copy and compares it with the local ledger block by block. That second step is what catches a deleted tail or a history that was rewritten and re-signed, because both leave the local files perfectly consistent with themselves. It also checks the signatures on the witnesses' receipts.")
    base.add_body(doc, "The outcome is one of three verdicts: pass; fail, naming the first thing that is wrong; or partial, meaning nothing is wrong but some events are not sealed yet or not enough witnesses could be reached. For sharing a single piece of evidence there is also a portable proof: one event, the few hashes that link it to its block's Merkle root, and the signed block. Anyone with the public key can check it without seeing any other event.")
    figure(doc, diagrams["verification"], "How the verifier arrives at a pass, partial or fail verdict.", width=5.8)

    base.add_heading(doc, "6. Implementation", 1)
    base.add_body(doc, "B-SCAF is written in Python (3.11 or newer), and its only runtime dependency is the cryptography library. We ran everything in Docker, partly so that nothing had to be installed on the host and partly so that anyone can repeat the experiments with a couple of commands. There is a small image for the tests and the replay experiments, and a privileged image with bpftrace for live capture. The main modules are listed below.")
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
    base.add_body(doc, "There are 48 automated tests. They cover hashing and tampering, real auditd lines in every format we support, recorded eBPF output, the command line (including re-ingesting the same log twice), the full attack matrix against real witness servers, the witness rules, mutual TLS, encrypted keys, search and the benchmark harness.")

    base.add_heading(doc, "7. Evaluation", 1)
    base.add_heading(doc, "7.1 Data and Environment", 2)
    base.add_body(doc, f"We used two kinds of data. The first is recorded: {real['dataset']['files']} raw auditd logs ({real['dataset']['bytes']:,} bytes) from Splunk's public Attack Data repository, captured in a lab while MITRE ATT&CK techniques were being carried out. We pinned the repository at commit {real['dataset']['commit'][:12]} and check every file against its SHA-256 before using it. The second is live: the eBPF collector running in a privileged container on the WSL2 kernel {live['kernel']}, watching every process on that kernel while a repeatable workload ran. All runs used Python {real['environment']['python']} on {real['environment']['platform']}.")

    base.add_heading(doc, "7.2 Recorded Attack Data", 2)
    base.add_body(doc, f"Our first prototype did badly on this data, which turned out to be a useful lesson. It aborted on 11 of the 100 files, because files exported with ausearch -i use a different timestamp format, and it kept only 46 events because it ignored everything except the SYSCALL record. The data had other surprises too: {everything.get('duplicate_syscall_records', 0)} SYSCALL records appear twice with the same audit ID, and many files list their events newest first. The final adapter copes with all of this. Table 1 and Figure 6 compare the two versions.")
    table(doc, ["Measure", "Earlier prototype", "Final system"], [
        ("Files ingested without aborting", "89 / 100", f"{everything['files']} / {real['dataset']['files']}"),
        ("Events committed (all system calls)", "46", fmt(everything.get("accepted", 0))),
        ("Events committed (default policy)", "-", fmt(default.get("accepted", 0))),
        ("Duplicate records merged", "-", fmt(everything.get("duplicate_syscall_records", 0))),
        ("Records rejected", "11 whole files", fmt(sum(everything.get("rejected", {}).values()))),
    ], widths=[2.8, 1.6, 1.8])
    caption(doc, "Table 1. Ingestion of the public auditd dataset.")
    figure(doc, charts["ingest"], "Ingesting the 100 public auditd logs: the earlier prototype compared with the final system.")
    figure(doc, charts["dataset_syscalls"], "System calls committed from the public dataset, by policy.", width=5.8)
    labels = {"default policy": "Default policy", "all policy": "All system calls"}
    verify_rows = [(labels.get(name, name), report["verdict"], fmt(report["events_checked"]), fmt(report["checkpoints_checked"])) for name, report in real["verify"].items()]
    table(doc, ["Ledger", "Verdict", "Events", "Blocks"], verify_rows, widths=[2.2, 1.2, 1.2, 1.2])
    proofs_ok = sum(item["valid"] for item in real["proofs"])
    base.add_body(doc, f"Both ledgers verified cleanly, and {proofs_ok} of {len(real['proofs'])} randomly chosen proofs checked out using nothing but the public key. With three witnesses and a quorum of two, the verdict stayed \"pass\" when one witness was switched off (with a notice saying so) and became \"partial\" when two were off, which is exactly the behaviour we wanted.")

    base.add_heading(doc, "7.3 Live Capture: Completeness and Overhead", 2)
    base.add_body(doc, f"For the live experiment we wrote a workload that does the kind of things an intruder might do. In each of {live['iterations']:,} iterations it creates and writes a file, renames it, changes its permissions, deletes it, starts /bin/true and opens a TCP connection. We ran it {live['runs']} times in each of three setups: with no tracing, with the eBPF program attached but its output thrown away, and with full B-SCAF capture sealing 1-second blocks and sending them to three witnesses. The tables report medians.")
    table(doc, ["Phase", "Workload time (s)", "Slowdown", "Collector CPU (s)"], [
        (phase, fmt(row["workload_seconds"], 2), f"{row['slowdown_percent']:+.1f}%", fmt(row["collector_cpu_seconds"], 2)) for phase, row in overview.items()
    ], widths=[2.0, 1.5, 1.2, 1.5])
    caption(doc, "Table 2. Workload slowdown: no tracing, eBPF tracing alone, full B-SCAF capture with witness replication.")
    figure(doc, charts["live_overhead"], "Live workload time per setup (bars: median of three runs; dots: individual runs).")
    table(doc, ["Run", "Events", "Blocks", "Lost", "Commit delay p50/p95 (ms)", "Verdict (local / witnesses)", "Workload calls captured"], [
        (index, fmt(run["events"]), run["blocks"], run["collector"]["lost_events"], f"{run['commit_delay_ms_median']:.0f} / {run['commit_delay_ms_p95']:.0f}",
         f"{run['verify_local']} / {run['verify_witnesses']}", f"{run['completeness']['captured']:,} / {run['completeness']['expected']:,}")
        for index, run in enumerate(live_runs, start=1)
    ])
    caption(doc, "Table 3. Live B-SCAF runs with 1-second blocks replicated to three witnesses.")
    figure(doc, charts["live_syscalls"], "System calls captured across the whole host during one live run (the workload plus everything else that was running).", width=5.8)
    if any(lost):
        lost_sentence = f"In {sum(1 for value in lost if value)} run(s) the kernel's buffer reported lost events ({max(lost)} at most), but all of them belonged to other processes; none of the workload's operations went missing."
    else:
        lost_sentence = "No events were reported lost."
    base.add_body(doc, f"In every run, every one of the workload's {workload_ops:,} operations ended up in the signed ledger. {lost_sentence}")
    base.add_body(doc, f"The overhead result surprised us at first: the full B-SCAF runs were not slower than tracing alone ({full_slowdown:+.0f}% against {tracing_slowdown:+.0f}%). On a workload this short, the difference is within normal run-to-run variation. What it tells us is that the cost lies in hooking busy system calls such as openat, not in hashing, signing and replicating, which run on another core and used about {overview['B-SCAF']['collector_cpu_seconds']:.1f} CPU-seconds per run. It is worth stressing that this workload does nothing but system calls, so these figures are close to a worst case; ordinary programs spend most of their time computing. Events were sealed within about a second, as you would expect with 1-second blocks.")

    base.add_heading(doc, "7.4 Attack Tests", 2)
    base.add_body(doc, "We wrote each attack as a small program that damages a copy of the ledger the way a real attacker would, then verified the damaged copy with and without witnesses.")
    table(doc, ["Attack", "Local", "With witnesses", "Detected by"], [
        (row["description"], row["local_verdict"], row["witness_verdict"], row["detected_by"]) for row in real["attacks"]
    ], widths=[3.2, 0.9, 1.2, 0.9])
    caption(doc, "Table 4. Attack matrix on the real-data ledger (identical outcomes on the live ledger).")
    figure(doc, charts["attacks"], "Attack scenarios: the verdict with local checks only and with three witnesses.")
    base.add_body(doc, "Edits, deletions, insertions, reordering, a changed Merkle root and a replayed block are all caught by the local checks alone. Two attacks are not: deleting the newest block, and re-signing a rewritten history with the stolen key. Both leave a ledger that is perfectly consistent with itself, and only the witnesses' copies give them away. When we tried to push the rewritten blocks to the witnesses, they refused them. A tampered witness receipt fails its signature check, and losing the quorum produces \"partial\", never a false \"pass\".")

    if bench:
        base.add_heading(doc, "7.5 Replay Benchmark", 2)
        events = real["bench"]["events"]
        base.add_body(doc, f"To measure raw speed we replayed {events:,} events from the dataset through three kinds of logging: plain JSON lines with no protection at all, a hash chain on its own, and B-SCAF with different block sizes. Each setup ran in its own process so the measurements did not interfere with each other.")
        table(doc, ["Configuration", "Events/s", "Latency p50/p95 (µs)", "Commit delay p50 (ms)", "Bytes/event", "Full verify (s)"], [
            (label, fmt(row["events_per_second"], 0), f"{row['latency_us_median']:.0f} / {row['latency_us_p95']:.0f}",
             fmt(row["commit_delay_ms_median"], 1), fmt(row["bytes_per_event"], 0), fmt(row.get("verify_seconds"), 2))
            for label, row in bench.items()
        ])
        caption(doc, "Table 5. Throughput, latency, storage and verification on replayed events.")
        figure(doc, charts["throughput"], "Ingest throughput per configuration on one core.")
        figure(doc, charts["latency"], "Per-event processing time: median and 95th percentile.")
        figure(doc, charts["tradeoff"], "How block size trades throughput against the delay until an event is sealed.")
        figure(doc, charts["storage"], "Storage needed per event.")
        n100 = bench.get("B-SCAF N=100")
        chain = bench.get("hash chain only")
        durable = bench.get("B-SCAF N=100 + fsync")
        if n100:
            share = f", about {100 * n100['events_per_second'] / chain['events_per_second']:.0f}% of what a bare hash chain manages, so the Merkle roots and signatures add surprisingly little" if chain else ""
            fsync_note = f" Forcing every block to disk with fsync brings throughput down to {durable['events_per_second']:,.0f} events per second, which mostly reflects how slowly the WSL2 virtual disk flushes." if durable else ""
            base.add_body(doc, f"With 100-event blocks B-SCAF handled {n100['events_per_second']:,.0f} events per second on one core{share}. Verifying all {events:,} events took {n100['verify_seconds']:.1f} s, checking a single proof took {1000 * n100['proof_verify_seconds']:.2f} ms, and sending every block to three witnesses took {n100.get('replicate_seconds', 0):.1f} s.{fsync_note}")

    base.add_heading(doc, "8. Problems We Ran Into", 1)
    base.add_body(doc, "A good part of the project was spent on things that did not work the first time. We think they are worth recording, because each one changed the design.")
    base.add_bullets(doc, [
        "Real logs broke the first parser. It had only been tried on a single hand-written line. The public dataset showed it several timestamp formats, events split across records, duplicated records and newest-first ordering.",
        "Ingestion was far too slow. The first version re-read the whole event file for every new event, so the work grew with the square of the log size, and 100,000 events would never have finished. Keeping the end of the chain in memory fixed it.",
        "auditd could not be controlled from a Docker Desktop container, so live capture with auditd was impossible in our setup. That is why the eBPF collector exists.",
        "Process IDs inside a container are not the IDs the kernel sees. This silently broke both the collector's self-filter and our completeness check until we added the kernel-ID probe.",
        "Flushing to disk on WSL2 costs around 8 ms per call, which dominated early measurements. We made durable writes a setting and report both modes.",
    ])

    base.add_heading(doc, "9. Achievement of Objectives", 1)
    table(doc, ["Objective", "Status", "Evidence"], [
        ("1. Capture system calls with context", "Achieved", "eBPF live capture with full workload coverage; auditd adapter on 100 real logs"),
        ("2. Immutable lightweight evidence chain", "Achieved", "Hash chain, Merkle batches (N, T, host), Ed25519 blocks, policy version"),
        ("3. Independent verification and report", "Achieved", "Local and witness verification; pass/fail/partial; offline proofs"),
        ("4. Practical evaluation", "Achieved", "Live overhead and completeness; replay throughput, latency, storage, verify time"),
        ("Phase 4: 3-5 permissioned witnesses", "Achieved", "Quorum replication, signed acks, equivocation refusal, mTLS"),
        ("Phase 5: attack tests", "Achieved", f"{attacks_ok}/{len(real['attacks'])} scenarios as designed"),
    ], widths=[2.2, 0.9, 3.1])

    base.add_heading(doc, "10. Limitations and Future Work", 1)
    base.add_body(doc, "B-SCAF has real limits, and it is better to state them plainly:")
    base.add_bullets(doc, [
        "It trusts the machine at the moment of recording. A compromised kernel or collector can invent or drop events before they are sealed. Remote attestation or measured boot would reduce that trust.",
        "The signing key is still a file, even if it can be encrypted with a passphrase. A TPM or hardware security module would stop the key from being stolen in the first place; today a stolen key is only caught through the witnesses.",
        "Events are unprotected for a short time, until their block is sealed and replicated. In the live runs that was about a second.",
        "The storage is simple. Verification keeps one hash per event in memory and exporting a proof scans the event file, so very large ledgers would need an index and archiving.",
        "Our live results come from WSL2 on a laptop. An auditd-based live run on a normal Linux machine and timings on bare metal are still to be done.",
        "The public auditd sample is small and mostly stores one record type per file, so larger multi-host captures would test the record grouping more thoroughly.",
    ])

    base.add_heading(doc, "11. Conclusion", 1)
    base.add_body(doc, "We set out to show that system-call evidence can be protected against a root-level attacker without a public blockchain and at a reasonable cost, and we think the results support that. In live capture every operation of our test workload made it into the signed ledger. The public attack dataset went through the whole pipeline. Every tampering scenario from the brief was caught, and so were deleting the tail and re-signing with a stolen key. What remains is mostly about trust at the edges: whether the machine was honest when it recorded the events, and how well the signing key is protected. Those are questions for hardware and platform design rather than gaps in the evidence chain itself.")

    base.add_heading(doc, "Appendix A. Reproducing the Results", 1)
    base.add_body(doc, "From the repository root on any machine with Docker:")
    code(doc, """
docker build -t bscaf .
docker run --rm -v "$PWD":/app bscaf pytest -q
docker run --rm -v "$PWD":/app -w /app bscaf python scripts/run_real_data.py
docker build -t bscaf-live -f deploy/live/Dockerfile deploy/live
docker run --rm --privileged --pid=host -v "$PWD":/app -w /app bscaf-live python scripts/live_capture.py
""")
    base.add_body(doc, "The scripts write results/REAL_DATA_REPORT.md and results/LIVE_REPORT.md, which contain the tables used in this report. On Windows PowerShell, write ${PWD} instead of $PWD.")

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

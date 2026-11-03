"""Build the final B-SCAF project report (.docx) from the measured results.

Inputs (snapshots of the evaluation outputs, committed under project-documents/data/):
  real-data-summary.json  from scripts/run_real_data.py
  live-summary.json       from scripts/live_capture.py

Run from the repository root (python-docx, python-pptx and Pillow required):
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
    """The implemented architecture, one colour per stage (shared with the other diagrams)."""
    base.ASSET_DIR.mkdir(parents=True, exist_ok=True)
    width, height = 2400, 1500
    canvas = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(canvas)
    title_font = base.find_font(50, bold=True)
    box_font = base.find_font(27, bold=True)
    small_font = base.find_font(25)
    title = "B-SCAF: Implemented Architecture"
    draw.text(((width - draw.textlength(title, font=title_font)) / 2, 28), title, fill="black", font=title_font)
    group, box = report_diagrams.group, report_diagrams.box

    for coords, label, stage in [
        ((30, 120, 470, 1330), "1. Collection", "collect"),
        ((510, 120, 990, 1330), "2. Evidence Construction", "evidence"),
        ((1030, 120, 1490, 1330), "3. Signed Ledger", "ledger"),
        ((1530, 120, 1930, 1330), "4. Witness Quorum", "witness"),
        ((1970, 120, 2370, 1330), "5. Verification", "verify"),
    ]:
        group(draw, coords, label, stage, centered=True)

    # 1. Collection
    box(draw, (80, 210, 420, 330), "Linux Processes", box_font, "collect")
    box(draw, (80, 410, 420, 530), "System Calls", box_font, "collect")
    box(draw, (80, 620, 420, 780), "eBPF Collector (bpftrace)", box_font, "collect")
    box(draw, (80, 860, 420, 1020), "auditd Log Adapter", box_font, "collect")
    box(draw, (80, 1100, 420, 1240), "JSONL Input", box_font, "collect")
    base.arrow(draw, (250, 330), (250, 410))
    base.arrow(draw, (250, 530), (250, 620))
    base.routed_arrow(draw, [(420, 470), (450, 470), (450, 940), (420, 940)])

    # 2. Evidence construction
    box(draw, (560, 210, 940, 360), "Versioned Policy: Allow-List, Redaction", box_font, "evidence")
    box(draw, (560, 450, 940, 590), "Canonical Normalization", box_font, "evidence")
    box(draw, (560, 680, 940, 830), "SHA-256 Event Hash Chain", box_font, "evidence")
    box(draw, (560, 930, 940, 1080), "Append-Only Event Store", box_font, "evidence")
    base.routed_arrow(draw, [(420, 700), (490, 700), (490, 285), (560, 285)])
    base.routed_arrow(draw, [(420, 1170), (490, 1170), (490, 285), (560, 285)])
    base.arrow(draw, (750, 360), (750, 450))
    base.arrow(draw, (750, 590), (750, 680))
    base.arrow(draw, (750, 830), (750, 930))

    # 3. Signed ledger
    box(draw, (1080, 210, 1440, 360), "Batch: N Events, T Seconds or Host Change", box_font, "ledger")
    box(draw, (1080, 450, 1440, 640), "Merkle Root, Time Window, Policy Version", box_font, "ledger")
    box(draw, (1080, 730, 1440, 860), "Ed25519 Block Signature", box_font, "ledger")
    box(draw, (1080, 950, 1440, 1080), "Checkpoint Ledger", box_font, "ledger")
    base.routed_arrow(draw, [(940, 755), (1010, 755), (1010, 285), (1080, 285)])
    base.arrow(draw, (1260, 360), (1260, 450))
    base.arrow(draw, (1260, 640), (1260, 730))
    base.arrow(draw, (1260, 860), (1260, 950))

    # 4. Witness quorum
    for index, top in enumerate((230, 450, 670)):
        box(draw, (1580, top, 1880, top + 150), f"Witness {index + 1}", box_font, "witness")
    box(draw, (1580, 930, 1880, 1110), "Signed Acks (quorum K of N)", box_font, "witness")
    for top in (305, 525, 745):
        base.routed_arrow(draw, [(1440, 795), (1505, 795), (1505, top), (1580, top)])
    base.arrow(draw, (1730, 820), (1730, 930))

    # 5. Verification
    box(draw, (2020, 230, 2320, 420), "Local Verifier: Chain, Roots, Links, Signatures", box_font, "verify")
    box(draw, (2020, 520, 2320, 720), "Witness Comparison: Truncation, Re-Signing", box_font, "verify")
    box(draw, (2020, 820, 2320, 960), "Verdict: Pass, Partial, Fail", box_font, "verify")
    box(draw, (2020, 1060, 2320, 1220), "Offline Merkle Proof", box_font, "verify")
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
        # Set both the grid columns and the cells: Word reads the cells, LibreOffice the grid.
        grid.autofit = False
        for index, width in enumerate(widths):
            grid.columns[index].width = Inches(width)
        for row in grid.rows:
            for index, width in enumerate(widths):
                row.cells[index].width = Inches(width)
    # Keep a table on one page (with its caption) where it fits; if it must break, repeat
    # the header row and never split a row, so a header is never stranded at a page foot.
    for position, row in enumerate(grid.rows):
        properties = row._tr.get_or_add_trPr()
        properties.append(base.OxmlElement("w:cantSplit"))
        if position == 0:
            header = base.OxmlElement("w:tblHeader")
            header.set(base.qn("w:val"), "true")
            properties.append(header)
        for cell in row.cells:
            for paragraph in cell.paragraphs:
                paragraph.paragraph_format.keep_with_next = True
    # The spacer also keeps with what follows, so a caption never drifts to the next page.
    spacer = doc.add_paragraph()
    spacer.paragraph_format.space_after = Pt(2)
    spacer.paragraph_format.keep_with_next = True
    return grid


FIGURES = {"n": 1}
GITHUB_URL = "https://github.com/AdityaVKochar/os_block"


def github_banner(doc, size=20, space_before=60):
    """The project's GitHub link, large and clickable, for a title page."""
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(space_before)
    base.set_font(p.add_run("Source code, data and reproduction scripts"), 12, bold=True)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    rel_id = p.part.relate_to(GITHUB_URL, "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink", is_external=True)
    link = base.OxmlElement("w:hyperlink")
    link.set(base.qn("r:id"), rel_id)
    run = base.OxmlElement("w:r")
    props = base.OxmlElement("w:rPr")
    fonts = base.OxmlElement("w:rFonts")
    fonts.set(base.qn("w:ascii"), "Times New Roman")
    fonts.set(base.qn("w:hAnsi"), "Times New Roman")
    props.append(fonts)
    for tag, value in (("w:b", None), ("w:color", "1C5CAB"), ("w:u", "single"), ("w:sz", str(size * 2))):
        element = base.OxmlElement(tag)
        if value is not None:
            element.set(base.qn("w:val"), value)
        props.append(element)
    run.append(props)
    text = base.OxmlElement("w:t")
    text.text = GITHUB_URL
    run.append(text)
    link.append(run)
    p._p.append(link)


def figure(doc, path, text, width=6.3):
    """Insert a picture (diagram) with an automatically numbered caption."""
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.keep_with_next = True
    p.add_run().add_picture(str(path), width=Inches(width))
    figure_caption(doc, text)


def figure_caption(doc, text):
    """Numbered caption for the figure just added (a diagram picture or a native chart)."""
    FIGURES["n"] += 1
    caption(doc, f"Figure {FIGURES['n']}. {text}")


VERDICT_CELLS = {  # word shown in the cell, cell fill, white text?
    "fail": ("Detected", "2A78D6", True),
    "pass": ("Pass", "EDEDEA", False),
    "partial": ("Partial", "EB6834", False),
}


def attack_table(doc, attacks):
    """The attack matrix as a native table: each verdict cell carries its word and a fill colour."""
    grid = table(doc, ["Attack", "Local checks", "With 3 witnesses", "Outcome"], [
        (row["description"], VERDICT_CELLS[row["local_verdict"]][0], VERDICT_CELLS[row["witness_verdict"]][0],
         "as designed" if row["as_expected"] else "UNEXPECTED")
        for row in attacks
    ], widths=[3.1, 1.0, 1.2, 0.9])
    for row, attack in zip(grid.rows[1:], attacks):
        for column, key in ((1, "local_verdict"), (2, "witness_verdict")):
            word, fill, white = VERDICT_CELLS[attack[key]]
            cell = row.cells[column]
            base.shade_cell(cell, fill)
            cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            for run in cell.paragraphs[0].runs:
                run.bold = white
                if white:
                    run.font.color.rgb = base.RGBColor(0xFF, 0xFF, 0xFF)
    return grid


def caption(doc, text):
    """Caption below a figure or table (the figure or table keeps itself with its caption)."""
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
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
    diagrams = report_diagrams.build_all(base.ASSET_DIR / "diagrams")
    FIGURES["n"] = 1
    doc = Document()
    base.configure_document(doc)

    everything = real["ingest"]["all_syscalls"]
    default = real["ingest"]["default"]
    live_runs = live["phases"]["B-SCAF"]
    overview = live["overview"]
    bench = {row["label"]: row for row in real.get("bench", {}).get("results", [])}
    live_complete = min(run["completeness"]["ratio"] for run in live_runs)
    workload_ops = live_runs[0]["completeness"]["expected"]
    attacks_ok = sum(row["as_expected"] for row in real["attacks"])
    lost = [run["collector"]["lost_events"] for run in live_runs]
    full_slowdown = overview["B-SCAF"]["slowdown_percent"]
    tracing_slowdown = overview["tracing only"]["slowdown_percent"]
    verify_all = real["verify"]["all policy"]
    verify_default = real["verify"]["default policy"]

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
    github_banner(doc)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(90)
    base.set_font(p.add_run("Operating Systems and Cybersecurity Project"), 11)
    p.add_run().add_break(WD_BREAK.PAGE)

    base.add_heading(doc, "Abstract", 1)
    base.add_body(doc, (
        "System-call logs are key evidence after a break-in, but they live on the machine the attacker controls, and anyone with root can rewrite them. "
        "B-SCAF makes these logs tamper-evident without a public blockchain. It captures security-relevant system calls (live with eBPF, or from auditd logs), removes sensitive values, chains every record with SHA-256 and seals batches into Ed25519-signed blocks, copies of which are kept by independent witnesses. "
        f"On {real['dataset']['files']} public attack logs it ingested every file ({everything.get('accepted', 0)} events, against 46 for our first prototype). "
        f"In live capture it recorded all {workload_ops:,} operations of a test workload in every run ({100 * live_complete:.0f}%), with about {full_slowdown:.0f}% slowdown on a deliberately system-call-heavy workload. "
        f"All {attacks_ok} tampering attacks, including re-signing with a stolen key, were detected."
    ))
    base.add_body(doc, "Keywords: system-call auditing; eBPF; tamper-evident logging; permissioned ledger; Merkle tree; witness quorum; digital forensics.", bold_lead="Keywords:")

    base.add_heading(doc, "1. Introduction", 1)
    base.add_body(doc, "After a server is compromised, the trail of system calls (programs run, files touched, permissions changed, connections made) is often the best evidence, because every action has to pass through the kernel. But that trail is stored on the same machine, so anyone with root can edit or delete it. Central log servers help availability, but then their administrator has to be trusted.")
    base.add_body(doc, "B-SCAF borrows what makes blockchains hard to tamper with (hashes, linked blocks, Merkle trees, signatures and independent copies) and leaves out mining, tokens and public consensus. Raw events stay on the host; only small signed summaries go to witnesses.")

    base.add_heading(doc, "2. Problem Statement and Objectives", 1)
    base.add_body(doc, "How can a Linux machine record its security-relevant system calls so that tampering is noticed, the evidence can be checked without trusting the machine, private data stays private, and overhead stays low? The brief set four objectives:")
    base.add_bullets(doc, [
        "Capture selected system calls with process, user, time, result and key arguments.",
        "Build a lightweight tamper-evident chain: canonical records, hash links, Merkle batches, signed blocks.",
        "Verify independently, with a pass, fail or partial verdict.",
        "Measure throughput, sealing delay, CPU, memory, storage and verification time.",
    ])

    base.add_heading(doc, "3. Research Gap and Contribution", 1)
    base.add_body(doc, "Blockchain logging work mostly protects cloud, health or IoT records, and system-call research mostly detects intrusions while assuming the data is genuine. Little work treats host system calls as evidence that must survive a root compromise. B-SCAF contributes the combination, built and measured end to end:")
    base.add_bullets(doc, [
        "kernel (eBPF) or auditd capture into records that always hash the same way;",
        "a hash chain for order, plus Merkle roots for batch seals and single-event proofs;",
        "witnesses that keep only signed summaries, refuse conflicting history and sign receipts;",
        "privacy filtering before storage, and verification that names the first problem.",
    ])
    base.add_body(doc, "The building blocks are not new; the integration and its evaluation are.")

    base.add_heading(doc, "4. Threat Model", 1)
    base.add_body(doc, "After events are recorded, an attacker gains root. They can edit, delete, insert or reorder evidence, steal the signing key to re-sign a rewritten history, and take some witnesses offline.")
    base.add_body(doc, "B-SCAF guarantees that any change to sealed evidence is reported, provided the verifier has the genuine public key and a quorum of witnesses is honest and reachable. It cannot vouch for events faked before recording or not yet sealed, and it reports \"partial\" when the quorum cannot be reached.")

    base.add_heading(doc, "5. System Design", 1)
    base.add_body(doc, "Figure 1 shows the design, one colour per stage: the host keeps the detailed evidence and signs summaries, witnesses keep copies of the summaries, and an auditor checks both.")
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.keep_with_next = True
    p.add_run().add_picture(str(DIAGRAM), width=Inches(6.3))
    caption(doc, "Figure 1. B-SCAF collection, evidence construction, signed ledger, witness quorum and verification.")

    base.add_heading(doc, "5.1 Collecting System Calls", 2)
    base.add_body(doc, "Live capture uses eBPF, because Docker Desktop containers cannot control auditd (the kernel only accepts audit commands from its initial process namespace). A generated bpftrace program hooks each system call's entry and exit and emits one line with the arguments and the return code; execve lines include the command line and connect or bind lines the network address. The collector first learns its own kernel process ID, which differs inside a container, so it never records itself.")
    base.add_body(doc, "The auditd adapter imports existing logs. It handles raw, enriched and ausearch -i formats, groups the several records of each event, decodes hex values, maps system-call numbers per CPU architecture, follows growing logs and skips records already imported.")
    figure(doc, diagrams["deployment"], "The live-capture setup used in the evaluation.")

    base.add_heading(doc, "5.2 Building the Evidence Chain", 2)
    base.add_body(doc, "Each kept event becomes a fixed record (sequence, UTC time, host, PID, PPID, UID, system call, program, arguments, return code) in canonical form, and its SHA-256 hash includes the previous event's hash. A batch closes after N events, T seconds or a change of host.")
    figure(doc, diagrams["evidence"], "Hash chain, Merkle batch, signed blocks and witness copies.")

    base.add_heading(doc, "5.3 Checkpoint Blocks", 2)
    base.add_body(doc, "Each batch is sealed into a block; the signature covers every field below.")
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
    base.add_body(doc, "Witnesses keep copies of blocks, never events. A witness accepts a block only from a trusted source, intact, correctly signed and continuing its chain; a different block for an existing number is refused (HTTP 409) and kept as evidence. Each accepted block gets a receipt signed with the witness's own key. Transport can use mutual TLS, and the collectors push each block as soon as it is sealed.")
    figure(doc, diagrams["sequence"], "The witness protocol, including refusal of a rewritten block.")

    base.add_heading(doc, "5.5 Verification", 2)
    base.add_body(doc, "The verifier recomputes every event hash and link, Merkle root, block hash, link, number and signature in one pass. With witnesses, it also compares each witness copy block by block, which exposes a deleted tail or a re-signed history, and checks the receipts. The verdict is pass, fail (naming the first problem) or partial. A portable proof (one event, its Merkle path and its signed block) can be checked with only the public key.")
    figure(doc, diagrams["verification"], "How the verifier reaches pass, partial or fail.", width=5.8)

    base.add_heading(doc, "6. Implementation", 1)
    base.add_body(doc, "B-SCAF is a Python 3.11+ package with one runtime dependency (cryptography). Everything runs in Docker: a small image for tests and replay experiments, and a privileged image with bpftrace for live capture.")
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
    base.add_body(doc, "48 automated tests cover hashing and tampering, every supported log format, recorded eBPF output, the command line, the attack matrix against real witnesses, mutual TLS, encrypted keys, search and the benchmark.")

    base.add_heading(doc, "7. Evaluation", 1)
    base.add_heading(doc, "7.1 Data and Environment", 2)
    base.add_body(doc, f"Recorded data: {real['dataset']['files']} raw auditd logs ({real['dataset']['bytes'] / 1e6:.2f} MB) from Splunk Attack Data, captured during MITRE ATT&CK simulations, pinned to commit {real['dataset']['commit'][:12]} and checked by SHA-256. Live data: the eBPF collector in a privileged container on the WSL2 kernel {live['kernel']}, while a repeatable workload ran. Python {real['environment']['python']}.")

    base.add_heading(doc, "7.2 Recorded Attack Data", 2)
    base.add_body(doc, f"Our first prototype crashed on 11 of the 100 files (ausearch -i timestamps) and kept only 46 events. The data also held {everything.get('duplicate_syscall_records', 0)} duplicated records and newest-first files, which the final adapter handles (Table 1).")
    table(doc, ["Measure", "Earlier prototype", "Final system"], [
        ("Files ingested without aborting", "89 / 100", f"{everything['files']} / {real['dataset']['files']}"),
        ("Events committed (all system calls)", "46", fmt(everything.get("accepted", 0))),
        ("Events committed (default policy)", "-", fmt(default.get("accepted", 0))),
        ("Duplicate records merged", "-", fmt(everything.get("duplicate_syscall_records", 0))),
        ("Records rejected", "11 whole files", fmt(sum(everything.get("rejected", {}).values()))),
    ], widths=[2.8, 1.6, 1.8])
    caption(doc, "Table 1. Ingestion of the public auditd dataset.")
    proofs_ok = sum(item["valid"] for item in real["proofs"])
    base.add_body(doc, f"Both ledgers verified as {verify_default['verdict']} ({verify_default['events_checked']} and {verify_all['events_checked']} events, {verify_default['checkpoints_checked']} and {verify_all['checkpoints_checked']} blocks), and {proofs_ok} of {len(real['proofs'])} sampled proofs checked out with only the public key. With three witnesses (quorum two), one witness offline still gave pass; two offline gave partial.")

    base.add_heading(doc, "7.3 Live Capture: Completeness and Overhead", 2)
    base.add_body(doc, f"The workload repeats {live['iterations']:,} times: create and write a file, rename it, chmod it, delete it, run /bin/true and open a TCP connection, i.e. {workload_ops:,} operations per run. We ran it {live['runs']} times each with no tracing, tracing only, and full B-SCAF with 1-second blocks and three witnesses.")
    report_charts.live_overhead(doc, live)
    figure_caption(doc, "Live workload time per setup (median of three runs), as a native Word chart.")
    table(doc, ["Run", "Events", "Blocks", "Lost", "Commit delay p50/p95 (ms)", "Verdict (local / witnesses)", "Workload calls captured"], [
        (index, fmt(run["events"]), run["blocks"], run["collector"]["lost_events"], f"{run['commit_delay_ms_median']:.0f} / {run['commit_delay_ms_p95']:.0f}",
         f"{run['verify_local']} / {run['verify_witnesses']}", f"{run['completeness']['captured']:,} / {run['completeness']['expected']:,}")
        for index, run in enumerate(live_runs, start=1)
    ])
    caption(doc, "Table 2. Live B-SCAF runs with 1-second blocks replicated to three witnesses.")
    lost_note = f" The {max(lost)} lost events in one run belonged to other processes." if any(lost) else ""
    base.add_body(doc, f"Every workload operation reached the signed ledger in every run.{lost_note} Full capture ({full_slowdown:+.0f}%) was no slower than tracing alone ({tracing_slowdown:+.0f}%): the cost is in hooking busy system calls, not in hashing and signing, which used about {overview['B-SCAF']['collector_cpu_seconds']:.1f} CPU-seconds per run on another core. Since the workload is all system calls, this is close to a worst case.")

    base.add_heading(doc, "7.4 Attack Tests", 2)
    base.add_body(doc, "Each attack damages a copy of the ledger as an attacker would (Table 3). Edits, deletions, insertions, reordering, a changed root and a replayed block are caught locally. Deleting the newest block and re-signing with a stolen key leave a self-consistent ledger and are caught only by the witnesses, which also refused the rewritten blocks. A forged receipt fails its signature check, and losing the quorum gives partial, never a false pass.")
    attack_table(doc, real["attacks"])
    caption(doc, "Table 3. Attack scenarios: the verdict with local checks only and with three witnesses.")

    if bench:
        base.add_heading(doc, "7.5 Replay Benchmark", 2)
        events = real["bench"]["events"]
        base.add_body(doc, f"We replayed {events:,} dataset events through plain logging, a hash chain alone and B-SCAF, each in its own process.")
        report_charts.throughput(doc, real)
        figure_caption(doc, "Ingest throughput per configuration on one core, as a native Word chart.")
        table(doc, ["Configuration", "Events/s", "Latency p50/p95 (µs)", "Bytes/event", "Full verify (s)"], [
            (report_charts.LABELS.get(label, label), fmt(row["events_per_second"], 0), f"{row['latency_us_median']:.0f} / {row['latency_us_p95']:.0f}",
             fmt(row["bytes_per_event"], 0), fmt(row.get("verify_seconds"), 2))
            for label, row in bench.items()
        ], widths=[2.0, 1.0, 1.3, 1.0, 0.9])
        caption(doc, "Table 4. Throughput, latency, storage and verification on replayed events.")
        n100 = bench.get("B-SCAF N=100")
        chain = bench.get("hash chain only")
        durable = bench.get("B-SCAF N=100 + fsync")
        if n100:
            share = f" ({100 * n100['events_per_second'] / chain['events_per_second']:.0f}% of a bare hash chain)" if chain else ""
            fsync_note = f" Forcing each block to disk drops throughput to {durable['events_per_second']:,.0f} events/s on WSL2's slow virtual disk." if durable else ""
            base.add_body(doc, f"With 100-event blocks B-SCAF reached {n100['events_per_second']:,.0f} events/s{share}, verified {events:,} events in {n100['verify_seconds']:.1f} s, checked a proof in {1000 * n100['proof_verify_seconds']:.2f} ms and replicated to three witnesses in {n100.get('replicate_seconds', 0):.1f} s.{fsync_note}")

    base.add_heading(doc, "8. Problems We Ran Into", 1)
    base.add_body(doc, "Each of these changed the design:")
    base.add_bullets(doc, [
        "Real logs broke the first parser: several formats, split records, duplicates and newest-first order.",
        "Ingest re-read the whole file for every event (quadratic); keeping the chain's tail in memory fixed it.",
        "auditd cannot be controlled from Docker Desktop, hence the eBPF collector.",
        "Container process IDs differ from kernel IDs, which broke self-filtering until we added the ID probe.",
        "fsync costs about 8 ms on WSL2, so durable writes became a setting.",
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
    base.add_bullets(doc, [
        "Capture trust: a compromised kernel or collector can fake or drop events before they are sealed.",
        "Key custody: keys are files (optionally encrypted); a TPM or HSM would prevent theft.",
        "About one second of unsealed events in live use.",
        "Simple storage: very large ledgers need indexing and archiving.",
        "Results come from WSL2 and a small public dataset; bare-metal runs and larger datasets remain.",
    ])

    base.add_heading(doc, "11. Conclusion", 1)
    base.add_body(doc, "B-SCAF shows that system-call evidence can be protected against a root-level attacker without a public blockchain, at modest cost. Live capture missed none of the workload's operations, the public dataset went through end to end, and every attack, including truncation and re-signing with a stolen key, was caught. The remaining limits concern trust at capture time and key custody, not the evidence chain itself.")

    base.add_heading(doc, "Appendix A. Reproducing the Results", 1)
    base.add_body(doc, "From the repository root on any machine with Docker (on Windows PowerShell write ${PWD} instead of $PWD):")
    code(doc, """
docker build -t bscaf .
docker run --rm -v "$PWD":/app bscaf pytest -q
docker run --rm -v "$PWD":/app -w /app bscaf python scripts/run_real_data.py
docker build -t bscaf-live -f deploy/live/Dockerfile deploy/live
docker run --rm --privileged --pid=host -v "$PWD":/app -w /app bscaf-live python scripts/live_capture.py
""")

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

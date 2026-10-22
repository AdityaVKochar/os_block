from __future__ import annotations

from pathlib import Path
import re

from PIL import Image, ImageDraw, ImageFont
from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor


DOCUMENTS_DIR = Path(__file__).resolve().parents[1]
SOURCE = DOCUMENTS_DIR / "Blockchain_System_Call_Audit_Framework.txt"
ASSET_DIR = DOCUMENTS_DIR / "assets"
DIAGRAM = ASSET_DIR / "bscaf-architecture.png"
OUTPUT = DOCUMENTS_DIR / "Blockchain_System_Call_Audit_Framework_Formal_Draft.docx"
BLACK = RGBColor(0, 0, 0)


def find_font(size: int, bold: bool = False):
    names = ["timesbd.ttf", "arialbd.ttf"] if bold else ["times.ttf", "arial.ttf"]
    # Windows, a Windows font folder mounted at /fonts (container builds) or WSL's view of it.
    folders = [Path(r"C:\Windows\Fonts"), Path("/fonts"), Path("/mnt/c/Windows/Fonts")]
    candidates = [folder / name for name in names for folder in folders]
    candidates.append(Path("/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf"))
    for candidate in candidates:
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size=size)
    try:  # Pillow 10.1+ ships a scalable default font
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def center_text(draw, box, text, font, spacing=7):
    x1, y1, x2, y2 = box
    max_width = x2 - x1 - 34
    words = text.split()
    lines, current = [], ""
    for word in words:
        trial = f"{current} {word}".strip()
        if draw.textlength(trial, font=font) <= max_width:
            current = trial
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    heights = [draw.textbbox((0, 0), line, font=font)[3] for line in lines]
    total = sum(heights) + spacing * (len(lines) - 1)
    y = y1 + (y2 - y1 - total) / 2
    for line, height in zip(lines, heights):
        width = draw.textlength(line, font=font)
        draw.text((x1 + (x2 - x1 - width) / 2, y), line, fill="black", font=font)
        y += height + spacing


def arrow(draw, start, end, width=5):
    draw.line([start, end], fill="black", width=width)
    x2, y2 = end
    x1, y1 = start
    if abs(x2 - x1) >= abs(y2 - y1):
        direction = 1 if x2 > x1 else -1
        points = [(x2, y2), (x2 - 18 * direction, y2 - 12), (x2 - 18 * direction, y2 + 12)]
    else:
        direction = 1 if y2 > y1 else -1
        points = [(x2, y2), (x2 - 12, y2 - 18 * direction), (x2 + 12, y2 - 18 * direction)]
    draw.polygon(points, fill="black")


def routed_arrow(draw, points, width=5):
    draw.line(points, fill="black", width=width, joint="curve")
    arrow(draw, points[-2], points[-1], width=width)


def box(draw, coords, text, font, fill="#FFFFFF", radius=18, width=4):
    draw.rounded_rectangle(coords, radius=radius, fill=fill, outline="black", width=width)
    center_text(draw, coords, text, font)


def create_architecture_diagram():
    ASSET_DIR.mkdir(parents=True, exist_ok=True)
    canvas = Image.new("RGB", (2200, 1450), "white")
    draw = ImageDraw.Draw(canvas)
    title_font = find_font(52, bold=True)
    group_font = find_font(32, bold=True)
    box_font = find_font(30, bold=True)
    small_font = find_font(26)

    title = "B-SCAF: Lightweight Permissioned Audit Architecture"
    tw = draw.textlength(title, font=title_font)
    draw.text(((2200 - tw) / 2, 30), title, fill="black", font=title_font)

    groups = [
        ((40, 130, 500, 1250), "1. Event Source", "#F6F6F6"),
        ((550, 130, 1130, 1250), "2. Trusted Processing", "#EEEEEE"),
        ((1180, 130, 1680, 1250), "3. Integrity Ledger", "#F6F6F6"),
        ((1730, 130, 2160, 1250), "4. Independent Audit", "#EEEEEE"),
    ]
    for coords, label, fill in groups:
        draw.rounded_rectangle(coords, radius=25, fill=fill, outline="black", width=3)
        w = draw.textlength(label, font=group_font)
        draw.text((coords[0] + (coords[2] - coords[0] - w) / 2, coords[1] + 18), label, fill="black", font=group_font)

    process = (105, 260, 435, 400)
    syscall = (105, 525, 435, 665)
    collector = (105, 790, 435, 950)
    box(draw, process, "Linux Applications and Processes", box_font)
    box(draw, syscall, "Security-Relevant System Calls", box_font)
    box(draw, collector, "auditd / eBPF / JSONL Collector", box_font)
    arrow(draw, (270, 400), (270, 525))
    arrow(draw, (270, 665), (270, 790))

    policy = (625, 225, 1055, 365)
    normalize = (625, 475, 1055, 615)
    hashchain = (625, 725, 1055, 885)
    eventstore = (625, 1000, 1055, 1150)
    box(draw, policy, "Allow-List and Sensitive-Field Redaction", box_font)
    box(draw, normalize, "Canonical Event Normalization", box_font)
    box(draw, hashchain, "SHA-256 Event Hash Chain", box_font)
    box(draw, eventstore, "Append-Only Raw Event Store", box_font)
    arrow(draw, (840, 365), (840, 475))
    arrow(draw, (840, 615), (840, 725))
    arrow(draw, (840, 885), (840, 1000))
    routed_arrow(draw, [(435, 870), (520, 870), (520, 295), (625, 295)])

    merkle = (1230, 250, 1630, 390)
    checkpoint = (1230, 535, 1630, 710)
    signer = (1230, 870, 1430, 1025)
    ledger = (1460, 870, 1630, 1025)
    box(draw, merkle, "Merkle Batch Builder", box_font)
    box(draw, checkpoint, "Checkpoint Block\nRoot + Previous Block Hash", box_font)
    box(draw, signer, "Ed25519\nSigner", box_font)
    box(draw, ledger, "Checkpoint\nLedger", box_font)
    routed_arrow(draw, [(1055, 805), (1155, 805), (1155, 320), (1230, 320)])
    arrow(draw, (1430, 390), (1430, 535))
    arrow(draw, (1330, 870), (1375, 710))
    arrow(draw, (1515, 710), (1545, 870))

    witness = (1780, 235, 2110, 390)
    proof = (1780, 535, 2110, 690)
    verifier = (1780, 900, 2110, 1060)
    box(draw, witness, "Permissioned Remote Witness", box_font)
    box(draw, proof, "Offline Merkle Proof Verifier", box_font)
    box(draw, verifier, "Full Local Integrity Verifier", box_font)
    arrow(draw, (1630, 610), (1780, 610))
    routed_arrow(draw, [(1630, 945), (1705, 945), (1705, 315), (1780, 315)])
    arrow(draw, (1630, 960), (1780, 980))
    routed_arrow(draw, [(1055, 1075), (1695, 1075), (1695, 1015), (1780, 1015)])

    note = "Raw events remain local. Only signed checkpoint metadata is replicated to the witness."
    nw = draw.textlength(note, font=small_font)
    draw.text(((2200 - nw) / 2, 1325), note, fill="black", font=small_font)
    canvas.save(DIAGRAM, dpi=(220, 220))


def set_font(run, size=None, bold=None, italic=None):
    run.font.name = "Times New Roman"
    run._element.get_or_add_rPr().rFonts.set(qn("w:ascii"), "Times New Roman")
    run._element.get_or_add_rPr().rFonts.set(qn("w:hAnsi"), "Times New Roman")
    run._element.get_or_add_rPr().rFonts.set(qn("w:eastAsia"), "Times New Roman")
    run.font.color.rgb = BLACK
    if size is not None:
        run.font.size = Pt(size)
    if bold is not None:
        run.bold = bold
    if italic is not None:
        run.italic = italic


def hyperlink(paragraph, text, url, size=10):
    rel_id = paragraph.part.relate_to(url, "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink", is_external=True)
    link = OxmlElement("w:hyperlink")
    link.set(qn("r:id"), rel_id)
    run = OxmlElement("w:r")
    props = OxmlElement("w:rPr")
    fonts = OxmlElement("w:rFonts")
    fonts.set(qn("w:ascii"), "Times New Roman")
    fonts.set(qn("w:hAnsi"), "Times New Roman")
    props.append(fonts)
    color = OxmlElement("w:color")
    color.set(qn("w:val"), "000000")
    props.append(color)
    underline = OxmlElement("w:u")
    underline.set(qn("w:val"), "single")
    props.append(underline)
    sz = OxmlElement("w:sz")
    sz.set(qn("w:val"), str(size * 2))
    props.append(sz)
    run.append(props)
    text_node = OxmlElement("w:t")
    text_node.text = text
    run.append(text_node)
    link.append(run)
    paragraph._p.append(link)


def configure_document(doc):
    section = doc.sections[0]
    section.page_height = Inches(11.69)
    section.page_width = Inches(8.27)
    section.top_margin = Inches(0.85)
    section.bottom_margin = Inches(0.85)
    section.left_margin = Inches(1.0)
    section.right_margin = Inches(1.0)

    normal = doc.styles["Normal"]
    normal.font.name = "Times New Roman"
    normal._element.rPr.rFonts.set(qn("w:ascii"), "Times New Roman")
    normal._element.rPr.rFonts.set(qn("w:hAnsi"), "Times New Roman")
    normal.font.size = Pt(11)
    normal.font.color.rgb = BLACK
    normal.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    normal.paragraph_format.line_spacing = 1.15
    normal.paragraph_format.space_after = Pt(6)

    for name, size, before, after in [("Heading 1", 14, 14, 7), ("Heading 2", 12, 10, 5), ("Heading 3", 11, 8, 4)]:
        style = doc.styles[name]
        style.font.name = "Times New Roman"
        style._element.rPr.rFonts.set(qn("w:ascii"), "Times New Roman")
        style._element.rPr.rFonts.set(qn("w:hAnsi"), "Times New Roman")
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = BLACK
        style.paragraph_format.space_before = Pt(before)
        style.paragraph_format.space_after = Pt(after)
        style.paragraph_format.keep_with_next = True

    for name in ("List Bullet", "List Number"):
        style = doc.styles[name]
        style.font.name = "Times New Roman"
        style._element.rPr.rFonts.set(qn("w:ascii"), "Times New Roman")
        style._element.rPr.rFonts.set(qn("w:hAnsi"), "Times New Roman")
        style.font.size = Pt(11)
        style.font.color.rgb = BLACK
        style.paragraph_format.space_after = Pt(3)

    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = footer.add_run("Page ")
    set_font(r, 9)
    field = OxmlElement("w:fldSimple")
    field.set(qn("w:instr"), "PAGE")
    footer._p.append(field)


def add_heading(doc, text, level=1):
    p = doc.add_paragraph(style=f"Heading {level}")
    r = p.add_run(text)
    set_font(r, 14 if level == 1 else 12 if level == 2 else 11, bold=True)
    return p


def add_body(doc, text, bold_lead=None):
    p = doc.add_paragraph()
    if bold_lead and text.startswith(bold_lead):
        r = p.add_run(bold_lead)
        set_font(r, 11, bold=True)
        r = p.add_run(text[len(bold_lead):])
        set_font(r, 11)
    else:
        r = p.add_run(text)
        set_font(r, 11)
    return p


def add_bullets(doc, items):
    for item in items:
        p = doc.add_paragraph(style="List Bullet")
        r = p.add_run(item)
        set_font(r, 11)


def set_cell_text(cell, text, bold=False):
    cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
    p = cell.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p.paragraph_format.space_after = Pt(0)
    r = p.add_run(text)
    set_font(r, 9.5, bold=bold)


def shade_cell(cell, fill):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)


def add_component_table(doc):
    rows = [
        ("Collection layer", "auditd, eBPF, or JSONL adapter", "Captures selected system-call activity and process context."),
        ("Privacy layer", "Allow-list and redactor", "Drops unrelated calls and removes sensitive argument values before persistence."),
        ("Event integrity layer", "Canonical serialization and SHA-256 hash chain", "Detects changed, deleted, inserted, or reordered event records."),
        ("Batch integrity layer", "Merkle tree", "Commits many events with one compact root and supports per-event proofs."),
        ("Checkpoint ledger", "Previous-block hash and Ed25519 signature", "Creates a lightweight permissioned blockchain without mining or cryptocurrency."),
        ("Independent witness", "Trusted HTTP witness node", "Retains signed checkpoint metadata outside the audited host."),
        ("Verification layer", "Full-chain and offline proof verifier", "Produces a clear integrity result for investigators and auditors."),
    ]
    table = doc.add_table(rows=1, cols=3)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = "Table Grid"
    headers = ["Layer", "Implementation", "Purpose"]
    for idx, text in enumerate(headers):
        set_cell_text(table.rows[0].cells[idx], text, bold=True)
        shade_cell(table.rows[0].cells[idx], "E7E7E7")
    for row in rows:
        cells = table.add_row().cells
        for idx, text in enumerate(row):
            set_cell_text(cells[idx], text)
    return table


def extract_references():
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    references = []
    capture = False
    for line in lines:
        if line.startswith("1. Ali, A."):
            capture = True
        if capture and re.match(r"^(?:[1-9]|[1-3][0-9]|40)\. ", line):
            references.append(line.strip())
        if line.startswith("40. Secinaro"):
            break
    return references


def add_reference(doc, reference):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.22)
    p.paragraph_format.first_line_indent = Inches(-0.22)
    p.paragraph_format.line_spacing = 1.0
    p.paragraph_format.space_after = Pt(4)
    match = re.search(r"(https://doi\.org/\S+)$", reference)
    if match:
        r = p.add_run(reference[:match.start()])
        set_font(r, 9.5)
        hyperlink(p, match.group(1), match.group(1), 9)
    else:
        r = p.add_run(reference)
        set_font(r, 9.5)


def build_document():
    create_architecture_diagram()
    doc = Document()
    configure_document(doc)

    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(110)
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run("BLOCKCHAIN-BASED SYSTEM CALL\nAUDIT FRAMEWORK")
    set_font(r, 20, bold=True)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(10)
    r = p.add_run("Immutable Audit Logs Using Lightweight Blockchain Principles")
    set_font(r, 14, bold=True)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(42)
    r = p.add_run("Formal Project Draft")
    set_font(r, 12, italic=True)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(160)
    r = p.add_run("Operating Systems and Cybersecurity Project")
    set_font(r, 11)
    p.add_run().add_break(WD_BREAK.PAGE)

    add_heading(doc, "Abstract", 1)
    add_body(doc, "Operating-system audit logs are essential for incident response, accountability, and digital forensics, yet conventional logs can be altered or deleted by malware or a privileged insider. This project proposes B-SCAF, a lightweight permissioned audit framework that protects Linux system-call evidence using deterministic event normalization, SHA-256 hash chaining, Merkle-tree batching, Ed25519-signed checkpoint blocks, and optional replication to trusted witness nodes. Detailed system-call records remain in a protected local store, while only compact integrity commitments are placed in the checkpoint ledger. This design avoids the cost, latency, and privacy problems of writing every event to a public blockchain. The framework provides full-ledger verification and portable proofs for individual events. The project is evaluated through controlled tampering experiments and measurements of throughput, latency, processor usage, storage growth, and verification time.")
    add_body(doc, "Keywords: system-call auditing; tamper-evident logging; lightweight blockchain; Merkle tree; hash chain; Ed25519; digital forensics.", bold_lead="Keywords:")

    add_heading(doc, "1. Introduction", 1)
    add_body(doc, "An operating system continuously mediates access to files, processes, credentials, and network resources. These actions cross the kernel boundary through system calls such as execve, openat, connect, unlinkat, chmod, setuid, and ptrace. A reliable record of these calls can reconstruct an intrusion and explain what a compromised process attempted to do.")
    add_body(doc, "Traditional audit files are commonly retained on the same host that generates them. If an attacker gains administrative privileges, the attacker may edit, remove, reorder, or replace the records needed for an investigation. Centralized logging improves availability but still creates a powerful trusted administrator and a single high-value target. A public blockchain is also unsuitable for raw system-call events because the volume is high, confirmation introduces delay, and event arguments may disclose sensitive paths, credentials, or user information.")
    add_body(doc, "B-SCAF addresses this tension with blockchain principles rather than a cryptocurrency network. Events are normalized and hash-linked locally, grouped into Merkle batches, and represented by digitally signed checkpoint blocks. Known witness nodes can retain these compact checkpoints, giving an auditor an external point of comparison without copying the raw audit stream.")

    add_heading(doc, "2. Design Ideology", 1)
    add_bullets(doc, [
        "Evidence should remain verifiable even when the machine that created it is later compromised.",
        "Integrity must be independently testable by recomputing hashes, Merkle roots, block links, and signatures.",
        "Raw system-call content should remain off-chain to preserve searchability, performance, and privacy.",
        "The design should avoid mining, cryptocurrency, gas fees, and public-network dependencies.",
        "Security claims must be supported by measurable overhead and controlled tampering tests.",
    ])

    add_heading(doc, "3. Problem Statement", 1)
    add_body(doc, "Privileged attackers, malicious administrators, or malware with elevated permissions can modify or destroy local system-call audit records. A centralized repository may still permit one trusted party to rewrite evidence, while a conventional blockchain cannot efficiently store the full volume of host telemetry. The problem is therefore to design a Linux audit mechanism that makes post-commit tampering detectable, permits independent verification, protects sensitive event content, and imposes only modest overhead on normal workloads.")

    add_heading(doc, "4. Research Gap", 1)
    add_body(doc, "Recent blockchain logging research has established the usefulness of immutable audit trails, but many systems concentrate on cloud operations, healthcare access, IoT telemetry, or enterprise transactions. System-call security research commonly uses call sequences for intrusion detection without protecting those sequences as durable forensic evidence. The remaining gap is an integrated host-level pipeline that combines fine-grained system-call collection, privacy-aware normalization, tamper-evident storage, compact signed commitments, independent witnessing, and practical verification.")

    add_heading(doc, "5. Novelty and Contribution", 1)
    add_bullets(doc, [
        "A kernel-to-proof pipeline that converts selected Linux system calls into deterministic, verifiable event records.",
        "Dual-level integrity using an event hash chain for order and a Merkle tree for efficient batch commitments and inclusion proofs.",
        "A permissioned witness design that stores signed checkpoint metadata without receiving sensitive raw events.",
        "Policy-based minimization that filters unrelated calls and redacts sensitive arguments before hashing and persistence.",
        "Failure-aware verification that distinguishes altered events, broken chain links, missing batches, changed Merkle roots, and invalid signatures.",
    ])
    add_body(doc, "The contribution is a practical integration of established cryptographic mechanisms for host auditing. It does not claim to invent hashing, Merkle trees, digital signatures, or distributed ledgers.")

    add_heading(doc, "6. Project Objectives", 1)
    add_bullets(doc, [
        "Capture configurable security-relevant Linux system calls with process, user, timestamp, result, and selected argument context.",
        "Construct a lightweight immutable evidence chain using canonical serialization, SHA-256, Merkle batching, and signed checkpoint blocks.",
        "Provide complete-ledger verification and portable proof verification for an individual committed event.",
        "Replicate checkpoint metadata to trusted witness nodes while keeping raw system-call data local.",
        "Measure ingestion throughput, commit latency, CPU and memory overhead, storage growth, and verification time under normal and adversarial tests.",
    ])

    add_heading(doc, "7. Methodology", 1)
    add_heading(doc, "7.1 Threat and Requirement Definition", 2)
    add_body(doc, "The prototype assumes that an attacker may obtain permission to modify locally stored audit files after events have been captured. The required properties are integrity, ordering, origin authentication, availability of commitments, privacy of raw event fields, and reproducible verification. A fully compromised kernel may fabricate or suppress an event before collection; this limitation is stated explicitly rather than hidden by the blockchain design.")
    add_heading(doc, "7.2 Collection and Normalization", 2)
    add_body(doc, "Linux auditd records, eBPF events, or newline-delimited JSON are converted to a common schema containing sequence number, UTC timestamp, host identifier, PID, parent PID, UID, system-call name, process path, selected arguments, return code, previous event hash, and current event hash. An allow-list and redaction policy is applied before the record is committed.")
    add_heading(doc, "7.3 Integrity Construction", 2)
    add_body(doc, "For event i, B-SCAF hashes the canonical event together with the previous event hash. Events are grouped by count or time interval, and their hashes become leaves of a binary Merkle tree. Odd leaf counts are handled by duplicating the final leaf. The Merkle root commits the entire batch while permitting a compact path proof for any one event.")
    add_heading(doc, "7.4 Permissioned Checkpointing", 2)
    add_body(doc, "Each block records a block number, previous block hash, batch identifier, Merkle root, first and last sequence, event count, host identity, timestamp, and signer identity. An Ed25519 signature authenticates the block. This is a private, application-specific permissioned blockchain: known entities participate, and there is no proof-of-work, cryptocurrency, or public consensus network.")
    add_heading(doc, "7.5 Verification and Evaluation", 2)
    add_body(doc, "The verifier recalculates event hashes, chain links, batch roots, block hashes, and signatures. Experiments modify, delete, insert, and reorder stored events; modify checkpoint fields; replay a checkpoint; and make a witness unavailable. Performance is compared with plain local logging and hash-chain-only logging using median and p95 latency, events per second, CPU utilization, memory use, storage per event, and proof-verification time.")

    add_heading(doc, "8. Proposed Architecture", 1)
    add_body(doc, "Figure 1 presents the end-to-end design. Trust is deliberately separated: the audited host stores detailed evidence and constructs signed commitments, while an independent witness retains only the resulting checkpoint metadata. An investigator can therefore compare a local ledger with a commitment that was observed outside the host.")
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.keep_with_next = True
    p.add_run().add_picture(str(DIAGRAM), width=Inches(6.25))
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(8)
    r = p.add_run("Figure 1. B-SCAF collection, integrity, checkpointing, and independent-verification architecture.")
    set_font(r, 10, italic=True)
    add_component_table(doc)

    add_heading(doc, "8.1 Event and Block Flow", 2)
    add_body(doc, "A process generates a system call, the collector records it, and the policy layer removes unrelated or sensitive content. Canonical normalization ensures that the same event always produces the same bytes. The event is chained to its predecessor and written to the event store. At the batch boundary, a Merkle root is created and included in a block linked to the previous checkpoint. After signing, the block is retained locally and may be replicated to one or more trusted witnesses.")
    add_heading(doc, "8.2 Proposed Checkpoint Fields", 2)
    add_body(doc, "block_number | previous_block_hash | batch_id | merkle_root | host_id | first_sequence | last_sequence | event_count | created_at | signer_id | signature")
    add_heading(doc, "8.3 Verification Paths", 2)
    add_bullets(doc, [
        "Full verification: recompute the complete event chain, every Merkle root, every block link, and every signature.",
        "Single-event verification: export the event, Merkle sibling path, signed checkpoint, and trusted public key for offline checking.",
        "Witness comparison: confirm that a locally presented checkpoint matches the independently retained signed block.",
    ])

    add_heading(doc, "9. Security Analysis", 1)
    add_body(doc, "Changing an event alters its calculated hash and the corresponding Merkle root. Deleting, inserting, or reordering an event breaks sequence or previous-hash continuity. Changing a checkpoint invalidates its block hash and Ed25519 signature. Rewriting a sequence of local checkpoint files remains detectable when an earlier signed block has already been replicated to a trusted witness.")
    add_body(doc, "The design is tamper-evident rather than tamper-proof. It does not stop an attacker from attempting to edit files; it makes an inconsistency discoverable. It also does not solve pre-capture falsification by a compromised kernel, denial of service against every replica, private-key theft, or confidential-data leakage caused by an incorrectly configured collection policy.")

    add_heading(doc, "10. Expected Outcomes and Evaluation Criteria", 1)
    add_bullets(doc, [
        "A Linux-capable prototype that accepts auditd/JSONL events and creates signed checkpoint batches.",
        "Detection of every controlled post-commit event modification, deletion, insertion, and reordering test.",
        "Successful offline verification of an individual event with its Merkle proof and trusted public key.",
        "Successful acceptance of valid checkpoints and rejection of changed or unknown-signer checkpoints by a witness node.",
        "A reproducible performance report covering throughput, latency, resource use, storage cost, and verification time.",
    ])

    add_heading(doc, "11. Literature Review", 1)
    add_body(doc, "The literature can be organized into three related streams. First, blockchain-backed logging systems demonstrate that audit integrity can be protected through signed, linked, and replicated commitments. BCALS, BlockTrail, RootLogChain, BlockAudit 2.0, and recent secure log-storage frameworks also expose the central engineering trade-off: greater decentralization can increase storage and processing cost. This motivates the project's compact checkpoint approach.")
    add_body(doc, "Second, domain-specific work in healthcare, genomics, IoT, and enterprise auditing shows the value of separating detailed data from integrity evidence. These systems support the decision to retain raw records off-chain and place hashes or roots in a permissioned ledger.")
    add_body(doc, "Third, host-intrusion research confirms that system-call sequences are meaningful security signals. Modern sequence models, provenance-based detection, and risk-based grouping can identify anomalous behavior, but detection accuracy does not guarantee that the input evidence remains trustworthy after collection. B-SCAF treats integrity as a foundation on which later detection models may operate.")
    add_body(doc, "Across these streams, the consistent gaps are efficient fine-grained verification, privacy-aware host integration, and evidence that remains useful after privileged compromise. The proposed architecture combines these concerns without claiming that a blockchain alone solves endpoint trust.")

    add_heading(doc, "12. Limitations and Future Work", 1)
    add_bullets(doc, [
        "The present adapter parses common x86_64 auditd system-call identifiers; additional architectures require expanded mappings.",
        "A production collector should use eBPF or auditd streaming rather than file-based import.",
        "Private keys should be protected by a TPM or HSM, and witness communication should use mutually authenticated TLS.",
        "A multi-witness quorum policy, durable rotation, role-based access control, and searchable dashboard remain deployment work.",
        "Remote attestation can reduce, but not completely eliminate, the trust placed in the capture host.",
    ])

    add_heading(doc, "13. Conclusion", 1)
    add_body(doc, "B-SCAF offers a realistic middle ground between mutable local logs and an impractical public blockchain. Its hash chain preserves event order, its Merkle roots make batch commitments efficient, its Ed25519 signatures authenticate checkpoint origin, and its permissioned witness provides an external integrity reference. The design is suitable for Linux deployment and supports credible evaluation because its guarantees and limitations are explicit and testable.")

    add_heading(doc, "References", 1)
    for reference in extract_references():
        add_reference(doc, reference)

    doc.core_properties.title = "Blockchain-Based System Call Audit Framework"
    doc.core_properties.subject = "Formal project draft with architecture"
    doc.core_properties.author = ""
    doc.core_properties.keywords = "system calls, audit logs, blockchain, Merkle tree, Ed25519"
    doc.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    build_document()

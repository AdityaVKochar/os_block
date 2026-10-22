"""Project diagrams for the final report and the guide.

Every diagram uses the same stage colours as the architecture figure, so a
reader can tell at a glance which part of the system a box belongs to:
collection (blue), evidence construction (green), signed ledger (orange),
witnesses (violet), verification (rose) and environment (grey). Text stays
black for legibility, and verdict boxes carry their word (PASS, PARTIAL,
FAIL) as well as a status colour, so colour is never the only cue.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

import build_formal_draft as base

WHITE = "#FFFFFF"
# stage: (accent for outlines, light tint for backgrounds, dark ink for headings)
STAGES = {
    "collect": ("#2a78d6", "#e6effb", "#1c5cab"),
    "evidence": ("#14895f", "#e2f4ec", "#0d6b4a"),
    "ledger": ("#d0551f", "#fdeadf", "#a3410f"),
    "witness": ("#5b49cf", "#ebe8fb", "#4433a8"),
    "verify": ("#c2416f", "#fbe8ef", "#9a2f56"),
    "neutral": ("#7a7974", "#f3f3f1", "#333333"),
}
STATUS = {
    "pass": ("#0ca30c", "#e1f5e1"),
    "partial": ("#c98500", "#fdf1d6"),
    "fail": ("#d03b3b", "#fde3e3"),
}


def _canvas(width: int, height: int, title: str):
    canvas = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(canvas)
    font = base.find_font(46, bold=True)
    draw.text(((width - draw.textlength(title, font=font)) / 2, 26), title, fill="black", font=font)
    return canvas, draw


def _label(draw, xy, text, size=24, bold=False, anchor="la", color="black"):
    draw.text(xy, text, fill=color, font=base.find_font(size, bold=bold), anchor=anchor)


def group(draw, coords, label, stage="neutral", fill=None, centered=False):
    """A tinted region with a heading in the stage's dark ink."""
    accent, tint, ink = STAGES[stage]
    draw.rounded_rectangle(coords, radius=22, fill=fill or tint, outline=accent, width=4)
    font = base.find_font(28, bold=True)
    x = coords[0] + (coords[2] - coords[0] - draw.textlength(label, font=font)) / 2 if centered else coords[0] + 22
    draw.text((x, coords[1] + 14), label, fill=ink, font=font)


def box(draw, coords, text, font, stage="neutral", fill=WHITE, radius=16, width=4):
    """A rounded box outlined in the stage colour, with centred black text."""
    draw.rounded_rectangle(coords, radius=radius, fill=fill, outline=STAGES[stage][0], width=width)
    base.center_text(draw, coords, text, font)


def status_box(draw, coords, text, font, status):
    accent, tint = STATUS[status]
    draw.rounded_rectangle(coords, radius=16, fill=tint, outline=accent, width=5)
    base.center_text(draw, coords, text, font)


def _diamond(draw, center, half_w, half_h, text, font, stage="neutral"):
    x, y = center
    draw.polygon([(x, y - half_h), (x + half_w, y), (x, y + half_h), (x - half_w, y)], fill=WHITE, outline=STAGES[stage][0], width=4)
    base.center_text(draw, (x - half_w + 40, y - half_h + 20, x + half_w - 40, y + half_h - 20), text, font, spacing=4)


def _dashed(draw, start, end, dash=14, gap=10, width=3, color="black"):
    (x1, y1), (x2, y2) = start, end
    length = max(abs(x2 - x1), abs(y2 - y1))
    steps = int(length // (dash + gap)) + 1
    for index in range(steps):
        a = index * (dash + gap) / length
        b = min(1.0, (index * (dash + gap) + dash) / length)
        draw.line([(x1 + (x2 - x1) * a, y1 + (y2 - y1) * a), (x1 + (x2 - x1) * b, y1 + (y2 - y1) * b)], fill=color, width=width)


# ------------------------------------------------------------- evidence structure

def evidence_structure(out: Path) -> Path:
    canvas, draw = _canvas(2400, 1560, "Evidence Structure: Hash Chain, Merkle Batch and Signed Blocks")
    box_font = base.find_font(25, bold=True)
    small = base.find_font(23)

    group(draw, (40, 110, 2360, 470), "Event hash chain (events.jsonl)", "evidence")
    xs = [110, 650, 1190, 1730]
    for index, x in enumerate(xs, start=1):
        draw.rounded_rectangle((x, 190, x + 470, 420), radius=16, fill=WHITE, outline=STAGES["evidence"][0], width=4)
        _label(draw, (x + 235, 215), f"Event {index}", 27, True, "ma")
        _label(draw, (x + 235, 262), "syscall, pid, ppid, uid, time,", 22, False, "ma")
        _label(draw, (x + 235, 294), "process, arguments, return", 22, False, "ma")
        _label(draw, (x + 235, 350), f"h{index} = SHA-256(event{index} || h{index - 1})", 22, True, "ma")
        if index < 4:
            base.arrow(draw, (x + 470, 305), (xs[index], 305))
    _label(draw, (110, 432), "h0 = genesis (64 zeros). Changing, deleting, inserting or reordering any event breaks every later link.", 22)

    group(draw, (40, 510, 1180, 1000), "Merkle batch (one block = N events)", "ledger")
    leaves = [(110, 860), (370, 860), (630, 860), (890, 860)]
    for index, (x, y) in enumerate(leaves, start=1):
        box(draw, (x, y, x + 200, y + 90), f"h{index}", box_font, "evidence")
    box(draw, (240, 720, 440, 810), "H(h1||h2)", small, "ledger")
    box(draw, (760, 720, 960, 810), "H(h3||h4)", small, "ledger")
    box(draw, (470, 580, 730, 670), "Merkle root", box_font, "ledger", fill=STAGES["ledger"][1])
    for x in (210, 470):
        base.arrow(draw, (x, 860), (340, 810))
    for x in (730, 990):
        base.arrow(draw, (x, 860), (860, 810))
    base.arrow(draw, (340, 720), (560, 670))
    base.arrow(draw, (860, 720), (640, 670))
    _label(draw, (90, 960), "Proof for event 3: h4 + H(h1||h2), checked against the signed root.", 22)

    group(draw, (1220, 510, 2360, 1000), "Signed checkpoint chain (checkpoints.jsonl)", "ledger")
    blocks = [(1260, "Block k-1"), (1640, "Block k"), (2020, "Block k+1")]
    for x, name in blocks:
        draw.rounded_rectangle((x, 600, x + 320, 940), radius=16, fill=WHITE, outline=STAGES["ledger"][0], width=4)
        _label(draw, (x + 160, 618), name, 27, True, "ma")
        for row, text in enumerate(["previous_block_hash", "merkle_root", "first..last sequence", "time window", "policy_version", "Ed25519 signature"]):
            _label(draw, (x + 24, 672 + row * 42), text, 21)
    for (x, _), (nx, _) in zip(blocks, blocks[1:]):
        base.routed_arrow(draw, [(nx, 690), (x + 320, 690)])
    base.routed_arrow(draw, [(730, 625), (1110, 625), (1110, 1035), (1600, 1035), (1600, 735), (1640, 735)])
    _label(draw, (1130, 1045), "root written into block k", 22)

    group(draw, (40, 1120, 2360, 1460), "Independent copies", "witness")
    for index, x in enumerate((140, 900, 1660)):
        box(draw, (x, 1200, x + 600, 1300), f"Witness {index + 1}: same signed blocks, chain continuity enforced", small, "witness")
        base.arrow(draw, (x + 300, 1300), (x + 300, 1370))
        box(draw, (x + 80, 1370, x + 520, 1440), f"Signed ack from witness {index + 1}", small, "witness")
    # Every signed block is pushed to each witness along one bus.
    draw.line([(1800, 940), (1800, 1095)], fill="black", width=5)
    draw.line([(440, 1095), (1960, 1095)], fill="black", width=5)
    for x in (440, 1200, 1960):
        base.arrow(draw, (x, 1095), (x, 1200))
    _label(draw, (1820, 960), "each signed block", 22)
    canvas.save(out, dpi=(220, 220))
    return out


# ------------------------------------------------------------- witness protocol

def witness_sequence(out: Path) -> Path:
    canvas, draw = _canvas(2400, 1820, "Witness Protocol (sequence)")
    head_font = base.find_font(27, bold=True)
    lanes = {"source": 330, "witness": 1200, "auditor": 2060}
    lane_stage = {"source": "ledger", "witness": "witness", "auditor": "verify"}
    heads = {"source": "Source host (collector + ledger)", "witness": "Witness i of N (HTTPS, mutual TLS)", "auditor": "Auditor / verifier"}
    for key, x in lanes.items():
        box(draw, (x - 260, 110, x + 260, 230), heads[key], head_font, lane_stage[key], fill=STAGES[lane_stage[key]][1])
        _dashed(draw, (x, 230), (x, 1760), color=STAGES[lane_stage[key]][0])

    def message(y, start, end, text, number, reply=False):
        x1, x2 = lanes[start], lanes[end]
        if reply:
            sign = 1 if x2 > x1 else -1
            _dashed(draw, (x1, y), (x2 - 20 * sign, y), dash=18, gap=10, width=4)
            base.arrow(draw, (x2 - 40 * sign, y), (x2, y))
        else:
            base.arrow(draw, (x1, y), (x2, y))
        _label(draw, ((x1 + x2) / 2, y - 40), f"{number}. {text}", 24, False, "ma")

    def self_note(y, lane, text, number, height=70, left=False):
        x = lanes[lane]
        accent, tint, _ = STAGES[lane_stage[lane]]
        x1, x2 = (x - 470, x - 20) if left else (x + 20, x + 470)
        draw.rectangle((x1, y - height / 2, x2, y + height / 2), fill=tint, outline=accent, width=3)
        base.center_text(draw, (x1, y - height / 2, x2, y + height / 2), f"{number}. {text}", base.find_font(22), spacing=3)

    self_note(310, "source", "Close batch, sign block k (Ed25519)", 1)
    message(430, "source", "witness", "POST /checkpoints  (block k, metadata only)", 2)
    self_note(540, "witness", "Trusted signer? Hash and signature valid? Extends held chain?", 3, height=100)
    message(680, "witness", "source", "201 Created + ack signed by the witness key", 4, reply=True)
    self_note(780, "source", "Store ack in witness-acks.jsonl; quorum K of N reached", 5, height=90)

    danger = STATUS["fail"][0]
    draw.rectangle((90, 860, 2310, 1150), outline=danger, width=4)
    attack = "Attack: history rewritten and re-signed with the stolen source key"
    attack_font = base.find_font(24, bold=True)
    draw.rectangle((100, 866, 120 + draw.textlength(attack, font=attack_font), 904), fill="white")
    _label(draw, (110, 872), attack, 24, True, color="#a32a2a")
    message(980, "source", "witness", "POST /checkpoints  (rewritten block j)", 6)
    self_note(1060, "witness", "Different block for number j: refuse, record equivocation", 7, height=90)
    message(1120, "witness", "source", "409 Conflict", 8, reply=True)

    message(1260, "auditor", "witness", "GET /checkpoints?signer=source", 9)
    message(1360, "witness", "auditor", "Witnessed chain (signed blocks)", 10, reply=True)
    self_note(1470, "auditor", "Compare with the local ledger and check ack signatures", 11, height=90, left=True)
    box(draw, (1540, 1560, 2330, 1730), "Verdict: pass, partial (quorum unreachable) or fail (truncation, mismatch, forged ack)", base.find_font(24, bold=True), "verify", fill=STAGES["verify"][1])
    base.arrow(draw, (lanes["auditor"], 1515), (lanes["auditor"], 1560))
    canvas.save(out, dpi=(220, 220))
    return out


# ------------------------------------------------------------- live deployment

def live_deployment(out: Path) -> Path:
    canvas, draw = _canvas(2400, 1500, "Live Capture Deployment (evaluation setup)")
    font = base.find_font(25, bold=True)
    small = base.find_font(22)
    group(draw, (40, 110, 2360, 1440), "Windows host", "neutral", fill=WHITE)
    group(draw, (90, 180, 2310, 1400), "WSL2 virtual machine", "neutral")
    group(draw, (140, 250, 1040, 1060), "Fedora WSL distribution", "neutral", fill=WHITE)
    box(draw, (200, 340, 980, 460), "Project repository (bind-mounted into containers)", font)
    box(draw, (200, 540, 980, 660), "results/LIVE_REPORT.md and live-summary.json", font, "verify")
    box(draw, (200, 740, 980, 860), "Docker CLI (sudo); nothing installed for B-SCAF", small)
    group(draw, (1090, 250, 2260, 1060), "Docker Desktop: privileged container bscaf-live (--pid=host)", "collect")
    box(draw, (1140, 340, 1640, 470), "Workload: files, /bin/true, TCP connect", font)
    box(draw, (1720, 340, 2210, 470), "Witnesses 1-3 (HTTPS)", font, "witness")
    box(draw, (1140, 590, 1640, 720), "bpftrace program (generated)", font, "collect")
    box(draw, (1720, 590, 2210, 720), "bscaf ingest-ebpf: chain, Merkle, sign every 1 s", font, "evidence")
    box(draw, (1720, 840, 2210, 970), "events.jsonl, checkpoints.jsonl, acks", font, "ledger")
    draw.rounded_rectangle((140, 1130, 2260, 1340), radius=20, fill=STAGES["collect"][1], outline=STAGES["collect"][0], width=4)
    _label(draw, (1200, 1160), "Linux kernel 6.18 (shared by every process in the VM)", 30, True, "ma")
    _label(draw, (1200, 1215), "syscall tracepoints: sys_enter_* saves arguments, sys_exit_* emits them with the return code", 24, False, "ma")
    _label(draw, (1200, 1260), "audit control is refused from container PID namespaces; eBPF is not", 24, False, "ma")
    base.routed_arrow(draw, [(1390, 470), (1390, 520), (1080, 520), (1080, 1130)])
    _label(draw, (1100, 1085), "system calls", 22)
    base.arrow(draw, (1300, 1130), (1300, 720))
    _label(draw, (1320, 1000), "perf buffer", 22)
    base.arrow(draw, (1640, 655), (1720, 655))
    _label(draw, (1680, 600), "lines", 22, False, "ma")
    base.arrow(draw, (1965, 720), (1965, 840))
    base.arrow(draw, (1965, 590), (1965, 470))
    _label(draw, (1985, 520), "each block", 22)
    base.routed_arrow(draw, [(1720, 905), (1060, 905), (1060, 600), (980, 600)])
    _label(draw, (1500, 868), "summaries", 22, False, "ma")
    canvas.save(out, dpi=(220, 220))
    return out


# ------------------------------------------------------------- verification flow

def verification_flow(out: Path) -> Path:
    canvas, draw = _canvas(2400, 1900, "Verification Decision Flow")
    font = base.find_font(25, bold=True)
    small = base.find_font(24, bold=True)
    steps = [
        (160, "Recompute every event hash and previous-hash link"),
        (310, "Rebuild each batch Merkle root from the events"),
        (460, "Check block hashes, links, numbers, ranges, replays, Ed25519 signatures"),
    ]
    for y, text in steps:
        box(draw, (650, y, 1450, y + 100), text, font, "verify")
    for (y, _), (ny, _) in zip(steps, steps[1:]):
        base.arrow(draw, (1050, y + 100), (1050, ny))
    _diamond(draw, (1050, 720), 300, 120, "Any local problem?", small, "verify")
    base.arrow(draw, (1050, 560), (1050, 600))
    status_box(draw, (1700, 660, 2250, 780), "FAIL: report the first invalid item", font, "fail")
    base.arrow(draw, (1350, 720), (1700, 720))
    _label(draw, (1520, 680), "yes", 24, True, "ma")
    _diamond(draw, (1050, 990), 300, 120, "Witnesses given?", small, "witness")
    base.arrow(draw, (1050, 840), (1050, 870))
    _label(draw, (1070, 842), "no", 24, True)
    box(draw, (650, 1180, 1450, 1280), "Fetch each witness chain; compare block by block; check ack signatures", font, "witness")
    base.arrow(draw, (1050, 1110), (1050, 1180))
    _label(draw, (1070, 1120), "yes", 24, True)
    _diamond(draw, (1050, 1420), 300, 110, "Truncation, mismatch or forged ack?", small, "witness")
    base.arrow(draw, (1050, 1280), (1050, 1310))
    base.routed_arrow(draw, [(1350, 1420), (1975, 1420), (1975, 780)])
    _label(draw, (1660, 1380), "yes", 24, True, "ma")
    _diamond(draw, (1050, 1680), 300, 110, "Quorum of complete, consistent witnesses?", small, "witness")
    base.arrow(draw, (1050, 1530), (1050, 1570))
    _label(draw, (1070, 1535), "no", 24, True)
    status_box(draw, (1700, 1620, 2250, 1740), "PARTIAL: evidence not independently confirmed", font, "partial")
    base.arrow(draw, (1350, 1680), (1700, 1680))
    _label(draw, (1520, 1640), "no", 24, True, "ma")
    _diamond(draw, (380, 1280), 250, 110, "Uncommitted events?", small, "verify")
    base.routed_arrow(draw, [(750, 990), (380, 990), (380, 1170)])
    _label(draw, (560, 950), "no", 24, True, "ma")
    base.routed_arrow(draw, [(750, 1680), (380, 1680), (380, 1390)])
    _label(draw, (560, 1640), "yes", 24, True, "ma")
    status_box(draw, (30, 1470, 230, 1570), "PARTIAL", font, "partial")
    status_box(draw, (530, 1470, 730, 1570), "PASS", font, "pass")
    base.arrow(draw, (130, 1280), (130, 1470))
    _label(draw, (110, 1350), "yes", 24, True, "ra")
    base.arrow(draw, (630, 1280), (630, 1470))
    _label(draw, (650, 1350), "no", 24, True)
    canvas.save(out, dpi=(220, 220))
    return out


def build_all(out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    return {
        "evidence": evidence_structure(out_dir / "diagram-evidence-structure.png"),
        "sequence": witness_sequence(out_dir / "diagram-witness-sequence.png"),
        "deployment": live_deployment(out_dir / "diagram-live-deployment.png"),
        "verification": verification_flow(out_dir / "diagram-verification-flow.png"),
    }


# ------------------------------------------------------------- guide: module map

def module_map(out: Path) -> Path:
    """Which code files exist and which layer each belongs to (read top to bottom)."""
    canvas, draw = _canvas(2400, 1930, "How the Code Is Organised")
    layers = [
        ("Entry points: how a person or script starts the system", "neutral", [
            ("cli.py + __main__.py", "every bscaf command"),
            ("ui.py", "web dashboard"),
            ("scripts/*.py", "experiments and downloads"),
        ]),
        ("Collectors: where events come from", "collect", [
            ("ebpf.py", "live capture from the kernel"),
            ("auditd.py", "existing audit logs"),
            ("JSONL input (cli.py)", "events from other tools"),
        ]),
        ("Core pipeline: turning events into evidence", "evidence", [
            ("policy.py", "keep, redact, truncate"),
            ("models.py + canonical.py", "fixed record, stable hash"),
            ("service.py", "chain, batch, seal, verify, search"),
            ("store.py", "append-only files, lock"),
        ]),
        ("Cryptography: the seals", "ledger", [
            ("merkle.py", "batch root, proof path"),
            ("crypto.py", "Ed25519 keys and signatures"),
            ("proof.py", "check one event offline"),
        ]),
        ("Independent copies", "witness", [
            ("witness.py", "witness server, quorum, comparison"),
            ("tlsutil.py", "HTTPS and mutual TLS"),
        ]),
        ("Evaluation and quality", "verify", [
            ("attacks.py", "12 tampering scenarios"),
            ("bench.py", "performance experiment"),
            ("tests/", "48 automated tests"),
        ]),
    ]
    top, band_height, gap = 110, 260, 40
    for index, (title, stage, boxes) in enumerate(layers):
        y = top + index * (band_height + gap)
        group(draw, (40, y, 2360, y + band_height), title, stage)
        width = (2360 - 40 - 60 - (len(boxes) - 1) * 40) / len(boxes)
        for position, (name, role) in enumerate(boxes):
            x = 70 + position * (width + 40)
            draw.rounded_rectangle((x, y + 70, x + width, y + band_height - 25), radius=16, fill=WHITE, outline=STAGES[stage][0], width=4)
            _label(draw, (x + width / 2, y + 100), name, 27, True, "ma")
            _label(draw, (x + width / 2, y + 150), role, 23, False, "ma")
        if index < len(layers) - 1:
            base.arrow(draw, (1200, y + band_height), (1200, y + band_height + gap))
    canvas.save(out, dpi=(220, 220))
    return out


# ------------------------------------------------------------- guide: life of one event

def event_lifecycle(out: Path) -> Path:
    """One system call travelling through the files, in ten numbered steps."""
    canvas, draw = _canvas(2400, 1190, "Life of One System Call Through the Code")
    font = base.find_font(25, bold=True)
    small = base.find_font(22)
    steps = [
        ("1. A program asks the kernel", "e.g. open /etc/passwd", "collect"),
        ("2. Kernel hook fires", "bpftrace program from ebpf.py", "collect"),
        ("3. Line becomes an event", "ebpf.py (or auditd.py)", "collect"),
        ("4. Keep or drop, hide secrets", "policy.py", "evidence"),
        ("5. Fixed record, chained hash", "models.py, canonical.py", "evidence"),
        ("10. Check everything later", "service.py, witness.py, proof.py", "verify"),
        ("9. Copies to witnesses", "witness.py, tlsutil.py", "witness"),
        ("8. Block signed and stored", "crypto.py, store.py", "ledger"),
        ("7. Merkle root of the batch", "merkle.py", "ledger"),
        ("6. Appended, batch grows", "service.py, store.py", "evidence"),
    ]
    width, height = 400, 230
    xs = [60 + index * (width + 65) for index in range(5)]
    rows = [200, 760]
    for index, (title, files, stage) in enumerate(steps):
        row = 0 if index < 5 else 1
        x = xs[index % 5]
        y = rows[row]
        accent, tint, _ = STAGES[stage]
        draw.rounded_rectangle((x, y, x + width, y + height), radius=18, fill=tint, outline=accent, width=4)
        base.center_text(draw, (x + 10, y + 20, x + width - 10, y + 130), title, font, spacing=4)
        base.center_text(draw, (x + 10, y + 130, x + width - 10, y + height - 15), files, small, spacing=3)
    for index in range(4):
        base.arrow(draw, (xs[index] + width, rows[0] + height / 2), (xs[index + 1], rows[0] + height / 2))
        base.arrow(draw, (xs[index + 1], rows[1] + height / 2), (xs[index] + width, rows[1] + height / 2))
    base.routed_arrow(draw, [(xs[4] + width / 2, rows[0] + height), (xs[4] + width / 2, rows[1])])
    _label(draw, (1200, 1065), "Steps 1-6 happen for every event. Steps 7-9 happen once per block (every N events or T seconds).", 25, False, "ma")
    _label(draw, (1200, 1115), "Step 10 runs whenever someone asks: bscaf verify, bscaf proof / proof-verify, or the dashboard.", 25, False, "ma")
    canvas.save(out, dpi=(220, 220))
    return out


def build_guide_diagrams(out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    return {
        "modules": module_map(out_dir / "guide-module-map.png"),
        "lifecycle": event_lifecycle(out_dir / "guide-event-lifecycle.png"),
    }

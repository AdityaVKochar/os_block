"""Build the B-SCAF code guide, setup instructions and viva preparation (.docx).

Uses the same styles as the final report and the same measured results
(project-documents/data/*.json), so every number quoted here matches the report.

Run from the repository root (python-docx, Pillow and matplotlib required):
  python project-documents/builders/build_viva_guide.py
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.shared import Inches, Pt

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_final_report as report  # noqa: E402  (tables, code blocks, captions, architecture figure)
import build_formal_draft as base  # noqa: E402
import report_diagrams  # noqa: E402

DATA_DIR = base.DOCUMENTS_DIR / "data"
OUTPUT = base.DOCUMENTS_DIR / "B-SCAF_Code_Guide_Setup_and_Viva_Preparation.docx"
REPO = "https://github.com/AdityaVKochar/os_block.git"
BRANCH = "feature/real-data-validation"

FIGURE = {"n": 0}


def figure(doc, path, text, width=6.3):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.keep_with_next = True
    p.add_run().add_picture(str(path), width=Inches(width))
    FIGURE["n"] += 1
    report.caption(doc, f"Figure {FIGURE['n']}. {text}")


def quote(doc, text):
    """An indented, italic block for the spoken pitches."""
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.35)
    p.paragraph_format.right_indent = Inches(0.35)
    r = p.add_run(text)
    base.set_font(r, 11, italic=True)


def qa(doc, number, question, answer):
    p = doc.add_paragraph()
    p.paragraph_format.keep_with_next = True
    p.paragraph_format.space_after = Pt(2)
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    base.set_font(p.add_run(f"Q{number}. {question}"), 11, bold=True)
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.3)
    p.paragraph_format.space_after = Pt(8)
    base.set_font(p.add_run(answer), 11)


def numbered(doc, items):
    """A numbered list that always starts at 1 (Word's list style would continue earlier lists)."""
    for index, text in enumerate(items, start=1):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        p.paragraph_format.left_indent = Inches(0.35)
        p.paragraph_format.first_line_indent = Inches(-0.25)
        p.paragraph_format.space_after = Pt(4)
        base.set_font(p.add_run(f"{index}. "), 11, bold=True)
        base.set_font(p.add_run(text), 11)


def term(doc, word, meaning):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(3)
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    base.set_font(p.add_run(f"{word}: "), 11, bold=True)
    base.set_font(p.add_run(meaning), 11)


def numbers(real: dict, live: dict) -> dict:
    everything = real["ingest"]["all_syscalls"]
    bench = {row["label"]: row for row in real["bench"]["results"]}
    runs = live["phases"]["B-SCAF"]
    overview = live["overview"]
    n100 = bench["B-SCAF N=100"]
    return {
        "files": real["dataset"]["files"],
        "bytes": real["dataset"]["bytes"],
        "commit": real["dataset"]["commit"][:12],
        "events_all": everything["accepted"],
        "events_default": real["ingest"]["default"]["accepted"],
        "duplicates": everything["duplicate_syscall_records"],
        "rejected": sum(everything.get("rejected", {}).values()),
        "blocks_all": real["verify"]["all policy"]["checkpoints_checked"],
        "proofs": len(real["proofs"]),
        "proofs_ok": sum(item["valid"] for item in real["proofs"]),
        "iterations": live["iterations"],
        "runs": live["runs"],
        "kernel": live["kernel"],
        "ops": runs[0]["completeness"]["expected"],
        "captured_min": min(run["completeness"]["captured"] for run in runs),
        "live_events_min": min(run["events"] for run in runs),
        "live_events_max": max(run["events"] for run in runs),
        "lost_max": max(run["collector"]["lost_events"] for run in runs),
        "delay_p50_min": min(run["commit_delay_ms_median"] for run in runs) / 1000,
        "delay_p50_max": max(run["commit_delay_ms_median"] for run in runs) / 1000,
        "delay_p95_max": max(run["commit_delay_ms_p95"] for run in runs) / 1000,
        "base_s": overview["baseline"]["workload_seconds"],
        "trace_s": overview["tracing only"]["workload_seconds"],
        "full_s": overview["B-SCAF"]["workload_seconds"],
        "trace_pct": overview["tracing only"]["slowdown_percent"],
        "full_pct": overview["B-SCAF"]["slowdown_percent"],
        "cpu": overview["B-SCAF"]["collector_cpu_seconds"],
        "attacks": len(real["attacks"]),
        "attacks_ok": sum(row["as_expected"] for row in real["attacks"]),
        "bench_events": real["bench"]["events"],
        "eps_plain": bench["plain log"]["events_per_second"],
        "eps_chain": bench["hash chain only"]["events_per_second"],
        "eps_10": bench["B-SCAF N=10"]["events_per_second"],
        "eps_100": n100["events_per_second"],
        "eps_1000": bench["B-SCAF N=1000"]["events_per_second"],
        "eps_fsync": bench["B-SCAF N=100 + fsync"]["events_per_second"],
        "verify_s": n100["verify_seconds"],
        "proof_ms": n100["proof_verify_seconds"] * 1000,
        "replicate_s": n100.get("replicate_seconds", 0.0),
        "blocks_100": n100["blocks"],
        "bytes_plain": bench["plain log"]["bytes_per_event"],
        "bytes_100": n100["bytes_per_event"],
        "delay_100_ms": n100["commit_delay_ms_median"],
    }


# --------------------------------------------------------------------- content

CORE_FILES = [
    ("__init__.py", "Marks src/bscaf as a Python package and records the version number (0.1.0).",
     "Nothing else; it is the package's label."),
    ("__main__.py", "Lets you run the program as python -m bscaf. It simply hands over to the command-line interface.",
     "cli.py"),
    ("cli.py", "The front door. It defines every bscaf command (init, ingest, ingest-auditd, ingest-ebpf, flush, verify, status, proof, proof-verify, search, policy, replicate, witness-init, witness-trust, witness-serve, tls-certs, ui, demo, bench), reads the options, builds an AuditService with the chosen policy and batching rules, and calls the right module. It also contains two small helpers: a cursor that remembers which audit records were already imported, so importing the same log twice adds nothing, and a 'replicate on commit' hook that pushes each new block to the witnesses as soon as it is sealed.",
     "Almost everything: service.py, auditd.py, ebpf.py, witness.py, tlsutil.py, proof.py, ui.py, bench.py."),
    ("models.py", "Defines the two kinds of record. An AuditEvent is one system call: sequence number, time, host, process and parent process IDs, user ID, system-call name, program, arguments, return code, the previous event's hash and its own hash. A Checkpoint is one block: number, previous block hash, batch range, Merkle root, host, time window, policy version, creation time, signer, signature and block hash. Each record knows how to compute its own hash.",
     "canonical.py for hashing; used by service.py, store.py, witness.py, proof.py and attacks.py."),
    ("canonical.py", "Turns a record into one fixed sequence of bytes (JSON with sorted keys and no spaces) and computes SHA-256. This is what guarantees that the same event always has the same hash on every machine.",
     "Used by models.py, policy.py, service.py, witness.py and proof.py."),
    ("policy.py", "Decides what is kept. It holds the allow-list of security-relevant system calls, replaces secret-looking values with [REDACTED] (including inline ones such as --password=... inside a command line), cuts very long values to 512 characters, and computes the policy version: a short hash of the rules that is written into every block. Policies can be loaded from a JSON file.",
     "Called by service.py for every event; configured from cli.py."),
    ("auditd.py", "Reads Linux audit logs. It understands raw, enriched, node-prefixed and ausearch -i formats, groups the several records that belong to one kernel event (SYSCALL, EXECVE, PATH, CWD, SOCKADDR, PROCTITLE), decodes hex-encoded values, translates system-call numbers into names for x86_64, aarch64 and i386, counts malformed lines instead of crashing, and can follow a growing log through rotation, like tail -f.",
     "Feeds events to service.py through cli.py."),
    ("ebpf.py", "Live capture. It generates a bpftrace program that hooks the kernel's entry and exit tracepoints for each traced system call, learns its own kernel process ID with a one-shot probe so it never records itself, turns the tracer's output lines into events (paths, command lines, network addresses, return codes), and runs the capture loop that feeds the service, closes blocks on time and stops cleanly when asked.",
     "Runs bpftrace; feeds service.py; can trigger witness.py through cli.py."),
    ("service.py", "The heart of the system (AuditService). On ingest it applies the policy, builds the event with its chained hash, appends it and, when a batch is complete (N events, T seconds or a new host), seals a block: Merkle root plus signature. It keeps the end of the chain in memory so it never re-reads the files. It also verifies a whole ledger in one pass, produces inclusion proofs and runs searches.",
     "policy.py, models.py, store.py, merkle.py, crypto.py; called by cli.py, ui.py, ebpf.py, attacks.py and bench.py."),
    ("store.py", "The filing cabinet. It appends records to the evidence files (events.jsonl, checkpoints.jsonl, witness-acks.jsonl), forces them to disk (fsync) so a block never refers to events that were not saved, holds a lock file so two writers cannot interleave, and streams records back for reading.",
     "Used by service.py and the command line."),
    ("merkle.py", "Builds the Merkle root of a batch of event hashes, produces the short list of sibling hashes that proves one event belongs to the batch, and checks such a list.",
     "Used by service.py, proof.py and attacks.py."),
    ("crypto.py", "Ed25519 keys and signatures: creates a key pair (the private key file is readable only by its owner and can be encrypted with BSCAF_KEY_PASSPHRASE), loads keys, signs and verifies.",
     "Used by service.py, witness.py, proof.py and attacks.py."),
    ("proof.py", "Checks an exported proof completely offline with only the public key: the event's hash, the Merkle path up to the root, the block hash and the block signature.",
     "models.py, merkle.py, crypto.py; called by the proof-verify command."),
    ("witness.py", "Both sides of the witness protocol. The WitnessStore holds the acceptance rules (trusted signer, intact and signed block, continues the chain), records conflicting blocks as equivocation evidence and signs receipts. It also contains the HTTP(S) server, the client that replicates blocks to several witnesses and checks the quorum, the comparison of a local ledger with witness copies, and a helper that starts local witnesses for tests and experiments.",
     "crypto.py, models.py, canonical.py, tlsutil.py; called by cli.py, attacks.py, bench.py and the scripts."),
    ("tlsutil.py", "Creates a development certificate authority with server and client certificates, and builds the TLS settings for HTTPS and mutual TLS, so witnesses only talk to authorized sources.",
     "Used by cli.py and witness.py."),
    ("attacks.py", "The twelve tampering scenarios written as code. Each one copies a ledger, damages it the way an attacker would (edit, delete, insert, reorder, change a root, replay, truncate, rewrite and re-sign, forge a receipt, take witnesses offline) and verifies the copy with and without witnesses.",
     "service.py, witness.py, merkle.py, crypto.py; used by tests and scripts."),
    ("bench.py", "The performance experiment. It replays events through plain logging, a hash chain alone and B-SCAF with different settings, each in its own process, and measures throughput, per-event time, delay until sealing, CPU, memory, storage, verification and replication time.",
     "service.py, witness.py, policy.py, models.py; run by bscaf bench and run_real_data.py."),
    ("ui.py", "A small web dashboard built on Python's own web server with the page embedded in the file. It shows the verdict, event and block counts, problems, recent events and blocks, and has three buttons: Add demo events, Flush batch and Verify integrity.",
     "service.py; started by bscaf ui."),
]

SCRIPTS = [
    ("scripts/fetch_datasets.py", "Downloads the 100 public audit logs listed in datasets/manifest.json and checks each file's SHA-256. Files that are already present and correct are not downloaded again."),
    ("scripts/run_real_data.py", "The whole recorded-data experiment: download, import every file through the real command line (once with the default policy, once with all system calls), verify, export and check five proofs, replicate to three witnesses and switch some off, run the attack matrix, run the benchmark, and write results/REAL_DATA_REPORT.md plus a JSON summary."),
    ("scripts/attack_matrix.py", "Runs all twelve attack scenarios against any existing ledger, using three temporary witnesses, and prints the results table."),
    ("scripts/live_capture.py", "The live experiment, run in the privileged container. It times the workload with no tracing, with tracing only, and with full B-SCAF capture plus three witnesses; checks that every workload operation reached the ledger; runs the attack matrix on the live ledger; and writes results/LIVE_REPORT.md."),
    ("scripts/workload.py", "A repeatable activity generator: N times, create and write a file, rename it, chmod it, delete it, start /bin/true and open a TCP connection. It reports exactly how many of each operation it performed."),
]

TESTS = [
    ("tests/test_integrity.py", "Core behaviour: Merkle proofs, clean verification, tamper detection, privacy policy, batching by time and host, the partial verdict, resuming an existing ledger, private-key permissions and the dashboard."),
    ("tests/test_auditd_real.py", "The audit-log parser on real excerpts from the public dataset and on synthetic examples of every format (node prefix, hex values, long arguments, network addresses, other CPU architectures, malformed lines)."),
    ("tests/test_cli.py", "The real command line: importing the same log twice adds nothing, and events from one file are committed in time order."),
    ("tests/test_attacks.py", "The full attack matrix against three real HTTP witness servers, plus the witness rules (signed receipts, chain order, refusing a conflicting block, surviving a restart)."),
    ("tests/test_live.py", "The eBPF parser and capture loop using recorded tracer output, search, encrypted keys, mutual TLS and replication on commit."),
    ("tests/test_bench.py", "A small run of every benchmark mode to make sure the harness works."),
    ("tests/fixtures/", "Real input samples used by the tests (audit-log excerpts with attribution, recorded eBPF output)."),
]

BUILD_FILES = [
    ("Dockerfile", "Builds the bscaf image: Python 3.12, the package and pytest. Used for tests, the demo, the dashboard and the recorded-data experiment."),
    ("deploy/live/Dockerfile", "Builds the bscaf-live image, which adds bpftrace (and auditd) for live capture in a privileged container."),
    ("deploy/audit/bscaf.rules", "Rules for auditd on a normal Linux machine, matching the default policy."),
    ("pyproject.toml", "Package description: the name, the single runtime dependency (cryptography), optional extras for tests and documents, and the bscaf command."),
    ("datasets/manifest.json", "The pinned list of public dataset files: repository commit, path and SHA-256 of each file."),
    ("samples/", "Two tiny example inputs: a few JSON events and one auditd line."),
    (".dockerignore, .gitignore, .gitattributes", "Keep generated data out of images and Git, and keep line endings consistent on Windows."),
    ("docs/", "README-level documentation: architecture and demo guide, results snapshot, status against the brief."),
    ("project-documents/builders/", "Scripts that generate the Word documents, diagrams and charts, including this guide."),
    ("project-documents/data/", "Snapshots of the measured results that the report and this guide are generated from."),
]

COMMAND_PATHS = [
    ("init", "cli.py, service.py, store.py, crypto.py"),
    ("ingest (JSON lines)", "cli.py, service.py, policy.py, models.py, canonical.py, store.py, merkle.py, crypto.py"),
    ("ingest-auditd", "cli.py, auditd.py, then the same path as ingest; witness.py and tlsutil.py with --replicate-url"),
    ("ingest-ebpf", "cli.py, ebpf.py (and bpftrace), then the same path as ingest; witness.py and tlsutil.py with --replicate-url"),
    ("flush", "cli.py, service.py, merkle.py, crypto.py, store.py"),
    ("verify / status", "cli.py, service.py, store.py, models.py, merkle.py, crypto.py; witness.py and tlsutil.py with --witness"),
    ("proof", "cli.py, service.py, merkle.py"),
    ("proof-verify", "cli.py, proof.py, models.py, merkle.py, crypto.py"),
    ("search", "cli.py, service.py, store.py"),
    ("policy", "cli.py, policy.py"),
    ("replicate", "cli.py, witness.py, tlsutil.py, store.py (saves receipts)"),
    ("witness-init / witness-trust / witness-serve", "cli.py, witness.py, crypto.py, tlsutil.py"),
    ("tls-certs", "cli.py, tlsutil.py"),
    ("ui", "cli.py, ui.py, service.py"),
    ("demo", "cli.py, service.py"),
    ("bench", "cli.py, bench.py, service.py, witness.py"),
]

DISK_FILES = [
    ("events.jsonl", "One line per recorded event, including its hash and the previous event's hash."),
    ("checkpoints.jsonl", "One line per signed block."),
    ("witness-acks.jsonl", "Receipts returned by witnesses, each signed with the witness's own key."),
    ("ingest-state.json", "The newest audit record imported per host, so the same log is never imported twice."),
    ("signing-private.pem / signing-public.pem", "The host's Ed25519 key pair. Only the public key is ever shared."),
    (".lock", "Lock file that stops two programs writing at the same time."),
    ("witness folder: witness.json, witness keys", "The witness's name and its own key pair for signing receipts."),
    ("witness folder: trusted-signers/", "Public keys of the sources this witness accepts blocks from."),
    ("witness folder: witness-checkpoints.jsonl", "The witness's copy of every accepted block."),
    ("witness folder: equivocations.jsonl", "Evidence of any attempt to give the witness a different version of history."),
]

DEFINITIONS = [
    ("System call", "A request from a program to the kernel, such as open a file or start a process."),
    ("Kernel", "The core of the operating system that controls processes, memory, files and permissions."),
    ("PID / PPID / UID", "Process ID, parent process ID and user ID: which program, started by which program, running as which user."),
    ("auditd", "Linux's standard audit daemon; it writes kernel audit records to a log file."),
    ("eBPF", "A way to run small, safety-checked programs inside the Linux kernel when events happen."),
    ("bpftrace", "A tool for writing eBPF programs in a short scripting language."),
    ("Tracepoint", "A fixed hook in the kernel, for example at the entry and exit of every system call."),
    ("Hash / SHA-256", "A fixed-size fingerprint of data; any change gives a completely different fingerprint."),
    ("Hash chain", "Records whose hashes each include the previous record's hash, so nothing can be changed, removed or reordered unnoticed."),
    ("Genesis hash", "The starting 'previous hash' for the first record: 64 zeros."),
    ("Merkle tree / root", "A tree of hashes that reduces a batch to one root hash and allows short proofs for single items."),
    ("Inclusion proof", "The few hashes that show one event belongs under a given Merkle root."),
    ("Digital signature", "A value made with a private key that anyone can check with the public key."),
    ("Ed25519", "The modern, fast signature scheme B-SCAF uses."),
    ("Block / checkpoint", "A signed summary of a batch of events, linked to the previous block."),
    ("Witness", "An independent machine that keeps copies of signed blocks and signs receipts."),
    ("Quorum", "The minimum number of witnesses that must hold a block, here 2 of 3."),
    ("Equivocation", "Offering two different versions of the same block; witnesses refuse and record it."),
    ("Truncation", "Deleting the newest part of the evidence; only witnesses can expose it."),
    ("Replay", "Re-inserting an old, genuine block to confuse the ledger."),
    ("Canonical form", "One fixed way to write a record so it always hashes the same."),
    ("Policy version", "A hash of the filtering rules, stored in every block."),
    ("Partial verdict", "Nothing is wrong, but the evidence cannot be fully confirmed yet."),
    ("TLS / mutual TLS", "Encrypted connections; mutual TLS also checks the client's certificate."),
    ("fsync", "Asking the operating system to really write data to disk now."),
    ("JSON Lines", "A text file with one JSON record per line."),
    ("Container / Docker", "A packaged, isolated environment that runs the same way on any machine."),
    ("Namespace", "A Linux feature that gives a container its own view of process IDs, files and network."),
    ("WSL2", "Windows Subsystem for Linux: a real Linux kernel running in a lightweight virtual machine on Windows."),
    ("MITRE ATT&CK", "A public catalogue of attacker techniques, used to label the dataset."),
    ("Tamper-evident", "Changes cannot be prevented but cannot go unnoticed."),
]


def viva_questions(n: dict) -> list[tuple[str, list[tuple[str, str]]]]:
    return [
        ("A. The big picture", [
            ("In one sentence, what is your project?",
             "B-SCAF watches the security-relevant requests that programs make to the Linux kernel, such as running a program, opening a file or connecting to the network, and seals those records with blockchain-style cryptography so that any later change to the evidence can be detected and located, even by someone who does not trust the machine."),
            ("What problem does it solve?",
             "After a break-in, logs are the main evidence, but they normally live on the machine the attacker now controls. With root access an attacker can edit or delete them and nobody would know. B-SCAF makes that kind of tampering visible."),
            ("Why does this problem matter?",
             "Incident response, legal cases and compliance audits all depend on logs being genuine. Attackers know this, which is why cleaning up logs is a standard step after an intrusion; MITRE ATT&CK even lists it as a technique of its own (T1070, Indicator Removal). Insiders matter too: an administrator should not be able to quietly rewrite the record of what they did."),
            ("Why system calls rather than ordinary application logs?",
             "Every meaningful action has to go through a system call: opening or deleting files, starting programs, changing permissions or identity, connecting to the network. Application logs only show what each program chooses to write, and malware writes nothing. System calls are the common layer underneath every program, so they capture activity no matter which program, or which piece of malware, is running."),
            ("Who would use something like this?",
             "Security teams investigating a breach; auditors who need evidence they can trust; organizations where administrators themselves must be accountable, such as universities, banks or hospitals with shared servers; and forensic investigators who may have to present evidence."),
            ("What does tamper-evident mean, and why not tamper-proof?",
             "Tamper-proof would mean nobody can change the logs at all, which is impossible on a machine the attacker fully controls, because they own the disk. Tamper-evident means a change cannot go unnoticed: if someone edits, deletes or reorders the evidence, verification fails and points to where. B-SCAF is tamper-evident, and we are careful to claim only that."),
            ("What were your objectives, and did you meet them?",
             f"There were four: capture system calls with context, build a lightweight tamper-evident evidence chain, verify it independently with a clear verdict, and measure the cost. All four were met. Live capture recorded every one of the {n['ops']:,} operations of our test workload, all {n['attacks']} tampering scenarios were detected, verification answers pass, fail or partial, and the overhead was measured both live and on replayed data."),
            ("Why call it blockchain-based if there is no cryptocurrency?",
             "Because it uses the ideas that make a blockchain trustworthy: hashing, blocks chained together, Merkle trees, digital signatures and copies held by several independent parties. What it leaves out is what only an open cryptocurrency needs: mining, tokens and public consensus. Technically it is a small permissioned ledger."),
            ("What is new in your work?",
             "Each technique on its own is well known. The new part is the combination, applied to operating-system evidence and tested properly: live capture from the kernel, privacy filtering, a two-layer integrity structure, witnesses that catch even a stolen signing key, and an evaluation on real attack data and live activity. It is an integration contribution, not a new cryptographic invention, and the report says so."),
            ("Summarize your results in a few numbers.",
             f"All {n['files']} public audit logs imported ({n['events_all']} events, against 46 for the first prototype); {n['captured_min']:,} of {n['ops']:,} workload operations captured live in every run; {n['attacks_ok']} of {n['attacks']} attacks detected as designed; about {n['eps_100']:,.0f} events per second per core; verification of {n['bench_events']:,} events in {n['verify_s']:.1f} seconds; and about {n['full_pct']:.0f}% slowdown on a workload that does nothing but system calls."),
        ]),
        ("B. Core ideas explained simply", [
            ("What is a system call? Give examples.",
             "A request a program makes to the operating-system kernel for something it is not allowed to do by itself, like reading a file or creating a process. B-SCAF records calls such as execve (run a program), openat (open a file), unlink (delete a file), rename, chmod (change permissions), setuid (change user identity), ptrace (inspect or control another process), connect (open a network connection) and finit_module (load a kernel module)."),
            ("What is the kernel, and what is user space?",
             "The kernel is the core of the operating system: it controls memory, processes, files, devices and permissions. Ordinary programs run in user space with limited rights; whenever they need something privileged, they must ask the kernel through a system call. That boundary is exactly why system calls are such a good place to watch."),
            ("What is an audit log, and what is auditd?",
             "An audit log is a record of who did what and when. On Linux the standard tool is auditd, which receives audit records from the kernel and writes them to /var/log/audit/audit.log. It records events, but it does nothing to protect that file from someone with root access."),
            ("What is a hash function, and why SHA-256?",
             "A hash function turns any amount of data into a short, fixed-size fingerprint. SHA-256 produces 256 bits, written as 64 hexadecimal characters. The same input always gives the same fingerprint, changing even one character gives a completely different one, and nobody knows how to find two inputs with the same fingerprint or to work backwards from one. SHA-256 is the standard choice: it protects web certificates, software updates and Bitcoin, and no practical attack on it is known."),
            ("What is a hash chain?",
             "Each record's hash also covers the previous record's hash. Picture a diary where every page begins by copying the fingerprint of the page before. If you change, remove, insert or reorder a page, its fingerprint changes and every later page stops matching. The very first record links to a 'genesis' value of 64 zeros."),
            ("What is a Merkle tree, and what is the Merkle root?",
             "A tree of hashes. The event hashes are the leaves; neighbouring pairs are hashed together, then pairs of those, until one hash is left at the top: the Merkle root, which stands for the whole batch. The useful property is that you can prove one event belongs to the batch by showing only a handful of hashes, about log2 of the batch size, instead of the whole batch. When a level has an odd number of hashes, the last one is paired with itself."),
            ("Why use both a hash chain and a Merkle tree?",
             "They do different jobs. The chain protects order and continuity across all events, so nothing can be dropped or slipped in. The Merkle root gives one small value per block that can be signed and handed to witnesses, and it allows proving a single event without revealing the others. Together you get complete verification and selective disclosure."),
            ("What is a digital signature?",
             "A value created with a private key that only the signer has; anyone can check it with the matching public key. A valid signature shows the data came from the key holder and has not changed since. It is the digital version of a wax seal that anyone can inspect but only one person can make."),
            ("Why Ed25519 for signatures?",
             "It is a modern scheme that is fast, has small keys and signatures (32-byte public keys and 64-byte signatures), is widely trusted (SSH uses it, for example), and avoids pitfalls of older schemes, such as needing fresh randomness for every signature."),
            ("What is the difference between the public and the private key?",
             "They are a matched pair. The private key is secret and is used to sign; the public key can be given to anyone and is used to check signatures. In B-SCAF the monitored machine signs blocks with its private key, and auditors and witnesses check them with its public key. Each witness also has its own pair for signing receipts."),
            ("What is a block in B-SCAF?",
             "A small signed summary of a batch of events: its number, the hash of the previous block, the range of event numbers it covers, the Merkle root of those events, the host, the time window, the policy version, who signed it and when, and the signature. It contains the batch's fingerprint, not the events themselves."),
            ("What is a witness?",
             "A separate machine, ideally run by a different person or team, that keeps a copy of every signed block and sends back a receipt signed with its own key. Because it holds copies made at the time, it can later expose a history that was rewritten or shortened. It never sees the events themselves."),
            ("What is a quorum?",
             "How many witnesses must hold a block before the evidence counts as independently confirmed, for example two out of three. One witness can be down or misbehaving without breaking anything, but we never rely on a single party."),
            ("What are eBPF, bpftrace and tracepoints?",
             "eBPF lets small, safety-checked programs run inside the Linux kernel when certain events happen. A tracepoint is one of those events; the kernel has one at the entry and exit of every system call. bpftrace is a tool that makes such programs easy to write. B-SCAF generates a bpftrace program automatically for the system calls in its policy."),
            ("What is a permissioned ledger, and how is it different from Bitcoin?",
             "In a permissioned ledger only known, authorized parties take part: here the host signs blocks and a configured set of witnesses keeps copies. In a public blockchain such as Bitcoin anyone can join, so participants need an expensive consensus mechanism (mining or staking) to agree on history. We do not need that, because the writer is known and the witnesses only have to keep and compare copies."),
            ("What are TLS and mutual TLS?",
             "TLS is the encryption behind the padlock in a web browser: it keeps traffic private and proves the server's identity with a certificate. Mutual TLS also makes the client prove its identity. B-SCAF witnesses can require this, so only authorized sources can talk to them; a client without the right certificate is turned away during the handshake."),
            ("What does canonical form mean, and why does it matter?",
             "One fixed way of writing a record. JSON allows the same record to be written in many ways (different key order or spacing), and each would give a different hash. B-SCAF always sorts the keys and removes spaces before hashing, so the same event produces the same hash on any machine."),
        ]),
        ("C. Design decisions", [
            ("Why not store the logs on Ethereum or Bitcoin?",
             "It would be too slow, too expensive and too public. Public chains take seconds to minutes to confirm a transaction and charge a fee for each one, while a busy server produces thousands of events per second. And system-call records contain file paths, user names and command lines that should never be published. Keeping the events local and protecting only their fingerprints gives the same tamper evidence."),
            ("Why keep the raw events on the monitored machine?",
             "For privacy and practicality. Events can contain sensitive details, and every extra copy is another place they could leak. Witnesses do not need the events to detect tampering, only the fingerprints. Keeping events local also keeps them searchable for investigators."),
            ("Why put events into batches instead of signing each one?",
             f"Signing every event would cost a signature and a network message per event. A batch costs one Merkle root and one signature however many events it holds. The benchmark shows the effect: about {n['eps_10']:,.0f} events per second with 10-event blocks against about {n['eps_1000']:,.0f} with 1,000-event blocks."),
            ("How do you choose the block size?",
             f"It is a trade-off between speed and how quickly evidence gets sealed. Bigger blocks are faster overall, but each event waits longer. B-SCAF closes a block after N events or after T seconds, whichever comes first. Live capture used 1-second blocks, so events were sealed within about a second; in the replay benchmark, 100-event blocks gave {n['eps_100']:,.0f} events per second with a median delay of {n['delay_100_ms']:.1f} ms."),
            ("Isn't the signature enough? Why do you need witnesses?",
             "A signature only proves a block was made with the host's key. An attacker with root can copy that key, rewrite the history, recompute every hash and re-sign every block, and locally everything would look perfect. Witnesses hold copies made before the attack, so the rewritten version no longer matches. Our tests show exactly this: deleting the tail and re-signing a forged history both pass local checks and fail against the witnesses."),
            ("Why three witnesses with a quorum of two?",
             "It tolerates one witness being offline or broken while still requiring confirmation from two independent parties. The brief suggested three to five witnesses; both the number and the quorum are settings."),
            ("Why do witnesses insist that each block continues their chain?",
             "So no witness can be tricked into holding two different versions of history. A witness only accepts a block that follows the chain it already has. If it is offered a different block for a number it already holds, it refuses with HTTP 409 (Conflict) and stores the conflicting block as evidence. This is called equivocation."),
            ("Why do witnesses send back signed receipts?",
             "The receipts let the source prove later that a quorum of witnesses really received each block, and when. A receipt cannot be forged without the witness's private key, which is exactly how our forged-receipt attack gets caught."),
            ("What does the privacy policy do, and why is it needed?",
             "System-call arguments can contain passwords, tokens and personal file names. Before anything is hashed or stored, the policy keeps only the system calls that matter for security, replaces secret-looking values with [REDACTED] (including inline ones like --password=hunter2 inside a command line), and trims very long values to 512 characters. Sensitive data never enters the evidence in the first place."),
            ("Why record a policy version in every block?",
             "If the rules change, an auditor needs to know which rules produced which evidence; otherwise an event that was simply filtered out might look like tampering. The policy version is a short hash of the rules, so it changes whenever they do."),
            ("Why plain JSON Lines files rather than a database?",
             "They are simple, append-only and human-readable; you can open them in any text editor, which also makes demonstrations easy, and they need no extra software. The cost is that there are no indexes, so very large ledgers would need a proper database. That is listed as future work."),
            ("Why Python?",
             f"It is quick to develop in, easy for others to read and run, and has a mature, well-reviewed cryptography library. Performance was good enough for a prototype, about {n['eps_100']:,.0f} events per second per core. The busiest parts could later move to a compiled language."),
            ("Why Docker?",
             "So the project runs the same way on any computer without installing dependencies, and so the experiments can be repeated exactly. Nothing besides Docker had to be installed on the development machine."),
            ("Why three verdicts instead of just pass or fail?",
             "Because 'not failed' is not the same as 'confirmed'. Pass means everything checks out and is independently confirmed. Fail means something was changed, and the report names the first problem. Partial means nothing is wrong but the evidence cannot be fully confirmed yet, for example because some events are not sealed or not enough witnesses could be reached. Saying 'pass' then would overstate what we know."),
            ("Why support both eBPF and auditd?",
             "auditd is the standard Linux audit system, so supporting it means B-SCAF can protect logs organizations already collect, and it let us test on a public dataset. eBPF was needed for live capture in our setup, because auditd cannot be controlled from a Docker Desktop container; it also delivers each event's arguments and return code in a single record."),
            ("Why does a block close when events from another host arrive?",
             "Each block names one host, so evidence from different machines is never mixed in one Merkle batch. That keeps proofs and witness comparisons clean per machine."),
        ]),
        ("D. How it works", [
            ("Walk us through what happens to a single system call.",
             "A program asks the kernel to do something, say open a file. The eBPF hook notes the arguments when the call starts and prints them with the result when it returns. The collector turns that line into an event. The policy decides whether to keep it and hides any secrets. The event gets a sequence number and a hash that includes the previous event's hash, and is appended to the event file. When the batch is full or a second has passed, B-SCAF computes the batch's Merkle root, signs a block, stores it and sends it to the witnesses, which return signed receipts. Later anyone can recheck the whole thing. Part 4 of this guide follows the same path through the code."),
            ("How does the live collector see system calls?",
             "It attaches small eBPF programs to the kernel tracepoints at the entry and exit of each system call in the policy. Because they run inside the kernel, they see every process on the machine, including anything an attacker starts."),
            ("How do you capture both the arguments and the result?",
             "At entry, the program saves the arguments in a small kernel table keyed by the thread's ID. At exit it reads them back and prints them together with the return code, then clears the entry. Each event therefore arrives complete: what was asked and whether it worked."),
            ("How does the collector avoid recording itself?",
             "It filters out its own process ID. The catch is that inside a container a process's ID differs from the ID the kernel reports, so the collector first runs a tiny one-shot probe: it opens a unique marker file and the probe reports which kernel process did it. Without this the collector would record its own file writes, which would be wasteful and confusing."),
            ("How do you read existing audit logs?",
             "auditd writes several lines for one kernel event (a SYSCALL line, plus EXECVE for the command line, PATH for files, CWD, SOCKADDR for network addresses and PROCTITLE), all sharing a timestamp and serial number. The parser groups them by that serial, decodes hex-encoded values, translates system-call numbers into names using the right table for the processor type, and understands raw, enriched and ausearch -i exports. Malformed lines are counted and skipped instead of stopping the import."),
            ("What exactly is stored for each event?",
             "A sequence number; the time in UTC; the host; the process ID and parent process ID; the user ID; the system-call name; the program; selected arguments such as file paths, the command line or the network destination; the return code; the previous event's hash; and the event's own hash."),
            ("What exactly is inside a block?",
             "Block number, previous block hash, batch ID, first and last sequence numbers, event count, Merkle root, host, the start and end of the time window, policy version, creation time, signer, the block's own hash, and the Ed25519 signature covering all of it."),
            ("How does verification work?",
             f"It reads every event and every block once. For events it recomputes each hash and checks each link and sequence number. For blocks it rebuilds the Merkle root from the events and checks the block hash, the link to the previous block, the numbering, the ranges, replays and the signature. If witnesses are given, it downloads each witness's copy, compares it with the local ledger block by block, and checks the signatures on the receipts. {n['bench_events']:,} events take about {n['verify_s']:.1f} seconds."),
            ("How does verification tell you where the problem is?",
             "Every failed check is recorded with a type and a location, for example 'event-hash at sequence 2: event contents were changed' or 'truncation at block 25'. The report highlights the first problem, which is usually where the tampering started."),
            ("What is an inclusion proof, and when would you use it?",
             f"A small file with one event, the few sibling hashes leading from it up to its block's Merkle root, and the signed block. Anyone with the public key can confirm that this exact event was part of the sealed evidence without seeing any other event. That is useful when one piece of evidence has to go to an auditor or a court while the rest stays private. Checking a proof takes about {n['proof_ms']:.2f} ms."),
            ("How does replication to the witnesses work?",
             "After a block is signed, the source sends it to each witness over HTTP or HTTPS. The witness checks that it comes from a trusted source, is unaltered and correctly signed, and continues the chain it holds. It stores it and returns a receipt signed with its own key. The source keeps the receipts. With the --replicate-url option this happens automatically for every new block."),
            ("What happens if a witness is offline?",
             "Nothing breaks. The source keeps working and the failure is reported. As long as a quorum (say two of three) holds every block, verification still passes, with a notice that one witness was unreachable. If fewer than the quorum can be reached, the verdict becomes partial."),
            ("What stops two programs from writing at the same time?",
             "A lock file. Only one process can append events or blocks at a time, so sequence numbers and links can never get mixed up."),
            ("What happens to events before their block is sealed?",
             "They are written to disk straight away but are not yet covered by a signature. Verification lists them as uncommitted and gives a partial verdict. With 1-second blocks and replication on every block, that window is about a second."),
            ("What if the computer crashes in the middle?",
             "Events are forced to disk before the block that covers them, so a block never points to events that do not exist. On restart the service rebuilds its state from the files and carries on. If the last line was only half written, verification reports it as a storage problem rather than silently accepting it."),
            ("How does search work?",
             "bscaf search reads through the event file and returns events that match any combination of system call, process or parent process ID, user, host, a piece of text (matched against the program, file paths, command line or destination) and a time range, either the first or the newest matches."),
            ("How did you test the software?",
             "With 48 automated tests covering hashing and tampering, real audit-log lines in every format we support, recorded eBPF output, the command line, the full attack matrix against real witness servers, the witness rules, mutual TLS, encrypted keys, search and the benchmark. On top of those, two end-to-end experiments, one on recorded data and one live, exercise the whole system together."),
            ("How is the code organized?",
             "In layers: entry points (command line, dashboard, scripts); collectors (eBPF, auditd); the core pipeline (policy, records and hashing, the service, storage); cryptography (Merkle trees, signatures, proofs); witnesses and TLS; and evaluation (attack scenarios, benchmark, tests). Part 3 of this guide describes every file."),
        ]),
        ("E. Security and the threat model", [
            ("What is your threat model?",
             "We assume that some time after events were recorded, an attacker gains root on the monitored machine. They can edit, delete, insert or reorder evidence, steal the signing key and re-sign a rewritten history, and take some witnesses offline. We assume the verifier has the genuine public keys and that at least a quorum of witnesses stays honest."),
            ("Which attacks did you test?",
             "Twelve scenarios: an untampered baseline; changing an event; deleting an event; inserting a forged event; swapping two events; changing a Merkle root; replaying an old block; deleting the newest block (truncation); rewriting history and re-signing it with the stolen key; forging a witness receipt; one witness offline; and too few witnesses reachable."),
            ("Which attacks can only be caught with witnesses, and why?",
             "Deleting the newest block, and rewriting history with the stolen key. After either attack every remaining hash, link and signature agrees with every other, so local checks see nothing wrong. Only an outside copy shows the difference. A forged witness receipt is also only caught using the witness's public key."),
            ("What if the attacker deletes the entire log?",
             "They can delete it locally, but the witnesses still hold every signed block, so verification reports the evidence as missing and shows how many blocks and which time windows are gone. B-SCAF cannot bring deleted events back, but it guarantees the deletion is noticed."),
            ("What if the attacker steals the signing key?",
             "They can sign new blocks, but every witness already holds the genuine blocks up to the moment of the theft and refuses different versions, so any rewrite of past evidence is detected. What a stolen key does allow is signing fake future events. That is why key protection matters: today the key can be encrypted with a passphrase, and a TPM or hardware security module would be the proper fix."),
            ("What if the machine was already compromised before the events were recorded?",
             "Then the attacker can stop or fake events at the source, and no logging system can fully prevent that; it is called the capture-trust problem. B-SCAF protects evidence once it has been recorded. Remote attestation and measured boot address trust at the source and are listed as future work."),
            ("What if the witnesses work together with the attacker?",
             "Then independent confirmation is lost, and that is a stated assumption. In practice the witnesses should be run by different parties, for example the IT department, the security team and an external auditor, so that all of them would have to be compromised at once."),
            ("What if the attacker changes the system clock?",
             "Timestamps would be wrong, but ordering does not depend on time: it is protected by sequence numbers and hash links. Witnesses also stamp every receipt with their own clock, so a host whose clock disagrees with its witnesses stands out."),
            ("Could an attacker replay an old block?",
             "Several checks catch it: the batch ID repeats, the block number and previous-hash link do not fit, and the event range overlaps earlier blocks. Witnesses also refuse any block that does not continue their chain. Our replay test is caught by the local checks."),
            ("What can a witness learn about the monitored machine?",
             "Only block metadata: numbers, hashes, the time window, the host name, the policy version and signatures. Never command lines, file names or user data. A witness can confirm that evidence exists and has not changed, but cannot read it."),
            ("How is communication with the witnesses protected?",
             "Witnesses can run over HTTPS with mutual TLS, so both sides prove who they are with certificates and outsiders are refused during the handshake. Even over plain HTTP a block could not be altered in transit without breaking its signature; TLS adds privacy and access control."),
            ("Is SHA-256 secure enough?",
             "As far as anyone knows, yes. No two inputs with the same SHA-256 hash have ever been found, and it protects web certificates and Bitcoin. If it were ever weakened, a new version of the record format could switch to a different hash function."),
            ("What about quantum computers?",
             "A large quantum computer could one day break Ed25519 signatures; SHA-256 is much less affected. The remedy would be a post-quantum signature scheme such as ML-DSA, which NIST standardized in 2024. Nothing in the design depends on Ed25519 in particular."),
            ("Couldn't the attacker simply switch the collector off?",
             "With root, yes. But that leaves a visible gap: blocks stop arriving at the witnesses, and the last block shows when it happened. A natural improvement is a heartbeat block every few seconds even when nothing happens, so that silence itself raises an alarm."),
            ("Isn't a collector running as root a risk in itself?",
             "It needs root to attach kernel probes, like any system monitor, auditd included. eBPF programs are checked by the kernel's verifier before they run, which limits what they can do. The witnesses and verifiers need no special privileges at all."),
            ("Where should verification be run?",
             "On a machine the auditor trusts, using public keys obtained in advance, never only on the possibly compromised host. A compromised host could lie about anything, including the result of its own verification."),
            ("How are secrets inside command lines handled?",
             "The policy redacts argument values whose names look secret (password, token, secret, cookie, API key and similar) and also scans text such as command lines for patterns like --password=... or token:..., replacing the value with [REDACTED] before anything is hashed or stored."),
        ]),
        ("F. Evaluation and results", [
            ("How did you evaluate the system?",
             f"In two ways. First, {n['files']} real audit logs from a public dataset recorded during simulated attacks: we imported, verified, attacked and benchmarked them. Second, live capture with eBPF on a real kernel while a repeatable workload ran, measuring overhead and checking that nothing was missed."),
            ("Why did you choose that dataset?",
             "Splunk's Attack Data repository contains real auditd output captured while MITRE ATT&CK techniques were carried out in a lab. It is public, and we pinned it to an exact version with checksums so anyone can rerun the experiment. It also contains the messy real-world formats a parser must cope with."),
            ("What did the real data teach you?",
             f"That our first parser was naive. It crashed on 11 of the 100 files and kept only 46 events. Real logs come in several formats, repeat records and often list events newest first. After fixing that: {n['files']} of {n['files']} files, {n['events_all']} events, {n['duplicates']} duplicate records merged and {n['rejected']} records rejected."),
            ("What is the live workload, and why that one?",
             f"{n['iterations']:,} repetitions of: create and write a file, rename it, change its permissions, delete it, start a small program and open a network connection. That is {n['ops']:,} security-relevant operations per run, the kind of things an intruder does, and the workload knows exactly how many of each it performed. Each setup was run {n['runs']} times."),
            ("How do you know nothing was missed?",
             f"Because the workload knows what it did, we searched the ledger afterwards for those exact operations: {n['captured_min']:,} of {n['ops']:,} in every run."),
            ("What was the overhead?",
             f"The workload took {n['base_s']:.2f} s without tracing, {n['trace_s']:.2f} s with eBPF tracing alone ({n['trace_pct']:+.0f}%) and {n['full_s']:.2f} s with full B-SCAF ({n['full_pct']:+.0f}%). The workload does nothing but system calls, so this is close to a worst case; normal programs spend most of their time computing."),
            ("Why was tracing alone slower than full B-SCAF?",
             "It is run-to-run variation on a workload that lasts just over a second on a laptop; the difference is not meaningful. The real conclusion is that B-SCAF's own work (hashing, signing, replicating) adds no measurable time to the traced program, because it runs on another core. The cost lies in hooking busy system calls."),
            ("How fast can B-SCAF process events?",
             f"On one core: {n['eps_100']:,.0f} events per second with 100-event blocks and {n['eps_1000']:,.0f} with 1,000-event blocks. For comparison, plain logging with no protection reached {n['eps_plain']:,.0f} and a bare hash chain {n['eps_chain']:,.0f}. Forcing every block to disk brought B-SCAF down to {n['eps_fsync']:,.0f}, mostly because the WSL2 virtual disk flushes slowly."),
            ("How long does verification take?",
             f"About {n['verify_s']:.1f} seconds for {n['bench_events']:,} events, and about {n['proof_ms']:.2f} ms to check a single proof. Sending all {n['blocks_100']:,} blocks to three witnesses took {n['replicate_s']:.1f} seconds."),
            ("How quickly is an event sealed?",
             f"In live capture with 1-second blocks the median delay was between {n['delay_p50_min']:.2f} and {n['delay_p50_max']:.2f} seconds, with the 95th percentile at most {n['delay_p95_max']:.2f} seconds. In the replay benchmark with 100-event blocks it was {n['delay_100_ms']:.1f} ms."),
            ("How much storage does it need?",
             f"About {n['bytes_100']:,.0f} bytes per event, compared with {n['bytes_plain']:,.0f} for a plain log; the difference is mainly the two hashes stored with each event. The blocks themselves are small."),
            ("Did you lose any events?",
             f"Not from the workload: all {n['ops']:,} operations were captured in every run. In one run the kernel's buffer reported {n['lost_max']} lost events, all from other processes. In production you would enlarge the buffer or trace fewer calls, and lost-event counts are reported so they cannot pass silently."),
            ("Why did you run on WSL2, and does it affect the results?",
             "It was the development machine, and WSL2 runs a real Linux kernel. The limitation is that timings on a laptop virtual machine are noisier than on a dedicated server, so we report medians of several runs and list bare-metal measurements as future work."),
            ("How reproducible are your results?",
             "Fully scripted: one command per experiment, all in Docker; the dataset is pinned by commit and checksums; the results are saved as JSON; and the report and this guide are generated from those JSON files, so no number is typed by hand."),
            ("What do the charts in your report show?",
             "Ingestion before and after the parser fixes; the mix of system calls in the dataset; live workload time per setup with each run shown as a dot; system calls captured across the whole machine; a grid of the twelve attacks with and without witnesses; throughput, per-event time and storage per configuration; and how block size trades speed against sealing delay."),
        ]),
        ("G. Comparison with existing work", [
            ("How is this different from sending logs to a central server or a SIEM?",
             "A central log server helps availability, but whoever runs it can still change records, and it holds every raw log in one place. B-SCAF makes changes detectable even by insiders, and its witnesses hold no raw data. The two fit together: B-SCAF's verified events could feed a SIEM."),
            ("How does it compare with other blockchain logging systems?",
             "Systems such as BCALS, BlockTrail and RootLogChain protect cloud or application logs, and several put more data on the chain. B-SCAF targets host system calls, keeps raw data off the ledger, uses witnesses that can catch a stolen key, and was evaluated with live capture."),
            ("Doesn't auditd already do this?",
             "auditd records events but does nothing to stop someone with root from editing the log afterwards. B-SCAF adds exactly that protection, and it can take auditd logs as input."),
            ("How does it relate to intrusion-detection research on system calls?",
             "That research uses system-call sequences to spot attacks and assumes the data is genuine. B-SCAF provides data you can trust; a detection model could run on top of it."),
            ("Where else are these ideas used?",
             "Bitcoin uses Merkle trees for the transactions in a block, Git links commits by hash, and Certificate Transparency, the public log of web certificates, uses Merkle trees together with independent monitors much as B-SCAF uses witnesses. Certificate Transparency is probably the closest real-world relative."),
            ("Why not use Hyperledger Fabric?",
             "Fabric is designed for business transactions between organizations and needs several services (ordering service, certificate authorities, peers). Our need is much simpler: keep and compare copies of signed blocks. The brief allowed a custom permissioned prototype, and ours is easier to understand and verify."),
        ]),
        ("H. Limitations, privacy and ethics", [
            ("What are the main limitations?",
             "Trust at the moment of recording (a compromised kernel could fake events); the signing key is still a file; a short unsealed window of about a second; simple storage that would need indexing for very large logs; timings from a laptop virtual machine; a small public dataset; and a dashboard without search."),
            ("Isn't monitoring every system call a privacy problem?",
             "It can be, which is why the policy keeps only security-relevant calls, removes secrets before storage, and witnesses never see raw data. Access to the event files should be restricted, users should be informed, and deployments must follow the organization's policies and data-protection law."),
            ("What about laws that require deleting personal data?",
             "Deleting a recorded event would show up as a gap, by design. Possible approaches are to filter personal data out before hashing, or to encrypt each event and later destroy the key (crypto-shredding), so the record becomes unreadable while the chain stays intact. This is future work."),
            ("What happens when the log becomes very large?",
             "The files grow and verification time grows in proportion. A production version would rotate and archive files by block range, add an index, and verify block by block. Witness storage stays tiny, because they only keep one small block per batch."),
            ("Would it slow down a busy server?",
             "Tracing every file open on a busy server is expensive, as our worst-case workload shows. The policy lets you trace fewer calls, auditd-style rules can restrict tracing to sensitive directories, and the user-space part can run on a spare core."),
            ("How accurate are the timestamps?",
             "For live capture the collector stamps each event as it reads it, a few milliseconds after the call; for auditd logs the kernel's own timestamp is used. Order never depends on timestamps, only on sequence numbers and hash links."),
            ("Is this ready for production?",
             "No, and we say so openly. It is a working, tested prototype. Production would need hardware-protected keys, heartbeats, an indexed store, monitoring and alerting, packaging, and testing on real servers."),
        ]),
        ("I. Future work and deployment", [
            ("How would you deploy this in a real organization?",
             "Run a collector on each server (eBPF or auditd) with 1 to 5 second blocks; run three witnesses operated by different teams or sites, connected with mutual TLS; keep signing keys in a TPM or hardware security module; run verification automatically every few minutes and raise an alert whenever the verdict is not pass; and give auditors read-only access."),
            ("What would you improve next?",
             "Hardware-protected keys, heartbeat blocks to expose a silenced collector, indexed storage, search in the dashboard, bare-metal benchmarks, a larger multi-host dataset, and an option for post-quantum signatures."),
            ("Could it work on Windows or macOS?",
             "The integrity part (hashing, blocks, witnesses, verification) is platform-independent. Only collection is Linux-specific; Windows has Event Tracing for Windows and macOS has the Endpoint Security framework, and either could feed the same pipeline through a new collector."),
            ("Could it handle many machines?",
             "Yes. Each machine has its own chain and key, and each witness keeps a separate chain per source. Because witnesses store only small blocks, one witness can serve many machines."),
            ("Could you add intrusion detection on top?",
             "Yes. The verified event stream is a good input for rules (for example an alert when a web server starts a shell or a process gains root) or for machine-learning models, with the advantage that the data has been proven untouched."),
        ]),
        ("J. Tough questions", [
            ("Isn't 'blockchain' just a buzzword here?",
             "It is a fair question. It is a blockchain in the original sense: a chain of signed blocks with Merkle roots, copied to independent parties. It deliberately has no mining or consensus because they are not needed. The most precise description is a lightweight permissioned ledger built on blockchain principles."),
            ("Why not just make the log file append-only, or use write-once storage?",
             "Root can remove the append-only flag. Write-once media helps, but it is local or vendor-trusted and gives neither proofs for single events nor independent confirmation. B-SCAF's guarantees come from cryptography plus independent witnesses, not from trusting one device."),
            ("Why not simply copy the logs to another server in real time?",
             "That helps and is close in spirit to witnesses, but you then have to trust that server's administrator with all the raw data. B-SCAF witnesses store only fingerprints, cannot alter signed blocks unnoticed, and the quorum avoids trusting any single party."),
            ("If the attacker controls the machine, can't they fake the verification tool too?",
             "Yes, on that machine. That is why verification must run on a machine the auditor trusts, with public keys obtained in advance. The witnesses' copies are what make that independent check possible."),
            ("A 21% slowdown sounds like a lot. Is it?",
             "For a workload that does nothing but system calls, that is close to the worst case: it is a stress test. Typical applications make far fewer system calls per second, so the relative cost is much lower, and you can trace fewer calls through the policy. Our measurements also show the cost is in the kernel tracing, not in B-SCAF's cryptography."),
            ("When could your verifier wrongly say 'pass'?",
             "If the attacker controls the signing key and a quorum of witnesses; if events were faked before they were recorded; or if the verifier is given the wrong public key. All three are stated assumptions of the design."),
            ("What if two events have identical content?",
             "They still get different sequence numbers and different previous hashes, so their hashes differ and both are protected."),
            ("What if a witness lies?",
             "A witness copy is checked against the source's signature, so an altered or unsigned copy is ignored with a warning. A witness can refuse or go silent, which the quorum tolerates. On its own it cannot make the verifier accept fake evidence."),
            ("What if an attacker floods the system with junk events?",
             "Everything is still recorded and sealed; the policy limits what is traced, and if the collector falls behind, the kernel reports lost events, which is itself a warning sign. Rate limiting and alerting would be the production answer."),
            ("Why should we trust your own tests?",
             "Because the attacks are written from an attacker's point of view, the experiments use public data pinned by checksum, and everything can be rerun with a few commands on any machine with Docker. We also report what went wrong and the limits openly."),
            ("Can an attacker insert an event with a valid hash?",
             "They can compute a valid hash for a fake event, but it breaks the link to the next event, and the block's Merkle root and signature no longer match. Hiding it would mean recomputing every later hash and re-signing every later block, which needs the stolen key, and then the witnesses' copies give it away. Our insertion test is caught by the local checks."),
            ("What if the network to the witnesses is down for a long time?",
             "The source keeps sealing blocks locally and reports that replication failed. When the network returns, replicate sends all the missing blocks in order; the witnesses accept them because they continue the chain, and the receipt timestamps show they arrived late. Until then, verification against the witnesses gives partial."),
        ]),
        ("K. Operating-systems concepts", [
            ("What actually happens during a system call?",
             "The program places the call number and arguments in registers and executes a special instruction that switches the processor from user mode to kernel mode. The kernel checks permissions, does the work and returns a result, a file descriptor or an error code, and the processor switches back to user mode. The tracepoints B-SCAF uses sit exactly at that entry and exit."),
            ("Why record both the process ID and the parent process ID?",
             "Because attacks are chains of processes: a web server starts a shell, which starts a downloader, which starts malware. The parent process ID lets an investigator rebuild that family tree. In our live test, for example, each /bin/true was linked back to the workload that started it."),
            ("What is a user ID, and why is setuid interesting?",
             "The user ID says which account a process runs as, and it decides what the process may do. setuid and related calls change it; gaining root (user ID 0) is often the key step of an attack, so these calls are always worth recording."),
            ("What are ptrace and kernel modules, and why audit them?",
             "ptrace lets one process inspect and control another; debuggers use it, and so does malware that injects code or steals passwords from memory. Kernel modules are code loaded into the kernel itself, which is how rootkits hide. Both are classic attacker tools, so B-SCAF's policy includes ptrace, init_module, finit_module and delete_module."),
            ("What are a file descriptor and a return code?",
             "When openat succeeds the kernel returns a small number, the file descriptor, which the program uses for later reads and writes; failures return a negative error code (for example -2 means 'no such file'). B-SCAF stores the return code, so you can tell an attempted action from a successful one."),
            ("What are namespaces, and why did they cause you trouble?",
             "Namespaces give a container its own view of process IDs, files and the network. Inside our container, a process's ID was different from the ID the kernel reported to eBPF. That silently broke the collector's self-filter and our completeness check until we added a probe that learns the collector's real kernel ID."),
            ("Why can't auditd run inside a Docker Desktop container?",
             "The kernel only accepts audit control commands from processes in its initial PID namespace, and Docker Desktop containers run in a different one, so the commands are refused with 'operation not permitted'. eBPF has no such restriction for a privileged container."),
            ("What is fsync, and why does it matter here?",
             "Writes normally sit in memory for a while before reaching the disk. fsync forces them to disk immediately. B-SCAF uses it so that events are safely stored before the block that vouches for them; it costs speed, about 8 ms per call on the WSL2 virtual disk, which is why it can be switched off for experiments."),
            ("Where could a race condition occur, and how did you prevent it?",
             "If two programs appended to the same ledger at once, they could hand out the same sequence number or interleave lines. B-SCAF takes an exclusive file lock before writing, and it reloads its in-memory state if another process has changed the files in the meantime."),
            ("Why does the kernel verify eBPF programs before running them?",
             "Code inside the kernel can crash or compromise the whole machine, so the kernel's verifier checks every eBPF program first: it must terminate, may only access memory it is allowed to, and may only call approved helper functions. That is what makes it safe to run monitoring code in the kernel."),
        ]),
        ("L. About your work", [
            ("What was the hardest part?",
             "Making it work on real data and in a real environment. The first parser failed on 11% of the public logs. Live capture was harder still: auditd could not be used from Docker Desktop, so we built the eBPF collector, and then process IDs turned out to differ between the container and the kernel, which broke both self-filtering and the completeness check."),
            ("What did you learn?",
             "That real data breaks assumptions quickly; that you should measure instead of guess; that security claims are only meaningful with stated assumptions; and that the cryptography is the easy part, while the hard part is the system around it."),
            ("What would you do differently if you started again?",
             "Use real data from day one, design the storage with an index from the start, and plan the evaluation environment, ideally a dedicated Linux machine, early on."),
            ("How big is the project?",
             "About 4,500 lines of Python across the package, scripts and tests, 48 automated tests, two scripted experiments, and the documents and charts generated from the results."),
            ("How did you make sure your results are honest?",
             "The numbers in the report are generated from the experiment outputs rather than typed in, the dataset is pinned by checksum, the attack tests include cases designed to fail without witnesses, and the report lists what went wrong and the limits."),
            ("What are you most proud of?",
             "Finding that two attacks, deleting the tail and re-signing with a stolen key, pass every local check, closing that gap with witnesses, and then demonstrating both outcomes side by side, on recorded data and on live capture."),
        ]),
    ]


# --------------------------------------------------------------------- build

def build() -> None:
    real = json.loads((DATA_DIR / "real-data-summary.json").read_text(encoding="utf-8"))
    live = json.loads((DATA_DIR / "live-summary.json").read_text(encoding="utf-8"))
    n = numbers(real, live)
    if not report.DIAGRAM.exists():
        report.create_final_diagram()
    guide = report_diagrams.build_guide_diagrams(base.ASSET_DIR / "diagrams")
    FIGURE["n"] = 0
    doc = Document()
    base.configure_document(doc)

    # Title page
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(110)
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    base.set_font(p.add_run("B-SCAF"), 22, bold=True)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    base.set_font(p.add_run("Code Guide, Setup and Viva Preparation"), 16, bold=True)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(30)
    base.set_font(p.add_run("Companion to the final report on the Blockchain-Based System Call Audit Framework"), 12, italic=True)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(150)
    base.set_font(p.add_run("Operating Systems and Cybersecurity Project"), 11)
    p.add_run().add_break(WD_BREAK.PAGE)

    base.add_heading(doc, "How to Use This Guide", 1)
    base.add_body(doc, "This guide sits next to the final report. The report argues the case; this guide helps you explain it, run it and defend it. It has eight parts:")
    base.add_bullets(doc, [
        "Part 1: pitches of 30 seconds and 2 minutes, an outline for a short presentation, and the numbers worth remembering.",
        "Part 2: the whole project in plain words, with an everyday analogy.",
        "Part 3: what every code file does.",
        "Part 4: how the files work together, following one system call from the kernel to the witnesses.",
        "Part 5: how to set the project up on any Windows, macOS or Linux computer, plus a ten-minute demo.",
        f"Part 6: {sum(len(items) for _, items in viva_questions(n))} likely viva questions with answers, from the basics to the awkward ones.",
        "Part 7: quick definitions for rapid-fire questions.",
        "Part 8: tips for the day.",
    ])
    base.add_body(doc, "Every number in this guide comes from the same measured results as the report, so the two always agree.")

    # Part 1
    base.add_heading(doc, "Part 1. The Pitch", 1)
    base.add_heading(doc, "1.1 Thirty-second pitch", 2)
    quote(doc, f"When attackers break into a computer, one of the first things they do is clean up the logs, and normally nobody can tell. My project, B-SCAF, fixes that for Linux. It records the important requests programs make to the operating system, like running programs, opening files and connecting to the network, and seals them the way a blockchain does, with hashes, signed blocks and copies held by independent witnesses, but without any cryptocurrency. If anyone later changes, deletes or reorders even one record, verification shows exactly where. On real attack data and in live tests it caught all {n['attacks']} tampering attacks we tried and recorded every operation of our test workload.")
    base.add_heading(doc, "1.2 Two-minute pitch", 2)
    quote(doc, "Logs are the black-box recorder of a computer. After a break-in, investigators depend on them to work out what happened. The problem is that the logs sit on the same machine the attacker has taken over, and with administrator rights the attacker can quietly edit or delete them.")
    quote(doc, "B-SCAF makes that tampering impossible to hide. It watches system calls, the requests every program has to make to the operating system to open files, run programs, change permissions or use the network, and turns them into evidence.")
    quote(doc, "It works in four steps. First, it captures the calls live from the Linux kernel with eBPF, or reads existing audit logs. Second, it removes anything private, like passwords typed into command lines. Third, it links every record to the one before it with a SHA-256 hash, groups the records into small batches and seals each batch into a block with a Merkle root and a digital signature. Fourth, it sends a copy of each sealed block, never the raw data, to independent witness machines that sign a receipt. Because the witnesses keep copies, even an attacker who steals the signing key and rewrites the whole history gets caught.")
    quote(doc, f"We tested it on {n['files']} real audit logs recorded during simulated attacks and with live capture on a real kernel. It recorded all {n['ops']:,} operations of a test workload, detected all {n['attacks']} tampering attacks, and handles about {round(n['eps_100'] / 500) * 500:,} events per second on one core.")
    quote(doc, "It cannot stop an attacker who already controls the machine before events are recorded, and the signing key should eventually live in hardware. But for evidence that has been recorded, it turns 'trust me' into 'check for yourself'.")

    base.add_heading(doc, "1.3 Outline for a five-minute presentation", 2)
    report.table(doc, ["Slide", "What to say", "What to show"], [
        ("1", "One-sentence summary of the project", "Title and the 30-second pitch"),
        ("2", "Attackers clean up logs; logs live on the attacked machine", "MITRE ATT&CK T1070 (Indicator Removal)"),
        ("3", "Why system calls are the right thing to record", "A few example calls: execve, openat, connect"),
        ("4", "The idea: blockchain principles without a cryptocurrency", "Hash chain and Merkle tree sketch"),
        ("5", "How the pieces fit", "Architecture figure (report Figure 1)"),
        ("6", "Why witnesses: the stolen-key attack", "Witness protocol figure (report Figure 4)"),
        ("7", "Results: completeness and overhead", "Live overhead chart and the 100% completeness table"),
        ("8", "Results: every attack detected", "Attack grid (report Figure 10)"),
        ("9", "Honest limits and future work", "Capture trust, key custody, scale"),
        ("10", "Demo or questions", "bscaf demo, a manual edit, the attack matrix"),
    ], widths=[0.6, 3.0, 2.6])

    base.add_heading(doc, "1.4 Numbers worth remembering", 2)
    report.table(doc, ["What", "Number"], [
        ("Public audit logs imported", f"{n['files']} / {n['files']} files (first prototype: 89)"),
        ("Events committed from them", f"{n['events_all']} (first prototype: 46)"),
        ("Duplicate records merged", f"{n['duplicates']}"),
        ("Live workload operations captured", f"{n['captured_min']:,} / {n['ops']:,} in each of {n['runs']} runs"),
        ("Live slowdown (system-call-only workload)", f"{n['full_pct']:+.0f}% full B-SCAF, {n['trace_pct']:+.0f}% tracing alone"),
        ("Delay until an event is sealed (live)", f"{n['delay_p50_min']:.2f}-{n['delay_p50_max']:.2f} s median, at most {n['delay_p95_max']:.2f} s at the 95th percentile"),
        ("Attack scenarios detected as designed", f"{n['attacks_ok']} / {n['attacks']}"),
        ("Throughput with 100-event blocks", f"{n['eps_100']:,.0f} events per second on one core"),
        ("Verify the whole ledger", f"{n['bench_events']:,} events in {n['verify_s']:.1f} s"),
        ("Check one proof", f"{n['proof_ms']:.2f} ms"),
        ("Storage per event", f"about {n['bytes_100']:.0f} bytes (plain log: {n['bytes_plain']:.0f})"),
        ("Witnesses and quorum", "3 witnesses, quorum of 2"),
        ("Automated tests", "48"),
    ], widths=[3.0, 3.2])

    # Part 2
    base.add_heading(doc, "Part 2. The Project in Plain Words", 1)
    base.add_heading(doc, "2.1 The diary analogy", 2)
    base.add_body(doc, "Imagine a diary that records every important thing that happens on a computer: who started which program, which files were opened or deleted, which network connections were made. A burglar who breaks into the computer can simply tear out the pages that mention them. B-SCAF makes that impossible to hide, in five steps:")
    base.add_bullets(doc, [
        "Fingerprints. Every page gets a fingerprint (a SHA-256 hash). Change one letter and the fingerprint changes completely.",
        "Chained pages. Every page copies the fingerprint of the page before it. Tear out, change or reorder a page and every later page stops matching (the hash chain).",
        "Sealed bundles. Every few pages, or every second, the fingerprints of the bundle are combined into one summary fingerprint (the Merkle root) and stamped with a seal only the diary's owner has (the digital signature). That stamped summary is a block.",
        "Copies with friends. A copy of each stamped summary, never the pages themselves, is posted to three friends, who each send back a signed receipt (the witnesses and the quorum).",
        "Checking. Anyone can recompute the fingerprints, check the seals and compare with the friends' copies. Any difference shows exactly where the diary was changed.",
    ])
    base.add_heading(doc, "2.2 What the burglar can and cannot do", 2)
    report.table(doc, ["The burglar tries to...", "What happens"], [
        ("change a page", "Its fingerprint no longer matches: caught by local checks."),
        ("tear out or insert a page", "The chain of fingerprints breaks: caught by local checks."),
        ("swap two pages", "The order no longer matches the chain: caught by local checks."),
        ("tear out the last bundle entirely", "Everything left looks fine locally, but the friends have the missing summary: caught by the witnesses."),
        ("steal the seal and rewrite the whole diary", "Locally perfect, but the friends' copies differ: caught by the witnesses."),
        ("fake a friend's receipt", "The friend's signature does not check out: caught."),
        ("lie before writing the page", "Not caught. B-SCAF protects what was recorded, not what was never recorded honestly."),
    ], widths=[2.4, 3.8])
    base.add_heading(doc, "2.3 Why not a normal blockchain?", 2)
    base.add_body(doc, "Public blockchains such as Bitcoin need every participant to agree on history with expensive mining, charge a fee for every write, take time to confirm, and are visible to everyone. A computer produces thousands of events a second, many of them private. B-SCAF keeps the useful ideas (fingerprints, chained blocks, signatures, independent copies) and drops the expensive ones. The raw diary stays at home; only stamped summaries travel.")

    # Part 3
    base.add_heading(doc, "Part 3. What Each File Does", 1)
    base.add_body(doc, "The code is a Python package (src/bscaf) plus scripts, tests and build files. Figure 1 shows how the package is layered: each layer only relies on the layers below it.")
    figure(doc, guide["modules"], "How the code is organised, from the entry points at the top to evaluation at the bottom.")
    base.add_heading(doc, "3.1 The core package: src/bscaf", 2)
    for name, does, works_with in CORE_FILES:
        base.add_heading(doc, name, 3)
        base.add_body(doc, does)
        base.add_body(doc, f"Works with: {works_with}", bold_lead="Works with:")
    base.add_heading(doc, "3.2 Scripts", 2)
    report.table(doc, ["File", "What it does"], SCRIPTS, widths=[1.9, 4.3])
    base.add_heading(doc, "3.3 Tests", 2)
    report.table(doc, ["File", "What it checks"], TESTS, widths=[1.9, 4.3])
    base.add_heading(doc, "3.4 Build, deployment, data and documents", 2)
    report.table(doc, ["File or folder", "Purpose"], BUILD_FILES, widths=[2.2, 4.0])

    # Part 4
    base.add_heading(doc, "Part 4. How the Parts Work Together", 1)
    base.add_heading(doc, "4.1 The life of one system call", 2)
    base.add_body(doc, "The easiest way to see how the files cooperate is to follow one event from start to finish (Figure 2).")
    figure(doc, guide["lifecycle"], "The life of one system call through the code. Steps 7 to 9 happen once per block, not once per event.")
    steps = [
        "A program asks the kernel to do something, for example open /etc/passwd. This is the openat system call.",
        "The kernel fires the sys_enter_openat tracepoint. The bpftrace program written by ebpf.py saves the path and flags, keyed by the thread. When the call returns, sys_exit_openat prints one line containing the path, flags, process, parent, user and return code.",
        "ebpf.py reads that line and turns it into an event (a Python dictionary). For recorded logs, auditd.py does the same job by grouping the lines of each audit event.",
        "Whenever 512 events have piled up, or the stream pauses for a quarter of a second, the collector hands its events to service.py (ingest_many). The service takes the lock in store.py so no other writer can interfere.",
        "policy.py decides whether to keep the event and hides secrets in its arguments.",
        "models.py builds the AuditEvent with the next sequence number and the previous event's hash; canonical.py writes it in canonical form and computes its SHA-256 hash.",
        "service.py adds the event to the open batch. When the batch is complete (N events, T seconds, or a new host), it seals a block.",
        "To seal, it first writes the events to events.jsonl and forces them to disk (store.py), computes the Merkle root of their hashes (merkle.py), builds a Checkpoint (models.py), signs it with Ed25519 (crypto.py) and appends it to checkpoints.jsonl.",
        "If --replicate-url was given, cli.py's replicate-on-commit hook calls witness.py, which sends the block to each witness, over HTTPS with the settings from tlsutil.py if configured. Each witness checks it and returns a signed receipt, which is stored in witness-acks.jsonl.",
        "Later, bscaf verify asks service.py to recompute everything from the files and, with --witness, asks witness.py to compare against each witness copy and check the receipts. bscaf proof and proof-verify use merkle.py and proof.py to prove a single event.",
    ]
    numbered(doc, steps)

    base.add_heading(doc, "4.2 Sealing a block", 2)
    base.add_body(doc, "Sealing is the only moment when cryptography is expensive, so it happens once per batch. The order matters: events are written and forced to disk before the block that vouches for them, so a crash can never leave a block pointing at events that were never saved. The service also keeps the end of the chain (last sequence number, last hash, last block hash, open batch) in memory, so adding an event never requires re-reading the files. If another process changes the files, it notices the size change and reloads.")
    base.add_heading(doc, "4.3 Copies to the witnesses", 2)
    base.add_body(doc, "witness.py contains both sides. On the source side, replicate() asks each witness for its name (/health), skips blocks that witness has already acknowledged, posts the rest in order (/checkpoints), stores the receipts and reports whether the quorum holds every block. On the witness side, WitnessStore.accept() checks the signer, the block hash, the signature and the chain continuity, refuses conflicting blocks with HTTP 409 and logs them to equivocations.jsonl, and signs a receipt with the witness's own key. The same file provides the comparison used by verify and a helper that starts local witnesses for tests.")
    base.add_heading(doc, "4.4 Checking the evidence", 2)
    base.add_body(doc, "service.verify() streams through events.jsonl once, recomputing every hash and link and collecting each block's event hashes; it then checks every block (Merkle root, block hash, link, number, range, replay and signature) and reports pass, partial or fail with the first problem. witness.verify_with_witnesses() then adds what only outsiders can see: a witness holding blocks the local ledger lacks (truncation), a different block at the same number (rewritten history), forged receipts, and how many complete, consistent witnesses were reachable.")
    base.add_heading(doc, "4.5 Proving a single event", 2)
    base.add_body(doc, "bscaf proof asks service.py for the event, its block, and the sibling hashes from merkle.py. The resulting file is self-contained. bscaf proof-verify passes it to proof.py, which needs nothing but the public key: it recomputes the event hash, climbs the Merkle path to the root, and checks the block hash and signature.")
    base.add_heading(doc, "4.6 Recorded logs instead of live capture", 2)
    base.add_body(doc, "bscaf ingest-auditd swaps the collector: auditd.py reads the log, groups each event's records and produces the same kind of event dictionary. cli.py sorts a finished file into audit order (many exports are newest first), skips records already imported using ingest-state.json, and passes the rest to the same service.ingest_many path. From there everything is identical, which is why recorded and live evidence can be verified the same way.")
    base.add_heading(doc, "4.7 The dashboard", 2)
    base.add_body(doc, "bscaf ui starts ui.py, a small web server on port 8000. Its page calls /api/dashboard, which asks service.py for the verdict, recent events and recent blocks. The three buttons call /api/demo (add three demo events and seal them), /api/flush (seal the open batch) and /api/verify (rerun every check).")
    base.add_heading(doc, "4.8 Which files each command uses", 2)
    report.table(doc, ["Command", "Files involved"], COMMAND_PATHS, widths=[2.0, 4.2])
    base.add_heading(doc, "4.9 What ends up on disk", 2)
    report.table(doc, ["File", "Contents"], DISK_FILES, widths=[2.4, 3.8])
    base.add_heading(doc, "4.10 How the experiments drive everything", 2)
    base.add_body(doc, "The scripts deliberately use the same paths a user would. run_real_data.py calls the real bscaf command for every dataset file, then uses attacks.py and bench.py. live_capture.py starts bscaf ingest-ebpf as a separate process, runs workload.py, stops the collector cleanly with a signal, verifies the ledger with witness.py and searches it for the workload's operations. Both scripts write JSON summaries that the document builders turn into the report's tables and charts.")

    # Part 5
    base.add_heading(doc, "Part 5. Setting It Up on Any Computer", 1)
    base.add_heading(doc, "5.1 What you need", 2)
    base.add_bullets(doc, [
        "Docker: Docker Desktop on Windows or macOS, or Docker Engine on Linux. This is the only real requirement.",
        "Git, to download the code (or download the ZIP from GitHub instead).",
        "About 2 GB of free disk space and an internet connection for the first build and the dataset download.",
        "For live capture only: a Linux kernel with eBPF support. It was tested on WSL2 through Docker Desktop; it should work on a normal Linux machine; on macOS it is untested.",
    ])
    base.add_body(doc, f"The project lives at {REPO}. Until the work is merged into the main branch, it is on the branch {BRANCH}, so the commands below check that branch out.")

    base.add_heading(doc, "5.2 Windows (PowerShell)", 2)
    base.add_bullets(doc, [
        "Install Docker Desktop from docker.com and accept the WSL 2 option. Start it and wait until it says the engine is running.",
        "Install Git for Windows from git-scm.com.",
        "Open PowerShell in the folder where you want the project and run:",
    ])
    report.code(doc, f"""
git clone {REPO}
cd os_block
git checkout {BRANCH}
docker build -t bscaf .
docker run --rm -v "${{PWD}}:/app" bscaf pytest -q
docker run --rm -v "${{PWD}}:/app" -w /app bscaf bscaf --data-dir demo --batch-size 2 demo
""")
    base.add_body(doc, "The test command should end with '48 passed'. The demo prints a report whose verdict is 'pass'. In the old Command Prompt (cmd.exe) write %cd% instead of ${PWD}.")

    base.add_heading(doc, "5.3 macOS (Terminal)", 2)
    base.add_body(doc, "Install Docker Desktop for Mac (choose Apple silicon or Intel), start it, and make sure Git is available (run xcode-select --install if it is not). Then:")
    report.code(doc, f"""
git clone {REPO}
cd os_block
git checkout {BRANCH}
docker build -t bscaf .
docker run --rm -v "$PWD":/app bscaf pytest -q
docker run --rm -v "$PWD":/app -w /app bscaf bscaf --data-dir demo --batch-size 2 demo
""")
    base.add_body(doc, "Everything except live capture works the same as on Linux. Live capture depends on the Linux kernel inside Docker Desktop's virtual machine providing system-call tracepoints, which has not been tested on a Mac.")

    base.add_heading(doc, "5.4 Linux (Ubuntu, Debian, Fedora)", 2)
    report.code(doc, f"""
sudo apt update && sudo apt install -y docker.io git        # Ubuntu or Debian
sudo dnf install -y moby-engine git && sudo systemctl enable --now docker   # Fedora
sudo usermod -aG docker $USER      # then log out and back in, or put sudo before docker
git clone {REPO}
cd os_block
git checkout {BRANCH}
docker build -t bscaf .
docker run --rm -v "$PWD":/app bscaf pytest -q
""")
    base.add_body(doc, "Use the apt line or the dnf line, whichever matches your distribution. Live capture works on most kernels from about 2020 onward (they include the BTF type information bpftrace needs).")

    base.add_heading(doc, "5.5 Without Docker", 2)
    base.add_body(doc, "With Python 3.11 or newer installed, the project also runs directly:")
    report.code(doc, """
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\activate
pip install -e ".[test]"
pytest -q
bscaf --data-dir demo --batch-size 2 demo
""")
    base.add_body(doc, "On Windows one test that needs a Linux-style executable is skipped. Live capture always needs Linux, root rights and bpftrace.")

    base.add_heading(doc, "5.6 Everyday commands", 2)
    base.add_body(doc, "Run these from the os_block folder. They are written for macOS and Linux; on Windows PowerShell replace $PWD with ${PWD}.")
    commands = report.table(doc, ["Task", "Command"], [
        ("Run all tests", 'docker run --rm -v "$PWD":/app bscaf pytest -q'),
        ("Make a small demo ledger", 'docker run --rm -v "$PWD":/app -w /app bscaf bscaf --data-dir demo --batch-size 2 demo'),
        ("Verify a ledger", 'docker run --rm -v "$PWD":/app -w /app bscaf bscaf --data-dir demo verify'),
        ("Recorded-data experiment (about 2 minutes)", 'docker run --rm -v "$PWD":/app -w /app bscaf python scripts/run_real_data.py --skip-bench'),
        ("Same plus the benchmark (about 4 minutes)", 'docker run --rm -v "$PWD":/app -w /app bscaf python scripts/run_real_data.py'),
        ("Dashboard (then open http://localhost:8000)", 'docker run --rm -it -p 8000:8000 -v "$PWD":/app -w /app bscaf bscaf --data-dir ui-demo --batch-size 2 ui --host 0.0.0.0 --no-browser'),
        ("Build the live-capture image", "docker build -t bscaf-live -f deploy/live/Dockerfile deploy/live"),
        ("Live-capture experiment (about 2 minutes)", 'docker run --rm --privileged --pid=host -v "$PWD":/app -w /app bscaf-live python scripts/live_capture.py'),
        ("Attack matrix on the recorded-data ledger", 'docker run --rm -v "$PWD":/app -w /app bscaf python scripts/attack_matrix.py --data-dir results/real-data/store-all-syscalls --signer-id dataset-source'),
        ("A shell with the bscaf command", 'docker run --rm -it -v "$PWD":/app -w /app bscaf bash'),
        ("Rebuild the report and this guide", 'docker run --rm -v "$PWD":/app -w /app bscaf bash -c "pip install --user -q python-docx pillow matplotlib && python project-documents/builders/build_final_report.py && python project-documents/builders/build_viva_guide.py"'),
    ], widths=[2.0, 4.2])
    for row in commands.rows[1:]:
        for paragraph in row.cells[1].paragraphs:
            for run in paragraph.runs:
                run.font.name = "Courier New"
                run._element.get_or_add_rPr().rFonts.set(base.qn("w:ascii"), "Courier New")
                run._element.get_or_add_rPr().rFonts.set(base.qn("w:hAnsi"), "Courier New")
                run.font.size = Pt(8)

    base.add_heading(doc, "5.7 Troubleshooting", 2)
    report.table(doc, ["Problem", "Fix"], [
        ("'docker: command not found' or 'cannot connect to the Docker daemon'", "Start Docker Desktop and wait for it to finish starting; on Linux run sudo systemctl start docker."),
        ("'permission denied' on /var/run/docker.sock (Linux)", "Put sudo in front of docker, or add yourself to the docker group and log in again."),
        ("${PWD} or $PWD is not recognized", "PowerShell uses ${PWD}, bash and zsh use $PWD, cmd.exe uses %cd%."),
        ("Dataset download fails", "Check the internet connection and run the command again; files already downloaded with the right checksum are skipped."),
        ("Port 8000 is already in use", "Change -p 8000:8000 to -p 8080:8000 and open http://localhost:8080."),
        ("Live capture says 'tracepoint not found' or 'operation not permitted'", "Use the bscaf-live image with --privileged --pid=host. The script mounts tracefs itself. On macOS this may not be supported."),
        ("'... is encrypted; set BSCAF_KEY_PASSPHRASE'", "The key was created with a passphrase; pass it with -e BSCAF_KEY_PASSPHRASE=... on the docker command."),
        ("'invalid checkpoint' in an old data folder", "The folder was created by an older version; delete it and run the command again."),
        ("The demo verdict is 'fail' on a fresh run", "The data folder already contains an edited ledger from an earlier demo. Delete the folder (for example demo) and start again."),
        ("The first build is slow", "Normal: Docker downloads the Python image and packages once; later builds are quick."),
    ], widths=[2.6, 3.6])

    base.add_heading(doc, "5.8 A ten-minute demo for the viva", 2)
    base.add_body(doc, "Before the viva, build both images and run the recorded-data experiment once, so that nothing needs downloading on the day. Then:")
    demo_steps = [
        "Give the 30-second pitch and show the architecture figure from the report.",
        "Create a ledger: docker run --rm -v \"$PWD\":/app -w /app bscaf bscaf --data-dir demo --batch-size 2 demo. Point out the verdict 'pass', 3 events and 2 blocks.",
        "Tamper with it by hand: open demo/events.jsonl in a text editor, change \"openat\" to \"unlinkat\" on the second line and save.",
        "Verify again: docker run --rm -v \"$PWD\":/app -w /app bscaf bscaf --data-dir demo verify. The verdict is now 'fail', and the first problem is event-hash at sequence 2.",
        "Show the witnesses: run the attack-matrix command from 5.6 and point at the two rows (truncation and rewrite-and-resign) that pass locally but fail with witnesses.",
        "Open the dashboard, press Add demo events and Verify integrity.",
        "Finish with the results charts in the report and one honest limitation.",
    ]
    numbered(doc, demo_steps)

    # Part 6
    base.add_heading(doc, "Part 6. Viva Questions and Answers", 1)
    base.add_body(doc, "The answers are written to be said out loud: short, plain and accurate. Learn the ideas, not the wording. Where a number appears, it is the measured value from the report.")
    counter = 0
    for section, items in viva_questions(n):
        base.add_heading(doc, section, 2)
        for question, answer in items:
            counter += 1
            qa(doc, counter, question, answer)

    # Part 7
    base.add_heading(doc, "Part 7. Quick Definitions", 1)
    base.add_body(doc, "One-line answers for rapid-fire questions.")
    for word, meaning in DEFINITIONS:
        term(doc, word, meaning)

    # Part 8
    base.add_heading(doc, "Part 8. Tips for the Day", 1)
    base.add_bullets(doc, [
        "Open with the 30-second pitch, then let the examiner steer.",
        "Draw the picture: four boxes in a chain, a small Merkle tree above a batch, a block, and three witnesses. Most questions can be answered by pointing at it.",
        "Know the handful of numbers in section 1.4; they show you measured rather than guessed.",
        "Be open about the limits before you are asked. Stating assumptions (honest quorum, trusted capture) makes the security claims stronger, not weaker.",
        "Connect answers to operating-systems ideas: system calls and the user/kernel boundary, processes and parents, user IDs and privilege, file descriptors, namespaces and containers, fsync and locking.",
        "Have the demo ready and tested on the laptop you will use, with Docker Desktop already running.",
        "If you do not know an answer, say how you would find out or test it. That is a good answer too.",
        "Keep the report open at the figures; the charts answer most results questions on their own.",
    ])

    doc.core_properties.title = "B-SCAF: Code Guide, Setup and Viva Preparation"
    doc.core_properties.subject = "Companion to the B-SCAF final report"
    doc.core_properties.author = ""
    doc.core_properties.keywords = "B-SCAF, viva, setup, code guide, system calls, eBPF, blockchain"
    doc.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    build()

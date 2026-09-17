# B-SCAF prototype

This is the first working slice of the **Blockchain-Based System Call Audit Framework** described in the project proposal. It is deliberately lightweight: raw events are kept locally, while hashes, Merkle roots and signed checkpoints provide tamper evidence.

## Implemented in this milestone

- Canonical system-call event normalization and validation.
- SHA-256 hash chain across events.
- Fixed-size Merkle batches with inclusion-proof generation.
- Ed25519-signed checkpoint ledger stored as JSON Lines.
- Offline verifier that detects modified, deleted, inserted or reordered events.
- A JSONL ingestion interface that can later be fed by auditd/eBPF collectors.

It does **not** yet collect kernel events directly. The `ingest` command is intentionally the integration boundary for an auditd/eBPF adapter, which is a later milestone.

## Quick start (PowerShell)

```powershell
$py = "C:\Users\adity\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
& $py -m pip install -e .
& $py -m bscaf --data-dir .\audit-data init
& $py -m bscaf --data-dir .\audit-data demo
& $py -m bscaf --data-dir .\audit-data verify
```

The final command prints a JSON integrity report. A clean run returns `valid: true`.

To ingest your own newline-delimited JSON events:

```powershell
& $py -m bscaf --data-dir .\audit-data ingest --input .\samples\events.jsonl
& $py -m bscaf --data-dir .\audit-data flush
```

Each event needs `syscall`, `pid`, `ppid`, `uid`, and `timestamp` (ISO-8601 UTC). Optional `arguments`, `return_code`, `host_id` and `process` fields are supported.

## Demonstrating the complete evidence flow

1. Ingest an event stream and flush its final partial batch.
2. Export a proof for a committed event.
3. Verify that proof from the exported JSON and the source public key.

```powershell
& $py -m bscaf --data-dir .\audit-data proof --sequence 1 | Out-File -Encoding utf8 .\proof.json
& $py -m bscaf --data-dir .\audit-data proof-verify --input .\proof.json --public-key .\audit-data\signing-public.pem
```

For a Linux auditd source, first configure audit rules appropriate to the host and export raw audit records. The adapter accepts `type=SYSCALL` lines:

```powershell
& $py -m bscaf --data-dir .\audit-data ingest-auditd --input .\samples\auditd-syscall.log --host-id lab-host
```

### Independent witness node

On the witness machine, trust the source node's public key once, then run the small HTTP witness service:

```powershell
& $py -m bscaf witness-trust --witness-dir .\witness-data --trusted-signer-id local-witness --public-key .\audit-data\signing-public.pem
& $py -m bscaf witness-serve --witness-dir .\witness-data --host 127.0.0.1 --port 8080
```

On the source machine, replicate signed checkpoint blocks only:

```powershell
& $py -m bscaf --data-dir .\audit-data replicate --url http://127.0.0.1:8080
```

The witness never receives raw events. It rejects unknown signers, modified blocks and invalid signatures.

## Minimal demonstration UI

Start the local black-and-white dashboard:

```powershell
$env:PYTHONPATH = "src"
& $py -m bscaf.cli --data-dir .\audit-data-ui --batch-size 2 ui
```

The browser opens at `http://127.0.0.1:8000`. Use **Add demo events** to create and commit a three-event audit trail. The dashboard then displays the integrity verdict, event count, checkpoint count, problems, recent system calls, and checkpoint hashes. Use **Verify integrity** to rerun all chain, Merkle-root, block-link, and signature checks.

The UI uses only Python's standard-library HTTP server and embedded HTML/CSS/JavaScript; it introduces no web-framework or frontend dependency. It binds to localhost by default and is intended for demonstration. Use `--no-browser` on a headless Linux machine.

## Command summary

| Command | Purpose |
| --- | --- |
| `init` | Create event/checkpoint stores and an Ed25519 key pair. |
| `ingest` / `ingest-auditd` | Add selected JSONL events or raw auditd SYSCALL records. |
| `flush` | Commit a final partial batch. |
| `verify` / `status` | Verify event links, batch roots, block links and signatures. |
| `proof` / `proof-verify` | Export and independently verify one committed event's proof. |
| `witness-trust`, `witness-serve`, `replicate` | Set up and use a permissioned checkpoint witness. |
| `ui` | Run the minimal local integrity dashboard. |

## Security scope

B-SCAF makes post-commit changes to its local event store evident when the signing public key and checkpoint ledger remain protected. It cannot prove that a fully compromised kernel did not fabricate an event before collection. Production use needs protected private-key storage, remote witness replication, access control and a real auditd/eBPF collector.

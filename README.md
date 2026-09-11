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
& $py -m bscaf init --data-dir .\audit-data
& $py -m bscaf demo --data-dir .\audit-data
& $py -m bscaf verify --data-dir .\audit-data
```

The final command prints a JSON integrity report. A clean run returns `valid: true`.

To ingest your own newline-delimited JSON events:

```powershell
& $py -m bscaf ingest --data-dir .\audit-data --input .\events.jsonl
& $py -m bscaf flush --data-dir .\audit-data
```

Each event needs `syscall`, `pid`, `ppid`, `uid`, and `timestamp` (ISO-8601 UTC). Optional `arguments`, `return_code`, `host_id` and `process` fields are supported.

## Security scope

B-SCAF makes post-commit changes to its local event store evident when the signing public key and checkpoint ledger remain protected. It cannot prove that a fully compromised kernel did not fabricate an event before collection. Production use needs protected private-key storage, remote witness replication, access control and a real auditd/eBPF collector.

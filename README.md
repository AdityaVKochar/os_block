# B-SCAF prototype

Working prototype of the **Blockchain-Based System Call Audit Framework** described in the project brief (`project-documents/`). Raw system-call events stay in a local store; SHA-256 hash chains, Merkle batch roots, Ed25519-signed checkpoint blocks and a quorum of independent witnesses make any later change to committed evidence detectable.

It has been validated end to end on 100 real Linux auditd logs from the public [Splunk Attack Data](https://github.com/splunk/attack_data) repository; see [`docs/ARCHITECTURE_AND_DEMO.md`](docs/ARCHITECTURE_AND_DEMO.md) and the generated `results/REAL_DATA_REPORT.md`. What is finished and what remains is tracked in [`docs/REMAINING_WORK.md`](docs/REMAINING_WORK.md).

## What it does

- **Collection adapter** for real auditd output: raw `audit.log`, ENRICHED logs, `node=` prefixes and `ausearch -i` exports. SYSCALL, EXECVE, PATH, CWD, SOCKADDR and PROCTITLE records of one kernel event are merged, so events carry argv, file paths and socket destinations. Per-architecture syscall tables (x86_64, aarch64, i386), streaming input (`-`, `.gz`), `--follow` with log rotation, and de-duplication on re-ingest.
- **Privacy policy**: an allow-list of security-relevant system calls, redaction of secret-looking keys and inline `--password=…` style arguments, truncation, and a policy version recorded in every block.
- **Evidence chain**: each event's hash covers the previous event's hash; blocks close every N events, every T seconds of event time, or on a host change, and commit a Merkle root, time window and policy version under an Ed25519 signature.
- **Verification** that names the first invalid item: altered, missing, inserted or reordered events, changed roots or blocks, invalid signatures, replayed or out-of-range blocks. Verdicts are `pass`, `fail` or `partial` (evidence not yet committed or witness quorum unreachable).
- **Witness quorum**: witnesses accept only blocks that extend the chain they hold, refuse and record conflicting blocks, and return signed acknowledgements. `verify --witness` compares the local ledger with each witness copy, which detects tail truncation and history re-signed with a stolen source key, both invisible to local checks.
- **Portable proofs**: one event's Merkle path plus its signed block, verifiable with only the public key.
- **Evaluation harness** comparing plain logging, a hash chain alone and B-SCAF (throughput, latency, commit delay, CPU, memory, storage, verification and replication time).
- A small dependency-free **dashboard**.

## Run it in a container (nothing to install on the host)

```bash
sudo docker build -t bscaf .
```

```bash
sudo docker run --rm -v "$PWD":/app bscaf pytest -q
```

```bash
sudo docker run --rm -v "$PWD":/app -w /app bscaf python scripts/run_real_data.py
```

The last command downloads the pinned dataset (about 1.5 MB, SHA-256 checked), ingests it, verifies it, exercises proofs, witnesses and every attack scenario, benchmarks 100,000 replayed events, and writes `results/REAL_DATA_REPORT.md`. Add `--skip-bench` for a two-minute run. (Without `sudo`, add your user to the `docker` group once.)

For an interactive shell with the `bscaf` command available:

```bash
sudo docker run --rm -it -v "$PWD":/app -w /app -p 8000:8000 bscaf bash
```

## Quick start

```bash
bscaf --data-dir audit-data init
bscaf --data-dir audit-data demo
bscaf --data-dir audit-data verify
```

`python -m bscaf …` is equivalent. Outside the container, `pip install -e .[test]` with Python 3.11+.

Ingest your own data:

```bash
bscaf --data-dir audit-data ingest --input samples/events.jsonl
bscaf --data-dir audit-data ingest-auditd --input /var/log/audit/audit.log --host-id web-01
bscaf --data-dir audit-data flush
```

JSONL events need `syscall`, `pid`, `ppid`, `uid` and an ISO-8601 `timestamp` with a timezone; `arguments`, `return_code`, `host_id` and `process` are optional. On a live Linux host, load `deploy/audit/bscaf.rules` and tail the log with `ingest-auditd --follow --batch-seconds 5`.

Export and check one event's proof:

```bash
bscaf --data-dir audit-data proof --sequence 1 > proof.json
bscaf proof-verify --input proof.json --public-key audit-data/signing-public.pem
```

## Witnesses

On each witness machine:

```bash
bscaf witness-init --witness-dir witness-1 --witness-id witness-1
bscaf witness-trust --witness-dir witness-1 --trusted-signer-id local-witness --public-key signing-public.pem
bscaf witness-serve --witness-dir witness-1 --host 0.0.0.0 --port 8080
```

On the source, replicate to all witnesses and verify against them (copy each `witness-public.pem` to the auditor first):

```bash
bscaf --data-dir audit-data replicate --url http://w1:8080 --url http://w2:8080 --url http://w3:8080 --quorum 2
bscaf --data-dir audit-data verify --witness http://w1:8080 --witness http://w2:8080 --witness http://w3:8080 --witness-key witness-1=w1.pem --witness-key witness-2=w2.pem --witness-key witness-3=w3.pem --quorum 2
```

Witnesses receive signed checkpoint metadata only, never raw events.

## Commands

| Command | Purpose |
| --- | --- |
| `init` | Create the event and checkpoint stores and an Ed25519 key pair. |
| `ingest` / `ingest-auditd` | Add JSONL events, or auditd logs (`--follow`, `--strict`, `--assume-tz`, `--no-dedupe`). |
| `flush` | Commit the pending partial batch. |
| `verify` / `status` | Verify chain, roots, block links, ranges and signatures; with `--witness`, also against witnesses. |
| `proof` / `proof-verify` | Export and independently verify one committed event's proof. |
| `policy` | Print the effective policy and its version. |
| `witness-init`, `witness-trust`, `witness-serve`, `replicate` | Run witnesses and replicate to a quorum. |
| `bench` | Run the Phase 6 performance comparison. |
| `ui` | Run the local dashboard (`--host 0.0.0.0 --no-browser` inside a container). |

Global options: `--batch-size N`, `--batch-seconds T`, `--policy file.json`, `--all-syscalls`, `--signer-id`, `--no-fsync` (benchmarks only).

Data directories created before this version use an older checkpoint format and must be recreated.

## Security scope

B-SCAF makes changes to committed evidence detectable as long as the source public key is trusted and a quorum of witnesses is honest and reachable. It cannot prove that a compromised kernel or collector did not fabricate or drop events before collection, and events not yet in a block are only protected once committed. Production use still needs protected key storage, authenticated transport between nodes and a live-host evaluation; see `docs/REMAINING_WORK.md`.

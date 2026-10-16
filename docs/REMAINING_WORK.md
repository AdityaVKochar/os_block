# Status against the project brief

Status as of 16 October 2026. Evidence:

- `results/REAL_DATA_REPORT.md` from `scripts/run_real_data.py` (public auditd dataset);
- `results/LIVE_REPORT.md` from `scripts/live_capture.py` (live eBPF capture);
- summarized in [`RESULTS.md`](RESULTS.md) and in the final report `project-documents/Blockchain_System_Call_Audit_Framework_Final_Report.docx`.

Legend: **Done**: implemented and tested. **Partial**: works, with the stated gap.

## Objectives

| Brief item | Status | Evidence |
| --- | --- | --- |
| Obj. 1: capture selected system calls with PID, PPID, UID, timestamp, return status, selected arguments | **Done** | The live eBPF collector (`ingest-ebpf`, `src/bscaf/ebpf.py`) captured 100% of a repeatable workload's operations in every run. The auditd adapter ingests all 100 public logs. |
| Obj. 2: hash-linked events, short batches, Merkle root, signature, permissioned checkpoint ledger | **Done** | `service.py`, `merkle.py`, `crypto.py`. Blocks close on N events, T seconds or a host change. |
| Obj. 3: independent verifier with pass / fail / partial-evidence report | **Done** | Local and witness verification name the first invalid item. Offline proofs need only the public key. |
| Obj. 4: throughput, commit delay, CPU, memory, storage, verification time | **Done** | Live: workload slowdown, collector CPU, commit delay and lost events. Replay: events/s, latency, RSS, bytes/event, verify and replication time. |

## Methodology phases

| Phase | Status | Notes |
| --- | --- | --- |
| 1. Requirements and threat model | **Done** | `ARCHITECTURE_AND_DEMO.md` §2 and report §4. |
| 2. System-call acquisition and canonicalization | **Done** | eBPF tracepoints live; auditd raw, ENRICHED, `node=` and `ausearch -i` offline or `--follow`. |
| 3. Local evidence construction (N events or T seconds) | **Done** | `--batch-size`, `--batch-seconds`. |
| 4. Checkpoints replicated to 3–5 permissioned verifiers | **Done** | Quorum replication, chain continuity, equivocation refusal, signed acks, HTTPS with mutual TLS, push-on-commit. |
| 5. Attack tests | **Done** | 12/12 scenarios as designed on the real-data ledger and on the live ledger. |
| 6. Evaluation against plain logging and hash-chain-only logging | **Done** | Live (no tracing / tracing only / B-SCAF) and replay (plain / hash chain / B-SCAF). |

## Block fields (brief §8)

All are present: `block_number`, `previous_block_hash`, `batch_id`, `merkle_root`, `host_id`, `time_window_start`/`time_window_end`, `event_count`, `policy_version`, `signer_id` and `signature`. `witness_acks` are stored in `witness-acks.jsonl` beside the ledger, because acknowledgements arrive after the block is signed. Each one is signed by its witness.

## Expected outcomes (brief §9)

| Outcome | Status |
| --- | --- |
| Prototype that collects system calls and produces verifiable batches | **Done** (eBPF live and auditd) |
| Every tested modification to committed evidence is detected | **Done** |
| Dashboard or CLI report with an understandable verdict | **Done** (CLI, dashboard, `search`) |
| Measured overhead profile and documented limits | **Done** |
| Reproducible dataset, threat model and evaluation scripts | **Done** (pinned manifest, `run_real_data.py`, `live_capture.py`, `bscaf bench`) |

## Known limits (future work, not required by the brief)

1. **Capture trust.** A compromised kernel or collector can fabricate or drop events before capture. Remote attestation or measured boot would reduce this, which the brief itself notes.
2. **Key custody.** Keys can be encrypted (`BSCAF_KEY_PASSPHRASE`) but remain files. A stolen source key is detected only through the witnesses. A TPM or HSM would prevent the theft.
3. **Unprotected window.** Events become tamper-evident once their block is signed and replicated: within 1 s in the live runs, using `--batch-seconds 1 --replicate-url`.
4. **Scale.** `verify` keeps one hash per event in memory, `proof` scans the event file, and the JSONL store has no archival. Very large ledgers would need an indexed store.
5. **auditd live mode.** It works on a normal Linux host (`deploy/audit/bscaf.rules`, `ingest-auditd --follow`). It cannot run from Docker Desktop on WSL2, because the kernel accepts audit control only from its initial PID namespace, so live results here come from eBPF.
6. **Environment.** Timings are from WSL2. Bare-metal numbers would be lower-noise. The public auditd sample is small and mostly exports one record type per file.
7. **Dashboard.** It shows recent events and the verdict. Search is in the CLI only, and there is no role-based access.

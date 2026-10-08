# Status against the project brief

Status as of 8 October 2026, after validation on the public Splunk Attack Data auditd logs (`results/REAL_DATA_REPORT.md`, produced by `scripts/run_real_data.py`).

Legend: **Done**: implemented and tested. **Partial**: works, with the stated gap. **Open**: not started.

## Objectives

| Brief item | Status | Evidence / gap |
| --- | --- | --- |
| Obj. 1: capture selected system calls with PID, PPID, UID, timestamp, return status, selected arguments | **Partial** | auditd adapter handles raw, ENRICHED, `node=` and `ausearch -i` logs and merges EXECVE/PATH/CWD/SOCKADDR/PROCTITLE records (`src/bscaf/auditd.py`, `tests/test_auditd_real.py`). Audit rules ship in `deploy/audit/bscaf.rules`, and `ingest-auditd --follow` tails a rotating log. **Gap:** not yet run against a live auditd daemon, and there is no eBPF collector. |
| Obj. 2: hash-linked events, short batches, Merkle root, signature, permissioned checkpoint ledger | **Done** | `service.py`, `merkle.py`, `crypto.py`. Batches close on N events, T seconds of event time, or a host change. |
| Obj. 3: independent verifier with pass / fail / partial-evidence report | **Done** | `verify` names the first invalid item. `verify --witness` adds witness comparison and ack checks. Exported proofs verify with only the public key. |
| Obj. 4: throughput, capture-to-commit delay, CPU, memory, storage, verification time | **Partial** | `bscaf bench` measures all of these on replayed real events (Performance section of the report). **Gap:** no live-host run, so auditd's own kernel overhead and real workload CPU impact are not measured. |

## Methodology phases

| Phase | Status | Notes |
| --- | --- | --- |
| 1. Requirements and threat model | **Done** | `docs/ARCHITECTURE_AND_DEMO.md` §2 states the assets, attacker abilities and the capture-trust limitation. |
| 2. System-call acquisition and canonicalization | **Partial** | Same as Objective 1: offline and `--follow` ingestion only. Canonical JSON plus a versioned policy make equivalent events hash identically. |
| 3. Local evidence construction (every N events or T seconds) | **Done** | `--batch-size`, `--batch-seconds`. |
| 4. Checkpointing replicated to 3–5 permissioned verifiers | **Done** (prototype) | Witnesses enforce chain continuity, record equivocations and sign acks; `replicate --quorum`. Transport is plain HTTP (see open items). Hyperledger Fabric was optional and is not used. |
| 5. Attack tests: modify, delete, insert, reorder, change root, replay, witness offline | **Done** | `tests/test_attacks.py` and the report's attack matrix also cover tail truncation, rewrite-and-re-sign with a stolen key, and forged acks. |
| 6. Evaluation: plain logging vs hash chain vs B-SCAF | **Partial** | Harness and replay results are done; the live workload is open (Objective 4). |

## Block fields (brief §8)

All are present: `block_number`, `previous_block_hash`, `batch_id`, `merkle_root`, `host_id`, `time_window_start`/`time_window_end`, `event_count`, `policy_version`, `signer_id`, `signature`. `witness_acks` are kept in `witness-acks.jsonl` beside the ledger rather than inside the block, because acknowledgements arrive after the block is signed. Each ack is signed by its witness and checked by `verify --witness-key`.

## Expected outcomes (brief §9)

| Outcome | Status |
| --- | --- |
| Prototype that collects system calls and produces verifiable batches | **Partial**: collection is file-based (see Objective 1). |
| Every tested modification to committed evidence is detected | **Done**: 12/12 scenarios behave as expected on the real-data ledger. |
| Dashboard or CLI report with an understandable verdict | **Done**: CLI JSON reports and the dashboard show pass / partial / fail. |
| Measured overhead profile and documented limits | **Partial**: replay measurements and limits are documented here. |
| Reproducible dataset, threat model and evaluation script | **Done**: `datasets/manifest.json` (pinned, SHA-256), `scripts/run_real_data.py`, `bscaf bench`. |

## Open items, in priority order

1. **Live-host validation.** Install auditd on a Linux VM, load `deploy/audit/bscaf.rules`, run `ingest-auditd --follow --batch-seconds 5`, and generate a repeatable workload of file operations, process creation and network connections. Record CPU, latency and throughput with auditd off, with auditd only, and with auditd plus B-SCAF. This closes Objectives 1 and 4 and Phase 6. The `b32` rules have not been loaded on a real kernel yet.
2. **Larger real dataset.** The Splunk sample is small (673 events after merging duplicates) and mostly exports one record type per file, so record correlation was exercised on only one real multi-record event plus synthetic tests. The next step is a multi-host audit log from AIT Log Data Set v2 (Zenodo, several GB per scenario).
3. **Key protection.** Source and witness private keys are unencrypted PEM files (owner-only permissions). An attacker with root on the source can re-sign local history. That is detected only because witnesses keep the original. Next steps: a TPM/HSM or passphrase-protected key, plus a key-rotation procedure.
4. **Transport and authentication.** The witness protocol is plain HTTP. Blocks are authenticated by signature, but there is no TLS, client authentication or rate limiting. Witness public keys are distributed by hand.
5. **Uncommitted window.** Events are protected only once their block is signed and replicated. An attacker who acts before then can delete them. Mitigations: small `--batch-seconds` and replicating after every block (for example, a `--follow` hook that calls `replicate`).
6. **Scale limits.** `verify` keeps one hash per event in memory, `proof` scans the whole event file, and the JSONL store has no rotation or archival. Throughput is about 6k events/s with fsync and 15–20k events/s without on one Python core. Hosts with broad `openat` rules may exceed this. Next steps: an indexed store (for example SQLite), per-block verification, and archival.
7. **Interpreted logs.** `ausearch -i` exports replace numeric UIDs with user names. Names other than `root`, `unset` and `nobody` are stored as `uid = -1` with `arguments.uid_name`, and local timestamps need `--assume-tz`. Prefer raw logs.
8. **Search and access control.** The dashboard lists recent events only. There is no query interface and no role-based access.
9. **Project documents.** The Word documents in `project-documents/` describe the earlier milestone and have not been regenerated.

# Threat Model — otel-agent-audit

> **Status:** Active · **Introduced:** Pre-public-launch hardening · **Applies to:** All v1 releases

This document states, plainly and completely, what the hash-chained audit log
**does and does not** protect against. Read it before deploying or relying on
this component for governance, compliance, or incident-response purposes.

---

## 1. Honest-infrastructure guarantees

When the audit pipeline runs on **honest infrastructure** (the collector is not
compromised, the filesystem is not tampered with, and the same operator controls
both write and read paths):

| Threat | Detected? | How |
|--------|-----------|-----|
| In-place edit of a single log entry | Yes | Ed25519 signature over canonical bytes fails re-verification |
| Deletion or reordering of a span within a sealed trace | Yes | Hash chain breaks from the altered entry onward |
| Deletion of an entire sealed trace | Yes (at checkpoint granularity) | `entry_count_mismatch` error when the checkpoint references the trace |
| Modification of a checkpoint | Yes | Checkpoint Ed25519 signature fails; `prev_checkpoint_hash` chain breaks |

The chain stays valid and reproducible with **a single audit replica and
deterministic ordering** (sort key `(start_time_unix_nano, span_id)`, set at
seal time). Replaying the same spans produces byte-identical entry hashes.

---

## 2. Malicious-operator limit

A **single-writer chain** does **not** defend against:

- An operator who **rewrites the entire log and re-signs every checkpoint**
  using the same private key. There is no mechanism in v1 to detect this if
  the attacker holds the signing key.
- A **split-view attack**, where an operator serves different versions of the
  log to different verifiers.

**Defense requires external witnesses.** The upgrade path is:

1. Publish checkpoint hashes to an append-only transparency log (e.g.,
   [Sigstore Rekor](https://docs.sigstore.dev/rekor/overview/) or a Trillian
   instance).
2. Independent parties obtain and compare checkpoint hashes out-of-band.

This is the **documented HA and transparency upgrade path**, not a v1 feature.
Until witnesses are in place, treat the audit log as tamper-*evident* (detects
honest mistakes and unsophisticated tampering) rather than tamper-*proof*
(defeats a determined, key-holding adversary).

---

## 3. Completeness granularity

### 3a. Cross-trace completeness (checkpoint cadence)

Cross-trace completeness is only as fine-grained as the **checkpoint cadence**
(`checkpoint_interval`, default 100 sealed traces). A complete trace that is
dropped between two checkpoints is detectable only at the **next checkpoint**
— there is no per-trace alert for missing-but-never-checkpointed traces.

Operators requiring finer completeness guarantees should lower
`checkpoint_interval` or call `Shutdown` at regular intervals to force a
checkpoint flush.

### 3b. Intra-trace completeness (early-root truncation)

A trace is sealed **as soon as any span with an empty `parent_span_id` arrives**
(the root span). If the root span arrives **before** its child spans, the trace
seals immediately and any subsequent child spans are **dropped with a warning
log** — they are not included in the sealed chain.

The sealed chain is internally valid (signatures and hashes pass), but it
represents an **incomplete trace**.

**Mitigation:** place the `agentauditselect` processor immediately upstream of
the exporter. It buffers all spans for a trace until the root arrives, then
forwards the entire trace as a single atomic batch. Without it, completeness
depends on the agent SDK sending the root span last (or after all children),
which is not guaranteed.

After the `trace_timeout` (default 30 s), the exporter seals whatever has been
buffered — root present or not. A verifier sees a valid but potentially partial
chain for timed-out traces.

### 3c. Sustained checkpoint write failure (pending-tip cap)

A checkpoint write that fails (ENOSPC, EIO, a revoked permission) keeps its
trace tips pending for retry rather than dropping them — that is deliberate:
the alternative is silently losing sealed traces on an ordinary, possibly
transient, IO error. Below the pending-tip cap described next, a backoff
(doubling after the first retry, capped at `maxCheckpointRetryGap`) bounds the wasted
re-signing work and thins the retry attempts as pending grows.

If the failure is **persistent** rather than transient, retained tips would
otherwise grow the pending set for as long as the outage lasts. `max_pending_tips`
(default `10 * checkpoint_interval`) bounds this: once exceeded, the **oldest**
pending tips are dropped — logged once per degraded episode, with a running
count reported at `Shutdown` — so the exporter trades a bounded amount of
additional data loss for a bounded memory footprint. The traces whose tips are
dropped this way are the same as any other checkpoint-uncovered trace: their
entries are still durably in the audit log, `VerifyLog` does not flag them as
an error (`internal/verify/verify.go` deliberately tolerates checkpoint-uncovered
traces), and only the checkpoint's coverage of them is lost.

Once pending is pinned at the cap, the backoff's thinning intentionally stops:
every subsequently sealed trace both retries the checkpoint write and re-trims
the pending set, for as long as the outage lasts. That is the trade for
guaranteeing the very next successful write is retried immediately rather than
at some later, possibly much larger, pending count — but it does mean the
write+`fsync` attempt rate against the already-faulting file rises to one per
sealed trace. The per-attempt failure log is suppressed during this steady
state (the one-time cap-exceeded log and the `Shutdown` summary already cover
it), so log volume does not scale with it, only the write attempts themselves do.
Decoupling the attempt rate itself from recovery-detection speed is tracked as
a follow-up (issue #30) rather than addressed here.

This is distinct from the **poisoned** state (`errCheckpointPoisoned`): poisoning
means no checkpoint can *ever* be written again for the life of the process, so
every subsequent tip is dropped immediately with no cap to reach. The
pending-tip cap instead covers the merely-persistent-but-not-fatal case, where
checkpointing could still succeed once the underlying fault clears.

**Mitigation:** monitor for the `pending tip set exceeded its cap` error log and
the `tips_dropped_for_pending_cap` count at `Shutdown` — both indicate degraded
coverage, not a crash. Size `max_pending_tips` for the outage duration an
operator is willing to tolerate before accepting additional loss.

### 3d. Sealed trace tip survives a crash before its checkpoint

Sealing a trace and covering it with a checkpoint are two separate steps —
the audit log write happens immediately, the checkpoint that attests to it
happens at the next `checkpoint_interval` boundary (§3a). A crash in between
those two steps does not lose the trace's checkpoint coverage: the WAL
retains a lightweight marker (the trace's tip hash and entry count, not its
full span records) for as long as the accumulator reports the tip as
pending. On restart, the marker is restored directly to the accumulator —
never by re-sealing the trace, which would duplicate its already-durable log
entries — so the next checkpoint covers it exactly as if the process had
never stopped.

This closes the gap whether the tip was pending because the checkpoint
interval simply hadn't been reached yet, or because the checkpoint write was
actively failing (§3c) — both leave the tip in the same recoverable state.

**What this does not change:** the two cases that were already a *deliberate*
trade rather than an accident. A poisoned checkpoint file
(`errCheckpointPoisoned`) still permanently drops every subsequent tip, since
no future checkpoint can ever be written to cover it. A pending-tip cap
(§3c) still drops the *oldest* tips once exceeded, since retaining them
indefinitely during a sustained outage is the unbounded-memory risk the cap
exists to prevent. In both cases the trace's entries remain durably in the
audit log and `VerifyLog` does not flag the gap as an error, matching §3a
and §3c.

This guarantee is scoped per sealed segment, not per `trace_id`: a duplicate
trace segment (§5) is a second, independent tip under the same `trace_id`, and
each tip's coverage is tracked and recovered on its own — settling one (by
checkpoint or by the cases above) never affects the other's pending state.

---

## 4. Single-replica constraint

**v1 must run as exactly one audit pipeline instance.** Multiple replicas
writing to the same audit log and checkpoint file produce:

- Independent, interleaved per-trace chains
- Spurious `entry_count_mismatch` and `tip_hash_mismatch` errors in the verifier

**Per-`trace_id` sharding across replicas** is the deferred HA path (each
replica owns a disjoint set of trace IDs and writes to its own file). This is
not implemented in v1.

If high availability is required, run the collector in active-passive mode
(one writer at a time) rather than active-active.

---

## 5. Duplicate trace segments (post-compact at-least-once)

After WAL compaction evicts a sealed trace's record, a re-delivered root span
for the same `trace_id` will be buffered and sealed again as a **second,
independent chain** for that `trace_id`. The verifier detects this and reports a
`duplicate_trace_segment` error rather than a misleading hash-mismatch.

This is an accepted **at-least-once delivery trade-off**. The
`agentauditselect` processor mitigates it by deduplicating at the trace level
before forwarding.

---

## 6. EU AI Act Article 12 — disclaimer

**EU AI Act Article 12 is technology-neutral.** It requires high-risk AI systems
to log enough information for post-hoc auditability, but it does **not** mandate
cryptographic hash chains, Ed25519 signatures, or any specific technical
standard. No finalized technical standard for Article 12 compliance exists as of
the writing of this document.

`otel-agent-audit` is a **useful tamper-evidence tool** that helps operators
demonstrate the integrity of their audit logs. It is **not** a certified
compliance product and makes no claim of Article 12 certification. Operators are
responsible for assessing their own compliance posture with qualified legal and
technical counsel.

---

## 7. What the verifier can and cannot conclude

| The verifier says | Meaning |
|-------------------|---------|
| `Status: OK` | No tampering detected **for the entries and checkpoints present**; the log is internally consistent with the supplied public key |
| `entry_count_mismatch` | A checkpoint claims more entries than the log contains — a trace may have been deleted post-seal |
| `tip_hash_mismatch` | The recomputed chain tip does not match the checkpoint — at least one entry was altered or reordered |
| `tip_hash_unverifiable` | The chain itself failed verification; the checkpoint tip cannot be independently confirmed |
| `key_id_mismatch` | The supplied public key does not match the `key_id` recorded in the log; you are using the wrong key |
| `duplicate_trace_segment` | Two independent chains exist for the same `trace_id` — this is an at-least-once delivery artifact, not evidence of tampering |

**The verifier cannot detect:**
- A trace that was **never written** to the log (it is absent, not corrupted)
- Tampering that occurred before the span reached the collector
- A complete log rewrite by an adversary who holds the private key (§2)

---

*Link: [README](../README.md) · [docs/verification.md](verification.md) · [docs/audit-record-schema.md](audit-record-schema.md)*

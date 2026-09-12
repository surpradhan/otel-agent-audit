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

A later segment's own not-yet-sealed spans are protected the same way. A
retained marker for an earlier, already-sealed segment can sit in the WAL
while a duplicate trace segment (§5) is still buffering its own spans under
the same `trace_id`; Replay and Compact distinguish the earlier segment's
marker from the later segment's still-open span data rather than treating
every span for that `trace_id` as settled the moment any marker for it is
seen, so the later segment's in-progress spans are never mistaken for the
earlier segment's and silently dropped.

### 3e. Parent-directory durability on first file creation

`fsync` on a file's descriptor makes its *data* durable; it says nothing about
the *directory entry* that names the file. The first time the audit log,
checkpoint file, or WAL is created at a given path, that directory entry is
not itself durable until the containing directory is also fsynced — so a
crash between file creation and that directory fsync can lose the file
entirely, even though every byte written to it was separately synced.

`Start` fsyncs each file's parent directory immediately after creating it, for
the audit log, the checkpoint file, and the WAL. The sync is best-effort: if
it fails — directory fsync is not supported on every platform, notably
Windows — `Start` logs a warning and continues rather than refusing to start
over a hardening step, unlike a failure to open or write the file itself,
which is fatal. This only matters for a path's first-ever run; every
subsequent restart reopens an already-durable directory entry. See issue #23.

This repo's CI runs `ubuntu-latest` only, so whether directory fsync actually
fails on Windows is unverified — if it does, every `Start` there logs one
warning per file, indefinitely, with no operator remedy. That trade-off is
deliberate rather than special-cased away: guessing wrong on `runtime.GOOS`
without evidence would trade a real durability improvement on an entire
platform for an assumed one.

**The quarantine sidecar** (the WAL path's sibling `*.quarantine.jsonl` file)
is created lazily, on the first record that cannot be sealed into a chain,
rather than at `Start` — so it was originally tracked as a separate gap
(issue #33) rather than folded in here, since there is no single fixed point
in `Start` to hook a lazily-created file's fix into. It gets the same
best-effort parent-directory fsync, just applied differently: every call to
`quarantineRecords` repeats it, rather than running once at a known
first-creation point. Repeating it is deliberate, not a missed optimization —
`os.OpenFile`'s `O_CREATE` doesn't report whether it just created the file or
opened an existing one, so there is no cheap way to run this only on the
actual first-creation call; fsyncing an already-durable directory on every
later call is a harmless, idempotent no-op, and quarantine events are rare
enough by design that the extra syscall per event is immaterial. See
issue #33.

**What this does not change:** `WAL.Compact`'s atomic rename over the live WAL
file has the same directory-durability property on an ongoing operation rather
than a first creation — a related but distinct gap, tracked as issue #36.

### 3f. Torn audit-log line within a single process lifetime

`Start` repairs a torn trailing line left by a crash before reopening the
audit log (§3e's sibling guarantee, via `repairTrailingPartialLine`) — but two
failure paths can leave the *live* file torn **without** a restart:

- A write that fails with `fsync_log: false` used to have no rollback to fall
  back on at all: `preWritePos` was only captured when fsync was enabled,
  since the rollback's own truncate-and-resync depended on it.
- A rollback's own `Truncate` can itself fail (e.g. the same fault that broke
  the original write).

`preWritePos` is now captured unconditionally, before a trace's first entry
is written, regardless of `fsync_log` — so either failure first attempts a
full `Truncate(preWritePos)`, atomically undoing every entry this trace wrote
in the current seal attempt, not just the one that failed. This matters for a
multi-span trace: a mid-loop failure on any entry but the first would
otherwise leave an *earlier*, already-durable sibling entry in the log with
no way to undo it later.

Only when that full rollback also fails does the exporter fall back to the
same narrower, trailing-line-only repair `Start` applies to a crash-torn file
— and only when doing so cannot leave the trace only partially represented: a
fragment that is valid JSON missing only its newline is terminated in place,
since it is a durable, signed record that simply lost its trailing byte (the
same reasoning issue #24 already established for the checkpoint file); any
other fragment is not a complete record and is truncated away. Both outcomes
are safe only when the trace has exactly one entry (either outcome then
unambiguously decides the whole trace's fate) or every entry already wrote
successfully this attempt (the trailing bytes are then structurally complete
regardless of entry count). A **multi**-entry trace failing mid-write — on any
entry, including the first — is unsafe either way: keeping a lone complete
fragment is exactly as dangerous as leaving an untouched earlier sibling,
since every later entry was never even attempted once the write loop returns.

In every unsafe case the log is marked **poisoned** instead (`errLogPoisoned`,
mirroring `errCheckpointPoisoned` — see §3c/§3d): no further trace is appended
to it, each subsequent one is quarantined instead (the same sidecar §3e
describes), and the failure is reported once at `Shutdown` with a running
count, not per trace. Poisoning alone does not guarantee anything is visibly
wrong on disk, though — a failure that deposits zero bytes, or a kept fragment
that happens to be valid JSON on its own, can leave the file looking
completely ordinary. So poisoning also appends a short, deliberately
unparseable marker to the file's current tail (best-effort; a failure here is
logged, not escalated further, since the process already knows to stop
trusting the file regardless): a `\x00` byte can never start or follow a
JSON value, so it forces the file's true final line to fail parsing — tolerated
as `torn_trailing_line`, not silently absent, whatever the triggering failure
actually left behind.

The one remaining gap is a triple fault: the original write fails, the full
rollback's `Truncate` also fails, **and** the marker write itself lands zero
bytes too. At that point nothing further is attempted — three independent
operations on the same file failing in immediate succession is treated as
evidence the underlying storage itself is unusable, not a case worth a fourth
layer of fallback. See issue #28.

**What this does not change:** the audit log's own hard-failure behavior in
`VerifyLog` (`torn_trailing_line`, §7) is unaffected — this section is about
*preventing* a torn line from reaching a state `VerifyLog` cannot tolerate
(anything but the log's own final line), not about relaxing what the verifier
accepts.

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
| `torn_trailing_line` | The audit log's final line was unparseable — likely an interrupted write from a crash. Its content was never cryptographically verified (that is what "unparseable" means), so this alone does not rule out tampering; entries before it were fully verified |

**The verifier cannot detect:**
- A trace that was **never written** to the log (it is absent, not corrupted)
- Tampering that occurred before the span reached the collector
- A complete log rewrite by an adversary who holds the private key (§2)

---

*Link: [README](../README.md) · [docs/verification.md](verification.md) · [docs/audit-record-schema.md](audit-record-schema.md)*

# Verifier CLI — otel-agent-audit-verify

`otel-agent-audit-verify` reads an audit log and checkpoint file produced by
`agentauditexporter` and verifies:

1. **Per-trace Ed25519 signatures** — every log entry's signature and entry hash.
2. **Hash chain continuity** — each entry links to the previous via `entry_hash`.
3. **Checkpoint coverage** — each checkpoint's signature and `prev_checkpoint_hash`
   chain; cross-checks `tip_hash` and `entry_count` against the log.

## Build

```bash
cd exporter/agentauditexporter
go build -o ../../dist/otel-agent-audit-verify ./cmd/otel-agent-audit-verify
```

## Usage

```
otel-agent-audit-verify [-key <hex>] [-key-file <pem>] [-json] <log-file> <checkpoint-file>
```

| Flag | Description |
|---|---|
| `-key <hex>` | Hex-encoded Ed25519 public key (64 hex chars = 32 bytes) |
| `-key-file <pem>` | Path to PEM file with `PUBLIC KEY` block (PKIX/SubjectPublicKeyInfo) |
| `-json` | Emit results as JSON (`{"TracesProcessed":…,"CheckpointsProcessed":…,"Errors":[…]}`) |

Exactly one of `-key` or `-key-file` is required; using both is an error.

## Getting the public key

The collector is configured with a PEM private key (`key_path` in the exporter
config). Extract the corresponding public key with OpenSSL:

```bash
openssl pkey -in /path/to/private.pem -pubout -out /path/to/public.pem
```

Then pass `-key-file /path/to/public.pem` to the verifier.

To get the raw hex bytes for use with `-key` (Ed25519 only — do not use for other key types):

```bash
openssl pkey -in /path/to/private.pem -pubout -outform DER | tail -c 32 | xxd -p -c 32
```

> **Warning:** `tail -c 32` works only for Ed25519, which has a fixed 32-byte public key at the end of its PKIX DER encoding. Using this command with a non-Ed25519 key produces incorrect bytes without any error. Prefer `-key-file` with the PEM file in all cases.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All checks pass, or only advisory findings were reported |
| 1 | One or more fatal verification failures were reported (see output for details) |
| 2 | Usage error, I/O error, or key parse error |

Every finding in `Report.Errors` carries a `Severity` of `"fatal"` or
`"advisory"` (issue #49):

- **fatal** — verification failed, or could not be completed:
  `chain`, `checkpoint`, `tip_hash_mismatch`, `entry_count_mismatch`,
  `tip_hash_unverifiable`, `duplicate_trace_segment`.
- **advisory** — the flagged entries were still fully verified against the
  supplied key despite the finding: `key_id_field_mismatch`,
  `torn_trailing_line`. Worth surfacing, but not a reason to treat the log
  as untrustworthy.

The exit code and the `Status:` line reflect only fatal findings, but the
`Status:` line always names the advisory count too, so it never undercounts
what the per-error lines printed below it will show. Advisory findings are
always printed (human-readable and JSON alike) but never affect the exit
code. Go callers of the `verify` package directly get the same policy via
`Report.FatalCount()` and `Report.StatusLine()`, which both
`otel-agent-audit-verify` and `cmd/demo` call — a single shared
implementation, not two mirrored ones, so the two CLIs cannot drift apart on
this decision. `FatalCount` is deliberately fail-closed: an error with an
empty or unrecognized `Severity` counts as fatal, never advisory.

> **Upgrading:** if existing automation treats any non-empty `Errors` as
> failure, that behavior has changed — a log with only advisory findings now
> reports `Status: OK` and exits 0. Check each error's `Severity` field if
> you need the old, stricter all-errors-fail behavior.

## Example output (human-readable)

```
Traces processed:      42
Checkpoints processed: 1
Status: OK
```

Failure example:

```
Traces processed:      42
Checkpoints processed: 1
Status: FAILED (1 error(s))
  [0123456789abcdef0123456789abcdef] chain (fatal): seq 2: signature verification failed
```

Advisory-only example — still exit 0, but the finding is still printed and
counted in the `Status:` line:

```
Traces processed:      42
Checkpoints processed: 1
Status: OK (1 advisory finding(s))
  [0123456789abcdef0123456789abcdef] key_id_field_mismatch (advisory): seq 2: entry key_id deadbeef does not match verified signer c0ffee
```

Mixed example — a fatal finding still fails the run (exit 1) even alongside
an advisory one. A checkpoint-covered trace whose chain fails verification
always produces `tip_hash_unverifiable` alongside `chain` (the checkpoint's
claimed tip can't be confirmed once the chain itself didn't verify), so two
fatal lines from one bad trace is the normal shape, not a bug; the advisory
line here has no `TraceID` (see above), so its bracket names the file
instead:

```
Traces processed:      42
Checkpoints processed: 1
Status: FAILED (2 fatal, 1 advisory)
  [0123456789abcdef0123456789abcdef] chain (fatal): seq 2: signature verification failed
  [0123456789abcdef0123456789abcdef] tip_hash_unverifiable (fatal): chain verification failed; checkpoint tip_hash 89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234 cannot be confirmed
  [audit log] torn_trailing_line (advisory): line 43: unparseable, likely a partial write from a crash: unexpected end of JSON input
```

## JSON output (`-json`)

```json
{
  "TracesProcessed": 42,
  "CheckpointsProcessed": 1,
  "Errors": []
}
```

`Errors` is a JSON array of objects:
`{"TraceID": "…", "Kind": "…", "Detail": "…", "Severity": "fatal"|"advisory"}`.
`TraceID` is empty for checkpoint-level errors and for the log-level
`torn_trailing_line` finding. See [Exit codes](#exit-codes) above for what
`Severity` means and how it drives the exit code.

`Report` itself carries no separate top-level pass/fail field (e.g. a
`Status` string or a fatal count) — a `-json` consumer must derive that from
`Errors[].Severity` the same way the CLI's own `Status:` line does. Adding
one is a reasonable future enhancement (tracked separately) but was left out
of this change: it would expand `Report`'s JSON shape beyond what issue #49
scoped, for a need the CLI's human-readable output doesn't have (it always
runs `Report.FatalCount()` itself, in Go).

## Audit policy

- Traces not covered by any checkpoint are counted but not flagged as errors
  (the last batch before a crash may have been written before the final checkpoint).
- A missing log or checkpoint file is treated as empty — no error is returned.
- An unparseable **final** line in either file is tolerated rather than treated as corruption: a single `write(2)` is not atomic, so a crash can tear the last line of any append-only file this exporter writes (see `Start`'s torn-tail repair and issue #24). A torn **checkpoint** line is silently dropped, matching the exporter's own restart-time repair. A torn **audit-log** line is instead recorded as a `torn_trailing_line` finding in `Report.Errors` (see [docs/threat-model.md §7](threat-model.md#7-what-the-verifier-can-and-cannot-conclude)) rather than silently dropped or hard-failed — entries before it are still fully verified, but the log is the evidence itself, and a silent drop there would hide exactly what an attacker who could truncate the file would want hidden.
- An unparseable line anywhere **other than the final line** of either file is always a hard error (I/O error, exit 2): only the last line can plausibly be an interrupted write, so an earlier one is corruption or tampering.

## Schema versions in a log

The verifier re-derives each entry's hash by re-serializing its `record` — so it
must reproduce the wire shape that entry was written in, not the newest one. Both
inputs come from the record itself:

- the **genesis seed** is `SHA256(traceIDBytes ‖ schema_version)`, taken from
  `record.schema_version` rather than the verifier's own constant; and
- since **v3**, the same field selects the **timestamp encoding**:
  `start_time_unix_nano` and `end_time_unix_nano` are decimal strings in v3 and
  later, JSON numbers in v1 and v2.

`otel-agent-audit-verify` handles both automatically, so a current binary
verifies v1, v2 and v3 logs. A third-party verifier must implement the same
dispatch, and must parse the v3 timestamp strings with an exact 64-bit integer
parser — routing a nanosecond timestamp through an IEEE-754 double loses
precision and makes the hash unreproducible. See
[docs/audit-record-schema.md §2.1](audit-record-schema.md#21-timestamp-encoding-v3).

A single log file **may** contain traces of different schema versions — the
verifier derives each trace's genesis seed and timestamp encoding from that
trace's own entries, so a file spanning a collector upgrade verifies as-is. What
must not happen is entries of different schema versions inside **one trace's
chain**; the exporter seals each trace against the schema version of its own
seq-0 record, and the verifier rejects a chain whose entries disagree.

## Key-id verification

Every log entry and checkpoint carries a `key_id` field equal to
`hex(SHA256(ed25519PublicKeyBytes))`, but the two are trusted differently:

- An **entry's** `key_id` (`sign.SignedEntry.KeyID`) sits beside its
  signature, not inside what gets signed (see `internal/sign`) — it is **not
  authenticated**, and nothing stops it being edited independently of a
  perfectly valid signature.
- A **checkpoint's** `key_id` (`chain.Checkpoint.KeyID`) is different: it is
  one of the fields `chain.CheckpointSigningPayload` marshals into the bytes
  that get signed (see `chain.Accumulator.Stage`), so it **is** authenticated
  — editing it invalidates the checkpoint's signature like editing any other
  signed field.

The verifier does not rely on this distinction, or on either field's claimed
value, to decide whether or how verification runs: every entry and
checkpoint is always verified directly against the supplied public key
(issue #46).

| Scenario | Verifier behaviour |
|----------|-------------------|
| Correct key supplied | Chain and checkpoint signatures are verified normally |
| Wrong key supplied | Ordinary `chain` / `checkpoint` signature-failure errors — the verifier cannot and does not try to tell "wrong key" apart from "corrupted" using a single candidate key |
| An entry verifies, but its claimed `key_id` disagrees with the supplied key | `key_id_field_mismatch` — `Severity: "advisory"` (see [Exit codes](#exit-codes)). The signature already proved the content is authentic; the `key_id` metadata is stale or was tampered with, which is worth flagging but not a reason to fail an otherwise-good entry. There is no checkpoint-side equivalent: a checkpoint's `key_id` is signed, so tampering it alone fails its signature check instead (an ordinary `checkpoint` error, `Severity: "fatal"`) |
| Log spans multiple key epochs | No longer refused outright — see [Multi-epoch logs](#multi-epoch-logs) below |

### Multi-epoch logs

When a signing key is rotated, entries before the rotation carry the old
`key_id` and entries after carry the new `key_id`. Before issue #46, the
verifier pre-scanned every claimed `key_id` — entries' and checkpoints'
alike — and refused to verify the log at all once it saw more than one
distinct value. That pre-scan is gone. Checkpoints' claimed `key_id` is
trustworthy (see above), but entries' is not, and the pre-scan mixed both
into one decision — so trusting it let one edited *entry* field either deny
verification of an otherwise-intact single-epoch log, or mask a genuinely
rotated log as single-epoch and bury real per-entry failures under a
misleading blanket diagnosis. See issue #46 for both scenarios in detail.

**Rotation-aware verification — a single run that cleanly attests both
epochs without signature-failure noise — is still not implemented**
(issue #19). What changed is *how* to work around that gap today.

Run the verifier **once per candidate key you hold, against the full,
unsplit log and checkpoint files** — do not pre-filter either file by
`key_id`. Every entry and checkpoint is verified directly against that one
key regardless of what it claims to be signed by:

- Entries and checkpoints from the epoch matching your key verify normally.
- Entries and checkpoints from a *different* epoch produce ordinary `chain` /
  `checkpoint` signature-failure errors. That is expected — it means "not
  signed by this key," not additional tampering. Run the verifier again with
  the other epoch's key for a clean report on that half.
- The checkpoint cross-checks (`entry_count_mismatch`, `tip_hash_mismatch`)
  still run for **every** checkpoint's `trace_tips`, including checkpoints
  whose own signature didn't verify against your key. This is what catches a
  deleted rotation-boundary trace: the checkpoint that attests it stays in
  view and stays cross-checked against the whole log, even though verifying
  *that checkpoint's own signature* needs the other epoch's key.

This one unsplit run gives strictly more coverage than the previously
documented split-per-epoch procedure, which is no longer recommended — it had
two real defects (issue #35):

- Filtering the checkpoint file by `key_id` can exclude the very checkpoint
  that covers a rotation-boundary trace, silently losing the only
  attestation that would have caught its deletion.
- Filtering both files independently gives the verifier no way to seed the
  previous epoch's tail, so every epoch after the first reports a spurious
  `prev_checkpoint_hash` mismatch against the zero sentinel.

To identify which keys you need in the first place:

```bash
jq -r '.signed.key_id' audit.jsonl | sort -u
jq -r '.key_id' checkpoint.jsonl | sort -u
```

Two further compensating controls reduce exposure while #19 remains open:

1. **Rotate only across a clean `Shutdown`.** A final checkpoint flush means
   no trace's coverage crosses the boundary, so there is no boundary trace to
   lose in the first place.
2. **Treat a `chain` / `checkpoint` signature failure as "try the other
   epoch's key," not automatically as tampering**, when you know a rotation
   happened around that point in time. The verifier cannot tell the two
   apart with only one candidate key at a time — closing that gap is exactly
   what issue #19 is for.

## Key distribution (v1 scope)

Key distribution is the operator's responsibility. Recommended practices:

- Store the public key alongside the audit log (e.g. `audit.pub.pem`).
- Include the `key_id` field from the log entries in any chain-of-custody
  record as a hint for which epoch's key to try first — it is not
  authenticated, so treat it as a hint, not proof (issue #46).
- Key rotation is not defined for v1 — see [Multi-epoch
  logs](#multi-epoch-logs) above for what verification actually covers today
  and its gaps (issue #19).

## Intra-trace completeness caveat

The exporter seals a trace **the moment any root span (`parent_span_id` is empty)
arrives**. If the root span arrives **before** its children, the trace seals
immediately and subsequent child spans are dropped. The sealed chain is
internally valid but represents an incomplete trace.

To ensure completeness, place the `agentauditselect` processor immediately
upstream of `agentauditexporter`. It buffers spans per trace until the root
arrives, then forwards the complete trace as one batch. Without it, completeness
depends on the agent SDK sending the root span last.

See [docs/threat-model.md §3b](threat-model.md#3b-intra-trace-completeness-early-root-truncation)
for the full discussion.

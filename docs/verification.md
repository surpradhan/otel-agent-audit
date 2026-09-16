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
| 0 | All checks pass |
| 1 | One or more verification failures (see output for details) |
| 2 | Usage error, I/O error, or key parse error |

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
  [0123456789abcdef0123456789abcdef] chain: seq 2: signature verification failed
```

## JSON output (`-json`)

```json
{
  "TracesProcessed": 42,
  "CheckpointsProcessed": 1,
  "Errors": []
}
```

`Errors` is a JSON array of objects: `{"TraceID": "…", "Kind": "…", "Detail": "…"}`.
`TraceID` is empty for checkpoint-level errors and for the log-level
`torn_trailing_line` finding.

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
`hex(SHA256(ed25519PublicKeyBytes))`. The verifier computes this fingerprint from
the supplied public key and compares it to the log before attempting any
signature verification. This produces actionable errors instead of confusing
"signature failed" messages when the wrong key is used.

| Scenario | Verifier behaviour |
|----------|-------------------|
| Correct key supplied | Chain and checkpoint signatures are verified normally |
| Wrong key supplied (single epoch) | `key_id_mismatch` error for each trace and checkpoint; no misleading signature errors |
| Log spans multiple key epochs | `VerifyLog` returns an error rather than a `Report` — a rotated log cannot yet be verified end to end; see [Multi-epoch logs](#multi-epoch-logs) below |

### Multi-epoch logs

When a signing key is rotated, entries before the rotation carry the old
`key_id` and entries after carry the new `key_id`. The verifier detects more
than one distinct `key_id` in the log and refuses to verify it as a whole.

**A rotated log cannot currently be verified end to end** (issue #19).
Splitting the log per epoch and verifying each slice separately — which this
section used to recommend as the fix — has two defects (issue #35):

- The trace sealed under the old key but first checkpointed under the new one
  loses its only attestation once the new epoch's checkpoint is excluded from
  the old epoch's slice. Deleting that trace afterward still reports
  `Status: OK`.
- Every epoch after the first reports a `prev_checkpoint_hash` mismatch
  against the zero sentinel — the same error that (correctly) flags
  checkpoint truncation — because the split gives the verifier no way to seed
  the previous epoch's tail.

To identify the epochs present in a log:

```bash
jq -r '.signed.key_id' audit.jsonl | sort -u
jq -r '.key_id' checkpoint.jsonl | sort -u
```

Until rotation-aware verification lands, two compensating controls reduce the
exposure without closing it:

1. **Rotate only across a clean `Shutdown`.** A final checkpoint flush means
   no trace's coverage crosses the boundary, so there is no boundary trace to
   lose.
2. **Run the verifier once per epoch, then cross-check every checkpoint's
   `trace_tips` against the whole (unsplit) log** — not just its own epoch's
   slice. Extract each epoch's lines by `key_id` — the log and checkpoint
   files nest it differently: `jq 'select(.signed.key_id == "<id>")'
   audit.jsonl` and `jq 'select(.key_id == "<id>")' checkpoint.jsonl` — and
   run the verifier against each slice with its matching key. That alone
   still reports `Status: OK` even when the boundary trace has been deleted,
   per above — the cross-check is what catches it: a checkpoint claiming a
   trace the full log no longer holds is the deletion made visible:

   ```
   cp claims 1111…  entry_count=2 ; log has 2
   cp claims 2222…  entry_count=2 ; log has 0   <- deleted boundary trace
   ```

   This catches an outright-deleted boundary trace, but covers neither that
   checkpoint's `tip_hash` nor its own signature — a partial check, not a
   substitute for rotation-aware verification.

## Key distribution (v1 scope)

Key distribution is the operator's responsibility. Recommended practices:

- Store the public key alongside the audit log (e.g. `audit.pub.pem`).
- Include the `key_id` field from the log entries in any chain-of-custody record
  so verifiers can confirm they are using the correct key for a given epoch.
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

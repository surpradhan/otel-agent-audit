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
`TraceID` is empty for checkpoint-level errors.

## Audit policy

- Traces not covered by any checkpoint are counted but not flagged as errors
  (the last batch before a crash may have been written before the final checkpoint).
- A missing log or checkpoint file is treated as empty — no error is returned.
- An unparseable line in the log or checkpoint file (e.g. a truncated line from a crash) causes the verifier to return an I/O error (exit 2). The WAL, not the audit log, absorbs crash-partial writes; the audit log only receives complete JSONL entries.

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
| Log spans multiple key epochs | `VerifyLog` returns an error: "multi-epoch log: re-run per epoch with the matching key" — see below |

### Multi-epoch logs

When a signing key is rotated, entries before the rotation carry the old
`key_id` and entries after carry the new `key_id`. The verifier detects more
than one distinct `key_id` in the log and returns an error. To verify a
multi-epoch log:

1. Identify the key epochs: `jq -r '.signed.key_id' audit.jsonl | sort -u`
2. Identify the checkpoint epochs: `jq -r '.key_id' checkpoint.jsonl | sort -u`
3. For each epoch, extract the relevant log/checkpoint lines and run the verifier
   with the key for that epoch.

## Key distribution (v1 scope)

Key distribution is the operator's responsibility. Recommended practices:

- Store the public key alongside the audit log (e.g. `audit.pub.pem`).
- Include the `key_id` field from the log entries in any chain-of-custody record
  so verifiers can confirm they are using the correct key for a given epoch.
- Key rotation is not defined for v1; after rotation, entries carry the new
  `key_id`. Run the verifier once per epoch, each time with the key that matches
  that epoch's `key_id`.

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

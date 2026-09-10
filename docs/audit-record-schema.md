# Audit Record Schema — v3

> **Status:** Active · **Introduced:** Phase B1 · **Updated:** Phase W9 · **Schema version:** `v3` · Previous: [`v2`](#v2-to-v3-changelog), [`v1`](#v1-to-v2-changelog)

This document is the authoritative field-by-field specification for `AuditRecord`
and the entry construction protocol. It is the cross-impl contract: any
implementation (Go exporter, Python verifier, future CLI) that produces or
consumes audit log entries MUST match this spec byte-for-byte.

---

## 1. Versioning

Every `AuditRecord` carries `schema_version: "v3"`. The genesis seed for a
trace's hash chain includes this string, so records of different schema versions
never silently interleave (the seed differs → the chains differ → comparison
fails at the first entry).

**v1/v2 backward compatibility:** v1 and v2 logs remain fully verifiable. The
verifier reads `schema_version` from the first log entry and calls
`GenesisSeedForSchema(traceID, schemaVersion)` to re-derive the correct genesis
seed. Since v3 the schema version also selects the **timestamp encoding** (§2.1),
so re-serializing a stored record reproduces the bytes that were originally
hashed regardless of the record's vintage. One log file may contain traces of
different schema versions — each trace's seed and encoding come from its own
entries — but entries of different schema versions must never appear inside a
single trace's chain.

**Breaking-change policy:** any change to field names, JSON key names, field
order, types, value encodings, or the `SelectedAttributes` allowlist is a
breaking chain-format change and requires:

1. A `SchemaVersion` constant bump (e.g. `"v2"` → `"v3"`)
2. New cross-impl fixtures in `internal/record/testdata/`,
   `internal/canonical/testdata/` and `internal/chain/testdata/`
3. A changelog entry and field-table update in this document

---

## 2. AuditRecord fields

Fields are listed in JSON output order (struct declaration order in Go —
changing this order changes canonical bytes).

| JSON key | Go type | Description | Mapping from `ptrace.Span` |
|---|---|---|---|
| `schema_version` | `string` | Always `"v3"` | Constant |
| `trace_id` | `string` | Lowercase hex, no dashes, 32 chars | `span.TraceID().String()` |
| `span_id` | `string` | Lowercase hex, 16 chars | `span.SpanID().String()` |
| `parent_span_id` | `string` | Lowercase hex, 16 chars; `""` (empty string) if no parent (root span) — this is the value `pcommon.SpanID{}.String()` returns for a zero span ID | `span.ParentSpanID().String()` |
| `seq_in_trace` | `integer` | 0-based position of this span within the sealed trace | Assigned by the exporter during B1 (always 0); B2 sets this from deterministic sort position |
| `start_time_unix_nano` | `string` (decimal `uint64`) | Span start time in nanoseconds since Unix epoch, encoded as a **decimal string** — see §2.1. v1/v2: JSON number | `record.UnixNano(span.StartTimestamp())` |
| `end_time_unix_nano` | `string` (decimal `uint64`) | Span end time in nanoseconds since Unix epoch, encoded as a **decimal string** — see §2.1. v1/v2: JSON number | `record.UnixNano(span.EndTimestamp())` |
| `span_name` | `string` | OTel span name | `span.Name()` |
| `otel_kind` | `string` | OTel span kind as returned by `SpanKind.String()`: `"Client"`, `"Server"`, `"Internal"`, `"Producer"`, `"Consumer"`, `"Unspecified"` | `span.Kind().String()` |
| `gen_ai_operation` | `string` | Value of `gen_ai.operation.name` attribute; empty string if absent | `attrs.Get("gen_ai.operation.name")` |
| `audit_kind` | `string` | Semantic role (see §3) | Inferred from span attributes |
| `selected_attributes` | `array` | Allowlisted span attributes (see §4) | See §4 |
| `status` | `string` | OTel status code as returned by `StatusCode.String()`: `"Unset"`, `"Ok"`, `"Error"` | `span.Status().Code().String()` |

---

## 2.1 Timestamp encoding (v3)

`start_time_unix_nano` and `end_time_unix_nano` are encoded as **JSON strings
containing a base-10 integer**, not as JSON numbers:

```json
"start_time_unix_nano": "1764547200123456789",
"end_time_unix_nano":   "1764547200987654321"
```

**Why.** A Unix nanosecond timestamp is around 1.7 × 10^18, well past
2^53 = 9007199254740992 — the largest integer an IEEE-754 double represents
exactly. Go and Python parse JSON integers into 64-bit integer types and are
exact, but a verifier whose JSON parser yields doubles (JavaScript's
`JSON.parse`, and several JCS implementations) silently rounds the value. Such a
verifier can no longer re-serialize the record to the bytes that were hashed, so
it cannot reproduce `entry_hash` — it would report tampering on an untampered
log. Encoding the value as a string keeps it out of the parser's number path
entirely. The OTLP/JSON specification encodes `fixed64` timestamps as decimal
strings for exactly this reason; v3 follows that precedent.

**Encoding rules.**

- **Producers** MUST emit a quoted, unsigned, base-10 integer with no leading
  `+`, no leading zeros, no exponent and no fractional part — the shortest
  decimal representation of the `uint64` value. The string MUST contain only
  ASCII digits: no JSON escape sequences, even though `"\u0031"` is a
  conformant JSON spelling of `"1"`. A second spelling of the same value would
  be a second canonical form, which the format cannot have.
- **Consumers** SHOULD reject the non-canonical spellings rather than
  normalizing them. The Go implementation does; normalizing would let two
  different inputs canonicalize alike while hashing differently upstream.
- **Consumers** MUST parse the string with an exact 64-bit integer parser. Never
  route the value through a float, and never re-encode it as a JSON number.
- **Consumers** SHOULD accept a bare JSON number as well, so that one code path
  reads v1/v2 and v3 logs; the Go implementation does (`record.UnixNano`).
- **Re-serialization is driven by the record's own `schema_version`**: v1 and v2
  records re-serialize with numeric timestamps, v3 and later with decimal
  strings. In Go this dispatch lives in `record.AuditRecord.MarshalJSON`, and the
  legacy shape is frozen in the unexported `legacyV1V2Record` struct. The set of
  numeric-timestamp versions — `{v1, v2}` — is closed and never grows; any
  schema version outside it uses the string encoding.

Every other integer field in the format (`seq_in_trace`, `checkpoint_seq`,
`entry_count`) stays a JSON number: none of them can approach 2^53 in practice.

---

## 3. AuditKind values

| Value | Meaning |
|---|---|
| `"task"` | Default; a top-level LLM inference or agent task |
| `"tool"` | Tool/function invocation by the agent |
| `"handoff"` | Agent-to-agent delegation or transfer |
| `"guardrail"` | A policy/governance gate evaluation (feeds Workstream A in B3) |
| `"error"` | Span with `StatusCode = Error` that does not match a more specific kind |

**Inference rules (applied in order):**
1. If `gen_ai.guardrail.name` attribute is present → `guardrail`
2. If `gen_ai.operation.name` is `"execute_tool"` or `"tool_call"` → `tool`
3. If `gen_ai.operation.name` is `"handoff"` or `"transfer"` → `handoff`
4. If `span.Status().Code() == StatusCodeError` → `error`
5. Otherwise → `task`

---

## 4. SelectedAttributes

`selected_attributes` is a **sorted array** of `{"key": "...", "value": "..."}`
objects, not a map. The sort order is fixed by the `attributeAllowlist` in
`internal/record/record.go`; it matches lexicographic order of the key strings.

**Current allowlist (unchanged since v2):**

| Attribute key | Notes |
|---|---|
| `gen_ai.guardrail.action` | (**v2**) Action taken by the agent's guardrail middleware (not by OTel); records a decision that already occurred. Values: `"block"`, `"warn"`, `"redact"`, `"allow"`. |
| `gen_ai.guardrail.name` | (**v2**) Name of the policy/guardrail that evaluated the span |
| `gen_ai.guardrail.reason` | (**v2**) Human-readable explanation of the guardrail decision |
| `gen_ai.guardrail.severity` | (**v2**) Severity level of the guardrail trigger: `"low"`, `"medium"`, `"high"` |
| `gen_ai.operation.name` | The LLM/agent operation type |
| `gen_ai.request.model` | Model requested by the client |
| `gen_ai.response.model` | Model that actually responded (may differ from request) |
| `gen_ai.system` | LLM provider (e.g. `"openai"`, `"anthropic"`) |
| `gen_ai.usage.input_tokens` | Prompt token count |
| `gen_ai.usage.output_tokens` | Completion token count |

See [`docs/guardrail-mapping.md`](guardrail-mapping.md) for detailed attribute semantics and examples.

Only attributes present in the span are included; missing allowlist keys are
omitted (no null entries). The resulting array preserves the allowlist order.

**Cross-impl note:** when no allowlisted attributes are present, the Go exporter
produces `"selected_attributes":null` (JSON null), not `"selected_attributes":[]`
(empty array). Verifiers written in other languages MUST treat both as equivalent
to "no attributes." Do not normalize one to the other — doing so would change
canonical bytes for a previously stored record.

---

## 5. Entry construction protocol (B2 — multi-entry chain)

This is the exact byte-level protocol used by `exporter.go` and expected by
any verifier. B2 extends B1 with per-trace hash chaining.

### SeqInTrace ordering invariant

`seq_in_trace` is assigned to each `AuditRecord` **after** sorting by
`(start_time_unix_nano ASC, span_id ASC)` and **before** canonical
serialization. The canonical bytes for entry `i` include `"seq_in_trace":i`;
this is load-bearing for the chain.

### Per-entry chain computation

```
// For each trace with N spans:
genesisSeed = SHA256(hex.DecodeString(trace_id) ‖ []byte(schema_version))
// e.g. for v3: SHA256(traceIDBytes ‖ "v3")

// Step 1: sort records by (start_time_unix_nano ASC, span_id ASC)
// Step 2: assign seq_in_trace = i (before canonicalizing)

for i in 0..N-1:
    canonicalBytes[i] = canonical.Marshal(records[i])   // includes seq_in_trace = i
    prev[i]           = genesisSeed       if i == 0
    prev[i]           = entryHash[i-1]    if i  > 0
    sigPayload[i]     = append(canonicalBytes[i][:len:len], prev[i]...)  // three-index cap
    entryHash[i]      = hex(SHA256(sigPayload[i]))
    signature[i]      = base64(ed25519.Sign(privKey, sigPayload[i]))
```

**Backward compatibility:** for a single-span trace (N=1, seq=0, prev=genesisSeed),
this is identical to B1.

**Known B2 limitation:** if child spans arrive in a later batch than the root
span (the span with `parent_span_id: ""`), those children are not included in the
sealed chain. Post-seal spans for an already-sealed `trace_id` are dropped with
a warning log.

The log entry JSON (one JSONL line per entry):
```json
{
  "record": { <AuditRecord fields per §2> },
  "signed": {
    "key_id":    "<hex(SHA256(publicKey))>",
    "algorithm": "ed25519",
    "entry_hash": "<hex(SHA256(sigPayload[i]))>",
    "signature":  "<base64(ed25519.Sign(privKey, sigPayload[i]))>"
  }
}
```

### Verification

A verifier MUST:
1. Group log entries by `trace_id`; sort by `seq_in_trace`.
2. Re-derive `genesisSeed` from `record.trace_id` as above.
3. For each entry `i`: reconstruct `canonicalBytes[i]` by re-marshaling
   `record` (this includes `seq_in_trace = i`). Re-marshal in the wire shape of
   that record's own `schema_version` — in particular the timestamp encoding of
   §2.1 — not in the verifier's newest shape.
4. Reconstruct `prev[i]` (genesisSeed for i=0; entryHash[i-1] for i>0).
5. Reconstruct `sigPayload[i] = append(canonicalBytes[i][:len:len], prev[i]...)`.
6. Verify the Ed25519 signature: `ed25519.Verify(pubKey, sigPayload[i], base64Decode(signed.signature))`.
7. Cross-check `entryHash[i] = hex(SHA256(sigPayload[i]))` against `signed.entry_hash`.

The verifier MUST NOT derive `sigPayload` from the stored `entry_hash` — only
from a fresh re-serialization of `record`. This ensures a tampered record
cannot pass verification even if its stored hash is also replaced.

---

## 6. Canonical serialization

`canonical.Marshal` produces compact JSON (no spaces, no trailing newline) with
fields in the order defined by the `AuditRecord` struct. It is a deterministic
function of the record's field values **and its `schema_version`**: identical
inputs produce byte-identical output across all runs.

**Reproducibility across language implementations.** Every value in the canonical
bytes is reproducible by any implementation that follows this spec, including one
whose JSON parser represents numbers as IEEE-754 doubles. That was *not* true
before v3: nanosecond timestamps were emitted as JSON numbers exceeding 2^53, so
JavaScript's `JSON.parse` and some JCS libraries rounded them and could not
re-derive the hashed bytes (§2.1). Implementations must still meet the remaining
requirements: preserve field order rather than sorting keys, treat
`selected_attributes` as an ordered array, parse the timestamp strings with an
exact 64-bit integer parser, and re-serialize a record in the wire shape of its
own `schema_version`.

The golden fixtures (paths relative to repo root):

v3 (current):
- Input: `exporter/agentauditexporter/internal/record/testdata/v3_span_to_record_fixture.json`
- Canonical output (seq_in_trace=0): `exporter/agentauditexporter/internal/canonical/testdata/v3_canonical_fixture.json`
- Canonical output (seq_in_trace=1): `exporter/agentauditexporter/internal/canonical/testdata/v3_canonical_seq1_fixture.json`
- Chain: `exporter/agentauditexporter/internal/chain/testdata/v3_two_span_chain_fixture.json`

v2 (frozen, for regression):
- Input: `exporter/agentauditexporter/internal/record/testdata/v2_span_to_record_fixture.json`
- Canonical output (seq_in_trace=0): `exporter/agentauditexporter/internal/canonical/testdata/v2_canonical_fixture.json`
- Canonical output (seq_in_trace=1): `exporter/agentauditexporter/internal/canonical/testdata/v2_canonical_seq1_fixture.json`
- Chain: `exporter/agentauditexporter/internal/chain/testdata/v2_two_span_chain_fixture.json`

v1 (frozen, for regression):
- Input: `exporter/agentauditexporter/internal/record/testdata/v1_span_to_record_fixture.json`
- Canonical output (seq_in_trace=0): `exporter/agentauditexporter/internal/canonical/testdata/v1_canonical_fixture.json`
- Canonical output (seq_in_trace=1): `exporter/agentauditexporter/internal/canonical/testdata/v1_canonical_seq1_fixture.json`
- Chain: `exporter/agentauditexporter/internal/chain/testdata/v1_two_span_chain_fixture.json`

The v3 fixtures deliberately use timestamps above 2^53
(`1764547200123456789`, `1764547200987654321`), so an implementation that routes
them through a double fails the fixture instead of passing on toy values. The v1
and v2 fixtures keep the small timestamps they were minted with; those bytes are
frozen.

Note: the canonical fixture files end with a single trailing newline added by editors.
That newline is **not** part of the canonical bytes — `canonical.Marshal` produces
compact JSON with no trailing newline. Tests strip trailing whitespace before comparing.

---

## 7. Key identity

`signed.key_id` = `hex(SHA256(ed25519PublicKeyBytes))`.

This is a stable fingerprint of the signing key. Key rotation starts a new
key epoch; all entries signed after rotation carry the new `key_id`. Entries
from before rotation remain verifiable against the old epoch's public key.
Key distribution is out of scope for v1 and will be specified in
`docs/verification.md` (B4).

---

## 8. Checkpoint format (B2)

A **checkpoint** is a signed commitment to all sealed trace chain tips since
the previous checkpoint. Checkpoints are written every `checkpoint_interval`
sealed traces (default 100) and on `Shutdown`.

### JSON format (one JSONL line per checkpoint)

```json
{
  "schema_version": "v3",
  "checkpoint_seq": 1,
  "timestamp": "2026-06-22T14:30:00Z",
  "prev_checkpoint_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "trace_tips": [
    {"trace_id": "…", "tip_hash": "…", "entry_count": 3}
  ],
  "key_id": "…",
  "algorithm": "ed25519",
  "signature": "…"
}
```

### Fields

| JSON key | Type | Description |
|---|---|---|
| `schema_version` | `string` | Always `"v3"` (matches the audit log entries in the same epoch) |
| `checkpoint_seq` | `uint64` | Starts at 1, increments by 1 per checkpoint. A gap indicates a missing checkpoint |
| `timestamp` | `string` | RFC3339 UTC timestamp when the checkpoint was built |
| `prev_checkpoint_hash` | `string` | `hex(SHA256(prev checkpointForSigning bytes))`; `"000…0"` (64 zeros) for the first checkpoint |
| `trace_tips` | `array` | Sorted by `trace_id`. Each element: `{trace_id, tip_hash, entry_count}` |
| `key_id` | `string` | Same key identity as audit log entries |
| `algorithm` | `string` | Always `"ed25519"` |
| `signature` | `string` | `base64(ed25519.Sign(privKey, checkpointForSigning))` |

### First-checkpoint sentinel

`prev_checkpoint_hash` for the very first checkpoint ever written (across all
process lifetimes) is the constant
`chain.ZeroPrevCheckpointHash = "0000000000000000000000000000000000000000000000000000000000000000"`
(64 ASCII '0' characters = hex encoding of 32 zero bytes).

### Checkpoint continuity across restarts

On `Start`, the exporter reads the last line of the checkpoint file and restores
`checkpoint_seq` and `prev_checkpoint_hash` from it before writing any new
checkpoints. This ensures `checkpoint_seq` is monotonically increasing across
process restarts (whether clean shutdowns or crash-recovery) and that the
`prev_checkpoint_hash` chain has no gaps, allowing verifiers to treat the entire
checkpoint file as one unbroken sequence regardless of how many times the
collector has been restarted. Partial or corrupt final lines left by a
crash-in-write are silently skipped; the previous complete checkpoint is used
as the restart base.

### Signing protocol

The signing payload (`checkpointForSigning`) is the compact JSON of all fields
except `signature`, in the same field order. `trace_tips` is sorted by `trace_id`
before marshaling to ensure deterministic bytes across implementations.

`prev_checkpoint_hash` = `hex(SHA256(prev checkpointForSigning bytes))`.
The first checkpoint uses the zero sentinel.

### Checkpoint verification

A verifier MUST:
1. Parse checkpoints in order (by `checkpoint_seq`).
2. Re-derive `checkpointForSigning` bytes (all fields except `signature`, sorted `trace_tips`).
3. Verify `prev_checkpoint_hash` equals `hex(SHA256(prev checkpointForSigning bytes))`.
4. Verify `ed25519.Verify(pubKey, checkpointForSigning, base64Decode(signature))`.
5. For each `trace_tip`, cross-check `entry_count` against the number of log
   entries for that `trace_id` to detect post-seal deletions.

**Policy for traces not covered by any checkpoint:** counted in
`Report.TracesProcessed` but not reported as errors (they are
"unchecked-by-checkpoint"). Rationale: the last batch before a crash may have
been written to the log before the final Shutdown checkpoint was persisted;
treating this as an error would produce false positives on clean restarts.

### Cross-impl fixture

- v3 (current): `exporter/agentauditexporter/internal/chain/testdata/v3_checkpoint_fixture.json`
- v2 (frozen): `exporter/agentauditexporter/internal/chain/testdata/v2_checkpoint_fixture.json`
- v1 (frozen): `exporter/agentauditexporter/internal/chain/testdata/v1_checkpoint_fixture.json`

The checkpoint payload carries no nanosecond timestamps of its own — its
`timestamp` is RFC3339 and `checkpoint_seq`/`entry_count` are small counters — so
v3 changes only its `schema_version` string and the `tip_hash` values it commits
to. No checkpoint field changed encoding.

---

## 9. Changelog

### v2-to-v3 changelog

| Change | Impact |
|---|---|
| `schema_version` bumped `"v2"` → `"v3"` | Genesis seed changes; v2 and v3 chains are never interleaved |
| `start_time_unix_nano` and `end_time_unix_nano` encoded as decimal strings instead of JSON numbers | Canonical bytes change for every record, so every entry hash changes. Makes the format reproducible by verifiers whose JSON parser yields IEEE-754 doubles (§2.1) — previously they could not re-derive `entry_hash` for any real nanosecond timestamp |
| No field added, removed, renamed or reordered | The v2→v3 diff is exactly the timestamp encoding; locked by `TestMarshal_TimestampEncodingIsTheOnlyV2ToV3Change` |
| `SelectedAttributes` allowlist unchanged | Guardrail attributes and everything else carry over from v2 as-is |
| Checkpoint format unchanged apart from `schema_version` | No checkpoint field encoding changed |

**v2 verifiability:** pass `"v2"` as `schemaVersion` to
`GenesisSeedForSchema(traceID, schemaVersion)` when verifying v2 logs, and
re-serialize v2 records with **numeric** timestamps. The Go implementation does
both automatically from the record's own `schema_version`; a third-party verifier
must implement the same dispatch. `otel-agent-audit-verify` reads the schema
version from the first log entry and selects the correct seed and encoding.

**Upgrading a running collector:** a WAL left by a v2 binary replays cleanly into
a v3 binary. Replayed records keep their own `schema_version`, so an in-flight
trace seals as a v2 chain and stays verifiable; traces that start after the
upgrade seal as v3. Do not hand-edit a v2 log into v3 form — that changes the
canonical bytes and invalidates every stored hash and signature in it.

### v1-to-v2 changelog

| Change | Impact |
|---|---|
| `schema_version` bumped `"v1"` → `"v2"` | Genesis seed changes; v1 and v2 chains are never interleaved |
| Added `gen_ai.guardrail.{action,name,reason,severity}` to `SelectedAttributes` allowlist | New attributes captured in canonical bytes; existing spans without guardrail attrs are unaffected (keys absent → not included) |

**v1 verifiability:** pass `"v1"` as `schemaVersion` to `GenesisSeedForSchema(traceID, schemaVersion)` when verifying v1 logs, and re-serialize v1 records with numeric timestamps (as for v2, above). The `otel-agent-audit-verify` CLI reads the schema version from the first log entry and selects the correct seed function automatically.

---

## 10. agentauditselect processor (B3b)

The `agentauditselect` processor sits immediately upstream of `agentauditexporter`
in the collector pipeline. It buffers spans in memory, keyed by `trace_id`, and
forwards each trace as a single `ptrace.Traces` call only when one of two
conditions is met:

1. **Root detected:** a span with `parent_span_id == ""` arrives. All buffered
   spans for that trace are forwarded immediately in one call.
2. **Timeout:** no new span for a trace has arrived for `trace_timeout` (default
   30 s). The partial buffer is forwarded as-is so the exporter can seal whatever
   was received.

**What this fixes:** prior to B3b, if child spans arrived in a later
`ConsumeTraces` batch than the root span, the exporter would seal on the root
and then drop the late children with a warning. The processor ensures the
exporter only ever sees complete (or timed-out-partial) traces.

**Schema impact:** none — no chain-format or schema_version changes. The
processor is transparent to the audit-record schema; it only controls the
delivery batching.

**Configuration:**

```yaml
processors:
  agentauditselect:
    trace_timeout: 30s   # optional; default 30s
```

**Ordering constraint:** `agentauditselect` must appear in the pipeline
immediately before `agentauditexporter`. Do not place the `batch` processor
between them (it regroups spans and defeats deterministic ordering).

---

## 11. Verifier CLI (B4)

`otel-agent-audit-verify` is the reference implementation for audit log
verification. It is built from
`exporter/agentauditexporter/cmd/otel-agent-audit-verify/` and wraps
`internal/verify.VerifyLog`.

See [`docs/verification.md`](verification.md) for build instructions, flags,
and example output.

**Schema impact:** none — the verifier is a read-only consumer of the existing
log format. No `schema_version` bump is required.

**Key distribution (v1 scope):** the operator is responsible for distributing
the Ed25519 public key out-of-band (e.g. storing it alongside the log, or in a
key management system). Key rotation is not defined for v1; rotated keys produce
new `key_id` values in the log, requiring the verifier to be run with the
appropriate key for each epoch.

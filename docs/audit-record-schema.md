# Audit Record Schema — v1

> **Status:** Active · **Introduced:** Phase B1 · **Schema version:** `v1`

This document is the authoritative field-by-field specification for `AuditRecord`
and the entry construction protocol. It is the cross-impl contract: any
implementation (Go exporter, Python verifier, future CLI) that produces or
consumes audit log entries MUST match this spec byte-for-byte.

---

## 1. Versioning

Every `AuditRecord` carries `schema_version: "v1"`. The genesis seed for a
trace's hash chain includes this string, so records of different schema versions
never silently interleave (the seed differs → the chains differ → comparison
fails at the first entry).

**Breaking-change policy:** any change to field names, JSON key names, field
order, types, or the `SelectedAttributes` allowlist is a breaking chain-format
change and requires:

1. A `SchemaVersion` constant bump (e.g. `"v1"` → `"v2"`)
2. New cross-impl fixtures in `internal/record/testdata/` and
   `internal/canonical/testdata/`
3. An update to this document

---

## 2. AuditRecord fields

Fields are listed in JSON output order (struct declaration order in Go —
changing this order changes canonical bytes).

| JSON key | Go type | Description | Mapping from `ptrace.Span` |
|---|---|---|---|
| `schema_version` | `string` | Always `"v1"` | Constant |
| `trace_id` | `string` | Lowercase hex, no dashes, 32 chars | `span.TraceID().String()` |
| `span_id` | `string` | Lowercase hex, 16 chars | `span.SpanID().String()` |
| `parent_span_id` | `string` | Lowercase hex, 16 chars; `""` (empty string) if no parent (root span) — this is the value `pcommon.SpanID{}.String()` returns for a zero span ID | `span.ParentSpanID().String()` |
| `seq_in_trace` | `integer` | 0-based position of this span within the sealed trace | Assigned by the exporter during B1 (always 0); B2 sets this from deterministic sort position |
| `start_time_unix_nano` | `uint64` | Span start time in nanoseconds since Unix epoch | `uint64(span.StartTimestamp())` |
| `end_time_unix_nano` | `uint64` | Span end time in nanoseconds since Unix epoch | `uint64(span.EndTimestamp())` |
| `span_name` | `string` | OTel span name | `span.Name()` |
| `otel_kind` | `string` | OTel span kind as returned by `SpanKind.String()`: `"Client"`, `"Server"`, `"Internal"`, `"Producer"`, `"Consumer"`, `"Unspecified"` | `span.Kind().String()` |
| `gen_ai_operation` | `string` | Value of `gen_ai.operation.name` attribute; empty string if absent | `attrs.Get("gen_ai.operation.name")` |
| `audit_kind` | `string` | Semantic role (see §3) | Inferred from span attributes |
| `selected_attributes` | `array` | Allowlisted span attributes (see §4) | See §4 |
| `status` | `string` | OTel status code as returned by `StatusCode.String()`: `"Unset"`, `"Ok"`, `"Error"` | `span.Status().Code().String()` |

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

**Current allowlist (v1):**

| Attribute key | Notes |
|---|---|
| `gen_ai.operation.name` | The LLM/agent operation type |
| `gen_ai.request.model` | Model requested by the client |
| `gen_ai.response.model` | Model that actually responded (may differ from request) |
| `gen_ai.system` | LLM provider (e.g. `"openai"`, `"anthropic"`) |
| `gen_ai.usage.input_tokens` | Prompt token count |
| `gen_ai.usage.output_tokens` | Completion token count |

Only attributes present in the span are included; missing allowlist keys are
omitted (no null entries). The resulting array preserves the allowlist order.

---

## 5. Entry construction protocol

This is the exact byte-level protocol used by `exporter.go` and expected by
any verifier.

```
1. rec           = SpanToRecord(span, seqInTrace)
2. canonicalBytes = canonical.Marshal(rec)          // compact JSON, field order per §2
3. traceIDBytes  = hex.DecodeString(rec.TraceID)    // 16 raw bytes
4. genesisSeed   = SHA256(traceIDBytes ‖ []byte(SchemaVersion))
5. sigPayload    = append(canonicalBytes, genesisSeed...)
6. entryHash     = SHA256(sigPayload)               // hex-encoded; used for B2 chain-linking
7. signature     = ed25519.Sign(privKey, sigPayload) // base64-encoded; NOT a pre-hash
```

The log entry JSON:
```json
{
  "record": { <AuditRecord fields per §2> },
  "signed": {
    "key_id":    "<hex(SHA256(publicKey))>",
    "algorithm": "ed25519",
    "entry_hash": "<hex(SHA256(sigPayload))>",
    "signature":  "<base64(ed25519.Sign(privKey, sigPayload))>"
  }
}
```

### Verification

A verifier MUST:
1. Reconstruct `canonicalBytes` by re-marshaling `record` from the log entry.
2. Re-derive `traceIDBytes` from `record.trace_id` and `genesisSeed` as in step 4.
3. Reconstruct `sigPayload = append(canonicalBytes, genesisSeed...)`.
4. Verify the Ed25519 signature: `ed25519.Verify(pubKey, sigPayload, base64Decode(signed.signature))`.
5. Optionally cross-check `entryHash = hex(SHA256(sigPayload))` to detect
   inconsistency between the stored hash and the recomputed canonical bytes.

The verifier MUST NOT derive `sigPayload` from the stored `entry_hash` — only
from a fresh re-serialization of `record`. This ensures a tampered record
cannot pass verification even if its stored hash is also replaced.

---

## 6. Canonical serialization

`canonical.Marshal` produces compact JSON (no spaces, no trailing newline) with
fields in the order defined by the `AuditRecord` struct. This is a deterministic
function: identical `AuditRecord` values produce byte-identical output across
all runs and language implementations.

The golden fixture is (paths relative to repo root):
- Input: `exporter/agentauditexporter/internal/record/testdata/v1_span_to_record_fixture.json`
- Canonical output: `exporter/agentauditexporter/internal/canonical/testdata/v1_canonical_fixture.json`

Note: the canonical fixture file ends with a single trailing newline added by editors.
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

# Guardrail Attribute Mapping — v2

> **Status:** Active · **Introduced:** Phase W8 · **Schema version:** `v2`

This document describes how guardrail evaluation events should be instrumented
as OTel spans so that `agentauditexporter` captures them correctly in
`selected_attributes`.

---

## Overview

When an AI agent framework evaluates a content-safety or policy guardrail, the
result should be recorded as an OTel span with `audit_kind: "guardrail"`. The
exporter infers `audit_kind = "guardrail"` whenever `gen_ai.guardrail.name` is
present on a span (see §3 of `docs/audit-record-schema.md` for the full
inference rules).

---

## Captured attributes (v2 allowlist)

| OTel attribute | Type | Required | Description |
|---|---|---|---|
| `gen_ai.guardrail.name` | `string` | Yes | Name of the policy or guardrail that evaluated this span. Typically the policy identifier used by the guardrail provider. Example: `"content-policy"`, `"pii-filter"` |
| `gen_ai.guardrail.action` | `string` | No | Action taken. SHOULD be one of `"block"`, `"warn"`, `"redact"`, `"allow"`. |
| `gen_ai.guardrail.reason` | `string` | No | Human-readable explanation of why the guardrail triggered. MAY be empty or absent when no violation occurred. |
| `gen_ai.guardrail.severity` | `string` | No | Severity of the detected policy violation. SHOULD be one of `"low"`, `"medium"`, `"high"`. Absent when action is `"allow"`. |

---

## Span instrumentation example

```go
ctx, span := tracer.Start(ctx, "guardrail.evaluate",
    trace.WithSpanKind(trace.SpanKindInternal),
)
defer span.End()

span.SetAttributes(
    attribute.String("gen_ai.guardrail.name",     "content-policy"),
    attribute.String("gen_ai.guardrail.action",   "block"),
    attribute.String("gen_ai.guardrail.reason",   "detected violent content in model output"),
    attribute.String("gen_ai.guardrail.severity", "high"),
)
```

---

## Resulting audit record (selected_attributes excerpt)

```json
"selected_attributes": [
  {"key": "gen_ai.guardrail.action",   "value": "block"},
  {"key": "gen_ai.guardrail.name",     "value": "content-policy"},
  {"key": "gen_ai.guardrail.reason",   "value": "detected violent content in model output"},
  {"key": "gen_ai.guardrail.severity", "value": "high"}
]
```

Attributes appear in allowlist order (alphabetical). Absent attributes are
omitted — there are never null entries.

---

## Verifier output

When verifying a log that contains guardrail spans, the `otel-agent-audit-verify`
CLI verifies their chain integrity and signatures identically to other span types.
Guardrail spans receive no special treatment in the report output; filtering by
`audit_kind` or `gen_ai.guardrail.action` value requires post-processing the log.

---

## Relationship to AuditKind

`audit_kind: "guardrail"` and the `gen_ai.guardrail.*` attributes are
complementary:

- `audit_kind` is a top-level classification field that allows fast filtering
  without parsing `selected_attributes`.
- `gen_ai.guardrail.*` attributes carry the semantics needed to reconstruct
  what happened (which policy, what action, why).

Both fields appear in the canonical bytes and are therefore part of the
entry hash. Tampering with either invalidates the Ed25519 signature.

// Package record defines the AuditRecord schema and its deterministic mapping
// from OTel spans.
//
// NOTE: These packages live inside the exporter module. The CLI at
// cmd/otel-agent-audit-verify imports them via same-module internal visibility
// (Go's internal rule permits this). A root-module restructuring was considered
// for B4 but deferred; the within-module approach is simpler and sufficient.
package record

import (
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// SchemaVersion is the current audit-record schema version.
// It is included in the genesis seed so chains of different schema versions
// never silently interleave.
//
// v2 adds gen_ai.guardrail.* attributes to the capture allowlist.
// v1 logs remain verifiable with GenesisSeedForSchema(traceID, "v1").
const SchemaVersion = "v2"

// AuditKind classifies the semantic role of a span in the audit log.
type AuditKind string

const (
	AuditKindTask      AuditKind = "task"
	AuditKindTool      AuditKind = "tool"
	AuditKindHandoff   AuditKind = "handoff"
	AuditKindGuardrail AuditKind = "guardrail"
	AuditKindError     AuditKind = "error"
)

// AttributeEntry is one key-value pair in SelectedAttributes.
//
// A sorted []AttributeEntry slice is used instead of map[string]string so
// canonical serialization is byte-stable across all language implementations
// without relying on any particular JSON library's map-key sort behavior.
type AttributeEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// AuditRecord is the versioned, schema-locked record of one span in the audit
// chain.
//
// BREAKING-CHANGE WARNING: encoding/json marshals struct fields in declaration
// order, so the JSON field order is load-bearing. Reordering fields here
// changes canonical bytes and breaks the chain. Any modification requires:
//   - a SchemaVersion bump
//   - a new cross-impl fixture in testdata/
//   - an update to docs/audit-record-schema.md
type AuditRecord struct {
	SchemaVersion      string           `json:"schema_version"`
	TraceID            string           `json:"trace_id"`
	SpanID             string           `json:"span_id"`
	ParentSpanID       string           `json:"parent_span_id"`
	SeqInTrace         int              `json:"seq_in_trace"`
	StartTimeUnixNano  uint64           `json:"start_time_unix_nano"`
	EndTimeUnixNano    uint64           `json:"end_time_unix_nano"`
	SpanName           string           `json:"span_name"`
	OtelKind           string           `json:"otel_kind"`
	GenAIOperation     string           `json:"gen_ai_operation"`
	AuditKind          AuditKind        `json:"audit_kind"`
	SelectedAttributes []AttributeEntry `json:"selected_attributes"`
	Status             string           `json:"status"`
}

// attributeAllowlist is the fixed, sorted set of span attribute keys captured
// in SelectedAttributes. Only keys in this list are ever included; the order
// is fixed so iteration produces a deterministically ordered slice without a
// runtime sort step.
var attributeAllowlist = []string{
	"gen_ai.guardrail.action",
	"gen_ai.guardrail.name",
	"gen_ai.guardrail.reason",
	"gen_ai.guardrail.severity",
	"gen_ai.operation.name",
	"gen_ai.request.model",
	"gen_ai.response.model",
	"gen_ai.system",
	"gen_ai.usage.input_tokens",
	"gen_ai.usage.output_tokens",
}

// SpanToRecord deterministically maps a ptrace.Span to an AuditRecord.
// seqInTrace is the span's 0-based position within its containing trace.
// The mapping is a pure function of span content: same span → same record.
func SpanToRecord(span ptrace.Span, seqInTrace int) AuditRecord {
	attrs := span.Attributes()

	var selected []AttributeEntry
	for _, key := range attributeAllowlist {
		if v, ok := attrs.Get(key); ok {
			selected = append(selected, AttributeEntry{Key: key, Value: v.AsString()})
		}
	}
	// attributeAllowlist is already sorted; SelectedAttributes inherits that order.

	genAIOp := ""
	if v, ok := attrs.Get("gen_ai.operation.name"); ok {
		genAIOp = v.AsString()
	}

	return AuditRecord{
		SchemaVersion:      SchemaVersion,
		TraceID:            span.TraceID().String(),
		SpanID:             span.SpanID().String(),
		ParentSpanID:       span.ParentSpanID().String(),
		SeqInTrace:         seqInTrace,
		StartTimeUnixNano:  uint64(span.StartTimestamp()),
		EndTimeUnixNano:    uint64(span.EndTimestamp()),
		SpanName:           span.Name(),
		OtelKind:           span.Kind().String(),
		GenAIOperation:     genAIOp,
		AuditKind:          inferAuditKind(span),
		SelectedAttributes: selected,
		Status:             span.Status().Code().String(),
	}
}

// inferAuditKind maps span content to an AuditKind.
// This is a best-effort heuristic for B1; B3 will add richer mapping when the
// agentauditselect processor is introduced.
func inferAuditKind(span ptrace.Span) AuditKind {
	attrs := span.Attributes()

	if _, ok := attrs.Get("gen_ai.guardrail.name"); ok {
		return AuditKindGuardrail
	}
	if v, ok := attrs.Get("gen_ai.operation.name"); ok {
		switch v.AsString() {
		case "execute_tool", "tool_call":
			return AuditKindTool
		case "handoff", "transfer":
			return AuditKindHandoff
		}
	}
	if span.Status().Code() == ptrace.StatusCodeError {
		return AuditKindError
	}
	return AuditKindTask
}

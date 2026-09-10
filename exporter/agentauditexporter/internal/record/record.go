// Package record defines the AuditRecord schema and its deterministic mapping
// from OTel spans.
//
// NOTE: These packages live inside the exporter module. The CLI at
// cmd/otel-agent-audit-verify imports them via same-module internal visibility
// (Go's internal rule permits this). A root-module restructuring was considered
// for B4 but deferred; the within-module approach is simpler and sufficient.
package record

import (
	"encoding/json"
	"fmt"
	"strconv"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

// SchemaVersion is the current audit-record schema version.
// It is included in the genesis seed so chains of different schema versions
// never silently interleave.
//
// v3 encodes start_time_unix_nano and end_time_unix_nano as decimal strings
// instead of JSON numbers (see UnixNano).
// v2 adds gen_ai.guardrail.* attributes to the capture allowlist.
// v1/v2 logs remain verifiable with GenesisSeedForSchema(traceID, "v1"/"v2").
const SchemaVersion = "v3"

// legacyNumericTimestampSchemas is the frozen set of schema versions whose
// canonical bytes encode start_time_unix_nano and end_time_unix_nano as JSON
// numbers. The set is closed: v3 and every later version encode them as
// decimal strings, so nothing is ever added here. A schema version outside the
// set is encoded with the current (decimal-string) rule.
var legacyNumericTimestampSchemas = map[string]struct{}{
	"v1": {},
	"v2": {},
}

// UsesNumericTimestamps reports whether records of schemaVersion encode their
// two timestamp fields as JSON numbers (v1, v2) rather than as decimal strings
// (v3 and later). It is the single source of truth for that dispatch, used by
// AuditRecord's JSON marshaller and by cross-version tests.
func UsesNumericTimestamps(schemaVersion string) bool {
	_, legacy := legacyNumericTimestampSchemas[schemaVersion]
	return legacy
}

// UnixNano is a Unix-epoch nanosecond timestamp.
//
// It marshals as a JSON decimal string ("1764547200123456789"), not as a JSON
// number. Nanosecond timestamps are ~1.7e18 and so exceed 2^53: a verifier that
// parses JSON numbers as IEEE-754 doubles (JavaScript's JSON.parse, several JCS
// implementations) silently rounds them and can no longer reproduce the
// canonical bytes, even though Go and Python are exact. The OTLP/JSON spec
// encodes fixed64 timestamps as decimal strings for exactly this reason.
//
// UnmarshalJSON accepts both a decimal string and a bare JSON number, so v1/v2
// log entries — which encode these fields as numbers — stay readable and
// therefore verifiable.
type UnixNano uint64

// MarshalJSON encodes t as a quoted decimal string. Records pinned to a legacy
// schema version never reach this method; see AuditRecord.MarshalJSON.
//
// The digits are appended straight into the quoted buffer rather than going
// through strconv.Quote: a decimal uint64 contains nothing JSON would escape,
// and this is on the per-span seal path, which marshals every record twice.
func (t UnixNano) MarshalJSON() ([]byte, error) {
	// 20 digits max for a uint64, plus the two quotes.
	b := make([]byte, 0, 22)
	b = append(b, '"')
	b = strconv.AppendUint(b, uint64(t), 10)
	return append(b, '"'), nil
}

// UnmarshalJSON decodes either a quoted decimal string (v3+) or a bare JSON
// number (v1/v2). Everything else is rejected rather than silently coerced: a
// float, an exponent form, a sign, a leading zero, a JSON escape sequence, or
// any non-decimal literal. The canonical form is the shortest run of ASCII
// digits, and accepting a second spelling of the same value would mean two
// inputs that canonicalize alike but hash differently.
//
// JSON null is the one exception: it decodes to zero, following the
// encoding/json convention that unmarshaling null into a value is a no-op on
// the wire's part. A record carrying null timestamps still fails verification,
// because re-marshaling emits "0" and the entry hash no longer matches.
func (t *UnixNano) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == "null" {
		*t = 0
		return nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	if len(s) > 1 && s[0] == '0' {
		return fmt.Errorf("record: non-canonical unix-nano timestamp %s: leading zeros", b)
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return fmt.Errorf("record: invalid unix-nano timestamp %s: %w", b, err)
	}
	*t = UnixNano(v)
	return nil
}

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
//   - new cross-impl fixtures in internal/record/testdata/,
//     internal/canonical/testdata/ and internal/chain/testdata/
//   - an update to docs/audit-record-schema.md, changelog included
//
// This struct describes the CURRENT (v3) wire shape. legacyV1V2Record is the
// frozen v1/v2 shape and must never be changed: a field added here must not
// appear in v1/v2 canonical bytes.
type AuditRecord struct {
	SchemaVersion      string           `json:"schema_version"`
	TraceID            string           `json:"trace_id"`
	SpanID             string           `json:"span_id"`
	ParentSpanID       string           `json:"parent_span_id"`
	SeqInTrace         int              `json:"seq_in_trace"`
	StartTimeUnixNano  UnixNano         `json:"start_time_unix_nano"`
	EndTimeUnixNano    UnixNano         `json:"end_time_unix_nano"`
	SpanName           string           `json:"span_name"`
	OtelKind           string           `json:"otel_kind"`
	GenAIOperation     string           `json:"gen_ai_operation"`
	AuditKind          AuditKind        `json:"audit_kind"`
	SelectedAttributes []AttributeEntry `json:"selected_attributes"`
	Status             string           `json:"status"`
}

// currentRecord is AuditRecord without its MarshalJSON method, so the encoder
// falls through to the struct tags (and to UnixNano's string encoding) instead
// of recursing into AuditRecord.MarshalJSON.
//
// There is deliberately no AuditRecord.UnmarshalJSON: decoding needs no
// version dispatch, because UnixNano accepts both the v1/v2 numeric form and
// the v3 decimal-string form. Adding one would also make *AuditRecord a
// json.Unmarshaler, which would silently disable json.Decoder's
// DisallowUnknownFields for every field of the record.
type currentRecord AuditRecord

// legacyV1V2Record is the frozen v1/v2 wire shape: the same fields in the same
// order, with the two timestamps as JSON numbers. It exists only so already
// written v1/v2 chains stay reproducible; it is never extended.
type legacyV1V2Record struct {
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

// MarshalJSON encodes r in the wire shape of its own schema_version: JSON
// numbers for the timestamps of a v1/v2 record, decimal strings for v3 and
// later. The encoding is a pure function of (field values, schema_version), so
// re-marshaling a stored record always reproduces the bytes that were hashed.
func (r AuditRecord) MarshalJSON() ([]byte, error) {
	if !UsesNumericTimestamps(r.SchemaVersion) {
		return json.Marshal(currentRecord(r))
	}
	return json.Marshal(legacyV1V2Record{
		SchemaVersion:      r.SchemaVersion,
		TraceID:            r.TraceID,
		SpanID:             r.SpanID,
		ParentSpanID:       r.ParentSpanID,
		SeqInTrace:         r.SeqInTrace,
		StartTimeUnixNano:  uint64(r.StartTimeUnixNano),
		EndTimeUnixNano:    uint64(r.EndTimeUnixNano),
		SpanName:           r.SpanName,
		OtelKind:           r.OtelKind,
		GenAIOperation:     r.GenAIOperation,
		AuditKind:          r.AuditKind,
		SelectedAttributes: r.SelectedAttributes,
		Status:             r.Status,
	})
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
		StartTimeUnixNano:  UnixNano(span.StartTimestamp()),
		EndTimeUnixNano:    UnixNano(span.EndTimestamp()),
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

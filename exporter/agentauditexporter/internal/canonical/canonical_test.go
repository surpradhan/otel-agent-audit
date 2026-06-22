package canonical

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
)

// fixtureRecord returns the canonical test record that must match the golden
// fixture in testdata/v1_canonical_fixture.json.
// It uses the same field values as the span-to-record fixture in
// internal/record/testdata/v1_span_to_record_fixture.json.
func fixtureRecord() record.AuditRecord {
	return record.AuditRecord{
		SchemaVersion:     record.SchemaVersion,
		TraceID:           "01010101010101010101010101010101",
		SpanID:            "0102030405060708",
		ParentSpanID:      "",
		SeqInTrace:        0,
		StartTimeUnixNano: 1000000000,
		EndTimeUnixNano:   2000000000,
		SpanName:          "gen_ai.chat",
		OtelKind:          "Client",
		GenAIOperation:    "chat",
		AuditKind:         record.AuditKindTask,
		SelectedAttributes: []record.AttributeEntry{
			{Key: "gen_ai.operation.name", Value: "chat"},
			{Key: "gen_ai.request.model", Value: "gpt-4o"},
			{Key: "gen_ai.system", Value: "openai"},
		},
		Status: "Ok",
	}
}

// TestMarshal_GoldenFixture is the cross-impl lock test: the canonical bytes
// for the fixture record must match testdata/v1_canonical_fixture.json
// byte-for-byte. Any encoding change that alters this output is a breaking
// chain-format change and requires a schema_version bump.
func TestMarshal_GoldenFixture(t *testing.T) {
	got, err := Marshal(fixtureRecord())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	const fixturePath = "testdata/v1_canonical_fixture.json"
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}

	// Trim trailing whitespace for editor-agnostic comparison.
	gotStr := strings.TrimRight(string(got), "\n\r ")
	wantStr := strings.TrimRight(string(want), "\n\r ")
	if gotStr != wantStr {
		t.Errorf("canonical bytes diverge from golden fixture.\ngot:  %s\nwant: %s", got, want)
	}
}

func TestMarshal_Deterministic(t *testing.T) {
	rec := fixtureRecord()
	a, err := Marshal(rec)
	if err != nil {
		t.Fatalf("first Marshal: %v", err)
	}
	b, err := Marshal(rec)
	if err != nil {
		t.Fatalf("second Marshal: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Error("Marshal is non-deterministic: two calls on the same record produced different bytes")
	}
}

func TestUnmarshal_RoundTrip(t *testing.T) {
	original := fixtureRecord()
	encoded, err := Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	decoded, err := Unmarshal(encoded)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	reEncoded, err := Marshal(decoded)
	if err != nil {
		t.Fatalf("re-Marshal: %v", err)
	}
	if !bytes.Equal(encoded, reEncoded) {
		t.Errorf("round-trip produced different bytes.\noriginal: %s\nafter:    %s", encoded, reEncoded)
	}
}

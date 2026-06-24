package canonical

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
)

// fixtureRecord returns the canonical test record used in golden-fixture tests.
// It uses the same field values as internal/record/testdata/v2_span_to_record_fixture.json.
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

// TestMarshal_GoldenFixture is the v2 cross-impl lock test: the canonical bytes
// for the fixture record must match testdata/v2_canonical_fixture.json
// byte-for-byte. Any encoding change that alters this output is a breaking
// chain-format change and requires a schema_version bump.
func TestMarshal_GoldenFixture(t *testing.T) {
	got, err := Marshal(fixtureRecord())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	const fixturePath = "testdata/v2_canonical_fixture.json"
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}

	// Trim trailing whitespace for editor-agnostic comparison.
	gotStr := strings.TrimRight(string(got), "\n\r ")
	wantStr := strings.TrimRight(string(want), "\n\r ")
	if gotStr != wantStr {
		t.Errorf("canonical bytes diverge from v2 golden fixture.\ngot:  %s\nwant: %s", got, want)
	}
}

// TestMarshal_GoldenFixture_V1Regression locks the v1 canonical bytes: any
// change that mutates testdata/v1_canonical_fixture.json would invalidate
// existing v1 audit chains (genesis seed encodes schema version, so
// cross-version interleaving is impossible, but serialisation bytes must remain
// stable so verifiers can reconstruct historical hashes).
func TestMarshal_GoldenFixture_V1Regression(t *testing.T) {
	rec := fixtureRecord()
	rec.SchemaVersion = "v1" // pin to frozen v1 bytes

	got, err := Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	const fixturePath = "testdata/v1_canonical_fixture.json"
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}

	gotStr := strings.TrimRight(string(got), "\n\r ")
	wantStr := strings.TrimRight(string(want), "\n\r ")
	if gotStr != wantStr {
		t.Errorf("v1 regression: canonical bytes diverged from frozen v1 fixture.\ngot:  %s\nwant: %s", got, want)
	}
}

// TestMarshal_GoldenFixture_Seq1 locks the v2 canonical bytes for the seq_in_trace=1
// record. Together with TestMarshal_GoldenFixture (seq=0) this covers the full
// two-span chain fixture used in TestTwoSpanChainFixture_FromFile.
func TestMarshal_GoldenFixture_Seq1(t *testing.T) {
	rec := record.AuditRecord{
		SchemaVersion:     record.SchemaVersion,
		TraceID:           "01010101010101010101010101010101",
		SpanID:            "0102030405060708",
		ParentSpanID:      "",
		SeqInTrace:        1,
		StartTimeUnixNano: 2000000000,
		EndTimeUnixNano:   3000000000,
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
	got, err := Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	const fixturePath = "testdata/v2_canonical_seq1_fixture.json"
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}

	gotStr := strings.TrimRight(string(got), "\n\r ")
	wantStr := strings.TrimRight(string(want), "\n\r ")
	if gotStr != wantStr {
		t.Errorf("canonical bytes diverge from v2 seq1 golden fixture.\ngot:  %s\nwant: %s", got, want)
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

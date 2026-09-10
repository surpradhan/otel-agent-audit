package canonical

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
)

// Timestamps for the v3 fixtures. Both exceed 2^53, so they are only
// reproducible by a verifier that never routes them through a float64 — which
// is what the decimal-string encoding guarantees.
const (
	v3StartNano     = 1764547200123456789
	v3EndNano       = 1764547200987654321
	v3Seq1StartNano = 1764547200987654321
	v3Seq1EndNano   = 1764547201123456789
)

// fixtureRecord returns the canonical test record used in golden-fixture tests.
// It uses the same field values as internal/record/testdata/v3_span_to_record_fixture.json.
func fixtureRecord() record.AuditRecord {
	rec := legacyFixtureRecord()
	rec.SchemaVersion = record.SchemaVersion
	rec.StartTimeUnixNano = v3StartNano
	rec.EndTimeUnixNano = v3EndNano
	return rec
}

// legacyFixtureRecord returns the record the frozen v1/v2 fixtures were minted
// from. Its small timestamps and its numeric encoding are both load-bearing:
// changing either would invalidate audit logs already on disk. The caller pins
// SchemaVersion to "v1" or "v2".
func legacyFixtureRecord() record.AuditRecord {
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

// TestMarshal_GoldenFixture is the v3 cross-impl lock test: the canonical bytes
// for the fixture record must match testdata/v3_canonical_fixture.json
// byte-for-byte. Any encoding change that alters this output is a breaking
// chain-format change and requires a schema_version bump.
func TestMarshal_GoldenFixture(t *testing.T) {
	got, err := Marshal(fixtureRecord())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	const fixturePath = "testdata/v3_canonical_fixture.json"
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}

	// Trim trailing whitespace for editor-agnostic comparison.
	gotStr := strings.TrimRight(string(got), "\n\r ")
	wantStr := strings.TrimRight(string(want), "\n\r ")
	if gotStr != wantStr {
		t.Errorf("canonical bytes diverge from v3 golden fixture.\ngot:  %s\nwant: %s", got, want)
	}
}

// TestMarshal_GoldenFixture_V1Regression locks the v1 canonical bytes: any
// change that mutates testdata/v1_canonical_fixture.json would invalidate
// existing v1 audit chains (genesis seed encodes schema version, so
// cross-version interleaving is impossible, but serialisation bytes must remain
// stable so verifiers can reconstruct historical hashes).
func TestMarshal_GoldenFixture_V1Regression(t *testing.T) {
	rec := legacyFixtureRecord()
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

// TestMarshal_GoldenFixture_Seq1 locks the v3 canonical bytes for the seq_in_trace=1
// record. Together with TestMarshal_GoldenFixture (seq=0) this covers the full
// two-span chain fixture used in TestTwoSpanChainFixtures_FromFile.
func TestMarshal_GoldenFixture_Seq1(t *testing.T) {
	rec := fixtureRecord()
	rec.SeqInTrace = 1
	rec.StartTimeUnixNano = v3Seq1StartNano
	rec.EndTimeUnixNano = v3Seq1EndNano

	got, err := Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	const fixturePath = "testdata/v3_canonical_seq1_fixture.json"
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}

	gotStr := strings.TrimRight(string(got), "\n\r ")
	wantStr := strings.TrimRight(string(want), "\n\r ")
	if gotStr != wantStr {
		t.Errorf("canonical bytes diverge from v3 seq1 golden fixture.\ngot:  %s\nwant: %s", got, want)
	}
}

// TestMarshal_GoldenFixture_V2Regression locks the v2 canonical bytes, which
// encode both timestamps as JSON numbers. v2 logs exist on disk and their
// hashes must stay reproducible; the numeric encoding is frozen for them even
// though v3 no longer uses it.
func TestMarshal_GoldenFixture_V2Regression(t *testing.T) {
	rec := legacyFixtureRecord()
	rec.SchemaVersion = "v2" // pin to frozen v2 bytes

	got, err := Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	const fixturePath = "testdata/v2_canonical_fixture.json"
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}

	gotStr := strings.TrimRight(string(got), "\n\r ")
	wantStr := strings.TrimRight(string(want), "\n\r ")
	if gotStr != wantStr {
		t.Errorf("v2 regression: canonical bytes diverged from frozen v2 fixture.\ngot:  %s\nwant: %s", got, want)
	}
}

// TestMarshal_TimestampEncodingIsTheOnlyV2ToV3Change proves the v3 bump is
// exactly the timestamp encoding and nothing else: swapping the version string
// and unquoting the two timestamp values turns v3 bytes into v2 bytes. If a
// future edit changes any other field, this test fails and forces the change to
// be justified as its own chain-format decision.
func TestMarshal_TimestampEncodingIsTheOnlyV2ToV3Change(t *testing.T) {
	rec := legacyFixtureRecord()

	rec.SchemaVersion = "v3"
	v3Bytes, err := Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal v3: %v", err)
	}
	rec.SchemaVersion = "v2"
	v2Bytes, err := Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal v2: %v", err)
	}

	derived := strings.NewReplacer(
		`"schema_version":"v3"`, `"schema_version":"v2"`,
		`"start_time_unix_nano":"1000000000"`, `"start_time_unix_nano":1000000000`,
		`"end_time_unix_nano":"2000000000"`, `"end_time_unix_nano":2000000000`,
	).Replace(string(v3Bytes))

	if derived != string(v2Bytes) {
		t.Errorf("v3 differs from v2 beyond the timestamp encoding.\n  v3-derived: %s\n  v2 actual:  %s", derived, v2Bytes)
	}
}

// TestUnmarshal_ReMarshalReproducesEveryFixture is the cross-version verifier
// contract: for every stored fixture, decoding it and re-encoding it must
// reproduce the file's bytes exactly. This is what lets one verifier binary
// re-derive the hashes of a v1, v2 or v3 log without knowing its vintage in
// advance — decoding accepts both timestamp encodings, and re-encoding follows
// the record's own schema_version.
func TestUnmarshal_ReMarshalReproducesEveryFixture(t *testing.T) {
	for _, fixturePath := range []string{
		"testdata/v1_canonical_fixture.json",
		"testdata/v1_canonical_seq1_fixture.json",
		"testdata/v2_canonical_fixture.json",
		"testdata/v2_canonical_seq1_fixture.json",
		"testdata/v3_canonical_fixture.json",
		"testdata/v3_canonical_seq1_fixture.json",
	} {
		t.Run(fixturePath, func(t *testing.T) {
			raw, err := os.ReadFile(fixturePath)
			if err != nil {
				t.Fatalf("reading fixture: %v", err)
			}
			want := strings.TrimRight(string(raw), "\n\r ")

			rec, err := Unmarshal([]byte(want))
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			got, err := Marshal(rec)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(got) != want {
				t.Errorf("re-marshal does not reproduce the fixture.\ngot:  %s\nwant: %s", got, want)
			}
		})
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

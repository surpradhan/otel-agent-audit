package record

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// Timestamps for the v3 golden fixture. Both exceed 2^53 (9007199254740992),
// so a verifier that parses JSON numbers as IEEE-754 doubles cannot round-trip
// them — which is precisely why v3 encodes them as decimal strings.
const (
	v3FixtureStartNano = 1764547200123456789
	v3FixtureEndNano   = 1764547200987654321
)

// fixtureSpan builds the legacy-valued test span used in the frozen v1/v2
// golden-fixture regressions. Its timestamps are small (1e9/2e9) because the
// v1 and v2 fixtures were minted with those values and can never change.
func fixtureSpan() ptrace.Span {
	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetTraceID(pcommon.TraceID([16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}))
	span.SetSpanID(pcommon.SpanID([8]byte{1, 2, 3, 4, 5, 6, 7, 8}))
	// parent span ID is zero-value (no parent)
	span.SetName("gen_ai.chat")
	span.SetKind(ptrace.SpanKindClient)
	span.SetStartTimestamp(pcommon.Timestamp(1000000000))
	span.SetEndTimestamp(pcommon.Timestamp(2000000000))
	span.Status().SetCode(ptrace.StatusCodeOk)
	span.Attributes().PutStr("gen_ai.operation.name", "chat")
	span.Attributes().PutStr("gen_ai.request.model", "gpt-4o")
	span.Attributes().PutStr("gen_ai.system", "openai")
	return span
}

// fixtureSpanV3 is fixtureSpan with realistic nanosecond timestamps — the span
// the current (v3) golden fixture is minted from.
func fixtureSpanV3() ptrace.Span {
	span := fixtureSpan()
	span.SetStartTimestamp(pcommon.Timestamp(v3FixtureStartNano))
	span.SetEndTimestamp(pcommon.Timestamp(v3FixtureEndNano))
	return span
}

// TestSpanToRecord_GoldenFixture is the v3 cross-impl lock: SpanToRecord must
// produce byte-for-byte JSON matching testdata/v3_span_to_record_fixture.json,
// with both timestamps encoded as decimal strings.
func TestSpanToRecord_GoldenFixture(t *testing.T) {
	span := fixtureSpanV3()
	got := SpanToRecord(span, 0)

	gotJSON, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}

	const fixturePath = "testdata/v3_span_to_record_fixture.json"
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}

	// Trim trailing whitespace for editor-agnostic comparison.
	if strings.TrimRight(string(gotJSON), "\n\r ") != strings.TrimRight(string(want), "\n\r ") {
		t.Errorf("SpanToRecord output diverges from v3 fixture.\ngot:\n%s\nwant:\n%s", gotJSON, want)
	}
}

// TestSpanToRecord_GoldenFixture_V2Regression locks the v2 schema bytes, which
// encode both timestamps as JSON numbers. Any change here would invalidate
// existing v2 audit logs.
func TestSpanToRecord_GoldenFixture_V2Regression(t *testing.T) {
	span := fixtureSpan()
	got := SpanToRecord(span, 0)
	got.SchemaVersion = "v2" // pin to v2 for regression comparison

	gotJSON, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}

	const fixturePath = "testdata/v2_span_to_record_fixture.json"
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}

	if strings.TrimRight(string(gotJSON), "\n\r ") != strings.TrimRight(string(want), "\n\r ") {
		t.Errorf("v2 regression: record bytes diverged from frozen v2 fixture.\ngot:\n%s\nwant:\n%s", gotJSON, want)
	}
}

// TestSpanToRecord_GoldenFixture_V1Regression locks the v1 schema bytes by
// constructing a record with SchemaVersion "v1" explicitly and comparing it to
// the frozen testdata/v1_span_to_record_fixture.json. Any change here would
// invalidate existing v1 audit logs.
func TestSpanToRecord_GoldenFixture_V1Regression(t *testing.T) {
	span := fixtureSpan()
	got := SpanToRecord(span, 0)
	got.SchemaVersion = "v1" // pin to v1 for regression comparison

	gotJSON, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}

	const fixturePath = "testdata/v1_span_to_record_fixture.json"
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}

	if strings.TrimRight(string(gotJSON), "\n\r ") != strings.TrimRight(string(want), "\n\r ") {
		t.Errorf("v1 regression: record bytes diverged from frozen v1 fixture.\ngot:\n%s\nwant:\n%s", gotJSON, want)
	}
}

func TestSpanToRecord_Deterministic(t *testing.T) {
	span := fixtureSpan()
	a := SpanToRecord(span, 0)
	b := SpanToRecord(span, 0)

	aJSON, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("json.Marshal(a): %v", err)
	}
	bJSON, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("json.Marshal(b): %v", err)
	}

	if string(aJSON) != string(bJSON) {
		t.Error("SpanToRecord is non-deterministic: two calls on the same span produced different output")
	}
}

func TestSpanToRecord_SelectedAttributesOrder(t *testing.T) {
	// Insert attributes in reverse allowlist order; output must still be sorted.
	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.Attributes().PutStr("gen_ai.system", "openai")
	span.Attributes().PutStr("gen_ai.request.model", "gpt-4o")
	span.Attributes().PutStr("gen_ai.operation.name", "chat")

	rec := SpanToRecord(span, 0)
	if len(rec.SelectedAttributes) != 3 {
		t.Fatalf("expected 3 attributes, got %d", len(rec.SelectedAttributes))
	}
	// attributeAllowlist order: operation.name < request.model < system (alphabetical).
	// Guardrail attrs come before operation.name but are not set on this span.
	if rec.SelectedAttributes[0].Key != "gen_ai.operation.name" {
		t.Errorf("index 0: want gen_ai.operation.name, got %s", rec.SelectedAttributes[0].Key)
	}
	if rec.SelectedAttributes[1].Key != "gen_ai.request.model" {
		t.Errorf("index 1: want gen_ai.request.model, got %s", rec.SelectedAttributes[1].Key)
	}
	if rec.SelectedAttributes[2].Key != "gen_ai.system" {
		t.Errorf("index 2: want gen_ai.system, got %s", rec.SelectedAttributes[2].Key)
	}
}

// TestSpanToRecord_GuardrailAttributes verifies that v2 gen_ai.guardrail.*
// attributes are captured in SelectedAttributes and appear before
// gen_ai.operation.name in the sorted allowlist order.
func TestSpanToRecord_GuardrailAttributes(t *testing.T) {
	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.Attributes().PutStr("gen_ai.guardrail.action", "block")
	span.Attributes().PutStr("gen_ai.guardrail.name", "content-policy")
	span.Attributes().PutStr("gen_ai.guardrail.reason", "violent content")
	span.Attributes().PutStr("gen_ai.guardrail.severity", "high")
	span.Attributes().PutStr("gen_ai.operation.name", "chat")

	rec := SpanToRecord(span, 0)

	if len(rec.SelectedAttributes) != 5 {
		t.Fatalf("expected 5 selected attributes, got %d", len(rec.SelectedAttributes))
	}
	// Must appear in allowlist (alphabetical) order.
	wantKeys := []string{
		"gen_ai.guardrail.action",
		"gen_ai.guardrail.name",
		"gen_ai.guardrail.reason",
		"gen_ai.guardrail.severity",
		"gen_ai.operation.name",
	}
	for i, want := range wantKeys {
		if rec.SelectedAttributes[i].Key != want {
			t.Errorf("SelectedAttributes[%d]: got %q, want %q", i, rec.SelectedAttributes[i].Key, want)
		}
	}
	if rec.SelectedAttributes[0].Value != "block" {
		t.Errorf("guardrail.action value: got %q, want %q", rec.SelectedAttributes[0].Value, "block")
	}
	if rec.SchemaVersion != "v3" {
		t.Errorf("SchemaVersion: got %q, want %q", rec.SchemaVersion, "v3")
	}
}

func TestSpanToRecord_AuditKinds(t *testing.T) {
	cases := []struct {
		name      string
		setupSpan func(ptrace.Span)
		want      AuditKind
	}{
		{
			name: "guardrail",
			setupSpan: func(s ptrace.Span) {
				s.Attributes().PutStr("gen_ai.guardrail.name", "content-policy")
			},
			want: AuditKindGuardrail,
		},
		{
			name: "tool",
			setupSpan: func(s ptrace.Span) {
				s.Attributes().PutStr("gen_ai.operation.name", "execute_tool")
			},
			want: AuditKindTool,
		},
		{
			name: "handoff",
			setupSpan: func(s ptrace.Span) {
				s.Attributes().PutStr("gen_ai.operation.name", "handoff")
			},
			want: AuditKindHandoff,
		},
		{
			name: "error",
			setupSpan: func(s ptrace.Span) {
				s.Status().SetCode(ptrace.StatusCodeError)
			},
			want: AuditKindError,
		},
		{
			name:      "default task",
			setupSpan: func(s ptrace.Span) {},
			want:      AuditKindTask,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			td := ptrace.NewTraces()
			span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
			tc.setupSpan(span)
			rec := SpanToRecord(span, 0)
			if rec.AuditKind != tc.want {
				t.Errorf("got %q, want %q", rec.AuditKind, tc.want)
			}
		})
	}
}

// TestUnixNano_MarshalsAsDecimalString is the core v3 property: the timestamp
// fields leave Go as JSON strings, never as JSON numbers.
func TestUnixNano_MarshalsAsDecimalString(t *testing.T) {
	got, err := json.Marshal(UnixNano(v3FixtureStartNano))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if want := `"1764547200123456789"`; string(got) != want {
		t.Errorf("UnixNano JSON: got %s, want %s", got, want)
	}
}

// TestUnixNano_ExceedsFloat64Precision documents why v3 exists: the fixture
// timestamps cannot survive a round-trip through an IEEE-754 double, so a
// verifier whose JSON parser produces float64 (JavaScript's JSON.parse, some
// JCS libraries) could not reproduce the canonical bytes from a numeric
// encoding. Encoding as a decimal string sidesteps the parser entirely.
func TestUnixNano_ExceedsFloat64Precision(t *testing.T) {
	const maxExactFloat64Int = uint64(1) << 53 // 9007199254740992

	for _, nanos := range []uint64{v3FixtureStartNano, v3FixtureEndNano} {
		if nanos <= maxExactFloat64Int {
			t.Fatalf("fixture timestamp %d does not exceed 2^53; it would not exercise the v3 rationale", nanos)
		}
		if roundTripped := uint64(float64(nanos)); roundTripped == nanos {
			t.Errorf("timestamp %d survived a float64 round-trip unchanged; pick a value that does not", nanos)
		}
	}

	// The string encoding, by contrast, is exact.
	encoded, err := json.Marshal(UnixNano(v3FixtureStartNano))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var decoded UnixNano
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if uint64(decoded) != v3FixtureStartNano {
		t.Errorf("string round-trip lost precision: got %d, want %d", decoded, uint64(v3FixtureStartNano))
	}
}

// TestUnixNano_UnmarshalAcceptsBothEncodings verifies the compatibility half of
// the contract: v1/v2 entries store these fields as JSON numbers and must stay
// decodable, while v3 entries store them as decimal strings.
func TestUnixNano_UnmarshalAcceptsBothEncodings(t *testing.T) {
	cases := []struct {
		name string
		json string
		want uint64
	}{
		{"v1_v2 numeric", `1764547200123456789`, 1764547200123456789},
		{"v3 decimal string", `"1764547200123456789"`, 1764547200123456789},
		{"zero numeric", `0`, 0},
		{"zero string", `"0"`, 0},
		{"max uint64", `"18446744073709551615"`, 18446744073709551615},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got UnixNano
			if err := json.Unmarshal([]byte(tc.json), &got); err != nil {
				t.Fatalf("Unmarshal(%s): %v", tc.json, err)
			}
			if uint64(got) != tc.want {
				t.Errorf("got %d, want %d", uint64(got), tc.want)
			}
		})
	}
}

// TestUnixNano_UnmarshalRejectsNonDecimal verifies that lossy or ambiguous
// encodings are refused rather than silently coerced — a float literal is
// exactly the failure mode v3 is meant to make impossible.
func TestUnixNano_UnmarshalRejectsNonDecimal(t *testing.T) {
	for _, bad := range []string{
		`1.764547200123456789e18`,
		`1764547200123456789.0`,
		`-1`,
		`"-1"`,
		`"1e9"`,
		`"1_000"`,
		`""`,
		`true`,
		`{}`,
		`"18446744073709551616"`, // overflows uint64
		// Non-canonical spellings of a valid value. Accepting a second
		// spelling would mean two inputs that canonicalize alike but hash
		// differently, so the parser must agree with the spec's "shortest
		// run of ASCII digits, no leading zeros, no escapes".
		`"01"`,
		`"0000001764547200123456789"`,
		`01`,
		// A JSON escape sequence spelling the same digits.
		`"\u0031764547200123456789"`,
	} {
		t.Run(bad, func(t *testing.T) {
			var got UnixNano
			if err := json.Unmarshal([]byte(bad), &got); err == nil {
				t.Errorf("Unmarshal(%s) succeeded with %d; want an error", bad, uint64(got))
			}
		})
	}
}

// TestUnixNano_UnmarshalNullDecodesToZero pins the one input that is accepted
// rather than rejected. Decoding null to zero follows the encoding/json
// convention, and it must not leave whatever happened to be in the receiver.
// A record carrying null timestamps is still caught downstream: re-marshaling
// emits "0", so its entry hash no longer matches and verification reports it.
func TestUnixNano_UnmarshalNullDecodesToZero(t *testing.T) {
	got := UnixNano(42)
	if err := json.Unmarshal([]byte(`null`), &got); err != nil {
		t.Fatalf("Unmarshal(null): %v", err)
	}
	if got != 0 {
		t.Errorf("Unmarshal(null): got %d, want 0 — null must not leave the prior value in place", uint64(got))
	}
}

// TestAuditRecord_RoundTripsAcrossSchemaVersions pins the invariant the whole
// chain rests on: re-marshaling a decoded record reproduces the bytes it was
// decoded from, for every schema version — numeric for v1/v2, string for v3.
func TestAuditRecord_RoundTripsAcrossSchemaVersions(t *testing.T) {
	cases := []struct {
		schemaVersion string
		wantTimestamp string
	}{
		{"v1", `"start_time_unix_nano":1764547200123456789`},
		{"v2", `"start_time_unix_nano":1764547200123456789`},
		{"v3", `"start_time_unix_nano":"1764547200123456789"`},
		{"v4-hypothetical", `"start_time_unix_nano":"1764547200123456789"`},
	}
	for _, tc := range cases {
		t.Run(tc.schemaVersion, func(t *testing.T) {
			rec := SpanToRecord(fixtureSpanV3(), 0)
			rec.SchemaVersion = tc.schemaVersion

			encoded, err := json.Marshal(rec)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if !strings.Contains(string(encoded), tc.wantTimestamp) {
				t.Errorf("encoding for %s: %s does not contain %s", tc.schemaVersion, encoded, tc.wantTimestamp)
			}

			var decoded AuditRecord
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if decoded.StartTimeUnixNano != rec.StartTimeUnixNano || decoded.EndTimeUnixNano != rec.EndTimeUnixNano {
				t.Errorf("timestamps changed across round-trip: got (%d, %d), want (%d, %d)",
					decoded.StartTimeUnixNano, decoded.EndTimeUnixNano, rec.StartTimeUnixNano, rec.EndTimeUnixNano)
			}

			reEncoded, err := json.Marshal(decoded)
			if err != nil {
				t.Fatalf("re-Marshal: %v", err)
			}
			if string(reEncoded) != string(encoded) {
				t.Errorf("re-marshal is not byte-identical.\n  first:  %s\n  second: %s", encoded, reEncoded)
			}
		})
	}
}

// TestUsesNumericTimestamps pins the frozen legacy set. v1 and v2 are the only
// schema versions whose canonical bytes carry numeric timestamps; the set never
// grows.
func TestUsesNumericTimestamps(t *testing.T) {
	for _, v := range []string{"v1", "v2"} {
		if !UsesNumericTimestamps(v) {
			t.Errorf("UsesNumericTimestamps(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"v3", "v4", "", "V2", "v2 "} {
		if UsesNumericTimestamps(v) {
			t.Errorf("UsesNumericTimestamps(%q) = true, want false", v)
		}
	}
	if UsesNumericTimestamps(SchemaVersion) {
		t.Errorf("the current SchemaVersion %q must not use numeric timestamps", SchemaVersion)
	}
}

// TestLegacyRecordMirrorsAuditRecord guards the one hazard of keeping a frozen
// v1/v2 mirror struct: if AuditRecord gains, loses, renames or reorders a
// field without a matching schema decision, the mirror silently drops it from
// v1/v2 output. The mirror must stay field-for-field identical to AuditRecord
// apart from the two timestamp fields' Go types.
func TestLegacyRecordMirrorsAuditRecord(t *testing.T) {
	current := reflect.TypeOf(AuditRecord{})
	legacy := reflect.TypeOf(legacyV1V2Record{})

	if current.NumField() != legacy.NumField() {
		t.Fatalf("field count: AuditRecord has %d, legacyV1V2Record has %d", current.NumField(), legacy.NumField())
	}

	timestampFields := map[string]bool{"StartTimeUnixNano": true, "EndTimeUnixNano": true}
	for i := range current.NumField() {
		cf, lf := current.Field(i), legacy.Field(i)
		if cf.Name != lf.Name {
			t.Errorf("field %d: AuditRecord has %q, legacyV1V2Record has %q", i, cf.Name, lf.Name)
			continue
		}
		if cf.Tag.Get("json") != lf.Tag.Get("json") {
			t.Errorf("field %q: json tag %q vs %q", cf.Name, cf.Tag.Get("json"), lf.Tag.Get("json"))
		}
		if timestampFields[cf.Name] {
			if cf.Type != reflect.TypeOf(UnixNano(0)) {
				t.Errorf("field %q: AuditRecord type is %s, want record.UnixNano", cf.Name, cf.Type)
			}
			if lf.Type.Kind() != reflect.Uint64 || lf.Type == reflect.TypeOf(UnixNano(0)) {
				t.Errorf("field %q: legacyV1V2Record type is %s, want plain uint64", cf.Name, lf.Type)
			}
			continue
		}
		if cf.Type != lf.Type {
			t.Errorf("field %q: type %s vs %s", cf.Name, cf.Type, lf.Type)
		}
	}
}

// TestUnixNano_MarshalJSONAllocatesOnce pins the single-allocation encoding.
// Nothing else would catch a regression here: the obvious implementation
// (quoting a freshly formatted string) allocates twice and passes every other
// test in this package. Marshal runs twice per record on the seal path, so the
// difference is per-span in a telemetry pipeline.
func TestUnixNano_MarshalJSONAllocatesOnce(t *testing.T) {
	ts := UnixNano(v3FixtureStartNano)
	got := testing.AllocsPerRun(1000, func() {
		if _, err := ts.MarshalJSON(); err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
	})
	if got > 1 {
		t.Errorf("MarshalJSON allocations per call: got %v, want at most 1", got)
	}
}

// TestRestampableToCurrent pins the membership of a set that is a curated claim
// rather than a frozen fact. Each entry asserts "data-compatible with
// SchemaVersion" — a claim relative to a constant that moves, so bumping
// SchemaVersion silently re-asserts every entry against a version nobody
// re-examined. Nothing else catches that: with SchemaVersion bumped and this set
// left alone, only the golden fixtures fail, and re-minting them is a step the
// bump requires anyway.
//
// Asserting the literal membership forces a bump author to edit this test
// deliberately, at which point the question "is v3 data still compatible with
// v4?" has to be answered rather than assumed. See the schema-bump checklist in
// docs/audit-record-schema.md §1.
func TestRestampableToCurrent(t *testing.T) {
	for _, v := range []string{"v2", "v3"} {
		if !RestampableToCurrent(v) {
			t.Errorf("RestampableToCurrent(%q) = false, want true", v)
		}
	}
	// v1 must never be restampable: v2 widened attributeAllowlist, so a v1
	// record's selected_attributes were captured under narrower rules.
	for _, v := range []string{"v1", "v99", "v4", "", "V2", "v2 "} {
		if RestampableToCurrent(v) {
			t.Errorf("RestampableToCurrent(%q) = true, want false", v)
		}
	}
	// The current version is trivially compatible with itself; a bump that
	// leaves it out of the set has not been thought through.
	if !RestampableToCurrent(SchemaVersion) {
		t.Errorf("the current SchemaVersion %q must be in restampableToCurrent — "+
			"re-evaluate every other member of the set at the same time", SchemaVersion)
	}
}

// TestImplemented pins which schema versions this binary can write. Every
// version here must have a marshalling path: v1 and v2 through the frozen
// legacy shape, v3 through the current struct. A version listed here without
// that code would let the exporter sign bytes it invented.
func TestImplemented(t *testing.T) {
	for _, v := range []string{"v1", "v2", "v3"} {
		if !Implemented(v) {
			t.Errorf("Implemented(%q) = false, want true", v)
		}
	}
	// A version from a rollback, or garbage, is not something we can write.
	for _, v := range []string{"v4", "v99", "", "V1", "v1 "} {
		if Implemented(v) {
			t.Errorf("Implemented(%q) = true, want false", v)
		}
	}
	if !Implemented(SchemaVersion) {
		t.Errorf("the current SchemaVersion %q must be implemented", SchemaVersion)
	}
	// Anything restampable must also be implemented: re-stamping rewrites a
	// record into the current shape, which presupposes we could read its own.
	for _, v := range []string{"v1", "v2", "v3", "v4", "v99", ""} {
		if RestampableToCurrent(v) && !Implemented(v) {
			t.Errorf("%q is restampable but not implemented — restamping presupposes implementing", v)
		}
	}
}

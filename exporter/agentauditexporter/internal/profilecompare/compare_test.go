package profilecompare

// Runs this repo's serialization (record.SpanToRecord + canonical.Marshal) over
// the data of each otel-span/canonical/1 vector, next to the profile
// implementation in profile_test.go, and pins every place the two agree and
// every place they differ. The prose version is
// docs/otel-canonical-profile-comparison.md; these tests are what keep it true.
//
// The two forms hash different objects and are not expected to produce the same
// bytes (TestCompare_HashesNeverCoincide). The comparison is about what each
// form commits to and what each refuses.
//
// Tests named TestFinding_* characterise behaviour of this repo that the
// profile treats as an error. They follow the repo's existing convention for a
// pinned, tracked defect (see internal/verify/rotation_boundary_test.go): each
// carries a BUG(#n) tag naming its open issue and asserts what the code does
// today, and whoever fixes the issue should flip the assertion rather than delete
// the test. Fixing #58 changes canonical bytes and so needs a schema_version bump
// under CLAUDE.md's chain-format discipline; the others change behaviour on
// malformed input only. The prefix lets `-run TestFinding_` select just these.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/canonical"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/chain"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/sign"
)

// ours serializes a pdata span the way the exporter does.
func ours(t *testing.T, s ptrace.Span) []byte {
	t.Helper()
	b, err := canonical.Marshal(record.SpanToRecord(s, 0))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeMap(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return m
}

type vectorCase struct {
	name        string
	canonical   []byte // the profile's canonical span bytes (the fixture)
	span        obj
	attrs       any
	pdata       ptrace.Span
	ourRecord   []byte
	profileSpan profileSpan
}

func loadCases(t *testing.T) []vectorCase {
	t.Helper()
	exp := loadExpected(t)
	if len(exp.Pass) != 8 {
		t.Fatalf("expected 8 pass vectors, found %d: the vendored set changed", len(exp.Pass))
	}
	var out []vectorCase
	for _, name := range sortedKeys(exp.Pass) {
		canon := readVector(t, "pass/"+name+".canonical.json")
		attrs, err := decodeOrdered(readVector(t, "pass/"+name+".attrs.json"))
		if err != nil {
			t.Fatal(err)
		}
		spanV, err := decodeOrdered(canon)
		if err != nil {
			t.Fatal(err)
		}
		span := spanV.(obj)
		ps, err := canonicalSpan(span, attrs)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		pd := buildSpan(t, span, attrs)
		out = append(out, vectorCase{name, canon, span, attrs, pd, ours(t, pd), ps})
	}
	return out
}

// otlpKind and otlpStatus are the numbers the profile hashes, mapped to the
// names this repo's records carry.
var (
	otlpKind   = []string{"Unspecified", "Internal", "Server", "Client", "Producer", "Consumer"}
	otlpStatus = []string{"Unset", "Ok", "Error"}
)

// --- Where the forms agree ------------------------------------------------

// Six of the profile's nine fields are carried by this repo's record with the
// same value, including both timestamps as decimal strings (the 2^53 boundary
// the profile and schema v3 both solve the same way) and the empty string for
// a span with no parent. kind and status_code carry the same information as
// names rather than numbers.
func TestCompare_SharedFieldsAgree(t *testing.T) {
	for _, c := range loadCases(t) {
		t.Run(c.name, func(t *testing.T) {
			theirs := decodeMap(t, c.canonical)
			mine := decodeMap(t, c.ourRecord)
			for _, f := range [][2]string{
				{"trace_id", "trace_id"},
				{"span_id", "span_id"},
				{"parent_span_id", "parent_span_id"},
				{"name", "span_name"},
				{"start_time_unix_nano", "start_time_unix_nano"},
				{"end_time_unix_nano", "end_time_unix_nano"},
			} {
				if theirs[f[0]] != mine[f[1]] {
					t.Errorf("%s vs %s: profile %v, record %v", f[0], f[1], theirs[f[0]], mine[f[1]])
				}
			}
			k := int(theirs["kind"].(float64))
			if mine["otel_kind"] != otlpKind[k] {
				t.Errorf("kind %d: record has %v, want %s", k, mine["otel_kind"], otlpKind[k])
			}
			sc := int(theirs["status_code"].(float64))
			if mine["status"] != otlpStatus[sc] {
				t.Errorf("status_code %d: record has %v, want %s", sc, mine["status"], otlpStatus[sc])
			}
		})
	}
}

// The forms hash different objects, so their bytes and hashes never coincide.
// Recorded so the premise of the comparison is itself tested.
func TestCompare_HashesNeverCoincide(t *testing.T) {
	for _, c := range loadCases(t) {
		if string(c.ourRecord) == string(c.canonical) || sha256Hex(c.ourRecord) == c.profileSpan.SpanSHA256 {
			t.Errorf("%s: forms coincide; the premise of the comparison changed", c.name)
		}
	}
}

// status.message is outside the profile's hash scope. It is outside this
// repo's record too: Status carries the code name only. Both sides are checked:
// the profile with OTLP's nested status object and with a flat field, this repo
// by setting a real message on a pdata span.
func TestCompare_StatusMessageIsOutsideBothForms(t *testing.T) {
	c := loadCases(t)[0]
	with := c.pdata
	before := ours(t, with)
	with.Status().SetMessage("upstream timed out after 30s")
	if after := ours(t, with); string(after) != string(before) {
		t.Errorf("a status message changed this repo's record:\n%s\n%s", before, after)
	}

	x := spanWith(t, "name", `"x"`)
	base := mustHash(t, x, `{}`).SpanSHA256
	for _, v := range []struct{ key, val string }{
		{"status", `{"code":1,"message":"upstream timed out after 30s"}`},
		{"status_message", `"upstream timed out after 30s"`},
	} {
		if got := mustHash(t, spanWith(t, v.key, v.val), `{}`).SpanSHA256; got != base {
			t.Errorf("a status message in field %q changed the profile's span hash", v.key)
		}
	}
}

// --- Where the forms differ by design --------------------------------------

// This repo's record is a projection: only the allowlisted gen_ai.* attributes
// are carried, as stringified key/value entries. The profile commits to every
// attribute through attributes_sha256. None of the profile's pass vectors use
// an allowlisted key, so every record here has no attributes at all, and a
// change to any other attribute is invisible to this repo's hash.
func TestCompare_AttributesOutsideTheAllowlistAreNotCommitted(t *testing.T) {
	for _, c := range loadCases(t) {
		if got := decodeMap(t, c.ourRecord)["selected_attributes"]; got != nil {
			t.Errorf("%s: selected_attributes = %v, want none (no vector attribute is allowlisted)", c.name, got)
		}
	}

	x := spanWith(t, "name", `"x"`)
	a := buildSpan(t, x, attrsOf(t, `{"http.method":{"s":"GET"}}`))
	b := buildSpan(t, x, attrsOf(t, `{"http.method":{"s":"POST"}}`))
	if string(ours(t, a)) != string(ours(t, b)) {
		t.Error("a non-allowlisted attribute now changes this repo's record; update the doc")
	}
	pa := mustHash(t, x, `{"http.method":{"s":"GET"}}`)
	pb := mustHash(t, x, `{"http.method":{"s":"POST"}}`)
	if pa.SpanSHA256 == pb.SpanSHA256 {
		t.Error("the profile's span hash should change with any attribute")
	}
}

// --- Where this repo's form is the weaker one ------------------------------

// FINDING: SpanToRecord stores v.AsString(), so the attribute's type is lost
// before hashing. An int, a double and a string that print alike, or raw bytes
// and their own base64 text, produce the same record bytes. The profile wraps
// every value in a one-key type tag so these are different bytes.
//
// Reachable for the allowlisted keys that are numeric in the semantic
// conventions (gen_ai.usage.input_tokens and gen_ai.usage.output_tokens).
func TestFinding_AttributeTypesCollide(t *testing.T) {
	// BUG(#58): attribute types are lost before hashing. Flip the collisions below
	// when the record carries the type.
	const key = "gen_ai.usage.input_tokens"
	mk := func(set func(m pcommon.Map)) []byte {
		s := ptrace.NewSpan()
		set(s.Attributes())
		return ours(t, s)
	}
	// carries guards against a vacuous pass: identical bytes only mean something
	// if the attribute actually reached the record.
	carries := func(rec []byte, want string) {
		t.Helper()
		if !strings.Contains(string(rec), want) {
			t.Fatalf("record does not carry %s (is the key still allowlisted?): %s", want, rec)
		}
	}
	intOne := mk(func(m pcommon.Map) { m.PutInt(key, 1) })
	strOne := mk(func(m pcommon.Map) { m.PutStr(key, "1") })
	dblOne := mk(func(m pcommon.Map) { m.PutDouble(key, 1.0) })
	carries(intOne, `"key":"gen_ai.usage.input_tokens","value":"1"`)
	carries(strOne, `"key":"gen_ai.usage.input_tokens","value":"1"`)
	carries(dblOne, `"key":"gen_ai.usage.input_tokens","value":"1"`)
	if string(intOne) != string(strOne) || string(intOne) != string(dblOne) {
		t.Errorf("int 1, string \"1\" and double 1.0 no longer collide:\n%s\n%s\n%s", intOne, strOne, dblOne)
	}

	boolTrue := mk(func(m pcommon.Map) { m.PutBool("gen_ai.system", true) })
	strTrue := mk(func(m pcommon.Map) { m.PutStr("gen_ai.system", "true") })
	carries(boolTrue, `"key":"gen_ai.system","value":"true"`)
	carries(strTrue, `"key":"gen_ai.system","value":"true"`)
	if string(boolTrue) != string(strTrue) {
		t.Error(`bool true and string "true" no longer collide`)
	}

	rawBytes := mk(func(m pcommon.Map) { m.PutEmptyBytes("gen_ai.system").FromRaw([]byte{0xde, 0xad, 0xbe, 0xef}) })
	b64Text := mk(func(m pcommon.Map) { m.PutStr("gen_ai.system", "3q2+7w==") })
	carries(rawBytes, `"key":"gen_ai.system","value":"3q2+7w=="`)
	carries(b64Text, `"key":"gen_ai.system","value":"3q2+7w=="`)
	if string(rawBytes) != string(b64Text) {
		t.Error("bytes and their base64 text no longer collide")
	}

	// The profile keeps every one of those apart.
	x := spanWith(t, "name", `"x"`)
	seen := map[string]string{}
	for label, a := range map[string]string{
		"int":     `{"k":{"i":"1"}}`,
		"string":  `{"k":{"s":"1"}}`,
		"double":  `{"k":{"d":1}}`,
		"bool":    `{"k":{"b":true}}`,
		"strtrue": `{"k":{"s":"true"}}`,
		"bytes":   `{"k":{"y":"3q2+7w=="}}`,
		"strb64":  `{"k":{"s":"3q2+7w=="}}`,
	} {
		h := mustHash(t, x, a).SpanSHA256
		if prev, dup := seen[h]; dup {
			t.Errorf("profile hashes %s and %s alike", prev, label)
		}
		seen[h] = label
	}
}

// FINDING: the OTLP wire carries attributes as a repeated key/value list, so a
// span can arrive with the same key twice. pdata keeps both; SpanToRecord asks
// for the key by name, gets the first, and the second is silently absent from
// the hash. The profile makes this a reject so that two stores that merge
// differently cannot both accept the span and hash it differently.
func TestFinding_DuplicateAttributeKeyIsFirstWins(t *testing.T) {
	// BUG(#59): a duplicate attribute key is silently first-wins. Flip this when
	// the span is refused, quarantined or the conflict recorded.
	otlp := `{"resourceSpans":[{"scopeSpans":[{"spans":[{` +
		`"traceId":"0af7651916cd43dd8448eb211c80319c","spanId":"b7ad6b7169203331","name":"x",` +
		`"attributes":[` +
		`{"key":"gen_ai.system","value":{"stringValue":"first"}},` +
		`{"key":"gen_ai.system","value":{"stringValue":"second"}}]}]}]}]}`
	td, err := (&ptrace.JSONUnmarshaler{}).UnmarshalTraces([]byte(otlp))
	if err != nil {
		t.Fatal(err)
	}
	s := td.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	if s.Attributes().Len() != 2 {
		t.Fatalf("pdata kept %d attributes, want 2: the test no longer reaches a duplicate", s.Attributes().Len())
	}
	rec := string(ours(t, s))
	if !strings.Contains(rec, `"value":"first"`) || strings.Contains(rec, "second") {
		t.Errorf("record = %s; want first value kept and second absent", rec)
	}

	wantReject(t, spanWith(t, "name", `"x"`),
		`[["gen_ai.system",{"s":"first"}],["gen_ai.system",{"s":"second"}]]`, "DUPLICATE_ATTRIBUTE_KEY")
}

// FINDING: SpanKind and StatusCode are written through their String methods,
// and a number outside the OTLP enum has no name. Distinct unknown numbers
// therefore collapse to the same empty string instead of being refused.
func TestFinding_OutOfRangeEnumsCollapseToEmpty(t *testing.T) {
	// BUG(#60): out-of-range kind and status serialize as "". Flip this when they
	// are refused or quarantined.
	mk := func(kind, status int) map[string]any {
		s := ptrace.NewSpan()
		s.SetKind(ptrace.SpanKind(kind))
		s.Status().SetCode(ptrace.StatusCode(status))
		return decodeMap(t, ours(t, s))
	}
	for _, n := range []int{6, 7, 9, 100} {
		got := mk(n, n)
		if got["otel_kind"] != "" || got["status"] != "" {
			t.Errorf("kind/status %d: otel_kind=%q status=%q, want both empty", n, got["otel_kind"], got["status"])
		}
	}
	wantReject(t, spanWith(t, "kind", `6`), `{}`, "KIND_OUT_OF_RANGE")
	wantReject(t, spanWith(t, "status_code", `3`), `{}`, "STATUS_OUT_OF_RANGE")
}

// What the read path (canonical.Unmarshal and chain.GenesisSeed) does with the
// profile's reject cases. The profile refuses all of these at its boundary. This
// repo builds records from typed pdata, so a malformed id or a number-typed
// timestamp cannot arise on the write path; the question here is only what a
// verifier does when a log line carries one.
func TestCompare_ReadPathVersusProfileRejects(t *testing.T) {
	line := func(mut map[string]any) []byte {
		base := map[string]any{
			"schema_version": "v3", "trace_id": "0af7651916cd43dd8448eb211c80319c",
			"span_id": "b7ad6b7169203331", "parent_span_id": "", "seq_in_trace": 0,
			"start_time_unix_nano": "1", "end_time_unix_nano": "2", "span_name": "x",
			"otel_kind": "Internal", "gen_ai_operation": "", "audit_kind": "task",
			"selected_attributes": nil, "status": "Unset",
		}
		for k, v := range mut {
			base[k] = v
		}
		b, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	number := func(s string) json.RawMessage { return json.RawMessage(s) }

	tests := []struct {
		name       string
		profile    string // the profile's reject code for the same defect
		mut        map[string]any
		wantReject bool // does canonical.Unmarshal refuse it?
	}{
		{"timestamp as a JSON number", "TIMESTAMP_NOT_STRING", map[string]any{"start_time_unix_nano": number("1754300000000000000")}, false},
		{"timestamp with a leading zero", "TIMESTAMP_NOT_DECIMAL", map[string]any{"start_time_unix_nano": "007"}, true},
		{"timestamp past uint64", "(accepted by the profile)", map[string]any{"end_time_unix_nano": "99999999999999999999999"}, true},
		{"uppercase trace id", "ID_NOT_LOWERCASE_HEX", map[string]any{"trace_id": "0AF7651916CD43DD8448EB211C80319C"}, false},
		{"short span id", "ID_BAD_LENGTH", map[string]any{"span_id": "b7ad"}, false},
		{"unknown kind name", "KIND_OUT_OF_RANGE", map[string]any{"otel_kind": "Bogus"}, false},
		{"unknown status name", "STATUS_OUT_OF_RANGE", map[string]any{"status": "Bogus"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := canonical.Unmarshal(line(tc.mut))
			if (err != nil) != tc.wantReject {
				t.Errorf("profile code %s: Unmarshal err = %v, want rejected = %v", tc.profile, err, tc.wantReject)
			}
		})
	}

	// The accepted number-typed timestamp is normalised on re-serialisation, so
	// the profile's "reject rather than coerce" is a coercion here. It has to
	// stay accepted for schema v1/v2 logs, whose timestamps are JSON numbers.
	r, err := canonical.Unmarshal(line(map[string]any{"start_time_unix_nano": number("1754300000000000000")}))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := canonical.Marshal(r)
	if !strings.Contains(string(out), `"start_time_unix_nano":"1754300000000000000"`) {
		t.Errorf("number timestamp not normalised to a string: %s", out)
	}
}

// FINDING: GenesisSeed's doc comment says it errors unless the trace id is
// "valid lowercase hex (32 hex chars = 16 bytes)". It decodes with
// hex.DecodeString, which accepts uppercase and any even length. An uppercase
// id therefore seeds the same chain as its lowercase spelling while the record
// bytes differ, and a 4-byte id seeds without error.
func TestFinding_GenesisSeedDoesNotEnforceItsDocumentedIDRule(t *testing.T) {
	// BUG(#61): the documented trace-id rule is not enforced. Flip this when the
	// rule is enforced or the comment is corrected.
	lower, err := chain.GenesisSeed("0af7651916cd43dd8448eb211c80319c")
	if err != nil {
		t.Fatal(err)
	}
	upper, err := chain.GenesisSeed("0AF7651916CD43DD8448EB211C80319C")
	if err != nil {
		t.Fatalf("uppercase id now errors (%v): the comment is true; update the doc", err)
	}
	if string(lower) != string(upper) {
		t.Error("uppercase and lowercase ids now seed differently")
	}
	if _, err := chain.GenesisSeed("0af76519"); err != nil {
		t.Errorf("short id now errors (%v): the comment is true; update the doc", err)
	}
	if _, err := chain.GenesisSeed("zz"); err == nil {
		t.Error("non-hex id should still error")
	}
}

// The profile rejects an empty batch ("nothing to commit"). The nearest thing
// here is a checkpoint over zero trace tips. Accumulator.Stage, the call the
// exporter persists through, does not refuse one (chain's own
// TestAccumulator_BuildEmpty relies on the same for Build, a test-only API).
// The exporter never asks for one: Shutdown checkpoints only when tips are
// pending, and the interval trigger needs pending >= checkpointInterval
// (exporter.go, Shutdown and shouldCheckpoint). So this is a property of the
// accumulator, not of what the exporter writes, and the analogy is loose: a
// checkpoint is a delta over sealed traces, not a batch from one export request.
func TestCompare_AccumulatorDoesNotRefuseZeroTips(t *testing.T) {
	priv, _, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	acc := chain.NewAccumulator(sign.NewEd25519Signer(priv), 0, chain.ZeroPrevCheckpointHash)
	if acc.PendingCount() != 0 {
		t.Fatal("a new accumulator should have no pending tips")
	}
	staged, err := acc.Stage(time.Unix(0, 0))
	if err != nil {
		t.Fatalf("a zero-tip checkpoint is now refused (%v): update the doc", err)
	}
	if len(staged.Checkpoint.TraceTips) != 0 || staged.Checkpoint.CheckpointSeq != 1 {
		t.Errorf("unexpected zero-tip checkpoint: %+v", staged.Checkpoint)
	}
}

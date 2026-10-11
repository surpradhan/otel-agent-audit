package profilecompare

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"
)

// These tests cover profile behaviour the vendored vectors do not reach. They
// are this repo's own tests of its own implementation, not the profile's
// vectors, and each says which of the three it is checking: a rule SPEC.md
// states, a choice the reference canonical.py makes where SPEC.md is silent, or
// a behaviour recorded because it is surprising.

const baseSpan = `{"trace_id":"0af7651916cd43dd8448eb211c80319c","span_id":"b7ad6b7169203331",` +
	`"parent_span_id":"","name":"x","kind":0,"status_code":0,` +
	`"start_time_unix_nano":"1754300000000000000","end_time_unix_nano":"1754300000123456789"}`

// spanWith replaces or adds one top-level member of baseSpan.
func spanWith(t *testing.T, key, rawValue string) obj {
	t.Helper()
	v, err := decodeOrdered([]byte(baseSpan))
	if err != nil {
		t.Fatal(err)
	}
	o := v.(obj)
	nv, err := decodeOrdered([]byte(rawValue))
	if err != nil {
		t.Fatalf("bad test value %q: %v", rawValue, err)
	}
	out := obj{}
	replaced := false
	for _, m := range o {
		if m.key == key {
			out = append(out, kvp{key, nv})
			replaced = true
			continue
		}
		out = append(out, m)
	}
	if !replaced {
		out = append(out, kvp{key, nv})
	}
	return out
}

func attrsOf(t *testing.T, raw string) any {
	t.Helper()
	v, err := decodeOrdered([]byte(raw))
	if err != nil {
		t.Fatalf("bad attrs %q: %v", raw, err)
	}
	return v
}

func mustHash(t *testing.T, span obj, attrs string) profileSpan {
	t.Helper()
	res, err := canonicalSpan(span, attrsOf(t, attrs))
	if err != nil {
		t.Fatalf("canonicalSpan: %v", err)
	}
	return res
}

func wantReject(t *testing.T, span obj, attrs, code string) {
	t.Helper()
	_, err := canonicalSpan(span, attrsOf(t, attrs))
	if got := rejectCode(err); got != code {
		t.Errorf("got reject %q (err=%v), want %q", got, err, code)
	}
}

// SPEC.md section 6 lists "leading-zero/sign-malformed decimal string" under
// INT_OUT_OF_RANGE, but no vendored reject vector exercises it: removing the
// check leaves every vector green.
func TestProfileEdge_MalformedIntStringIsIntOutOfRange(t *testing.T) {
	for _, s := range []string{"007", "-007", "+5", "", "-", "1.5", "1e3", " 1", "1 ", "abc", "0x10"} {
		t.Run("["+s+"]", func(t *testing.T) {
			wantReject(t, spanWith(t, "name", `"x"`), `{"a":{"i":"`+s+`"}}`, "INT_OUT_OF_RANGE")
		})
	}
}

// The int64 boundaries are in a pass vector; one past each is a reject.
func TestProfileEdge_Int64Boundaries(t *testing.T) {
	ok := func(s string) { mustHash(t, spanWith(t, "name", `"x"`), `{"a":{"i":"`+s+`"}}`) }
	ok("9223372036854775807")
	ok("-9223372036854775808")
	wantReject(t, spanWith(t, "name", `"x"`), `{"a":{"i":"9223372036854775808"}}`, "INT_OUT_OF_RANGE")
	wantReject(t, spanWith(t, "name", `"x"`), `{"a":{"i":"-9223372036854775809"}}`, "INT_OUT_OF_RANGE")
}

// SPEC.md allows "optional leading -, no leading zeros", and "-0" has no
// leading zero. Both "0" and "-0" therefore pass, name the same int64, and
// hash differently: two canonical encodings of one value. Recorded, not fixed.
func TestProfileEdge_NegativeZeroIsASecondEncodingOfZero(t *testing.T) {
	zero := mustHash(t, spanWith(t, "name", `"x"`), `{"a":{"i":"0"}}`)
	negZero := mustHash(t, spanWith(t, "name", `"x"`), `{"a":{"i":"-0"}}`)
	if zero.AttrSHA256 == negZero.AttrSHA256 {
		t.Fatal(`"0" and "-0" now hash alike: the profile closed this gap; update the comparison doc`)
	}
}

// SPEC.md says bytes are "RFC 4648 standard alphabet, with padding". The
// reference only checks that the value is a string. This implementation checks
// the spec, so a value the reference would hash is a reject here.
func TestProfileEdge_Base64IsValidated(t *testing.T) {
	mustHash(t, spanWith(t, "name", `"x"`), `{"a":{"y":"3q2+7w=="}}`)
	mustHash(t, spanWith(t, "name", `"x"`), `{"a":{"y":""}}`)
	for _, bad := range []string{"3q2+7w", "3q2-7w==", "not base64!", "3q2+7w=", "3q2+\\n7w=="} {
		wantReject(t, spanWith(t, "name", `"x"`), `{"a":{"y":"`+bad+`"}}`, "BAD_WRAPPER")
	}
}

// A double wrapper holds a JSON number, and RFC 8785 serializes a number as an
// IEEE-754 double. An integer literal past 2^53 is therefore rounded before it
// is hashed: 9007199254740993 canonicalizes as 9007199254740992.
func TestProfileEdge_DoubleLiteralPast2p53IsRounded(t *testing.T) {
	res := mustHash(t, spanWith(t, "name", `"x"`), `{"a":{"d":9007199254740993}}`)
	if !strings.Contains(string(res.AttrBytes), `9007199254740992`) || strings.Contains(string(res.AttrBytes), `9007199254740993`) {
		t.Errorf("attr bytes: %s", res.AttrBytes)
	}
}

// SPEC.md says NaN and +/-Infinity are rejects and notes they cannot appear in
// JSON. A literal that overflows a double (1e999) can, and is mirrored from the
// reference as NONFINITE_DOUBLE, which also gives that code a JSON vector.
func TestProfileEdge_OverflowingDoubleLiteralIsNonfinite(t *testing.T) {
	wantReject(t, spanWith(t, "name", `"x"`), `{"a":{"d":1e999}}`, "NONFINITE_DOUBLE")
	wantReject(t, spanWith(t, "name", `"x"`), `{"a":{"d":-1e999}}`, "NONFINITE_DOUBLE")
}

// A wrong-typed attribute value is BAD_WRAPPER. A wrong-typed span field gets the
// named code of its own rule (kind, status_code, ids, timestamps), as canonical.py
// does, although SPEC.md section 6 describes BAD_WRAPPER as the catch-all for a
// span field that is structurally malformed. That ambiguity is recorded in the
// comparison doc.
func TestProfileEdge_WrongTypes(t *testing.T) {
	x := spanWith(t, "name", `"x"`)
	wantReject(t, x, `{"a":{"d":true}}`, "BAD_WRAPPER")
	wantReject(t, x, `{"a":{"d":"1"}}`, "BAD_WRAPPER")
	wantReject(t, x, `{"a":{"b":"true"}}`, "BAD_WRAPPER")
	wantReject(t, x, `{"a":{"s":1}}`, "BAD_WRAPPER")
	wantReject(t, x, `{"a":{"q":"1"}}`, "BAD_WRAPPER")
	wantReject(t, x, `{"a":{}}`, "BAD_WRAPPER")
	wantReject(t, x, `{"a":{"s":"1","b":true}}`, "BAD_WRAPPER")
	wantReject(t, x, `{"a":"plain"}`, "BAD_WRAPPER")
	wantReject(t, spanWith(t, "name", `7`), `{}`, "BAD_WRAPPER")
	// kind and status_code: a JSON bool or a float is "not an integer in range".
	wantReject(t, spanWith(t, "kind", `true`), `{}`, "KIND_OUT_OF_RANGE")
	wantReject(t, spanWith(t, "kind", `2.0`), `{}`, "KIND_OUT_OF_RANGE")
	wantReject(t, spanWith(t, "kind", `"2"`), `{}`, "KIND_OUT_OF_RANGE")
	wantReject(t, spanWith(t, "kind", `-1`), `{}`, "KIND_OUT_OF_RANGE")
	wantReject(t, spanWith(t, "kind", `6`), `{}`, "KIND_OUT_OF_RANGE")
	wantReject(t, spanWith(t, "status_code", `3`), `{}`, "STATUS_OUT_OF_RANGE")
}

// Duplicate keys are rejected at every nesting level, not just the top.
func TestProfileEdge_DuplicateKeysAtEveryLevel(t *testing.T) {
	x := spanWith(t, "name", `"x"`)
	wantReject(t, x, `[["k",{"s":"a"}],["k",{"s":"b"}]]`, "DUPLICATE_ATTRIBUTE_KEY")
	wantReject(t, x, `{"outer":{"kv":{"k":{"s":"a"},"k":{"s":"b"}}}}`, "DUPLICATE_ATTRIBUTE_KEY")
	wantReject(t, x, `[["outer",{"kv":[["k",{"s":"a"}],["k",{"s":"b"}]]}]]`, "DUPLICATE_ATTRIBUTE_KEY")
	// The same key at different levels is not a duplicate.
	mustHash(t, x, `{"k":{"kv":{"k":{"s":"a"}}}}`)
}

// Fields outside the allowlist, including a status message, do not reach the
// hash (SPEC.md section 2).
func TestProfileEdge_NonAllowlistedFieldsAreIgnored(t *testing.T) {
	base := mustHash(t, spanWith(t, "name", `"x"`), `{}`)
	for _, extra := range []struct{ k, v string }{
		{"status_message", `"upstream timed out"`},
		{"resource", `{"service.name":"a"}`},
		{"events", `[1,2,3]`},
		{"flags", `1`},
	} {
		got := mustHash(t, spanWith(t, extra.k, extra.v), `{}`)
		if got.SpanSHA256 != base.SpanSHA256 {
			t.Errorf("field %q changed the span hash", extra.k)
		}
	}
}

// SPEC.md says timestamps are "decimal digits only, no sign, no leading zeros"
// and says nothing about an upper bound, though OTLP defines them as uint64.
// A value past 2^64-1 passes. Recorded because the repo's own UnixNano type
// cannot represent it (see the comparison tests).
func TestProfileEdge_TimestampPastUint64IsAccepted(t *testing.T) {
	mustHash(t, spanWith(t, "end_time_unix_nano", `"99999999999999999999999"`), `{}`)
	wantReject(t, spanWith(t, "end_time_unix_nano", `"-1"`), `{}`, "TIMESTAMP_NOT_DECIMAL")
	wantReject(t, spanWith(t, "end_time_unix_nano", `"1.5"`), `{}`, "TIMESTAMP_NOT_DECIMAL")
	wantReject(t, spanWith(t, "end_time_unix_nano", `""`), `{}`, "TIMESTAMP_NOT_DECIMAL")
	wantReject(t, spanWith(t, "end_time_unix_nano", `null`), `{}`, "TIMESTAMP_NOT_DECIMAL")
	mustHash(t, spanWith(t, "end_time_unix_nano", `"0"`), `{}`)
}

// spanWithMany is spanWith for several members at once; pairs is key, value, key,
// value, and so on, each value raw JSON.
func spanWithMany(t *testing.T, pairs ...string) obj {
	t.Helper()
	if len(pairs)%2 != 0 {
		t.Fatal("spanWithMany needs key/value pairs")
	}
	o := spanWith(t, "name", `"x"`)
	for i := 0; i < len(pairs); i += 2 {
		nv, err := decodeOrdered([]byte(pairs[i+1]))
		if err != nil {
			t.Fatalf("bad test value %q: %v", pairs[i+1], err)
		}
		replaced := false
		for j := range o {
			if o[j].key == pairs[i] {
				o[j].val = nv
				replaced = true
			}
		}
		if !replaced {
			o = append(o, kvp{pairs[i], nv})
		}
	}
	return o
}

// With several defects the code reported depends on check order, which SPEC.md
// does not define, and the two references disagree on (canonical.py checks the
// ids before the name, validate.mjs the name before the ids). This pins every
// adjacent pair in canonical.py's order, the one used here, so a change is
// deliberate: in each row the earlier check must win over the later one, and the
// two defects carry different codes so a swap is visible.
func TestProfileEdge_RejectPrecedence(t *testing.T) {
	rows := []struct {
		name  string
		span  obj
		attrs string
		want  string
	}{
		{"attributes before kind", spanWithMany(t, "kind", `9`), `{"k":{"i":"007"}}`, "INT_OUT_OF_RANGE"},
		{"kind before status", spanWithMany(t, "kind", `9`, "status_code", `9`), `{}`, "KIND_OUT_OF_RANGE"},
		{"status before trace_id", spanWithMany(t, "status_code", `9`, "trace_id", `"zz"`), `{}`, "STATUS_OUT_OF_RANGE"},
		{"trace_id before span_id", spanWithMany(t, "trace_id", `"zz"`, "span_id", `"B7AD6B7169203331"`), `{}`, "ID_BAD_LENGTH"},
		{"span_id before parent_span_id", spanWithMany(t, "span_id", `"zz"`, "parent_span_id", `"B7AD6B7169203331"`), `{}`, "ID_BAD_LENGTH"},
		// The row that separates canonical.py from validate.mjs, which would
		// report BAD_WRAPPER for the name here.
		{"parent_span_id before name", spanWithMany(t, "parent_span_id", `"zz"`, "name", `7`), `{}`, "ID_BAD_LENGTH"},
		{"name before start", spanWithMany(t, "name", `7`, "start_time_unix_nano", `5`), `{}`, "BAD_WRAPPER"},
		{"start before end", spanWithMany(t, "start_time_unix_nano", `"007"`, "end_time_unix_nano", `5`), `{}`, "TIMESTAMP_NOT_DECIMAL"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			wantReject(t, r.span, r.attrs, r.want)
		})
	}
}

// A JSON bool is not a string timestamp. canonical.py reports it as
// TIMESTAMP_NOT_STRING (a Python bool is an int); validate.mjs reports
// TIMESTAMP_NOT_DECIMAL (read, not run). This follows canonical.py. A non-string
// int attribute value is INT_OUT_OF_RANGE for the same reason, where SPEC.md
// section 6 would read as BAD_WRAPPER.
func TestProfileEdge_WrongTypedTimestampAndIntFollowCanonicalPy(t *testing.T) {
	wantReject(t, spanWith(t, "start_time_unix_nano", `true`), `{}`, "TIMESTAMP_NOT_STRING")
	wantReject(t, spanWith(t, "end_time_unix_nano", `false`), `{}`, "TIMESTAMP_NOT_STRING")
	wantReject(t, spanWith(t, "end_time_unix_nano", `12.5`), `{}`, "TIMESTAMP_NOT_STRING")
	wantReject(t, spanWith(t, "name", `"x"`), `{"k":{"i":5}}`, "INT_OUT_OF_RANGE")
	wantReject(t, spanWith(t, "name", `"x"`), `{"k":{"i":true}}`, "INT_OUT_OF_RANGE")
}

// Non-zero trailing bits ("QR==" decodes to the same byte as "QQ==") are a
// second spelling of the same bytes. SPEC.md does not forbid them and RFC 4648
// section 3.5 only permits a decoder to; this implementation does reject them,
// because the canonical form hashes the string, not the bytes. Two conforming
// implementations could differ here.
func TestProfileEdge_Base64TrailingBitsAreRejected(t *testing.T) {
	mustHash(t, spanWith(t, "name", `"x"`), `{"a":{"y":"QQ=="}}`)
	wantReject(t, spanWith(t, "name", `"x"`), `{"a":{"y":"QR=="}}`, "BAD_WRAPPER")
}

// A base64 value with an embedded line break is refused: encoding/base64 would
// skip it, RFC 4648 section 3.3 says to reject it.
func TestProfileEdge_Base64LineBreakIsRejected(t *testing.T) {
	wantReject(t, spanWith(t, "name", `"x"`), `{"a":{"y":"3q2+\n7w=="}}`, "BAD_WRAPPER")
	wantReject(t, spanWith(t, "name", `"x"`), `{"a":{"y":"3q2+\r7w=="}}`, "BAD_WRAPPER")
}

// The list form of an attribute collection must be well-formed pairs.
func TestProfileEdge_PairListShape(t *testing.T) {
	x := spanWith(t, "name", `"x"`)
	wantReject(t, x, `[["k"]]`, "BAD_WRAPPER")
	wantReject(t, x, `[["k",{"s":"a"},"extra"]]`, "BAD_WRAPPER")
	wantReject(t, x, `[[1,{"s":"a"}]]`, "BAD_WRAPPER")
	wantReject(t, x, `["k"]`, "BAD_WRAPPER")
	wantReject(t, x, `"k"`, "BAD_WRAPPER")
}

// SPEC.md rejects duplicate *attribute* keys and says nothing about a duplicate
// member in the span core. The reference loads JSON last-wins, which this
// mirrors: {"kind":0,...,"kind":9} is a reject, {"kind":9,...,"kind":0} is not.
// A first-wins parser would disagree on both.
func TestProfileEdge_DuplicateSpanCoreMemberIsLastWins(t *testing.T) {
	lastBad := append(spanWith(t, "kind", `0`), kvp{"kind", json9()})
	wantReject(t, lastBad, `{}`, "KIND_OUT_OF_RANGE")
	firstBad := append(obj{{"kind", json9()}}, spanWith(t, "kind", `0`)...)
	mustHash(t, firstBad, `{}`)
}

// json9 is the JSON number 9, as decodeOrdered would produce it.
func json9() any { return json.Number("9") }

// An empty id, or one of the wrong length in any of the three id fields, is
// ID_BAD_LENGTH; only parent_span_id may be empty.
func TestProfileEdge_EmptyAndShortIDs(t *testing.T) {
	for _, tc := range []struct{ key, val string }{
		{"trace_id", `""`},
		{"trace_id", `"0af7"`},
		{"span_id", `""`},
		{"span_id", `"b7ad"`},
		{"parent_span_id", `"b7ad"`},
		{"parent_span_id", `"b7ad6b71692033311"`},
	} {
		t.Run(tc.key+"="+tc.val, func(t *testing.T) {
			wantReject(t, spanWith(t, tc.key, tc.val), `{}`, "ID_BAD_LENGTH")
		})
	}
	wantReject(t, spanWith(t, "parent_span_id", `"B7AD6B7169203331"`), `{}`, "ID_NOT_LOWERCASE_HEX")
}

// A missing parent_span_id and an empty one both mean "no parent" and hash alike.
// An explicit null, or any non-string, is not the empty string. canonical.py
// rejects it as ID_BAD_LENGTH; validate.mjs would accept null (read, not run).
func TestProfileEdge_ParentSpanIDMissingNullAndEmpty(t *testing.T) {
	v, err := decodeOrdered([]byte(baseSpan))
	if err != nil {
		t.Fatal(err)
	}
	var missing obj
	for _, m := range v.(obj) {
		if m.key != "parent_span_id" {
			missing = append(missing, m)
		}
	}
	empty := mustHash(t, spanWith(t, "parent_span_id", `""`), `{}`)
	if got := mustHash(t, missing, `{}`); got.SpanSHA256 != empty.SpanSHA256 {
		t.Errorf("missing parent hashes %s, empty parent %s", got.SpanSHA256, empty.SpanSHA256)
	}
	wantReject(t, spanWith(t, "parent_span_id", `null`), `{}`, "ID_BAD_LENGTH")
	wantReject(t, spanWith(t, "parent_span_id", `7`), `{}`, "ID_BAD_LENGTH")
}

// A malformed element inside an array wrapper is rejected, not skipped.
func TestProfileEdge_MalformedArrayElementIsRejected(t *testing.T) {
	x := spanWith(t, "name", `"x"`)
	wantReject(t, x, `{"k":{"a":[{"s":"ok"},{"i":"007"}]}}`, "INT_OUT_OF_RANGE")
	wantReject(t, x, `{"k":{"a":[{"q":1}]}}`, "BAD_WRAPPER")
	wantReject(t, x, `{"k":{"a":[{"s":"ok"},"plain"]}}`, "BAD_WRAPPER")
	mustHash(t, x, `{"k":{"a":[{"s":"ok"},{"i":"7"}]}}`)
}

// A wrapper object that repeats its tag is BAD_WRAPPER here. Both references load
// JSON last-wins and would accept {"s":"a","s":"b"} as {"s":"b"}; this is a
// deliberate departure, because two spellings of one wrapper is exactly what a
// canonical form is meant to remove.
func TestProfileEdge_WrapperWithRepeatedTagIsRejected(t *testing.T) {
	wantReject(t, spanWith(t, "name", `"x"`), `{"k":{"s":"a","s":"b"}}`, "BAD_WRAPPER")
}

// Python's re `$` also matches before a trailing newline, so under canonical.py's
// regexes "123\n" would pass as a timestamp and 31 hex digits plus "\n" as a
// 32-character id (read, and confirmed with the same patterns in Python). SPEC.md
// says "digits only" and "lowercase hex", and Go's `$` is end-of-text only.
func TestProfileEdge_TrailingNewlineIsNotADigitOrHexCharacter(t *testing.T) {
	wantReject(t, spanWith(t, "trace_id", `"0af7651916cd43dd8448eb211c80319\n"`), `{}`, "ID_NOT_LOWERCASE_HEX")
	wantReject(t, spanWith(t, "span_id", `"b7ad6b716920333\n"`), `{}`, "ID_NOT_LOWERCASE_HEX")
	wantReject(t, spanWith(t, "end_time_unix_nano", `"123\n"`), `{}`, "TIMESTAMP_NOT_DECIMAL")
	wantReject(t, spanWith(t, "name", `"x"`), `{"k":{"i":"5\n"}}`, "INT_OUT_OF_RANGE")
}

// The hash is over the string the span carries, and encoding/json replaces
// invalid UTF-8 and a lone surrogate with U+FFFD while decoding, so a name that
// is not valid Unicode arrives already replaced. SPEC.md section 2 says "as
// given". Recorded as a limitation of this implementation, not fixed.
func TestProfileEdge_InvalidUnicodeNameIsReplacedBeforeHashing(t *testing.T) {
	replaced := mustHash(t, spanWith(t, "name", `"\ufffd"`), `{}`)
	lone := mustHash(t, spanWith(t, "name", `"\ud800"`), `{}`)
	if lone.SpanSHA256 != replaced.SpanSHA256 {
		t.Error("a lone surrogate no longer hashes as U+FFFD: the limitation is gone, update the doc")
	}
	// Raw invalid UTF-8 (a stray 0xff byte) is replaced too. The byte is written as
	// an escape in this Go string so the source file itself stays valid UTF-8.
	rawBad := mustHash(t, spanWith(t, "name", "\"a\xffb\""), `{}`)
	wantRepl := mustHash(t, spanWith(t, "name", `"a\ufffdb"`), `{}`)
	if rawBad.SpanSHA256 != wantRepl.SpanSHA256 {
		t.Error("invalid UTF-8 no longer hashes as U+FFFD: the limitation is gone, update the doc")
	}
}

// QQ== and QR== are two spellings of one byte (the second has non-zero trailing
// bits). A non-strict decoder accepts both and yields the same bytes, while the
// canonical form hashes the string, so a validator that did not refuse QR== would
// give one byte value two hashes. canonical.py does not validate base64, so it
// would hash both (read, not run).
func TestProfileEdge_NonCanonicalBase64SpellingsDecodeAlikeButHashDifferently(t *testing.T) {
	a, errA := base64.StdEncoding.DecodeString("QQ==")
	b, errB := base64.StdEncoding.DecodeString("QR==")
	if errA != nil || errB != nil || string(a) != string(b) {
		t.Fatalf("a non-strict decoder should read both as the same byte: %q (%v), %q (%v)", a, errA, b, errB)
	}
	ja, err := jcs.Transform([]byte(`{"k":{"y":"QQ=="}}`))
	if err != nil {
		t.Fatal(err)
	}
	jb, err := jcs.Transform([]byte(`{"k":{"y":"QR=="}}`))
	if err != nil {
		t.Fatal(err)
	}
	if sha256Hex(ja) == sha256Hex(jb) {
		t.Error("the two spellings should hash differently")
	}
}

// RFC 8785 is what makes attribute order and number spelling irrelevant. Every
// vendored attrs file is already key-sorted and number-canonical, so building
// from the shipped bytes cannot show the normalisation working. Here the same
// attributes arrive in reverse order, and the doubles arrive in non-canonical
// spellings, and the published hashes must still come out.
func TestProfileEdge_AttributeInputIsNormalisedByJCS(t *testing.T) {
	exp := loadExpected(t)

	reversed := 0
	for _, name := range sortedKeys(exp.Pass) {
		attrs, err := decodeOrdered(readVector(t, "pass/"+name+".attrs.json"))
		if err != nil {
			t.Fatal(err)
		}
		if len(attrs.(obj)) < 2 {
			continue // reversing zero or one attribute changes nothing
		}
		reversed++
		t.Run("reversed/"+name, func(t *testing.T) {
			span, err := decodeOrdered(readVector(t, "pass/"+name+".canonical.json"))
			if err != nil {
				t.Fatal(err)
			}
			in := attrs.(obj)
			rev := make(obj, len(in))
			for i, m := range in {
				rev[len(in)-1-i] = m
			}
			got, err := canonicalSpan(span.(obj), rev)
			if err != nil {
				t.Fatal(err)
			}
			if got.AttrSHA256 != exp.Pass[name].AttributesSHA256 || got.SpanSHA256 != exp.Pass[name].SpanSHA256 {
				t.Errorf("reversed attribute order changed the hash: attrs %s span %s", got.AttrSHA256, got.SpanSHA256)
			}
		})
	}

	if reversed != 5 {
		t.Fatalf("reversed %d vectors, want the 5 with two or more attributes: the vendored set changed", reversed)
	}

	// double-forms ships as 100, 0, 1e+21, 10000000000000000, 5e-7, 0.000001.
	x := spanWith(t, "name", `"x"`)
	spelled := `{"a.integral":{"d":100.0},"b.negzero":{"d":-0.0},"c.big":{"d":1E21},` +
		`"d.sixteen":{"d":1e16},"e.small":{"d":5E-7},"f.edge":{"d":1E-6}}`
	if got := mustHash(t, x, spelled).AttrSHA256; got != exp.Pass["double-forms"].AttributesSHA256 {
		t.Errorf("non-canonical double spellings changed the attribute hash: got %s, want %s",
			got, exp.Pass["double-forms"].AttributesSHA256)
	}
}

// A lowercase letter outside a-f is not hex, and an id one character too long is
// not the right length, whichever field it is in.
func TestProfileEdge_NonHexAndOverlongIDs(t *testing.T) {
	wantReject(t, spanWith(t, "span_id", `"b7ad6b716920333g"`), `{}`, "ID_NOT_LOWERCASE_HEX")
	wantReject(t, spanWith(t, "trace_id", `"0af7651916cd43dd8448eb211c80319z"`), `{}`, "ID_NOT_LOWERCASE_HEX")
	wantReject(t, spanWith(t, "parent_span_id", `"b7ad6b716920333g"`), `{}`, "ID_NOT_LOWERCASE_HEX")
	wantReject(t, spanWith(t, "span_id", `"b7ad6b71692033310"`), `{}`, "ID_BAD_LENGTH")
	wantReject(t, spanWith(t, "trace_id", `"0af7651916cd43dd8448eb211c80319c0"`), `{}`, "ID_BAD_LENGTH")
}

// Numbers are normalised by RFC 8785, so different spellings of one double give one
// hash, and a different double gives a different one.
func TestProfileEdge_EquivalentDoubleSpellingsHashAlike(t *testing.T) {
	x := spanWith(t, "name", `"x"`)
	one := mustHash(t, x, `{"k":{"d":1}}`).AttrSHA256
	for _, spelling := range []string{`1.0`, `1E0`, `1e0`, `10E-1`, `0.1e1`} {
		if got := mustHash(t, x, `{"k":{"d":`+spelling+`}}`).AttrSHA256; got != one {
			t.Errorf("double spelled %s hashes differently from 1", spelling)
		}
	}
	if mustHash(t, x, `{"k":{"d":2}}`).AttrSHA256 == one {
		t.Error("a different double hashed alike")
	}
	// 1.0 as a double and "1" as an int are different typed values.
	if mustHash(t, x, `{"k":{"i":"1"}}`).AttrSHA256 == one {
		t.Error(`int "1" and double 1 hashed alike`)
	}
}

// decodeOrdered refuses anything after the first JSON value.
func TestProfileEdge_DecodeOrderedRejectsTrailingData(t *testing.T) {
	for _, bad := range []string{`{} x`, `{}{}`, `1 2`, `{"a":1`, ``} {
		if _, err := decodeOrdered([]byte(bad)); err == nil {
			t.Errorf("decodeOrdered(%q) accepted malformed input", bad)
		}
	}
	if _, err := decodeOrdered([]byte(` {"a":[1,"b",null,true]} `)); err != nil {
		t.Errorf("surrounding whitespace should be fine: %v", err)
	}
}

// Both references load JSON last-wins, so a repeated parent_span_id member is
// decided by its last occurrence. The parent id has its own lookup in
// canonicalSpan, separate from the shared field helper, so it is pinned here too.
func TestProfileEdge_RepeatedParentSpanIDMemberIsLastWins(t *testing.T) {
	badThenEmpty := append(spanWithMany(t, "parent_span_id", `"zz"`), kvp{"parent_span_id", ""})
	mustHash(t, badThenEmpty, `{}`)
	emptyThenBad := append(spanWithMany(t, "parent_span_id", `""`), kvp{"parent_span_id", "zz"})
	wantReject(t, emptyThenBad, `{}`, "ID_BAD_LENGTH")
}

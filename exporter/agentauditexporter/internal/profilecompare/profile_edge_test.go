package profilecompare

import (
	"encoding/json"
	"strings"
	"testing"
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

// Wrong-typed values are structural defects, not range defects.
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

// With several defects the code reported depends on check order, which SPEC.md
// does not define. This pins the order used here (the reference's) so a change
// is deliberate.
func TestProfileEdge_RejectPrecedence(t *testing.T) {
	bad := spanWith(t, "kind", `9`)
	bad = append(obj{}, bad...)
	bad = append(bad, kvp{"trace_id", "NOT-HEX"})                                      // last wins: second trace_id
	wantReject(t, bad, `[["k",{"s":"a"}],["k",{"s":"b"}]]`, "DUPLICATE_ATTRIBUTE_KEY") // attributes first
	wantReject(t, bad, `{}`, "KIND_OUT_OF_RANGE")                                      // then kind, before ids
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

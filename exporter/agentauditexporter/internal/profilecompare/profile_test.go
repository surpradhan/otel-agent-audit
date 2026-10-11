package profilecompare

// An independent Go implementation of the otel-span/canonical/1 profile
// published at github.com/MarkovianProtocol/otel-canonical-profile (commit
// 4f8c4c5), written from its SPEC.md and checked against its conformance
// vectors. It exists to answer one question: do we reproduce the profile's
// hashes and refuse its reject cases? See docs/otel-canonical-profile-comparison.md.
//
// It is test code on purpose. Nothing here is a second serialization for the
// exporter to use, and nothing in internal/record or internal/canonical is
// touched.
//
// Where SPEC.md is silent this follows canonical.py, the Python reference, and
// marks the choice at the line that makes it. "The reference" below always means
// canonical.py: the Node reference (validate.mjs) differs from it in places
// (check order, a null parent_span_id, a boolean timestamp), see the comparison
// doc. Choices that come from canonical.py, not SPEC.md:
//
//   - the order the checks run in: attributes, kind, status_code, trace_id,
//     span_id, parent_span_id, name, start, end (validate.mjs checks name before
//     the ids);
//   - kind and status_code must be integer literals in range, so a bool, a
//     float or a string is "out of range";
//   - a wrong-typed span field gets the named code of its own rule, and a
//     non-string int attribute value is INT_OUT_OF_RANGE, where SPEC.md
//     section 6 would read as the BAD_WRAPPER catch-all;
//   - a JSON bool in a timestamp is TIMESTAMP_NOT_STRING (a bool is an int in
//     Python); validate.mjs reports TIMESTAMP_NOT_DECIMAL;
//   - a repeated member in the span core is last-wins;
//   - a missing parent_span_id means no parent, an explicit null does not;
//   - a double literal that overflows (1e999) is NONFINITE_DOUBLE;
//   - a kvlist is accepted as an object (SPEC.md) or as a list of pairs (the
//     reject inputs).
//
// Departures from canonical.py, all toward SPEC.md or stricter:
//
//   - base64 content is validated, including line breaks and trailing bits;
//   - a wrapper object with a repeated tag is BAD_WRAPPER where both references
//     would load it last-wins;
//   - Go's $ matches only at end of text, so a trailing newline is not a digit or
//     hex character (Python's $ also matches before it);
//   - a double literal past 2^53 is rounded to a double, as RFC 8785 requires;
//     canonical.py hashes the integer literal's exact digits.
//
// One limit of this implementation: names are hashed after encoding/json has
// decoded them, so invalid UTF-8 or a lone surrogate arrives as U+FFFD, not "as
// given".

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/gowebpki/jcs"
)

// rejectError carries one of the profile's reject codes (SPEC.md section 6).
type rejectError struct{ code string }

func (e rejectError) Error() string { return e.code }

func reject(code string) error { return rejectError{code} }

// rejectCode returns the profile reject code in err, or "" if err is not one.
func rejectCode(err error) string {
	var r rejectError
	if errors.As(err, &r) {
		return r.code
	}
	return ""
}

// kvp and obj model a JSON object with its member order and any duplicate
// keys preserved. encoding/json maps would silently collapse duplicates, which
// is precisely what the profile says must be a reject.
type kvp struct {
	key string
	val any
}

type obj []kvp

// last returns the final member named name, matching what a last-wins
// json.load (the reference's) would see.
func (o obj) last(name string) (any, bool) {
	for i := len(o) - 1; i >= 0; i-- {
		if o[i].key == name {
			return o[i].val, true
		}
	}
	return nil, false
}

// decodeOrdered parses data into strings, json.Number, bool, nil, []any and
// obj, preserving object member order and duplicates.
func decodeOrdered(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := readValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after JSON value")
	}
	return v, nil
}

func readValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	switch d {
	case '{':
		o := obj{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			v, err := readValue(dec)
			if err != nil {
				return nil, err
			}
			o = append(o, kvp{key: kt.(string), val: v})
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return o, nil
	case '[':
		a := []any{}
		for dec.More() {
			v, err := readValue(dec)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return a, nil
	}
	return nil, errors.New("unexpected delimiter")
}

var (
	hexRE    = regexp.MustCompile(`^[0-9a-f]+$`)
	decRE    = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	intRE    = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	int64Min = new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 63))
	int64Max = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 63), big.NewInt(1))
)

// jstr encodes s as a JSON string. jcs.Transform re-serializes it, so this only
// has to be valid JSON.
func jstr(s string) string {
	b, _ := json.Marshal(s) // cannot fail for a string
	return string(b)
}

// attrObject validates pairs (SPEC.md section 3) and returns the attribute
// object as JSON text, ready for jcs.Transform. Each element of pairs is
// either a kvp (an attribute object, as in the canonical attrs.json files) or
// a two-element []any{key, wrapper} (the list form the reject inputs use, so
// that duplicate keys are representable).
func attrObject(pairs []kvp) (string, error) {
	seen := map[string]struct{}{}
	out := []byte{'{'}
	for i, p := range pairs {
		if _, dup := seen[p.key]; dup {
			return "", reject("DUPLICATE_ATTRIBUTE_KEY")
		}
		seen[p.key] = struct{}{}
		w, err := wrapperText(p.val)
		if err != nil {
			return "", err
		}
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, jstr(p.key)...)
		out = append(out, ':')
		out = append(out, w...)
	}
	return string(append(out, '}')), nil
}

// pairsFromAny normalizes the two shapes an attribute collection arrives in.
func pairsFromAny(v any) ([]kvp, error) {
	switch t := v.(type) {
	case obj:
		return t, nil
	case []any:
		out := make([]kvp, 0, len(t))
		for _, item := range t {
			pair, ok := item.([]any)
			if !ok || len(pair) != 2 {
				return nil, reject("BAD_WRAPPER")
			}
			k, ok := pair[0].(string)
			if !ok {
				return nil, reject("BAD_WRAPPER")
			}
			out = append(out, kvp{key: k, val: pair[1]})
		}
		return out, nil
	}
	return nil, reject("BAD_WRAPPER")
}

// wrapperText validates one typed value wrapper and returns it as JSON text.
func wrapperText(v any) (string, error) {
	w, ok := v.(obj)
	if !ok || len(w) != 1 {
		return "", reject("BAD_WRAPPER")
	}
	tag, val := w[0].key, w[0].val
	switch tag {
	case "s":
		s, ok := val.(string)
		if !ok {
			return "", reject("BAD_WRAPPER")
		}
		return `{"s":` + jstr(s) + `}`, nil
	case "b":
		b, ok := val.(bool)
		if !ok {
			return "", reject("BAD_WRAPPER")
		}
		return `{"b":` + strconv.FormatBool(b) + `}`, nil
	case "i":
		s, ok := val.(string)
		if !ok || !intRE.MatchString(s) {
			return "", reject("INT_OUT_OF_RANGE")
		}
		n, _ := new(big.Int).SetString(s, 10)
		if n.Cmp(int64Min) < 0 || n.Cmp(int64Max) > 0 {
			return "", reject("INT_OUT_OF_RANGE")
		}
		return `{"i":` + jstr(s) + `}`, nil
	case "d":
		n, ok := val.(json.Number)
		if !ok {
			return "", reject("BAD_WRAPPER")
		}
		// A literal such as 1e999 is not NaN or Infinity, but it is not a
		// finite double either; the reference's json.load turns it into inf
		// and rejects it as NONFINITE_DOUBLE, so that is mirrored.
		if _, err := strconv.ParseFloat(string(n), 64); err != nil {
			return "", reject("NONFINITE_DOUBLE")
		}
		return `{"d":` + string(n) + `}`, nil
	case "y":
		s, ok := val.(string)
		if !ok {
			return "", reject("BAD_WRAPPER")
		}
		// SPEC.md section 3 says RFC 4648 standard alphabet with padding.
		// The reference only checks that the value is a string; this checks
		// the spec. See the comparison doc.
		// encoding/base64 silently skips \r and \n, which RFC 4648 section 3.3
		// says to reject, so they are refused before decoding.
		if strings.ContainsAny(s, "\r\n") {
			return "", reject("BAD_WRAPPER")
		}
		if _, err := base64.StdEncoding.Strict().DecodeString(s); err != nil {
			return "", reject("BAD_WRAPPER")
		}
		return `{"y":` + jstr(s) + `}`, nil
	case "a":
		arr, ok := val.([]any)
		if !ok {
			return "", reject("BAD_WRAPPER")
		}
		out := []byte(`{"a":[`)
		for i, e := range arr {
			t, err := wrapperText(e)
			if err != nil {
				return "", err
			}
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, t...)
		}
		return string(append(out, "]}"...)), nil
	case "kv":
		// SPEC.md shows kvlist as an object; the reject inputs spell it as a
		// list of [key, wrapper] pairs. Both are accepted here.
		pairs, err := pairsFromAny(val)
		if err != nil {
			return "", err
		}
		body, err := attrObject(pairs)
		if err != nil {
			return "", err
		}
		return `{"kv":` + body + `}`, nil
	}
	return "", reject("BAD_WRAPPER")
}

func checkID(v any, length int, allowEmpty bool) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", reject("ID_BAD_LENGTH")
	}
	if s == "" && allowEmpty {
		return s, nil
	}
	if len(s) != length {
		return "", reject("ID_BAD_LENGTH")
	}
	if !hexRE.MatchString(s) {
		return "", reject("ID_NOT_LOWERCASE_HEX")
	}
	return s, nil
}

func checkTimestamp(v any) (string, error) {
	// A JSON number is NOT_STRING, and so is a bool: canonical.py tests
	// isinstance(v, (int, float)) and a Python bool is an int.
	switch v.(type) {
	case json.Number, bool:
		return "", reject("TIMESTAMP_NOT_STRING")
	}
	s, ok := v.(string)
	if !ok || !decRE.MatchString(s) {
		return "", reject("TIMESTAMP_NOT_DECIMAL")
	}
	return s, nil
}

// checkSmallInt accepts a JSON integer literal in [0, hi].
func checkSmallInt(v any, hi int64, code string) (int64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, reject(code)
	}
	// ParseInt accepts only an integer literal, so 2.0 and 2e0 are refused here as
	// the reference refuses them (a float is not an int), and a bool or string
	// never reaches this far.
	i, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil || i < 0 || i > hi {
		return 0, reject(code)
	}
	return i, nil
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// profileSpan is the result of canonicalizing one span.
type profileSpan struct {
	CanonicalBytes []byte // JCS of the section 2 object
	SpanSHA256     string
	AttrBytes      []byte // JCS of the section 3 object
	AttrSHA256     string
}

// canonicalSpan builds the profile's canonical object and hash from raw span
// fields and attributes, checking the rules in the order canonical.py does:
// attributes, kind, status_code, trace_id, span_id, parent_span_id, name,
// start_time_unix_nano, end_time_unix_nano. SPEC.md does not define that
// precedence; it only matters for an input with more than one defect, and no
// published vector has one.
func canonicalSpan(span obj, attributes any) (profileSpan, error) {
	pairs, err := pairsFromAny(attributes)
	if err != nil {
		return profileSpan{}, err
	}
	attrText, err := attrObject(pairs)
	if err != nil {
		return profileSpan{}, err
	}
	attrBytes, err := jcs.Transform([]byte(attrText))
	if err != nil {
		return profileSpan{}, err
	}

	field := func(name string) any { v, _ := span.last(name); return v }

	kind, err := checkSmallInt(field("kind"), 5, "KIND_OUT_OF_RANGE")
	if err != nil {
		return profileSpan{}, err
	}
	status, err := checkSmallInt(field("status_code"), 2, "STATUS_OUT_OF_RANGE")
	if err != nil {
		return profileSpan{}, err
	}
	traceID, err := checkID(field("trace_id"), 32, false)
	if err != nil {
		return profileSpan{}, err
	}
	spanID, err := checkID(field("span_id"), 16, false)
	if err != nil {
		return profileSpan{}, err
	}
	// A missing parent_span_id is "no parent". An explicit JSON null is not:
	// SPEC.md allows only the empty string, and canonical.py rejects null as
	// ID_BAD_LENGTH (validate.mjs would accept it).
	parent, hasParent := span.last("parent_span_id")
	if !hasParent {
		parent = ""
	}
	parentID, err := checkID(parent, 16, true)
	if err != nil {
		return profileSpan{}, err
	}
	name, ok := field("name").(string)
	if !ok {
		return profileSpan{}, reject("BAD_WRAPPER")
	}
	start, err := checkTimestamp(field("start_time_unix_nano"))
	if err != nil {
		return profileSpan{}, err
	}
	end, err := checkTimestamp(field("end_time_unix_nano"))
	if err != nil {
		return profileSpan{}, err
	}

	attrSum := sha256Hex(attrBytes)
	text := `{"trace_id":` + jstr(traceID) +
		`,"span_id":` + jstr(spanID) +
		`,"parent_span_id":` + jstr(parentID) +
		`,"name":` + jstr(name) +
		`,"kind":` + strconv.FormatInt(kind, 10) +
		`,"start_time_unix_nano":` + jstr(start) +
		`,"end_time_unix_nano":` + jstr(end) +
		`,"status_code":` + strconv.FormatInt(status, 10) +
		`,"attributes_sha256":` + jstr(attrSum) + `}`
	canon, err := jcs.Transform([]byte(text))
	if err != nil {
		return profileSpan{}, err
	}
	return profileSpan{
		CanonicalBytes: canon,
		SpanSHA256:     sha256Hex(canon),
		AttrBytes:      attrBytes,
		AttrSHA256:     attrSum,
	}, nil
}

// batchRoot is the RFC 6962 Merkle tree head over span hashes (SPEC.md
// section 4). hashes are lowercase hex SHA-256 values.
func batchRoot(hashes []string) (string, error) {
	if len(hashes) == 0 {
		return "", reject("EMPTY_BATCH")
	}
	raw := make([][]byte, len(hashes))
	for i, h := range hashes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != sha256.Size {
			return "", errors.New("span hash is not 32 hex-encoded bytes")
		}
		raw[i] = b
	}
	var mth func([][]byte) []byte
	mth = func(xs [][]byte) []byte {
		if len(xs) == 1 {
			s := sha256.Sum256(append([]byte{0x00}, xs[0]...))
			return s[:]
		}
		k := 1
		for k*2 < len(xs) {
			k *= 2
		}
		l, r := mth(xs[:k]), mth(xs[k:])
		s := sha256.Sum256(append(append([]byte{0x01}, l...), r...))
		return s[:]
	}
	return hex.EncodeToString(mth(raw)), nil
}

package profilecompare

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// setWrapper stores the profile's typed wrapper w into v as the matching pdata
// value type.
func setWrapper(t *testing.T, v pcommon.Value, w any) {
	t.Helper()
	wo := w.(obj)
	tag, val := wo[0].key, wo[0].val
	switch tag {
	case "s":
		v.SetStr(val.(string))
	case "b":
		v.SetBool(val.(bool))
	case "i":
		n, err := strconv.ParseInt(val.(string), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		v.SetInt(n)
	case "d":
		f, err := strconv.ParseFloat(string(val.(json.Number)), 64)
		if err != nil {
			t.Fatal(err)
		}
		v.SetDouble(f)
	case "y":
		raw, err := base64.StdEncoding.DecodeString(val.(string))
		if err != nil {
			t.Fatal(err)
		}
		v.SetEmptyBytes().FromRaw(raw)
	case "a":
		s := v.SetEmptySlice()
		for _, e := range val.([]any) {
			setWrapper(t, s.AppendEmpty(), e)
		}
	case "kv":
		pairs, err := pairsFromAny(val)
		if err != nil {
			t.Fatal(err)
		}
		m := v.SetEmptyMap()
		for _, p := range pairs {
			setWrapper(t, m.PutEmpty(p.key), p.val)
		}
	default:
		t.Fatalf("unknown wrapper tag %q", tag)
	}
}

// buildSpan turns a profile span object (the fields of a *.canonical.json, or
// of a reject input's "span") plus its attributes into a pdata span, so the
// repo's own SpanToRecord can be run over exactly the same data the profile
// hashed. It only accepts well-formed input: rejects have no pdata analogue.
func buildSpan(t *testing.T, span obj, attrs any) ptrace.Span {
	t.Helper()
	s := ptrace.NewSpan()
	get := func(k string) any { v, _ := span.last(k); return v }

	var tid pcommon.TraceID
	b, _ := hex.DecodeString(get("trace_id").(string))
	copy(tid[:], b)
	s.SetTraceID(tid)

	var sid pcommon.SpanID
	b, _ = hex.DecodeString(get("span_id").(string))
	copy(sid[:], b)
	s.SetSpanID(sid)

	if p, _ := get("parent_span_id").(string); p != "" {
		var pid pcommon.SpanID
		b, _ = hex.DecodeString(p)
		copy(pid[:], b)
		s.SetParentSpanID(pid)
	}

	s.SetName(get("name").(string))
	kind, _ := strconv.Atoi(string(get("kind").(json.Number)))
	s.SetKind(ptrace.SpanKind(kind))
	start, _ := strconv.ParseUint(get("start_time_unix_nano").(string), 10, 64)
	end, _ := strconv.ParseUint(get("end_time_unix_nano").(string), 10, 64)
	s.SetStartTimestamp(pcommon.Timestamp(start))
	s.SetEndTimestamp(pcommon.Timestamp(end))
	status, _ := strconv.Atoi(string(get("status_code").(json.Number)))
	s.Status().SetCode(ptrace.StatusCode(status))

	pairs, err := pairsFromAny(attrs)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pairs {
		setWrapper(t, s.Attributes().PutEmpty(p.key), p.val)
	}
	return s
}

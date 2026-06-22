package record

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// fixtureSpan builds the canonical test span used in golden-fixture tests.
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

func TestSpanToRecord_GoldenFixture(t *testing.T) {
	span := fixtureSpan()
	got := SpanToRecord(span, 0)

	gotJSON, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}

	const fixturePath = "testdata/v1_span_to_record_fixture.json"
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}

	// Trim trailing whitespace for editor-agnostic comparison.
	if strings.TrimRight(string(gotJSON), "\n\r ") != strings.TrimRight(string(want), "\n\r ") {
		t.Errorf("SpanToRecord output diverges from fixture.\ngot:\n%s\nwant:\n%s", gotJSON, want)
	}
}

func TestSpanToRecord_Deterministic(t *testing.T) {
	span := fixtureSpan()
	a := SpanToRecord(span, 0)
	b := SpanToRecord(span, 0)

	aJSON, _ := json.Marshal(a)
	bJSON, _ := json.Marshal(b)

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
	// attributeAllowlist order: operation.name < request.model < system (alphabetical)
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

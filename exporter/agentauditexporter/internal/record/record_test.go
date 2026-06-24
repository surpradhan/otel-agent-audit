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

// TestSpanToRecord_GoldenFixture is the v2 cross-impl lock: SpanToRecord must
// produce byte-for-byte JSON matching testdata/v2_span_to_record_fixture.json.
func TestSpanToRecord_GoldenFixture(t *testing.T) {
	span := fixtureSpan()
	got := SpanToRecord(span, 0)

	gotJSON, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}

	const fixturePath = "testdata/v2_span_to_record_fixture.json"
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}

	// Trim trailing whitespace for editor-agnostic comparison.
	if strings.TrimRight(string(gotJSON), "\n\r ") != strings.TrimRight(string(want), "\n\r ") {
		t.Errorf("SpanToRecord output diverges from v2 fixture.\ngot:\n%s\nwant:\n%s", gotJSON, want)
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
	if rec.SchemaVersion != "v2" {
		t.Errorf("SchemaVersion: got %q, want %q", rec.SchemaVersion, "v2")
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

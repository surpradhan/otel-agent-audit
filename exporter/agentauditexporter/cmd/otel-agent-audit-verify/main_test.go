package main

import (
	"testing"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/verify"
)

// TestErrorLabel pins the "[...]" prefix used for each report line, since an
// empty TraceID alone is not a safe proxy for "checkpoint-level" now that
// torn_trailing_line (log-level) also carries an empty TraceID.
func TestErrorLabel(t *testing.T) {
	tests := []struct {
		name string
		err  verify.VerifyError
		want string
	}{
		{
			name: "trace-scoped error",
			err:  verify.VerifyError{TraceID: "abc123", Kind: "chain"},
			want: "abc123",
		},
		{
			name: "checkpoint error",
			err:  verify.VerifyError{TraceID: "", Kind: "checkpoint"},
			want: "checkpoint",
		},
		{
			// Not a Kind verify.VerifyLog produces today (checkpoint and
			// torn_trailing_line are the only empty-TraceID kinds it emits —
			// see verify.go) — this pins errorLabel's fallback for any other
			// empty-TraceID kind, so a future addition defaults sanely without
			// needing its own case here.
			name: "unrecognized empty-TraceID kind falls back to checkpoint",
			err:  verify.VerifyError{TraceID: "", Kind: "some_future_kind"},
			want: "checkpoint",
		},
		{
			name: "torn trailing audit-log line",
			err:  verify.VerifyError{TraceID: "", Kind: verify.KindTornTrailingLine},
			want: "audit log",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errorLabel(tt.err); got != tt.want {
				t.Errorf("errorLabel(%+v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

// TestFatalCount pins the exit-code/Status-line policy (issue #49): only
// verify.SeverityFatal errors count, so a report holding solely advisory
// findings counts zero, and mixing severities counts only the fatal ones.
func TestFatalCount(t *testing.T) {
	tests := []struct {
		name string
		errs []verify.VerifyError
		want int
	}{
		{
			name: "no errors",
			errs: nil,
			want: 0,
		},
		{
			name: "all advisory",
			errs: []verify.VerifyError{
				{Kind: "key_id_field_mismatch", Severity: verify.SeverityAdvisory},
				{Kind: verify.KindTornTrailingLine, Severity: verify.SeverityAdvisory},
			},
			want: 0,
		},
		{
			name: "all fatal",
			errs: []verify.VerifyError{
				{Kind: "chain", Severity: verify.SeverityFatal},
				{Kind: "checkpoint", Severity: verify.SeverityFatal},
			},
			want: 2,
		},
		{
			name: "mixed severities counts only fatal",
			errs: []verify.VerifyError{
				{Kind: "chain", Severity: verify.SeverityFatal},
				{Kind: "key_id_field_mismatch", Severity: verify.SeverityAdvisory},
				{Kind: verify.KindTornTrailingLine, Severity: verify.SeverityAdvisory},
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fatalCount(tt.errs); got != tt.want {
				t.Errorf("fatalCount(%+v) = %d, want %d", tt.errs, got, tt.want)
			}
		})
	}
}

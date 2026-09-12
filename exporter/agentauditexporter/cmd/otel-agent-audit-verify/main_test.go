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
			name: "checkpoint-side key_id_mismatch",
			err:  verify.VerifyError{TraceID: "", Kind: "key_id_mismatch"},
			want: "checkpoint",
		},
		{
			name: "torn trailing audit-log line",
			err:  verify.VerifyError{TraceID: "", Kind: "torn_trailing_line"},
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

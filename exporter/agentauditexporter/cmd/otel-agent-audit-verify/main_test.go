package main

import (
	"strings"
	"testing"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/verify"
)

// TestFormatReport_LayoutWithoutOtherClaimedKeyIDs pins the human-readable
// layout byte for byte when there is nothing to hint at, so a report for an
// ordinary log reads exactly as it did before issue #50 added the Note block.
func TestFormatReport_LayoutWithoutOtherClaimedKeyIDs(t *testing.T) {
	report := verify.Report{
		TracesProcessed:      2,
		CheckpointsProcessed: 1,
		Errors: []verify.VerifyError{
			{TraceID: "abc123", Kind: "chain", Detail: "seq 0: signature verification failed", Severity: verify.SeverityFatal},
			{Kind: verify.KindTornTrailingLine, Detail: "line 3: unparseable", Severity: verify.SeverityAdvisory},
		},
	}
	want := "Traces processed:      2\n" +
		"Checkpoints processed: 1\n" +
		"Status: FAILED (1 fatal, 1 advisory)\n" +
		"  [abc123] chain (fatal): seq 0: signature verification failed\n" +
		"  [audit log] torn_trailing_line (advisory): line 3: unparseable\n"
	if got := formatReport(report); got != want {
		t.Errorf("formatReport mismatch\n got: %q\nwant: %q", got, want)
	}
}

// TestFormatReport_NoteFollowsTheFindings pins where the Note block goes and
// what it lists: after the per-finding lines, one ID per line, with the Status
// line above it untouched.
func TestFormatReport_NoteFollowsTheFindings(t *testing.T) {
	report := verify.Report{
		TracesProcessed:      2,
		CheckpointsProcessed: 2,
		Errors: []verify.VerifyError{
			{Kind: "checkpoint", Detail: "seq 2: checkpoint: signature verification failed", Severity: verify.SeverityFatal},
		},
		OtherClaimedKeyIDs: []string{"aaaa", "bbbb"},
	}
	got := formatReport(report)

	wantPrefix := "Traces processed:      2\n" +
		"Checkpoints processed: 2\n" +
		"Status: FAILED (1 error(s))\n" +
		"  [checkpoint] checkpoint (fatal): seq 2: checkpoint: signature verification failed\n" +
		"Note: the log claims 2 key_id(s) other than the supplied key's:\n" +
		"  aaaa\n" +
		"  bbbb\n"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("formatReport does not start with the expected findings + Note header\n got: %q\nwant prefix: %q", got, wantPrefix)
	}
	for _, phrase := range []string{"key rotation", "wrong key", "unauthenticated", "never affects Status or the exit code", "docs/verification.md"} {
		if !strings.Contains(got, phrase) {
			t.Errorf("the Note should mention %q; got:\n%s", phrase, got)
		}
	}
}

// TestFormatReport_NoteNeverChangesStatus: the hint is not a finding, so a log
// with nothing else wrong still reads Status: OK while carrying it.
func TestFormatReport_NoteNeverChangesStatus(t *testing.T) {
	got := formatReport(verify.Report{
		TracesProcessed:      1,
		CheckpointsProcessed: 1,
		OtherClaimedKeyIDs:   []string{"aaaa"},
	})
	if !strings.Contains(got, "\nStatus: OK\n") || strings.Contains(got, "FAILED") {
		t.Errorf("a hint alone must leave the report at Status: OK; got:\n%s", got)
	}
	if !strings.Contains(got, "claims 1 key_id(s)") {
		t.Errorf("expected the Note for one key_id; got:\n%s", got)
	}
}

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

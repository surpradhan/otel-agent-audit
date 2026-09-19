package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/chain"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/sign"
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
// what it says when something failed: after the per-finding lines, one ID per
// line, with the Status line above it untouched, and with advice that is
// explicit that it does not excuse the findings.
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
	for _, phrase := range []string{
		"unverified claims",
		"does not explain or excuse the findings above",
		"obtained independently of this log",
		"never affects Status or the exit code",
		"docs/verification.md",
	} {
		if !strings.Contains(got, phrase) {
			t.Errorf("the Note should mention %q; got:\n%s", phrase, got)
		}
	}
	if strings.Contains(got, "key_id metadata only") {
		t.Errorf("the metadata-only wording is for reports with no fatal finding; got:\n%s", got)
	}
}

// TestFormatReport_NoteWithoutFatalFindings: when nothing failed — here the
// advisory-only report an edited entry key_id produces, where everything
// verified against the supplied key — the Note must not offer a rotation or a
// wrong key as an explanation for anything, and the report still reads
// Status: OK.
func TestFormatReport_NoteWithoutFatalFindings(t *testing.T) {
	got := formatReport(verify.Report{
		TracesProcessed:      1,
		CheckpointsProcessed: 1,
		Errors: []verify.VerifyError{
			{TraceID: "abc123", Kind: "key_id_field_mismatch", Detail: "seq 0: entry key_id bogus does not match verified signer real", Severity: verify.SeverityAdvisory},
		},
		OtherClaimedKeyIDs: []string{"bogus"},
	})

	wantPrefix := "Traces processed:      1\n" +
		"Checkpoints processed: 1\n" +
		"Status: OK (1 advisory finding(s))\n" +
		"  [abc123] key_id_field_mismatch (advisory): seq 0: entry key_id bogus does not match verified signer real\n" +
		"Note: the log claims 1 key_id(s) other than the supplied key's:\n" +
		"  bogus\n"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("formatReport does not start with the expected findings + Note header\n got: %q\nwant prefix: %q", got, wantPrefix)
	}
	if !strings.Contains(got, "key_id metadata only") {
		t.Errorf("with nothing failed the Note should say this concerns metadata only; got:\n%s", got)
	}
	for _, phrase := range []string{"key rotation", "verify again", "explain or excuse"} {
		if strings.Contains(got, phrase) {
			t.Errorf("with nothing failed the Note must not mention %q; got:\n%s", phrase, got)
		}
	}
}

// TestFormatReport_NoteEscapesUntrustedIDs: the key_ids the Note lists are text
// read from the log, which anyone who can edit it controls. A newline in one
// must not be able to forge an output line (a fake "Status: OK"), and an escape
// sequence must not reach the terminal. This covers the Note only; the report's
// other lines are unchanged by issue #50.
func TestFormatReport_NoteEscapesUntrustedIDs(t *testing.T) {
	got := formatReport(verify.Report{
		TracesProcessed:      1,
		CheckpointsProcessed: 1,
		Errors: []verify.VerifyError{
			{Kind: "checkpoint", Detail: "seq 1: checkpoint: signature verification failed", Severity: verify.SeverityFatal},
		},
		OtherClaimedKeyIDs: []string{"evil\nStatus: OK", "esc\x1b[2J\x1b[H"},
	})

	for i := 0; i < len(got); i++ {
		if c := got[i]; c != '\n' && (c < 0x20 || c == 0x7f) {
			t.Fatalf("output contains a raw control byte %#x at offset %d: %q", c, i, got)
		}
	}
	var statusLines int
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Status:") {
			statusLines++
		}
	}
	if statusLines != 1 {
		t.Errorf("want exactly one Status line, got %d:\n%s", statusLines, got)
	}
	for _, want := range []string{`evil\nStatus: OK`, `esc\x1b[2J\x1b[H`} {
		if !strings.Contains(got, want) {
			t.Errorf("want the escaped form %q in the output; got:\n%s", want, got)
		}
	}
}

// TestEscapeUntrusted_LeavesNormalKeyIDsUnchanged: a key_id in its normal form
// (64 lowercase hex characters) must print exactly as it is stored, so the
// escaping never gets in the way of matching an id against a known key.
func TestEscapeUntrusted_LeavesNormalKeyIDsUnchanged(t *testing.T) {
	id := strings.Repeat("0123456789abcdef", 4)
	if got := escapeUntrusted(id); got != id {
		t.Errorf("escapeUntrusted(%q) = %q, want it unchanged", id, got)
	}
}

// runCLI runs the CLI in-process with args and returns what it wrote to stdout
// and its exit code. run reads os.Args and writes to os.Stdout directly, so
// this swaps both for the duration of the call; callers must not run in
// parallel.
func runCLI(t *testing.T, args ...string) (stdout string, exitCode int) {
	t.Helper()
	origArgs, origStdout := os.Args, os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { os.Args, os.Stdout = origArgs, origStdout })
	os.Args = append([]string{"otel-agent-audit-verify"}, args...)
	os.Stdout = w

	captured := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		captured <- string(b)
	}()
	exitCode = run()
	os.Args, os.Stdout = origArgs, origStdout
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	stdout = <-captured
	_ = r.Close()
	return stdout, exitCode
}

// writeJSONLine writes v as a single JSON line to path.
func writeJSONLine(t *testing.T, path string, v any) {
	t.Helper()
	line, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal for %s: %v", path, err)
	}
	if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeSingleKeyFixture writes a one-trace log and its checkpoint, both signed
// by one fresh key, and returns their paths and that key in the hex form -key
// takes.
func writeSingleKeyFixture(t *testing.T) (logPath, checkpointPath, pubHex string) {
	t.Helper()
	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	signer := sign.NewEd25519Signer(priv)

	const traceID = "01010101010101010101010101010101"
	rec := record.AuditRecord{
		SchemaVersion: record.SchemaVersion,
		TraceID:       traceID,
		SpanID:        "0102030405060708",
		ParentSpanID:  "0000000000000000",
		SeqInTrace:    0,
		SpanName:      "root",
		OtelKind:      "Internal",
		AuditKind:     record.AuditKindTask,
		Status:        "Ok",
	}
	seed, err := chain.GenesisSeed(traceID)
	if err != nil {
		t.Fatalf("GenesisSeed: %v", err)
	}
	built, err := chain.BuildChain([]record.AuditRecord{rec}, seed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)
	acc.AddTip(traceID, chain.TipHash(built), len(built))
	cp, err := acc.Build(time.Unix(1757000000, 0).UTC())
	if err != nil {
		t.Fatalf("Build checkpoint: %v", err)
	}

	dir := t.TempDir()
	logPath = filepath.Join(dir, "audit.jsonl")
	checkpointPath = filepath.Join(dir, "checkpoint.jsonl")
	writeJSONLine(t, logPath, chain.ToLogEntries(built)[0])
	writeJSONLine(t, checkpointPath, cp)
	return logPath, checkpointPath, hex.EncodeToString(pub)
}

// readEntry returns the single log entry in logPath.
func readEntry(t *testing.T, logPath string) chain.LogEntry {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read %s: %v", logPath, err)
	}
	var e chain.LogEntry
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}
	return e
}

// TestRun_OtherClaimedKeyIDs drives the real CLI entry point end to end. The
// property that matters most about the hint, that it never changes the exit
// code, is implemented in run, not in formatReport, so only a test of run can
// guard it.
func TestRun_OtherClaimedKeyIDs(t *testing.T) {
	t.Run("no hint: exit 0 and no Note", func(t *testing.T) {
		logPath, cpPath, pubHex := writeSingleKeyFixture(t)
		out, code := runCLI(t, "-key", pubHex, logPath, cpPath)
		if code != 0 {
			t.Errorf("exit code = %d, want 0; output:\n%s", code, out)
		}
		want := "Traces processed:      1\nCheckpoints processed: 1\nStatus: OK\n"
		if out != want {
			t.Errorf("output mismatch\n got: %q\nwant: %q", out, want)
		}
	})

	t.Run("hint only (edited entry key_id): still exit 0 and Status: OK", func(t *testing.T) {
		logPath, cpPath, pubHex := writeSingleKeyFixture(t)
		e := readEntry(t, logPath)
		e.Signed.KeyID = "bogus-key-id"
		writeJSONLine(t, logPath, e)

		out, code := runCLI(t, "-key", pubHex, logPath, cpPath)
		if code != 0 {
			t.Errorf("exit code = %d, want 0: a hint alone must not fail verification; output:\n%s", code, out)
		}
		if !strings.Contains(out, "Status: OK (1 advisory finding(s))\n") {
			t.Errorf("want Status: OK with the one advisory finding; output:\n%s", out)
		}
		if !strings.Contains(out, "Note: the log claims 1 key_id(s) other than the supplied key's:\n  bogus-key-id\n") {
			t.Errorf("want the Note listing the edited key_id; output:\n%s", out)
		}
	})

	t.Run("hint plus a fatal finding (wrong key): exit 1", func(t *testing.T) {
		logPath, cpPath, _ := writeSingleKeyFixture(t)
		realKeyID := readEntry(t, logPath).Signed.KeyID
		_, wrongPub, err := sign.GenerateEd25519Key()
		if err != nil {
			t.Fatalf("GenerateEd25519Key: %v", err)
		}

		out, code := runCLI(t, "-key", hex.EncodeToString(wrongPub), logPath, cpPath)
		if code != 1 {
			t.Errorf("exit code = %d, want 1; output:\n%s", code, out)
		}
		if !strings.Contains(out, "Status: FAILED") {
			t.Errorf("want Status: FAILED; output:\n%s", out)
		}
		if !strings.Contains(out, "Note: the log claims 1 key_id(s) other than the supplied key's:\n  "+realKeyID+"\n") {
			t.Errorf("want the Note listing the log's real key_id %s; output:\n%s", realKeyID, out)
		}
	})

	t.Run("-json carries the hint under its documented name", func(t *testing.T) {
		logPath, cpPath, _ := writeSingleKeyFixture(t)
		realKeyID := readEntry(t, logPath).Signed.KeyID
		_, wrongPub, err := sign.GenerateEd25519Key()
		if err != nil {
			t.Fatalf("GenerateEd25519Key: %v", err)
		}

		out, code := runCLI(t, "-json", "-key", hex.EncodeToString(wrongPub), logPath, cpPath)
		if code != 1 {
			t.Errorf("exit code = %d, want 1; output:\n%s", code, out)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(out), &fields); err != nil {
			t.Fatalf("output is not a JSON object: %v\n%s", err, out)
		}
		var got []string
		if err := json.Unmarshal(fields["OtherClaimedKeyIDs"], &got); err != nil {
			t.Fatalf(`JSON key "OtherClaimedKeyIDs" is missing or not an array of strings: %v; output:\n%s`, err, out)
		}
		if want := []string{realKeyID}; !slices.Equal(got, want) {
			t.Errorf(`JSON key "OtherClaimedKeyIDs" = %q, want %q; output:\n%s`, got, want, out)
		}
	})
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

package verify_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

const fixtureTraceID = "01010101010101010101010101010101"

func makeVerifyFixture(t *testing.T) (logPath, checkpointPath string, pub []byte) {
	t.Helper()
	priv, pubKey, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	signer := sign.NewEd25519Signer(priv)

	recs := []record.AuditRecord{
		{
			SchemaVersion: record.SchemaVersion,
			TraceID:       fixtureTraceID,
			SpanID:        "0102030405060708",
			ParentSpanID:  "0000000000000000",
			SeqInTrace:    0,
			SpanName:      "root",
			OtelKind:      "Internal",
			AuditKind:     record.AuditKindTask,
			Status:        "Ok",
		},
	}

	genesisSeed, err := chain.GenesisSeed(fixtureTraceID)
	if err != nil {
		t.Fatalf("GenesisSeed: %v", err)
	}
	entries, err := chain.BuildChain(recs, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	dir := t.TempDir()
	logPath = filepath.Join(dir, "audit.jsonl")
	checkpointPath = filepath.Join(dir, "checkpoint.jsonl")

	lf, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	for _, e := range chain.ToLogEntries(entries) {
		line, _ := json.Marshal(e)
		_, _ = lf.Write(append(line, '\n'))
	}
	_ = lf.Close()

	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)
	acc.AddTip(fixtureTraceID, chain.TipHash(entries), len(entries))
	cp, err := acc.Build(time.Now())
	if err != nil {
		t.Fatalf("Build checkpoint: %v", err)
	}
	cf, err := os.Create(checkpointPath)
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}
	cpLine, _ := json.Marshal(cp)
	_, _ = cf.Write(append(cpLine, '\n'))
	_ = cf.Close()

	return logPath, checkpointPath, []byte(pubKey)
}

// TestReport_FatalCount pins the exit-code/Status-line policy (issue #49):
// only non-advisory errors count, and — deliberately — an error with an
// empty or unrecognized Severity counts as fatal (fail-closed), not
// advisory, since a tamper-evidence tool should never silently treat an
// unclassified finding as safe to ignore.
func TestReport_FatalCount(t *testing.T) {
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
			name: "mixed severities counts only non-advisory",
			errs: []verify.VerifyError{
				{Kind: "chain", Severity: verify.SeverityFatal},
				{Kind: "key_id_field_mismatch", Severity: verify.SeverityAdvisory},
				{Kind: verify.KindTornTrailingLine, Severity: verify.SeverityAdvisory},
			},
			want: 1,
		},
		{
			name: "empty Severity fails closed as fatal",
			errs: []verify.VerifyError{
				{Kind: "some_future_kind", Severity: ""},
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := verify.Report{Errors: tt.errs}
			if got := report.FatalCount(); got != tt.want {
				t.Errorf("Report{Errors: %+v}.FatalCount() = %d, want %d", tt.errs, got, tt.want)
			}
		})
	}
}

// TestReport_StatusLine pins the exact "Status: ..." text for every
// combination of fatal/advisory error counts (issue #49) — only fatal
// findings decide OK vs FAILED, but the advisory count is always named too,
// so the line never undercounts what a caller's per-error printout shows
// underneath it. Both otel-agent-audit-verify and cmd/demo call this method
// directly, so pinning it here covers both CLIs' Status-line text at once.
func TestReport_StatusLine(t *testing.T) {
	tests := []struct {
		name string
		errs []verify.VerifyError
		want string
	}{
		{
			name: "clean",
			errs: nil,
			want: "Status: OK",
		},
		{
			name: "advisory only",
			errs: []verify.VerifyError{
				{Kind: "key_id_field_mismatch", Severity: verify.SeverityAdvisory},
				{Kind: verify.KindTornTrailingLine, Severity: verify.SeverityAdvisory},
			},
			want: "Status: OK (2 advisory finding(s))",
		},
		{
			name: "fatal only",
			errs: []verify.VerifyError{
				{Kind: "chain", Severity: verify.SeverityFatal},
			},
			want: "Status: FAILED (1 error(s))",
		},
		{
			name: "mixed",
			errs: []verify.VerifyError{
				{Kind: "chain", Severity: verify.SeverityFatal},
				{Kind: "key_id_field_mismatch", Severity: verify.SeverityAdvisory},
				{Kind: verify.KindTornTrailingLine, Severity: verify.SeverityAdvisory},
			},
			want: "Status: FAILED (1 fatal, 2 advisory)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := verify.Report{Errors: tt.errs}
			if got := report.StatusLine(); got != tt.want {
				t.Errorf("Report{Errors: %+v}.StatusLine() = %q, want %q", tt.errs, got, tt.want)
			}
		})
	}
}

func TestVerifyLog_HappyPath(t *testing.T) {
	logPath, checkpointPath, pub := makeVerifyFixture(t)
	report, err := verify.VerifyLog(logPath, checkpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("expected no errors; got %v", report.Errors)
	}
	if report.TracesProcessed != 1 {
		t.Errorf("want 1 trace verified; got %d", report.TracesProcessed)
	}
	if report.CheckpointsProcessed != 1 {
		t.Errorf("want 1 checkpoint verified; got %d", report.CheckpointsProcessed)
	}
}

func TestVerifyLog_TamperedRecord(t *testing.T) {
	logPath, checkpointPath, pub := makeVerifyFixture(t)
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	tampered := strings.ReplaceAll(string(data), `"root"`, `"tampered"`)
	if err := os.WriteFile(logPath, []byte(tampered), 0600); err != nil {
		t.Fatalf("write tampered log: %v", err)
	}

	report, err := verify.VerifyLog(logPath, checkpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) == 0 {
		t.Error("expected verification errors for tampered record; got none")
	}
}

func TestVerifyLog_MissingFiles(t *testing.T) {
	_, _, pub := makeVerifyFixture(t)
	report, err := verify.VerifyLog("/nonexistent/audit.jsonl", "/nonexistent/checkpoint.jsonl", pub)
	if err != nil {
		t.Fatalf("VerifyLog with missing files: %v", err)
	}
	if report.TracesProcessed != 0 {
		t.Errorf("want 0 traces; got %d", report.TracesProcessed)
	}
	if len(report.Errors) != 0 {
		t.Errorf("expected no errors for empty log; got %v", report.Errors)
	}
}

// TestVerifyLog_TamperedChainEmitsBothErrors asserts that when a chain fails
// verification, the cross-check loop still emits tip_hash_unverifiable for the
// trace rather than silently skipping it (regression for the ok-guard bug).
func TestVerifyLog_TamperedChainEmitsBothErrors(t *testing.T) {
	logPath, checkpointPath, pub := makeVerifyFixture(t)
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	tampered := strings.ReplaceAll(string(data), `"root"`, `"tampered"`)
	if err := os.WriteFile(logPath, []byte(tampered), 0600); err != nil {
		t.Fatalf("write tampered log: %v", err)
	}

	report, err := verify.VerifyLog(logPath, checkpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}

	var hasChain, hasTipUnverifiable bool
	for _, e := range report.Errors {
		if e.Kind == "chain" {
			hasChain = true
			if e.Severity != verify.SeverityFatal {
				t.Errorf("chain error Severity = %q, want %q", e.Severity, verify.SeverityFatal)
			}
		}
		if e.Kind == "tip_hash_unverifiable" {
			hasTipUnverifiable = true
			if e.Severity != verify.SeverityFatal {
				t.Errorf("tip_hash_unverifiable error Severity = %q, want %q", e.Severity, verify.SeverityFatal)
			}
		}
	}
	if !hasChain {
		t.Error("expected a 'chain' error; got none")
	}
	if !hasTipUnverifiable {
		t.Errorf("expected a 'tip_hash_unverifiable' error; got errors: %v", report.Errors)
	}
}

// TestVerifyLog_BothSidesTamperedEmitsUnverifiable covers the full attack
// scenario: the log entries AND the checkpoint tip_hash are both replaced.
// The verifier must emit tip_hash_unverifiable (chain failure takes priority)
// and must NOT emit tip_hash_mismatch (the comparison is never reached).
func TestVerifyLog_BothSidesTamperedEmitsUnverifiable(t *testing.T) {
	logPath, checkpointPath, pub := makeVerifyFixture(t)

	// Tamper the log — break the chain signature.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if err := os.WriteFile(logPath, []byte(strings.ReplaceAll(string(data), `"root"`, `"tampered"`)), 0600); err != nil {
		t.Fatalf("write tampered log: %v", err)
	}

	// Also tamper the checkpoint tip_hash to a fabricated value.
	cpData, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	var cp chain.Checkpoint
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(cpData))), &cp); err != nil {
		t.Fatalf("unmarshal checkpoint: %v", err)
	}
	cp.TraceTips[0].TipHash = strings.Repeat("ff", 32)
	cpLine, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("marshal checkpoint: %v", err)
	}
	if err := os.WriteFile(checkpointPath, append(cpLine, '\n'), 0600); err != nil {
		t.Fatalf("write tampered checkpoint: %v", err)
	}

	report, err := verify.VerifyLog(logPath, checkpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}

	var hasChain, hasTipUnverifiable bool
	for _, e := range report.Errors {
		if e.Kind == "chain" {
			hasChain = true
			if e.Severity != verify.SeverityFatal {
				t.Errorf("chain error Severity = %q, want %q", e.Severity, verify.SeverityFatal)
			}
		}
		if e.Kind == "tip_hash_unverifiable" {
			hasTipUnverifiable = true
			if e.Severity != verify.SeverityFatal {
				t.Errorf("tip_hash_unverifiable error Severity = %q, want %q", e.Severity, verify.SeverityFatal)
			}
		}
		if e.Kind == "tip_hash_mismatch" {
			t.Errorf("unexpected tip_hash_mismatch when chain failed: %v", e)
		}
	}
	if !hasChain {
		t.Error("expected a 'chain' error; got none")
	}
	if !hasTipUnverifiable {
		t.Errorf("expected 'tip_hash_unverifiable'; got errors: %v", report.Errors)
	}
}

func TestVerifyChain_Empty(t *testing.T) {
	_, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	if err := verify.VerifyChain(nil, pub); err != nil {
		t.Errorf("VerifyChain(nil): %v", err)
	}
}

// TestVerifyLog_WrongKey asserts that supplying the wrong public key produces
// ordinary signature-failure errors ("chain" / "checkpoint" /
// "tip_hash_unverifiable"), not a distinct "key_id_mismatch" kind. As of
// issue #46, VerifyLog never decides this from the claimed (unauthenticated)
// key_id field — the outcome is whatever the Ed25519 check against the
// supplied key actually says.
func TestVerifyLog_WrongKey(t *testing.T) {
	logPath, checkpointPath, _ := makeVerifyFixture(t)
	_, wrongPub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	report, err := verify.VerifyLog(logPath, checkpointPath, wrongPub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	var sawChain, sawCheckpoint, sawTipUnverifiable bool
	for _, e := range report.Errors {
		if e.Severity != verify.SeverityFatal {
			t.Errorf("%s error Severity = %q, want %q (wrong key: every kind here should be fatal)", e.Kind, e.Severity, verify.SeverityFatal)
		}
		switch e.Kind {
		case "chain":
			sawChain = true
			if !strings.Contains(e.Detail, "signature verification failed") {
				t.Errorf("chain error detail = %q, want it to mention signature verification", e.Detail)
			}
		case "checkpoint":
			sawCheckpoint = true
			if !strings.Contains(e.Detail, "signature verification failed") {
				t.Errorf("checkpoint error detail = %q, want it to mention signature verification", e.Detail)
			}
		case "tip_hash_unverifiable":
			sawTipUnverifiable = true
		default:
			t.Errorf("unexpected error kind %q: %+v", e.Kind, e)
		}
	}
	if !sawChain || !sawCheckpoint || !sawTipUnverifiable {
		t.Errorf("expected chain + checkpoint + tip_hash_unverifiable errors; got %v", report.Errors)
	}
}

// TestVerifyLog_EntrySignedByDifferentKey replaces the old "multi-epoch"
// bail-out test (issue #46): a log holding entries signed by two different
// keys no longer makes VerifyLog refuse the whole log. Each trace is verified
// independently against the single supplied key — the trace actually signed
// by that key verifies cleanly, the other produces an ordinary "chain"
// signature-failure error, and VerifyLog still returns a Report either way.
func TestVerifyLog_EntrySignedByDifferentKey(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	checkpointPath := filepath.Join(dir, "checkpoint.jsonl")

	// Build two entries signed by different keys.
	priv1, _, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key 1: %v", err)
	}
	signer1 := sign.NewEd25519Signer(priv1)

	priv2, pub2, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key 2: %v", err)
	}
	signer2 := sign.NewEd25519Signer(priv2)

	makeEntry := func(signer sign.Signer, traceID, spanID string, seq int) chain.LogEntry {
		rec := record.AuditRecord{
			SchemaVersion: record.SchemaVersion,
			TraceID:       traceID,
			SpanID:        spanID,
			SeqInTrace:    seq,
			SpanName:      "span",
			OtelKind:      "Internal",
			AuditKind:     record.AuditKindTask,
			Status:        "Ok",
		}
		seed, _ := chain.GenesisSeed(traceID)
		entries, _ := chain.BuildChain([]record.AuditRecord{rec}, seed, signer)
		return chain.ToLogEntries(entries)[0]
	}

	traceID1 := "01010101010101010101010101010101"
	traceID2 := "02020202020202020202020202020202"
	e1 := makeEntry(signer1, traceID1, "0102030405060708", 0)
	e2 := makeEntry(signer2, traceID2, "0807060504030201", 0)

	lf, _ := os.Create(logPath)
	for _, e := range []chain.LogEntry{e1, e2} {
		line, _ := json.Marshal(e)
		_, _ = lf.Write(append(line, '\n'))
	}
	_ = lf.Close()
	// Empty checkpoint file.
	if f, err := os.Create(checkpointPath); err == nil {
		_ = f.Close()
	}

	report, err := verify.VerifyLog(logPath, checkpointPath, pub2)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if report.TracesProcessed != 2 {
		t.Errorf("TracesProcessed = %d, want 2", report.TracesProcessed)
	}
	if len(report.Errors) != 1 {
		t.Fatalf("expected exactly 1 error (traceID1, signed by a different key); got %v", report.Errors)
	}
	if e := report.Errors[0]; e.TraceID != traceID1 || e.Kind != "chain" {
		t.Errorf("expected a chain error for %s; got %+v", traceID1, e)
	} else if !strings.Contains(e.Detail, "signature verification failed") {
		t.Errorf("expected a signature-verification-failed detail, got: %s", e.Detail)
	} else if e.Severity != verify.SeverityFatal {
		t.Errorf("chain error Severity = %q, want %q", e.Severity, verify.SeverityFatal)
	}
}

// TestVerifyLog_DifferentSignerWithTornTrailingLine covers the interaction
// between a real different-signer trace and a torn trailing line — both must
// surface in the same Report now that neither condition makes VerifyLog bail
// out early (issue #46).
func TestVerifyLog_DifferentSignerWithTornTrailingLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	checkpointPath := filepath.Join(dir, "checkpoint.jsonl")

	priv1, _, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key 1: %v", err)
	}
	signer1 := sign.NewEd25519Signer(priv1)

	priv2, pub2, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key 2: %v", err)
	}
	signer2 := sign.NewEd25519Signer(priv2)

	makeEntry := func(signer sign.Signer, traceID, spanID string, seq int) chain.LogEntry {
		rec := record.AuditRecord{
			SchemaVersion: record.SchemaVersion,
			TraceID:       traceID,
			SpanID:        spanID,
			SeqInTrace:    seq,
			SpanName:      "span",
			OtelKind:      "Internal",
			AuditKind:     record.AuditKindTask,
			Status:        "Ok",
		}
		seed, _ := chain.GenesisSeed(traceID)
		entries, _ := chain.BuildChain([]record.AuditRecord{rec}, seed, signer)
		return chain.ToLogEntries(entries)[0]
	}

	traceID1 := "01010101010101010101010101010101"
	traceID2 := "02020202020202020202020202020202"
	e1 := makeEntry(signer1, traceID1, "0102030405060708", 0)
	e2 := makeEntry(signer2, traceID2, "0807060504030201", 0)

	lf, _ := os.Create(logPath)
	for _, e := range []chain.LogEntry{e1, e2} {
		line, _ := json.Marshal(e)
		_, _ = lf.Write(append(line, '\n'))
	}
	_, _ = lf.WriteString(`{"record":{"trace_id":"broken"` + "\n")
	_ = lf.Close()
	if f, err := os.Create(checkpointPath); err == nil {
		_ = f.Close()
	}

	report, err := verify.VerifyLog(logPath, checkpointPath, pub2)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	var sawChain, sawTornTail bool
	for _, e := range report.Errors {
		switch {
		case e.Kind == "chain" && e.TraceID == traceID1:
			sawChain = true
			if e.Severity != verify.SeverityFatal {
				t.Errorf("chain error Severity = %q, want %q", e.Severity, verify.SeverityFatal)
			}
		case e.Kind == verify.KindTornTrailingLine:
			sawTornTail = true
			if e.Severity != verify.SeverityAdvisory {
				t.Errorf("torn_trailing_line error Severity = %q, want %q", e.Severity, verify.SeverityAdvisory)
			}
		}
	}
	if !sawChain {
		t.Errorf("expected a chain error for %s; got %v", traceID1, report.Errors)
	}
	if !sawTornTail {
		t.Errorf("expected torn_trailing_line error; got %v", report.Errors)
	}
}

// TestVerifyLog_DuplicateTraceSegment verifies that a log with two entries
// sharing the same (trace_id, seq_in_trace) produces a "duplicate_trace_segment"
// error rather than a confusing chain error.
//
// Severity is pinned as SeverityFatal, not SeverityAdvisory, even though
// docs/threat-model.md §7 calls a duplicate segment "not evidence of
// tampering" (issue #49's deliberate call): that framing is about the
// segment-split event, not about the entries under it, and chain
// verification is skipped entirely for a duplicated trace_id — unlike the
// two advisory kinds, nothing here was actually cryptographically checked.
func TestVerifyLog_DuplicateTraceSegment(t *testing.T) {
	logPath, checkpointPath, pub := makeVerifyFixture(t)

	// Duplicate the single entry to simulate a post-compact re-delivery.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	line := strings.TrimRight(string(data), "\n")
	duplicated := line + "\n" + line + "\n"
	if err := os.WriteFile(logPath, []byte(duplicated), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	report, err := verify.VerifyLog(logPath, checkpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	var found bool
	for _, e := range report.Errors {
		if e.Kind == "duplicate_trace_segment" {
			found = true
			if e.Severity != verify.SeverityFatal {
				t.Errorf("duplicate_trace_segment Severity = %q, want %q", e.Severity, verify.SeverityFatal)
			}
		}
		if e.Kind == "chain" {
			t.Errorf("got misleading chain error for duplicate segment: %v", e)
		}
	}
	if !found {
		t.Errorf("expected duplicate_trace_segment error; got: %v", report.Errors)
	}
}

// TestVerifyLog_TipHashMismatchIsFatal covers a checkpoint whose claimed
// tip_hash disagrees with the actual recomputed tip while the underlying
// chain verifies cleanly — no existing test exercises tip_hash_mismatch as a
// positive case (TestVerifyLog_BothSidesTamperedEmitsUnverifiable pins the
// opposite: when the chain ALSO fails, tip_hash_unverifiable fires instead,
// and the mismatch comparison is never reached). Built by feeding the
// Accumulator a fabricated tip hash directly: Build signs over whatever
// TraceTips it is given, so the checkpoint's own signature — and
// EntryCount, left correct — verify cleanly, isolating the tip_hash
// cross-check itself.
func TestVerifyLog_TipHashMismatchIsFatal(t *testing.T) {
	priv, pubKey, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	signer := sign.NewEd25519Signer(priv)

	recs := []record.AuditRecord{
		{
			SchemaVersion: record.SchemaVersion,
			TraceID:       fixtureTraceID,
			SpanID:        "0102030405060708",
			ParentSpanID:  "0000000000000000",
			SeqInTrace:    0,
			SpanName:      "root",
			OtelKind:      "Internal",
			AuditKind:     record.AuditKindTask,
			Status:        "Ok",
		},
	}
	genesisSeed, err := chain.GenesisSeed(fixtureTraceID)
	if err != nil {
		t.Fatalf("GenesisSeed: %v", err)
	}
	entries, err := chain.BuildChain(recs, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	checkpointPath := filepath.Join(dir, "checkpoint.jsonl")

	lf, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	for _, e := range chain.ToLogEntries(entries) {
		line, _ := json.Marshal(e)
		_, _ = lf.Write(append(line, '\n'))
	}
	_ = lf.Close()

	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)
	fakeTip := strings.Repeat("ab", 32)
	acc.AddTip(fixtureTraceID, fakeTip, len(entries))
	cp, err := acc.Build(time.Now())
	if err != nil {
		t.Fatalf("Build checkpoint: %v", err)
	}
	cf, err := os.Create(checkpointPath)
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}
	cpLine, _ := json.Marshal(cp)
	_, _ = cf.Write(append(cpLine, '\n'))
	_ = cf.Close()

	report, err := verify.VerifyLog(logPath, checkpointPath, pubKey)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) != 1 {
		t.Fatalf("expected exactly 1 error (tip_hash_mismatch); got %v", report.Errors)
	}
	e := report.Errors[0]
	if e.Kind != "tip_hash_mismatch" {
		t.Errorf("expected kind=tip_hash_mismatch, got kind=%s detail=%s", e.Kind, e.Detail)
	}
	if e.Severity != verify.SeverityFatal {
		t.Errorf("expected Severity=%s, got %s", verify.SeverityFatal, e.Severity)
	}
	if !strings.Contains(e.Detail, fakeTip) {
		t.Errorf("expected detail to mention the fabricated tip_hash %s, got: %s", fakeTip, e.Detail)
	}
}

// TestVerifyLog_PartialLastCheckpointLine covers the crash-recovery scenario from
// docs/threat-model.md §3a: a power-loss between the log write and the checkpoint
// fsync can leave a truncated final line in the checkpoint file. The exporter skips
// such lines on restart (readLastCheckpoint); the verifier must do the same so an
// operator can immediately re-run the verifier after a restart without a spurious error.
func TestVerifyLog_PartialLastCheckpointLine(t *testing.T) {
	logPath, checkpointPath, pub := makeVerifyFixture(t)

	// Append a truncated JSON object that cannot be parsed.
	cf, err := os.OpenFile(checkpointPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open checkpoint for append: %v", err)
	}
	_, _ = cf.WriteString(`{"schema_version":"v1","checkpoint_seq":99` + "\n")
	_ = cf.Close()

	report, err := verify.VerifyLog(logPath, checkpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog with partial last checkpoint line: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("expected no errors after partial last line; got %v", report.Errors)
	}
}

// TestVerifyLog_PartialLastLogLine covers issue #27: a crash can tear the
// final line of the audit log itself, not just the checkpoint file, since a
// single write(2) is not atomic. Unlike the checkpoint case, entries before
// the torn line are still verified, and the torn line is reported as a
// torn_trailing_line finding rather than silently dropped or hard-failed —
// the audit log is the evidence, so a silent drop would hide exactly what an
// attacker who could truncate the file would want hidden.
func TestVerifyLog_PartialLastLogLine(t *testing.T) {
	logPath, checkpointPath, pub := makeVerifyFixture(t)

	// Append a truncated JSON object that cannot be parsed.
	lf, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open log for append: %v", err)
	}
	_, _ = lf.WriteString(`{"record":{"trace_id":"broken"` + "\n")
	_ = lf.Close()

	report, err := verify.VerifyLog(logPath, checkpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog with partial last log line: %v", err)
	}
	if report.TracesProcessed != 1 {
		t.Errorf("want 1 trace verified (the entry before the torn line); got %d", report.TracesProcessed)
	}
	var found bool
	for _, e := range report.Errors {
		if e.Kind == "chain" {
			t.Errorf("got misleading chain error for torn trailing line: %v", e)
		}
		if e.Kind == verify.KindTornTrailingLine {
			found = true
		}
	}
	if !found {
		t.Errorf("expected torn_trailing_line error; got: %v", report.Errors)
	}
	if len(report.Errors) != 1 {
		t.Errorf("expected exactly 1 error; got %v", report.Errors)
	}
}

// TestVerifyLog_UnparseableNonFinalLogLine ensures the torn-tail tolerance is
// scoped to the final line only: an unparseable line anywhere earlier is
// corruption or tampering, not an interrupted write, and must remain a hard
// error.
func TestVerifyLog_UnparseableNonFinalLogLine(t *testing.T) {
	logPath, checkpointPath, pub := makeVerifyFixture(t)

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	// Prepend a garbage line so it is first, not last.
	corrupted := `{"record":{"trace_id":"broken"` + "\n" + string(data)
	if err := os.WriteFile(logPath, []byte(corrupted), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	if _, err := verify.VerifyLog(logPath, checkpointPath, pub); err == nil {
		t.Error("expected a hard error for an unparseable non-final line; got nil")
	}
}

// TestVerifyLog_OnlyLogLineIsTorn covers a crash on the very first write: the
// log contains nothing but a torn line, which is both first and last. It must
// be tolerated the same as a torn tail following valid entries, not
// hard-error just because it is also the only line.
//
// The fixture's checkpoint still claims one entry for fixtureTraceID, but the
// log now has zero — so, in addition to torn_trailing_line, an incidental
// entry_count_mismatch is expected too. Both are pinned explicitly (rather
// than just checking torn_trailing_line is present) so a future regression in
// the checkpoint cross-check does not go unnoticed here.
func TestVerifyLog_OnlyLogLineIsTorn(t *testing.T) {
	logPath, checkpointPath, pub := makeVerifyFixture(t)

	if err := os.WriteFile(logPath, []byte(`{"record":{"trace_id":"broken"`+"\n"), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	report, err := verify.VerifyLog(logPath, checkpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog with only-line-torn log: %v", err)
	}
	if report.TracesProcessed != 0 {
		t.Errorf("want 0 traces verified; got %d", report.TracesProcessed)
	}
	var sawTornTail, sawEntryCountMismatch bool
	for _, e := range report.Errors {
		switch e.Kind {
		case verify.KindTornTrailingLine:
			sawTornTail = true
			if e.Severity != verify.SeverityAdvisory {
				t.Errorf("torn_trailing_line Severity = %q, want %q", e.Severity, verify.SeverityAdvisory)
			}
		case "entry_count_mismatch":
			sawEntryCountMismatch = true
			if e.Severity != verify.SeverityFatal {
				t.Errorf("entry_count_mismatch Severity = %q, want %q", e.Severity, verify.SeverityFatal)
			}
		}
	}
	if !sawTornTail {
		t.Errorf("expected torn_trailing_line error; got: %v", report.Errors)
	}
	if !sawEntryCountMismatch {
		t.Errorf("expected incidental entry_count_mismatch (checkpoint still claims 1 entry); got: %v", report.Errors)
	}
	if len(report.Errors) != 2 {
		t.Errorf("expected exactly 2 errors (torn_trailing_line + entry_count_mismatch); got %v", report.Errors)
	}
}

// TestVerifyLog_WrongKeyWithTornTrailingLine covers a wrong-key run whose log
// also has a torn final line — both must surface in the same Report; neither
// condition makes VerifyLog bail out early.
func TestVerifyLog_WrongKeyWithTornTrailingLine(t *testing.T) {
	logPath, checkpointPath, _ := makeVerifyFixture(t)
	_, wrongPub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}

	lf, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open log for append: %v", err)
	}
	_, _ = lf.WriteString(`{"record":{"trace_id":"broken"` + "\n")
	_ = lf.Close()

	report, err := verify.VerifyLog(logPath, checkpointPath, wrongPub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	var sawChain, sawTornTail bool
	for _, e := range report.Errors {
		switch e.Kind {
		case "chain":
			sawChain = true
			if e.Severity != verify.SeverityFatal {
				t.Errorf("chain error Severity = %q, want %q", e.Severity, verify.SeverityFatal)
			}
		case verify.KindTornTrailingLine:
			sawTornTail = true
			if e.Severity != verify.SeverityAdvisory {
				t.Errorf("torn_trailing_line Severity = %q, want %q", e.Severity, verify.SeverityAdvisory)
			}
		}
	}
	if !sawChain {
		t.Errorf("expected a chain signature-failure error; got: %v", report.Errors)
	}
	if !sawTornTail {
		t.Errorf("expected torn_trailing_line error alongside the wrong-key errors; got: %v", report.Errors)
	}
}

// TestVerifyLog_TamperedEntryKeyIDDoesNotBlockVerification pins issue #46's
// first scenario. key_id sits beside the signature, not inside what gets
// signed, so editing one entry's key_id to a bogus value must not deny
// verification of an otherwise-intact, single-signer log. Before the fix,
// this tripped the pre-scan's "more than one distinct key_id" multi-epoch
// guard and returned a bare Go error instead of a Report — a log that was
// entirely intact failed outright over one unsigned byte.
func TestVerifyLog_TamperedEntryKeyIDDoesNotBlockVerification(t *testing.T) {
	logPath, checkpointPath, pub := makeVerifyFixture(t)

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var entry chain.LogEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}
	realKeyID := entry.Signed.KeyID
	entry.Signed.KeyID = "bogus-tampered-key-id"
	tampered, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal tampered entry: %v", err)
	}
	if err := os.WriteFile(logPath, append(tampered, '\n'), 0600); err != nil {
		t.Fatalf("write tampered log: %v", err)
	}

	report, err := verify.VerifyLog(logPath, checkpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog returned a bare error instead of a Report: %v", err)
	}
	if report.TracesProcessed != 1 {
		t.Errorf("TracesProcessed = %d, want 1", report.TracesProcessed)
	}
	if report.CheckpointsProcessed != 1 {
		t.Errorf("CheckpointsProcessed = %d, want 1", report.CheckpointsProcessed)
	}
	if len(report.Errors) != 1 {
		t.Fatalf("expected exactly 1 error (key_id_field_mismatch); got %v", report.Errors)
	}
	e := report.Errors[0]
	if e.Kind != "key_id_field_mismatch" {
		t.Errorf("expected kind=key_id_field_mismatch, got kind=%s detail=%s", e.Kind, e.Detail)
	}
	if e.Severity != verify.SeverityAdvisory {
		t.Errorf("expected Severity=%s (the signature already proved the content authentic), got %s", verify.SeverityAdvisory, e.Severity)
	}
	if !strings.Contains(e.Detail, "bogus-tampered-key-id") || !strings.Contains(e.Detail, realKeyID) {
		t.Errorf("expected detail to name both the claimed and verified key_id, got: %s", e.Detail)
	}
}

// TestVerifyLog_TamperedCheckpointKeyIDFailsSignature pins a security
// property distinct from the entry-side case above: a checkpoint's key_id is
// one of the fields chain.CheckpointSigningPayload marshals into the signed
// bytes (see chain.Accumulator.Stage), so — unlike an entry's key_id —
// editing it alone invalidates the checkpoint's signature. This must produce
// an ordinary "checkpoint" signature-failure error, never
// "key_id_field_mismatch": that finding only exists for entries, because only
// an entry's key_id sits outside what gets signed.
func TestVerifyLog_TamperedCheckpointKeyIDFailsSignature(t *testing.T) {
	logPath, checkpointPath, pub := makeVerifyFixture(t)

	data, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	var cp chain.Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		t.Fatalf("unmarshal checkpoint: %v", err)
	}
	cp.KeyID = "bogus-tampered-key-id"
	tampered, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("marshal tampered checkpoint: %v", err)
	}
	if err := os.WriteFile(checkpointPath, append(tampered, '\n'), 0600); err != nil {
		t.Fatalf("write tampered checkpoint: %v", err)
	}

	report, err := verify.VerifyLog(logPath, checkpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) != 1 {
		t.Fatalf("expected exactly 1 error; got %v", report.Errors)
	}
	e := report.Errors[0]
	if e.Kind != "checkpoint" {
		t.Errorf("expected kind=checkpoint (key_id is signed, so tampering it fails signature verification), got kind=%s detail=%s", e.Kind, e.Detail)
	}
	if e.Severity != verify.SeverityFatal {
		t.Errorf("expected Severity=%s, got %s", verify.SeverityFatal, e.Severity)
	}
	if !strings.Contains(e.Detail, "signature verification failed") {
		t.Errorf("expected a signature-verification-failed detail, got: %s", e.Detail)
	}
}

// TestVerifyLog_UnifiedFakeKeyIDDoesNotMaskDifferentSigner pins issue #46's
// second scenario. Forcing every entry's key_id to the same (possibly fake)
// value must not collapse a log that genuinely has entries signed by
// different keys into one misleading diagnosis. Each entry is still judged
// strictly by its own signature: the one actually signed by the supplied key
// verifies (with a key_id_field_mismatch flagging its now-wrong metadata),
// and the one signed by a different key still produces a genuine chain
// error — not a blanket "key_id_mismatch" wall that would have hidden which
// trace is the real problem and obscured that this log needs the
// per-epoch procedure at all.
func TestVerifyLog_UnifiedFakeKeyIDDoesNotMaskDifferentSigner(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	checkpointPath := filepath.Join(dir, "checkpoint.jsonl")

	priv1, pub1, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key 1: %v", err)
	}
	signer1 := sign.NewEd25519Signer(priv1)

	priv2, _, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key 2: %v", err)
	}
	signer2 := sign.NewEd25519Signer(priv2)

	makeEntry := func(signer sign.Signer, traceID, spanID string, seq int) chain.LogEntry {
		rec := record.AuditRecord{
			SchemaVersion: record.SchemaVersion,
			TraceID:       traceID,
			SpanID:        spanID,
			SeqInTrace:    seq,
			SpanName:      "span",
			OtelKind:      "Internal",
			AuditKind:     record.AuditKindTask,
			Status:        "Ok",
		}
		seed, _ := chain.GenesisSeed(traceID)
		entries, _ := chain.BuildChain([]record.AuditRecord{rec}, seed, signer)
		return chain.ToLogEntries(entries)[0]
	}

	traceID1 := "01010101010101010101010101010101"
	traceID2 := "02020202020202020202020202020202"
	e1 := makeEntry(signer1, traceID1, "0102030405060708", 0)
	e2 := makeEntry(signer2, traceID2, "0807060504030201", 0)

	// Force both entries to claim the same fake key_id, disguising the fact
	// that they were really signed by two different keys.
	e1.Signed.KeyID = "shared-fake-key-id"
	e2.Signed.KeyID = "shared-fake-key-id"

	lf, _ := os.Create(logPath)
	for _, e := range []chain.LogEntry{e1, e2} {
		line, _ := json.Marshal(e)
		_, _ = lf.Write(append(line, '\n'))
	}
	_ = lf.Close()
	if f, err := os.Create(checkpointPath); err == nil {
		_ = f.Close()
	}

	report, err := verify.VerifyLog(logPath, checkpointPath, pub1)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if report.TracesProcessed != 2 {
		t.Errorf("TracesProcessed = %d, want 2", report.TracesProcessed)
	}
	if len(report.Errors) != 2 {
		t.Fatalf("expected exactly 2 errors; got %v", report.Errors)
	}
	var sawFieldMismatch, sawChain bool
	for _, e := range report.Errors {
		switch {
		case e.TraceID == traceID1 && e.Kind == "key_id_field_mismatch":
			sawFieldMismatch = true
			if e.Severity != verify.SeverityAdvisory {
				t.Errorf("key_id_field_mismatch Severity = %q, want %q", e.Severity, verify.SeverityAdvisory)
			}
		case e.TraceID == traceID2 && e.Kind == "chain":
			sawChain = true
			if !strings.Contains(e.Detail, "signature verification failed") {
				t.Errorf("expected a signature-verification-failed detail for %s, got: %s", traceID2, e.Detail)
			}
			if e.Severity != verify.SeverityFatal {
				t.Errorf("chain error Severity = %q, want %q", e.Severity, verify.SeverityFatal)
			}
		default:
			t.Errorf("unexpected error: %+v", e)
		}
	}
	if !sawFieldMismatch {
		t.Errorf("expected key_id_field_mismatch for %s (verifies, but claims the wrong key_id); got %v", traceID1, report.Errors)
	}
	if !sawChain {
		t.Errorf("expected a real chain error for %s (signed by a different key); got %v", traceID2, report.Errors)
	}
}

// keyIDOf recomputes a public key's key_id from the documented scheme,
// hex(SHA256(publicKeyBytes)) (docs/audit-record-schema.md §7), independently
// of the verifier's own helper, so a test can name the exact value it expects.
func keyIDOf(pub []byte) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// makeClaimedEntry builds a single-entry trace signed by signer whose entry
// then claims claimedKeyID instead of its real key_id. The field sits outside
// what gets signed, so the result is still a well-formed log line.
func makeClaimedEntry(t *testing.T, signer sign.Signer, traceID, claimedKeyID string) chain.LogEntry {
	t.Helper()
	rec := record.AuditRecord{
		SchemaVersion: record.SchemaVersion,
		TraceID:       traceID,
		SpanID:        "0102030405060708",
		ParentSpanID:  "0000000000000000",
		SeqInTrace:    0,
		SpanName:      "span",
		OtelKind:      "Internal",
		AuditKind:     record.AuditKindTask,
		Status:        "Ok",
	}
	seed, err := chain.GenesisSeed(traceID)
	if err != nil {
		t.Fatalf("GenesisSeed(%s): %v", traceID, err)
	}
	entries, err := chain.BuildChain([]record.AuditRecord{rec}, seed, signer)
	if err != nil {
		t.Fatalf("BuildChain(%s): %v", traceID, err)
	}
	e := chain.ToLogEntries(entries)[0]
	e.Signed.KeyID = claimedKeyID
	return e
}

// setFixtureEntryKeyID rewrites the one entry in makeVerifyFixture's log to
// claim keyID, leaving the rest of the line (signature included) untouched.
func setFixtureEntryKeyID(t *testing.T, logPath, keyID string) {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var entry chain.LogEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}
	entry.Signed.KeyID = keyID
	out, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal log entry: %v", err)
	}
	if err := os.WriteFile(logPath, append(out, '\n'), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
}

// TestVerifyLog_OtherClaimedKeyIDs_EmptyWhenEveryClaimMatches: a single-key log
// verified against its own key has nothing to hint at. The field stays empty
// and, being omitempty, is absent from JSON altogether — so the report for the
// common case has the same shape it had before issue #50.
func TestVerifyLog_OtherClaimedKeyIDs_EmptyWhenEveryClaimMatches(t *testing.T) {
	logPath, checkpointPath, pub := makeVerifyFixture(t)

	report, err := verify.VerifyLog(logPath, checkpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Fatalf("fixture should verify cleanly; got %v", report.Errors)
	}
	if len(report.OtherClaimedKeyIDs) != 0 {
		t.Errorf("OtherClaimedKeyIDs = %v, want empty", report.OtherClaimedKeyIDs)
	}
	out, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if strings.Contains(string(out), "OtherClaimedKeyIDs") {
		t.Errorf("an empty OtherClaimedKeyIDs must be omitted from JSON; got %s", out)
	}
}

// TestVerifyLog_OtherClaimedKeyIDs_WrongKey: the hint is not specific to
// rotation. Against the wrong key every signature fails (see
// TestVerifyLog_WrongKey) and nothing else in the report says why; the log's
// real key_id is exactly what the operator is missing. The hint must not soften
// that verdict.
func TestVerifyLog_OtherClaimedKeyIDs_WrongKey(t *testing.T) {
	logPath, checkpointPath, pub := makeVerifyFixture(t)
	_, wrongPub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}

	report, err := verify.VerifyLog(logPath, checkpointPath, wrongPub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if want := []string{keyIDOf(pub)}; !slices.Equal(report.OtherClaimedKeyIDs, want) {
		t.Errorf("OtherClaimedKeyIDs = %v, want %v (the log's real key_id)", report.OtherClaimedKeyIDs, want)
	}
	if report.FatalCount() == 0 {
		t.Errorf("wrong-key verification must still fail; got %+v", report.Errors)
	}
}

// TestVerifyLog_OtherClaimedKeyIDs_EditedEntryKeyIDIsOnlyAHint: an entry's
// key_id is unauthenticated, so editing it alone is enough to make the field
// non-empty. That is why the field is a hint and must never move the verdict:
// the entry still verifies and the report stays Status: OK, carrying only the
// advisory key_id_field_mismatch it already carried before issue #50.
func TestVerifyLog_OtherClaimedKeyIDs_EditedEntryKeyIDIsOnlyAHint(t *testing.T) {
	logPath, checkpointPath, pub := makeVerifyFixture(t)
	setFixtureEntryKeyID(t, logPath, "bogus-tampered-key-id")

	report, err := verify.VerifyLog(logPath, checkpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if want := []string{"bogus-tampered-key-id"}; !slices.Equal(report.OtherClaimedKeyIDs, want) {
		t.Errorf("OtherClaimedKeyIDs = %v, want %v", report.OtherClaimedKeyIDs, want)
	}
	if len(report.Errors) != 1 || report.Errors[0].Kind != "key_id_field_mismatch" {
		t.Errorf("expected exactly the advisory key_id_field_mismatch; got %+v", report.Errors)
	}
	if n := report.FatalCount(); n != 0 {
		t.Errorf("FatalCount = %d, want 0: an edited key_id field must not fail verification", n)
	}
	if got := report.StatusLine(); !strings.HasPrefix(got, "Status: OK") {
		t.Errorf("StatusLine = %q, want it to stay Status: OK", got)
	}
}

// TestVerifyLog_OtherClaimedKeyIDs_IgnoresEmptyKeyIDs: an empty key_id is "no
// claim" (a log written before the field existed), not a claim of the empty
// string, on the entry side and the checkpoint side alike.
func TestVerifyLog_OtherClaimedKeyIDs_IgnoresEmptyKeyIDs(t *testing.T) {
	t.Run("entry", func(t *testing.T) {
		logPath, checkpointPath, pub := makeVerifyFixture(t)
		setFixtureEntryKeyID(t, logPath, "")

		report, err := verify.VerifyLog(logPath, checkpointPath, pub)
		if err != nil {
			t.Fatalf("VerifyLog: %v", err)
		}
		if len(report.OtherClaimedKeyIDs) != 0 {
			t.Errorf("OtherClaimedKeyIDs = %q, want empty", report.OtherClaimedKeyIDs)
		}
		if len(report.Errors) != 0 {
			t.Errorf("a blank entry key_id should verify cleanly; got %v", report.Errors)
		}
	})

	t.Run("checkpoint", func(t *testing.T) {
		logPath, checkpointPath, pub := makeVerifyFixture(t)
		data, err := os.ReadFile(checkpointPath)
		if err != nil {
			t.Fatalf("read checkpoint: %v", err)
		}
		var cp chain.Checkpoint
		if err := json.Unmarshal(data, &cp); err != nil {
			t.Fatalf("unmarshal checkpoint: %v", err)
		}
		cp.KeyID = ""
		writeCheckpoints(t, checkpointPath, cp)

		report, err := verify.VerifyLog(logPath, checkpointPath, pub)
		if err != nil {
			t.Fatalf("VerifyLog: %v", err)
		}
		if len(report.OtherClaimedKeyIDs) != 0 {
			t.Errorf("OtherClaimedKeyIDs = %q, want empty", report.OtherClaimedKeyIDs)
		}
		// key_id is signed on a checkpoint, so blanking it fails the signature —
		// pinning that the scenario is what this subtest thinks it is.
		if len(report.Errors) != 1 || report.Errors[0].Kind != "checkpoint" {
			t.Errorf("expected exactly one checkpoint signature failure; got %+v", report.Errors)
		}
	})
}

// TestVerifyLog_OtherClaimedKeyIDs_SortedDeduplicatedAndExcludesSuppliedKey pins
// the field's shape across both sources at once. Claims are deliberately out of
// order and repeated — "eeee" by two entries, "bbbb" by an entry and by a
// checkpoint — and one entry claims the supplied key itself, which is never
// "other". The checkpoints contribute "ffff", "dddd", "cccc" in that
// descending order. The field is built from a map, and Go leaves map iteration
// order unspecified; on the runtime this was written against it only rotates
// the insertion order, and no rotation of a sequence containing those descents
// is ascending, so an implementation that forgot to sort fails on every run
// rather than passing by chance.
func TestVerifyLog_OtherClaimedKeyIDs_SortedDeduplicatedAndExcludesSuppliedKey(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	checkpointPath := filepath.Join(dir, "checkpoint.jsonl")

	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	signer := sign.NewEd25519Signer(priv)

	writeLogEntries(t, logPath, []chain.LogEntry{
		makeClaimedEntry(t, signer, "01010101010101010101010101010101", "eeee"),
		makeClaimedEntry(t, signer, "02020202020202020202020202020202", "bbbb"),
		makeClaimedEntry(t, signer, "03030303030303030303030303030303", "eeee"),
		makeClaimedEntry(t, signer, "04040404040404040404040404040404", keyIDOf(pub)),
		makeClaimedEntry(t, signer, "05050505050505050505050505050505", "aaaa"),
	})

	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)
	acc.AddTip("01010101010101010101010101010101", strings.Repeat("0", 64), 1)
	cp, err := acc.Build(time.Unix(1757000000, 0).UTC())
	if err != nil {
		t.Fatalf("build checkpoint: %v", err)
	}
	var cps []chain.Checkpoint
	for _, claimed := range []string{"ffff", "bbbb", "dddd", "cccc"} {
		c := cp
		c.KeyID = claimed
		cps = append(cps, c)
	}
	writeCheckpoints(t, checkpointPath, cps...)

	report, err := verify.VerifyLog(logPath, checkpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	want := []string{"aaaa", "bbbb", "cccc", "dddd", "eeee", "ffff"}
	if !slices.Equal(report.OtherClaimedKeyIDs, want) {
		t.Errorf("OtherClaimedKeyIDs = %q, want %q (sorted, de-duplicated, without the supplied key %s)",
			report.OtherClaimedKeyIDs, want, keyIDOf(pub))
	}
}

// TestReport_OtherClaimedKeyIDsJSONFieldName pins the wire name that the docs
// and -json consumers rely on: a non-empty list marshals under exactly
// "OtherClaimedKeyIDs", as a plain array.
func TestReport_OtherClaimedKeyIDsJSONFieldName(t *testing.T) {
	out, err := json.Marshal(verify.Report{
		TracesProcessed:      1,
		CheckpointsProcessed: 1,
		OtherClaimedKeyIDs:   []string{"aa", "bb"},
	})
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(out, &fields); err != nil {
		t.Fatalf("unmarshal report JSON: %v", err)
	}
	if got := string(fields["OtherClaimedKeyIDs"]); got != `["aa","bb"]` {
		t.Errorf(`JSON key "OtherClaimedKeyIDs" = %q, want ["aa","bb"]; full output: %s`, got, out)
	}
}

// TestVerifyLog_OtherClaimedKeyIDs_ReadsEveryEntryOfATrace: claims are read
// from every entry, not only a trace's first or last. Here just the middle
// entry of a three-entry trace claims a foreign key_id; the trace itself still
// verifies, so the report stays free of fatal findings.
func TestVerifyLog_OtherClaimedKeyIDs_ReadsEveryEntryOfATrace(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	checkpointPath := filepath.Join(dir, "checkpoint.jsonl") // never created: a missing file reads as empty

	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	const traceID = "01010101010101010101010101010101"
	var recs []record.AuditRecord
	for seq, spanID := range []string{"0000000000000001", "0000000000000002", "0000000000000003"} {
		recs = append(recs, record.AuditRecord{
			SchemaVersion: record.SchemaVersion,
			TraceID:       traceID,
			SpanID:        spanID,
			ParentSpanID:  "0000000000000000",
			SeqInTrace:    seq,
			SpanName:      "span",
			OtelKind:      "Internal",
			AuditKind:     record.AuditKindTask,
			Status:        "Ok",
		})
	}
	seed, err := chain.GenesisSeed(traceID)
	if err != nil {
		t.Fatalf("GenesisSeed: %v", err)
	}
	built, err := chain.BuildChain(recs, seed, sign.NewEd25519Signer(priv))
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}
	entries := chain.ToLogEntries(built)
	entries[1].Signed.KeyID = "middle-claim"
	writeLogEntries(t, logPath, entries)

	report, err := verify.VerifyLog(logPath, checkpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if want := []string{"middle-claim"}; !slices.Equal(report.OtherClaimedKeyIDs, want) {
		t.Errorf("OtherClaimedKeyIDs = %q, want %q", report.OtherClaimedKeyIDs, want)
	}
	if n := report.FatalCount(); n != 0 {
		t.Errorf("FatalCount = %d, want 0 (the trace verifies; only its metadata disagrees): %+v", n, report.Errors)
	}
}

// TestVerifyLog_OtherClaimedKeyIDs_ReadsClaimsFromDuplicateSegments pins design
// choice "claims are taken as-is": the field reports what the log claims, not
// what verified, so a claim inside a trace whose chain verification is skipped
// (duplicate_trace_segment) is still listed.
func TestVerifyLog_OtherClaimedKeyIDs_ReadsClaimsFromDuplicateSegments(t *testing.T) {
	logPath, checkpointPath, pub := makeVerifyFixture(t)
	setFixtureEntryKeyID(t, logPath, "dup-claim")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	line := strings.TrimRight(string(data), "\n")
	if err := os.WriteFile(logPath, []byte(line+"\n"+line+"\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	report, err := verify.VerifyLog(logPath, checkpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	var sawDuplicate bool
	for _, e := range report.Errors {
		if e.Kind == "duplicate_trace_segment" {
			sawDuplicate = true
		}
	}
	if !sawDuplicate {
		t.Fatalf("fixture is wrong: expected a duplicate_trace_segment error; got %+v", report.Errors)
	}
	if want := []string{"dup-claim"}; !slices.Equal(report.OtherClaimedKeyIDs, want) {
		t.Errorf("OtherClaimedKeyIDs = %q, want %q", report.OtherClaimedKeyIDs, want)
	}
}

// TestVerifyLog_OtherClaimedKeyIDs_IgnoresATornTrailingLine: a torn final line
// is unparsed evidence, not an entry, so whatever key_id text it happens to
// contain is not a claim. Only what the parser actually read counts — for the
// audit log (reported as torn_trailing_line) and for the checkpoint file
// (silently dropped) alike.
func TestVerifyLog_OtherClaimedKeyIDs_IgnoresATornTrailingLine(t *testing.T) {
	appendTornLine := func(t *testing.T, path, torn string) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatalf("open %s for append: %v", path, err)
		}
		_, _ = f.WriteString(torn + "\n")
		_ = f.Close()
	}

	t.Run("audit log", func(t *testing.T) {
		logPath, checkpointPath, pub := makeVerifyFixture(t)
		appendTornLine(t, logPath, `{"record":{"trace_id":"broken"},"signed":{"key_id":"torn-log-claim"`)

		report, err := verify.VerifyLog(logPath, checkpointPath, pub)
		if err != nil {
			t.Fatalf("VerifyLog: %v", err)
		}
		var sawTornTail bool
		for _, e := range report.Errors {
			if e.Kind == verify.KindTornTrailingLine {
				sawTornTail = true
			}
		}
		if !sawTornTail {
			t.Fatalf("fixture is wrong: expected a torn_trailing_line finding; got %+v", report.Errors)
		}
		if len(report.OtherClaimedKeyIDs) != 0 {
			t.Errorf("OtherClaimedKeyIDs = %q, want empty: a torn line is not a claim", report.OtherClaimedKeyIDs)
		}
	})

	t.Run("checkpoint file", func(t *testing.T) {
		logPath, checkpointPath, pub := makeVerifyFixture(t)
		appendTornLine(t, checkpointPath, `{"key_id":"torn-checkpoint-claim"`)

		report, err := verify.VerifyLog(logPath, checkpointPath, pub)
		if err != nil {
			t.Fatalf("VerifyLog: %v", err)
		}
		if report.CheckpointsProcessed != 1 {
			t.Fatalf("fixture is wrong: CheckpointsProcessed = %d, want 1 (the torn line must have been dropped)", report.CheckpointsProcessed)
		}
		if len(report.OtherClaimedKeyIDs) != 0 {
			t.Errorf("OtherClaimedKeyIDs = %q, want empty: a torn line is not a claim", report.OtherClaimedKeyIDs)
		}
	})
}

// TestVerifyLog_HappyPath_V3Log is the current-format counterpart of the legacy
// test below: a log written at record.SchemaVersion must carry decimal-string
// timestamps on disk — the whole point of v3 — and verify cleanly.
func TestVerifyLog_HappyPath_V3Log(t *testing.T) {
	priv, pubKey, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	signer := sign.NewEd25519Signer(priv)

	recs := []record.AuditRecord{
		{
			SchemaVersion:     record.SchemaVersion,
			TraceID:           fixtureTraceID,
			SpanID:            "0102030405060708",
			ParentSpanID:      "0000000000000000",
			SeqInTrace:        0,
			StartTimeUnixNano: 1764547200123456789,
			EndTimeUnixNano:   1764547200987654321,
			SpanName:          "v3-root",
			OtelKind:          "Internal",
			AuditKind:         record.AuditKindTask,
			Status:            "Ok",
		},
	}

	genesisSeed, err := chain.GenesisSeed(fixtureTraceID)
	if err != nil {
		t.Fatalf("GenesisSeed: %v", err)
	}
	entries, err := chain.BuildChain(recs, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	checkpointPath := filepath.Join(dir, "checkpoint.jsonl")

	lf, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	for _, e := range chain.ToLogEntries(entries) {
		line, _ := json.Marshal(e)
		_, _ = lf.Write(append(line, '\n'))
	}
	_ = lf.Close()

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(raw), `"start_time_unix_nano":"1764547200123456789"`) {
		t.Errorf("v3 log does not carry a decimal-string start timestamp: %s", raw)
	}
	if !strings.Contains(string(raw), `"end_time_unix_nano":"1764547200987654321"`) {
		t.Errorf("v3 log does not carry a decimal-string end timestamp: %s", raw)
	}

	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)
	acc.AddTip(fixtureTraceID, chain.TipHash(entries), len(entries))
	cp, err := acc.Build(time.Now())
	if err != nil {
		t.Fatalf("Build checkpoint: %v", err)
	}
	cf, err := os.Create(checkpointPath)
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}
	cpLine, _ := json.Marshal(cp)
	_, _ = cf.Write(append(cpLine, '\n'))
	_ = cf.Close()

	report, err := verify.VerifyLog(logPath, checkpointPath, []byte(pubKey))
	if err != nil {
		t.Fatalf("VerifyLog v3 log: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("expected zero errors for a valid v3 log, got %d: %v", len(report.Errors), report.Errors)
	}
}

// TestVerifyLog_HappyPath_LegacySchemaLog is an integration test for the
// version-aware genesis-seed path: for each legacy schema version it builds a
// log on disk (records pinned to that version, chain built with
// GenesisSeedForSchema(traceID, version)), then calls VerifyLog and asserts
// zero errors. This ensures the verifier reads SchemaVersion from
// entries[0].Record.SchemaVersion rather than always using record.SchemaVersion.
//
// Since v3 the version also selects the timestamp encoding, so this doubles as
// the end-to-end check that a current binary re-derives the numeric-timestamp
// canonical bytes of a legacy log rather than its own decimal-string form.
// The timestamps here exceed 2^53 deliberately: legacy logs really do contain
// such values, and they must keep verifying byte-for-byte.
//
// Note: the checkpoint is built with chain.NewAccumulator, which stamps the
// current record.SchemaVersion on the checkpoint's schema_version field. This
// is an intentional simplification — the verifier does not enforce that log and
// checkpoint schema_version values agree, so the mismatch is harmless here.
func TestVerifyLog_HappyPath_LegacySchemaLog(t *testing.T) {
	for _, schemaVersion := range []string{"v1", "v2"} {
		t.Run(schemaVersion, func(t *testing.T) {
			priv, pubKey, err := sign.GenerateEd25519Key()
			if err != nil {
				t.Fatalf("GenerateEd25519Key: %v", err)
			}
			signer := sign.NewEd25519Signer(priv)

			recs := []record.AuditRecord{
				{
					SchemaVersion:     schemaVersion,
					TraceID:           fixtureTraceID,
					SpanID:            "0102030405060708",
					ParentSpanID:      "0000000000000000",
					SeqInTrace:        0,
					StartTimeUnixNano: 1764547200123456789,
					EndTimeUnixNano:   1764547200987654321,
					SpanName:          schemaVersion + "-root",
					OtelKind:          "Internal",
					AuditKind:         record.AuditKindTask,
					Status:            "Ok",
				},
			}

			genesisSeed, err := chain.GenesisSeedForSchema(fixtureTraceID, schemaVersion)
			if err != nil {
				t.Fatalf("GenesisSeedForSchema %s: %v", schemaVersion, err)
			}
			entries, err := chain.BuildChain(recs, genesisSeed, signer)
			if err != nil {
				t.Fatalf("BuildChain: %v", err)
			}

			dir := t.TempDir()
			logPath := filepath.Join(dir, "audit.jsonl")
			checkpointPath := filepath.Join(dir, "checkpoint.jsonl")

			lf, err := os.Create(logPath)
			if err != nil {
				t.Fatalf("create log: %v", err)
			}
			for _, e := range chain.ToLogEntries(entries) {
				line, _ := json.Marshal(e)
				_, _ = lf.Write(append(line, '\n'))
			}
			_ = lf.Close()

			// The log on disk must carry the legacy numeric encoding.
			raw, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("read log: %v", err)
			}
			if !strings.Contains(string(raw), `"start_time_unix_nano":1764547200123456789`) {
				t.Errorf("%s log is not numerically encoded: %s", schemaVersion, raw)
			}

			acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)
			acc.AddTip(fixtureTraceID, chain.TipHash(entries), len(entries))
			cp, err := acc.Build(time.Now())
			if err != nil {
				t.Fatalf("Build checkpoint: %v", err)
			}
			cf, err := os.Create(checkpointPath)
			if err != nil {
				t.Fatalf("create checkpoint: %v", err)
			}
			cpLine, _ := json.Marshal(cp)
			_, _ = cf.Write(append(cpLine, '\n'))
			_ = cf.Close()

			report, err := verify.VerifyLog(logPath, checkpointPath, []byte(pubKey))
			if err != nil {
				t.Fatalf("VerifyLog %s log: %v", schemaVersion, err)
			}
			if len(report.Errors) != 0 {
				t.Errorf("expected zero errors for a valid %s log, got %d: %v",
					schemaVersion, len(report.Errors), report.Errors)
			}
		})
	}
}

// TestVerifyChain_RejectsMixedSchemaVersions pins the invariant the exporter
// upholds by construction: one chain, one schema version. The seed comes from
// entries[0] and every entry is re-marshaled in the shape of its own
// schema_version, so before this check a mixed chain reproduced every hash and
// verified cleanly — leaving the documented MUST enforced by nothing a verifier
// could attest to.
func TestVerifyChain_RejectsMixedSchemaVersions(t *testing.T) {
	priv, pubKey, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	signer := sign.NewEd25519Signer(priv)

	mk := func(schemaVersion, spanID string, seq int, startNano record.UnixNano) record.AuditRecord {
		return record.AuditRecord{
			SchemaVersion:     schemaVersion,
			TraceID:           fixtureTraceID,
			SpanID:            spanID,
			ParentSpanID:      "",
			SeqInTrace:        seq,
			StartTimeUnixNano: startNano,
			EndTimeUnixNano:   startNano + 1000,
			SpanName:          "mixed",
			OtelKind:          "Internal",
			AuditKind:         record.AuditKindTask,
			Status:            "Ok",
		}
	}

	// Build a genuinely well-formed chain whose second entry disagrees on
	// schema_version — every hash and signature in it is correct.
	recs := []record.AuditRecord{
		mk(record.SchemaVersion, "aaaaaaaaaaaaaaaa", 0, 1764547200123456789),
		mk("v2", "bbbbbbbbbbbbbbbb", 1, 1764547200987654321),
	}
	genesisSeed, err := chain.GenesisSeedForSchema(fixtureTraceID, recs[0].SchemaVersion)
	if err != nil {
		t.Fatalf("GenesisSeedForSchema: %v", err)
	}
	entries, err := chain.BuildChain(recs, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	err = verify.VerifyChain(chain.ToLogEntries(entries), pubKey)
	if err == nil {
		t.Fatal("a chain mixing schema versions verified; it must be rejected")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error should name the mismatched field, got: %v", err)
	}

	// The same chain, single-version, must still verify — the check must reject
	// mixing, not chains in general.
	recs[1].SchemaVersion = record.SchemaVersion
	entries, err = chain.BuildChain(recs, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}
	if err := verify.VerifyChain(chain.ToLogEntries(entries), pubKey); err != nil {
		t.Errorf("single-version chain must still verify: %v", err)
	}
}

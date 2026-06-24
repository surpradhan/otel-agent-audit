package verify_test

import (
	"encoding/json"
	"os"
	"path/filepath"
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
		}
		if e.Kind == "tip_hash_unverifiable" {
			hasTipUnverifiable = true
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
		}
		if e.Kind == "tip_hash_unverifiable" {
			hasTipUnverifiable = true
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

// TestVerifyLog_WrongKey_KeyIDMismatch asserts that supplying the wrong public
// key produces "key_id_mismatch" errors (not misleading "chain" errors).
// A key_id mismatch is detected before signature verification, so the error
// kind unambiguously tells the operator to check which key epoch they need.
func TestVerifyLog_WrongKey_KeyIDMismatch(t *testing.T) {
	logPath, checkpointPath, _ := makeVerifyFixture(t)
	_, wrongPub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	report, err := verify.VerifyLog(logPath, checkpointPath, wrongPub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) == 0 {
		t.Fatal("expected errors when verifying with wrong key; got none")
	}
	for _, e := range report.Errors {
		if e.Kind != "key_id_mismatch" {
			t.Errorf("expected kind=key_id_mismatch, got kind=%s detail=%s", e.Kind, e.Detail)
		}
	}
}

// TestVerifyLog_MultiEpochLog verifies that a log containing entries signed by
// two different keys returns an error (not a report with per-trace errors).
// The operator must re-run per epoch with the matching key.
func TestVerifyLog_MultiEpochLog(t *testing.T) {
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

	_, err = verify.VerifyLog(logPath, checkpointPath, pub2)
	if err == nil {
		t.Fatal("expected an error for multi-epoch log; got nil")
	}
	if !strings.Contains(err.Error(), "multi-epoch log") {
		t.Errorf("expected 'multi-epoch log' in error, got: %v", err)
	}
}

// TestVerifyLog_DuplicateTraceSegment verifies that a log with two entries
// sharing the same (trace_id, seq_in_trace) produces a "duplicate_trace_segment"
// error rather than a confusing chain error.
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
		}
		if e.Kind == "chain" {
			t.Errorf("got misleading chain error for duplicate segment: %v", e)
		}
	}
	if !found {
		t.Errorf("expected duplicate_trace_segment error; got: %v", report.Errors)
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

// TestVerifyLog_HappyPath_V1Log is an integration test for the version-aware
// genesis-seed path: it builds a v1 log on disk (records with SchemaVersion "v1",
// chain built with GenesisSeedForSchema(traceID, "v1")), then calls VerifyLog and
// asserts zero errors. This ensures the verifier correctly reads SchemaVersion from
// entries[0].Record.SchemaVersion rather than always using record.SchemaVersion.
//
// Note: the checkpoint is built with chain.NewAccumulator which uses the current
// record.SchemaVersion ("v2") for the checkpoint's schema_version field. This is an
// intentional simplification — the verifier does not enforce that log and checkpoint
// schema_version values agree, so the v1/v2 mismatch is harmless in this test.
func TestVerifyLog_HappyPath_V1Log(t *testing.T) {
	priv, pubKey, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	signer := sign.NewEd25519Signer(priv)

	recs := []record.AuditRecord{
		{
			SchemaVersion: "v1",
			TraceID:       fixtureTraceID,
			SpanID:        "0102030405060708",
			ParentSpanID:  "0000000000000000",
			SeqInTrace:    0,
			SpanName:      "v1-root",
			OtelKind:      "Internal",
			AuditKind:     record.AuditKindTask,
			Status:        "Ok",
		},
	}

	genesisSeed, err := chain.GenesisSeedForSchema(fixtureTraceID, "v1")
	if err != nil {
		t.Fatalf("GenesisSeedForSchema v1: %v", err)
	}
	entries, err := chain.BuildChain(recs, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	dir := t.TempDir()
	logPath := filepath.Join(dir, "v1audit.jsonl")
	checkpointPath := filepath.Join(dir, "v1checkpoint.jsonl")

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

	report, err := verify.VerifyLog(logPath, checkpointPath, []byte(pubKey))
	if err != nil {
		t.Fatalf("VerifyLog v1 log: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("expected zero errors for valid v1 log, got %d: %v", len(report.Errors), report.Errors)
	}
}

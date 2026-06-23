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

func TestVerifyChain_Empty(t *testing.T) {
	_, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	if err := verify.VerifyChain(nil, pub); err != nil {
		t.Errorf("VerifyChain(nil): %v", err)
	}
}

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
	if len(report.Errors) == 0 {
		t.Error("expected errors when verifying with wrong key; got none")
	}
}

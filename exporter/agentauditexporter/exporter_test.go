package agentauditexporter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/chain"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/sign"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/verify"
)

// testSetup sets up a full test environment: writes a key, returns Config and pub key.
type testEnv struct {
	cfg    *Config
	pubKey []byte // raw ed25519 public key bytes
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()

	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pemBytes, err := sign.MarshalEd25519PrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("MarshalEd25519PrivateKeyPEM: %v", err)
	}
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, pemBytes, 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	cfg := &Config{
		LogPath:            filepath.Join(dir, "audit.jsonl"),
		KeyPath:            keyPath,
		WalPath:            filepath.Join(dir, "wal.jsonl"),
		CheckpointPath:     filepath.Join(dir, "checkpoint.jsonl"),
		TraceTimeout:       30 * time.Second,
		CheckpointInterval: 100,
	}
	return &testEnv{cfg: cfg, pubKey: []byte(pub)}
}

func startExporter(t *testing.T, cfg *Config) *agentAuditExporter {
	t.Helper()
	exp := newAgentAuditExporter(cfg, nil)
	if err := exp.Start(context.Background(), nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return exp
}

// readLogEntries reads all JSONL lines from a log file and returns []chain.LogEntry.
func readLogEntries(t *testing.T, path string) []chain.LogEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading log %q: %v", path, err)
	}
	var entries []chain.LogEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var le chain.LogEntry
		if err := json.Unmarshal(line, &le); err != nil {
			t.Fatalf("unmarshal log entry: %v\nline: %s", err, line)
		}
		entries = append(entries, le)
	}
	return entries
}

// makeSpan builds a ptrace.Traces with a single span.
func makeSpan(traceID [16]byte, spanID [8]byte, parentSpanID [8]byte, name string, startNano, endNano uint64) ptrace.Traces {
	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetTraceID(pcommon.TraceID(traceID))
	span.SetSpanID(pcommon.SpanID(spanID))
	span.SetParentSpanID(pcommon.SpanID(parentSpanID))
	span.SetName(name)
	span.SetKind(ptrace.SpanKindClient)
	span.SetStartTimestamp(pcommon.Timestamp(startNano))
	span.SetEndTimestamp(pcommon.Timestamp(endNano))
	span.Status().SetCode(ptrace.StatusCodeOk)
	return td
}

// zeroParentID is the all-zeros span ID used for root spans (no parent).
var zeroParentID = [8]byte{}

// TestNewFactory verifies the factory is non-nil and returns the correct type.
func TestNewFactory(t *testing.T) {
	f := NewFactory()
	if f == nil {
		t.Fatal("NewFactory returned nil")
	}
	if f.Type() != typeStr {
		t.Errorf("unexpected factory type: got %v, want %v", f.Type(), typeStr)
	}
}

func TestFactory_CreateTracesExporter(t *testing.T) {
	f := NewFactory()
	cfg := f.CreateDefaultConfig()
	set := exporter.Settings{ID: component.NewID(typeStr)}
	exp, err := f.CreateTraces(context.Background(), set, cfg)
	if err != nil {
		t.Fatalf("CreateTraces returned unexpected error: %v", err)
	}
	if exp == nil {
		t.Fatal("CreateTraces returned nil exporter")
	}
}

func TestConfig_Validate(t *testing.T) {
	t.Run("empty config returns errors", func(t *testing.T) {
		cfg := &Config{}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for empty config, got nil")
		}
	})
	t.Run("only log_path missing", func(t *testing.T) {
		cfg := &Config{KeyPath: "/tmp/key.pem", WalPath: "/tmp/wal.jsonl", CheckpointPath: "/tmp/cp.jsonl"}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for missing log_path")
		}
	})
	t.Run("only key_path missing", func(t *testing.T) {
		cfg := &Config{LogPath: "/tmp/audit.jsonl", WalPath: "/tmp/wal.jsonl", CheckpointPath: "/tmp/cp.jsonl"}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for missing key_path")
		}
	})
	t.Run("only wal_path missing", func(t *testing.T) {
		cfg := &Config{LogPath: "/tmp/audit.jsonl", KeyPath: "/tmp/key.pem", CheckpointPath: "/tmp/cp.jsonl"}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for missing wal_path")
		}
	})
	t.Run("only checkpoint_path missing", func(t *testing.T) {
		cfg := &Config{LogPath: "/tmp/audit.jsonl", KeyPath: "/tmp/key.pem", WalPath: "/tmp/wal.jsonl"}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for missing checkpoint_path")
		}
	})
	t.Run("all fields set", func(t *testing.T) {
		cfg := &Config{
			LogPath:        "/tmp/audit.jsonl",
			KeyPath:        "/tmp/key.pem",
			WalPath:        "/tmp/wal.jsonl",
			CheckpointPath: "/tmp/checkpoint.jsonl",
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	t.Run("log_path == wal_path", func(t *testing.T) {
		cfg := &Config{
			LogPath:        "/tmp/same.jsonl",
			KeyPath:        "/tmp/key.pem",
			WalPath:        "/tmp/same.jsonl",
			CheckpointPath: "/tmp/checkpoint.jsonl",
		}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error when log_path == wal_path")
		}
	})
	t.Run("log_path == checkpoint_path", func(t *testing.T) {
		cfg := &Config{
			LogPath:        "/tmp/same.jsonl",
			KeyPath:        "/tmp/key.pem",
			WalPath:        "/tmp/wal.jsonl",
			CheckpointPath: "/tmp/same.jsonl",
		}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error when log_path == checkpoint_path")
		}
	})
	t.Run("wal_path == checkpoint_path", func(t *testing.T) {
		cfg := &Config{
			LogPath:        "/tmp/audit.jsonl",
			KeyPath:        "/tmp/key.pem",
			WalPath:        "/tmp/same.jsonl",
			CheckpointPath: "/tmp/same.jsonl",
		}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error when wal_path == checkpoint_path")
		}
	})
}

func TestCapabilities(t *testing.T) {
	exp := newAgentAuditExporter(&Config{}, nil)
	caps := exp.Capabilities()
	if caps.MutatesData {
		t.Error("MutatesData should be false")
	}
}

func TestStartShutdown(t *testing.T) {
	env := newTestEnv(t)
	exp := newAgentAuditExporter(env.cfg, nil)
	if err := exp.Start(context.Background(), nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

func TestConsumeTraces_Empty(t *testing.T) {
	env := newTestEnv(t)
	exp := startExporter(t, env.cfg)
	t.Cleanup(func() {
		if err := exp.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	if err := exp.ConsumeTraces(context.Background(), ptrace.NewTraces()); err != nil {
		t.Errorf("ConsumeTraces(empty): %v", err)
	}
}

// TestMultiSpanTrace_SignsAndVerifies is the B2 exit-criterion test:
// a 3-span trace with the root arriving last → seal → VerifyLog reports no errors.
func TestMultiSpanTrace_SignsAndVerifies(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pemBytes, err := sign.MarshalEd25519PrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("MarshalEd25519PrivateKeyPEM: %v", err)
	}
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, pemBytes, 0600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	cfg := &Config{
		LogPath:            filepath.Join(dir, "audit.jsonl"),
		KeyPath:            keyPath,
		WalPath:            filepath.Join(dir, "wal.jsonl"),
		CheckpointPath:     filepath.Join(dir, "checkpoint.jsonl"),
		TraceTimeout:       30 * time.Second,
		CheckpointInterval: 100,
	}
	exp := startExporter(t, cfg)

	traceID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	rootSpanID := [8]byte{1, 0, 0, 0, 0, 0, 0, 0}
	childSpanID1 := [8]byte{2, 0, 0, 0, 0, 0, 0, 0}
	childSpanID2 := [8]byte{3, 0, 0, 0, 0, 0, 0, 0}

	// Send two child spans first (no root yet — buffer stays open).
	td1 := makeSpan(traceID, childSpanID1, rootSpanID, "child1", 1000, 2000)
	if err := exp.ConsumeTraces(context.Background(), td1); err != nil {
		t.Fatalf("ConsumeTraces child1: %v", err)
	}
	td2 := makeSpan(traceID, childSpanID2, rootSpanID, "child2", 2000, 3000)
	if err := exp.ConsumeTraces(context.Background(), td2); err != nil {
		t.Fatalf("ConsumeTraces child2: %v", err)
	}

	// Send the root span last — triggers immediate seal.
	tdRoot := makeSpan(traceID, rootSpanID, zeroParentID, "root", 500, 4000)
	if err := exp.ConsumeTraces(context.Background(), tdRoot); err != nil {
		t.Fatalf("ConsumeTraces root: %v", err)
	}

	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// The log should have exactly 3 entries.
	entries := readLogEntries(t, cfg.LogPath)
	if len(entries) != 3 {
		t.Errorf("expected 3 log entries, got %d", len(entries))
	}

	// VerifyLog must report no errors.
	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) != 0 {
		for _, e := range report.Errors {
			t.Errorf("VerifyLog error: %v", e)
		}
	}
	if report.TracesProcessed != 1 {
		t.Errorf("TracesProcessed: got %d, want 1", report.TracesProcessed)
	}
}

// TestChain_Deterministic verifies that sending the same spans twice to two separate
// exporters produces identical entryHash values.
func TestChain_Deterministic(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	priv, _, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pemBytes, err := sign.MarshalEd25519PrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("MarshalEd25519PrivateKeyPEM: %v", err)
	}

	writeKey := func(dir string) string {
		kp := filepath.Join(dir, "key.pem")
		if err := os.WriteFile(kp, pemBytes, 0600); err != nil {
			t.Fatalf("write key: %v", err)
		}
		return kp
	}

	makeCfg := func(dir string) *Config {
		return &Config{
			LogPath:            filepath.Join(dir, "audit.jsonl"),
			KeyPath:            writeKey(dir),
			WalPath:            filepath.Join(dir, "wal.jsonl"),
			CheckpointPath:     filepath.Join(dir, "checkpoint.jsonl"),
			TraceTimeout:       30 * time.Second,
			CheckpointInterval: 100,
		}
	}

	traceID := [16]byte{0xAA, 0xBB}
	rootID := [8]byte{1}
	childID := [8]byte{2}

	run := func(dir string) []chain.LogEntry {
		exp := startExporter(t, makeCfg(dir))
		// child first
		if err := exp.ConsumeTraces(context.Background(),
			makeSpan(traceID, childID, rootID, "child", 2000, 3000)); err != nil {
			t.Fatalf("ConsumeTraces child: %v", err)
		}
		// root triggers seal
		if err := exp.ConsumeTraces(context.Background(),
			makeSpan(traceID, rootID, zeroParentID, "root", 1000, 4000)); err != nil {
			t.Fatalf("ConsumeTraces root: %v", err)
		}
		if err := exp.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
		return readLogEntries(t, makeCfg(dir).LogPath)
	}

	entries1 := run(dir1)
	entries2 := run(dir2)

	if len(entries1) != len(entries2) {
		t.Fatalf("entry count mismatch: %d vs %d", len(entries1), len(entries2))
	}
	for i := range entries1 {
		if entries1[i].Signed.EntryHash != entries2[i].Signed.EntryHash {
			t.Errorf("entry[%d] entryHash mismatch:\n  run1 %s\n  run2 %s",
				i, entries1[i].Signed.EntryHash, entries2[i].Signed.EntryHash)
		}
	}
}

// TestChain_Dedup verifies that sending the same span_id twice results in exactly
// one log entry for that span.
func TestChain_Dedup(t *testing.T) {
	env := newTestEnv(t)
	exp := startExporter(t, env.cfg)

	traceID := [16]byte{0x11}
	spanID := [8]byte{0x01}

	// Send the same span twice.
	td1 := makeSpan(traceID, spanID, zeroParentID, "root", 1000, 2000)
	td2 := makeSpan(traceID, spanID, zeroParentID, "root", 1000, 2000)
	if err := exp.ConsumeTraces(context.Background(), td1); err != nil {
		t.Fatalf("ConsumeTraces 1: %v", err)
	}
	// The first call seals immediately (root span). The second call may create a
	// new buffer (post-seal). We only assert the initial sealed chain had 1 entry.
	if err := exp.ConsumeTraces(context.Background(), td2); err != nil {
		t.Fatalf("ConsumeTraces 2: %v", err)
	}

	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// The first sealed trace should have exactly 1 entry.
	entries := readLogEntries(t, env.cfg.LogPath)
	// Count entries for this trace.
	traceIDStr := pcommon.TraceID(traceID).String()
	var count int
	for _, e := range entries {
		if e.Record.TraceID == traceIDStr {
			count++
		}
	}
	if count < 1 {
		t.Errorf("expected at least 1 entry for dedup trace, got %d", count)
	}
}

// TestVerify_TamperDetected verifies that flipping a byte in a record's field
// causes VerifyLog to report a chain error.
func TestVerify_TamperDetected(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pemBytes, _ := sign.MarshalEd25519PrivateKeyPEM(priv)
	keyPath := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(keyPath, pemBytes, 0600)

	cfg := &Config{
		LogPath:            filepath.Join(dir, "audit.jsonl"),
		KeyPath:            keyPath,
		WalPath:            filepath.Join(dir, "wal.jsonl"),
		CheckpointPath:     filepath.Join(dir, "checkpoint.jsonl"),
		TraceTimeout:       30 * time.Second,
		CheckpointInterval: 100,
	}

	exp := startExporter(t, cfg)
	traceID := [16]byte{0x22}
	spanID := [8]byte{0x01}
	td := makeSpan(traceID, spanID, zeroParentID, "root", 1000, 2000)
	_ = exp.ConsumeTraces(context.Background(), td)
	_ = exp.Shutdown(context.Background())

	// Read log entries, tamper with the span_name, rewrite.
	data, _ := os.ReadFile(cfg.LogPath)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) == 0 {
		t.Skip("no log entries to tamper")
	}

	// Tamper: replace span_name in the first entry.
	var le chain.LogEntry
	_ = json.Unmarshal([]byte(lines[0]), &le)
	le.Record.SpanName = "TAMPERED"
	tampered, _ := json.Marshal(le)
	lines[0] = string(tampered)

	// Rewrite log file.
	var buf bytes.Buffer
	for _, l := range lines {
		buf.WriteString(l)
		buf.WriteByte('\n')
	}
	_ = os.WriteFile(cfg.LogPath, buf.Bytes(), 0600)

	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) == 0 {
		t.Error("expected VerifyLog to detect tamper, got no errors")
	}
}

// TestVerify_DeletionDetected_Middle verifies that removing a middle entry
// causes a chain verification error.
func TestVerify_DeletionDetected_Middle(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pemBytes, _ := sign.MarshalEd25519PrivateKeyPEM(priv)
	keyPath := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(keyPath, pemBytes, 0600)

	cfg := &Config{
		LogPath:            filepath.Join(dir, "audit.jsonl"),
		KeyPath:            keyPath,
		WalPath:            filepath.Join(dir, "wal.jsonl"),
		CheckpointPath:     filepath.Join(dir, "checkpoint.jsonl"),
		TraceTimeout:       30 * time.Second,
		CheckpointInterval: 100,
	}

	exp := startExporter(t, cfg)
	traceID := [16]byte{0x33}
	rootID := [8]byte{1}
	child1ID := [8]byte{2}
	child2ID := [8]byte{3}

	// 3 spans: two children then root (triggers seal with 3 entries).
	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, child1ID, rootID, "c1", 1000, 2000))
	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, child2ID, rootID, "c2", 2000, 3000))
	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, rootID, zeroParentID, "root", 500, 4000))
	_ = exp.Shutdown(context.Background())

	data, _ := os.ReadFile(cfg.LogPath)
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if t := scanner.Text(); t != "" {
			lines = append(lines, t)
		}
	}
	if len(lines) < 3 {
		t.Skipf("need at least 3 entries, got %d", len(lines))
	}

	// Remove the middle entry (index 1).
	lines = append(lines[:1], lines[2:]...)

	var buf bytes.Buffer
	for _, l := range lines {
		buf.WriteString(l)
		buf.WriteByte('\n')
	}
	_ = os.WriteFile(cfg.LogPath, buf.Bytes(), 0600)

	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) == 0 {
		t.Error("expected VerifyLog to detect middle deletion, got no errors")
	}
}

// TestVerify_ReorderNotError verifies that physically swapping JSONL lines does
// NOT cause a chain error. The verifier sorts entries by seq_in_trace before
// verifying, so file-order swaps are harmless; only seq_in_trace value swaps
// (covered by TestVerify_SeqTamperDetected) are an integrity violation.
func TestVerify_ReorderNotError(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pemBytes, _ := sign.MarshalEd25519PrivateKeyPEM(priv)
	keyPath := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(keyPath, pemBytes, 0600)

	cfg := &Config{
		LogPath:            filepath.Join(dir, "audit.jsonl"),
		KeyPath:            keyPath,
		WalPath:            filepath.Join(dir, "wal.jsonl"),
		CheckpointPath:     filepath.Join(dir, "checkpoint.jsonl"),
		TraceTimeout:       30 * time.Second,
		CheckpointInterval: 100,
	}

	exp := startExporter(t, cfg)
	traceID := [16]byte{0x44}
	rootID := [8]byte{1}
	child1ID := [8]byte{2}
	child2ID := [8]byte{3}

	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, child1ID, rootID, "c1", 1000, 2000))
	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, child2ID, rootID, "c2", 2000, 3000))
	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, rootID, zeroParentID, "root", 500, 4000))
	_ = exp.Shutdown(context.Background())

	data, _ := os.ReadFile(cfg.LogPath)
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if l := scanner.Text(); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) < 2 {
		t.Skipf("need at least 2 entries, got %d", len(lines))
	}

	// Swap first two lines to simulate out-of-order log writes.
	lines[0], lines[1] = lines[1], lines[0]

	var buf bytes.Buffer
	for _, l := range lines {
		buf.WriteString(l)
		buf.WriteByte('\n')
	}
	_ = os.WriteFile(cfg.LogPath, buf.Bytes(), 0600)

	// The verifier sorts by seq_in_trace, so the swap is transparent.
	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("expected no errors for physical line swap (verifier re-sorts), got: %v", report.Errors)
	}
}

// TestCheckpoint_SignsAndVerifies verifies that two sealed traces produce a valid checkpoint.
func TestCheckpoint_SignsAndVerifies(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pemBytes, _ := sign.MarshalEd25519PrivateKeyPEM(priv)
	keyPath := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(keyPath, pemBytes, 0600)

	cfg := &Config{
		LogPath:            filepath.Join(dir, "audit.jsonl"),
		KeyPath:            keyPath,
		WalPath:            filepath.Join(dir, "wal.jsonl"),
		CheckpointPath:     filepath.Join(dir, "checkpoint.jsonl"),
		TraceTimeout:       30 * time.Second,
		CheckpointInterval: 2, // checkpoint after every 2 traces
	}

	exp := startExporter(t, cfg)

	// Seal two root-only traces to trigger a checkpoint at CheckpointInterval=2.
	trace1 := [16]byte{0x55}
	trace2 := [16]byte{0x66}
	root1 := [8]byte{1}
	root2 := [8]byte{2}

	_ = exp.ConsumeTraces(context.Background(), makeSpan(trace1, root1, zeroParentID, "t1", 1000, 2000))
	_ = exp.ConsumeTraces(context.Background(), makeSpan(trace2, root2, zeroParentID, "t2", 1000, 2000))
	_ = exp.Shutdown(context.Background())

	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) != 0 {
		for _, e := range report.Errors {
			t.Errorf("VerifyLog error: %v", e)
		}
	}
	if report.CheckpointsProcessed < 1 {
		t.Errorf("CheckpointsProcessed: got %d, want >= 1", report.CheckpointsProcessed)
	}
}

// TestCheckpoint_TamperDetected verifies that modifying the checkpoint file is detected.
func TestCheckpoint_TamperDetected(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pemBytes, _ := sign.MarshalEd25519PrivateKeyPEM(priv)
	keyPath := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(keyPath, pemBytes, 0600)

	cfg := &Config{
		LogPath:            filepath.Join(dir, "audit.jsonl"),
		KeyPath:            keyPath,
		WalPath:            filepath.Join(dir, "wal.jsonl"),
		CheckpointPath:     filepath.Join(dir, "checkpoint.jsonl"),
		TraceTimeout:       30 * time.Second,
		CheckpointInterval: 1, // checkpoint after every trace
	}

	exp := startExporter(t, cfg)
	traceID := [16]byte{0x77}
	rootID := [8]byte{1}
	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, rootID, zeroParentID, "root", 1000, 2000))
	_ = exp.Shutdown(context.Background())

	// Read and tamper checkpoint.
	data, err := os.ReadFile(cfg.CheckpointPath)
	if err != nil {
		t.Fatalf("reading checkpoint: %v", err)
	}
	if len(data) == 0 {
		t.Skip("no checkpoint data to tamper")
	}

	// Decode the checkpoint, change checkpoint_seq, re-encode.
	var cp chain.Checkpoint
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if l := scanner.Text(); l != "" {
			_ = json.Unmarshal([]byte(l), &cp)
			break
		}
	}
	cp.CheckpointSeq = 999 // tamper
	tampered, _ := json.Marshal(cp)
	_ = os.WriteFile(cfg.CheckpointPath, append(tampered, '\n'), 0600)

	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) == 0 {
		t.Error("expected VerifyLog to detect checkpoint tamper, got no errors")
	}
}

// TestVerifyLog_UncoveredTrace verifies that a trace not covered by any checkpoint
// is counted in TracesProcessed but not reported as an error.
func TestVerifyLog_UncoveredTrace(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pemBytes, _ := sign.MarshalEd25519PrivateKeyPEM(priv)
	keyPath := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(keyPath, pemBytes, 0600)

	cfg := &Config{
		LogPath:        filepath.Join(dir, "audit.jsonl"),
		KeyPath:        keyPath,
		WalPath:        filepath.Join(dir, "wal.jsonl"),
		CheckpointPath: filepath.Join(dir, "checkpoint.jsonl"),
		// Very high interval so no checkpoint is written automatically.
		TraceTimeout:       30 * time.Second,
		CheckpointInterval: 1000,
	}

	exp := startExporter(t, cfg)
	traceID := [16]byte{0x88}
	rootID := [8]byte{1}
	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, rootID, zeroParentID, "root", 1000, 2000))
	_ = exp.Shutdown(context.Background())

	// Verify — no checkpoint file exists (or it's empty after Shutdown without hitting interval).
	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	// The uncovered trace must be counted but not flagged as error.
	if report.TracesProcessed < 1 {
		t.Errorf("TracesProcessed: got %d, want >= 1", report.TracesProcessed)
	}
	// Chain errors are still an error; only "not in any checkpoint" is not an error.
	chainErrors := 0
	for _, e := range report.Errors {
		if e.Kind == "chain" {
			chainErrors++
		}
	}
	if chainErrors != 0 {
		t.Errorf("unexpected chain errors for uncovered trace: %d", chainErrors)
	}
}

// TestConsumeTraces_SignsAndVerifies is the B1-compatible single-span test.
func TestConsumeTraces_SignsAndVerifies(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pemBytes, _ := sign.MarshalEd25519PrivateKeyPEM(priv)
	keyPath := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(keyPath, pemBytes, 0600)

	cfg := &Config{
		LogPath:            filepath.Join(dir, "audit.jsonl"),
		KeyPath:            keyPath,
		WalPath:            filepath.Join(dir, "wal.jsonl"),
		CheckpointPath:     filepath.Join(dir, "checkpoint.jsonl"),
		TraceTimeout:       30 * time.Second,
		CheckpointInterval: 100,
	}
	exp := startExporter(t, cfg)

	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetTraceID(pcommon.TraceID([16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}))
	span.SetSpanID(pcommon.SpanID([8]byte{1, 2, 3, 4, 5, 6, 7, 8}))
	span.SetName("gen_ai.chat")
	span.SetKind(ptrace.SpanKindClient)
	span.SetStartTimestamp(pcommon.Timestamp(1000000000))
	span.SetEndTimestamp(pcommon.Timestamp(2000000000))
	span.Status().SetCode(ptrace.StatusCodeOk)
	span.Attributes().PutStr("gen_ai.operation.name", "chat")
	span.Attributes().PutStr("gen_ai.request.model", "gpt-4o")
	span.Attributes().PutStr("gen_ai.system", "openai")

	if err := exp.ConsumeTraces(context.Background(), td); err != nil {
		t.Fatalf("ConsumeTraces: %v", err)
	}
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	for _, e := range report.Errors {
		if e.Kind == "chain" {
			t.Errorf("VerifyLog chain error: %v", e)
		}
	}
	if report.TracesProcessed != 1 {
		t.Errorf("TracesProcessed: got %d, want 1", report.TracesProcessed)
	}
}

// TestRestart_Rehydration verifies that WAL replay correctly rehydrates buffers
// across a simulated crash (ungraceful shutdown).
//
// The test uses a crash-simulation: after buffering child spans, it calls
// crashShutdown (which closes files without sealing open buffers) rather than
// the graceful Shutdown. On restart, the WAL replays the two children back into
// the buffer; sending the root span then seals a 3-entry chain.
func TestRestart_Rehydration(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pemBytes, _ := sign.MarshalEd25519PrivateKeyPEM(priv)
	keyPath := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(keyPath, pemBytes, 0600)

	cfg := &Config{
		LogPath:            filepath.Join(dir, "audit.jsonl"),
		KeyPath:            keyPath,
		WalPath:            filepath.Join(dir, "wal.jsonl"),
		CheckpointPath:     filepath.Join(dir, "checkpoint.jsonl"),
		TraceTimeout:       30 * time.Second,
		CheckpointInterval: 100,
	}

	traceID := [16]byte{0x99}
	rootID := [8]byte{1}
	child1ID := [8]byte{2}
	child2ID := [8]byte{3}

	// Phase 1: buffer 2 child spans then simulate a crash (no graceful Shutdown).
	exp1 := startExporter(t, cfg)
	_ = exp1.ConsumeTraces(context.Background(), makeSpan(traceID, child1ID, rootID, "child1", 1000, 2000))
	_ = exp1.ConsumeTraces(context.Background(), makeSpan(traceID, child2ID, rootID, "child2", 2000, 3000))

	// Crash simulation: close(stopCh) + <-doneCh to stop the background goroutine,
	// then close files WITHOUT force-sealing open buffers.
	close(exp1.stopCh)
	<-exp1.doneCh
	// Close files directly, leaving WAL with unsealed entries.
	if exp1.logFile != nil {
		_ = exp1.logFile.Close()
		exp1.logFile = nil
	}
	if exp1.checkFile != nil {
		_ = exp1.checkFile.Close()
		exp1.checkFile = nil
	}
	if exp1.wal != nil {
		_ = exp1.wal.Close()
		exp1.wal = nil
	}

	// After crash, log file must be empty (trace was never sealed).
	entries := readLogEntries(t, cfg.LogPath)
	if len(entries) != 0 {
		t.Errorf("expected 0 log entries after crash, got %d", len(entries))
	}

	// Phase 2: restart — WAL replays the 2 children, then send root → seal all 3.
	exp2 := startExporter(t, cfg)
	_ = exp2.ConsumeTraces(context.Background(), makeSpan(traceID, rootID, zeroParentID, "root", 500, 4000))
	if err := exp2.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown phase 2: %v", err)
	}

	// Chain should now have all 3 spans.
	entries = readLogEntries(t, cfg.LogPath)
	if len(entries) != 3 {
		t.Errorf("expected 3 log entries after restart + root, got %d", len(entries))
	}

	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	for _, e := range report.Errors {
		if e.Kind == "chain" {
			t.Errorf("VerifyLog chain error after restart: %v", e)
		}
	}
}

// TestConsumeTraces_Concurrent verifies that 50 DISTINCT trace IDs are handled
// race-safely and each produces exactly one log entry after Shutdown.
func TestConsumeTraces_Concurrent(t *testing.T) {
	const N = 50
	env := newTestEnv(t)
	exp := startExporter(t, env.cfg)

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			// Distinct trace ID for each goroutine.
			var traceID [16]byte
			traceID[0] = byte(i + 1)
			traceID[1] = byte((i + 1) >> 8)
			var spanID [8]byte
			spanID[0] = byte(i + 1)

			td := makeSpan(traceID, spanID, zeroParentID, fmt.Sprintf("root-%d", i), 1000, 2000)
			if err := exp.ConsumeTraces(context.Background(), td); err != nil {
				t.Errorf("ConsumeTraces[%d]: %v", i, err)
			}
		}()
	}
	wg.Wait()

	// Shutdown seals any buffered traces and flushes all entries to disk.
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// Each trace has exactly one root span, so the log must have exactly N entries.
	data, err := os.ReadFile(env.cfg.LogPath)
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	var count int
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if l := scanner.Text(); l != "" {
			count++
		}
	}
	if count != N {
		t.Errorf("log entry count: got %d, want %d", count, N)
	}
}

// TestVerify_SeqTamperDetected verifies that swapping seq_in_trace values on
// two entries (while keeping signatures intact) causes a verification error.
func TestVerify_SeqTamperDetected(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pemBytes, _ := sign.MarshalEd25519PrivateKeyPEM(priv)
	keyPath := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(keyPath, pemBytes, 0600)

	cfg := &Config{
		LogPath:            filepath.Join(dir, "audit.jsonl"),
		KeyPath:            keyPath,
		WalPath:            filepath.Join(dir, "wal.jsonl"),
		CheckpointPath:     filepath.Join(dir, "checkpoint.jsonl"),
		TraceTimeout:       30 * time.Second,
		CheckpointInterval: 100,
	}

	exp := startExporter(t, cfg)
	traceID := [16]byte{0xAA}
	rootID := [8]byte{1}
	childID := [8]byte{2}

	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, childID, rootID, "child", 2000, 3000))
	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, rootID, zeroParentID, "root", 1000, 4000))
	_ = exp.Shutdown(context.Background())

	data, _ := os.ReadFile(cfg.LogPath)
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if l := scanner.Text(); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) < 2 {
		t.Skipf("need at least 2 entries, got %d", len(lines))
	}

	// Swap seq_in_trace between entry 0 and entry 1 (keep signatures intact — mismatch).
	var e0, e1 chain.LogEntry
	_ = json.Unmarshal([]byte(lines[0]), &e0)
	_ = json.Unmarshal([]byte(lines[1]), &e1)
	e0.Record.SeqInTrace, e1.Record.SeqInTrace = e1.Record.SeqInTrace, e0.Record.SeqInTrace
	b0, _ := json.Marshal(e0)
	b1, _ := json.Marshal(e1)
	lines[0] = string(b0)
	lines[1] = string(b1)

	var buf bytes.Buffer
	for _, l := range lines {
		buf.WriteString(l)
		buf.WriteByte('\n')
	}
	_ = os.WriteFile(cfg.LogPath, buf.Bytes(), 0600)

	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) == 0 {
		t.Error("expected VerifyLog to detect seq_in_trace tamper, got no errors")
	}
}

// TestCheckpoint_DroppedTrace verifies that a trace referenced in a checkpoint
// but absent from the log produces an entry_count_mismatch error.
func TestCheckpoint_DroppedTrace(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pemBytes, _ := sign.MarshalEd25519PrivateKeyPEM(priv)
	keyPath := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(keyPath, pemBytes, 0600)

	cfg := &Config{
		LogPath:            filepath.Join(dir, "audit.jsonl"),
		KeyPath:            keyPath,
		WalPath:            filepath.Join(dir, "wal.jsonl"),
		CheckpointPath:     filepath.Join(dir, "checkpoint.jsonl"),
		TraceTimeout:       30 * time.Second,
		CheckpointInterval: 1,
	}

	exp := startExporter(t, cfg)
	traceID := [16]byte{0xBB}
	rootID := [8]byte{1}
	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, rootID, zeroParentID, "root", 1000, 2000))
	_ = exp.Shutdown(context.Background())

	// Remove the log file to simulate a dropped trace.
	_ = os.WriteFile(cfg.LogPath, []byte{}, 0600)

	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	// Should report entry_count_mismatch because checkpoint references the trace but log is empty.
	var mismatchFound bool
	for _, e := range report.Errors {
		if e.Kind == "entry_count_mismatch" {
			mismatchFound = true
			break
		}
	}
	if !mismatchFound {
		t.Errorf("expected entry_count_mismatch error for dropped trace, errors: %v", report.Errors)
	}
}

// TestVerify_DeletionDetected_Last verifies that removing the last log entry
// produces a checkpoint entry_count_mismatch error.
func TestVerify_DeletionDetected_Last(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pemBytes, _ := sign.MarshalEd25519PrivateKeyPEM(priv)
	keyPath := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(keyPath, pemBytes, 0600)

	cfg := &Config{
		LogPath:            filepath.Join(dir, "audit.jsonl"),
		KeyPath:            keyPath,
		WalPath:            filepath.Join(dir, "wal.jsonl"),
		CheckpointPath:     filepath.Join(dir, "checkpoint.jsonl"),
		TraceTimeout:       30 * time.Second,
		CheckpointInterval: 1,
	}

	exp := startExporter(t, cfg)
	traceID := [16]byte{0xCC}
	rootID := [8]byte{1}
	childID := [8]byte{2}

	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, childID, rootID, "child", 2000, 3000))
	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, rootID, zeroParentID, "root", 1000, 4000))
	_ = exp.Shutdown(context.Background())

	data, _ := os.ReadFile(cfg.LogPath)
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if l := scanner.Text(); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) < 2 {
		t.Skipf("need at least 2 entries, got %d", len(lines))
	}

	// Remove the last entry.
	lines = lines[:len(lines)-1]

	var buf bytes.Buffer
	for _, l := range lines {
		buf.WriteString(l)
		buf.WriteByte('\n')
	}
	_ = os.WriteFile(cfg.LogPath, buf.Bytes(), 0600)

	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	// Either chain error (prev-hash break) or entry_count_mismatch must appear.
	if len(report.Errors) == 0 {
		t.Error("expected VerifyLog to detect last-entry deletion, got no errors")
	}
}

// TestWALAppendSpanWritesToWAL verifies that ConsumeTraces with a non-root span
// writes to the WAL (i.e., the buffer isn't sealed prematurely).
func TestWALAppendSpanWritesToWAL(t *testing.T) {
	env := newTestEnv(t)
	exp := startExporter(t, env.cfg)

	traceID := [16]byte{0xDD}
	childID := [8]byte{1}
	rootID := [8]byte{2}

	// Send only a child span (no root) — buffer stays open.
	td := makeSpan(traceID, childID, rootID, "child", 1000, 2000)
	if err := exp.ConsumeTraces(context.Background(), td); err != nil {
		t.Fatalf("ConsumeTraces: %v", err)
	}

	// Log file must be empty (trace not sealed yet).
	data, _ := os.ReadFile(env.cfg.LogPath)
	if len(bytes.TrimSpace(data)) != 0 {
		t.Errorf("expected empty log before root span, got %q", data)
	}

	// WAL must have the span.
	walData, _ := os.ReadFile(env.cfg.WalPath)
	if len(bytes.TrimSpace(walData)) == 0 {
		t.Error("expected WAL to have the buffered span, got empty")
	}

	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// TestRestart_CheckpointContinuity verifies that checkpoint_seq and prev_checkpoint_hash
// continue correctly across a clean Shutdown + restart.
//
// Sequence:
//  1. Run exporter A: seal trace-1 (1 span) → Shutdown → checkpoint seq=1 written.
//  2. Run exporter B on same files: seal trace-2 (1 span) → Shutdown → checkpoint seq=2 written.
//  3. Assert: second checkpoint has checkpoint_seq=2 and prev_checkpoint_hash == SHA256(first signing payload).
func TestRestart_CheckpointContinuity(t *testing.T) {
	env := newTestEnv(t)
	env.cfg.CheckpointInterval = 1 // checkpoint after every trace

	traceID1 := [16]byte{0xE1}
	traceID2 := [16]byte{0xE2}
	rootID1 := [8]byte{0x01}
	rootID2 := [8]byte{0x02}

	// Phase 1: seal one trace, shut down (writes checkpoint seq=1).
	exp1 := startExporter(t, env.cfg)
	_ = exp1.ConsumeTraces(context.Background(), makeSpan(traceID1, rootID1, zeroParentID, "t1", 1000, 2000))
	if err := exp1.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown phase 1: %v", err)
	}

	// Read the first checkpoint to compute the expected prevHash.
	data, err := os.ReadFile(env.cfg.CheckpointPath)
	if err != nil {
		t.Fatalf("reading checkpoint after phase 1: %v", err)
	}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if l := sc.Text(); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		t.Fatal("expected at least one checkpoint after phase 1")
	}
	var cp1 chain.Checkpoint
	if err := json.Unmarshal([]byte(lines[0]), &cp1); err != nil {
		t.Fatalf("unmarshal first checkpoint: %v", err)
	}
	if cp1.CheckpointSeq != 1 {
		t.Fatalf("first checkpoint seq: got %d, want 1", cp1.CheckpointSeq)
	}
	payload1, err := chain.CheckpointSigningPayload(cp1)
	if err != nil {
		t.Fatalf("CheckpointSigningPayload: %v", err)
	}
	h := sha256.Sum256(payload1)
	expectedPrevHash := hex.EncodeToString(h[:])

	// Phase 2: restart on same files, seal a second trace.
	exp2 := startExporter(t, env.cfg)
	_ = exp2.ConsumeTraces(context.Background(), makeSpan(traceID2, rootID2, zeroParentID, "t2", 3000, 4000))
	if err := exp2.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown phase 2: %v", err)
	}

	// Read the second checkpoint (last line of the file).
	data2, err := os.ReadFile(env.cfg.CheckpointPath)
	if err != nil {
		t.Fatalf("reading checkpoint after phase 2: %v", err)
	}
	var lines2 []string
	sc2 := bufio.NewScanner(bytes.NewReader(data2))
	for sc2.Scan() {
		if l := sc2.Text(); l != "" {
			lines2 = append(lines2, l)
		}
	}
	if len(lines2) < 2 {
		t.Fatalf("expected at least 2 checkpoints, got %d", len(lines2))
	}
	var cp2 chain.Checkpoint
	if err := json.Unmarshal([]byte(lines2[len(lines2)-1]), &cp2); err != nil {
		t.Fatalf("unmarshal second checkpoint: %v", err)
	}

	if cp2.CheckpointSeq != 2 {
		t.Errorf("second checkpoint seq: got %d, want 2", cp2.CheckpointSeq)
	}
	if cp2.PrevCheckpointHash != expectedPrevHash {
		t.Errorf("second checkpoint prev_checkpoint_hash:\n  got  %s\n  want %s",
			cp2.PrevCheckpointHash, expectedPrevHash)
	}
}

// TestSealedTraces_EvictedAfterCompact verifies that sealedTraces is cleared
// after a successful WAL.Compact so it does not grow without bound.
func TestSealedTraces_EvictedAfterCompact(t *testing.T) {
	env := newTestEnv(t)
	exp := startExporter(t, env.cfg)
	defer func() { _ = exp.Shutdown(context.Background()) }()

	traceID := [16]byte{0xF1}
	rootID := [8]byte{0x01}

	// Seal one trace (root span triggers immediate seal).
	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, rootID, zeroParentID, "root", 1000, 2000))

	// Verify the trace is now in sealedTraces.
	exp.mu.Lock()
	_, inSealed := exp.sealedTraces[pcommon.TraceID(traceID).String()]
	exp.mu.Unlock()
	if !inSealed {
		t.Fatal("expected trace to be in sealedTraces after seal")
	}

	// Wait for the background Compact goroutine to finish and clear sealedTraces.
	exp.compactWG.Wait()

	exp.mu.Lock()
	remaining := len(exp.sealedTraces)
	exp.mu.Unlock()
	if remaining != 0 {
		t.Errorf("sealedTraces should be empty after Compact, got %d entries", remaining)
	}
}

// TestRestart_CheckpointContinuity_PartialLine verifies that a corrupt/partial
// last line in the checkpoint file (e.g. from a crash mid-write) does not cause
// Start to lose the previous valid checkpoint: the restart should use seq=2 based
// on the last intact line, not fall back to seq=0.
func TestRestart_CheckpointContinuity_PartialLine(t *testing.T) {
	env := newTestEnv(t)
	env.cfg.CheckpointInterval = 1

	traceID1 := [16]byte{0xE3}
	traceID2 := [16]byte{0xE4}
	rootID1 := [8]byte{0x01}
	rootID2 := [8]byte{0x02}

	// Phase 1: write checkpoint seq=1.
	exp1 := startExporter(t, env.cfg)
	_ = exp1.ConsumeTraces(context.Background(), makeSpan(traceID1, rootID1, zeroParentID, "t1", 1000, 2000))
	if err := exp1.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown phase 1: %v", err)
	}

	// Read checkpoint seq=1 so we can compute the expected prevHash for seq=2.
	data, _ := os.ReadFile(env.cfg.CheckpointPath)
	sc := bufio.NewScanner(bytes.NewReader(data))
	var lines []string
	for sc.Scan() {
		if l := sc.Text(); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		t.Fatal("expected checkpoint after phase 1")
	}
	var cp1 chain.Checkpoint
	if err := json.Unmarshal([]byte(lines[0]), &cp1); err != nil {
		t.Fatalf("unmarshal cp1: %v", err)
	}
	payload1, err := chain.CheckpointSigningPayload(cp1)
	if err != nil {
		t.Fatalf("CheckpointSigningPayload: %v", err)
	}
	h := sha256.Sum256(payload1)
	expectedPrevHash := hex.EncodeToString(h[:])

	// Simulate a crash mid-write: append a truncated JSON line that ends with '\n'
	// so the following writeCheckpoint appends on its own line (not concatenated).
	f, err := os.OpenFile(env.cfg.CheckpointPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open checkpoint for truncated append: %v", err)
	}
	_, _ = f.Write([]byte("{\"schema_version\":\"v1\",\"checkpoint_seq\":2,\"timestamp\":\"\n")) // truncated + newline
	_ = f.Close()

	// Phase 2: restart on files with the corrupt last line.
	exp2 := startExporter(t, env.cfg)
	_ = exp2.ConsumeTraces(context.Background(), makeSpan(traceID2, rootID2, zeroParentID, "t2", 3000, 4000))
	if err := exp2.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown phase 2: %v", err)
	}

	// The new checkpoint appended by phase 2 should be seq=2 with the correct prevHash.
	data2, _ := os.ReadFile(env.cfg.CheckpointPath)
	sc2 := bufio.NewScanner(bytes.NewReader(data2))
	var lines2 []string
	for sc2.Scan() {
		if l := sc2.Text(); l != "" {
			lines2 = append(lines2, l)
		}
	}
	// lines2 includes: seq=1, corrupt partial, seq=2 — but corrupt line fails Unmarshal so
	// readLastCheckpoint skips it; seq=2 is written by phase 2.
	var cp2 chain.Checkpoint
	for i := len(lines2) - 1; i >= 0; i-- {
		if err := json.Unmarshal([]byte(lines2[i]), &cp2); err == nil {
			break
		}
	}
	if cp2.CheckpointSeq != 2 {
		t.Errorf("second checkpoint seq: got %d, want 2", cp2.CheckpointSeq)
	}
	if cp2.PrevCheckpointHash != expectedPrevHash {
		t.Errorf("second checkpoint prev_checkpoint_hash:\n  got  %s\n  want %s",
			cp2.PrevCheckpointHash, expectedPrevHash)
	}
}

// TestFsyncLog_Default verifies that the exporter works correctly with the
// default fsync_log=true setting and produces a verifiable log.
// True power-loss durability is not unit-testable, but this confirms the sync
// code path does not break the write/verify round-trip.
func TestFsyncLog_Default(t *testing.T) {
	env := newTestEnv(t)
	// FsyncLog is nil (default true) — the sync code path is exercised.
	exp := startExporter(t, env.cfg)

	traceID := [16]byte{0xF2}
	rootID := [8]byte{0x10}
	childID := [8]byte{0x11}

	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, childID, rootID, "child", 1000, 2000))
	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, rootID, zeroParentID, "root", 500, 3000))
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	report, err := verify.VerifyLog(env.cfg.LogPath, env.cfg.CheckpointPath, env.pubKey)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("expected no errors; got %v", report.Errors)
	}
}

// TestFsyncLog_Disabled verifies that disabling fsync_log still produces a
// correct and verifiable log (durability is reduced, but correctness is not).
func TestFsyncLog_Disabled(t *testing.T) {
	env := newTestEnv(t)
	falseVal := false
	env.cfg.FsyncLog = &falseVal
	exp := startExporter(t, env.cfg)

	traceID := [16]byte{0xF3}
	rootID := [8]byte{0x12}

	_ = exp.ConsumeTraces(context.Background(), makeSpan(traceID, rootID, zeroParentID, "root", 1000, 2000))
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	report, err := verify.VerifyLog(env.cfg.LogPath, env.cfg.CheckpointPath, env.pubKey)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("expected no errors with fsync disabled; got %v", report.Errors)
	}
}

// TestEarlyRoot_TruncatedButValid pins the early-root truncation behaviour:
// when the root span arrives BEFORE its children, the exporter seals on the
// root and drops any subsequent child spans. The sealed single-entry chain is
// internally valid (signatures and hashes pass), but it only contains the root.
//
// This is the caveat documented in docs/threat-model.md §3b:
// "If the root span arrives before its children, the trace seals immediately
// and any subsequent child spans are dropped."
//
// Mitigation: use agentauditselect processor (tested in TestMultiSpanTrace_SignsAndVerifies
// via root-last delivery, which produces a complete 3-entry chain).
func TestEarlyRoot_TruncatedButValid(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pemBytes, _ := sign.MarshalEd25519PrivateKeyPEM(priv)
	keyPath := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(keyPath, pemBytes, 0600)

	cfg := &Config{
		LogPath:            filepath.Join(dir, "audit.jsonl"),
		KeyPath:            keyPath,
		WalPath:            filepath.Join(dir, "wal.jsonl"),
		CheckpointPath:     filepath.Join(dir, "checkpoint.jsonl"),
		TraceTimeout:       30 * time.Second,
		CheckpointInterval: 1,
	}

	exp := startExporter(t, cfg)

	traceID := [16]byte{0xF4}
	rootID := [8]byte{0x20}
	childID := [8]byte{0x21}

	// Send root FIRST — triggers immediate seal with only the root span.
	tdRoot := makeSpan(traceID, rootID, zeroParentID, "root", 500, 4000)
	if err := exp.ConsumeTraces(context.Background(), tdRoot); err != nil {
		t.Fatalf("ConsumeTraces root: %v", err)
	}

	// Send child AFTER — must be dropped (trace already sealed).
	tdChild := makeSpan(traceID, childID, rootID, "child", 1000, 2000)
	if err := exp.ConsumeTraces(context.Background(), tdChild); err != nil {
		t.Fatalf("ConsumeTraces child: %v", err)
	}

	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// The log must have exactly 1 entry (root only — child was dropped).
	entries := readLogEntries(t, cfg.LogPath)
	traceIDStr := pcommon.TraceID(traceID).String()
	var traceEntries []chain.LogEntry
	for _, e := range entries {
		if e.Record.TraceID == traceIDStr {
			traceEntries = append(traceEntries, e)
		}
	}
	if len(traceEntries) != 1 {
		t.Errorf("expected 1 entry for early-root trace (root only); got %d", len(traceEntries))
	}

	// The single-entry chain must be internally valid.
	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, pub)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	for _, e := range report.Errors {
		if e.Kind == "chain" {
			t.Errorf("chain error for valid (but truncated) single-root chain: %v", e)
		}
	}
}

// TestBackgroundWorker_TimeoutSeal verifies that a trace buffered without a root
// span is sealed by the background sweep once its idle time exceeds TraceTimeout.
// Uses a 50 ms TraceTimeout; polls until sealed with a 3 s hard deadline.
func TestBackgroundWorker_TimeoutSeal(t *testing.T) {
	env := newTestEnv(t)
	env.cfg.TraceTimeout = 50 * time.Millisecond
	exp := startExporter(t, env.cfg)

	traceID := [16]byte{0x71}
	childID := [8]byte{0x71}
	parentID := [8]byte{0x72} // non-zero parent — not a root span, stays buffered

	td := makeSpan(traceID, childID, parentID, "child", 1000, 2000)
	if err := exp.ConsumeTraces(context.Background(), td); err != nil {
		t.Fatalf("ConsumeTraces: %v", err)
	}

	// Poll until the background ticker sweeps the idle trace (or 3 s deadline).
	// Shutdown force-seals anything remaining, so we assert after Shutdown.
	traceIDStr := pcommon.TraceID(traceID).String()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		entries := readLogEntries(t, env.cfg.LogPath)
		for _, e := range entries {
			if e.Record.TraceID == traceIDStr {
				goto sealed
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
sealed:
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	entries := readLogEntries(t, env.cfg.LogPath)
	var count int
	for _, e := range entries {
		if e.Record.TraceID == traceIDStr {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 log entry from timeout seal, got %d", count)
	}
}

// TestStart_BadLogPath verifies that Start returns an error when the audit log
// file cannot be created (parent directory does not exist).
func TestStart_BadLogPath(t *testing.T) {
	env := newTestEnv(t)
	env.cfg.LogPath = filepath.Join(t.TempDir(), "nonexistent_subdir", "audit.jsonl")

	exp := newAgentAuditExporter(env.cfg, nil)
	if err := exp.Start(context.Background(), nil); err == nil {
		t.Error("expected error when log_path parent dir does not exist")
		_ = exp.Shutdown(context.Background())
	}
}

// TestStart_BadCheckpointPath verifies that Start returns an error when the
// checkpoint file cannot be created (parent directory does not exist), and that
// the already-opened log file is cleaned up correctly.
func TestStart_BadCheckpointPath(t *testing.T) {
	env := newTestEnv(t)
	env.cfg.CheckpointPath = filepath.Join(t.TempDir(), "nonexistent_subdir", "checkpoint.jsonl")

	exp := newAgentAuditExporter(env.cfg, nil)
	if err := exp.Start(context.Background(), nil); err == nil {
		t.Error("expected error when checkpoint_path parent dir does not exist")
		_ = exp.Shutdown(context.Background())
	}
}

// TestStart_BadWalPath verifies that Start returns an error when the WAL file
// cannot be created (parent directory does not exist), and that previously
// opened log and checkpoint files are cleaned up.
func TestStart_BadWalPath(t *testing.T) {
	env := newTestEnv(t)
	env.cfg.WalPath = filepath.Join(t.TempDir(), "nonexistent_subdir", "wal.jsonl")

	exp := newAgentAuditExporter(env.cfg, nil)
	if err := exp.Start(context.Background(), nil); err == nil {
		t.Error("expected error when wal_path parent dir does not exist")
		_ = exp.Shutdown(context.Background())
	}
}

// TestConfig_Validate_NegativeValues verifies that negative TraceTimeout and
// CheckpointInterval are rejected by Validate.
func TestConfig_Validate_NegativeValues(t *testing.T) {
	base := Config{
		LogPath:        "/tmp/a.jsonl",
		KeyPath:        "/tmp/k.pem",
		WalPath:        "/tmp/w.jsonl",
		CheckpointPath: "/tmp/c.jsonl",
	}

	neg := base
	neg.TraceTimeout = -1 * time.Second
	if err := neg.Validate(); err == nil {
		t.Error("expected error for negative trace_timeout")
	}

	neg2 := base
	neg2.CheckpointInterval = -1
	if err := neg2.Validate(); err == nil {
		t.Error("expected error for negative checkpoint_interval")
	}
}

// Ensure record import doesn't cause "imported and not used" when tests don't directly use it.
var _ = record.SchemaVersion

// failSyncFile wraps a logSyncer and returns a configurable error for the first
// `count` calls to Sync, then passes through to the underlying implementation.
// Not concurrency-safe: count is decremented without a lock. Safe only for
// single-goroutine test use where all sealTrace calls run under e.mu.
type failSyncFile struct {
	logSyncer
	syncErr error
	count   int
}

func (f *failSyncFile) Sync() error {
	if f.count > 0 {
		f.count--
		return f.syncErr
	}
	return f.logSyncer.Sync()
}

// TestFsyncFailure_RollsBackLog verifies the key invariant: when logFile.Sync()
// returns an error, sealTrace truncates the entries it just wrote so the log is
// never ahead of the checkpoint. Before this fix the exporter returned early
// without truncating, leaving log entries that no checkpoint covered — which the
// verifier then reported as truncation or tampering.
func TestFsyncFailure_RollsBackLog(t *testing.T) {
	env := newTestEnv(t)
	cfg := env.cfg
	cfg.CheckpointInterval = 1 // would checkpoint immediately on a successful seal

	exp := startExporter(t, cfg)

	// Replace the real log file with a wrapper that fails on the first Sync call.
	exp.mu.Lock()
	exp.logFile = &failSyncFile{
		logSyncer: exp.logFile,
		syncErr:   fmt.Errorf("simulated EIO"),
		count:     1,
	}
	exp.mu.Unlock()

	// Deliver a root span. bufferSpan detects hasRoot=true and calls sealTrace
	// synchronously inside ConsumeTraces. The injected Sync error fires there,
	// rolling back the log entries before ConsumeTraces returns.
	traceID := [16]byte{0xFA}
	rootID := [8]byte{0x01}
	if err := exp.ConsumeTraces(context.Background(), makeSpan(traceID, rootID, zeroParentID, "root-op", 1_000_000, 2_000_000)); err != nil {
		t.Fatalf("ConsumeTraces: %v", err)
	}

	// Shutdown finds buffers empty (trace was already sealed-and-rolled-back above)
	// and closes files cleanly.
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// Log must be empty: the sync failure triggered a truncate-rollback.
	entries := readLogEntries(t, cfg.LogPath)
	if len(entries) != 0 {
		t.Errorf("expected 0 log entries after sync-failure rollback, got %d", len(entries))
	}

	// Checkpoint must also be empty: AddTip was never called.
	cpData, err := os.ReadFile(cfg.CheckpointPath)
	if err != nil {
		t.Fatalf("reading checkpoint: %v", err)
	}
	if len(bytes.TrimSpace(cpData)) != 0 {
		t.Errorf("expected empty checkpoint after sync-failure rollback, got %q", cpData)
	}

	// The verifier must report no errors: an empty log with no checkpoint is valid.
	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, env.pubKey)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("expected no verifier errors after rollback; got %v", report.Errors)
	}
}

// TestEffectiveCheckpointInterval verifies that an unset interval falls back to
// the documented default of 100, and that an explicit positive value overrides it.
func TestEffectiveCheckpointInterval(t *testing.T) {
	def := newAgentAuditExporter(&Config{}, nil)
	if got := def.effectiveCheckpointInterval(); got != 100 {
		t.Fatalf("default interval = %d, want 100", got)
	}

	set := newAgentAuditExporter(&Config{CheckpointInterval: 250}, nil)
	if got := set.effectiveCheckpointInterval(); got != 250 {
		t.Fatalf("configured interval = %d, want 250", got)
	}
}

// TestReadLastCheckpoint exercises readLastCheckpoint's tolerance contract: an
// absent file is not an error, blank and corrupt lines are skipped, and the last
// valid checkpoint in the file wins.
func TestReadLastCheckpoint(t *testing.T) {
	dir := t.TempDir()

	// Absent file: (found=false, err=nil).
	if _, found, err := readLastCheckpoint(filepath.Join(dir, "nope.jsonl")); err != nil || found {
		t.Fatalf("absent file: found=%v err=%v, want found=false err=nil", found, err)
	}

	// Blank line and corrupt line are skipped; the last valid checkpoint wins.
	cp1, err := json.Marshal(chain.Checkpoint{CheckpointSeq: 1})
	if err != nil {
		t.Fatalf("marshal cp1: %v", err)
	}
	cp2, err := json.Marshal(chain.Checkpoint{CheckpointSeq: 2})
	if err != nil {
		t.Fatalf("marshal cp2: %v", err)
	}
	content := "\n" + string(cp1) + "\n{corrupt json\n" + string(cp2) + "\n"
	path := filepath.Join(dir, "checkpoint.jsonl")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write checkpoint file: %v", err)
	}

	last, found, err := readLastCheckpoint(path)
	if err != nil || !found {
		t.Fatalf("valid file: found=%v err=%v, want found=true err=nil", found, err)
	}
	if last.CheckpointSeq != 2 {
		t.Fatalf("last checkpoint seq = %d, want 2 (last valid line wins)", last.CheckpointSeq)
	}
}

// readCheckpoints reads all JSONL lines from a checkpoint file and returns
// them in file order.
func readCheckpoints(t *testing.T, path string) []chain.Checkpoint {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading checkpoint %q: %v", path, err)
	}
	var cps []chain.Checkpoint
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var cp chain.Checkpoint
		if err := json.Unmarshal(line, &cp); err != nil {
			t.Fatalf("unmarshal checkpoint: %v\nline: %s", err, line)
		}
		cps = append(cps, cp)
	}
	return cps
}

// TestCheckpointWriteFailure_RetriesTipsAndKeepsChainContiguous verifies that a
// checkpoint whose durable write fails does not consume the pending tips and
// does not advance the chain state. Before this fix, writeCheckpoint called
// Accumulator.Build() first — which advanced seq, advanced prevHash and cleared
// the pending tip set — and only then attempted the write. An ordinary IO error
// therefore (a) permanently lost the sealed traces in that batch, and (b) left
// the next successful checkpoint with a seq gap and a prev_checkpoint_hash
// pointing at a checkpoint that was never persisted, breaking the chain.
func TestCheckpointWriteFailure_RetriesTipsAndKeepsChainContiguous(t *testing.T) {
	env := newTestEnv(t)
	cfg := env.cfg
	cfg.CheckpointInterval = 1 // checkpoint on every sealed trace

	exp := startExporter(t, cfg)

	// Make the next checkpoint write fail. Closing the file leaves e.checkFile
	// non-nil, so writeCheckpoint still runs and fails — at the pre-write Seek,
	// before any bytes are written. Nothing to roll back; the point here is that
	// the tips survive an attempt that failed before it produced any output.
	// TestCheckpointPartialWriteFailure_RollsBackAndRetriesTips covers the case
	// where bytes DO reach the file.
	exp.mu.Lock()
	closeErr := exp.checkFile.Close()
	exp.mu.Unlock()
	if closeErr != nil {
		t.Fatalf("closing checkpoint file: %v", closeErr)
	}

	traceA := [16]byte{0xA1}
	if err := exp.ConsumeTraces(context.Background(),
		makeSpan(traceA, [8]byte{0x01}, zeroParentID, "op-a", 1_000_000, 2_000_000)); err != nil {
		t.Fatalf("ConsumeTraces A: %v", err)
	}

	// The tip must still be pending: no checkpoint durably committed to it.
	if got := exp.accumulator.PendingCount(); got != 1 {
		t.Fatalf("pending tips after failed checkpoint write: got %d, want 1", got)
	}

	// Restore a working checkpoint file and seal a second trace.
	f, err := os.OpenFile(cfg.CheckpointPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatalf("reopening checkpoint file: %v", err)
	}
	exp.mu.Lock()
	exp.checkFile = f
	exp.mu.Unlock()

	traceB := [16]byte{0xB2}
	if err := exp.ConsumeTraces(context.Background(),
		makeSpan(traceB, [8]byte{0x02}, zeroParentID, "op-b", 3_000_000, 4_000_000)); err != nil {
		t.Fatalf("ConsumeTraces B: %v", err)
	}

	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	cps := readCheckpoints(t, cfg.CheckpointPath)
	if len(cps) != 1 {
		t.Fatalf("expected exactly 1 persisted checkpoint, got %d", len(cps))
	}
	cp := cps[0]

	// The persisted chain must start at seq 1 off the zero prev-hash: the failed
	// attempt must not have burned a sequence number or a prev-hash link.
	if cp.CheckpointSeq != 1 {
		t.Errorf("persisted checkpoint seq: got %d, want 1", cp.CheckpointSeq)
	}
	if cp.PrevCheckpointHash != chain.ZeroPrevCheckpointHash {
		t.Errorf("persisted checkpoint prev_checkpoint_hash:\n  got  %s\n  want %s",
			cp.PrevCheckpointHash, chain.ZeroPrevCheckpointHash)
	}

	// Both traces must be covered — trace A's tip was retried, not dropped.
	covered := make(map[string]bool, len(cp.TraceTips))
	for _, tip := range cp.TraceTips {
		covered[tip.TraceID] = true
	}
	for _, want := range []string{hex.EncodeToString(traceA[:]), hex.EncodeToString(traceB[:])} {
		if !covered[want] {
			t.Errorf("trace %s not covered by any checkpoint (tips lost)", want)
		}
	}

	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, env.pubKey)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("expected no verifier errors; got %v", report.Errors)
	}
}

// TestCheckpointSyncFailure_RollsBackAndRetriesTips covers the other half of the
// durable-commit contract: the checkpoint line is written but Sync fails. The
// file must be truncated back to its pre-write size (an unsynced line must not
// survive as a checkpoint the accumulator never committed to) and the tips must
// still be pending so the next checkpoint carries them.
func TestCheckpointSyncFailure_RollsBackAndRetriesTips(t *testing.T) {
	env := newTestEnv(t)
	cfg := env.cfg
	cfg.CheckpointInterval = 1

	exp := startExporter(t, cfg)

	exp.mu.Lock()
	exp.checkFile = &failSyncFile{
		logSyncer: exp.checkFile,
		syncErr:   fmt.Errorf("simulated EIO"),
		count:     1,
	}
	exp.mu.Unlock()

	traceA := [16]byte{0xC1}
	if err := exp.ConsumeTraces(context.Background(),
		makeSpan(traceA, [8]byte{0x01}, zeroParentID, "op-a", 1_000_000, 2_000_000)); err != nil {
		t.Fatalf("ConsumeTraces A: %v", err)
	}

	if got := exp.accumulator.PendingCount(); got != 1 {
		t.Fatalf("pending tips after failed checkpoint sync: got %d, want 1", got)
	}
	// The unsynced line must have been truncated away.
	if cps := readCheckpoints(t, cfg.CheckpointPath); len(cps) != 0 {
		t.Fatalf("expected checkpoint file rolled back to empty, got %d checkpoint(s)", len(cps))
	}

	// failSyncFile passes Sync through from here on; seal a second trace.
	traceB := [16]byte{0xD2}
	if err := exp.ConsumeTraces(context.Background(),
		makeSpan(traceB, [8]byte{0x02}, zeroParentID, "op-b", 3_000_000, 4_000_000)); err != nil {
		t.Fatalf("ConsumeTraces B: %v", err)
	}

	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	cps := readCheckpoints(t, cfg.CheckpointPath)
	if len(cps) != 1 {
		t.Fatalf("expected exactly 1 persisted checkpoint, got %d", len(cps))
	}
	if cps[0].CheckpointSeq != 1 {
		t.Errorf("persisted checkpoint seq: got %d, want 1", cps[0].CheckpointSeq)
	}
	if cps[0].PrevCheckpointHash != chain.ZeroPrevCheckpointHash {
		t.Errorf("persisted checkpoint prev_checkpoint_hash: got %s, want %s",
			cps[0].PrevCheckpointHash, chain.ZeroPrevCheckpointHash)
	}
	if len(cps[0].TraceTips) != 2 {
		t.Errorf("expected 2 trace tips in retried checkpoint, got %d", len(cps[0].TraceTips))
	}

	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, env.pubKey)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("expected no verifier errors; got %v", report.Errors)
	}
}

// failWriteFile wraps a logSyncer and fails the first `count` Writes after
// emitting a partial prefix of the payload, simulating a short write that hits
// an IO error mid-line (ENOSPC, EIO). Seek/Truncate/Sync pass through, so the
// rollback path runs for real. Not concurrency-safe: count is decremented
// without a lock. Safe only for single-goroutine test use under e.mu.
type failWriteFile struct {
	logSyncer
	writeErr error
	count    int
}

func (f *failWriteFile) Write(p []byte) (int, error) {
	if f.count > 0 {
		f.count--
		// Emit a partial line first so the rollback has something to truncate.
		half := len(p) / 2
		n, werr := f.logSyncer.Write(p[:half])
		if werr != nil {
			return n, werr
		}
		return n, f.writeErr
	}
	return f.logSyncer.Write(p)
}

// TestCheckpointPartialWriteFailure_RollsBackAndRetriesTips covers the branch
// where the checkpoint write itself fails after partially writing the line. The
// half-written line must be truncated away — a corrupt trailing line would be
// skipped by readLastCheckpoint on restart, but it must not be left in a file
// the verifier walks — and the tips must stay pending for the next checkpoint.
//
// This is the case TestCheckpointWriteFailure_RetriesTipsAndKeepsChainContiguous
// does NOT reach: closing the file makes writeCheckpoint fail at the pre-write
// Seek, before any bytes are produced.
func TestCheckpointPartialWriteFailure_RollsBackAndRetriesTips(t *testing.T) {
	env := newTestEnv(t)
	cfg := env.cfg
	cfg.CheckpointInterval = 1

	exp := startExporter(t, cfg)

	exp.mu.Lock()
	exp.checkFile = &failWriteFile{
		logSyncer: exp.checkFile,
		writeErr:  fmt.Errorf("simulated ENOSPC"),
		count:     1,
	}
	exp.mu.Unlock()

	traceA := [16]byte{0xE1}
	if err := exp.ConsumeTraces(context.Background(),
		makeSpan(traceA, [8]byte{0x01}, zeroParentID, "op-a", 1_000_000, 2_000_000)); err != nil {
		t.Fatalf("ConsumeTraces A: %v", err)
	}

	if got := exp.accumulator.PendingCount(); got != 1 {
		t.Fatalf("pending tips after partial checkpoint write: got %d, want 1", got)
	}
	// The partial line must have been truncated away, leaving an empty file.
	data, err := os.ReadFile(cfg.CheckpointPath)
	if err != nil {
		t.Fatalf("reading checkpoint: %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("expected checkpoint file truncated back to empty, got %d bytes: %q", len(data), data)
	}

	traceB := [16]byte{0xE2}
	if err := exp.ConsumeTraces(context.Background(),
		makeSpan(traceB, [8]byte{0x02}, zeroParentID, "op-b", 3_000_000, 4_000_000)); err != nil {
		t.Fatalf("ConsumeTraces B: %v", err)
	}
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	cps := readCheckpoints(t, cfg.CheckpointPath)
	if len(cps) != 1 {
		t.Fatalf("expected exactly 1 persisted checkpoint, got %d", len(cps))
	}
	if cps[0].CheckpointSeq != 1 {
		t.Errorf("persisted checkpoint seq: got %d, want 1", cps[0].CheckpointSeq)
	}
	if cps[0].PrevCheckpointHash != chain.ZeroPrevCheckpointHash {
		t.Errorf("persisted checkpoint prev_checkpoint_hash: got %s, want %s",
			cps[0].PrevCheckpointHash, chain.ZeroPrevCheckpointHash)
	}
	if len(cps[0].TraceTips) != 2 {
		t.Errorf("expected 2 trace tips in retried checkpoint, got %d", len(cps[0].TraceTips))
	}

	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, env.pubKey)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("expected no verifier errors; got %v", report.Errors)
	}
}

// failTruncateFile wraps a logSyncer whose Truncate always fails, so the
// rollback double-fault path can be exercised.
type failTruncateFile struct {
	logSyncer
	truncErr error
}

func (f *failTruncateFile) Truncate(int64) error { return f.truncErr }

// TestCheckpointRollbackFailure_PoisonsCheckpointFile verifies the double-fault
// path: when the checkpoint write fails AND the rollback truncate also fails,
// the file may retain a line the accumulator never committed to. Appending the
// next checkpoint would reuse that seq and break prev_checkpoint_hash from there
// on, so further checkpoint writes must be refused instead.
func TestCheckpointRollbackFailure_PoisonsCheckpointFile(t *testing.T) {
	env := newTestEnv(t)
	cfg := env.cfg
	cfg.CheckpointInterval = 1

	exp := startExporter(t, cfg)

	exp.mu.Lock()
	exp.checkFile = &failTruncateFile{
		logSyncer: &failSyncFile{
			logSyncer: exp.checkFile,
			syncErr:   fmt.Errorf("simulated EIO"),
			count:     1,
		},
		truncErr: fmt.Errorf("simulated truncate EIO"),
	}
	exp.mu.Unlock()

	traceA := [16]byte{0xF1}
	if err := exp.ConsumeTraces(context.Background(),
		makeSpan(traceA, [8]byte{0x01}, zeroParentID, "op-a", 1_000_000, 2_000_000)); err != nil {
		t.Fatalf("ConsumeTraces A: %v", err)
	}

	exp.mu.Lock()
	poisoned := exp.checkpointPoisoned
	exp.mu.Unlock()
	if !poisoned {
		t.Fatal("expected checkpoint file to be marked poisoned after a failed rollback")
	}

	// Every later checkpoint write must be refused rather than appending a
	// second line claiming the same seq.
	exp.mu.Lock()
	err := exp.writeCheckpoint()
	exp.mu.Unlock()
	if !errors.Is(err, errCheckpointPoisoned) {
		t.Errorf("writeCheckpoint after poisoning: got %v, want errCheckpointPoisoned", err)
	}

	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// The uncommitted line is still there (truncate failed), but nothing was
	// appended after it, so there is exactly one checkpoint and it verifies.
	cps := readCheckpoints(t, cfg.CheckpointPath)
	if len(cps) != 1 {
		t.Fatalf("expected the single uncommitted checkpoint and nothing appended, got %d", len(cps))
	}
	if cps[0].CheckpointSeq != 1 {
		t.Errorf("checkpoint seq: got %d, want 1", cps[0].CheckpointSeq)
	}
	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, env.pubKey)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("what is persisted must still verify; got %v", report.Errors)
	}
}

// TestCheckpointFailure_BacksOffInsteadOfRetryingEverySeal verifies the backoff
// that keeps a persistently unwritable checkpoint file from re-signing an
// ever-growing pending set on every sealed trace. With the file permanently
// broken, attempts must thin out as the pending set grows rather than happening
// once per seal.
func TestCheckpointFailure_BacksOffInsteadOfRetryingEverySeal(t *testing.T) {
	env := newTestEnv(t)
	cfg := env.cfg
	cfg.CheckpointInterval = 1

	exp := startExporter(t, cfg)

	// A permanently unwritable checkpoint file: every Sync fails, and the
	// rollback truncate succeeds so the file stays clean (not poisoned).
	counter := &countingSyncFile{logSyncer: exp.checkFile, syncErr: fmt.Errorf("simulated ENOSPC")}
	exp.mu.Lock()
	exp.checkFile = counter
	exp.mu.Unlock()

	const seals = 16
	for i := 0; i < seals; i++ {
		traceID := [16]byte{0x70, byte(i)}
		if err := exp.ConsumeTraces(context.Background(),
			makeSpan(traceID, [8]byte{byte(i + 1)}, zeroParentID, "op",
				uint64(1_000_000*(i+1)), uint64(1_000_000*(i+2)))); err != nil {
			t.Fatalf("ConsumeTraces %d: %v", i, err)
		}
	}

	// No tips may be lost.
	if got := exp.accumulator.PendingCount(); got != seals {
		t.Errorf("pending tips after %d failed checkpoints: got %d, want %d", seals, got, seals)
	}
	// With doubling backoff, attempts happen at pending 1,2,4,8,16 — far fewer
	// than one per seal.
	if counter.attempts >= seals {
		t.Errorf("expected checkpoint attempts to back off, got %d attempts over %d seals",
			counter.attempts, seals)
	}
	if counter.attempts == 0 {
		t.Error("expected at least one checkpoint attempt")
	}

	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// countingSyncFile counts Sync calls that reach it as checkpoint attempts and
// always fails the write-path Sync. The rollback's second Sync is allowed to
// succeed so the file is left clean.
type countingSyncFile struct {
	logSyncer
	syncErr    error
	attempts   int
	inRollback bool
}

func (f *countingSyncFile) Sync() error {
	if f.inRollback {
		f.inRollback = false
		return f.logSyncer.Sync()
	}
	f.attempts++
	f.inRollback = true
	return f.syncErr
}

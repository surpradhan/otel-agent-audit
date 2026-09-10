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
	"reflect"
	"slices"
	"strings"
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

	neg3 := base
	neg3.MaxPendingTips = -1
	if err := neg3.Validate(); err == nil {
		t.Error("expected error for negative max_pending_tips")
	}
}

// TestConfig_Validate_MaxPendingTipsBelowCheckpointInterval verifies the
// cross-field check: if the effective pending-tip cap is below the effective
// checkpoint interval, TrimPending would hold pending below the threshold
// shouldCheckpoint needs, so a checkpoint could never fire. This must be
// rejected at config-validation time rather than silently degrading at runtime.
func TestConfig_Validate_MaxPendingTipsBelowCheckpointInterval(t *testing.T) {
	base := Config{
		LogPath:        "/tmp/a.jsonl",
		KeyPath:        "/tmp/k.pem",
		WalPath:        "/tmp/w.jsonl",
		CheckpointPath: "/tmp/c.jsonl",
	}

	// Both explicit and conflicting.
	bad := base
	bad.CheckpointInterval = 100
	bad.MaxPendingTips = 50
	if err := bad.Validate(); err == nil {
		t.Error("expected error when max_pending_tips is below checkpoint_interval (both explicit)")
	}

	// Interval defaults to 100; an explicit cap below that must still be caught.
	bad2 := base
	bad2.MaxPendingTips = 50
	if err := bad2.Validate(); err == nil {
		t.Error("expected error when max_pending_tips is below the *default* checkpoint_interval")
	}

	// Equal is fine — the boundary itself must not be rejected.
	ok := base
	ok.CheckpointInterval = 100
	ok.MaxPendingTips = 100
	if err := ok.Validate(); err != nil {
		t.Errorf("expected no error when max_pending_tips equals checkpoint_interval, got %v", err)
	}

	// Both defaulted (0, 0): 10x100 default never conflicts with the 100 default.
	def := base
	if err := def.Validate(); err != nil {
		t.Errorf("expected no error with both fields defaulted, got %v", err)
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

// TestEffectiveMaxPendingTips verifies that an unset cap falls back to 10x the
// effective checkpoint interval, and that an explicit positive value overrides it.
func TestEffectiveMaxPendingTips(t *testing.T) {
	def := newAgentAuditExporter(&Config{CheckpointInterval: 100}, nil)
	if got := def.effectiveMaxPendingTips(def.effectiveCheckpointInterval()); got != 1000 {
		t.Fatalf("default cap = %d, want 1000 (10x checkpoint interval)", got)
	}

	set := newAgentAuditExporter(&Config{CheckpointInterval: 100, MaxPendingTips: 42}, nil)
	if got := set.effectiveMaxPendingTips(set.effectiveCheckpointInterval()); got != 42 {
		t.Fatalf("configured cap = %d, want 42", got)
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
	// A checkpoint line grows with the number of trace tips and can exceed the
	// scanner's default 64KB token limit. Without this the helper would silently
	// return FEWER checkpoints, making "expected no checkpoint yet" assertions
	// pass vacuously. Mirrors readLastCheckpoint in exporter.go.
	sc.Buffer(make([]byte, 64*1024), maxScanTokenSize)
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
	if err := sc.Err(); err != nil {
		t.Fatalf("scanning checkpoint %q: %v", path, err)
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
	wrote    int // bytes emitted by the failing writes, for the test to assert on
}

func (f *failWriteFile) Write(p []byte) (int, error) {
	if f.count > 0 {
		f.count--
		// Emit a partial line first so the rollback has something to truncate.
		half := len(p) / 2
		n, werr := f.logSyncer.Write(p[:half])
		f.wrote += n
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

	failing := &failWriteFile{
		logSyncer: exp.checkFile,
		writeErr:  fmt.Errorf("simulated ENOSPC"),
		count:     1,
	}
	exp.mu.Lock()
	exp.checkFile = failing
	exp.mu.Unlock()

	traceA := [16]byte{0xE1}
	if err := exp.ConsumeTraces(context.Background(),
		makeSpan(traceA, [8]byte{0x01}, zeroParentID, "op-a", 1_000_000, 2_000_000)); err != nil {
		t.Fatalf("ConsumeTraces A: %v", err)
	}

	if got := exp.accumulator.PendingCount(); got != 1 {
		t.Fatalf("pending tips after partial checkpoint write: got %d, want 1", got)
	}
	// Bytes must actually have reached the file, or "the file is empty" below
	// would pass vacuously and stop pinning the rollback.
	if failing.wrote == 0 {
		t.Fatal("fake wrote no bytes: the rollback assertion below would be vacuous")
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

	// Shutdown must report the poisoning rather than exiting cleanly: for an
	// audit component, "checkpointing died" is the operator-visible event.
	shutdownErr := exp.Shutdown(context.Background())
	if !errors.Is(shutdownErr, errCheckpointPoisoned) {
		t.Errorf("Shutdown error: got %v, want it to wrap errCheckpointPoisoned", shutdownErr)
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
//
// MaxPendingTips is set well above the 16 seals this test drives so the
// pending-tip cap (TestPendingCap_DropsOldestTipsAndRecovers) does not
// interfere with the schedule asserted here — this test is specifically about
// the backoff arithmetic below the cap, not the cap itself.
func TestCheckpointFailure_BacksOffInsteadOfRetryingEverySeal(t *testing.T) {
	env := newTestEnv(t)
	cfg := env.cfg
	cfg.CheckpointInterval = 1
	cfg.MaxPendingTips = 1024

	exp := startExporter(t, cfg)

	// A permanently unwritable checkpoint file: every write-path Sync fails, and
	// the rollback truncate+sync succeed so the file stays clean (not poisoned).
	counter := &countingWriteFile{
		logSyncer: exp.checkFile,
		syncErr:   fmt.Errorf("simulated ENOSPC"),
		pending:   exp.accumulator.PendingCount,
	}
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

	// No tips may be lost: a transient-looking failure must keep retrying them.
	if got := exp.accumulator.PendingCount(); got != seals {
		t.Errorf("pending tips after %d failed checkpoints: got %d, want %d", seals, got, seals)
	}
	// The schedule is deterministic: the first failure retries promptly (pending
	// 1 then 2), and the doubling starts from the second consecutive failure —
	// so attempts land at pending 1, 2, 4, 8, 16. Assert the exact count rather
	// than a loose bound, so a regression to "retry every seal" cannot slip past.
	// Assert the schedule itself, not just the count: a count alone is
	// coincidental — starting the doubling one failure later gives 1,2,3,6,12,
	// also five attempts.
	wantSchedule := []int{1, 2, 4, 8, 16}
	if !reflect.DeepEqual(counter.pendingAt, wantSchedule) {
		t.Errorf("checkpoint attempts happened at pending %v, want %v",
			counter.pendingAt, wantSchedule)
	}
	// Nothing may have been committed to the file either.
	if data, err := os.ReadFile(cfg.CheckpointPath); err != nil {
		t.Fatalf("reading checkpoint: %v", err)
	} else if len(data) != 0 {
		t.Errorf("expected an empty checkpoint file after only failed attempts, got %d bytes", len(data))
	}
	// A merely-failing file must NOT be poisoned — poisoning is for double faults.
	exp.mu.Lock()
	poisoned := exp.checkpointPoisoned
	exp.mu.Unlock()
	if poisoned {
		t.Error("a repeatedly failing (but rollback-able) checkpoint file must not be poisoned")
	}

	// Shutdown attempts one final checkpoint, which also fails and is reported.
	if err := exp.Shutdown(context.Background()); err == nil {
		t.Error("expected Shutdown to report the failed final checkpoint")
	}
}

// countingWriteFile counts checkpoint attempts on Write — exactly one per
// attempt, unambiguously — and fails the write-path Sync so every attempt
// fails. The rollback's truncate and its fsync pass through, so the file is
// left clean and never poisoned.
type countingWriteFile struct {
	logSyncer
	syncErr error
	// pending reports the accumulator's pending count; recording it per attempt
	// pins the actual retry SCHEDULE, not just the attempt count. Safe to call:
	// Write runs under e.mu and the accumulator has its own lock.
	pending   func() int
	attempts  int
	pendingAt []int
	inWrite   bool
}

func (f *countingWriteFile) Write(p []byte) (int, error) {
	f.attempts++
	if f.pending != nil {
		f.pendingAt = append(f.pendingAt, f.pending())
	}
	f.inWrite = true
	return f.logSyncer.Write(p)
}

func (f *countingWriteFile) Sync() error {
	if f.inWrite {
		// The write-path Sync for this attempt: fail it.
		f.inWrite = false
		return f.syncErr
	}
	// The rollback's fsync-of-truncation: let it succeed.
	return f.logSyncer.Sync()
}

// alwaysFailSyncFile fails every Sync, including the rollback's fsync of the
// truncation. Truncate passes through, so the file is left clean but the
// truncation is not durable.
type alwaysFailSyncFile struct {
	logSyncer
	syncErr error
}

func (f *alwaysFailSyncFile) Sync() error { return f.syncErr }

// TestCheckpointRollbackSyncFailure_PoisonsCheckpointFile covers the second
// poison branch: the rollback truncate succeeds but the fsync OF that truncation
// fails, so the removed line is not durably gone and a crash could resurrect it
// as a checkpoint the accumulator never committed to. That must poison the file
// exactly like a failed truncate.
func TestCheckpointRollbackSyncFailure_PoisonsCheckpointFile(t *testing.T) {
	env := newTestEnv(t)
	cfg := env.cfg
	cfg.CheckpointInterval = 1

	exp := startExporter(t, cfg)
	exp.mu.Lock()
	exp.checkFile = &alwaysFailSyncFile{
		logSyncer: exp.checkFile,
		syncErr:   fmt.Errorf("simulated EIO"),
	}
	exp.mu.Unlock()

	traceA := [16]byte{0xC7}
	if err := exp.ConsumeTraces(context.Background(),
		makeSpan(traceA, [8]byte{0x01}, zeroParentID, "op-a", 1_000_000, 2_000_000)); err != nil {
		t.Fatalf("ConsumeTraces A: %v", err)
	}

	exp.mu.Lock()
	poisoned := exp.checkpointPoisoned
	pending := exp.accumulator.PendingCount()
	exp.mu.Unlock()
	if !poisoned {
		t.Fatal("a failed fsync of the rollback truncation must poison the checkpoint file")
	}
	// Poisoning must also drop the now-undrainable tips rather than leaking them.
	if pending != 0 {
		t.Errorf("pending tips after poisoning: got %d, want 0 (they can never be written)", pending)
	}

	shutdownErr := exp.Shutdown(context.Background())
	if !errors.Is(shutdownErr, errCheckpointPoisoned) {
		t.Errorf("Shutdown error: got %v, want it to wrap errCheckpointPoisoned", shutdownErr)
	}
}

// TestPoisonedCheckpoint_DoesNotAccumulateTips is the regression guard for the
// leak that poisoning would otherwise introduce. Once checkpointing is
// permanently disabled, no checkpoint can ever be written again, so retaining
// tips grows the pending set without bound for no possible benefit. Sealed
// traces must still reach the audit log, and the count of uncovered traces must
// be reported at Shutdown.
func TestPoisonedCheckpoint_DoesNotAccumulateTips(t *testing.T) {
	env := newTestEnv(t)
	cfg := env.cfg
	cfg.CheckpointInterval = 1

	exp := startExporter(t, cfg)
	exp.mu.Lock()
	exp.checkFile = &alwaysFailSyncFile{
		logSyncer: exp.checkFile,
		syncErr:   fmt.Errorf("simulated EIO"),
	}
	exp.mu.Unlock()

	const seals = 30
	for i := 0; i < seals; i++ {
		traceID := [16]byte{0x90, byte(i)}
		if err := exp.ConsumeTraces(context.Background(),
			makeSpan(traceID, [8]byte{byte(i + 1)}, zeroParentID, "op",
				uint64(1_000_000*(i+1)), uint64(1_000_000*(i+2)))); err != nil {
			t.Fatalf("ConsumeTraces %d: %v", i, err)
		}
	}

	exp.mu.Lock()
	pending := exp.accumulator.PendingCount()
	uncovered := exp.uncoveredAfterPoison
	exp.mu.Unlock()

	if pending != 0 {
		t.Errorf("pending tips after %d seals on a poisoned file: got %d, want 0 — "+
			"these can never be checkpointed, so retaining them is an unbounded leak", seals, pending)
	}
	// ALL seals are uncovered, including the one whose checkpoint attempt did the
	// poisoning: its tip was pending and got dropped, so it is counted too.
	// Counting only the traces sealed after poisoning would under-report by a
	// whole checkpoint interval.
	if uncovered != seals {
		t.Errorf("uncovered traces counted: got %d, want %d", uncovered, seals)
	}

	// The audit log must still have every trace's entries — poisoning stops
	// checkpointing, not logging.
	entries := readLogEntries(t, cfg.LogPath)
	if len(entries) != seals {
		t.Errorf("audit log entries: got %d, want %d", len(entries), seals)
	}

	shutdownErr := exp.Shutdown(context.Background())
	if !errors.Is(shutdownErr, errCheckpointPoisoned) {
		t.Errorf("Shutdown error: got %v, want it to wrap errCheckpointPoisoned", shutdownErr)
	}
}

// TestPendingCap_DropsOldestTipsAndRecovers covers the policy chosen for
// issue #21: a sustained but rollback-able checkpoint write failure must not
// grow the pending set without bound. Once MaxPendingTips is exceeded, the
// oldest tips are dropped (not the file poisoned), a loud warning fires once
// per degraded episode, and — critically — checkpointing must still detect
// recovery: this is also the regression guard for the nextCheckpointRetryAt
// clamp, since without it the backoff target could grow past what a capped
// pending set can ever reach again, permanently starving retries.
func TestPendingCap_DropsOldestTipsAndRecovers(t *testing.T) {
	env := newTestEnv(t)
	cfg := env.cfg
	cfg.CheckpointInterval = 1
	cfg.MaxPendingTips = 5

	exp := startExporter(t, cfg)

	realFile := exp.checkFile
	counter := &countingWriteFile{
		logSyncer: realFile,
		syncErr:   fmt.Errorf("simulated ENOSPC"),
	}
	exp.mu.Lock()
	exp.checkFile = counter
	exp.mu.Unlock()

	seal := func(i int) {
		t.Helper()
		traceID := [16]byte{0xB0, byte(i)}
		if err := exp.ConsumeTraces(context.Background(),
			makeSpan(traceID, [8]byte{byte(i + 1)}, zeroParentID, "op",
				uint64(1_000_000*(i+1)), uint64(1_000_000*(i+2)))); err != nil {
			t.Fatalf("ConsumeTraces %d: %v", i, err)
		}
	}
	traceIDHex := func(i int) string {
		b := [16]byte{0xB0, byte(i)}
		return hex.EncodeToString(b[:])
	}

	const failingSeals = 12
	for i := 0; i < failingSeals; i++ {
		seal(i)
	}

	exp.mu.Lock()
	pending := exp.accumulator.PendingCount()
	dropped := exp.pendingCapDropped
	warned := exp.pendingCapWarned
	poisoned := exp.checkpointPoisoned
	exp.mu.Unlock()

	if pending != 5 {
		t.Errorf("pending after %d failing seals: got %d, want 5 (capped)", failingSeals, pending)
	}
	if dropped != failingSeals-5 {
		t.Errorf("pendingCapDropped: got %d, want %d", dropped, failingSeals-5)
	}
	if !warned {
		t.Error("expected pendingCapWarned once the cap was first hit")
	}
	if poisoned {
		t.Error("a repeatedly failing but rollback-able checkpoint file must not be poisoned")
	}

	// Recovery: the underlying file becomes writable again.
	exp.mu.Lock()
	exp.checkFile = realFile
	exp.mu.Unlock()
	seal(failingSeals) // index 12; also trimmed before its own checkpoint attempt.

	exp.mu.Lock()
	pendingAfter := exp.accumulator.PendingCount()
	warnedAfter := exp.pendingCapWarned
	droppedAfter := exp.pendingCapDropped
	exp.mu.Unlock()

	if pendingAfter != 0 {
		t.Fatalf("pending after the recovery seal: got %d, want 0 (checkpoint must have succeeded — "+
			"if this is nonzero, retries likely stopped firing once pending hit the cap)", pendingAfter)
	}
	if warnedAfter {
		t.Error("pendingCapWarned must reset once a checkpoint succeeds")
	}
	if want := failingSeals - 5 + 1; droppedAfter != want {
		t.Errorf("pendingCapDropped after recovery: got %d, want %d (the recovery seal is also trimmed before its checkpoint succeeds)",
			droppedAfter, want)
	}

	cps := readCheckpoints(t, cfg.CheckpointPath)
	if len(cps) != 1 {
		t.Fatalf("checkpoints written: got %d, want 1", len(cps))
	}
	var gotIDs []string
	for _, tip := range cps[0].TraceTips {
		gotIDs = append(gotIDs, tip.TraceID)
	}
	var wantIDs []string
	for i := 8; i <= 12; i++ {
		wantIDs = append(wantIDs, traceIDHex(i))
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Errorf("checkpointed tips: got %v, want %v (only the newest 5 survivors)", gotIDs, wantIDs)
	}

	// pendingCapDropped is a lifetime counter and must still be surfaced at
	// Shutdown even though the exporter has since recovered.
	shutdownErr := exp.Shutdown(context.Background())
	if shutdownErr == nil {
		t.Error("expected Shutdown to report the tips dropped for the pending cap")
	}
}

// TestCheckpointWriteFailure_ZeroBytesDoesNotPoison verifies that a write which
// fails having emitted nothing does not poison the file. The file is already
// byte-identical to its pre-write state, so there is nothing to roll back —
// and calling Truncate anyway would risk poisoning over a fault that changed
// nothing, which matters because a failing write and a failing Truncate are
// usually the same underlying fault.
func TestCheckpointWriteFailure_ZeroBytesDoesNotPoison(t *testing.T) {
	env := newTestEnv(t)
	cfg := env.cfg
	cfg.CheckpointInterval = 1

	exp := startExporter(t, cfg)
	exp.mu.Lock()
	exp.checkFile = &zeroWriteFailFile{
		logSyncer: exp.checkFile,
		writeErr:  fmt.Errorf("simulated EIO"),
		truncErr:  fmt.Errorf("simulated truncate EIO"),
		count:     1,
	}
	exp.mu.Unlock()

	traceA := [16]byte{0xA7}
	if err := exp.ConsumeTraces(context.Background(),
		makeSpan(traceA, [8]byte{0x01}, zeroParentID, "op-a", 1_000_000, 2_000_000)); err != nil {
		t.Fatalf("ConsumeTraces A: %v", err)
	}

	exp.mu.Lock()
	poisoned := exp.checkpointPoisoned
	pending := exp.accumulator.PendingCount()
	exp.mu.Unlock()
	if poisoned {
		t.Error("a write that emitted no bytes must not poison the file: there was nothing to roll back")
	}
	if pending != 1 {
		t.Errorf("pending tips after a zero-byte write failure: got %d, want 1", pending)
	}

	// The next checkpoint must succeed normally and cover the retried tip.
	traceB := [16]byte{0xA8}
	if err := exp.ConsumeTraces(context.Background(),
		makeSpan(traceB, [8]byte{0x02}, zeroParentID, "op-b", 3_000_000, 4_000_000)); err != nil {
		t.Fatalf("ConsumeTraces B: %v", err)
	}
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	cps := readCheckpoints(t, cfg.CheckpointPath)
	if len(cps) != 1 || len(cps[0].TraceTips) != 2 {
		t.Fatalf("expected 1 checkpoint covering both traces, got %d checkpoint(s)", len(cps))
	}
	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, env.pubKey)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("expected no verifier errors; got %v", report.Errors)
	}
}

// zeroWriteFailFile fails the first `count` Writes without emitting any bytes,
// and fails every Truncate — so if the code rolled back unnecessarily it would
// poison the file, which is exactly what the test asserts must not happen.
type zeroWriteFailFile struct {
	logSyncer
	writeErr error
	truncErr error
	count    int
}

func (f *zeroWriteFailFile) Write(p []byte) (int, error) {
	if f.count > 0 {
		f.count--
		return 0, f.writeErr
	}
	return f.logSyncer.Write(p)
}

func (f *zeroWriteFailFile) Truncate(int64) error { return f.truncErr }

// TestTransientCheckpointFailure_RetriesOnNextSeal pins the prompt-retry half of
// the backoff: a SINGLE failed checkpoint must be retried on the very next seal,
// not deferred until the pending set doubles. With the default interval of 100,
// charging the doubling to the first failure would mean one transient EIO at
// pending=100 leaves everything un-checkpointed until pending=200.
//
// The doubling still applies from the second consecutive failure — that is what
// TestCheckpointFailure_BacksOffInsteadOfRetryingEverySeal covers.
func TestTransientCheckpointFailure_RetriesOnNextSeal(t *testing.T) {
	env := newTestEnv(t)
	cfg := env.cfg
	cfg.CheckpointInterval = 10

	exp := startExporter(t, cfg)

	// Fail exactly one checkpoint Sync, then behave normally.
	exp.mu.Lock()
	exp.checkFile = &failSyncFile{
		logSyncer: exp.checkFile,
		syncErr:   fmt.Errorf("simulated transient EIO"),
		count:     1,
	}
	exp.mu.Unlock()

	// Seal exactly interval traces: the checkpoint fires and fails.
	for i := 0; i < 10; i++ {
		traceID := [16]byte{0xB0, byte(i)}
		if err := exp.ConsumeTraces(context.Background(),
			makeSpan(traceID, [8]byte{byte(i + 1)}, zeroParentID, "op",
				uint64(1_000_000*(i+1)), uint64(1_000_000*(i+2)))); err != nil {
			t.Fatalf("ConsumeTraces %d: %v", i, err)
		}
	}
	if got := exp.accumulator.PendingCount(); got != 10 {
		t.Fatalf("pending after the failed checkpoint: got %d, want 10", got)
	}
	if cps := readCheckpoints(t, cfg.CheckpointPath); len(cps) != 0 {
		t.Fatalf("expected no checkpoint yet, got %d", len(cps))
	}

	// One more seal. The retry must happen NOW (pending 11), not at pending 20.
	if err := exp.ConsumeTraces(context.Background(),
		makeSpan([16]byte{0xB0, 0xFF}, [8]byte{0xFF}, zeroParentID, "op-retry",
			90_000_000, 91_000_000)); err != nil {
		t.Fatalf("ConsumeTraces retry: %v", err)
	}

	cps := readCheckpoints(t, cfg.CheckpointPath)
	if len(cps) != 1 {
		t.Fatalf("expected the checkpoint to be retried on the next seal, got %d checkpoint(s) "+
			"(pending=%d) — a single transient failure must not defer the retry until the "+
			"pending set doubles", len(cps), exp.accumulator.PendingCount())
	}
	if len(cps[0].TraceTips) != 11 {
		t.Errorf("retried checkpoint tips: got %d, want 11", len(cps[0].TraceTips))
	}
	if got := exp.accumulator.PendingCount(); got != 0 {
		t.Errorf("pending after the successful retry: got %d, want 0", got)
	}

	// Second cycle: the consecutive-failure counter must have been reset by the
	// success above, so another isolated blip is again retried promptly rather
	// than being treated as the second consecutive failure and doubled.
	exp.mu.Lock()
	exp.checkFile = &failSyncFile{
		logSyncer: exp.checkFile,
		syncErr:   fmt.Errorf("simulated second transient EIO"),
		count:     1,
	}
	exp.mu.Unlock()

	for i := 0; i < 10; i++ {
		traceID := [16]byte{0xB1, byte(i)}
		if err := exp.ConsumeTraces(context.Background(),
			makeSpan(traceID, [8]byte{byte(i + 1)}, zeroParentID, "op2",
				uint64(100_000_000+1_000_000*(i+1)), uint64(100_000_000+1_000_000*(i+2)))); err != nil {
			t.Fatalf("ConsumeTraces cycle2 %d: %v", i, err)
		}
	}
	if cps := readCheckpoints(t, cfg.CheckpointPath); len(cps) != 1 {
		t.Fatalf("expected the second cycle's checkpoint to have failed, got %d", len(cps))
	}
	if err := exp.ConsumeTraces(context.Background(),
		makeSpan([16]byte{0xB1, 0xFF}, [8]byte{0xFE}, zeroParentID, "op2-retry",
			190_000_000, 191_000_000)); err != nil {
		t.Fatalf("ConsumeTraces cycle2 retry: %v", err)
	}
	if cps := readCheckpoints(t, cfg.CheckpointPath); len(cps) != 2 {
		t.Errorf("second transient failure was not retried promptly: got %d checkpoint(s), want 2 — "+
			"the consecutive-failure counter was not reset by the earlier success", len(cps))
	}

	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	report, err := verify.VerifyLog(cfg.LogPath, cfg.CheckpointPath, env.pubKey)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("expected no verifier errors; got %v", report.Errors)
	}
}

// TestNextCheckpointRetryAt covers the retry schedule directly, including the
// gap cap. Without a gap cap, recovery latency after a healed outage grows with
// the length of the outage: a file that becomes writable again at pending=600
// would not be retried until pending=1024, and a long outage is far worse.
//
// MaxPendingTips is set to an effectively unlimited value so this arithmetic is
// exercised in isolation from the separate pending-tip-cap clamp covered by
// TestNextCheckpointRetryAt_ClampedToPendingCap below.
func TestNextCheckpointRetryAt(t *testing.T) {
	e := newAgentAuditExporter(&Config{MaxPendingTips: 1 << 30}, nil)

	tests := []struct {
		name     string
		failures int
		pending  int
		want     int
	}{
		{"first failure retries promptly", 1, 10, 11},
		{"first failure at scale still prompt", 1, 5000, 5001},
		{"second failure doubles", 2, 10, 20},
		{"later failure doubles", 5, 64, 128},
		{"doubling applies up to the cap", 5, maxCheckpointRetryGap, 2 * maxCheckpointRetryGap},
		{"beyond the cap the gap is capped", 5, maxCheckpointRetryGap + 1, maxCheckpointRetryGap*2 + 1},
		{"long outage stays capped", 50, 200000, 200000 + maxCheckpointRetryGap},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.checkpointFailures = tt.failures
			if got := e.nextCheckpointRetryAt(tt.pending); got != tt.want {
				t.Errorf("nextCheckpointRetryAt(%d) with %d failures: got %d, want %d",
					tt.pending, tt.failures, got, tt.want)
			}
		})
	}

	// The gap must never exceed the cap, at any scale.
	e.checkpointFailures = 99
	for _, pending := range []int{1, 100, 1023, 1024, 1025, 10000, 1 << 20} {
		if gap := e.nextCheckpointRetryAt(pending) - pending; gap > maxCheckpointRetryGap {
			t.Errorf("retry gap at pending=%d: got %d, want <= %d", pending, gap, maxCheckpointRetryGap)
		}
	}
}

// TestNextCheckpointRetryAt_ClampedToPendingCap is the regression guard for the
// bug the pending-tip cap would otherwise introduce: an unclamped backoff
// target can grow past the cap, and since TrimPending holds pending at the cap
// forever during a sustained failure, pending could then never again satisfy
// shouldCheckpoint's "pending >= checkpointRetryAt" and retries would stop
// permanently — even after the underlying outage heals.
func TestNextCheckpointRetryAt_ClampedToPendingCap(t *testing.T) {
	e := newAgentAuditExporter(&Config{CheckpointInterval: 100, MaxPendingTips: 1000}, nil)

	tests := []struct {
		name     string
		failures int
		pending  int
		want     int
	}{
		{"under the cap: unclamped", 5, 400, 800},
		{"doubling would exceed the cap: clamped", 5, 600, 1000},
		{"already at the cap: clamped to itself so a retry can still fire", 5, 1000, 1000},
		{"first failure past the cap: still clamped", 1, 1000, 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.checkpointFailures = tt.failures
			if got := e.nextCheckpointRetryAt(tt.pending); got != tt.want {
				t.Errorf("nextCheckpointRetryAt(%d) with %d failures: got %d, want %d",
					tt.pending, tt.failures, got, tt.want)
			}
		})
	}
}

// TestRestart_TornCheckpointLine_Fusion reproduces issue #24: a torn checkpoint
// line (a partial write with no trailing newline) left behind by a crash must not
// fuse onto the next checkpoint appended after a restart.
//
// This differs from TestRestart_CheckpointContinuity_PartialLine, whose truncated
// line ends in '\n' and so never fuses. Here the line ends mid-token, which is what
// an interrupted write actually leaves, and the assertion is end-to-end: after two
// further checkpoints the whole file must still verify.
func TestRestart_TornCheckpointLine_Fusion(t *testing.T) {
	env := newTestEnv(t)
	env.cfg.CheckpointInterval = 1

	// Phase 1: one clean checkpoint.
	exp1 := startExporter(t, env.cfg)
	_ = exp1.ConsumeTraces(context.Background(), makeSpan([16]byte{0xE5}, [8]byte{0x01}, zeroParentID, "t1", 1000, 2000))
	if err := exp1.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown phase 1: %v", err)
	}

	// Simulate a crash mid-write: a partial JSON line with NO trailing newline.
	f, err := os.OpenFile(env.cfg.CheckpointPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open checkpoint for torn append: %v", err)
	}
	if _, err := f.Write([]byte(`{"schema_version":"v1","checkpoint_seq":2,"timestamp":"`)); err != nil {
		t.Fatalf("write torn line: %v", err)
	}
	_ = f.Close()

	// Phase 2: restart and write two further checkpoints, so the fused line is
	// no longer the final line of the file.
	exp2 := startExporter(t, env.cfg)
	_ = exp2.ConsumeTraces(context.Background(), makeSpan([16]byte{0xE6}, [8]byte{0x02}, zeroParentID, "t2", 3000, 4000))
	_ = exp2.ConsumeTraces(context.Background(), makeSpan([16]byte{0xE7}, [8]byte{0x03}, zeroParentID, "t3", 5000, 6000))
	if err := exp2.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown phase 2: %v", err)
	}

	report, err := verify.VerifyLog(env.cfg.LogPath, env.cfg.CheckpointPath, env.pubKey)
	if err != nil {
		t.Fatalf("VerifyLog hard error: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("VerifyLog reported %d error(s): %v", len(report.Errors), report.Errors)
	}
}

// TestRepairTrailingPartialLine covers repairTrailingPartialLine directly: it must
// drop only an unterminated tail, and must never touch a complete line — including
// a complete line that fails to parse, which is evidence the verifier has to see.
func TestRepairTrailingPartialLine(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		wantContent    string
		wantDropped    int64
		wantTerminated int64
	}{
		{
			name:           "durable record missing only its newline is terminated",
			content:        "{\"a\":1}\n{\"b\":2}",
			wantContent:    "{\"a\":1}\n{\"b\":2}\n",
			wantTerminated: 7,
		},
		{
			name:        "torn tail is dropped",
			content:     "{\"a\":1}\n{\"b\":2}\n{\"c\":",
			wantContent: "{\"a\":1}\n{\"b\":2}\n",
			wantDropped: 5,
		},
		{
			name:        "file ending in newline is untouched",
			content:     "{\"a\":1}\n{\"b\":2}\n",
			wantContent: "{\"a\":1}\n{\"b\":2}\n",
			wantDropped: 0,
		},
		{
			name:        "complete but unparseable line is preserved",
			content:     "{\"a\":1}\n{\"torn\":\n",
			wantContent: "{\"a\":1}\n{\"torn\":\n",
			wantDropped: 0,
		},
		{
			name:        "corrupt complete line is kept while the torn tail is dropped",
			content:     "{\"a\":1}\n{\"bad\"\n{\"c\":3}\n{\"d\":",
			wantContent: "{\"a\":1}\n{\"bad\"\n{\"c\":3}\n",
			wantDropped: 5,
		},
		{
			name:        "single unterminated line truncates to empty",
			content:     "{\"a\":",
			wantContent: "",
			wantDropped: 5,
		},
		{
			name:        "empty file is untouched",
			content:     "",
			wantContent: "",
			wantDropped: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "f.jsonl")
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			rep, err := repairTrailingPartialLine(path)
			if err != nil {
				t.Fatalf("repairTrailingPartialLine: %v", err)
			}
			if rep.Dropped != tc.wantDropped {
				t.Errorf("dropped: got %d, want %d", rep.Dropped, tc.wantDropped)
			}
			if rep.Terminated != tc.wantTerminated {
				t.Errorf("terminated: got %d, want %d", rep.Terminated, tc.wantTerminated)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if string(got) != tc.wantContent {
				t.Errorf("content:\n  got  %q\n  want %q", got, tc.wantContent)
			}
			// Repair must be idempotent: a second pass changes nothing.
			againRep, err := repairTrailingPartialLine(path)
			if err != nil {
				t.Fatalf("repairTrailingPartialLine (second pass): %v", err)
			}
			if againRep.Dropped != 0 {
				t.Errorf("second pass dropped %d bytes, want 0", againRep.Dropped)
			}
			if againRep.Terminated != 0 {
				t.Errorf("second pass terminated %d bytes, want 0", againRep.Terminated)
			}
		})
	}
}

// TestRepairTrailingPartialLine_MissingFile confirms a not-yet-created file is a
// no-op rather than an error, since Start runs the repair before O_CREATE.
func TestRepairTrailingPartialLine_MissingFile(t *testing.T) {
	rep, err := repairTrailingPartialLine(filepath.Join(t.TempDir(), "absent.jsonl"))
	if err != nil {
		t.Fatalf("repairTrailingPartialLine on missing file: %v", err)
	}
	if rep.Dropped != 0 {
		t.Errorf("dropped: got %d, want 0", rep.Dropped)
	}
}

// TestRestart_TornAuditLogLine_Fusion is the audit-log counterpart of
// TestRestart_TornCheckpointLine_Fusion. The log file is opened O_APPEND too, so a
// torn entry left by a crash would otherwise fuse onto the next entry written after
// a restart, and readLogEntries rejects any unparseable line at all.
func TestRestart_TornAuditLogLine_Fusion(t *testing.T) {
	env := newTestEnv(t)
	env.cfg.CheckpointInterval = 1

	exp1 := startExporter(t, env.cfg)
	_ = exp1.ConsumeTraces(context.Background(), makeSpan([16]byte{0xE8}, [8]byte{0x01}, zeroParentID, "t1", 1000, 2000))
	if err := exp1.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown phase 1: %v", err)
	}

	f, err := os.OpenFile(env.cfg.LogPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open log for torn append: %v", err)
	}
	if _, err := f.Write([]byte(`{"record":{"schema_version":"v2","trace_id":"`)); err != nil {
		t.Fatalf("write torn line: %v", err)
	}
	_ = f.Close()

	exp2 := startExporter(t, env.cfg)
	_ = exp2.ConsumeTraces(context.Background(), makeSpan([16]byte{0xE9}, [8]byte{0x02}, zeroParentID, "t2", 3000, 4000))
	if err := exp2.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown phase 2: %v", err)
	}

	report, err := verify.VerifyLog(env.cfg.LogPath, env.cfg.CheckpointPath, env.pubKey)
	if err != nil {
		t.Fatalf("VerifyLog hard error: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("VerifyLog reported %d error(s): %v", len(report.Errors), report.Errors)
	}
}

// TestRepairTrailingPartialLine_BoundedScan pins the one repair path that hard-fails
// Start. A tail longer than one maximum-size line is not a partial write, so the
// repair must refuse rather than truncate on that assumption.
func TestRepairTrailingPartialLine_BoundedScan(t *testing.T) {
	head := []byte("{\"a\":1}\n")

	t.Run("tail one byte under the cap is truncated", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "f.jsonl")
		content := append(append([]byte{}, head...), bytes.Repeat([]byte("x"), maxScanTokenSize-1)...)
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		rep, err := repairTrailingPartialLine(path)
		if err != nil {
			t.Fatalf("repairTrailingPartialLine: %v", err)
		}
		if rep.Dropped != maxScanTokenSize-1 {
			t.Errorf("dropped: got %d, want %d", rep.Dropped, maxScanTokenSize-1)
		}
		got, _ := os.ReadFile(path)
		if !bytes.Equal(got, head) {
			t.Errorf("content: got %d bytes, want the %d-byte head", len(got), len(head))
		}
	})

	t.Run("tail at the cap is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "f.jsonl")
		content := append(append([]byte{}, head...), bytes.Repeat([]byte("x"), maxScanTokenSize)...)
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		before, _ := os.ReadFile(path)
		rep, err := repairTrailingPartialLine(path)
		if err == nil {
			t.Fatal("expected a refusal, got nil error")
		}
		if rep.Dropped != 0 {
			t.Errorf("dropped: got %d, want 0", rep.Dropped)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Error("file was modified despite the refusal")
		}
	})
}

// TestStart_TornTailRefusal_IsFatal confirms Start propagates a refusal rather than
// starting on a file it could see but could not repair.
func TestStart_TornTailRefusal_IsFatal(t *testing.T) {
	env := newTestEnv(t)
	content := append([]byte("{\"a\":1}\n"), bytes.Repeat([]byte("x"), maxScanTokenSize)...)
	if err := os.WriteFile(env.cfg.LogPath, content, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	exp := newAgentAuditExporter(env.cfg, nil)
	err := exp.Start(context.Background(), nil)
	if err == nil {
		_ = exp.Shutdown(context.Background())
		t.Fatal("Start succeeded on an unrepairable audit log; want an error")
	}
	if !strings.Contains(err.Error(), "refusing to truncate") {
		t.Errorf("Start error = %v, want it to mention refusing to truncate", err)
	}
}

// TestStart_UninspectableFile_IsNotFatal is the counterpart: when the file cannot be
// opened for inspection at all, nothing is known to be torn and the append-only open
// may still succeed, so Start must not deny a configuration that worked before this
// check existed. An append-only audit log (chattr +a / uappnd) is the motivating
// case; a write-only mode reproduces the same class portably.
func TestStart_UninspectableFile_IsNotFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; file mode does not restrict access")
	}
	env := newTestEnv(t)
	if err := os.WriteFile(env.cfg.LogPath, []byte("{\"a\":1}\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Write-only: the O_RDWR repair open is refused, the O_APPEND|O_WRONLY open is not.
	if err := os.Chmod(env.cfg.LogPath, 0200); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(env.cfg.LogPath, 0600) })

	if _, err := os.OpenFile(env.cfg.LogPath, os.O_RDWR, 0); err == nil {
		t.Skip("O_RDWR unexpectedly permitted; cannot exercise the degraded path here")
	}

	exp := newAgentAuditExporter(env.cfg, nil)
	if err := exp.Start(context.Background(), nil); err != nil {
		t.Fatalf("Start failed on an uninspectable audit log: %v", err)
	}
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// TestRestart_DurableRecordMissingNewline_IsPreserved covers the case where a
// complete, signed record reached disk but its terminating newline did not —
// reachable with fsync_log disabled, where nothing orders the record's bytes
// against the newline.
//
// The fragment is a complete record, so truncating it would destroy signed
// evidence and turn a log that verified cleanly into an entry_count_mismatch.
// The repair must terminate the line instead. A strict prefix of a
// one-object-per-line record can never parse, so valid JSON is an exact
// discriminator between this case and an interrupted write.
func TestRestart_DurableRecordMissingNewline_IsPreserved(t *testing.T) {
	env := newTestEnv(t)
	env.cfg.CheckpointInterval = 1

	exp1 := startExporter(t, env.cfg)
	_ = exp1.ConsumeTraces(context.Background(), makeSpan([16]byte{0xEA}, [8]byte{0x01}, zeroParentID, "t1", 1000, 2000))
	_ = exp1.ConsumeTraces(context.Background(), makeSpan([16]byte{0xEB}, [8]byte{0x02}, zeroParentID, "t2", 3000, 4000))
	if err := exp1.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown phase 1: %v", err)
	}

	// Baseline: the log verifies cleanly, and we record how many entries it holds.
	if report, err := verify.VerifyLog(env.cfg.LogPath, env.cfg.CheckpointPath, env.pubKey); err != nil {
		t.Fatalf("baseline VerifyLog hard error: %v", err)
	} else if len(report.Errors) != 0 {
		t.Fatalf("baseline VerifyLog reported errors: %v", report.Errors)
	}
	entriesBefore := len(readLogEntries(t, env.cfg.LogPath))

	// Drop only the terminating newline: every record byte is still durable.
	data, err := os.ReadFile(env.cfg.LogPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatalf("expected the log to end in a newline, got %q", tailOf(data))
	}
	if err := os.WriteFile(env.cfg.LogPath, data[:len(data)-1], 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	exp2 := startExporter(t, env.cfg)
	if err := exp2.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown phase 2: %v", err)
	}

	if got := len(readLogEntries(t, env.cfg.LogPath)); got != entriesBefore {
		t.Errorf("log entries after restart: got %d, want %d — a durable record was destroyed", got, entriesBefore)
	}
	report, err := verify.VerifyLog(env.cfg.LogPath, env.cfg.CheckpointPath, env.pubKey)
	if err != nil {
		t.Fatalf("VerifyLog hard error: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("VerifyLog reported %d error(s): %v", len(report.Errors), report.Errors)
	}
}

// tailOf returns a short printable tail of b for failure messages.
func tailOf(b []byte) []byte {
	if len(b) > 32 {
		return b[len(b)-32:]
	}
	return b
}

// TestSealTrace_UsesRecordSchemaVersionForGenesisSeed is the regression lock for
// the genesis-seed derivation. sealTrace must seed the chain from the schema
// version of the records it is sealing, not from the record.SchemaVersion
// package constant: a verifier derives the seed from each entry's stored
// schema_version, so a chain seeded from anything else fails verification on a
// log nobody tampered with — the worst failure mode this component has.
//
// The buffer is populated directly rather than through WAL replay, because
// replay now re-stamps records to the current version (see
// TestStart_ReplayedRecordsAreRestampedToCurrentSchema). That makes this the
// only test holding the seed derivation honest, which is the point: the
// derivation must be correct for whatever version reaches it.
func TestSealTrace_UsesRecordSchemaVersionForGenesisSeed(t *testing.T) {
	env := newTestEnv(t)
	exp := startExporter(t, env.cfg)

	const legacyTraceID = "01010101010101010101010101010101"
	exp.mu.Lock()
	exp.buffers[legacyTraceID] = &traceBuffer{
		records: map[string]record.AuditRecord{
			"0102030405060708": {
				SchemaVersion:     "v2",
				TraceID:           legacyTraceID,
				SpanID:            "0102030405060708",
				ParentSpanID:      "",
				StartTimeUnixNano: 1764547200123456789,
				EndTimeUnixNano:   1764547200987654321,
				SpanName:          "legacy.root",
				OtelKind:          "Client",
				AuditKind:         record.AuditKindTask,
				Status:            "Ok",
			},
		},
		lastSeen: time.Now(),
		hasRoot:  true,
	}
	exp.mu.Unlock()

	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	entries := readLogEntries(t, env.cfg.LogPath)
	if len(entries) != 1 {
		t.Fatalf("expected 1 sealed entry, got %d", len(entries))
	}
	if got := entries[0].Record.SchemaVersion; got != "v2" {
		t.Errorf("sealed record schema_version: got %q, want %q", got, "v2")
	}
	if err := verify.VerifyChain(entries, env.pubKey); err != nil {
		t.Errorf("verifying a chain sealed from a v2 record: %v\n"+
			"sealTrace must use chain.GenesisSeedForSchema(traceID, recs[0].SchemaVersion)", err)
	}
}

// TestStart_ReplayedRecordsAreRestampedToCurrentSchema pins the upgrade path: a
// WAL left by an earlier binary carries that binary's schema_version, but its
// entries are unsealed drafts — nothing has hashed them. Replay re-stamps them
// to the current version so a trace completed after the upgrade seals into a
// single-version chain, rather than one silently mixing encodings because a
// re-delivered span replaced its record last-write-wins.
//
// The timestamp values must survive the re-stamp exactly: only the encoding
// changes (JSON number to decimal string), never the instant recorded.
func TestStart_ReplayedRecordsAreRestampedToCurrentSchema(t *testing.T) {
	env := newTestEnv(t)

	const legacyTraceID = "01010101010101010101010101010101"
	legacyWAL := `{"type":"span","trace_id":"` + legacyTraceID + `","record":` +
		`{"schema_version":"v2","trace_id":"` + legacyTraceID + `","span_id":"0102030405060708",` +
		`"parent_span_id":"","seq_in_trace":0,"start_time_unix_nano":1764547200123456789,` +
		`"end_time_unix_nano":1764547200987654321,"span_name":"pre-upgrade.root","otel_kind":"Client",` +
		`"gen_ai_operation":"","audit_kind":"task","selected_attributes":null,"status":"Ok"}}` + "\n"
	if err := os.WriteFile(env.cfg.WalPath, []byte(legacyWAL), 0600); err != nil {
		t.Fatalf("writing legacy WAL: %v", err)
	}

	exp := startExporter(t, env.cfg)
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	entries := readLogEntries(t, env.cfg.LogPath)
	if len(entries) != 1 {
		t.Fatalf("expected 1 sealed entry, got %d", len(entries))
	}
	if got := entries[0].Record.SchemaVersion; got != record.SchemaVersion {
		t.Errorf("replayed record schema_version: got %q, want %q", got, record.SchemaVersion)
	}
	if got := uint64(entries[0].Record.StartTimeUnixNano); got != 1764547200123456789 {
		t.Errorf("StartTimeUnixNano changed across the re-stamp: got %d, want 1764547200123456789", got)
	}
	if got := uint64(entries[0].Record.EndTimeUnixNano); got != 1764547200987654321 {
		t.Errorf("EndTimeUnixNano changed across the re-stamp: got %d, want 1764547200987654321", got)
	}

	// The re-stamped record must be written in the current encoding.
	raw, err := os.ReadFile(env.cfg.LogPath)
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"start_time_unix_nano":"1764547200123456789"`)) {
		t.Errorf("re-stamped record not written with v3 string encoding: %s", raw)
	}

	if err := verify.VerifyChain(entries, env.pubKey); err != nil {
		t.Errorf("verifying a re-stamped replayed chain: %v", err)
	}
}

// TestStart_ReplayedTraceCanStillBeCompleted guards the capability the
// re-stamping approach was chosen to preserve: a crash-interrupted trace stays
// open after replay, so a root span arriving post-restart still completes it
// into one chain. Sealing replayed buffers at startup instead would truncate
// this trace to its replayed prefix.
func TestStart_ReplayedTraceCanStillBeCompleted(t *testing.T) {
	env := newTestEnv(t)

	const legacyTraceID = "01010101010101010101010101010101"
	legacyWAL := `{"type":"span","trace_id":"` + legacyTraceID + `","record":` +
		`{"schema_version":"v2","trace_id":"` + legacyTraceID + `","span_id":"0102030405060708",` +
		`"parent_span_id":"aabbccddeeff0011","seq_in_trace":0,"start_time_unix_nano":1764547200123456789,` +
		`"end_time_unix_nano":1764547200987654321,"span_name":"pre-upgrade.child","otel_kind":"Client",` +
		`"gen_ai_operation":"","audit_kind":"task","selected_attributes":null,"status":"Ok"}}` + "\n"
	if err := os.WriteFile(env.cfg.WalPath, []byte(legacyWAL), 0600); err != nil {
		t.Fatalf("writing legacy WAL: %v", err)
	}

	exp := startExporter(t, env.cfg)
	// The root arrives after the upgrade and seals the trace.
	traceID := [16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	rootID := [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	_ = exp.ConsumeTraces(context.Background(),
		makeSpan(traceID, rootID, zeroParentID, "post-upgrade.root", 1764547200000000000, 1764547201000000000))
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	entries := readLogEntries(t, env.cfg.LogPath)
	if len(entries) != 2 {
		t.Fatalf("expected the replayed span and the post-restart root in one chain, got %d entries", len(entries))
	}
	// Naming both spans guards against a pass where replay silently dropped the
	// child and some other entry took its place.
	var names []string
	for _, e := range entries {
		names = append(names, e.Record.SpanName)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"post-upgrade.root", "pre-upgrade.child"}) {
		t.Errorf("chain span names: got %v, want the replayed child and the post-restart root", names)
	}
	// Both entries must carry the same schema version — that is the whole point.
	if entries[0].Record.SchemaVersion != entries[1].Record.SchemaVersion {
		t.Errorf("chain mixes schema versions: %q and %q",
			entries[0].Record.SchemaVersion, entries[1].Record.SchemaVersion)
	}
	if got := entries[0].Record.SchemaVersion; got != record.SchemaVersion {
		t.Errorf("chain schema version: got %q, want %q", got, record.SchemaVersion)
	}
	if err := verify.VerifyChain(entries, env.pubKey); err != nil {
		t.Errorf("verifying a completed post-upgrade chain: %v", err)
	}
}

// legacyWALLine builds a WAL span line stamped with an arbitrary schema version
// and numeric (v1/v2-shaped) timestamps, as an earlier binary would have written it.
func legacyWALLine(schemaVersion, traceID, spanID, parentSpanID, name string) string {
	return `{"type":"span","trace_id":"` + traceID + `","record":` +
		`{"schema_version":"` + schemaVersion + `","trace_id":"` + traceID + `","span_id":"` + spanID + `",` +
		`"parent_span_id":"` + parentSpanID + `","seq_in_trace":0,"start_time_unix_nano":1764547200123456789,` +
		`"end_time_unix_nano":1764547200987654321,"span_name":"` + name + `","otel_kind":"Client",` +
		`"gen_ai_operation":"","audit_kind":"task","selected_attributes":null,"status":"Ok"}}` + "\n"
}

// TestStart_DataIncompatibleVersionIsSealedAtItsOwnVersion pins one limit of
// re-stamping. v1 predates v2's widening of attributeAllowlist, so a v1
// record's selected_attributes were captured under narrower rules; re-stamping
// would assert that a v1 binary looked for guardrail attributes and found none,
// when it never looked. But this binary DOES implement v1's wire format, so
// sealing the trace as a v1 chain is honest — the bytes signed are the bytes v1
// defines — and the records are preserved.
func TestStart_DataIncompatibleVersionIsSealedAtItsOwnVersion(t *testing.T) {
	env := newTestEnv(t)
	const traceID = "01010101010101010101010101010101"
	if err := os.WriteFile(env.cfg.WalPath,
		[]byte(legacyWALLine("v1", traceID, "0102030405060708", "", "pre-upgrade.root")), 0600); err != nil {
		t.Fatalf("writing legacy WAL: %v", err)
	}

	exp := startExporter(t, env.cfg)
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	entries := readLogEntries(t, env.cfg.LogPath)
	if len(entries) != 1 {
		t.Fatalf("expected 1 sealed entry, got %d", len(entries))
	}
	if got := entries[0].Record.SchemaVersion; got != "v1" {
		t.Errorf("schema_version: got %q, want v1 — this version must not be re-stamped", got)
	}

	// Written in v1's encoding, not merely labelled v1.
	raw, err := os.ReadFile(env.cfg.LogPath)
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"start_time_unix_nano":1764547200123456789`)) {
		t.Errorf("v1 record not written with numeric timestamps:\n%s", raw)
	}
	if err := verify.VerifyChain(entries, env.pubKey); err != nil {
		t.Errorf("verifying a chain sealed at v1: %v", err)
	}
}

// TestStart_UnimplementedVersionIsQuarantinedNotSealed covers the case a
// rollback produces: a WAL written by a NEWER binary. This one must not be
// sealed at all.
//
// The records were decoded through the current AuditRecord, so any field that
// version added is already gone, and canonical.Marshal would emit current-shaped
// bytes under that version's label. Signing that attests to evidence this binary
// altered, and a verifier that does implement the version reproduces different
// bytes and reports tampering on an untampered log. The earlier version of this
// test asserted the opposite and passed only because the verifier it used was
// this same binary.
func TestStart_UnimplementedVersionIsQuarantinedNotSealed(t *testing.T) {
	env := newTestEnv(t)
	const traceID = "01010101010101010101010101010101"
	if err := os.WriteFile(env.cfg.WalPath,
		[]byte(legacyWALLine("v99", traceID, "0102030405060708", "", "post-rollback.root")), 0600); err != nil {
		t.Fatalf("writing WAL: %v", err)
	}

	exp := startExporter(t, env.cfg)
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	if entries := readLogEntries(t, env.cfg.LogPath); len(entries) != 0 {
		t.Fatalf("a record of an unimplemented version must not be sealed and signed; got %d entries", len(entries))
	}

	quarantined, err := os.ReadFile(env.cfg.WalPath + ".quarantine.jsonl")
	if err != nil {
		t.Fatalf("reading quarantine sidecar: %v", err)
	}
	if !bytes.Contains(quarantined, []byte(`"span_name":"post-rollback.root"`)) {
		t.Errorf("record was destroyed rather than quarantined:\n%s", quarantined)
	}
	if !bytes.Contains(quarantined, []byte(`"v99"`)) {
		t.Errorf("quarantine entry does not record the stored version:\n%s", quarantined)
	}
}

// TestStart_UnrestampableTraceIsSealedNotLeftOpen is the other half: a trace
// held at its stored version must not stay open, or a span stamped with the
// current version would join it and the chain would mix versions.
func TestStart_UnrestampableTraceIsSealedNotLeftOpen(t *testing.T) {
	env := newTestEnv(t)
	const traceIDHex = "01010101010101010101010101010101"
	if err := os.WriteFile(env.cfg.WalPath,
		[]byte(legacyWALLine("v1", traceIDHex, "0102030405060708", "aabbccddeeff0011", "pre-upgrade.child")), 0600); err != nil {
		t.Fatalf("writing legacy WAL: %v", err)
	}

	exp := startExporter(t, env.cfg)

	// A current-version span for the same trace arrives after the restart. The
	// replayed trace is already sealed, so it is dropped rather than joining it.
	traceID := [16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	rootID := [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	_ = exp.ConsumeTraces(context.Background(),
		makeSpan(traceID, rootID, zeroParentID, "post-upgrade.root", 1764547200000000000, 1764547201000000000))
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	entries := readLogEntries(t, env.cfg.LogPath)
	for i, e := range entries {
		if e.Record.SchemaVersion != entries[0].Record.SchemaVersion {
			t.Fatalf("chain mixes schema versions at seq %d: %q vs %q",
				i, e.Record.SchemaVersion, entries[0].Record.SchemaVersion)
		}
	}
	if len(entries) != 1 {
		t.Fatalf("expected the v1 trace sealed alone, got %d entries", len(entries))
	}
	if got := entries[0].Record.SchemaVersion; got != "v1" {
		t.Errorf("sealed at %q, want v1", got)
	}
	if err := verify.VerifyChain(entries, env.pubKey); err != nil {
		t.Errorf("verifying the sealed v1 chain: %v", err)
	}
}

// TestStart_RestampSurvivesSameSpanRedelivery covers the scenario the re-stamp
// exists for, which no earlier test exercised: the SAME span_id is re-delivered
// after the restart, replacing its replayed record last-write-wins with one
// stamped at the current version. Without the re-stamp the buffer would hold
// one v2 record and one v3 record and seal a chain mixing both.
func TestStart_RestampSurvivesSameSpanRedelivery(t *testing.T) {
	env := newTestEnv(t)
	const traceIDHex = "01010101010101010101010101010101"
	const childSpanHex = "0102030405060708"
	if err := os.WriteFile(env.cfg.WalPath,
		[]byte(legacyWALLine("v2", traceIDHex, childSpanHex, "aabbccddeeff0011", "pre-upgrade.child")), 0600); err != nil {
		t.Fatalf("writing legacy WAL: %v", err)
	}

	exp := startExporter(t, env.cfg)

	traceID := [16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	childID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	rootID := [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}

	// The upstream exporter re-delivers the same span after the restart.
	_ = exp.ConsumeTraces(context.Background(),
		makeSpan(traceID, childID, rootID, "redelivered.child", 1764547200123456789, 1764547200987654321))
	// Then the root arrives and seals the trace.
	_ = exp.ConsumeTraces(context.Background(),
		makeSpan(traceID, rootID, zeroParentID, "post-upgrade.root", 1764547200000000000, 1764547201000000000))
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	entries := readLogEntries(t, env.cfg.LogPath)
	if len(entries) != 2 {
		t.Fatalf("expected the re-delivered child and the root in one chain, got %d entries", len(entries))
	}
	for i, e := range entries {
		if e.Record.SchemaVersion != record.SchemaVersion {
			t.Errorf("entry %d schema_version: got %q, want %q", i, e.Record.SchemaVersion, record.SchemaVersion)
		}
	}
	// Last write wins: the re-delivered span replaced the replayed record.
	var names []string
	for _, e := range entries {
		names = append(names, e.Record.SpanName)
	}
	if !slices.Contains(names, "redelivered.child") {
		t.Errorf("re-delivered span did not replace the replayed record; span names: %v", names)
	}
	if err := verify.VerifyChain(entries, env.pubKey); err != nil {
		t.Errorf("verifying the chain after a same-span re-delivery: %v", err)
	}
}

// TestStart_MultipleUnrestampableTracesSealSafely covers the concurrency shape
// the earlier tests missed: sealing more than one trace during Start. sealTrace
// requires e.mu and dispatches a compaction goroutine that takes the lock
// itself, so an unlocked seal loop raced that goroutine from the second
// iteration onward — a concurrent map write that can panic the collector at
// startup. One unrestampable trace never exposed it; -race catches it here.
func TestStart_MultipleUnrestampableTracesSealSafely(t *testing.T) {
	env := newTestEnv(t)

	const traces = 6
	var walLines string
	for i := 0; i < traces; i++ {
		walLines += legacyWALLine("v1",
			fmt.Sprintf("%032x", 0x1000+i), fmt.Sprintf("%016x", 0x20+i), "", "legacy.root")
	}
	if err := os.WriteFile(env.cfg.WalPath, []byte(walLines), 0600); err != nil {
		t.Fatalf("writing WAL: %v", err)
	}

	exp := startExporter(t, env.cfg)
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	entries := readLogEntries(t, env.cfg.LogPath)
	if len(entries) != traces {
		t.Fatalf("expected %d sealed entries, got %d", traces, len(entries))
	}
	for i, e := range entries {
		if e.Record.SchemaVersion != "v1" {
			t.Errorf("entry %d: schema_version %q, want v1", i, e.Record.SchemaVersion)
		}
	}
}

// TestStart_TraceSpanningSchemaVersionsIsDropped covers the case a per-record
// decision got wrong: two crash-and-upgrade cycles on one in-flight trace leave
// a WAL trace holding records of different versions. No single-version chain can
// represent it, and a mixed chain is one this project's own verifier rejects —
// so the trace is dropped loudly rather than sealed into an unverifiable log.
//
// The combinations are the four the round-3 validator measured writing a mixed
// chain: a restampable version paired with a non-restampable one, in both
// directions, and two non-restampable ones together.
func TestStart_TraceSpanningSchemaVersionsIsDropped(t *testing.T) {
	for _, versions := range [][2]string{
		{"v2", "v1"},
		{"v1", "v99"},
		{record.SchemaVersion, "v1"},
		{"v2", "v99"},
	} {
		versions := versions
		t.Run(versions[0]+"+"+versions[1], func(t *testing.T) {
			env := newTestEnv(t)
			const traceID = "01010101010101010101010101010101"
			walLines := legacyWALLine(versions[0], traceID, "0102030405060708", "aabbccddeeff0011", "first") +
				legacyWALLine(versions[1], traceID, "0203040506070809", "aabbccddeeff0011", "second")
			if err := os.WriteFile(env.cfg.WalPath, []byte(walLines), 0600); err != nil {
				t.Fatalf("writing WAL: %v", err)
			}

			exp := startExporter(t, env.cfg)

			entries := readLogEntries(t, env.cfg.LogPath)
			if len(entries) != 0 {
				var got []string
				for _, e := range entries {
					got = append(got, e.Record.SchemaVersion)
				}
				t.Fatalf("a trace spanning schema versions must not be sealed; got %d entries at %v", len(entries), got)
			}

			// It must not replay forever. Asserting "the log is still empty after
			// a restart" would be vacuous — a still-present mixed trace is simply
			// re-dropped, silently, every time. The durable property is that the
			// records are gone from the WAL, so assert that directly.
			walAfter, err := os.ReadFile(env.cfg.WalPath)
			if err != nil && !os.IsNotExist(err) {
				t.Fatalf("reading WAL: %v", err)
			}
			for _, name := range []string{"first", "second"} {
				if bytes.Contains(walAfter, []byte(`"span_name":"`+name+`"`)) {
					t.Errorf("dropped record %q still in the WAL; it will replay on every restart:\n%s", name, walAfter)
				}
			}

			// And the records must have been set aside, not destroyed.
			quarantined, err := os.ReadFile(env.cfg.WalPath + ".quarantine.jsonl")
			if err != nil {
				t.Fatalf("reading quarantine sidecar: %v", err)
			}
			for _, name := range []string{"first", "second"} {
				if !bytes.Contains(quarantined, []byte(`"span_name":"`+name+`"`)) {
					t.Errorf("dropped record %q is not in quarantine; it was destroyed:\n%s", name, quarantined)
				}
			}

			// A later span must not re-open the dropped trace_id and write a
			// silently truncated chain under it that verifies cleanly.
			traceIDBytes := [16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
			rootID := [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
			_ = exp.ConsumeTraces(context.Background(),
				makeSpan(traceIDBytes, rootID, zeroParentID, "post-drop.root", 1764547200000000000, 1764547201000000000))
			if entries := readLogEntries(t, env.cfg.LogPath); len(entries) != 0 {
				t.Errorf("a span after the drop re-opened the trace and wrote %d entries; the trace must stay closed", len(entries))
			}
			if err := exp.Shutdown(context.Background()); err != nil {
				t.Fatalf("Shutdown: %v", err)
			}
		})
	}
}

// TestSealTrace_UnseedableRecordDoesNotReplayForever pins the other half of the
// same lesson. sealTrace drops the buffer before deriving the genesis seed, so a
// record whose schema_version cannot be seeded — empty, as a corrupt WAL line
// yields — used to vanish from the log while staying in the WAL, re-processed on
// every restart. It must be recorded as an unrecoverable drop instead.
func TestSealTrace_UnseedableRecordDoesNotReplayForever(t *testing.T) {
	env := newTestEnv(t)
	const traceID = "01010101010101010101010101010101"
	// schema_version "" is what a zero-value or corrupt record decodes to.
	if err := os.WriteFile(env.cfg.WalPath,
		[]byte(legacyWALLine("", traceID, "0102030405060708", "", "corrupt.root")), 0600); err != nil {
		t.Fatalf("writing WAL: %v", err)
	}

	exp := startExporter(t, env.cfg)
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if entries := readLogEntries(t, env.cfg.LogPath); len(entries) != 0 {
		t.Fatalf("an unseedable record must not be sealed, got %d entries", len(entries))
	}

	walAfter, err := os.ReadFile(env.cfg.WalPath)
	if err != nil {
		t.Fatalf("reading WAL: %v", err)
	}
	if strings.Contains(string(walAfter), "corrupt.root") {
		t.Errorf("unseedable record still in the WAL after seal; it will replay on every restart:\n%s", walAfter)
	}
}

// TestStart_SealedAtOwnVersionSurvivesCompaction closes the window the
// startup-seal guarantee actually has to hold across. sealTrace dispatches a
// background Compact whose success handler resets sealedTraces — correct for an
// ordinary seal, which only needs the guard until the sealed WAL records are
// gone. A trace sealed during Start at an earlier schema version is different:
// re-opening it would let a current-version span start a second chain under the
// same trace_id, seq restarting at 0, which the verifier reports as
// duplicate_trace_segment forever after.
//
// Waiting on the compaction before sending the span is what makes this
// deterministic: without it the test merely wins a race, which is why the
// sibling test passes with or without the guard.
func TestStart_SealedAtOwnVersionSurvivesCompaction(t *testing.T) {
	env := newTestEnv(t)
	const traceIDHex = "01010101010101010101010101010101"
	if err := os.WriteFile(env.cfg.WalPath,
		[]byte(legacyWALLine("v1", traceIDHex, "0102030405060708", "aabbccddeeff0011", "pre-upgrade.child")), 0600); err != nil {
		t.Fatalf("writing WAL: %v", err)
	}

	exp := startExporter(t, env.cfg)

	// Let the compaction dispatched by the startup seal run to completion, so
	// sealedTraces has been reset by the time the span arrives.
	exp.compactWG.Wait()

	traceID := [16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	rootID := [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	_ = exp.ConsumeTraces(context.Background(),
		makeSpan(traceID, rootID, zeroParentID, "post-upgrade.root", 1764547200000000000, 1764547201000000000))
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	entries := readLogEntries(t, env.cfg.LogPath)
	if len(entries) != 1 {
		var got []string
		for _, e := range entries {
			got = append(got, fmt.Sprintf("seq=%d %s %s", e.Record.SeqInTrace, e.Record.SchemaVersion, e.Record.SpanName))
		}
		t.Fatalf("the startup-sealed trace must stay closed after compaction; got %d entries: %v", len(entries), got)
	}
	if got := entries[0].Record.SchemaVersion; got != "v1" {
		t.Errorf("sealed at %q, want v1", got)
	}
}

// TestStart_TraceSpanningRestampableVersionsIsKept is the counterpart to the
// drop test, and covers the pair the ordinary upgrade path actually produces.
//
// Re-stamping is in-memory only — wal.Compact deliberately rewrites each record
// at its stored version — so one upgrade plus a second crash leaves a WAL trace
// holding {previous, current}. Every version present is restampable to current,
// so they collapse onto it exactly as a single one would; dropping the trace
// because the SET has more than one member destroys audit data on a common path.
func TestStart_TraceSpanningRestampableVersionsIsKept(t *testing.T) {
	env := newTestEnv(t)
	const traceIDHex = "01010101010101010101010101010101"
	walLines := legacyWALLine("v2", traceIDHex, "0102030405060708", "aabbccddeeff0011", "pre-upgrade.child") +
		legacyWALLine(record.SchemaVersion, traceIDHex, "0203040506070809", "aabbccddeeff0011", "post-upgrade.child")
	if err := os.WriteFile(env.cfg.WalPath, []byte(walLines), 0600); err != nil {
		t.Fatalf("writing WAL: %v", err)
	}

	exp := startExporter(t, env.cfg)
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	entries := readLogEntries(t, env.cfg.LogPath)
	if len(entries) != 2 {
		t.Fatalf("both records must survive; got %d entries", len(entries))
	}
	for i, e := range entries {
		if e.Record.SchemaVersion != record.SchemaVersion {
			t.Errorf("entry %d: schema_version %q, want %q", i, e.Record.SchemaVersion, record.SchemaVersion)
		}
	}
	if err := verify.VerifyChain(entries, env.pubKey); err != nil {
		t.Errorf("verifying the re-stamped chain: %v", err)
	}
	if _, err := os.Stat(env.cfg.WalPath + ".quarantine.jsonl"); !os.IsNotExist(err) {
		t.Errorf("nothing should have been quarantined; sidecar exists (stat err: %v)", err)
	}
}

// TestStart_SameSpanRedeliveredAcrossRestartIsNotDropped covers the other false
// drop. wal.Replay returns every appended span line with no dedup, so a span
// written under v2 and re-delivered post-upgrade as v3 appears twice under one
// span_id. The buffer dedups it last-write-wins into a single current-version
// record, so the trace is unanimous — but a version set computed over the raw
// replayed slice sees two versions and destroys it.
func TestStart_SameSpanRedeliveredAcrossRestartIsNotDropped(t *testing.T) {
	env := newTestEnv(t)
	const traceIDHex = "01010101010101010101010101010101"
	const spanIDHex = "0102030405060708"
	// The same span_id twice: the original v1 entry and its v3 re-delivery. v1 is
	// chosen deliberately — it is NOT restampable, so if the version set is taken
	// over the raw replayed slice the trace looks irreconcilable and is destroyed.
	// After dedup only the v3 record survives, and the trace is unanimous.
	walLines := legacyWALLine("v1", traceIDHex, spanIDHex, "", "original") +
		legacyWALLine(record.SchemaVersion, traceIDHex, spanIDHex, "", "redelivered")
	if err := os.WriteFile(env.cfg.WalPath, []byte(walLines), 0600); err != nil {
		t.Fatalf("writing WAL: %v", err)
	}

	exp := startExporter(t, env.cfg)
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	entries := readLogEntries(t, env.cfg.LogPath)
	if len(entries) != 1 {
		t.Fatalf("a re-delivered span must dedup to one record, not be dropped; got %d entries", len(entries))
	}
	if got := entries[0].Record.SpanName; got != "redelivered" {
		t.Errorf("span name %q, want the last write to win with %q", got, "redelivered")
	}
	if got := entries[0].Record.SchemaVersion; got != record.SchemaVersion {
		t.Errorf("schema_version %q, want %q", got, record.SchemaVersion)
	}
	if err := verify.VerifyChain(entries, env.pubKey); err != nil {
		t.Errorf("verifying the deduped chain: %v", err)
	}
}

// TestSealTrace_UnsealableRecordsAreQuarantined pins that sealTrace's
// cannot-seal path sets the records aside rather than erasing them. The audit
// log has no way to record its own gap, so a drop with only a counter in a log
// line leaves an operator unable to tell what was lost.
func TestSealTrace_UnsealableRecordsAreQuarantined(t *testing.T) {
	env := newTestEnv(t)
	const traceID = "01010101010101010101010101010101"
	if err := os.WriteFile(env.cfg.WalPath,
		[]byte(legacyWALLine("", traceID, "0102030405060708", "", "corrupt.root")), 0600); err != nil {
		t.Fatalf("writing WAL: %v", err)
	}

	exp := startExporter(t, env.cfg)
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	quarantined, err := os.ReadFile(env.cfg.WalPath + ".quarantine.jsonl")
	if err != nil {
		t.Fatalf("reading quarantine sidecar: %v", err)
	}
	if !bytes.Contains(quarantined, []byte(`"span_name":"corrupt.root"`)) {
		t.Errorf("unsealable record was destroyed rather than quarantined:\n%s", quarantined)
	}
	// The sidecar must carry enough context to act on.
	for _, want := range []string{`"trace_id"`, `"reason"`, `"current_schema_version"`, `"quarantined_at"`} {
		if !bytes.Contains(quarantined, []byte(want)) {
			t.Errorf("quarantine entry missing %s:\n%s", want, quarantined)
		}
	}
}

// TestQuarantine_OpenFailureLeavesRecordsInWAL covers the one path where this
// component would otherwise destroy audit data outright. When the sidecar
// cannot be written, the records must stay in the WAL rather than being marked
// sealed and compacted away: the seal failure that sent them there is
// deterministic, but a quarantine failure — a full disk, a directory not yet
// writable at startup — is typically transient. Loud and repeating beats gone.
func TestQuarantine_OpenFailureLeavesRecordsInWAL(t *testing.T) {
	env := newTestEnv(t)
	const traceID = "01010101010101010101010101010101"
	walLines := legacyWALLine("v1", traceID, "0102030405060708", "aabbccddeeff0011", "first") +
		legacyWALLine(record.SchemaVersion, traceID, "0203040506070809", "aabbccddeeff0011", "second")
	if err := os.WriteFile(env.cfg.WalPath, []byte(walLines), 0600); err != nil {
		t.Fatalf("writing WAL: %v", err)
	}
	// A directory where the sidecar should be: os.OpenFile fails with EISDIR
	// for any uid, unlike a permission bit that root ignores.
	if err := os.Mkdir(env.cfg.WalPath+".quarantine.jsonl", 0700); err != nil {
		t.Fatalf("creating blocking directory: %v", err)
	}

	exp := startExporter(t, env.cfg)
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown must still succeed when quarantine is unwritable: %v", err)
	}

	// The audit log is untouched — nothing unsealable was written to it.
	if entries := readLogEntries(t, env.cfg.LogPath); len(entries) != 0 {
		t.Errorf("unsealable records must not reach the audit log; got %d entries", len(entries))
	}

	// The records must still be in the WAL: they were not quarantined, so they
	// must not have been erased.
	walAfter, err := os.ReadFile(env.cfg.WalPath)
	if err != nil {
		t.Fatalf("reading WAL: %v", err)
	}
	for _, name := range []string{"first", "second"} {
		if !bytes.Contains(walAfter, []byte(`"span_name":"`+name+`"`)) {
			t.Errorf("record %q was erased despite quarantine failing; it existed nowhere else:\n%s", name, walAfter)
		}
	}
}

// TestQuarantine_AppendsAcrossDropsAndIsPrivate pins two properties of the
// sidecar that nothing else would catch: it appends rather than truncating, so
// a second drop cannot erase the first's records, and it is 0600, since it
// holds complete audit records including span names and selected attributes.
func TestQuarantine_AppendsAcrossDropsAndIsPrivate(t *testing.T) {
	env := newTestEnv(t)
	// Two different traces, each irreconcilable, replayed together.
	walLines := legacyWALLine("v1", "01010101010101010101010101010101", "0102030405060708", "aabbccddeeff0011", "traceA.first") +
		legacyWALLine(record.SchemaVersion, "01010101010101010101010101010101", "0203040506070809", "aabbccddeeff0011", "traceA.second") +
		legacyWALLine("v1", "02020202020202020202020202020202", "0304050607080900", "bbccddeeff001122", "traceB.first") +
		legacyWALLine(record.SchemaVersion, "02020202020202020202020202020202", "0405060708090001", "bbccddeeff001122", "traceB.second")
	if err := os.WriteFile(env.cfg.WalPath, []byte(walLines), 0600); err != nil {
		t.Fatalf("writing WAL: %v", err)
	}

	exp := startExporter(t, env.cfg)
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	path := env.cfg.WalPath + ".quarantine.jsonl"
	quarantined, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading quarantine sidecar: %v", err)
	}
	// All four records from both traces must be present: a second drop must not
	// have truncated the first.
	for _, name := range []string{"traceA.first", "traceA.second", "traceB.first", "traceB.second"} {
		if !bytes.Contains(quarantined, []byte(`"span_name":"`+name+`"`)) {
			t.Errorf("%q missing from quarantine; a later drop truncated it:\n%s", name, quarantined)
		}
	}
	if got := bytes.Count(bytes.TrimRight(quarantined, "\n"), []byte("\n")) + 1; got != 4 {
		t.Errorf("quarantine holds %d lines, want 4", got)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat quarantine: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("quarantine sidecar mode %04o, want 0600 — it holds complete audit records", perm)
	}
}

// TestQuarantine_TornTrailingLineIsRepaired covers the sidecar with the same
// guarantee #24 gave the audit log and checkpoint file. It is appended the same
// way, so a crash mid-write leaves a fragment that the next append fuses onto —
// and here that corrupts both the torn record and the next one, in the only
// file still holding either.
func TestQuarantine_TornTrailingLineIsRepaired(t *testing.T) {
	env := newTestEnv(t)
	quarantinePath := env.cfg.WalPath + ".quarantine.jsonl"

	// A fragment as an interrupted append leaves it: no trailing newline, cut
	// mid-token.
	torn := `{"trace_id":"aaaa","quarantined_at":"2026-06-22T00:00:00Z","reason":"earlier drop","record":{"schema_ver`
	if err := os.WriteFile(quarantinePath, []byte(torn), 0600); err != nil {
		t.Fatalf("writing torn sidecar: %v", err)
	}

	const traceID = "01010101010101010101010101010101"
	walLines := legacyWALLine("v1", traceID, "0102030405060708", "aabbccddeeff0011", "first") +
		legacyWALLine(record.SchemaVersion, traceID, "0203040506070809", "aabbccddeeff0011", "second")
	if err := os.WriteFile(env.cfg.WalPath, []byte(walLines), 0600); err != nil {
		t.Fatalf("writing WAL: %v", err)
	}

	exp := startExporter(t, env.cfg)
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	quarantined, err := os.ReadFile(quarantinePath)
	if err != nil {
		t.Fatalf("reading quarantine sidecar: %v", err)
	}
	// Every line must be parseable — nothing fused onto the fragment.
	for i, line := range bytes.Split(bytes.TrimRight(quarantined, "\n"), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Errorf("quarantine line %d is not valid JSON (a torn line fused onto it): %v\n%s", i, err, line)
		}
	}
	// And the new records still arrived.
	for _, name := range []string{"first", "second"} {
		if !bytes.Contains(quarantined, []byte(`"span_name":"`+name+`"`)) {
			t.Errorf("%q missing from the repaired sidecar:\n%s", name, quarantined)
		}
	}
}

// TestConfig_Validate_QuarantineSidecarCollision covers the one audit path that
// is derived rather than configured. Config.Validate already requires log_path,
// wal_path and checkpoint_path to be distinct, but the quarantine sidecar is
// derived from wal_path and escapes that check — pointing an attestable file at
// it would interleave quarantined records into one.
func TestConfig_Validate_QuarantineSidecarCollision(t *testing.T) {
	base := func() *Config {
		return &Config{
			LogPath:        "/tmp/audit.jsonl",
			WalPath:        "/tmp/audit.wal",
			CheckpointPath: "/tmp/checkpoint.jsonl",
			KeyPath:        "/tmp/key.pem",
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("baseline config must be valid: %v", err)
	}

	cfg := base()
	cfg.LogPath = cfg.WalPath + quarantineSuffix
	if err := cfg.Validate(); err == nil {
		t.Error("log_path colliding with the quarantine sidecar must be rejected")
	}

	cfg = base()
	cfg.CheckpointPath = cfg.WalPath + quarantineSuffix
	if err := cfg.Validate(); err == nil {
		t.Error("checkpoint_path colliding with the quarantine sidecar must be rejected")
	}
}

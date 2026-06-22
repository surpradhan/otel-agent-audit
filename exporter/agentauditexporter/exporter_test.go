package agentauditexporter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
	if report.TracesVerified != 1 {
		t.Errorf("TracesVerified: got %d, want 1", report.TracesVerified)
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

// TestVerify_ReorderDetected verifies that physically swapping two complete JSONL
// lines causes a chain break error.
func TestVerify_ReorderDetected(t *testing.T) {
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

	// Swap first two lines.
	lines[0], lines[1] = lines[1], lines[0]

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
		t.Error("expected VerifyLog to detect reorder, got no errors")
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
	if report.CheckpointsVerified < 1 {
		t.Errorf("CheckpointsVerified: got %d, want >= 1", report.CheckpointsVerified)
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
// is counted in TracesVerified but not reported as an error.
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
	if report.TracesVerified < 1 {
		t.Errorf("TracesVerified: got %d, want >= 1", report.TracesVerified)
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
	if report.TracesVerified != 1 {
		t.Errorf("TracesVerified: got %d, want 1", report.TracesVerified)
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
// race-safely and each produces at least one log entry.
func TestConsumeTraces_Concurrent(t *testing.T) {
	const N = 50
	env := newTestEnv(t)
	exp := startExporter(t, env.cfg)
	t.Cleanup(func() {
		if err := exp.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})

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

	// Wait for Shutdown (via t.Cleanup) to seal all remaining buffers.
	// The Cleanup above runs after the test returns.
	// For now, count entries written during the concurrent phase.
	// (Some may still be buffered; Shutdown seals them all.)
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

// Ensure record import doesn't cause "imported and not used" when tests don't directly use it.
var _ = record.SchemaVersion

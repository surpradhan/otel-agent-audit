package agentauditexporter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/canonical"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/sign"
)

// testConfig creates a Config pointing at temp key and log files.
func testConfig(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()

	priv, _, err := sign.GenerateEd25519Key()
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

	return &Config{
		LogPath: filepath.Join(dir, "audit.jsonl"),
		KeyPath: keyPath,
	}
}

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
	// Factory does not call Validate; use a populated config so Start won't fail
	// if it were called — but CreateTraces itself only instantiates, doesn't start.
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
		cfg := &Config{KeyPath: "/tmp/key.pem"}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for missing log_path")
		}
	})
	t.Run("only key_path missing", func(t *testing.T) {
		cfg := &Config{LogPath: "/tmp/audit.jsonl"}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for missing key_path")
		}
	})
	t.Run("both fields set", func(t *testing.T) {
		cfg := &Config{LogPath: "/tmp/audit.jsonl", KeyPath: "/tmp/key.pem"}
		if err := cfg.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
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
	cfg := testConfig(t)
	exp := newAgentAuditExporter(cfg, nil)
	if err := exp.Start(context.Background(), nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

func TestConsumeTraces_Empty(t *testing.T) {
	cfg := testConfig(t)
	exp := newAgentAuditExporter(cfg, nil)
	if err := exp.Start(context.Background(), nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := exp.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	// Empty traces must not error.
	if err := exp.ConsumeTraces(context.Background(), ptrace.NewTraces()); err != nil {
		t.Errorf("ConsumeTraces(empty): %v", err)
	}
}

// TestConsumeTraces_SignsAndVerifies is the B1 exit-criterion test:
// a one-span trace produces a signed log entry that independently verifies.
func TestConsumeTraces_SignsAndVerifies(t *testing.T) {
	dir := t.TempDir()

	// Generate key and write to file.
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
	logPath := filepath.Join(dir, "audit.jsonl")

	cfg := &Config{LogPath: logPath, KeyPath: keyPath}
	exp := newAgentAuditExporter(cfg, nil)
	if err := exp.Start(context.Background(), nil); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Build a single-span trace with known values.
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

	// Read the log file.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	data = bytes.TrimSpace(data)

	var entry logEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}

	// Reconstruct sigPayload the same way the exporter built it.
	canonicalBytes, err := canonical.Marshal(entry.Record)
	if err != nil {
		t.Fatalf("re-marshal record: %v", err)
	}
	// hex.DecodeString(entry.Record.TraceID) yields the same 16 bytes as
	// span.TraceID()[:] because rec.TraceID = span.TraceID().String() (lowercase hex).
	traceIDBytes, err := hex.DecodeString(entry.Record.TraceID)
	if err != nil {
		t.Fatalf("decode trace ID: %v", err)
	}
	seedH := sha256.New()
	seedH.Write(traceIDBytes)
	seedH.Write([]byte(record.SchemaVersion))
	genesisSeed := seedH.Sum(nil)

	// Three-index slice cap prevents aliasing into canonicalBytes' backing array.
	sigPayload := append(canonicalBytes[:len(canonicalBytes):len(canonicalBytes)], genesisSeed...)

	// Verify the signature.
	if err := sign.Verify(entry.Signed, sigPayload, pub); err != nil {
		t.Errorf("Verify: %v", err)
	}

	// Verify entryHash matches.
	expectedHash := sha256.Sum256(sigPayload)
	if entry.Signed.EntryHash != hex.EncodeToString(expectedHash[:]) {
		t.Errorf("EntryHash mismatch: got %s, want %s",
			entry.Signed.EntryHash, hex.EncodeToString(expectedHash[:]))
	}

	// Sanity: verify the record schema version.
	if entry.Record.SchemaVersion != record.SchemaVersion {
		t.Errorf("schema_version: got %q, want %q", entry.Record.SchemaVersion, record.SchemaVersion)
	}
}

// TestConsumeTraces_Concurrent verifies that concurrent calls to ConsumeTraces
// are race-safe and each produce exactly one JSONL entry.
func TestConsumeTraces_Concurrent(t *testing.T) {
	const N = 50
	cfg := testConfig(t)
	exp := newAgentAuditExporter(cfg, nil)
	if err := exp.Start(context.Background(), nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := exp.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			td := ptrace.NewTraces()
			span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
			span.SetTraceID(pcommon.TraceID([16]byte{1}))
			span.SetSpanID(pcommon.SpanID([8]byte{1}))
			span.SetName("gen_ai.chat")
			if err := exp.ConsumeTraces(context.Background(), td); err != nil {
				t.Errorf("ConsumeTraces: %v", err)
			}
		}()
	}
	wg.Wait()

	data, err := os.ReadFile(cfg.LogPath)
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	count := 0
	for scanner.Scan() {
		if scanner.Text() != "" {
			count++
		}
	}
	if count != N {
		t.Errorf("expected %d log entries, got %d", N, count)
	}
}

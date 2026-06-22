package agentauditexporter

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/canonical"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/sign"
)

// logEntry is the JSON object written to the audit log for each processed span.
type logEntry struct {
	Record record.AuditRecord `json:"record"`
	Signed sign.SignedEntry   `json:"signed"`
}

type agentAuditExporter struct {
	cfg     *Config
	logger  *zap.Logger
	signer  sign.Signer
	logFile *os.File
	mu      sync.Mutex
}

func newAgentAuditExporter(cfg *Config, logger *zap.Logger) *agentAuditExporter {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &agentAuditExporter{cfg: cfg, logger: logger}
}

func (e *agentAuditExporter) Start(_ context.Context, _ component.Host) error {
	priv, err := sign.LoadEd25519PrivateKeyPEM(e.cfg.KeyPath)
	if err != nil {
		return fmt.Errorf("agentaudit: loading signing key: %w", err)
	}
	e.signer = sign.NewEd25519Signer(priv)

	f, err := os.OpenFile(e.cfg.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("agentaudit: opening audit log %q: %w", e.cfg.LogPath, err)
	}
	e.logFile = f
	return nil
}

func (e *agentAuditExporter) Shutdown(_ context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.logFile != nil {
		return e.logFile.Close()
	}
	return nil
}

func (e *agentAuditExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// ConsumeTraces processes spans from the OTel pipeline.
//
// B1 limitation: only the first span of the first ScopeSpans of the first
// ResourceSpans is processed. Multi-span batches are truncated with a warning.
// B2 will replace this with a full per-trace buffer and deterministic ordering.
func (e *agentAuditExporter) ConsumeTraces(_ context.Context, td ptrace.Traces) error {
	rss := td.ResourceSpans()
	if rss.Len() == 0 {
		return nil
	}
	ss := rss.At(0).ScopeSpans()
	if ss.Len() == 0 {
		return nil
	}
	spans := ss.At(0).Spans()
	if spans.Len() == 0 {
		return nil
	}

	if total := td.SpanCount(); total > 1 {
		e.logger.Warn("agentaudit: B1 limitation: multi-span batch truncated to first span",
			zap.Int("total_spans", total))
	}

	span := spans.At(0)
	rec := record.SpanToRecord(span, 0)

	canonicalBytes, err := canonical.Marshal(rec)
	if err != nil {
		return fmt.Errorf("agentaudit: canonical marshal: %w", err)
	}

	// Use hex.DecodeString(rec.TraceID) so the bytes fed into the genesis seed
	// are derived from the stored record field, matching any verifier that
	// reconstructs traceIDBytes from the log entry rather than the live span.
	traceIDBytes, err := hex.DecodeString(rec.TraceID)
	if err != nil {
		return fmt.Errorf("agentaudit: decoding trace ID %q: %w", rec.TraceID, err)
	}
	h := sha256.New()
	h.Write(traceIDBytes)
	h.Write([]byte(record.SchemaVersion))
	genesisSeed := h.Sum(nil)

	// Three-index slice cap prevents append from aliasing into canonicalBytes.
	sigPayload := append(canonicalBytes[:len(canonicalBytes):len(canonicalBytes)], genesisSeed...)

	entryHashArr := sha256.Sum256(sigPayload)
	entryHash := hex.EncodeToString(entryHashArr[:])

	sig, err := e.signer.Sign(sigPayload)
	if err != nil {
		return fmt.Errorf("agentaudit: signing entry: %w", err)
	}

	entry := logEntry{
		Record: rec,
		Signed: sign.SignedEntry{
			KeyID:     e.signer.KeyID(),
			Algorithm: "ed25519",
			EntryHash: entryHash,
			Signature: base64.StdEncoding.EncodeToString(sig),
		},
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("agentaudit: marshaling log entry: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := fmt.Fprintf(e.logFile, "%s\n", line); err != nil {
		return fmt.Errorf("agentaudit: writing log entry: %w", err)
	}
	return nil
}

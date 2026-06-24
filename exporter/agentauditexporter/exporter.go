// Package agentauditexporter implements an OpenTelemetry Collector exporter that
// writes a tamper-evident audit log of agent spans.
//
// B2 design: spans are buffered per trace_id. When a root span (parent_span_id == "")
// is detected, or when a trace has been idle for TraceTimeout, the buffer is sealed:
// spans are sorted by (start_time_unix_nano ASC, span_id ASC), SeqInTrace is
// assigned, and BuildChain produces a per-entry hash chain. Each entry is written
// as a JSONL line to the audit log. A signed checkpoint is written every
// CheckpointInterval sealed traces and on Shutdown.
//
// Post-seal behaviour: a span arriving for an already-sealed trace_id is dropped
// with a warning log. Place the agentauditselect processor upstream to ensure
// the exporter only receives complete traces.
//
// WAL: in-progress trace buffers are backed by a write-ahead log so a collector
// restart does not introduce spurious gaps. Sealed traces are excluded from
// Replay. Compact is run on Start (after Replay) and after each seal to
// prevent unbounded WAL growth.
package agentauditexporter

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/chain"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/sign"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/wal"
)

// maxScanTokenSize caps the bufio.Scanner token size for checkpoint JSONL lines.
// The 64 KB default is too small when CheckpointInterval is large; 4 MB provides headroom.
const maxScanTokenSize = 4 * 1024 * 1024

// traceBuffer holds spans received for one in-progress trace.
type traceBuffer struct {
	records  map[string]record.AuditRecord // keyed by span_id for dedup
	lastSeen time.Time
	hasRoot  bool
}

// logSyncer is the subset of *os.File behaviour used by the exporter's write path.
// The interface exists so tests can inject a fake that simulates sync failures.
type logSyncer interface {
	io.Writer
	Sync() error
	Close() error
	Truncate(size int64) error
	Seek(offset int64, whence int) (int64, error)
}

type agentAuditExporter struct {
	cfg          *Config
	logger       *zap.Logger
	signer       sign.Signer
	logFile      logSyncer
	checkFile    *os.File
	wal          *wal.WAL
	accumulator  *chain.Accumulator
	buffers      map[string]*traceBuffer // guarded by mu
	// sealedTraces prevents re-sealing a trace in the window between seal and the
	// next WAL.Compact. Cleared after each successful Compact so it does not grow
	// without bound. After eviction, a re-delivered root span for a compacted
	// traceID will be buffered and sealed again as a new chain — this is an accepted
	// at-least-once pipeline trade-off, addressed in B3 by the agentauditselect processor.
	sealedTraces map[string]struct{} // guarded by mu
	mu           sync.Mutex
	compactWG    sync.WaitGroup // tracks background Compact goroutines
	stopCh       chan struct{}
	doneCh       chan struct{}
}

// effectiveCheckpointInterval returns the configured interval with a default
// of 100 applied when unset (zero). Centralizes the three-way repeated default.
func (e *agentAuditExporter) effectiveCheckpointInterval() int {
	if e.cfg.CheckpointInterval > 0 {
		return e.cfg.CheckpointInterval
	}
	return 100
}

// fsyncLog reports whether the audit-log file should be fsynced after each
// sealed trace's entries are written. Returns true unless FsyncLog is
// explicitly set to false in the config.
func (e *agentAuditExporter) fsyncLog() bool {
	if e.cfg.FsyncLog != nil {
		return *e.cfg.FsyncLog
	}
	return true
}

func newAgentAuditExporter(cfg *Config, logger *zap.Logger) *agentAuditExporter {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &agentAuditExporter{
		cfg:    cfg,
		logger: logger,
	}
}

// Start loads the signing key, opens all files, replays the WAL, and starts
// the background goroutine that seals timed-out traces.
func (e *agentAuditExporter) Start(_ context.Context, _ component.Host) error {
	priv, err := sign.LoadEd25519PrivateKeyPEM(e.cfg.KeyPath)
	if err != nil {
		return fmt.Errorf("agentaudit: loading signing key: %w", err)
	}
	e.signer = sign.NewEd25519Signer(priv)

	// Open audit log.
	logF, err := os.OpenFile(e.cfg.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("agentaudit: opening audit log %q: %w", e.cfg.LogPath, err)
	}
	e.logFile = logF

	// Open checkpoint file.
	checkF, err := os.OpenFile(e.cfg.CheckpointPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		_ = logF.Close()
		return fmt.Errorf("agentaudit: opening checkpoint file %q: %w", e.cfg.CheckpointPath, err)
	}
	e.checkFile = checkF

	// Open WAL.
	w, err := wal.Open(e.cfg.WalPath)
	if err != nil {
		_ = logF.Close()
		_ = checkF.Close()
		return fmt.Errorf("agentaudit: opening WAL %q: %w", e.cfg.WalPath, err)
	}
	e.wal = w

	// Replay WAL to rehydrate in-progress buffers.
	replayed, err := w.Replay()
	if err != nil {
		_ = logF.Close()
		_ = checkF.Close()
		_ = w.Close()
		return fmt.Errorf("agentaudit: WAL replay: %w", err)
	}

	now := time.Now()
	e.buffers = make(map[string]*traceBuffer, len(replayed))
	e.sealedTraces = make(map[string]struct{})
	for traceID, recs := range replayed {
		buf := &traceBuffer{
			records:  make(map[string]record.AuditRecord, len(recs)),
			lastSeen: now,
		}
		for _, rec := range recs {
			buf.records[rec.SpanID] = rec
			if rec.ParentSpanID == "" {
				buf.hasRoot = true
			}
		}
		e.buffers[traceID] = buf
	}

	// Compact WAL after replay to remove any sealed entries from before the crash.
	if err := w.Compact(); err != nil {
		e.logger.Warn("agentaudit: WAL compact after replay failed", zap.Error(err))
	}

	// Reload seq and prevHash from the last persisted checkpoint so the chain
	// continues correctly across restarts instead of resetting to seq=1.
	initialSeq := uint64(0)
	prevHash := chain.ZeroPrevCheckpointHash
	if lastCP, ok, cpErr := readLastCheckpoint(e.cfg.CheckpointPath); ok {
		payload, payloadErr := chain.CheckpointSigningPayload(lastCP)
		if payloadErr != nil {
			// CheckpointSigningPayload marshals a struct of basic types; this
			// path is unreachable in practice. Treat it as fatal: a silent
			// fallback to seq=0 would break the checkpoint chain invisibly.
			_ = logF.Close()
			_ = checkF.Close()
			_ = w.Close()
			return fmt.Errorf("agentaudit: cannot reconstruct checkpoint signing payload on restart: %w", payloadErr)
		}
		h := sha256.Sum256(payload)
		prevHash = hex.EncodeToString(h[:])
		initialSeq = lastCP.CheckpointSeq
	} else if cpErr != nil {
		e.logger.Warn("agentaudit: could not read last checkpoint on restart", zap.Error(cpErr))
	}
	e.accumulator = chain.NewAccumulator(e.signer, initialSeq, prevHash)

	traceTimeout := e.cfg.TraceTimeout
	if traceTimeout <= 0 {
		traceTimeout = 30 * time.Second
	}

	e.stopCh = make(chan struct{})
	e.doneCh = make(chan struct{})

	go e.backgroundWorker(traceTimeout, e.effectiveCheckpointInterval())

	return nil
}

// backgroundWorker runs until stopCh is closed. It wakes every traceTimeout/2
// and seals traces that have been idle for at least traceTimeout.
func (e *agentAuditExporter) backgroundWorker(traceTimeout time.Duration, checkpointInterval int) {
	defer close(e.doneCh)
	ticker := time.NewTicker(traceTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case now := <-ticker.C:
			e.mu.Lock()
			for traceID, buf := range e.buffers {
				if now.Sub(buf.lastSeen) >= traceTimeout {
					e.logger.Info("agentaudit: sealing timed-out trace",
						zap.String("trace_id", traceID),
						zap.Duration("idle", now.Sub(buf.lastSeen)))
					e.sealTrace(traceID, buf, checkpointInterval)
				}
			}
			e.mu.Unlock()
		}
	}
}

// Shutdown follows the explicit 8-step ordering from the B2 plan:
//  1. close(stopCh)
//  2. <-doneCh          — block until background goroutine exits and releases mu
//  3. mu.Lock()
//  4. force-seal all remaining buffers
//  5. write final checkpoint
//  6. mu.Unlock()
//  7. compactWG.Wait()  — wait for background Compact goroutines
//  8. close logFile, checkFile; WAL.Compact(); WAL.Close()
func (e *agentAuditExporter) Shutdown(ctx context.Context) error {
	if e.stopCh == nil {
		// Start was never called (e.g. factory test).
		return nil
	}

	// Step 1.
	close(e.stopCh)

	// Step 2.
	<-e.doneCh

	// Step 3.
	e.mu.Lock()

	// Step 4: force-seal all remaining buffers.
	for traceID, buf := range e.buffers {
		e.sealTrace(traceID, buf, e.effectiveCheckpointInterval())
	}

	// Step 5: write final checkpoint if there are pending tips.
	if e.accumulator.PendingCount() > 0 {
		if err := e.writeCheckpoint(); err != nil {
			e.logger.Error("agentaudit: writing final checkpoint", zap.Error(err))
		}
	}

	// Step 6.
	e.mu.Unlock()

	// Step 7: wait for all background Compact goroutines, honoring ctx.
	waitDone := make(chan struct{})
	go func() { e.compactWG.Wait(); close(waitDone) }()
	select {
	case <-waitDone:
	case <-ctx.Done():
		e.logger.Warn("agentaudit: Shutdown context expired waiting for Compact goroutines")
	}

	// Step 8: close files and compact WAL one final time.
	var errs []error
	if e.logFile != nil {
		if err := e.logFile.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing log file: %w", err))
		}
		e.logFile = nil
	}
	if e.checkFile != nil {
		if err := e.checkFile.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing checkpoint file: %w", err))
		}
		e.checkFile = nil
	}
	if e.wal != nil {
		if err := e.wal.Compact(); err != nil {
			e.logger.Warn("agentaudit: final WAL compact failed", zap.Error(err))
		} else {
			// No concurrent goroutines remain at this point (compactWG drained,
			// background worker stopped), but we take mu for consistency with the
			// background-goroutine path that also clears sealedTraces under mu.
			e.mu.Lock()
			e.sealedTraces = make(map[string]struct{})
			e.mu.Unlock()
		}
		if err := e.wal.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing WAL: %w", err))
		}
		e.wal = nil
	}

	return errors.Join(errs...)
}

func (e *agentAuditExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// ConsumeTraces processes spans from the OTel pipeline.
// Each span is added to its trace's buffer. If the trace now has a root span
// (parent_span_id == ""), the entire buffer is sealed immediately.
func (e *agentAuditExporter) ConsumeTraces(_ context.Context, td ptrace.Traces) error {
	now := time.Now()
	checkpointInterval := e.effectiveCheckpointInterval()

	rss := td.ResourceSpans()
	for i := 0; i < rss.Len(); i++ {
		scopeSpans := rss.At(i).ScopeSpans()
		for j := 0; j < scopeSpans.Len(); j++ {
			spans := scopeSpans.At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				span := spans.At(k)
				// Use seqInTrace=0 as a placeholder; real seq is assigned in sealTrace.
				rec := record.SpanToRecord(span, 0)

				e.mu.Lock()
				err := e.bufferSpan(rec, now, checkpointInterval)
				e.mu.Unlock()

				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// bufferSpan adds rec to its trace's buffer. If a root span is found, seals immediately.
// Called under e.mu.
func (e *agentAuditExporter) bufferSpan(rec record.AuditRecord, now time.Time, checkpointInterval int) error {
	traceID := rec.TraceID
	if traceID == "" {
		e.logger.Warn("agentaudit: span with empty trace_id, dropping")
		return nil
	}

	// Drop spans for already-sealed traces. A second root span would create a second
	// chain for the same trace_id, making the log ambiguous for verifiers.
	if _, sealed := e.sealedTraces[traceID]; sealed {
		e.logger.Warn("agentaudit: span for already-sealed trace, dropping",
			zap.String("trace_id", traceID))
		return nil
	}

	buf := e.buffers[traceID]
	if buf == nil {
		buf = &traceBuffer{
			records:  make(map[string]record.AuditRecord),
			lastSeen: now,
		}
		e.buffers[traceID] = buf
	}

	// Dedup by span_id: last write wins (idempotent for re-delivered spans).
	buf.records[rec.SpanID] = rec
	buf.lastSeen = now
	if rec.ParentSpanID == "" {
		buf.hasRoot = true
	}

	// Write to WAL for crash recovery (before sealing).
	if e.wal != nil {
		if err := e.wal.AppendSpan(traceID, rec); err != nil {
			e.logger.Warn("agentaudit: WAL append span failed",
				zap.String("trace_id", traceID), zap.Error(err))
		}
	}

	// Seal immediately on root span detection.
	if buf.hasRoot {
		e.sealTrace(traceID, buf, checkpointInterval)
	}

	return nil
}

// sealTrace seals a trace buffer: sorts, assigns SeqInTrace, builds the chain,
// writes JSONL entries, updates the accumulator, and marks the WAL sealed.
// Called under e.mu. Compact is dispatched in a goroutine OUTSIDE the lock
// (but the goroutine is started while we still hold the lock so compactWG.Add
// happens before Shutdown's compactWG.Wait).
func (e *agentAuditExporter) sealTrace(traceID string, buf *traceBuffer, checkpointInterval int) {
	// Extract records as a slice.
	recs := make([]record.AuditRecord, 0, len(buf.records))
	for _, rec := range buf.records {
		recs = append(recs, rec)
	}

	// Remove from buffers and mark sealed so future spans for this trace_id are dropped.
	delete(e.buffers, traceID)
	e.sealedTraces[traceID] = struct{}{}

	if len(recs) == 0 {
		return
	}

	// Step 1: sort in-place.
	chain.SortRecords(recs)

	// Step 2: assign SeqInTrace BEFORE BuildChain.
	for i := range recs {
		recs[i].SeqInTrace = i
	}

	// Step 3: build chain.
	genesisSeed, err := chain.GenesisSeed(traceID)
	if err != nil {
		e.logger.Error("agentaudit: genesis seed", zap.String("trace_id", traceID), zap.Error(err))
		return
	}

	entries, err := chain.BuildChain(recs, genesisSeed, e.signer)
	if err != nil {
		e.logger.Error("agentaudit: build chain", zap.String("trace_id", traceID), zap.Error(err))
		return
	}

	// Step 4: write each entry as a JSONL line.
	// If fsync is enabled, snapshot the log's end offset first so we can
	// truncate back to it if Sync later fails — keeping the log consistent
	// with the checkpoint (which is only updated in Step 5 below).
	var preWritePos int64
	if e.fsyncLog() {
		if preWritePos, err = e.logFile.Seek(0, io.SeekEnd); err != nil {
			e.logger.Error("agentaudit: get log offset before write",
				zap.String("trace_id", traceID), zap.Error(err))
			return
		}
	}

	// rollbackLog truncates the file back to preWritePos and fsyncs the truncation
	// so that a crash after the call cannot leave the log ahead of the checkpoint.
	// Used on both write-loop failure and Sync failure below.
	rollbackLog := func(cause string, causeErr error) {
		e.logger.Error(cause, zap.String("trace_id", traceID), zap.Error(causeErr))
		if terr := e.logFile.Truncate(preWritePos); terr != nil {
			e.logger.Error("agentaudit: rollback log truncate failed — log may be ahead of checkpoint",
				zap.String("trace_id", traceID), zap.Error(terr))
			return
		}
		// Fsync the truncation so a crash cannot recover the removed entries.
		if serr := e.logFile.Sync(); serr != nil {
			e.logger.Error("agentaudit: rollback log sync failed — log may be ahead of checkpoint",
				zap.String("trace_id", traceID), zap.Error(serr))
		}
	}

	logEntries := chain.ToLogEntries(entries)
	for _, le := range logEntries {
		if err := e.writeLogEntry(le); err != nil {
			if e.fsyncLog() {
				rollbackLog("agentaudit: write log entry", err)
			} else {
				e.logger.Error("agentaudit: write log entry",
					zap.String("trace_id", traceID), zap.Error(err))
			}
			return
		}
	}

	// Step 4b: fsync the audit log before the checkpoint commits to these entries.
	// This ensures a power-loss between the two writes cannot produce spurious
	// entry_count_mismatch errors on restart. Skipped when FsyncLog is explicitly
	// set to false (high-throughput testing); default is true.
	//
	// On Sync failure we truncate (and re-sync the truncation) so the log is never
	// ahead of the checkpoint. The WAL for this trace is not yet marked sealed,
	// so the trace replays cleanly on the next startup.
	if e.fsyncLog() {
		if err := e.logFile.Sync(); err != nil {
			rollbackLog("agentaudit: sync log file", err)
			return
		}
	}

	// Step 5: update accumulator.
	tipHash := chain.TipHash(entries)
	e.accumulator.AddTip(traceID, tipHash, len(entries))

	// Step 6: checkpoint if interval reached.
	if e.accumulator.PendingCount() >= checkpointInterval {
		if err := e.writeCheckpoint(); err != nil {
			e.logger.Error("agentaudit: write checkpoint", zap.Error(err))
		}
	}

	// Step 7: mark WAL sealed (calls Sync).
	if e.wal != nil {
		if err := e.wal.MarkSealed(traceID); err != nil {
			e.logger.Error("agentaudit: WAL mark sealed",
				zap.String("trace_id", traceID), zap.Error(err))
		}
	}

	// Step 8: schedule compact OUTSIDE the lock (goroutine is launched while lock is held
	// so compactWG.Add(1) is observed by Shutdown's compactWG.Wait()).
	// On success, clear sealedTraces: entries only need to persist until Compact removes
	// the sealed WAL records; after that the map can grow again from scratch.
	if e.wal != nil {
		e.compactWG.Add(1)
		w := e.wal
		go func() {
			defer e.compactWG.Done()
			if err := w.Compact(); err != nil {
				e.logger.Warn("agentaudit: background WAL compact failed", zap.Error(err))
				return
			}
			e.mu.Lock()
			e.sealedTraces = make(map[string]struct{})
			e.mu.Unlock()
		}()
	}
}

// writeLogEntry marshals a LogEntry and appends it as a JSONL line.
// Called under e.mu.
func (e *agentAuditExporter) writeLogEntry(le chain.LogEntry) error {
	if e.logFile == nil {
		return fmt.Errorf("agentaudit: logFile is nil (Start not called?)")
	}
	line, err := json.Marshal(le)
	if err != nil {
		return fmt.Errorf("agentaudit: marshal log entry: %w", err)
	}
	if _, err := fmt.Fprintf(e.logFile, "%s\n", line); err != nil {
		return fmt.Errorf("agentaudit: write log entry: %w", err)
	}
	return nil
}

// readLastCheckpoint opens path for reading and returns the last valid Checkpoint
// found in the JSONL file. Returns (_, false, nil) when the file is empty or absent.
// Partial/corrupt lines are silently skipped (same tolerance as WAL replay).
func readLastCheckpoint(path string) (chain.Checkpoint, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return chain.Checkpoint{}, false, nil
		}
		return chain.Checkpoint{}, false, fmt.Errorf("agentaudit: reading checkpoint %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var last chain.Checkpoint
	found := false
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), maxScanTokenSize)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var cp chain.Checkpoint
		if err := json.Unmarshal(line, &cp); err != nil {
			continue
		}
		last = cp
		found = true
	}
	if err := scanner.Err(); err != nil {
		return chain.Checkpoint{}, false, fmt.Errorf("agentaudit: scanning checkpoint %q: %w", path, err)
	}
	return last, found, nil
}

// writeCheckpoint builds and writes a checkpoint to the checkpoint file.
// Called under e.mu.
func (e *agentAuditExporter) writeCheckpoint() error {
	if e.checkFile == nil {
		return fmt.Errorf("agentaudit: checkFile is nil")
	}
	cp, err := e.accumulator.Build(time.Now())
	if err != nil {
		return fmt.Errorf("agentaudit: build checkpoint: %w", err)
	}
	line, err := json.Marshal(cp)
	if err != nil {
		return fmt.Errorf("agentaudit: marshal checkpoint: %w", err)
	}
	if _, err := fmt.Fprintf(e.checkFile, "%s\n", line); err != nil {
		return fmt.Errorf("agentaudit: write checkpoint: %w", err)
	}
	if err := e.checkFile.Sync(); err != nil {
		return fmt.Errorf("agentaudit: sync checkpoint: %w", err)
	}
	return nil
}

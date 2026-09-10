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
	"bytes"
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

// logSyncer is the subset of *os.File behaviour used by the exporter's append-
// and-rollback write path, for both the audit log and the checkpoint file.
// The interface exists so tests can inject a fake that simulates sync failures.
type logSyncer interface {
	io.Writer
	Sync() error
	Close() error
	Truncate(size int64) error
	Seek(offset int64, whence int) (int64, error)
}

type agentAuditExporter struct {
	cfg         *Config
	logger      *zap.Logger
	signer      sign.Signer
	logFile     logSyncer
	checkFile   logSyncer
	wal         *wal.WAL
	accumulator *chain.Accumulator
	buffers     map[string]*traceBuffer // guarded by mu
	// sealedTraces prevents re-sealing a trace in the window between seal and the
	// next WAL.Compact. Cleared after each successful Compact so it does not grow
	// without bound. After eviction, a re-delivered root span for a compacted
	// traceID will be buffered and sealed again as a new chain — this is an accepted
	// at-least-once pipeline trade-off, addressed in B3 by the agentauditselect processor.
	sealedTraces map[string]struct{} // guarded by mu

	// checkpointPoisoned is set when a failed checkpoint write could not be
	// rolled back, so the file may still hold an uncommitted checkpoint line.
	// Further checkpoint writes are refused: the next checkpoint would reuse the
	// same seq, and the verifier walks checkpoints in file order, so appending
	// would break prev_checkpoint_hash from that line onward. Better to stop
	// extending the chain than to extend it unverifiably.
	checkpointPoisoned bool // guarded by mu

	// checkpointRetryAt is the pending-tip count at which a checkpoint write is
	// retried after a failure; 0 means "no backoff". See shouldCheckpoint.
	checkpointRetryAt int // guarded by mu

	// checkpointFailures counts consecutive failed checkpoint writes. The first
	// failure is retried promptly; the backoff only kicks in from the second, so
	// a transient blip does not widen the un-checkpointed window. Reset on
	// success. See shouldCheckpoint.
	checkpointFailures int // guarded by mu

	// uncoveredAfterPoison counts traces sealed after checkpointing was disabled.
	// Their entries are still durably in the audit log; they are simply covered
	// by no checkpoint. Reported once at Shutdown rather than per trace.
	uncoveredAfterPoison int // guarded by mu

	mu        sync.Mutex
	compactWG sync.WaitGroup // tracks background Compact goroutines
	stopCh    chan struct{}
	doneCh    chan struct{}
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

	// Repair a torn trailing line left by an interrupted append before reopening
	// either file O_APPEND, so the next record starts on a fresh line instead of
	// fusing onto the fragment. See repairTrailingPartialLine and issue #24.
	for _, f := range []struct {
		name string
		path string
	}{
		{"audit log", e.cfg.LogPath},
		{"checkpoint file", e.cfg.CheckpointPath},
	} {
		rep, repairErr := repairTrailingPartialLine(f.path)
		switch {
		case repairErr == nil:
		case errors.Is(repairErr, errRepairUnavailable):
			// Nothing is known to be torn, and the append-only open below may
			// well succeed. Refusing to start here would deny a configuration
			// that worked before this check existed.
			e.logger.Error("agentaudit: could not check for a torn trailing line; "+
				"a partial write left by an earlier crash will not be repaired",
				zap.String("file", f.path), zap.Error(repairErr))
		default:
			return fmt.Errorf("agentaudit: repairing %s %q: %w", f.name, f.path, repairErr)
		}
		switch {
		case rep.Dropped > 0:
			// Error, not Warn: bytes were removed from an audit file.
			e.logger.Error("agentaudit: dropped torn trailing line",
				zap.String("file", f.path),
				zap.Int64("bytes", rep.Dropped),
				zap.ByteString("dropped_prefix", rep.Prefix))
		case rep.Terminated > 0:
			e.logger.Warn("agentaudit: terminated an unterminated final line; "+
				"the fragment was syntactically complete, so it was not an interrupted write",
				zap.String("file", f.path),
				zap.Int64("bytes", rep.Terminated),
				zap.ByteString("terminated_prefix", rep.Prefix))
		}
	}

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
	//
	// A checkpoint failure here is collected rather than only logged: for an
	// audit-integrity component, "the final checkpoint never landed" is exactly
	// the outcome the operator must not miss. Poisoning is reported the same way
	// even though there are no pending tips left to write — see poisonCheckpoint.
	var shutdownErrs []error
	if e.accumulator.PendingCount() > 0 {
		if err := e.writeCheckpoint(); err != nil {
			e.logger.Error("agentaudit: writing final checkpoint", zap.Error(err))
			shutdownErrs = append(shutdownErrs, fmt.Errorf("writing final checkpoint: %w", err))
		}
	}
	if e.checkpointPoisoned {
		e.logger.Error("agentaudit: shutting down with checkpointing disabled",
			zap.Int("traces_sealed_but_uncovered", e.uncoveredAfterPoison))
		shutdownErrs = append(shutdownErrs, fmt.Errorf(
			"%w (%d trace(s) sealed to the audit log but covered by no checkpoint)",
			errCheckpointPoisoned, e.uncoveredAfterPoison))
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
	errs := shutdownErrs
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
	//
	// Once checkpointing is permanently disabled there is nothing a tip can ever
	// be written into, so accumulating it would grow the pending set without
	// bound for no benefit. The entries above are already durably in the audit
	// log; the trace is simply left uncovered, counted, and reported at Shutdown.
	if e.checkpointPoisoned {
		e.uncoveredAfterPoison++
	} else {
		tipHash := chain.TipHash(entries)
		e.accumulator.AddTip(traceID, tipHash, len(entries))
	}

	// Step 6: checkpoint if interval reached (and not backing off after a
	// failed attempt).
	if e.shouldCheckpoint(checkpointInterval) {
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

// tornTailRepair reports what repairTrailingPartialLine did to a file.
type tornTailRepair struct {
	Dropped    int64  // bytes discarded as an interrupted write
	Terminated int64  // bytes preserved by appending the missing newline
	Prefix     []byte // bounded copy of the affected fragment
}

// errRepairUnavailable wraps a failure to *inspect* a file for a torn tail, as
// distinct from a failure to repair one that is known to be torn. Opening
// O_RDWR is refused for an append-only inode (Linux `chattr +a`, BSD `uappnd`)
// and for a file whose mode grants write but not read, both of which the plain
// O_APPEND|O_WRONLY open below tolerates. Treating those as fatal would let a
// hygiene step deny startup for a configuration that worked, on evidence that
// says nothing about whether the file is torn. (A read-only mount fails that
// open too, so there this only buys a clearer error.)
var errRepairUnavailable = errors.New("cannot inspect file for a torn trailing line")

// maxTornTailPrefix caps how many bytes of a discarded fragment are logged.
const maxTornTailPrefix = 256

// repairTrailingPartialLine removes a trailing partial line from path — a line
// with no terminating newline, which is what an append interrupted by a crash
// leaves behind.
//
// Both the audit log and the checkpoint file are reopened O_APPEND on Start, so
// without this the next record written *after a restart* fuses onto the torn
// fragment and becomes one corrupt line in the middle of the file. The verifier
// tolerates an unparseable checkpoint line only as the final line, so a single
// further append turns a tolerable tail into a hard failure that validates
// nothing — not even the good prefix before it. See issue #24.
//
// Only an unterminated tail is removed. A complete line that fails to parse is
// left in place: that is evidence of corruption or tampering the verifier must
// still see, not an interrupted write. Dropping the tail is safe because a torn
// line is by definition unparseable and uncommitted — writeCheckpoint advances
// the accumulator only after a durable write (#20), so nothing references it.
//
// The WAL is deliberately not repaired here: wal.Compact runs on Start after
// Replay and rewrites the file via temp+rename, dropping unparseable lines, so
// a torn WAL tail is normally cleaned before anything appends to it. A Compact
// failure is only logged, so a torn tail can survive it — but both Replay and
// Compact skip unparseable lines, which bounds the damage.
//
// Single-writer assumption: this is the only place in the exporter that can
// destroy bytes, and it assumes no other process is appending to path. Two
// exporters sharing a log_path already corrupt the chain by interleaving, so
// this does not make a working configuration worse — but note the asymmetry:
// concurrent appends previously only ever added bytes, whereas here the truncate
// would discard whatever a second writer appended between the Stat and the
// Truncate, and the terminating WriteAt would land a newline in the middle of
// it, splitting one complete record into two corrupt lines.
//
// A fragment that is itself valid JSON is provably not an interrupted write:
// these files carry one top-level JSON object per line, and a strict prefix of
// such an object always leaves a brace unbalanced, so it can never parse. It is
// most likely a complete, durable record whose terminating newline did not reach
// disk — reachable with fsync_log disabled, where nothing orders the record's
// bytes against the newline. Discarding it would destroy a signed record and
// turn a log that verified cleanly into an entry_count_mismatch, so it is
// terminated with a newline rather than truncated. If such a fragment is instead
// injected or corrupt, terminating it preserves it as evidence under the same
// rule that keeps a complete-but-unparseable line.
//
// Returns what was done and a bounded prefix of the affected fragment, so an
// operator can see the bytes rather than only a count.
func repairTrailingPartialLine(path string) (tornTailRepair, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return tornTailRepair{}, nil
		}
		return tornTailRepair{}, fmt.Errorf("%w: %w", errRepairUnavailable, err)
	}
	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil {
		return tornTailRepair{}, fmt.Errorf("stat: %w", err)
	}
	size := st.Size()
	if size == 0 {
		return tornTailRepair{}, nil
	}

	// A file already ending in a newline has no torn tail.
	var last [1]byte
	if _, err := f.ReadAt(last[:], size-1); err != nil {
		return tornTailRepair{}, fmt.Errorf("reading last byte: %w", err)
	}
	if last[0] == '\n' {
		return tornTailRepair{}, nil
	}

	// Scan back for the newline that ends the last complete line. The scan is
	// bounded: a tail longer than one maximum-size line is not a partial write,
	// and truncating on that assumption could discard complete records.
	start := size - maxScanTokenSize
	if start < 0 {
		start = 0
	}
	buf := make([]byte, size-start)
	n, err := f.ReadAt(buf, start)
	if err != nil && !errors.Is(err, io.EOF) {
		return tornTailRepair{}, fmt.Errorf("reading tail: %w", err)
	}
	if int64(n) != size-start {
		// The file shrank under us, so every offset computed from Stat is stale.
		return tornTailRepair{}, fmt.Errorf(
			"file shrank while being repaired (read %d of %d bytes)", n, size-start)
	}

	cut := int64(0)
	if idx := bytes.LastIndexByte(buf, '\n'); idx >= 0 {
		cut = start + int64(idx) + 1
	} else if start > 0 {
		return tornTailRepair{}, fmt.Errorf(
			"no line terminator in the last %d bytes, so the tail is not a partial write; "+
				"refusing to truncate — inspect and rotate the file manually", maxScanTokenSize)
	}

	fragment := buf[cut-start:]
	prefix := make([]byte, min(len(fragment), maxTornTailPrefix))
	copy(prefix, fragment)

	// A complete record that only lost its newline: terminate, do not discard.
	if json.Valid(bytes.TrimSpace(fragment)) {
		if _, err := f.WriteAt([]byte("\n"), size); err != nil {
			return tornTailRepair{}, fmt.Errorf("terminating unterminated final line: %w", err)
		}
		if err := f.Sync(); err != nil {
			return tornTailRepair{}, fmt.Errorf("syncing terminated final line: %w", err)
		}
		return tornTailRepair{Terminated: int64(len(fragment)), Prefix: prefix}, nil
	}

	if err := f.Truncate(cut); err != nil {
		return tornTailRepair{}, fmt.Errorf("truncating torn tail: %w", err)
	}
	// Persist the repair, so a crash before the next write does not resurrect
	// the torn tail and leave the same fusion hazard for the following start.
	// Truncation mutates the inode's size, which fsync flushes; no parent-dir
	// sync is needed because this open never creates a directory entry.
	if err := f.Sync(); err != nil {
		return tornTailRepair{}, fmt.Errorf("syncing repair: %w", err)
	}
	return tornTailRepair{Dropped: size - cut, Prefix: prefix}, nil
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

// errCheckpointPoisoned is returned once a failed checkpoint write could not be
// rolled back. See agentAuditExporter.checkpointPoisoned.
var errCheckpointPoisoned = errors.New(
	"agentaudit: checkpoint file may contain an uncommitted checkpoint after a failed rollback; " +
		"refusing to append a checkpoint the verifier could never validate")

// maxCheckpointRetryGap caps how many additional pending tips the backoff will
// wait for before retrying. Without a cap, recovery latency after a healed
// outage grows with the length of the outage — a file that becomes writable
// again at pending=600 would not be retried until pending=1024 — and the error
// log thins out exactly as the pending set grows largest.
const maxCheckpointRetryGap = 1024

// shouldCheckpoint reports whether a checkpoint write should be attempted now.
// Called under e.mu.
//
// Beyond the configured interval it applies a backoff after repeated failures.
// A failed checkpoint keeps its tips pending (that is the point — see
// writeCheckpoint), so without a backoff a persistently unwritable checkpoint
// file would re-copy, re-sort, re-marshal and re-sign the whole, ever-growing
// pending set on every subsequently sealed trace: quadratic work on the
// synchronous ConsumeTraces path. Requiring the pending set to grow before each
// retry keeps the total work near O(n log n) and the error log proportionate.
//
// The first failure is retried promptly — a single transient blip should not
// widen the un-checkpointed window — and the doubling only starts from the
// second consecutive failure.
//
// Note this bounds the wasted *work*, not the *memory*: for a merely transient
// failure tips are still retained, so a checkpoint file that stays unwritable
// grows the pending set. Retaining them is the deliberate trade — the
// alternative is dropping sealed traces — and bounding that growth is tracked
// in the follow-up issue. (Once checkpointing is *permanently* disabled the
// tips are dropped instead; see poisonCheckpoint.)
func (e *agentAuditExporter) shouldCheckpoint(checkpointInterval int) bool {
	pending := e.accumulator.PendingCount()
	return pending >= checkpointInterval && pending >= e.checkpointRetryAt
}

// nextCheckpointRetryAt returns the pending count at which the next retry is
// allowed after a failed attempt at the given pending count. Called under e.mu.
func (e *agentAuditExporter) nextCheckpointRetryAt(pending int) int {
	if e.checkpointFailures <= 1 {
		// Retry the very next seal: one transient failure should not delay it.
		return pending + 1
	}
	if pending > maxCheckpointRetryGap {
		return pending + maxCheckpointRetryGap
	}
	return pending * 2
}

// writeCheckpoint builds and writes a checkpoint to the checkpoint file.
// Called under e.mu.
//
// The accumulator's state advance (seq, prevHash, clearing the pending tips) is
// committed only after the checkpoint is durably on disk. If the write or Sync
// fails, the file is truncated back to its pre-write size and the accumulator is
// left untouched, so the pending tips are retried by the next checkpoint and the
// persisted chain stays contiguous — an ordinary IO error must not drop sealed
// traces or leave a prev_checkpoint_hash pointing at a checkpoint that was never
// persisted.
//
// The one case where contiguity cannot be preserved is a double fault: if the
// rollback itself fails, the file may retain a checkpoint line the accumulator
// never committed to. Appending the next checkpoint would then reuse that seq
// and break prev_checkpoint_hash from there on, so instead the file is marked
// poisoned and every later checkpoint write fails with errCheckpointPoisoned.
// The chain stops growing, but what is already persisted still verifies.
func (e *agentAuditExporter) writeCheckpoint() (err error) {
	// Back off before retrying a failed checkpoint; clear the backoff on success.
	defer func() {
		if err != nil {
			e.checkpointFailures++
			e.checkpointRetryAt = e.nextCheckpointRetryAt(e.accumulator.PendingCount())
			return
		}
		e.checkpointFailures = 0
		e.checkpointRetryAt = 0
	}()

	if e.checkFile == nil {
		return fmt.Errorf("agentaudit: checkFile is nil")
	}
	if e.checkpointPoisoned {
		return errCheckpointPoisoned
	}
	staged, err := e.accumulator.Stage(time.Now())
	if err != nil {
		return fmt.Errorf("agentaudit: stage checkpoint: %w", err)
	}
	line, err := json.Marshal(staged.Checkpoint)
	if err != nil {
		return fmt.Errorf("agentaudit: marshal checkpoint: %w", err)
	}

	// Snapshot the end offset so a partial write or a failed Sync can be rolled
	// back, leaving the file byte-identical to before the attempt.
	preWritePos, err := e.checkFile.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("agentaudit: get checkpoint offset before write: %w", err)
	}

	// Only roll back if bytes actually reached the file. A write that emitted
	// nothing leaves the file already byte-identical to preWritePos, and calling
	// Truncate anyway risks poisoning it over a fault that changed nothing —
	// which matters because a failing write and a failing Truncate are usually
	// the same underlying fault (bad fd, device EIO).
	if n, werr := fmt.Fprintf(e.checkFile, "%s\n", line); werr != nil {
		if n > 0 {
			e.rollbackCheckpoint(preWritePos, werr)
		}
		return fmt.Errorf("agentaudit: write checkpoint: %w", werr)
	}
	if err := e.checkFile.Sync(); err != nil {
		e.rollbackCheckpoint(preWritePos, err)
		return fmt.Errorf("agentaudit: sync checkpoint: %w", err)
	}

	// Durable: only now advance seq/prevHash and drop the tips this checkpoint
	// covers.
	if cerr := e.accumulator.Commit(staged); cerr != nil {
		// The checkpoint is already on disk, so the accumulator and the file have
		// diverged and the next checkpoint would reuse this seq. e.mu serializes
		// stage->commit, so this should be unreachable; treat it like a failed
		// rollback rather than extending a chain that cannot verify.
		e.poisonCheckpoint("agentaudit: checkpoint committed to disk but the accumulator rejected it", cerr, nil)
		return fmt.Errorf("agentaudit: commit checkpoint: %w", cerr)
	}
	return nil
}

// poisonCheckpoint permanently disables checkpoint writing for this process and
// discards the pending tips. Called under e.mu.
//
// Once the checkpoint file may hold a line the accumulator never committed to,
// appending to it would reuse that seq and break prev_checkpoint_hash for every
// later checkpoint, so no further checkpoint can ever be written. That makes the
// pending tips undrainable: retaining them would grow the set without bound for
// no possible benefit, so they are dropped here with a single loud log rather
// than leaking.
//
// What is already persisted still verifies for the lifetime of this process,
// and a restart resumes the chain correctly — readLastCheckpoint picks the last
// *valid* line. A torn line left behind by the failed truncate is removed by
// repairTrailingPartialLine on the next Start (#24); it was never committed to
// the accumulator, so nothing references it.
func (e *agentAuditExporter) poisonCheckpoint(msg string, err, cause error) {
	if e.checkpointPoisoned {
		return
	}
	e.checkpointPoisoned = true
	dropped := e.accumulator.DropPending()
	// The dropped tips are uncovered too — they were sealed since the last
	// successful checkpoint and can now never be written. Counting only the
	// traces sealed *after* poisoning would under-report by a whole checkpoint
	// interval, and would report the least alarming number in the worst case.
	//
	// Two paths can over-report, both deliberately. On the failed-truncate path
	// the staged line did reach the file, so a verifier reading it will consider
	// those traces covered; they are still counted as uncovered here because the
	// write was never fsynced and its durability is therefore unknown. On the
	// commit-failure path the checkpoint is durable and does cover its staged
	// tips, but that path is unreachable while e.mu serializes stage->commit.
	// Over-reporting is the safe direction for an audit component.
	e.uncoveredAfterPoison += dropped
	fields := []zap.Field{
		zap.Error(err),
		zap.Int("uncovered_tips_discarded", dropped),
	}
	if cause != nil {
		fields = append(fields, zap.NamedError("cause", cause))
	}
	e.logger.Error(msg+" — checkpointing is now permanently disabled for this process; "+
		"sealed traces are still written to the audit log but will not be covered by any checkpoint",
		fields...)
}

// rollbackCheckpoint truncates the checkpoint file back to preWritePos and
// fsyncs the truncation, so a crash cannot resurrect a checkpoint line the
// accumulator never committed to. If either step fails the file is marked
// poisoned — see agentAuditExporter.checkpointPoisoned. Called under e.mu.
func (e *agentAuditExporter) rollbackCheckpoint(preWritePos int64, cause error) {
	if terr := e.checkFile.Truncate(preWritePos); terr != nil {
		e.poisonCheckpoint("agentaudit: rollback checkpoint truncate failed — checkpoint file may contain an uncommitted checkpoint", terr, cause)
		return
	}
	// Fsync the truncation: until it lands, a crash could resurrect the removed
	// line as a checkpoint the accumulator never committed to.
	if serr := e.checkFile.Sync(); serr != nil {
		e.poisonCheckpoint("agentaudit: rollback checkpoint sync failed — checkpoint file may contain an uncommitted checkpoint", serr, cause)
	}
}

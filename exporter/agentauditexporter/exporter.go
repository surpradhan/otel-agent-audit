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
// Replay's in-progress buffers, but a sealed trace not yet covered by a durable
// checkpoint has its tip carried forward via Replay's sealedPending result and
// restored directly to the accumulator, without re-sealing — see
// wal.WAL.Compact. Compact is run on Start (after Replay) and after each seal
// to prevent unbounded WAL growth.
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
	"path/filepath"
	"sort"
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

// quarantineSuffix is appended to wal_path to derive the quarantine sidecar.
// Config.Validate rejects a log_path or checkpoint_path that collides with it.
const quarantineSuffix = ".quarantine.jsonl"

// quarantineEntry is one line of the quarantine sidecar: the record that could
// not be sealed, plus enough context for an operator to understand why it is
// there and what to do with it.
type quarantineEntry struct {
	TraceID        string             `json:"trace_id"`
	QuarantinedAt  string             `json:"quarantined_at"`
	Reason         string             `json:"reason"`
	SchemaVersions []string           `json:"schema_versions"`
	CurrentSchema  string             `json:"current_schema_version"`
	Record         record.AuditRecord `json:"record"`
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

	// startupSealed holds traces sealed during Start because they had to keep a
	// schema version this binary must not re-stamp. Unlike sealedTraces it is
	// never cleared: Compact clearing sealedTraces is safe for an ordinary seal,
	// which only needs the guard until the sealed WAL records are gone, but
	// these traces must stay closed for the process's lifetime. Re-opening one
	// would let a span stamped with the current version start a second chain
	// under the same trace_id. Bounded by the traces in flight at crash time.
	//
	// The guarantee is process-scoped, not absolute: after a restart the WAL
	// entries are gone and a re-delivered span does start a fresh chain, which
	// a verifier reports as duplicate_trace_segment. That is the same accepted
	// at-least-once trade-off documented on sealedTraces above, addressed
	// upstream by agentauditselect rather than here.
	startupSealed map[string]struct{} // guarded by mu

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

	// logPoisoned is set when an audit-log write failure could not be rolled
	// back, and the same torn-tail repair Start applies before reopening the
	// file (repairTrailingPartialLine) could not clean it up either. Further
	// audit-log writes are refused: appending onto an unrepairable torn tail
	// would fuse a new record onto the wreckage, corrupting it too. See
	// sealTrace's logPoisoned check, repairOrPoisonLog, and issue #28.
	logPoisoned bool // guarded by mu

	// quarantinedAfterLogPoison counts records quarantined after the audit log
	// was poisoned. Reported once at Shutdown rather than per trace — the same
	// rationale as uncoveredAfterPoison.
	quarantinedAfterLogPoison int // guarded by mu

	// pendingCapDropped counts pending trace tips dropped by TrimPending because
	// the pending-tip cap (effectiveMaxPendingTips) was exceeded during a
	// sustained but rollback-able checkpoint write failure. Unlike
	// uncoveredAfterPoison this is not necessarily permanent — checkpointing can
	// recover — so it can accumulate across more than one degraded episode in
	// the process lifetime. Reported once at Shutdown rather than per trace.
	pendingCapDropped int // guarded by mu

	// pendingCapWarned is set the first time the pending-tip cap is hit, so the
	// loud log fires once per degraded episode rather than once per dropped tip
	// — the same rationale as shouldCheckpoint's backoff. Cleared whenever a
	// checkpoint write next succeeds (see writeCheckpoint).
	pendingCapWarned bool // guarded by mu

	mu        sync.Mutex
	compactWG sync.WaitGroup // tracks background Compact goroutines
	stopCh    chan struct{}
	doneCh    chan struct{}
}

// defaultCheckpointInterval is applied when CheckpointInterval is unset.
const defaultCheckpointInterval = 100

// defaultMaxPendingTipsFactor is the default pending-tip cap expressed as a
// multiple of the effective checkpoint interval, applied when MaxPendingTips
// is unset. See effectiveMaxPendingTipsOf.
const defaultMaxPendingTipsFactor = 10

// effectiveCheckpointIntervalOf returns interval with defaultCheckpointInterval
// applied when unset (<= 0). A free function, rather than a method, so
// Config.Validate can share this exact defaulting rule with
// agentAuditExporter.effectiveCheckpointInterval without duplicating it.
func effectiveCheckpointIntervalOf(interval int) int {
	if interval > 0 {
		return interval
	}
	return defaultCheckpointInterval
}

// effectiveMaxPendingTipsOf returns maxPendingTips with the
// defaultMaxPendingTipsFactor-times-interval default applied when unset
// (<= 0). Shared between Config.Validate and
// agentAuditExporter.effectiveMaxPendingTips for the same reason as
// effectiveCheckpointIntervalOf.
func effectiveMaxPendingTipsOf(maxPendingTips, checkpointInterval int) int {
	if maxPendingTips > 0 {
		return maxPendingTips
	}
	return defaultMaxPendingTipsFactor * checkpointInterval
}

// effectiveCheckpointInterval returns the configured interval with a default
// of 100 applied when unset (zero). Centralizes the three-way repeated default.
func (e *agentAuditExporter) effectiveCheckpointInterval() int {
	return effectiveCheckpointIntervalOf(e.cfg.CheckpointInterval)
}

// effectiveMaxPendingTips returns the configured pending-tip cap, defaulting
// to defaultMaxPendingTipsFactor times checkpointInterval when MaxPendingTips
// is unset (zero). This bounds how far Accumulator.pending can grow during a
// sustained checkpoint write failure — see the TrimPending call in sealTrace.
func (e *agentAuditExporter) effectiveMaxPendingTips(checkpointInterval int) int {
	return effectiveMaxPendingTipsOf(e.cfg.MaxPendingTips, checkpointInterval)
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
		// The quarantine sidecar is appended the same way and needs the same
		// repair — more so, since it holds the only surviving copy of records
		// that could not be sealed, so a fused line corrupts the one thing
		// standing between an operator and total loss. Unlike the two above it
		// is diagnostic rather than attestable, so a repair failure on it is
		// logged rather than fatal: see the fatal-vs-logged split below.
		{"quarantine sidecar", e.quarantinePath()},
	} {
		rep, repairErr := repairTrailingPartialLine(f.path)
		switch {
		case repairErr == nil:
		case f.path == e.quarantinePath():
			// Never refuse to start over a diagnostic file. Losing the repair
			// risks a fused quarantine line; refusing to start guarantees the
			// collector records nothing at all.
			e.logger.Error("agentaudit: could not repair the quarantine sidecar; "+
				"a partial write left by an earlier crash may fuse onto the next entry",
				zap.String("file", f.path), zap.Error(repairErr))
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
	e.warnIfParentDirSyncFails("audit log", e.cfg.LogPath)

	// Open checkpoint file.
	checkF, err := os.OpenFile(e.cfg.CheckpointPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		_ = logF.Close()
		return fmt.Errorf("agentaudit: opening checkpoint file %q: %w", e.cfg.CheckpointPath, err)
	}
	e.checkFile = checkF
	e.warnIfParentDirSyncFails("checkpoint file", e.cfg.CheckpointPath)

	// Open WAL.
	w, err := wal.Open(e.cfg.WalPath)
	if err != nil {
		_ = logF.Close()
		_ = checkF.Close()
		return fmt.Errorf("agentaudit: opening WAL %q: %w", e.cfg.WalPath, err)
	}
	e.wal = w
	e.warnIfParentDirSyncFails("WAL", e.cfg.WalPath)

	// Replay WAL to rehydrate in-progress buffers, plus any sealed trace's tip
	// that must be restored to the accumulator below (see the accumulator
	// construction and its rehydration loop, further down).
	replayed, sealedPending, err := w.Replay()
	if err != nil {
		_ = logF.Close()
		_ = checkF.Close()
		_ = w.Close()
		return fmt.Errorf("agentaudit: WAL replay: %w", err)
	}

	now := time.Now()
	e.buffers = make(map[string]*traceBuffer, len(replayed))
	e.sealedTraces = make(map[string]struct{})
	e.startupSealed = make(map[string]struct{})
	// sealAtOwnVersion collects traces that must keep the schema version they
	// were written with. They are sealed as soon as the accumulator exists,
	// below, rather than left open: an open buffer would go on to accept spans
	// stamped with the current version and seal one chain mixing two.
	var sealAtOwnVersion []string

	for traceID, recs := range replayed {
		// Build the buffer BEFORE deciding anything. WAL span entries are in
		// append order and the same span_id can appear more than once — a span
		// re-delivered after an upgrade is appended again under the current
		// version, leaving its older copy on disk. Only the deduped records are
		// ever sealed, so the schema-version decision has to be made over those;
		// deciding over the raw slice counts a re-delivery as two versions.
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

		// Decide per TRACE, not per record. A chain carries exactly one
		// schema_version, so a replayed trace's disposition is a property of
		// all its records together; deciding record by record can leave a
		// buffer holding two versions and seal a chain this project's own
		// verifier rejects.
		stored := map[string]struct{}{}
		for _, rec := range buf.records {
			stored[rec.SchemaVersion] = struct{}{}
		}
		versions := make([]string, 0, len(stored))
		for v := range stored {
			versions = append(versions, v)
		}
		sort.Strings(versions)

		// A WAL entry is an unsealed draft: nothing has hashed it, so adopting
		// the current schema version costs no stored hash or signature. That is
		// only safe where the versions agree on what a record's fields MEAN —
		// record.RestampableToCurrent is the authority, and it excludes v1
		// (whose attributeAllowlist was narrower) and every version this binary
		// does not implement, including a newer one left by a rollback.
		//
		// The test is over the whole SET, not its size: several restampable
		// versions collapse onto the current one just as safely as one does,
		// and a trace really can hold two of them. Re-stamping is in-memory
		// only — wal.Compact deliberately rewrites each record at its stored
		// version — so one upgrade plus a second crash is enough to leave a
		// {previous, current} WAL trace, which is an ordinary upgrade path and
		// must not lose data.
		allRestampable := true
		for _, v := range versions {
			if !record.RestampableToCurrent(v) {
				allRestampable = false
				break
			}
		}

		switch {
		case allRestampable:
			restamped := 0
			for spanID, rec := range buf.records {
				if rec.SchemaVersion != record.SchemaVersion {
					rec.SchemaVersion = record.SchemaVersion
					buf.records[spanID] = rec
					restamped++
				}
			}
			e.buffers[traceID] = buf
			if restamped > 0 {
				e.logger.Info("agentaudit: re-stamped replayed WAL records to the current schema version",
					zap.String("trace_id", traceID),
					zap.Strings("from", versions),
					zap.String("to", record.SchemaVersion),
					zap.Int("records", restamped))
			}

		case len(versions) == 1 && record.Implemented(versions[0]):
			// A single version this binary must not re-stamp but CAN write —
			// v1, whose wire shape the frozen legacy marshaller still produces.
			// Sealing it is honest: the bytes we sign are the bytes that
			// version defines. Seal it below rather than leaving it open to
			// accept spans stamped with the current version.
			e.buffers[traceID] = buf
			sealAtOwnVersion = append(sealAtOwnVersion, traceID)

		default:
			// Either several versions that cannot be reconciled into one chain,
			// or a single version this binary cannot write — what a rollback
			// leaves behind. Both are unsealable for the same underlying
			// reason: any chain we produced would be signed over bytes that do
			// not represent the records. The unimplemented case is the worse of
			// the two, because the records were decoded through the current
			// struct and any field that version added is already gone, so
			// sealing would attest to altered evidence.
			//
			// Set the records aside where an operator can find them, then drop
			// the trace: erasing evidence with only a log line to show for it
			// is not an option for an audit component.
			unsealable := make([]record.AuditRecord, 0, len(buf.records))
			for _, rec := range buf.records {
				unsealable = append(unsealable, rec)
			}
			reason := "trace spans schema versions that cannot be reconciled into one chain"
			if len(versions) == 1 {
				reason = "schema version is not implemented by this binary; its records cannot be sealed honestly"
			}
			retained := e.quarantineRecords(traceID, unsealable, versions, reason)
			e.startupSealed[traceID] = struct{}{}
			if retained == len(unsealable) {
				// Every record is safely set aside, so the WAL copies can go.
				e.markWALSealed(traceID)
			} else {
				// Quarantine is typically transient — a full disk, a directory
				// not yet writable at startup — unlike the seal failure that
				// sent us here, which is deterministic. Leave the WAL entries
				// alone: the trace re-quarantines on the next start, which is
				// loud and repeats, but does not destroy the only copy.
				e.logger.Error("agentaudit: not all records could be quarantined; leaving them in the WAL rather than erasing them",
					zap.String("trace_id", traceID),
					zap.Int("records", len(unsealable)),
					zap.Int("quarantined", retained))
			}
			continue
		}
	}

	// Reload seq and prevHash from the last persisted checkpoint so the chain
	// continues correctly across restarts instead of resetting to seq=1.
	//
	// This must happen BEFORE the post-replay Compact below: Compact needs the
	// accumulator's pending set to decide which sealed-but-uncheckpointed WAL
	// markers are still owed a checkpoint, and sealedPending is rehydrated into
	// the accumulator right after it is constructed.
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

	// Re-add tips for traces that were fully sealed to the audit log (and
	// WAL-marked sealed) but never covered by a durable checkpoint before the
	// process stopped. Their log entries are already on disk, so this must NOT
	// re-seal them — only restore the pending tip so the next checkpoint covers
	// it, the same as if the process had never stopped. See issue #22.
	for _, tip := range sealedPending {
		e.accumulator.AddTip(tip.TraceID, tip.TipHash, tip.EntryCount)
	}

	// Compact WAL after replay to remove any sealed entries from before the
	// crash whose tip is already durably checkpoint-committed (or was never
	// added to the accumulator at all, e.g. a quarantined trace). Sealed
	// markers for the tips just re-added above are retained so a further crash
	// before the next checkpoint does not lose them again.
	if err := w.Compact(e.accumulator.PendingTips()); err != nil {
		e.logger.Warn("agentaudit: WAL compact after replay failed", zap.Error(err))
	}

	// Seal the traces that must keep their stored schema version, now that the
	// accumulator sealTrace adds tips to exists. Sealing here costs them the
	// trace_timeout grace window; leaving them open would cost the chain its
	// single-version guarantee, which is the more expensive of the two.
	//
	// sealTrace's contract is that the caller holds e.mu: it mutates e.buffers
	// and e.sealedTraces, and dispatches a compaction goroutine that takes the
	// lock itself. Those goroutines simply block until this loop is done.
	e.mu.Lock()
	for _, traceID := range sealAtOwnVersion {
		buf := e.buffers[traceID]
		if buf == nil {
			continue
		}
		e.logger.Error("agentaudit: replayed trace holds records this binary must not re-stamp; sealing at its own schema version",
			zap.String("trace_id", traceID),
			zap.String("current_schema_version", record.SchemaVersion))
		e.startupSealed[traceID] = struct{}{}
		e.sealTrace(traceID, buf, e.effectiveCheckpointInterval())
	}
	e.mu.Unlock()

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
	if e.pendingCapDropped > 0 {
		e.logger.Error("agentaudit: shutting down having dropped pending tips that exceeded the pending-tip cap",
			zap.Int("tips_dropped_for_pending_cap", e.pendingCapDropped))
		shutdownErrs = append(shutdownErrs, fmt.Errorf(
			"%d pending trace tip(s) were dropped after exceeding the pending-tip cap during a sustained checkpoint write failure",
			e.pendingCapDropped))
	}
	if e.logPoisoned {
		e.logger.Error("agentaudit: shutting down with the audit log disabled",
			zap.Int("records_quarantined_after_log_poison", e.quarantinedAfterLogPoison))
		shutdownErrs = append(shutdownErrs, fmt.Errorf(
			"%w (%d record(s) quarantined after the audit log was poisoned)",
			errLogPoisoned, e.quarantinedAfterLogPoison))
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
		if err := e.wal.Compact(e.accumulator.PendingTips()); err != nil {
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
	if _, sealed := e.startupSealed[traceID]; sealed {
		e.logger.Warn("agentaudit: span for a trace sealed at an earlier schema version during startup, dropping",
			zap.String("trace_id", traceID))
		return nil
	}
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

	// If the audit log is poisoned, no further write to it can be trusted —
	// route straight to quarantine instead of building a chain that could
	// never be durably logged, and never add the trace's tip to the
	// accumulator: there would be nothing in the log for a future checkpoint
	// to be committing to. See issue #28.
	if e.logPoisoned {
		written := e.quarantineRecords(traceID, recs, nil, "audit log poisoned; cannot append")
		e.quarantinedAfterLogPoison += written
		if written == len(recs) {
			e.markWALSealed(traceID)
		}
		// Compact must still run: unlike checkpointPoisoned (which only skips
		// the accumulator step and reaches Step 8 normally every time), this
		// branch returns before Step 8 below — and since poisoning is
		// permanent, every future seal would keep taking this same early
		// return, so without this call Compact would never run again for the
		// rest of the process's lifetime. See issue #28.
		e.scheduleWALCompact()
		return
	}

	// Step 1: sort in-place.
	chain.SortRecords(recs)

	// Step 2: assign SeqInTrace BEFORE BuildChain.
	for i := range recs {
		recs[i].SeqInTrace = i
	}

	// Step 3: build chain.
	//
	// The seed must come from the SEALED RECORDS' own schema_version, not from
	// the package constant: a verifier derives it from entries[0]'s stored
	// schema_version, so a chain built with a different one fails verification
	// on an untampered log. They diverge after an upgrade — records replayed
	// from a WAL written by an earlier binary keep the schema version they were
	// created with. recs is sorted above, so recs[0] is the seq-0 entry the
	// verifier reads.
	genesisSeed, err := chain.GenesisSeedForSchema(traceID, recs[0].SchemaVersion)
	if err != nil {
		// The buffer is already dropped above, so returning here would lose the
		// records from the log AND leave them in the WAL to replay on every
		// restart. The failure is deterministic — a record whose schema_version
		// is empty or unseedable never becomes sealable — so record it as an
		// unrecoverable drop instead of retrying it forever.
		e.logger.Error("agentaudit: genesis seed; dropping trace, its records cannot be sealed",
			zap.String("trace_id", traceID),
			zap.String("schema_version", recs[0].SchemaVersion),
			zap.Int("records", len(recs)),
			zap.Error(err))
		if e.quarantineRecords(traceID, recs, nil, "schema_version cannot seed a chain") == len(recs) {
			e.markWALSealed(traceID)
		}
		e.scheduleWALCompact()
		return
	}

	entries, err := chain.BuildChain(recs, genesisSeed, e.signer)
	if err != nil {
		e.logger.Error("agentaudit: build chain; dropping trace, its records cannot be sealed",
			zap.String("trace_id", traceID), zap.Int("records", len(recs)), zap.Error(err))
		if e.quarantineRecords(traceID, recs, nil, "chain could not be built") == len(recs) {
			e.markWALSealed(traceID)
		}
		e.scheduleWALCompact()
		return
	}

	// Step 4: write each entry as a JSONL line.
	// preWritePos is captured unconditionally — regardless of fsync_log — so
	// any write failure can attempt a full rollback to before this trace's
	// first entry. Before issue #28, fsync_log:false had no rollback at all.
	preWritePos, err := e.logFile.Seek(0, io.SeekEnd)
	if err != nil {
		e.logger.Error("agentaudit: get log offset before write",
			zap.String("trace_id", traceID), zap.Error(err))
		return
	}

	// rollbackLog truncates the file back to preWritePos and fsyncs the
	// truncation so that a crash after the call cannot leave the log ahead of
	// the checkpoint — an atomic "this trace's entries or nothing" rollback.
	// Used on both write-loop failure and Sync failure below.
	//
	// safeToRepairTail must be false whenever falling back to a narrower,
	// trailing-line-only repair (repairOrPoisonLog) — if this truncate also
	// fails — could leave this trace only PARTIALLY represented in the log.
	// repairOrPoisonLog only ever touches the final line, and it has two
	// outcomes: drop the fragment (if it's not valid JSON) or KEEP it,
	// terminated with a newline (if it happens to be complete, valid JSON
	// missing only that byte — see repairTrailingPartialLine). The keep
	// outcome is exactly as dangerous as an untouched earlier sibling: a
	// multi-entry trace whose FIRST entry fails at precisely the JSON/newline
	// byte boundary would have that one entry kept, while every later entry
	// (never even attempted, since the write loop returns on the first
	// failure) is silently missing — a partial, uncheckpointed, unquarantined
	// trace that VerifyLog reports zero errors for, the identical hazard as
	// stranding an earlier sibling, just reached through the repair's OWN
	// "keep" branch instead of leaving one untouched.
	//
	// So this is only safe when EITHER (a) the trace has exactly one entry —
	// whatever repairOrPoisonLog does to it, keep or drop, is unambiguously
	// the whole trace's fate, not a partial subset of it — or (b) every entry
	// already wrote successfully this attempt (the post-loop Sync failure
	// below): the trailing bytes are then structurally complete regardless of
	// entry count, so there is nothing for a line-level repair to get wrong.
	// A mid-loop failure on a MULTI-entry trace is unsafe regardless of which
	// entry index failed, including the first. See issue #28.
	rollbackLog := func(cause string, causeErr error, safeToRepairTail bool) {
		e.logger.Error(cause, zap.String("trace_id", traceID), zap.Error(causeErr))
		if terr := e.logFile.Truncate(preWritePos); terr != nil {
			if !safeToRepairTail {
				// This is a multi-entry trace and the full rollback failed:
				// no repair can restore "all or nothing" here, whether that's
				// because an earlier sibling is already durably in the file,
				// or because the repair's own "keep, terminated" outcome
				// could strand later entries that were never even attempted
				// (see the safeToRepairTail comment above). Poison rather
				// than risk a narrower repair silently laundering the file
				// clean — poisonLog forces the actual tail to become
				// verifier-visible as torn_trailing_line regardless of what
				// the underlying failure happened to leave behind. See
				// issue #28.
				e.poisonLog("agentaudit: rollback log truncate failed with this trace only partially written", terr, causeErr)
				return
			}
			// The truncate itself failed: the file's bytes are torn right now,
			// not just at risk after some future crash. Repair (or, if that
			// also fails, poison) rather than leaving it for the next trace's
			// write to fuse onto. See issue #28.
			e.repairOrPoisonLog(traceID, "agentaudit: rollback log truncate failed — log may be ahead of checkpoint", terr)
			return
		}
		// Fsync the truncation so a crash cannot recover the removed entries.
		// If this fails, the file is already byte-correct for any read within
		// this process — only crash durability is at risk, which Start's
		// repairTrailingPartialLine independently covers on the next restart —
		// so this does not escalate to repairOrPoisonLog. (rollbackCheckpoint's
		// equivalent branch does escalate: poisoning the log is categorically
		// more disruptive — it stops the primary audit record, not just its
		// checkpoint coverage — so the log side tolerates a durability-only
		// risk the checkpoint side does not.)
		if serr := e.logFile.Sync(); serr != nil {
			e.logger.Error("agentaudit: rollback log sync failed — log may be ahead of checkpoint",
				zap.String("trace_id", traceID), zap.Error(serr))
		}
	}

	logEntries := chain.ToLogEntries(entries)
	for i, le := range logEntries {
		if err := e.writeLogEntry(le); err != nil {
			rollbackLog("agentaudit: write log entry", err, i == 0 && len(logEntries) == 1)
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
			rollbackLog("agentaudit: sync log file", err, true)
			return
		}
	}

	// tipHash is computed regardless of checkpointPoisoned: Step 7 below always
	// carries it into the WAL's sealed marker, so that if this trace ends up
	// pending (added to the accumulator, not yet checkpoint-committed), a crash
	// before the next successful checkpoint does not lose its coverage. A trace
	// that is never added to the accumulator (poisoned, quarantined, unsealable)
	// is never pending, so sealedMarkerTip below writes an empty marker for it
	// immediately, the same as Compact would otherwise drop it on its next
	// pass — see wal.Compact and sealedMarkerTip.
	tipHash := chain.TipHash(entries)

	// Step 5: update accumulator.
	//
	// Once checkpointing is permanently disabled there is nothing a tip can ever
	// be written into, so accumulating it would grow the pending set without
	// bound for no benefit. The entries above are already durably in the audit
	// log; the trace is simply left uncovered, counted, and reported at Shutdown.
	if e.checkpointPoisoned {
		e.uncoveredAfterPoison++
	} else {
		e.accumulator.AddTip(traceID, tipHash, len(entries))

		// A sustained but rollback-able checkpoint write failure keeps every tip
		// pending for retry (that is the point — see writeCheckpoint), so without
		// a cap the pending set grows for as long as the outage lasts. Once the
		// cap is exceeded, drop the oldest tips — bounded, observable data loss
		// in exchange for a bounded pending set.
		maxPending := e.effectiveMaxPendingTips(checkpointInterval)
		if dropped := e.accumulator.TrimPending(maxPending); dropped > 0 {
			e.pendingCapDropped += dropped
			if !e.pendingCapWarned {
				e.pendingCapWarned = true
				e.logger.Error("agentaudit: pending tip set exceeded its cap; dropping oldest tips — "+
					"checkpoint writes are failing persistently and the dropped traces can no longer be covered by any checkpoint",
					zap.Int("max_pending_tips", maxPending),
					zap.Int("dropped", dropped))
			}
		}
	}

	// Step 6: checkpoint if interval reached (and not backing off after a
	// failed attempt).
	if e.shouldCheckpoint(checkpointInterval) {
		if err := e.writeCheckpoint(); err != nil {
			// Once pinned at the pending-tip cap, nextCheckpointRetryAt's clamp
			// means shouldCheckpoint retries on literally every seal for as long
			// as the outage lasts (see its doc comment) — logging each of those
			// failures would flood the log for no new information beyond what the
			// one-time pendingCapWarned log and the Shutdown summary already give.
			// Below the cap, attempts are already rare (the backoff is doing its
			// job), so log every one of those.
			if !e.pendingCapWarned {
				e.logger.Error("agentaudit: write checkpoint", zap.Error(err))
			}
		}
	}

	// Step 7: mark WAL sealed (calls Sync), carrying the tip so Compact below
	// can retain it if the trace is still pending a checkpoint.
	if e.wal != nil {
		sealTipHash, sealEntryCount := sealedMarkerTip(e.accumulator, traceID, tipHash, len(entries))
		if err := e.wal.MarkSealed(traceID, sealTipHash, sealEntryCount); err != nil {
			e.logger.Error("agentaudit: WAL mark sealed",
				zap.String("trace_id", traceID), zap.Error(err))
		}
	}

	// Step 8: schedule compact.
	e.scheduleWALCompact()
}

// scheduleWALCompact launches a background WAL.Compact OUTSIDE the lock
// (compactWG.Add(1) happens here, while the lock is held, so it is observed
// by Shutdown's compactWG.Wait()). On success, clears sealedTraces: entries
// only need to persist until Compact removes the sealed WAL records; after
// that the map can grow again from scratch. Called under e.mu, from every
// early-return branch in sealTrace that marks a trace sealed without
// reaching the ordinary Step 8 at the bottom — the schema_version/chain-build
// quarantine branches and the logPoisoned branch alike.
//
// The permanent, sustained case is what makes this load-bearing: once
// logPoisoned is set it never clears, so every future seal keeps taking that
// same early return, and without scheduling Compact there too it would never
// run again for the rest of the process's lifetime (see issue #28). The
// schema_version/chain-build branches are one-off failures for a single
// malformed trace, not a permanent state, so a later trace's ordinary seal
// would eventually reach Step 8 and compact them away regardless — but
// calling this uniformly from every such branch, rather than reasoning about
// which ones strictly need it, is simpler and removes the "one-off in
// practice" judgment call as a place a future change could get wrong.
func (e *agentAuditExporter) scheduleWALCompact() {
	if e.wal == nil {
		return
	}
	e.compactWG.Add(1)
	w := e.wal
	acc := e.accumulator
	go func() {
		defer e.compactWG.Done()
		if err := w.Compact(acc.PendingTips()); err != nil {
			e.logger.Warn("agentaudit: background WAL compact failed", zap.Error(err))
			return
		}
		e.mu.Lock()
		e.sealedTraces = make(map[string]struct{})
		e.mu.Unlock()
	}()
}

// quarantinePath is the sidecar the exporter writes records to when it cannot
// seal them into a chain. It sits next to the WAL so it inherits the same
// directory and retention the operator already manages for in-flight data.
func (e *agentAuditExporter) quarantinePath() string {
	return e.cfg.WalPath + quarantineSuffix
}

// quarantineRecords writes records that cannot be sealed to the quarantine
// sidecar, one JSON object per line, and logs where they went and what they
// were. It is the difference between "these spans were destroyed" and "these
// spans were set aside for a human": the audit log itself has no way to record
// a gap, so if the records are erased with only a counter in a log line, no
// operator can tell what was lost or reconstruct it.
//
// Best-effort by design — a quarantine failure is logged, not propagated,
// because the caller's alternative is to seal an unverifiable chain. Called
// with e.mu held; during Start it runs before the background goroutine
// that would contend for it exists.
func (e *agentAuditExporter) quarantineRecords(traceID string, recs []record.AuditRecord, versions []string, reason string) int {
	bySpanID := make(map[string]record.AuditRecord, len(recs))
	spanIDs := make([]string, 0, len(recs))
	seenVersions := map[string]struct{}{}
	for _, rec := range recs {
		if _, seen := bySpanID[rec.SpanID]; !seen {
			spanIDs = append(spanIDs, rec.SpanID)
		}
		bySpanID[rec.SpanID] = rec
		seenVersions[rec.SchemaVersion] = struct{}{}
	}
	sort.Strings(spanIDs)

	// Derive the versions rather than trusting the caller to have got them
	// right: this file's whole job is telling an operator what happened, so it
	// must not report a set that does not match the records beside it.
	if versions == nil {
		versions = make([]string, 0, len(seenVersions))
		for v := range seenVersions {
			versions = append(versions, v)
		}
		sort.Strings(versions)
	}

	path := e.quarantinePath()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		e.logger.Error("agentaudit: cannot open quarantine file; unsealable records are being dropped with no copy retained",
			zap.String("trace_id", traceID),
			zap.String("path", path),
			zap.Strings("span_ids", spanIDs),
			zap.Error(err))
		return 0
	}
	defer func() { _ = f.Close() }()

	// Unlike the audit log, checkpoint file, and WAL — created eagerly at a
	// single point in Start — this file is created lazily, on whichever call
	// first fails to seal a trace. There is no "start of day" to hook a
	// one-time fsync into, so it is repeated on every call instead: cheap and
	// idempotent once the directory entry is already durable, and the only
	// way to cover the actual first-creation run without tracking extra state
	// to detect it. See issue #33.
	e.warnIfParentDirSyncFails("quarantine sidecar", path)

	written := 0
	for _, spanID := range spanIDs {
		line, err := json.Marshal(quarantineEntry{
			TraceID:        traceID,
			QuarantinedAt:  time.Now().UTC().Format(time.RFC3339),
			Reason:         reason,
			SchemaVersions: versions,
			CurrentSchema:  record.SchemaVersion,
			Record:         bySpanID[spanID],
		})
		if err != nil {
			e.logger.Error("agentaudit: marshalling quarantined record",
				zap.String("trace_id", traceID), zap.String("span_id", spanID), zap.Error(err))
			continue
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			e.logger.Error("agentaudit: writing quarantined record",
				zap.String("trace_id", traceID), zap.String("span_id", spanID), zap.Error(err))
			continue
		}
		written++
	}
	if err := f.Sync(); err != nil {
		e.logger.Warn("agentaudit: syncing quarantine file", zap.String("path", path), zap.Error(err))
	}

	e.logger.Error("agentaudit: records could not be sealed into a chain; they are quarantined and the trace is dropped",
		zap.String("trace_id", traceID),
		zap.String("reason", reason),
		zap.Strings("schema_versions", versions),
		zap.Strings("span_ids", spanIDs),
		zap.Int("records", len(recs)),
		zap.Int("quarantined", written),
		zap.String("quarantine_path", path))
	return written
}

// sealedMarkerTip decides what tip payload sealTrace's Step 7 should carry
// into the WAL's sealed marker: the trace's own tip if it is still awaiting a
// checkpoint, or an empty marker otherwise. "Otherwise" covers two distinct
// cases identically: Step 6's checkpoint attempt already committed this exact
// tip inline on this same seal (the ordinary, common case — see the crash
// window this closes at exporter.go's sealTrace Step 7), or the trace was
// never added to the accumulator at all (checkpointPoisoned, quarantined,
// unsealable — acc.PendingTips()[traceID] is then absent and the lookup is a
// safe nil-map read). Either way carrying the stale tipHash forward would let
// a crash before Step 8's Compact resurrect a tip that must not come back:
// already durably covered in the first case, permanently uncoverable in the
// second.
func sealedMarkerTip(acc *chain.Accumulator, traceID, tipHash string, entryCount int) (string, int) {
	if _, stillPending := acc.PendingTips()[traceID][tipHash]; !stillPending {
		return "", 0
	}
	return tipHash, entryCount
}

// markWALSealed marks traceID sealed in the WAL, logging rather than returning
// a failure. Called on the paths where a trace has been removed from the
// buffers but no chain could be written for it: without this its records
// replay on every restart, since Compact only drops entries for sealed traces.
// No tip is carried — these traces (quarantined or unsealable) are never added
// to the accumulator, so Compact drops the marker on its next pass regardless.
// Called either under e.mu, or from Start before the goroutine that contends
// for it exists.
func (e *agentAuditExporter) markWALSealed(traceID string) {
	if e.wal == nil {
		return
	}
	if err := e.wal.MarkSealed(traceID, "", 0); err != nil {
		e.logger.Warn("agentaudit: WAL mark sealed failed",
			zap.String("trace_id", traceID), zap.Error(err))
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

// syncParentDir fsyncs the directory containing path. A file's own contents
// being fsynced does not make the directory entry that names it durable: on
// the run that *creates* path, a crash before this returns can lose the file
// entirely even though its data separately reached disk. See issue #23.
//
// Only the os.Open-fails branch is exercised by tests (TestSyncParentDir_
// MissingParent, TestStart_ParentDirSyncFailureIsNonFatal); forcing Open to
// succeed and the subsequent Sync to fail is not portably reachable from
// package os without a fault-injection seam this package does not have, so
// that branch's correctness rests on d.Sync() simply forwarding the OS error,
// not on a dedicated test.
//
// This repo's CI (.github/workflows/ci.yml) runs ubuntu-latest only, so the
// Windows behavior this comment describes is unverified: on a platform where
// directory fsync is unsupported, every Start would log the warning below
// once per file, forever, with no operator remedy. That's deliberately not
// special-cased on runtime.GOOS without evidence — guessing wrong would trade
// a real durability improvement on an entire platform for an assumed one.
func syncParentDir(path string) error {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// warnIfParentDirSyncFails fsyncs path's parent directory, logging (rather
// than failing Start) if that does not succeed — see syncParentDir. The what
// parameter names the file for the log line, e.g. "audit log".
func (e *agentAuditExporter) warnIfParentDirSyncFails(what, path string) {
	if err := syncParentDir(path); err != nil {
		e.logger.Warn("agentaudit: syncing "+what+"'s parent directory; "+
			"a crash before this succeeds could lose a freshly created file",
			zap.String("path", path), zap.Error(err))
	}
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

// repairOrPoisonLog attempts to clear a torn trailing line left by a log write
// that failed and could not be rolled back, reusing the exact repair Start
// applies to a crash-torn file (repairTrailingPartialLine) so the next
// trace's write does not fuse onto the wreckage. Escalates to poisonLog only
// if the repair itself fails — at that point there is no way to guarantee
// where a further write would land, which is exactly the state poisonLog
// exists to stop. Called under e.mu. See issue #28.
//
// Unlike Start's own repair loop — which treats an uninspectable file
// (errRepairUnavailable) as non-fatal and lets the process continue, since
// nothing is yet known to be torn and refusing to start would deny a
// configuration that worked before that check existed — this treats the same
// error as poison-worthy. Start is a precautionary cold-boot check against a
// system with no known active fault; this runs immediately after a live write
// failure, where being unable to confirm the file is safe is a much stronger
// signal that something is already wrong.
func (e *agentAuditExporter) repairOrPoisonLog(traceID, cause string, causeErr error) {
	e.logger.Error(cause, zap.String("trace_id", traceID), zap.Error(causeErr))
	rep, repairErr := repairTrailingPartialLine(e.cfg.LogPath)
	if repairErr != nil {
		e.poisonLog("agentaudit: repairing the audit log after a failed write", repairErr, causeErr)
		return
	}
	switch {
	case rep.Dropped > 0:
		e.logger.Error("agentaudit: dropped a torn trailing line after a failed write",
			zap.String("trace_id", traceID),
			zap.Int64("bytes", rep.Dropped),
			zap.ByteString("dropped_prefix", rep.Prefix))
	case rep.Terminated > 0:
		e.logger.Warn("agentaudit: terminated an unterminated line after a failed write; "+
			"the fragment was syntactically complete, so it was not an interrupted write",
			zap.String("trace_id", traceID),
			zap.Int64("bytes", rep.Terminated),
			zap.ByteString("terminated_prefix", rep.Prefix))
	}
}

// logPoisonTornMarker is appended, best-effort, to the log's current tail
// when poisoning — see poisonLog. It can never be a prefix or suffix of a
// valid canonical audit record (these are JSON objects; a leading NUL is not
// valid JSON syntax and appending it directly after a complete JSON value
// with no separating newline invalidates that value's line too, since
// json.Unmarshal rejects trailing non-whitespace content), so it forces the
// file's actual final line to fail parsing regardless of what the triggering
// failure happened to leave behind.
const logPoisonTornMarker = "\x00 agentaudit: log poisoned, see errLogPoisoned \x00"

// poisonLog permanently disables further audit-log writes for this process.
// Called once a log write failure cannot be rolled back, and either an
// earlier entry of the same trace already landed this attempt or the inline
// repair repairOrPoisonLog attempts also fails: at that point there is no way
// to guarantee this trace is either fully present or fully absent. Future
// traces are quarantined instead — see sealTrace's logPoisoned check. Called
// under e.mu.
//
// Best-effort, appends logPoisonTornMarker to the file's current tail. Without
// this, a failure that happened to leave the file looking complete — nothing
// written at all, or a fragment that happens to be valid JSON missing only
// its newline (see repairTrailingPartialLine and the safeToRepairTail comment
// in sealTrace) — would poison writes for this process but leave nothing for
// VerifyLog to flag: the on-disk bytes alone are indistinguishable from an
// ordinary, complete trace. The marker forces the file's true final line to
// be unparseable, so it surfaces as torn_trailing_line — tolerated as the
// last line (nothing more is ever appended once poisoned), not silently
// absent. If the marker write itself fails, that gap stands for this
// instance: logged, not escalated further, since the process already knows
// to stop trusting this file regardless.
//
// What was already durably in the log before poisoning still verifies for
// the lifetime of this process, and a restart resumes cleanly:
// repairTrailingPartialLine repairs or drops whatever is left behind
// (marker included — it is itself an invalid, unterminated fragment) before
// the file is reopened. See issue #28.
func (e *agentAuditExporter) poisonLog(msg string, err, cause error) {
	if e.logPoisoned {
		return
	}
	e.logPoisoned = true
	fields := []zap.Field{zap.Error(err)}
	if cause != nil {
		fields = append(fields, zap.NamedError("cause", cause))
	}
	e.logger.Error(msg+" — audit-log writes are now permanently disabled for this process; "+
		"further sealed traces will be quarantined instead of logged",
		fields...)

	if _, werr := e.logFile.Write([]byte(logPoisonTornMarker)); werr != nil {
		e.logger.Warn("agentaudit: could not mark the audit log's tail as torn after poisoning; "+
			"whatever was left behind may look complete to the verifier",
			zap.Error(werr))
		return
	}
	if serr := e.logFile.Sync(); serr != nil {
		e.logger.Warn("agentaudit: syncing the poison marker", zap.Error(serr))
	}
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

// errLogPoisoned is returned once an audit-log write failure could not be
// rolled back or repaired. See agentAuditExporter.logPoisoned.
var errLogPoisoned = errors.New(
	"agentaudit: audit-log write failed and the torn tail it left could not be repaired; " +
		"further traces are quarantined instead of logged")

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
// alternative is dropping sealed traces — but that growth is itself capped;
// see effectiveMaxPendingTips and the TrimPending call in sealTrace. (Once
// checkpointing is *permanently* disabled the tips are all dropped instead;
// see poisonCheckpoint.)
func (e *agentAuditExporter) shouldCheckpoint(checkpointInterval int) bool {
	pending := e.accumulator.PendingCount()
	return pending >= checkpointInterval && pending >= e.checkpointRetryAt
}

// nextCheckpointRetryAt returns the pending count at which the next retry is
// allowed after a failed attempt at the given pending count. Called under e.mu.
//
// The result is clamped to effectiveMaxPendingTips. Without the clamp, a long
// enough run of consecutive failures could grow the backoff target past the
// pending-tip cap; TrimPending then holds pending at the cap forever, so
// pending could never again satisfy shouldCheckpoint's "pending >=
// checkpointRetryAt" condition and retries would stop permanently — even after
// the underlying outage heals. Clamping guarantees pending sitting at the cap
// always qualifies for a retry, so recovery is still detected.
//
// This deliberately gives up the backoff's thinning once pending is pinned at
// the cap: from that point every seal both retries and re-trims, for as long
// as the outage lasts. That is the trade for guaranteeing recovery is detected
// on the very next successful write rather than at some later, possibly much
// larger, pending count. See the pendingCapWarned check around the
// writeCheckpoint call in sealTrace, which is what keeps that steady-state
// retrying from also flooding the log.
func (e *agentAuditExporter) nextCheckpointRetryAt(pending int) int {
	next := pending + 1
	if e.checkpointFailures > 1 {
		if pending > maxCheckpointRetryGap {
			next = pending + maxCheckpointRetryGap
		} else {
			next = pending * 2
		}
	}
	if maxPending := e.effectiveMaxPendingTips(e.effectiveCheckpointInterval()); maxPending > 0 && next > maxPending {
		next = maxPending
	}
	return next
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
		// A successful write drains the tips the cap was protecting against —
		// the next episode of sustained failures should warn again.
		e.pendingCapWarned = false
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

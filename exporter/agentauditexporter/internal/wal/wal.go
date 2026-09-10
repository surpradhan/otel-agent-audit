// Package wal implements a crash-recovery write-ahead log for in-progress trace buffers.
//
// Write semantics: AppendSpan does not call Sync (kernel buffers the write).
// MarkSealed and Compact call Sync() before returning.
// This provides crash-recovery for in-progress traces but not power-loss durability.
//
// Sealed-but-uncheckpointed tips: MarkSealed carries the sealed trace's tip hash
// and entry count. A sealed marker is not simply forgotten once its span entries
// are compacted away — Compact keeps re-writing it forward, unexpanded, for as
// long as the caller says that specific tip is still pending a checkpoint. That
// lets Start re-add the tip straight to the accumulator via Replay's
// sealedPending result after a crash, without re-sealing the trace (which would
// duplicate its already-durable log entries) and without losing checkpoint
// coverage for it forever. See the pending parameter on Compact and issue #22.
//
// Thread-safety: WAL has an internal mutex.
//   - All writes (AppendSpan, MarkSealed) are serialized by the WAL's internal mutex.
//   - Compact acquires the same mutex, atomically renames a temp file over the WAL,
//     then re-opens the fd before releasing. No concurrent write can touch the
//     unlinked inode after Compact completes.
//   - Close acquires the mutex; call only after compactWG.Wait() in Shutdown.
//   - Replay is called only from Start, before any concurrent writes begin.
package wal

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
)

type entryType string

const (
	entryTypeSpan   entryType = "span"
	entryTypeSealed entryType = "sealed"
)

// maxScanTokenSize caps the bufio.Scanner token size for WAL lines.
// The 64 KB default is too small for traces with many spans; 4 MB provides headroom.
const maxScanTokenSize = 4 * 1024 * 1024

type walEntry struct {
	Type    entryType           `json:"type"`
	TraceID string              `json:"trace_id"`
	Record  *record.AuditRecord `json:"record,omitempty"`

	// TipHash and EntryCount are set on an entryTypeSealed entry whose trace was
	// added to the accumulator's pending set (i.e. checkpointing was not
	// poisoned at seal time). Empty/zero for a trace that was quarantined,
	// unsealable, or sealed while poisoned — those were never pending, so there
	// is nothing to restore for them. See SealedTip.
	TipHash    string `json:"tip_hash,omitempty"`
	EntryCount int    `json:"entry_count,omitempty"`
}

// SealedTip is a sealed trace's chain tip, carried by an entryTypeSealed WAL
// entry so a crash before the next successful checkpoint does not lose
// coverage for it. Mirrors chain.TraceTip's fields without importing the chain
// package, keeping wal's only dependency on the exporter's data model.
type SealedTip struct {
	TraceID    string
	TipHash    string
	EntryCount int
}

// WAL is a JSONL write-ahead log for buffered trace spans.
type WAL struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

// Open opens or creates the WAL file at path for appending.
func Open(path string) (*WAL, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("wal: open %q: %w", path, err)
	}
	return &WAL{path: path, f: f}, nil
}

// AppendSpan writes a span entry to the WAL. Does not call Sync.
func (w *WAL) AppendSpan(traceID string, rec record.AuditRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	entry := walEntry{Type: entryTypeSpan, TraceID: traceID, Record: &rec}
	return w.appendEntry(entry)
}

// MarkSealed writes a sealed marker and calls Sync. tipHash and entryCount are
// the trace's chain tip as added to the accumulator (chain.TipHash and the
// sealed entry count); pass "" and 0 for a trace that was never added to the
// accumulator (quarantined, unsealable, or sealed while checkpointing was
// poisoned) — Compact treats an empty TipHash as nothing to preserve.
func (w *WAL) MarkSealed(traceID, tipHash string, entryCount int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	entry := walEntry{Type: entryTypeSealed, TraceID: traceID, TipHash: tipHash, EntryCount: entryCount}
	if err := w.appendEntry(entry); err != nil {
		return err
	}
	return w.f.Sync()
}

// appendEntry serializes entry as a JSONL line. Caller holds mu.
func (w *WAL) appendEntry(entry walEntry) error {
	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("wal: marshal entry: %w", err)
	}
	line = append(line, '\n')
	if _, err := w.f.Write(line); err != nil {
		return fmt.Errorf("wal: write entry: %w", err)
	}
	return nil
}

// Replay reads the WAL and returns all in-progress (non-sealed) traces, plus
// any sealed trace's tip that must be restored to the accumulator because it
// was not yet checkpoint-committed when the WAL was last written (see
// Compact). Sealed traces are excluded from the buffers result — the caller
// must not re-seal them, only re-add their tip via sealedPending. Partial
// final lines from a crash are tolerated (silently skipped).
// Call this from Start before any concurrent writes begin.
func (w *WAL) Replay() (buffers map[string][]record.AuditRecord, sealedPending []SealedTip, err error) {
	// Read-only scan; no lock needed (called only from Start, single-threaded).
	rf, err := os.Open(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]record.AuditRecord{}, nil, nil
		}
		return nil, nil, fmt.Errorf("wal: replay open %q: %w", w.path, err)
	}
	defer func() { _ = rf.Close() }()

	sealed := map[string]bool{}
	buffers = map[string][]record.AuditRecord{}

	scanner := bufio.NewScanner(rf)
	scanner.Buffer(make([]byte, 64*1024), maxScanTokenSize)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry walEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue // tolerate partial final line from a crash
		}
		switch entry.Type {
		case entryTypeSpan:
			if !sealed[entry.TraceID] && entry.Record != nil {
				buffers[entry.TraceID] = append(buffers[entry.TraceID], *entry.Record)
			}
		case entryTypeSealed:
			sealed[entry.TraceID] = true
			delete(buffers, entry.TraceID)
			if entry.TipHash != "" {
				sealedPending = append(sealedPending, SealedTip{
					TraceID:    entry.TraceID,
					TipHash:    entry.TipHash,
					EntryCount: entry.EntryCount,
				})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("wal: replay scan: %w", err)
	}
	return buffers, sealedPending, nil
}

// Compact rewrites the WAL, dropping in-progress span entries for sealed
// traces. A sealed marker itself is only dropped once pending says its
// specific tip is no longer awaiting a checkpoint (covered by one, or
// deliberately abandoned by a policy like the pending-tip cap) — until then it
// is carried forward unexpanded so Replay can restore the tip after a crash
// instead of silently losing checkpoint coverage for it. Pass the
// accumulator's current pending tips (e.g. Accumulator.PendingTips); a
// nil/empty map keeps no sealed markers, which is correct once nothing is
// pending.
//
// Retention is keyed by (trace_id, tip_hash), not trace_id alone: the same
// trace_id can have two independent sealed markers outstanding at once (a
// duplicate_trace_segment re-seal), and trace-ID-only matching would keep an
// already-settled marker just because its trace_id has another, unrelated tip
// still pending — resurrecting it into the accumulator on the next restart.
//
// It acquires the write lock, atomically renames the new file over the old
// one, then re-opens the append fd so subsequent AppendSpan calls are not
// writing to the unlinked inode. Compact calls Sync before rename.
func (w *WAL) Compact(pending map[string]map[string]struct{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Read the WAL to find in-progress (non-sealed) entries.
	rf, err := os.Open(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("wal: compact open %q: %w", w.path, err)
	}

	type spanEntry struct {
		traceID string
		rec     record.AuditRecord
	}
	sealed := map[string]bool{}
	var spans []spanEntry
	var keepSealed []walEntry

	scanner := bufio.NewScanner(rf)
	scanner.Buffer(make([]byte, 64*1024), maxScanTokenSize)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry walEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		switch entry.Type {
		case entryTypeSpan:
			if !sealed[entry.TraceID] && entry.Record != nil {
				spans = append(spans, spanEntry{entry.TraceID, *entry.Record})
			}
		case entryTypeSealed:
			sealed[entry.TraceID] = true
			// Remove previously buffered spans for this trace.
			filtered := spans[:0]
			for _, s := range spans {
				if s.traceID != entry.TraceID {
					filtered = append(filtered, s)
				}
			}
			spans = filtered
			if hashes, ok := pending[entry.TraceID]; ok {
				if _, stillPending := hashes[entry.TipHash]; stillPending {
					keepSealed = append(keepSealed, entry)
				}
			}
		}
	}
	_ = rf.Close()
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("wal: compact scan: %w", err)
	}

	// Write compacted content to a temp file.
	tmpPath := w.path + ".tmp"
	tf, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("wal: compact create temp: %w", err)
	}

	enc := json.NewEncoder(tf)
	for _, s := range spans {
		entry := walEntry{Type: entryTypeSpan, TraceID: s.traceID, Record: &s.rec}
		if err := enc.Encode(entry); err != nil {
			_ = tf.Close()
			_ = os.Remove(tmpPath)
			return fmt.Errorf("wal: compact encode: %w", err)
		}
	}
	for _, entry := range keepSealed {
		if err := enc.Encode(entry); err != nil {
			_ = tf.Close()
			_ = os.Remove(tmpPath)
			return fmt.Errorf("wal: compact encode sealed marker: %w", err)
		}
	}
	if err := tf.Sync(); err != nil {
		_ = tf.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("wal: compact sync: %w", err)
	}
	_ = tf.Close()

	// Atomic rename, then re-open the fd.
	if err := os.Rename(tmpPath, w.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("wal: compact rename: %w", err)
	}

	// Re-open the append fd so AppendSpan doesn't write to the unlinked inode.
	_ = w.f.Close()
	newF, err := os.OpenFile(w.path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("wal: compact reopen: %w", err)
	}
	w.f = newF
	return nil
}

// Close closes the WAL file. Call only after compactWG.Wait() in Shutdown.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f != nil {
		err := w.f.Close()
		w.f = nil
		return err
	}
	return nil
}

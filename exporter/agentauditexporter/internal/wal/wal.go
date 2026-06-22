// Package wal implements a crash-recovery write-ahead log for in-progress trace buffers.
//
// Write semantics: AppendSpan does not call Sync (kernel buffers the write).
// MarkSealed and Compact call Sync() before returning.
// This provides crash-recovery for in-progress traces but not power-loss durability.
//
// Thread-safety: WAL has an internal RWMutex.
//   - AppendSpan and MarkSealed acquire a read lock (multiple writers serialized
//     by OS write-atomicity for small appends; lock protects the fd from Compact).
//   - Compact acquires the write lock, atomically renames a temp file over the WAL,
//     then re-opens the fd before releasing. No concurrent AppendSpan can write to
//     the unlinked inode after Compact completes.
//   - Close acquires the write lock; call only after compactWG.Wait() in Shutdown.
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

type walEntry struct {
	Type    entryType           `json:"type"`
	TraceID string              `json:"trace_id"`
	Record  *record.AuditRecord `json:"record,omitempty"`
}

// WAL is a JSONL write-ahead log for buffered trace spans.
type WAL struct {
	mu   sync.RWMutex
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
	w.mu.RLock()
	defer w.mu.RUnlock()
	entry := walEntry{Type: entryTypeSpan, TraceID: traceID, Record: &rec}
	return w.appendEntry(entry)
}

// MarkSealed writes a sealed marker and calls Sync.
func (w *WAL) MarkSealed(traceID string) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	entry := walEntry{Type: entryTypeSealed, TraceID: traceID}
	if err := w.appendEntry(entry); err != nil {
		return err
	}
	return w.f.Sync()
}

// appendEntry serializes entry as a JSONL line. Caller holds at least RLock.
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

// Replay reads the WAL and returns all in-progress (non-sealed) traces.
// Sealed traces are excluded from the result. Partial final lines from a crash
// are tolerated (silently skipped).
// Call this from Start before any concurrent writes begin.
func (w *WAL) Replay() (map[string][]record.AuditRecord, error) {
	// Read-only scan; no lock needed (called only from Start, single-threaded).
	rf, err := os.Open(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]record.AuditRecord{}, nil
		}
		return nil, fmt.Errorf("wal: replay open %q: %w", w.path, err)
	}
	defer func() { _ = rf.Close() }()

	sealed := map[string]bool{}
	buffers := map[string][]record.AuditRecord{}

	scanner := bufio.NewScanner(rf)
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
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("wal: replay scan: %w", err)
	}
	return buffers, nil
}

// Compact rewrites the WAL omitting sealed trace entries. It acquires the write
// lock, atomically renames the new file over the old one, then re-opens the
// append fd so subsequent AppendSpan calls are not writing to the unlinked inode.
// Compact calls Sync before rename.
func (w *WAL) Compact() error {
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

	scanner := bufio.NewScanner(rf)
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

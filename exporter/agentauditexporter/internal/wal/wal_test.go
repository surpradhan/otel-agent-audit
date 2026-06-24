package wal_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/wal"
)

func makeRecord(traceID, spanID string, startNano uint64) record.AuditRecord {
	return record.AuditRecord{
		SchemaVersion:     record.SchemaVersion,
		TraceID:           traceID,
		SpanID:            spanID,
		StartTimeUnixNano: startNano,
		EndTimeUnixNano:   startNano + 1000,
		SpanName:          "test.span",
		AuditKind:         record.AuditKindTask,
		Status:            "Ok",
	}
}

func openWAL(t *testing.T) (*wal.WAL, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.wal")
	w, err := wal.Open(path)
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, path
}

// TestWAL_AppendAndReplay verifies that two appended spans are returned by Replay.
func TestWAL_AppendAndReplay(t *testing.T) {
	w, _ := openWAL(t)

	rec0 := makeRecord("trace001", "span001", 1000)
	rec1 := makeRecord("trace001", "span002", 2000)
	if err := w.AppendSpan("trace001", rec0); err != nil {
		t.Fatalf("AppendSpan 0: %v", err)
	}
	if err := w.AppendSpan("trace001", rec1); err != nil {
		t.Fatalf("AppendSpan 1: %v", err)
	}

	buffers, err := w.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}

	recs, ok := buffers["trace001"]
	if !ok {
		t.Fatal("trace001 not found in replay")
	}
	if len(recs) != 2 {
		t.Errorf("expected 2 records for trace001, got %d", len(recs))
	}
}

// TestWAL_ReplaySkipsSealed verifies that sealed traces are excluded from Replay.
func TestWAL_ReplaySkipsSealed(t *testing.T) {
	w, _ := openWAL(t)

	rec0 := makeRecord("trace001", "span001", 1000)
	rec1 := makeRecord("trace001", "span002", 2000)
	if err := w.AppendSpan("trace001", rec0); err != nil {
		t.Fatalf("AppendSpan 0: %v", err)
	}
	if err := w.AppendSpan("trace001", rec1); err != nil {
		t.Fatalf("AppendSpan 1: %v", err)
	}
	if err := w.MarkSealed("trace001"); err != nil {
		t.Fatalf("MarkSealed: %v", err)
	}

	buffers, err := w.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(buffers) != 0 {
		t.Errorf("expected empty map after seal, got %d entries", len(buffers))
	}
}

// TestWAL_CompactDropsSealed verifies that Compact removes sealed trace entries
// and Replay after Compact returns only in-progress traces.
func TestWAL_CompactDropsSealed(t *testing.T) {
	w, _ := openWAL(t)

	rec0 := makeRecord("trace001", "span001", 1000)
	rec1 := makeRecord("trace002", "span002", 2000)
	rec2 := makeRecord("trace002", "span003", 3000)

	if err := w.AppendSpan("trace001", rec0); err != nil {
		t.Fatalf("AppendSpan trace001: %v", err)
	}
	if err := w.AppendSpan("trace002", rec1); err != nil {
		t.Fatalf("AppendSpan trace002 span1: %v", err)
	}
	if err := w.AppendSpan("trace002", rec2); err != nil {
		t.Fatalf("AppendSpan trace002 span2: %v", err)
	}
	// Seal trace001; trace002 remains open.
	if err := w.MarkSealed("trace001"); err != nil {
		t.Fatalf("MarkSealed trace001: %v", err)
	}

	if err := w.Compact(); err != nil {
		t.Fatalf("Compact: %v", err)
	}

	buffers, err := w.Replay()
	if err != nil {
		t.Fatalf("Replay after compact: %v", err)
	}

	if _, ok := buffers["trace001"]; ok {
		t.Error("trace001 should have been removed by Compact")
	}
	recs2, ok2 := buffers["trace002"]
	if !ok2 || len(recs2) != 2 {
		t.Errorf("trace002: expected 2 records, got %d (ok=%v)", len(buffers["trace002"]), ok2)
	}
}

// TestWAL_CompactSafe_Concurrent races AppendSpan against Compact to verify
// the internal RWMutex prevents data races (detected by -race).
func TestWAL_CompactSafe_Concurrent(t *testing.T) {
	w, _ := openWAL(t)

	// Seed some initial data.
	for i := 0; i < 5; i++ {
		rec := makeRecord("trace001", "span001", uint64(i*1000))
		_ = w.AppendSpan("trace001", rec)
	}

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			if i%3 == 0 {
				_ = w.Compact()
			} else {
				rec := makeRecord("trace002", "span002", uint64(i*1000))
				_ = w.AppendSpan("trace002", rec)
			}
		}()
	}
	wg.Wait()
	// No assertions needed beyond the race detector not triggering.
}

// TestWAL_Open_InvalidPath verifies that Open returns an error when the parent
// directory does not exist.
func TestWAL_Open_InvalidPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent_subdir", "test.wal")
	_, err := wal.Open(path)
	if err == nil {
		t.Fatal("expected error when parent directory does not exist, got nil")
	}
}

// TestWAL_Close_Idempotent verifies that calling Close a second time on an
// already-closed WAL returns nil (the nil-file guard in Close is exercised).
func TestWAL_Close_Idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idempotent.wal")
	w, err := wal.Open(path)
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close (already closed): %v", err)
	}
}

// TestWAL_Replay_UnlinkedFile verifies that Replay returns an empty map when the
// WAL file has been deleted from the filesystem after Open (the append fd still
// holds the inode, but os.Open on the path fails with IsNotExist).
func TestWAL_Replay_UnlinkedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unlinked.wal")
	w, err := wal.Open(path)
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	defer func() { _ = w.Close() }()

	if err := os.Remove(path); err != nil {
		t.Fatalf("os.Remove: %v", err)
	}

	buffers, err := w.Replay()
	if err != nil {
		t.Fatalf("Replay on unlinked file: %v", err)
	}
	if len(buffers) != 0 {
		t.Errorf("expected empty buffers for unlinked WAL, got %d entries", len(buffers))
	}
}

// TestWAL_Compact_UnlinkedFile verifies that Compact returns nil when the WAL
// file has been deleted from the filesystem after Open (the os.IsNotExist
// early-return path in Compact).
func TestWAL_Compact_UnlinkedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compact-unlinked.wal")
	w, err := wal.Open(path)
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	defer func() { _ = w.Close() }()

	if err := os.Remove(path); err != nil {
		t.Fatalf("os.Remove: %v", err)
	}

	if err := w.Compact(); err != nil {
		t.Fatalf("Compact on unlinked file: %v", err)
	}
}

// TestWAL_ReplayTolerantPartialLine verifies that a truncated final line
// (simulating a crash mid-write) does not cause Replay to return an error.
func TestWAL_ReplayTolerantPartialLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partial.wal")
	w, err := wal.Open(path)
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}

	// Write one good span.
	rec := makeRecord("trace001", "span001", 1000)
	if err := w.AppendSpan("trace001", rec); err != nil {
		t.Fatalf("AppendSpan: %v", err)
	}
	_ = w.Close()

	// Append a truncated (partial) JSON line to simulate a crash mid-write.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open for truncation append: %v", err)
	}
	_, _ = f.Write([]byte(`{"type":"span","trace_id":"trace002","record":{`)) // truncated
	_ = f.Close()

	// Reopen and replay.
	w2, err := wal.Open(path)
	if err != nil {
		t.Fatalf("wal.Open after truncation: %v", err)
	}
	defer func() { _ = w2.Close() }()

	buffers, err := w2.Replay()
	if err != nil {
		t.Fatalf("Replay with partial line: %v", err)
	}
	// The good span should be present; the partial line should be skipped.
	if recs, ok := buffers["trace001"]; !ok || len(recs) != 1 {
		t.Errorf("trace001: expected 1 record, got %d (ok=%v)", len(buffers["trace001"]), ok)
	}
	if _, ok := buffers["trace002"]; ok {
		t.Error("trace002 partial line should have been skipped")
	}
}

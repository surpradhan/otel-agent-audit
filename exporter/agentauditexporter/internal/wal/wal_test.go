package wal_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/wal"
)

func makeRecord(traceID, spanID string, startNano record.UnixNano) record.AuditRecord {
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

	buffers, _, err := w.Replay()
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
	if err := w.MarkSealed("trace001", "", 0); err != nil {
		t.Fatalf("MarkSealed: %v", err)
	}

	buffers, _, err := w.Replay()
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
	if err := w.MarkSealed("trace001", "", 0); err != nil {
		t.Fatalf("MarkSealed trace001: %v", err)
	}

	if err := w.Compact(nil); err != nil {
		t.Fatalf("Compact: %v", err)
	}

	buffers, _, err := w.Replay()
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

// TestWAL_Replay_ReturnsSealedPendingTip verifies that a sealed entry carrying
// a tip hash and entry count surfaces via Replay's sealedPending result, with
// the trace still excluded from the in-progress buffers.
func TestWAL_Replay_ReturnsSealedPendingTip(t *testing.T) {
	w, _ := openWAL(t)

	rec := makeRecord("trace001", "span001", 1000)
	if err := w.AppendSpan("trace001", rec); err != nil {
		t.Fatalf("AppendSpan: %v", err)
	}
	if err := w.MarkSealed("trace001", "deadbeef", 1); err != nil {
		t.Fatalf("MarkSealed: %v", err)
	}

	buffers, sealedPending, err := w.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if _, ok := buffers["trace001"]; ok {
		t.Error("trace001 must not appear as an in-progress buffer once sealed")
	}
	if len(sealedPending) != 1 {
		t.Fatalf("sealedPending: got %d entries, want 1", len(sealedPending))
	}
	got := sealedPending[0]
	want := wal.SealedTip{TraceID: "trace001", TipHash: "deadbeef", EntryCount: 1}
	if got != want {
		t.Errorf("sealedPending[0] = %+v, want %+v", got, want)
	}
}

// TestWAL_Replay_OmitsSealedTipWithoutTipHash verifies that a sealed marker
// with no tip payload (a quarantined or unsealable trace — see
// agentAuditExporter.markWALSealed) is not surfaced as a pending tip: there is
// nothing to restore for a trace that was never added to the accumulator.
func TestWAL_Replay_OmitsSealedTipWithoutTipHash(t *testing.T) {
	w, _ := openWAL(t)

	if err := w.MarkSealed("trace001", "", 0); err != nil {
		t.Fatalf("MarkSealed: %v", err)
	}

	_, sealedPending, err := w.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(sealedPending) != 0 {
		t.Errorf("sealedPending: got %d entries, want 0 for a tip-less seal", len(sealedPending))
	}
}

// TestWAL_Compact_RetainsSealedMarkerForPendingTip verifies that Compact keeps
// a sealed trace's marker (and its tip payload) when the caller says that
// trace is still pending a checkpoint — the crash-durability guarantee the
// naive "just skip MarkSealed on checkpoint failure" fix cannot provide
// without either losing the tip on a crash or re-sealing and duplicating the
// trace's already-durable log entries.
func TestWAL_Compact_RetainsSealedMarkerForPendingTip(t *testing.T) {
	w, path := openWAL(t)

	rec := makeRecord("trace001", "span001", 1000)
	if err := w.AppendSpan("trace001", rec); err != nil {
		t.Fatalf("AppendSpan: %v", err)
	}
	if err := w.MarkSealed("trace001", "deadbeef", 1); err != nil {
		t.Fatalf("MarkSealed: %v", err)
	}

	pending := map[string]map[string]struct{}{"trace001": {"deadbeef": {}}}
	if err := w.Compact(pending); err != nil {
		t.Fatalf("Compact: %v", err)
	}

	// The span itself must still be gone — only the lightweight marker survives.
	buffers, sealedPending, err := w.Replay()
	if err != nil {
		t.Fatalf("Replay after compact: %v", err)
	}
	if _, ok := buffers["trace001"]; ok {
		t.Error("trace001's span entries should not be resurrected by a retained sealed marker")
	}
	if len(sealedPending) != 1 || sealedPending[0].TraceID != "trace001" || sealedPending[0].TipHash != "deadbeef" {
		t.Errorf("sealedPending after compact = %+v, want [{trace001 deadbeef 1}]", sealedPending)
	}

	// Simulate a second restart with the SAME on-disk WAL (no further writes):
	// re-opening it must still find the retained marker, proving it survived
	// Compact's rewrite rather than merely surviving in the live fd's buffer.
	w2, err := wal.Open(path)
	if err != nil {
		t.Fatalf("re-opening WAL: %v", err)
	}
	defer func() { _ = w2.Close() }()
	_, sealedPending2, err := w2.Replay()
	if err != nil {
		t.Fatalf("Replay on reopened WAL: %v", err)
	}
	if len(sealedPending2) != 1 || sealedPending2[0].TipHash != "deadbeef" {
		t.Errorf("sealedPending after reopen = %+v, want the retained tip to survive on disk", sealedPending2)
	}
}

// TestWAL_Compact_DropsSealedMarkerOnceNotPending verifies that once the
// caller reports a trace is no longer pending (checkpointed, or deliberately
// abandoned), Compact stops carrying its marker forward — otherwise the WAL
// would retain a sealed-pending entry forever.
func TestWAL_Compact_DropsSealedMarkerOnceNotPending(t *testing.T) {
	w, _ := openWAL(t)

	rec := makeRecord("trace001", "span001", 1000)
	if err := w.AppendSpan("trace001", rec); err != nil {
		t.Fatalf("AppendSpan: %v", err)
	}
	if err := w.MarkSealed("trace001", "deadbeef", 1); err != nil {
		t.Fatalf("MarkSealed: %v", err)
	}

	// Empty pending set: trace001's tip has already been committed by a
	// checkpoint (or deliberately dropped) by the time Compact runs.
	if err := w.Compact(map[string]map[string]struct{}{}); err != nil {
		t.Fatalf("Compact: %v", err)
	}

	_, sealedPending, err := w.Replay()
	if err != nil {
		t.Fatalf("Replay after compact: %v", err)
	}
	if len(sealedPending) != 0 {
		t.Errorf("sealedPending after compact = %+v, want none once the tip is no longer pending", sealedPending)
	}
}

// TestWAL_Compact_TracksTraceAndTipHashIndependently pins the fix for the case
// where the same trace_id has two independent sealed tips outstanding at
// once: a re-delivered root span for an already-sealed trace_id starts a
// second, independent chain (duplicate_trace_segment) once the exporter's
// re-seal guard has cleared, producing a second WAL sealed marker under the
// same trace_id before either tip has settled. Retention must be keyed by
// (trace_id, tip_hash), not trace_id alone — trace-ID-only matching would keep
// BOTH markers as long as the trace_id has any pending tip at all, resurrecting
// an already-settled one into the accumulator on the next restart.
func TestWAL_Compact_TracksTraceAndTipHashIndependently(t *testing.T) {
	w, _ := openWAL(t)

	// Two independent seals of the SAME trace_id, each carrying its own tip.
	if err := w.MarkSealed("trace001", "hash1", 1); err != nil {
		t.Fatalf("MarkSealed hash1: %v", err)
	}
	if err := w.MarkSealed("trace001", "hash2", 1); err != nil {
		t.Fatalf("MarkSealed hash2: %v", err)
	}

	// hash1 has already been committed by a checkpoint (or deliberately
	// dropped); only hash2 is still pending.
	pending := map[string]map[string]struct{}{"trace001": {"hash2": {}}}
	if err := w.Compact(pending); err != nil {
		t.Fatalf("Compact: %v", err)
	}

	_, sealedPending, err := w.Replay()
	if err != nil {
		t.Fatalf("Replay after compact: %v", err)
	}
	if len(sealedPending) != 1 {
		t.Fatalf("sealedPending after compact = %+v, want exactly 1 (only hash2 is still pending)", sealedPending)
	}
	if sealedPending[0].TipHash != "hash2" {
		t.Errorf("sealedPending[0].TipHash = %q, want %q — hash1's settled marker must not survive "+
			"Compact just because trace001 has another, unrelated tip still pending", sealedPending[0].TipHash, "hash2")
	}
}

// TestWAL_Replay_SecondSegmentSpanSurvivesRetainedEarlierMarker pins a gap the
// tip-hash-retention fix opened: once Compact can retain a sealed marker
// while its tip is pending, a duplicate_trace_segment re-seal can append a
// brand new segment's spans for the SAME trace_id AFTER that retained marker
// in the WAL. Replay's `sealed` map latches permanently once true, so
// without unlatching on a later span, the new segment's spans would be
// silently treated as belonging to the old, already-sealed segment and
// dropped — with no verifier signal, since they were never durably logged at
// all. This never arose before the retention fix: Compact used to evict a
// sealed trace's marker unconditionally, so a trace_id's marker and any
// later segment's spans could never coexist in one file.
func TestWAL_Replay_SecondSegmentSpanSurvivesRetainedEarlierMarker(t *testing.T) {
	w, _ := openWAL(t)

	// Segment 1 seals; its tip is still pending, so a Compact retains the marker.
	if err := w.MarkSealed("trace001", "hash1", 1); err != nil {
		t.Fatalf("MarkSealed hash1: %v", err)
	}
	if err := w.Compact(map[string]map[string]struct{}{"trace001": {"hash1": {}}}); err != nil {
		t.Fatalf("Compact (retain hash1): %v", err)
	}

	// Segment 2 (a duplicate_trace_segment re-seal) starts buffering under the
	// same trace_id, appended after the retained marker.
	seg2Span := makeRecord("trace001", "span-seg2", 5000)
	if err := w.AppendSpan("trace001", seg2Span); err != nil {
		t.Fatalf("AppendSpan (segment 2): %v", err)
	}

	buffers, sealedPending, err := w.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(sealedPending) != 1 || sealedPending[0].TipHash != "hash1" {
		t.Errorf("sealedPending = %+v, want exactly segment 1's hash1", sealedPending)
	}
	recs, ok := buffers["trace001"]
	if !ok || len(recs) != 1 || recs[0].SpanID != "span-seg2" {
		t.Errorf("buffers[trace001] = %+v (ok=%v), want segment 2's still-open span, "+
			"not silently dropped as if it belonged to the sealed segment 1", recs, ok)
	}
}

// TestWAL_Compact_DoesNotDropOpenSecondSegmentSpan is
// TestWAL_Replay_SecondSegmentSpanSurvivesRetainedEarlierMarker's Compact-side
// counterpart: an ORDINARY subsequent Compact call (no crash at all) must not
// itself destroy segment 2's open span while rewriting the file.
func TestWAL_Compact_DoesNotDropOpenSecondSegmentSpan(t *testing.T) {
	w, _ := openWAL(t)

	if err := w.MarkSealed("trace001", "hash1", 1); err != nil {
		t.Fatalf("MarkSealed hash1: %v", err)
	}
	pending := map[string]map[string]struct{}{"trace001": {"hash1": {}}}
	if err := w.Compact(pending); err != nil {
		t.Fatalf("Compact (retain hash1): %v", err)
	}

	seg2Span := makeRecord("trace001", "span-seg2", 5000)
	if err := w.AppendSpan("trace001", seg2Span); err != nil {
		t.Fatalf("AppendSpan (segment 2): %v", err)
	}

	// A second, ordinary Compact — as any unrelated trace sealing elsewhere
	// would trigger — with hash1 still pending.
	if err := w.Compact(pending); err != nil {
		t.Fatalf("second Compact: %v", err)
	}

	buffers, sealedPending, err := w.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(sealedPending) != 1 || sealedPending[0].TipHash != "hash1" {
		t.Errorf("sealedPending = %+v, want exactly segment 1's hash1", sealedPending)
	}
	recs, ok := buffers["trace001"]
	if !ok || len(recs) != 1 || recs[0].SpanID != "span-seg2" {
		t.Errorf("buffers[trace001] = %+v (ok=%v), want segment 2's open span to survive "+
			"an ordinary Compact call", recs, ok)
	}
}

// TestWAL_Compact_StableAcrossRepeatedCyclesWithOpenSecondSegment pins WHY
// Compact writes retained sealed markers before spans rather than after: a
// retained marker for an OLDER segment must stay positioned before a NEWER
// segment's still-open spans for the same trace_id in every rewrite, or a
// later Compact call — which unlatches on the span, then re-latches and
// unconditionally evicts on the next sealed-marker line it sees — mis-scopes
// that eviction onto the wrong segment. This test runs Compact THREE times
// with segment 2 left open throughout, which the write-order fix must
// survive. A fix that only unlatches on span, without also preserving
// marker-before-span order, never establishes even one stable cycle: with
// the old spans-then-markers write order, the very first Compact call here
// already rewrites the file as [span][marker] instead of [marker][span], so
// TestWAL_Compact_DoesNotDropOpenSecondSegmentSpan's single follow-up Compact
// — and this test's first loop iteration — already mis-scope the marker's
// eviction onto segment 2's span.
func TestWAL_Compact_StableAcrossRepeatedCyclesWithOpenSecondSegment(t *testing.T) {
	w, _ := openWAL(t)

	if err := w.MarkSealed("trace001", "hash1", 1); err != nil {
		t.Fatalf("MarkSealed hash1: %v", err)
	}
	seg2Span := makeRecord("trace001", "span-seg2", 5000)
	if err := w.AppendSpan("trace001", seg2Span); err != nil {
		t.Fatalf("AppendSpan (segment 2): %v", err)
	}

	pending := map[string]map[string]struct{}{"trace001": {"hash1": {}}}
	for i := 0; i < 3; i++ {
		if err := w.Compact(pending); err != nil {
			t.Fatalf("Compact cycle %d: %v", i+1, err)
		}
		buffers, sealedPending, err := w.Replay()
		if err != nil {
			t.Fatalf("Replay after cycle %d: %v", i+1, err)
		}
		if len(sealedPending) != 1 || sealedPending[0].TipHash != "hash1" {
			t.Fatalf("cycle %d: sealedPending = %+v, want exactly segment 1's hash1", i+1, sealedPending)
		}
		recs, ok := buffers["trace001"]
		if !ok || len(recs) != 1 || recs[0].SpanID != "span-seg2" {
			t.Fatalf("cycle %d: buffers[trace001] = %+v (ok=%v), want segment 2's open span "+
				"to survive repeated Compact cycles", i+1, recs, ok)
		}
	}
}

// TestWAL_CompactSafe_Concurrent races AppendSpan against Compact to verify
// the internal RWMutex prevents data races (detected by -race).
func TestWAL_CompactSafe_Concurrent(t *testing.T) {
	w, _ := openWAL(t)

	// Seed some initial data.
	for i := 0; i < 5; i++ {
		rec := makeRecord("trace001", "span001", record.UnixNano(i*1000))
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
				_ = w.Compact(nil)
			} else {
				rec := makeRecord("trace002", "span002", record.UnixNano(i*1000))
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

	buffers, _, err := w.Replay()
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

	if err := w.Compact(nil); err != nil {
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

	buffers, _, err := w2.Replay()
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

// TestWAL_ReplayAcceptsLegacyNumericTimestamps covers the decoding half of the
// upgrade path: a WAL left behind by a v2-era binary encodes start/end
// timestamps as JSON numbers, and a v3 binary must replay those entries
// unchanged — same values, still pinned to their own schema_version.
//
// What happens next is the exporter's business, not the WAL's: on replay it
// re-stamps the record to the current schema version before buffering it, so
// the trace seals into a single-version chain. See
// TestStart_ReplayedRecordsAreRestampedToCurrentSchema in the exporter package.
func TestWAL_ReplayAcceptsLegacyNumericTimestamps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.wal")
	const legacyLine = `{"type":"span","trace_id":"trace001","record":` +
		`{"schema_version":"v2","trace_id":"trace001","span_id":"span001","parent_span_id":"",` +
		`"seq_in_trace":0,"start_time_unix_nano":1764547200123456789,` +
		`"end_time_unix_nano":1764547200987654321,"span_name":"test.span","otel_kind":"Client",` +
		`"gen_ai_operation":"","audit_kind":"task","selected_attributes":null,"status":"Ok"}}` + "\n"
	if err := os.WriteFile(path, []byte(legacyLine), 0o644); err != nil {
		t.Fatalf("write legacy wal: %v", err)
	}

	w, err := wal.Open(path)
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	defer func() { _ = w.Close() }()

	buffers, _, err := w.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	recs, ok := buffers["trace001"]
	if !ok || len(recs) != 1 {
		t.Fatalf("expected 1 replayed record for trace001, got %v", buffers)
	}
	if recs[0].SchemaVersion != "v2" {
		t.Errorf("SchemaVersion: got %q, want %q — a replayed record keeps its own version", recs[0].SchemaVersion, "v2")
	}
	if got := uint64(recs[0].StartTimeUnixNano); got != 1764547200123456789 {
		t.Errorf("StartTimeUnixNano: got %d, want 1764547200123456789", got)
	}
	if got := uint64(recs[0].EndTimeUnixNano); got != 1764547200987654321 {
		t.Errorf("EndTimeUnixNano: got %d, want 1764547200987654321", got)
	}
}

// TestWAL_CompactPreservesStoredSchemaVersion pins that compaction re-encodes a
// record in the shape of its OWN schema_version rather than the current one.
// The exporter may re-stamp a replayed record in memory, but the WAL copy must
// keep what was written: replay is then idempotent across repeated crashes, and
// a record the current binary must not re-stamp stays recoverable by one that
// can read it.
func TestWAL_CompactPreservesStoredSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.wal")
	const legacyLine = `{"type":"span","trace_id":"trace001","record":` +
		`{"schema_version":"v2","trace_id":"trace001","span_id":"span001","parent_span_id":"",` +
		`"seq_in_trace":0,"start_time_unix_nano":1764547200123456789,` +
		`"end_time_unix_nano":1764547200987654321,"span_name":"test.span","otel_kind":"Client",` +
		`"gen_ai_operation":"","audit_kind":"task","selected_attributes":null,"status":"Ok"}}` + "\n"
	if err := os.WriteFile(path, []byte(legacyLine), 0o644); err != nil {
		t.Fatalf("write legacy wal: %v", err)
	}

	w, err := wal.Open(path)
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	defer func() { _ = w.Close() }()

	if _, _, err := w.Replay(); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if err := w.Compact(nil); err != nil {
		t.Fatalf("Compact: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read wal after compact: %v", err)
	}
	if !strings.Contains(string(after), `"schema_version":"v2"`) {
		t.Errorf("compaction changed the stored schema_version: %s", after)
	}
	if !strings.Contains(string(after), `"start_time_unix_nano":1764547200123456789`) {
		t.Errorf("compaction re-encoded a v2 timestamp out of its numeric form: %s", after)
	}
}

package verify_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/chain"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/sign"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/verify"
)

// This file pins the behaviour of the multi-epoch verification procedure
// documented in docs/verification.md § "Multi-epoch logs" — issues #19 and #35.
//
// Every assertion here describes what the code does TODAY, including where that
// is wrong. Assertions marked BUG(#19) are the defect: they are expected to
// change when a rotation-aware verification context lands, and whoever fixes it
// should flip them rather than delete them. The tests are green on purpose so
// they can merge into a protected main.
//
// The shape under test, which is what a real rotation produces: Start rehydrates
// sequence and previous-hash state from the last checkpoint and re-adds pending
// tips, so stop / swap key / start leaves a trace that was sealed under the old
// key but first checkpointed under the new one — unless the previous process
// exited through Shutdown, which flushes a final checkpoint. Entries and cp1 are
// produced by the ordinary writer under key A; only cp2 is signed under key B.

const (
	rotTraceCovered  = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a" // sealed and checkpointed under A
	rotTraceBoundary = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" // sealed under A, first checkpointed under B
)

// rotationFixture builds the two-epoch log described above and returns the
// directory plus both public keys. The log holds two traces, both written and
// signed under key A. cp1 (key A) covers only the first; cp2 (key B) covers only
// the boundary trace and chains from cp1.
type rotationFixture struct {
	dir      string
	logPath  string
	cpPath   string
	pubA     []byte
	pubB     []byte
	cp1, cp2 chain.Checkpoint
	entries  map[string][]chain.LogEntry
}

func newRotationFixture(t *testing.T) rotationFixture {
	t.Helper()

	privA, pubA, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key A: %v", err)
	}
	signerA := sign.NewEd25519Signer(privA)

	privB, pubB, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key B: %v", err)
	}
	signerB := sign.NewEd25519Signer(privB)

	// Both traces are written by the ordinary path under key A.
	build := func(traceID, spanID string) ([]chain.ChainEntry, []chain.LogEntry) {
		t.Helper()
		rec := record.AuditRecord{
			SchemaVersion: record.SchemaVersion,
			TraceID:       traceID,
			SpanID:        spanID,
			ParentSpanID:  "0000000000000000",
			SeqInTrace:    0,
			SpanName:      "span",
			OtelKind:      "Internal",
			AuditKind:     record.AuditKindTask,
			Status:        "Ok",
		}
		seed, err := chain.GenesisSeed(traceID)
		if err != nil {
			t.Fatalf("GenesisSeed(%s): %v", traceID, err)
		}
		ce, err := chain.BuildChain([]record.AuditRecord{rec}, seed, signerA)
		if err != nil {
			t.Fatalf("BuildChain(%s): %v", traceID, err)
		}
		return ce, chain.ToLogEntries(ce)
	}

	coveredChain, coveredLog := build(rotTraceCovered, "0102030405060708")
	boundaryChain, boundaryLog := build(rotTraceBoundary, "0807060504030201")

	// cp1: the last checkpoint of epoch A, covering only the first trace.
	accA := chain.NewAccumulator(signerA, 0, chain.ZeroPrevCheckpointHash)
	accA.AddTip(rotTraceCovered, chain.TipHash(coveredChain), len(coveredChain))
	cp1, err := accA.Build(time.Unix(1757000000, 0).UTC())
	if err != nil {
		t.Fatalf("build cp1: %v", err)
	}

	// cp2: the first checkpoint after the rotation. It chains from cp1 and is the
	// only thing that ever attests the boundary trace.
	payload1, err := chain.CheckpointSigningPayload(cp1)
	if err != nil {
		t.Fatalf("CheckpointSigningPayload(cp1): %v", err)
	}
	h1 := sha256.Sum256(payload1)
	accB := chain.NewAccumulator(signerB, 1, hex.EncodeToString(h1[:]))
	accB.AddTip(rotTraceBoundary, chain.TipHash(boundaryChain), len(boundaryChain))
	cp2, err := accB.Build(time.Unix(1757003600, 0).UTC())
	if err != nil {
		t.Fatalf("build cp2: %v", err)
	}

	dir := t.TempDir()
	f := rotationFixture{
		dir:     dir,
		logPath: filepath.Join(dir, "audit.jsonl"),
		cpPath:  filepath.Join(dir, "checkpoint.jsonl"),
		pubA:    []byte(pubA),
		pubB:    []byte(pubB),
		cp1:     cp1,
		cp2:     cp2,
		entries: map[string][]chain.LogEntry{
			rotTraceCovered:  coveredLog,
			rotTraceBoundary: boundaryLog,
		},
	}
	writeLogEntries(t, f.logPath, append(append([]chain.LogEntry{}, coveredLog...), boundaryLog...))
	writeCheckpoints(t, f.cpPath, cp1, cp2)
	return f
}

func writeLogEntries(t *testing.T, path string, entries []chain.LogEntry) {
	t.Helper()
	var b strings.Builder
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal log entry: %v", err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeCheckpoints(t *testing.T, path string, cps ...chain.Checkpoint) {
	t.Helper()
	var b strings.Builder
	for _, cp := range cps {
		line, err := json.Marshal(cp)
		if err != nil {
			t.Fatalf("marshal checkpoint: %v", err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestRotation_WholeLogRefused is the guard working as designed: the log holds
// one entry key_id (A) and two checkpoint key_ids (A and B), so the whole-log run
// bails out rather than reporting. This is the behaviour that sends an operator
// to the per-epoch procedure the rest of this file exercises.
func TestRotation_WholeLogRefused(t *testing.T) {
	f := newRotationFixture(t)

	_, err := verify.VerifyLog(f.logPath, f.cpPath, f.pubA)
	if err == nil {
		t.Fatal("expected the multi-epoch guard to refuse the whole log; got nil")
	}
	if !strings.Contains(err.Error(), "multi-epoch log") {
		t.Errorf("expected 'multi-epoch log', got: %v", err)
	}
	if !strings.Contains(err.Error(), "2 distinct key_ids") {
		t.Errorf("expected 2 distinct key_ids, got: %v", err)
	}
}

// TestRotation_EpochASliceReportsClean runs step 3 of the documented procedure:
// extract the lines for epoch A and verify with key A. The boundary trace is
// present in the log but cp2 — its only attestation — was dropped with the other
// epoch's checkpoints, so it is now a trace no checkpoint covers. VerifyLog
// tolerates those deliberately, which is correct for the last batch before a
// crash and is what makes the next test possible.
func TestRotation_EpochASliceReportsClean(t *testing.T) {
	f := newRotationFixture(t)
	cpPath := filepath.Join(f.dir, "epoch_a.jsonl")
	writeCheckpoints(t, cpPath, f.cp1)

	report, err := verify.VerifyLog(f.logPath, cpPath, f.pubA)
	if err != nil {
		t.Fatalf("epoch A slice: %v", err)
	}
	if report.TracesProcessed != 2 {
		t.Errorf("TracesProcessed = %d, want 2", report.TracesProcessed)
	}
	if report.CheckpointsProcessed != 1 {
		t.Errorf("CheckpointsProcessed = %d, want 1", report.CheckpointsProcessed)
	}
	// BUG(#19): the boundary trace has lost its only coverage and nothing says so.
	// A rotation-aware run must report the uncovered trace here; flip this when it does.
	if len(report.Errors) != 0 {
		t.Errorf("epoch A slice: got %d errors, want 0 (today's behaviour): %+v",
			len(report.Errors), report.Errors)
	}
}

// TestRotation_BoundaryTraceDeletionIsInvisible is the defect. Delete the trace
// that lost its coverage and the documented procedure still reports success: exit
// status clean, zero errors. TracesProcessed drops from 2 to 1, which is not
// detection — an honest log legitimately varies there, so there is nothing for an
// operator to compare against.
func TestRotation_BoundaryTraceDeletionIsInvisible(t *testing.T) {
	f := newRotationFixture(t)

	logPath := filepath.Join(f.dir, "audit_boundary_deleted.jsonl")
	writeLogEntries(t, logPath, f.entries[rotTraceCovered])
	cpPath := filepath.Join(f.dir, "epoch_a.jsonl")
	writeCheckpoints(t, cpPath, f.cp1)

	report, err := verify.VerifyLog(logPath, cpPath, f.pubA)
	// BUG(#19): deleting the boundary trace outright is indistinguishable from an
	// honest log. Every assertion below pins that, and every one should change.
	if err != nil {
		t.Fatalf("epoch A slice with the boundary trace deleted: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Errorf("deletion of the boundary trace produced %d errors, want 0 (today's behaviour): %+v",
			len(report.Errors), report.Errors)
	}
	if report.TracesProcessed != 1 {
		t.Errorf("TracesProcessed = %d, want 1", report.TracesProcessed)
	}

	// The cross-check the issue proposes as a compensating control does see it:
	// cp2 claims a trace the whole log no longer holds. Nothing in VerifyLog does
	// this today, which is the point.
	var claimed int
	for _, tip := range f.cp2.TraceTips {
		if tip.TraceID == rotTraceBoundary {
			claimed = tip.EntryCount
		}
	}
	if claimed == 0 {
		t.Fatal("fixture is wrong: cp2 does not claim the boundary trace")
	}
	held := len(readTraceEntries(t, logPath, rotTraceBoundary))
	if held != 0 {
		t.Fatalf("fixture is wrong: boundary trace still present in the trimmed log (%d entries)", held)
	}
	t.Logf("cross-check against the whole log: cp2 claims entry_count=%d for %s; log holds %d",
		claimed, rotTraceBoundary, held)
}

// TestRotation_EpochBAloneSymptoms pins the other half of the procedure. Epoch B
// cannot be run with the entries — they are signed by A, so the multi-epoch guard
// fires again — and without them it reports two errors that both look like
// tampering on a perfectly clean rotation.
func TestRotation_EpochBAloneSymptoms(t *testing.T) {
	f := newRotationFixture(t)
	cpPath := filepath.Join(f.dir, "epoch_b.jsonl")
	writeCheckpoints(t, cpPath, f.cp2)

	t.Run("with the entries", func(t *testing.T) {
		_, err := verify.VerifyLog(f.logPath, cpPath, f.pubB)
		if err == nil {
			t.Fatal("expected the multi-epoch guard to fire; got nil")
		}
		if !strings.Contains(err.Error(), "multi-epoch log") {
			t.Errorf("expected 'multi-epoch log', got: %v", err)
		}
	})

	t.Run("without the entries", func(t *testing.T) {
		emptyLog := filepath.Join(f.dir, "empty.jsonl")
		if err := os.WriteFile(emptyLog, nil, 0o600); err != nil {
			t.Fatalf("write empty log: %v", err)
		}
		report, err := verify.VerifyLog(emptyLog, cpPath, f.pubB)
		if err != nil {
			t.Fatalf("epoch B alone: %v", err)
		}

		var prevMismatch, countMismatch bool
		for _, e := range report.Errors {
			if strings.Contains(e.Detail, "prev_checkpoint_hash mismatch") {
				prevMismatch = true
			}
			if e.Kind == "entry_count_mismatch" {
				countMismatch = true
			}
		}
		// BUG(#19): VerifyLog seeds prevHash with chain.ZeroPrevCheckpointHash
		// unconditionally and offers no way to supply the previous epoch's tail, so
		// every epoch after the first reports this. It is the same error that detects
		// checkpoint-stream truncation, and the documented procedure teaches operators
		// to read it as expected noise.
		if !prevMismatch {
			t.Errorf("want a prev_checkpoint_hash mismatch against the zero sentinel (today's behaviour); errors: %+v",
				report.Errors)
		}
		// BUG(#19): cp2 claims the boundary trace, the slice has no entries for it.
		if !countMismatch {
			t.Errorf("want entry_count_mismatch (today's behaviour); errors: %+v", report.Errors)
		}
	})
}

func readTraceEntries(t *testing.T, path, traceID string) []chain.LogEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []chain.LogEntry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e chain.LogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("unmarshal log line: %v", err)
		}
		if e.Record.TraceID == traceID {
			out = append(out, e)
		}
	}
	return out
}

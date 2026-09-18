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

// This file pins the behaviour of key-rotation verification at the epoch
// boundary — issues #19, #35, and #46.
//
// Before #46, VerifyLog pre-scanned the raw, unauthenticated key_id field and
// refused to produce a Report at all once it saw more than one distinct
// value — sending an operator to a documented split-per-epoch procedure that
// itself had two defects (#35): it dropped the one checkpoint that could
// catch a deleted rotation-boundary trace, and it manufactured a
// prev_checkpoint_hash mismatch on every epoch after the first.
//
// #46 removed that pre-scan: VerifyLog now always verifies every entry and
// checkpoint directly against the supplied key, so a genuinely multi-key log
// no longer bails out — the traces/checkpoints signed by a different key
// simply produce ordinary "chain" / "checkpoint" signature-failure errors
// (TestRotation_WholeLogAgainstOneKey, TestRotation_EpochBAloneSymptoms).
// Running the verifier this way — once per candidate key, against the FULL,
// UNSPLIT log and checkpoint files, never pre-filtered by key_id — turns out
// to already close the boundary-trace-deletion gap described above: the
// checkpoint that covers the boundary trace is still present and still
// cross-checked even when its own signature does not verify against the key
// in hand (TestRotation_UnsplitRunCatchesBoundaryTraceDeletion).
//
// Splitting per epoch remains unsafe for the reasons #35 found. The two
// tests below that build a manually pre-split checkpoint file
// (TestRotation_EpochASliceReportsClean,
// TestRotation_BoundaryTraceDeletionIsInvisible) still pin that defect
// unchanged — which is exactly why splitting is no longer the recommended
// approach; see docs/verification.md § "Multi-epoch logs". Assertions marked
// BUG(#19) remain the open defect: full rotation-aware verification — a
// first-class multi-key API with clean, non-noisy attestation across the
// boundary — is still #19's design question, not solved here. Whoever
// implements it should flip those assertions rather than delete them.
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

// TestRotation_WholeLogAgainstOneKey replaces the old guard-based test
// (issue #46): running the FULL, unsplit log and checkpoint file against just
// pubA no longer bails out. Both traces verify — they are genuinely signed by
// A — and so does cp1. cp2 does not: it is genuinely signed by B, so it
// produces an ordinary checkpoint signature-failure error. Critically, cp2's
// own trace_tips cross-check still runs despite its signature failing, which
// is what TestRotation_UnsplitRunCatchesBoundaryTraceDeletion below depends on.
func TestRotation_WholeLogAgainstOneKey(t *testing.T) {
	f := newRotationFixture(t)

	report, err := verify.VerifyLog(f.logPath, f.cpPath, f.pubA)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if report.TracesProcessed != 2 {
		t.Errorf("TracesProcessed = %d, want 2", report.TracesProcessed)
	}
	if report.CheckpointsProcessed != 2 {
		t.Errorf("CheckpointsProcessed = %d, want 2", report.CheckpointsProcessed)
	}
	if len(report.Errors) != 1 {
		t.Fatalf("expected exactly 1 error (cp2, signed by B); got %+v", report.Errors)
	}
	e := report.Errors[0]
	if e.TraceID != "" || e.Kind != "checkpoint" {
		t.Errorf("expected a checkpoint error for cp2; got %+v", e)
	}
	if !strings.Contains(e.Detail, "signature verification failed") {
		t.Errorf("expected a signature-verification-failed detail, got: %s", e.Detail)
	}
}

// TestRotation_UnsplitRunCatchesBoundaryTraceDeletion is the fix's payoff:
// deleting the boundary trace is no longer invisible once an operator skips
// the (now-unsafe) per-epoch split and just runs the verifier, unsplit,
// against a key they hold. cp2's signature does not verify against pubA — it
// is really signed by B — but its trace_tips are cross-checked against the
// whole log regardless, and that whole log no longer has the trace cp2
// claims. Contrast with TestRotation_BoundaryTraceDeletionIsInvisible below,
// which pins the same deletion going undetected under the old split
// procedure.
func TestRotation_UnsplitRunCatchesBoundaryTraceDeletion(t *testing.T) {
	f := newRotationFixture(t)

	logPath := filepath.Join(f.dir, "audit_boundary_deleted.jsonl")
	writeLogEntries(t, logPath, f.entries[rotTraceCovered])

	report, err := verify.VerifyLog(logPath, f.cpPath, f.pubA)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	// Exactly 2: cp2's own signature still fails against pubA (it is really
	// signed by B — same as TestRotation_WholeLogAgainstOneKey), plus the
	// entry_count_mismatch this test is about. Asserting the exact count, not
	// just presence, so a future regression adding a spurious extra finding
	// doesn't slip through unnoticed.
	if len(report.Errors) != 2 {
		t.Fatalf("expected exactly 2 errors (cp2 signature failure + entry_count_mismatch); got %+v", report.Errors)
	}
	var sawCountMismatch, sawCheckpointFailure bool
	for _, e := range report.Errors {
		switch {
		case e.TraceID == rotTraceBoundary && e.Kind == "entry_count_mismatch":
			sawCountMismatch = true
			if !strings.Contains(e.Detail, "log has 0") {
				t.Errorf("expected the mismatch detail to show the log now holds 0 entries, got: %s", e.Detail)
			}
		case e.TraceID == "" && e.Kind == "checkpoint":
			sawCheckpointFailure = true
		default:
			t.Errorf("unexpected error: %+v", e)
		}
	}
	if !sawCountMismatch {
		t.Errorf("expected entry_count_mismatch for the deleted boundary trace; got %v", report.Errors)
	}
	if !sawCheckpointFailure {
		t.Errorf("expected cp2's own checkpoint signature failure alongside it; got %v", report.Errors)
	}
}

// TestRotation_EpochASliceReportsClean runs the now-discouraged split-per-epoch
// procedure: extract the lines for epoch A and verify with key A alone. The
// boundary trace is present in the log but cp2 — its only attestation — was
// dropped along with the rest of epoch B's checkpoints, so it is now a trace
// no checkpoint in THIS run covers. VerifyLog tolerates that deliberately,
// which is correct for the last batch before a crash, and is what makes the
// next test possible. Compare TestRotation_UnsplitRunCatchesBoundaryTraceDeletion
// above, which keeps cp2 in view by not splitting and so does not have this
// blind spot.
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
	// BUG(#19, #35): the boundary trace has lost its only coverage and nothing says so.
	// A rotation-aware run must report the uncovered trace here; flip this when it does.
	if len(report.Errors) != 0 {
		t.Errorf("epoch A slice: got %d errors, want 0 (today's behaviour): %+v",
			len(report.Errors), report.Errors)
	}
}

// TestRotation_BoundaryTraceDeletionIsInvisible is the defect that motivates
// no longer recommending the split-per-epoch procedure. Delete the trace that
// lost its coverage in the epoch-A-only slice and verification still reports
// success: exit status clean, zero errors. TracesProcessed drops from 2 to 1,
// which is not detection — an honest log legitimately varies there, so there
// is nothing for an operator to compare against. See
// TestRotation_UnsplitRunCatchesBoundaryTraceDeletion above for the same
// deletion caught by not splitting.
func TestRotation_BoundaryTraceDeletionIsInvisible(t *testing.T) {
	f := newRotationFixture(t)

	logPath := filepath.Join(f.dir, "audit_boundary_deleted.jsonl")
	writeLogEntries(t, logPath, f.entries[rotTraceCovered])
	cpPath := filepath.Join(f.dir, "epoch_a.jsonl")
	writeCheckpoints(t, cpPath, f.cp1)

	report, err := verify.VerifyLog(logPath, cpPath, f.pubA)
	// BUG(#19, #35): deleting the boundary trace outright is indistinguishable
	// from an honest log. Every assertion below pins that, and every one should
	// change.
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

// TestRotation_EpochBAloneSymptoms pins the other half of the split-per-epoch
// procedure. With the full log's entries present, neither trace verifies
// against pubB — both are genuinely signed by A — so this now reports
// ordinary chain errors rather than bailing out. Without the entries, it
// reports two errors that both look like tampering on a perfectly clean
// rotation (BUG(#19, #35), unchanged by issue #46).
func TestRotation_EpochBAloneSymptoms(t *testing.T) {
	f := newRotationFixture(t)
	cpPath := filepath.Join(f.dir, "epoch_b.jsonl")
	writeCheckpoints(t, cpPath, f.cp2)

	t.Run("with the entries", func(t *testing.T) {
		report, err := verify.VerifyLog(f.logPath, cpPath, f.pubB)
		if err != nil {
			t.Fatalf("VerifyLog: %v", err)
		}
		// Exactly 4: a "chain" error per trace (both signed by A, checked
		// against pubB), cp2's own prev_checkpoint_hash mismatch, and
		// tip_hash_unverifiable for the one trace cp2 covers. Asserting the
		// exact count, not just presence, so a future regression adding a
		// spurious extra finding doesn't slip through unnoticed.
		if len(report.Errors) != 4 {
			t.Fatalf("expected exactly 4 errors; got %+v", report.Errors)
		}
		chainErrs := 0
		var sawPrevMismatch, sawTipUnverifiable bool
		for _, e := range report.Errors {
			switch e.Kind {
			case "chain":
				chainErrs++
			case "checkpoint":
				if strings.Contains(e.Detail, "prev_checkpoint_hash mismatch") {
					sawPrevMismatch = true
				}
			case "tip_hash_unverifiable":
				if e.TraceID == rotTraceBoundary {
					sawTipUnverifiable = true
				}
			default:
				t.Errorf("unexpected error kind %q: %+v", e.Kind, e)
			}
		}
		// Both traces are genuinely signed by A, so neither verifies against pubB.
		if chainErrs != 2 {
			t.Errorf("expected 2 chain errors (both traces signed by A, checked against pubB); got %d in %+v",
				chainErrs, report.Errors)
		}
		// cp2 alone has no epoch-A tail to chain from — same BUG(#19, #35) as
		// the "without the entries" case below.
		if !sawPrevMismatch {
			t.Errorf("expected a prev_checkpoint_hash mismatch; got %+v", report.Errors)
		}
		// rotTraceBoundary's chain failed (checked against the wrong key), so
		// cp2's claimed tip_hash for it cannot be confirmed either way.
		if !sawTipUnverifiable {
			t.Errorf("expected tip_hash_unverifiable for %s; got %+v", rotTraceBoundary, report.Errors)
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
		// BUG(#19, #35): VerifyLog seeds prevHash with chain.ZeroPrevCheckpointHash
		// unconditionally and offers no way to supply the previous epoch's tail, so
		// every epoch after the first reports this. It is the same error that detects
		// checkpoint-stream truncation, and the documented procedure teaches operators
		// to read it as expected noise.
		if !prevMismatch {
			t.Errorf("want a prev_checkpoint_hash mismatch against the zero sentinel (today's behaviour); errors: %+v",
				report.Errors)
		}
		// BUG(#19, #35): cp2 claims the boundary trace, the slice has no entries for it.
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

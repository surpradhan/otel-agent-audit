package chain_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/chain"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/sign"
)

// checkpointForSigning mirrors the signing struct in checkpoint.go for test reconstruction.
type checkpointForSigning struct {
	SchemaVersion      string           `json:"schema_version"`
	CheckpointSeq      uint64           `json:"checkpoint_seq"`
	Timestamp          string           `json:"timestamp"`
	PrevCheckpointHash string           `json:"prev_checkpoint_hash"`
	TraceTips          []chain.TraceTip `json:"trace_tips"`
	KeyID              string           `json:"key_id"`
	Algorithm          string           `json:"algorithm"`
}

func makeTestSignerFull(t *testing.T) (sign.Signer, ed25519.PublicKey) {
	t.Helper()
	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	return sign.NewEd25519Signer(priv), pub
}

// TestAccumulator_BuildEmpty verifies seq starts at 1 and prevHash is ZeroPrevCheckpointHash.
func TestAccumulator_BuildEmpty(t *testing.T) {
	signer, _ := makeTestSignerFull(t)
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)

	ts := time.Date(2026, 6, 22, 14, 30, 0, 0, time.UTC)
	cp, err := acc.Build(ts)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if cp.CheckpointSeq != 1 {
		t.Errorf("CheckpointSeq: got %d, want 1", cp.CheckpointSeq)
	}
	if cp.PrevCheckpointHash != chain.ZeroPrevCheckpointHash {
		t.Errorf("PrevCheckpointHash: got %q, want ZeroPrevCheckpointHash", cp.PrevCheckpointHash)
	}
	if cp.SchemaVersion != record.SchemaVersion {
		t.Errorf("SchemaVersion: got %q, want %q", cp.SchemaVersion, record.SchemaVersion)
	}
	if cp.Algorithm != "ed25519" {
		t.Errorf("Algorithm: got %q, want %q", cp.Algorithm, "ed25519")
	}
	if cp.Timestamp != "2026-06-22T14:30:00Z" {
		t.Errorf("Timestamp: got %q, want %q", cp.Timestamp, "2026-06-22T14:30:00Z")
	}
}

// TestAccumulator_SortsTraceTips verifies that tips are sorted by trace_id in the
// signed payload regardless of AddTip insertion order.
func TestAccumulator_SortsTraceTips(t *testing.T) {
	signer, _ := makeTestSignerFull(t)
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)

	// Add tips in reverse alphabetical order.
	acc.AddTip("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "hash3", 1)
	acc.AddTip("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "hash1", 1)
	acc.AddTip("mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm", "hash2", 1)

	cp, err := acc.Build(time.Now())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if len(cp.TraceTips) != 3 {
		t.Fatalf("expected 3 tips, got %d", len(cp.TraceTips))
	}
	// Must be sorted by trace_id ascending.
	for i := 1; i < len(cp.TraceTips); i++ {
		if cp.TraceTips[i].TraceID < cp.TraceTips[i-1].TraceID {
			t.Errorf("tips not sorted: tips[%d].TraceID=%q < tips[%d].TraceID=%q",
				i, cp.TraceTips[i].TraceID, i-1, cp.TraceTips[i-1].TraceID)
		}
	}
}

// TestAccumulator_AdvancesPrevHash verifies that consecutive Build calls advance
// prevHash correctly: second checkpoint's PrevCheckpointHash == SHA256(first signing payload).
func TestAccumulator_AdvancesPrevHash(t *testing.T) {
	signer, _ := makeTestSignerFull(t)
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)

	ts := time.Date(2026, 6, 22, 14, 30, 0, 0, time.UTC)
	cp1, err := acc.Build(ts)
	if err != nil {
		t.Fatalf("Build 1: %v", err)
	}

	// Reconstruct signing payload for cp1.
	cfs1 := checkpointForSigning{
		SchemaVersion:      cp1.SchemaVersion,
		CheckpointSeq:      cp1.CheckpointSeq,
		Timestamp:          cp1.Timestamp,
		PrevCheckpointHash: cp1.PrevCheckpointHash,
		TraceTips:          cp1.TraceTips,
		KeyID:              cp1.KeyID,
		Algorithm:          cp1.Algorithm,
	}
	payload1, err := json.Marshal(cfs1)
	if err != nil {
		t.Fatalf("marshal signing payload: %v", err)
	}
	h1 := sha256.Sum256(payload1)
	expectedPrevHash2 := hex.EncodeToString(h1[:])

	acc.AddTip("aabbccdd", "somehash", 2)
	cp2, err := acc.Build(ts.Add(time.Minute))
	if err != nil {
		t.Fatalf("Build 2: %v", err)
	}

	if cp2.PrevCheckpointHash != expectedPrevHash2 {
		t.Errorf("cp2.PrevCheckpointHash:\n  got  %s\n  want %s",
			cp2.PrevCheckpointHash, expectedPrevHash2)
	}
	if cp2.CheckpointSeq != 2 {
		t.Errorf("cp2.CheckpointSeq: got %d, want 2", cp2.CheckpointSeq)
	}
}

// TestCheckpoint_SignsAndVerifies is an integration test: AddTip → Build → verify signature.
func TestCheckpoint_SignsAndVerifies(t *testing.T) {
	signer, pubKey := makeTestSignerFull(t)
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)

	acc.AddTip("trace001", "tiphash001", 3)
	acc.AddTip("trace002", "tiphash002", 1)

	ts := time.Date(2026, 6, 22, 14, 30, 0, 0, time.UTC)
	cp, err := acc.Build(ts)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Reconstruct signing payload.
	cfs := checkpointForSigning{
		SchemaVersion:      cp.SchemaVersion,
		CheckpointSeq:      cp.CheckpointSeq,
		Timestamp:          cp.Timestamp,
		PrevCheckpointHash: cp.PrevCheckpointHash,
		TraceTips:          cp.TraceTips,
		KeyID:              cp.KeyID,
		Algorithm:          cp.Algorithm,
	}
	payload, err := json.Marshal(cfs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	sig, err := base64.StdEncoding.DecodeString(cp.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(pubKey, payload, sig) {
		t.Error("checkpoint signature verification failed")
	}
}

// TestAccumulator_ResetsPendingAfterBuild verifies that a second Build produces
// an empty TraceTips list when no new tips were added.
func TestAccumulator_ResetsPendingAfterBuild(t *testing.T) {
	signer, _ := makeTestSignerFull(t)
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)

	acc.AddTip("trace001", "hash001", 1)
	_, err := acc.Build(time.Now())
	if err != nil {
		t.Fatalf("Build 1: %v", err)
	}

	cp2, err := acc.Build(time.Now())
	if err != nil {
		t.Fatalf("Build 2: %v", err)
	}
	if len(cp2.TraceTips) != 0 {
		t.Errorf("expected 0 tips after reset, got %d", len(cp2.TraceTips))
	}
}

// TestAccumulator_PendingCount verifies PendingCount returns correct value.
func TestAccumulator_PendingCount(t *testing.T) {
	signer, _ := makeTestSignerFull(t)
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)

	if got := acc.PendingCount(); got != 0 {
		t.Errorf("initial PendingCount: got %d, want 0", got)
	}
	acc.AddTip("t1", "h1", 1)
	acc.AddTip("t2", "h2", 2)
	if got := acc.PendingCount(); got != 2 {
		t.Errorf("PendingCount after 2 adds: got %d, want 2", got)
	}
	_, _ = acc.Build(time.Now())
	if got := acc.PendingCount(); got != 0 {
		t.Errorf("PendingCount after Build: got %d, want 0", got)
	}
}

// TestAccumulator_PendingTips verifies PendingTips reflects exactly the
// (trace_id, tip_hash) pairs currently awaiting a checkpoint, and that both a
// successful Commit and a deliberate abandonment (TrimPending) remove a tip
// from it — the WAL relies on this to know which sealed markers it may safely
// drop.
func TestAccumulator_PendingTips(t *testing.T) {
	signer, _ := makeTestSignerFull(t)
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)

	if got := acc.PendingTips(); len(got) != 0 {
		t.Errorf("initial PendingTips: got %v, want empty", got)
	}

	acc.AddTip("t1", "h1", 1)
	acc.AddTip("t2", "h2", 1)
	got := acc.PendingTips()
	want := map[string]map[string]struct{}{"t1": {"h1": {}}, "t2": {"h2": {}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PendingTips after 2 adds: got %v, want %v", got, want)
	}

	// A committed checkpoint removes its covered tip from the set.
	st, err := acc.Stage(time.Now())
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	acc.AddTip("t3", "h3", 1) // added after Stage; must survive Commit
	if err := acc.Commit(st); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	got = acc.PendingTips()
	want = map[string]map[string]struct{}{"t3": {"h3": {}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PendingTips after Commit: got %v, want %v", got, want)
	}

	// A deliberate abandonment (TrimPending) also removes a tip: it drops the
	// OLDEST pending tips, so adding t4 and trimming to 1 drops t3, keeps t4.
	acc.AddTip("t4", "h4", 1)
	if dropped := acc.TrimPending(1); dropped != 1 {
		t.Fatalf("TrimPending(1): dropped %d, want 1", dropped)
	}
	got = acc.PendingTips()
	want = map[string]map[string]struct{}{"t4": {"h4": {}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PendingTips after TrimPending: got %v, want %v", got, want)
	}

	// DropPending abandons everything still pending.
	acc.DropPending()
	if got := acc.PendingTips(); len(got) != 0 {
		t.Errorf("PendingTips after DropPending: got %v, want empty", got)
	}
}

// TestAccumulator_PendingTips_TracksSameTraceIndependently pins the fix for
// duplicate_trace_segment: a re-delivered root span for an already-sealed
// trace_id starts an independent second chain, so the same trace_id can have
// two tips pending at once. PendingTips must track them as separate entries —
// collapsing by trace_id alone would make settling one tip look like it
// settled the other too, since both would share the same key.
func TestAccumulator_PendingTips_TracksSameTraceIndependently(t *testing.T) {
	signer, _ := makeTestSignerFull(t)
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)

	acc.AddTip("dup", "h1", 1)
	acc.AddTip("dup", "h2", 1)
	got := acc.PendingTips()
	want := map[string]map[string]struct{}{"dup": {"h1": {}, "h2": {}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PendingTips after 2 adds to the same trace_id: got %v, want %v", got, want)
	}

	// Settle only h1 (the older of the two) via TrimPending's oldest-first drop
	// policy; add a third, unrelated tip so trimming to 2 has exactly one tip
	// to drop.
	acc.AddTip("other", "h3", 1)
	if dropped := acc.TrimPending(2); dropped != 1 {
		t.Fatalf("TrimPending(2): dropped %d, want 1", dropped)
	}
	got = acc.PendingTips()
	want = map[string]map[string]struct{}{"dup": {"h2": {}}, "other": {"h3": {}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PendingTips after settling h1: got %v, want %v — h1 must be gone but h2, "+
			"the same trace_id's other tip, must remain", got, want)
	}
}

// TestAccumulator_TrimPending verifies TrimPending drops the oldest tips once
// pending exceeds max, keeping exactly the newest max tips.
func TestAccumulator_TrimPending(t *testing.T) {
	signer, _ := makeTestSignerFull(t)
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)

	for i := 0; i < 10; i++ {
		acc.AddTip(fmt.Sprintf("t%d", i), fmt.Sprintf("h%d", i), 1)
	}
	if got := acc.PendingCount(); got != 10 {
		t.Fatalf("PendingCount before trim: got %d, want 10", got)
	}

	if dropped := acc.TrimPending(3); dropped != 7 {
		t.Errorf("TrimPending(3) dropped: got %d, want 7", dropped)
	}
	if got := acc.PendingCount(); got != 3 {
		t.Fatalf("PendingCount after trim: got %d, want 3", got)
	}

	st, err := acc.Stage(time.Now())
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	var gotIDs []string
	for _, tip := range st.Checkpoint.TraceTips {
		gotIDs = append(gotIDs, tip.TraceID)
	}
	wantIDs := []string{"t7", "t8", "t9"}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Errorf("surviving tips: got %v, want %v (oldest must be dropped, newest kept)", gotIDs, wantIDs)
	}
}

// TestAccumulator_TrimPending_NoopUnderOrAtCap verifies TrimPending does
// nothing while pending is at or below max.
func TestAccumulator_TrimPending_NoopUnderOrAtCap(t *testing.T) {
	signer, _ := makeTestSignerFull(t)
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)

	acc.AddTip("t0", "h0", 1)
	acc.AddTip("t1", "h1", 1)

	if dropped := acc.TrimPending(2); dropped != 0 {
		t.Errorf("TrimPending at exactly cap: got %d dropped, want 0", dropped)
	}
	if dropped := acc.TrimPending(5); dropped != 0 {
		t.Errorf("TrimPending under cap: got %d dropped, want 0", dropped)
	}
	if got := acc.PendingCount(); got != 2 {
		t.Errorf("PendingCount unchanged: got %d, want 2", got)
	}
}

// TestAccumulator_TrimPending_DisabledForNonPositiveMax verifies max<=0
// disables the cap, matching effectiveMaxPendingTips' "unset" sentinel.
func TestAccumulator_TrimPending_DisabledForNonPositiveMax(t *testing.T) {
	signer, _ := makeTestSignerFull(t)
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)
	acc.AddTip("t0", "h0", 1)

	if dropped := acc.TrimPending(0); dropped != 0 {
		t.Errorf("TrimPending(0): got %d dropped, want 0 (0 disables the cap)", dropped)
	}
	if dropped := acc.TrimPending(-1); dropped != 0 {
		t.Errorf("TrimPending(-1): got %d dropped, want 0", dropped)
	}
}

// TestCheckpointSigningPayloadFixture_V1Regression is the frozen v1 cross-impl
// lock for the checkpoint signing payload. The v1 bytes must never change — they
// are load-bearing for any verifier that re-derives prev_checkpoint_hash from a
// v1-era checkpoint file.
func TestCheckpointSigningPayloadFixture_V1Regression(t *testing.T) {
	cfs := checkpointForSigning{
		SchemaVersion:      "v1",
		CheckpointSeq:      1,
		Timestamp:          "2026-06-22T00:00:00Z",
		PrevCheckpointHash: chain.ZeroPrevCheckpointHash,
		TraceTips: []chain.TraceTip{{
			TraceID:    "01010101010101010101010101010101",
			TipHash:    "a0415a08bbac8ad89462cae146a727dbcfb3022b3f1e5870886fb2deb1538f9c",
			EntryCount: 2,
		}},
		KeyID:     "PLACEHOLDER",
		Algorithm: "ed25519",
	}

	got, err := json.Marshal(cfs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	const fixturePath = "testdata/v1_checkpoint_fixture.json"
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}

	gotStr := strings.TrimRight(string(got), "\n\r ")
	wantStr := strings.TrimRight(string(want), "\n\r ")
	if gotStr != wantStr {
		t.Errorf("v1 checkpoint payload diverges from frozen fixture.\ngot:  %s\nwant: %s", got, want)
	}
}

// TestCheckpointSigningPayloadFixture_V2Regression is the frozen v2 cross-impl
// lock for the checkpoint signing payload, alongside the v1 one above.
func TestCheckpointSigningPayloadFixture_V2Regression(t *testing.T) {
	cfs := checkpointForSigning{
		SchemaVersion:      "v2",
		CheckpointSeq:      1,
		Timestamp:          "2026-06-22T00:00:00Z",
		PrevCheckpointHash: chain.ZeroPrevCheckpointHash,
		TraceTips: []chain.TraceTip{{
			TraceID:    "01010101010101010101010101010101",
			TipHash:    "3e5adf011183ce2128aeca9d337ddf60ea867dbd96f47c16c77e876b36fbc63c",
			EntryCount: 2,
		}},
		KeyID:     "PLACEHOLDER",
		Algorithm: "ed25519",
	}

	got, err := json.Marshal(cfs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	const fixturePath = "testdata/v2_checkpoint_fixture.json"
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}

	gotStr := strings.TrimRight(string(got), "\n\r ")
	wantStr := strings.TrimRight(string(want), "\n\r ")
	if gotStr != wantStr {
		t.Errorf("v2 checkpoint payload diverges from frozen fixture.\ngot:  %s\nwant: %s", got, want)
	}
}

// TestCheckpointSigningPayloadFixture_V3 is the v3 cross-impl lock: the compact
// JSON of checkpointForSigning for the v3 fixture inputs must match
// testdata/v3_checkpoint_fixture.json byte-for-byte. The checkpoint payload
// carries no nanosecond timestamps of its own — its timestamp is RFC3339 and
// its counters are small — so v3 changes only the schema_version string and the
// tip hash it commits to.
func TestCheckpointSigningPayloadFixture_V3(t *testing.T) {
	cfs := checkpointForSigning{
		SchemaVersion:      "v3",
		CheckpointSeq:      1,
		Timestamp:          "2026-06-22T00:00:00Z",
		PrevCheckpointHash: chain.ZeroPrevCheckpointHash,
		TraceTips: []chain.TraceTip{{
			TraceID:    "01010101010101010101010101010101",
			TipHash:    "fe7cb7a264d7e80e370d6333dc797361a34d8b86f0af009cbc24380ed047d3bb",
			EntryCount: 2,
		}},
		KeyID:     "PLACEHOLDER",
		Algorithm: "ed25519",
	}

	got, err := json.Marshal(cfs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	const fixturePath = "testdata/v3_checkpoint_fixture.json"
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}

	gotStr := strings.TrimRight(string(got), "\n\r ")
	wantStr := strings.TrimRight(string(want), "\n\r ")
	if gotStr != wantStr {
		t.Errorf("v3 checkpoint payload diverges from golden fixture.\ngot:  %s\nwant: %s", got, want)
	}
}

// TestAccumulator_StageDoesNotMutateUntilCommit verifies that Stage leaves seq,
// prevHash and the pending set untouched, so a caller whose durable write fails
// can drop the staged checkpoint and have the next Stage produce the same
// sequence number, the same prev-hash and the same tips.
func TestAccumulator_StageDoesNotMutateUntilCommit(t *testing.T) {
	signer, _ := makeTestSignerFull(t)
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)
	acc.AddTip("trace001", "hash001", 1)

	ts := time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)
	staged, err := acc.Stage(ts)
	if err != nil {
		t.Fatalf("Stage 1: %v", err)
	}
	if got := acc.PendingCount(); got != 1 {
		t.Errorf("PendingCount after Stage: got %d, want 1", got)
	}

	// Drop the staged checkpoint (simulating a failed write) and re-stage.
	restaged, err := acc.Stage(ts)
	if err != nil {
		t.Fatalf("Stage 2: %v", err)
	}
	if restaged.Checkpoint.CheckpointSeq != staged.Checkpoint.CheckpointSeq {
		t.Errorf("re-staged seq: got %d, want %d",
			restaged.Checkpoint.CheckpointSeq, staged.Checkpoint.CheckpointSeq)
	}
	if restaged.Checkpoint.PrevCheckpointHash != chain.ZeroPrevCheckpointHash {
		t.Errorf("re-staged prev_checkpoint_hash: got %s, want %s",
			restaged.Checkpoint.PrevCheckpointHash, chain.ZeroPrevCheckpointHash)
	}
	if len(restaged.Checkpoint.TraceTips) != 1 {
		t.Errorf("re-staged tips: got %d, want 1", len(restaged.Checkpoint.TraceTips))
	}

	if err := acc.Commit(restaged); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got := acc.PendingCount(); got != 0 {
		t.Errorf("PendingCount after Commit: got %d, want 0", got)
	}

	next, err := acc.Stage(ts)
	if err != nil {
		t.Fatalf("Stage 3: %v", err)
	}
	if next.Checkpoint.CheckpointSeq != 2 {
		t.Errorf("seq after Commit: got %d, want 2", next.Checkpoint.CheckpointSeq)
	}
	if next.Checkpoint.PrevCheckpointHash == chain.ZeroPrevCheckpointHash {
		t.Error("prev_checkpoint_hash did not advance after Commit")
	}
}

// TestAccumulator_CommitKeepsTipsAddedAfterStage verifies Commit only drops the
// tips its checkpoint actually covers: a tip added between Stage and Commit
// stays pending for the next checkpoint rather than being silently discarded.
func TestAccumulator_CommitKeepsTipsAddedAfterStage(t *testing.T) {
	signer, _ := makeTestSignerFull(t)
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)
	acc.AddTip("trace001", "hash001", 1)

	staged, err := acc.Stage(time.Now())
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	acc.AddTip("trace002", "hash002", 3)
	if err := acc.Commit(staged); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if got := acc.PendingCount(); got != 1 {
		t.Fatalf("PendingCount after Commit: got %d, want 1", got)
	}
	next, err := acc.Stage(time.Now())
	if err != nil {
		t.Fatalf("Stage 2: %v", err)
	}
	if len(next.Checkpoint.TraceTips) != 1 || next.Checkpoint.TraceTips[0].TraceID != "trace002" {
		t.Errorf("next checkpoint tips: got %+v, want only trace002", next.Checkpoint.TraceTips)
	}
}

// flakySigner fails the first `failures` Sign calls, then recovers. Recovery is
// the point: it lets the SAME accumulator be observed across a failure and a
// later success, which is what proves the failure burned nothing.
type flakySigner struct {
	inner    sign.Signer
	failures int
}

func (s *flakySigner) Sign(p []byte) ([]byte, error) {
	if s.failures > 0 {
		s.failures--
		return nil, errors.New("simulated HSM failure")
	}
	return s.inner.Sign(p)
}

func (s *flakySigner) KeyID() string { return s.inner.KeyID() }

// TestAccumulator_SigningFailureDoesNotAdvanceSeq pins the guarantee that a
// failed Stage/Build leaves the accumulator untouched: the sequence number is
// not burned, so the next SUCCESSFUL checkpoint on that same accumulator is
// still seq 1 chained off the zero prev-hash, and the tips are still pending.
// The pre-Stage implementation incremented seq before signing and lost this.
func TestAccumulator_SigningFailureDoesNotAdvanceSeq(t *testing.T) {
	inner, _ := makeTestSignerFull(t)
	signer := &flakySigner{inner: inner, failures: 2}
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)
	acc.AddTip("trace001", "hash001", 1)

	if _, err := acc.Stage(time.Now()); err == nil {
		t.Fatal("expected Stage to fail while the signer is failing")
	}
	if _, err := acc.Build(time.Now()); err == nil {
		t.Fatal("expected Build to fail while the signer is failing")
	}
	// Tips must survive a signing failure too.
	if got := acc.PendingCount(); got != 1 {
		t.Errorf("PendingCount after signing failures: got %d, want 1", got)
	}

	// The signer has recovered. The same accumulator must still produce seq 1
	// off the zero prev-hash — the two failures burned nothing.
	cp, err := acc.Build(time.Now())
	if err != nil {
		t.Fatalf("Build after signer recovery: %v", err)
	}
	if cp.CheckpointSeq != 1 {
		t.Errorf("seq after 2 signing failures: got %d, want 1", cp.CheckpointSeq)
	}
	if cp.PrevCheckpointHash != chain.ZeroPrevCheckpointHash {
		t.Errorf("prev_checkpoint_hash after signing failures: got %s, want %s",
			cp.PrevCheckpointHash, chain.ZeroPrevCheckpointHash)
	}
	if len(cp.TraceTips) != 1 {
		t.Errorf("tips in recovered checkpoint: got %d, want 1", len(cp.TraceTips))
	}
}

// TestAccumulator_CommitRejectsMisPairedStage verifies Commit refuses a staged
// checkpoint that does not directly succeed the current state, rather than
// silently rewinding seq or dropping tips no checkpoint covers. The chain state
// is load-bearing, so mis-pairing must be loud.
func TestAccumulator_CommitRejectsMisPairedStage(t *testing.T) {
	signer, _ := makeTestSignerFull(t)
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)
	acc.AddTip("trace001", "hash001", 1)

	// Zero value: must not rewind seq to 0 or blank the prev-hash.
	if err := acc.Commit(chain.StagedCheckpoint{}); err == nil {
		t.Error("expected Commit of a zero-value StagedCheckpoint to fail")
	}
	if got := acc.PendingCount(); got != 1 {
		t.Errorf("PendingCount after rejected zero-value Commit: got %d, want 1", got)
	}

	staged, err := acc.Stage(time.Now())
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := acc.Commit(staged); err != nil {
		t.Fatalf("first Commit: %v", err)
	}

	// Double-commit of the same staged checkpoint must be refused.
	acc.AddTip("trace002", "hash002", 2)
	if err := acc.Commit(staged); err == nil {
		t.Error("expected a duplicate Commit to fail")
	}
	if got := acc.PendingCount(); got != 1 {
		t.Errorf("PendingCount after rejected duplicate Commit: got %d, want 1", got)
	}

	// State must still be intact: next checkpoint is seq 2 covering trace002.
	next, err := acc.Stage(time.Now())
	if err != nil {
		t.Fatalf("Stage after rejected commits: %v", err)
	}
	if next.Checkpoint.CheckpointSeq != 2 {
		t.Errorf("next seq: got %d, want 2", next.Checkpoint.CheckpointSeq)
	}
	if len(next.Checkpoint.TraceTips) != 1 || next.Checkpoint.TraceTips[0].TraceID != "trace002" {
		t.Errorf("next tips: got %+v, want only trace002", next.Checkpoint.TraceTips)
	}
}

package chain_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/chain"
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
	if cp.SchemaVersion != "v2" {
		t.Errorf("SchemaVersion: got %q, want %q", cp.SchemaVersion, "v2")
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

// TestCheckpointSigningPayloadFixture is the cross-impl lock test for the
// checkpoint signing payload. It verifies that the compact JSON of
// checkpointForSigning for known inputs matches the golden fixture byte-for-byte.
// Any encoding change here is a breaking chain-format change and requires a
// schema_version bump per CLAUDE.md.
func TestCheckpointSigningPayloadFixture(t *testing.T) {
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
		t.Errorf("checkpoint signing payload diverges from golden fixture.\ngot:  %s\nwant: %s", got, want)
	}
}

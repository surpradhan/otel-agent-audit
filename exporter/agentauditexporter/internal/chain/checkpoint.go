package chain

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/sign"
)

// ZeroPrevCheckpointHash is the sentinel value for prev_checkpoint_hash in the
// very first checkpoint (64 ASCII '0' chars = hex encoding of 32 zero bytes).
const ZeroPrevCheckpointHash = "0000000000000000000000000000000000000000000000000000000000000000"

// TraceTip records the tail of one sealed trace's chain.
type TraceTip struct {
	TraceID    string `json:"trace_id"`
	TipHash    string `json:"tip_hash"`
	EntryCount int    `json:"entry_count"`
}

// checkpointForSigning is the subset of Checkpoint that is signed (all fields
// except Signature). JSON field order must match Checkpoint exactly minus Signature.
// This struct is kept in sync with Checkpoint manually — any field addition requires
// updating both structs.
type checkpointForSigning struct {
	SchemaVersion      string     `json:"schema_version"`
	CheckpointSeq      uint64     `json:"checkpoint_seq"`
	Timestamp          string     `json:"timestamp"`
	PrevCheckpointHash string     `json:"prev_checkpoint_hash"`
	TraceTips          []TraceTip `json:"trace_tips"`
	KeyID              string     `json:"key_id"`
	Algorithm          string     `json:"algorithm"`
}

// Checkpoint is a signed commitment to a set of sealed trace chain tips.
// It is appended as a JSONL line to the checkpoint file.
type Checkpoint struct {
	SchemaVersion      string     `json:"schema_version"`
	CheckpointSeq      uint64     `json:"checkpoint_seq"`
	Timestamp          string     `json:"timestamp"`
	PrevCheckpointHash string     `json:"prev_checkpoint_hash"`
	TraceTips          []TraceTip `json:"trace_tips"`
	KeyID              string     `json:"key_id"`
	Algorithm          string     `json:"algorithm"`
	Signature          string     `json:"signature"`
}

// Accumulator collects sealed trace tips and produces signed checkpoints.
// All methods are safe for concurrent use.
type Accumulator struct {
	mu       sync.Mutex
	signer   sign.Signer
	seq      uint64
	prevHash string
	pending  []TraceTip
}

// NewAccumulator creates an Accumulator. Pass initialSeq=0 and
// prevHash=ZeroPrevCheckpointHash on first start; load from the last
// persisted checkpoint on restart.
func NewAccumulator(signer sign.Signer, initialSeq uint64, prevHash string) *Accumulator {
	return &Accumulator{
		signer:   signer,
		seq:      initialSeq,
		prevHash: prevHash,
	}
}

// AddTip adds a sealed trace tip to the pending set.
func (a *Accumulator) AddTip(traceID, tipHash string, entryCount int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pending = append(a.pending, TraceTip{
		TraceID:    traceID,
		TipHash:    tipHash,
		EntryCount: entryCount,
	})
}

// PendingCount returns how many trace tips are waiting to be checkpointed.
func (a *Accumulator) PendingCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.pending)
}

// Build creates and signs a checkpoint from all pending tips.
// trace_tips are sorted by trace_id before signing to ensure deterministic
// checkpointForSigning bytes across implementations.
// Resets the pending set and advances seq + prevHash.
func (a *Accumulator) Build(ts time.Time) (Checkpoint, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.seq++
	tips := make([]TraceTip, len(a.pending))
	copy(tips, a.pending)

	// Sort deterministically for cross-impl reproducibility.
	sort.Slice(tips, func(i, j int) bool {
		return tips[i].TraceID < tips[j].TraceID
	})

	cfs := checkpointForSigning{
		SchemaVersion:      "v1",
		CheckpointSeq:      a.seq,
		Timestamp:          ts.UTC().Format(time.RFC3339),
		PrevCheckpointHash: a.prevHash,
		TraceTips:          tips,
		KeyID:              a.signer.KeyID(),
		Algorithm:          "ed25519",
	}

	payload, err := json.Marshal(cfs)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("checkpoint: marshal for signing: %w", err)
	}

	sig, err := a.signer.Sign(payload)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("checkpoint: signing: %w", err)
	}

	// Advance prevHash to SHA256 of this checkpoint's signing payload.
	h := sha256.Sum256(payload)
	a.prevHash = hex.EncodeToString(h[:])
	a.pending = nil

	return Checkpoint{
		SchemaVersion:      cfs.SchemaVersion,
		CheckpointSeq:      cfs.CheckpointSeq,
		Timestamp:          cfs.Timestamp,
		PrevCheckpointHash: cfs.PrevCheckpointHash,
		TraceTips:          tips,
		KeyID:              cfs.KeyID,
		Algorithm:          cfs.Algorithm,
		Signature:          base64.StdEncoding.EncodeToString(sig),
	}, nil
}

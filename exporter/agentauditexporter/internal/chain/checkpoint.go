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

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
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
//
// Each method is individually safe for concurrent use, but Stage and Commit are
// a pair that must be driven by a single caller: staging a second checkpoint
// before the first is committed or dropped makes both claim the same sequence
// number. See Stage.
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

// DropPending discards every pending tip and returns how many were dropped.
// seq and prevHash are left untouched, so the persisted chain is unaffected and
// remains verifiable; only the coverage of those traces is given up.
//
// This exists for the one case where retaining tips is provably pointless: the
// caller has determined it can never write another checkpoint (see the
// checkpointPoisoned path in the exporter). Retaining tips that no checkpoint
// can ever cover would grow without bound for no benefit. Do NOT use it for a
// merely transient write failure — there, retention is the entire point of the
// Stage/Commit split.
//
// Do NOT call this between Stage and Commit. It is the only mutator besides
// AddTip, and it is the only one that does not preserve the prefix invariant
// StagedCheckpoint.tipCount relies on: the staged checkpoint's tip count would
// then refer to a prefix that no longer exists, and committing it afterwards
// could discard tips that no checkpoint covers.
func (a *Accumulator) DropPending() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := len(a.pending)
	a.pending = nil
	return n
}

// CheckpointSigningPayload returns the compact JSON bytes that were signed to
// produce cp. It reconstructs the checkpointForSigning struct used by Build,
// allowing callers to re-derive SHA256(payload) for chaining prevHash across
// restarts without duplicating the internal struct.
func CheckpointSigningPayload(cp Checkpoint) ([]byte, error) {
	cfs := checkpointForSigning{
		SchemaVersion:      cp.SchemaVersion,
		CheckpointSeq:      cp.CheckpointSeq,
		Timestamp:          cp.Timestamp,
		PrevCheckpointHash: cp.PrevCheckpointHash,
		TraceTips:          cp.TraceTips,
		KeyID:              cp.KeyID,
		Algorithm:          cp.Algorithm,
	}
	b, err := json.Marshal(cfs)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: marshal signing payload: %w", err)
	}
	return b, nil
}

// StagedCheckpoint is a signed checkpoint whose state advance has not yet been
// applied to the Accumulator. The caller must durably persist Checkpoint and
// only then call Commit. If persisting fails, the caller simply drops the
// StagedCheckpoint: the accumulator is untouched, so the tips are retried by
// the next checkpoint and no sequence number or prev-hash link is burned on a
// checkpoint that never reached disk.
type StagedCheckpoint struct {
	// Checkpoint is the signed checkpoint to persist.
	Checkpoint Checkpoint

	// nextPrevHash is the prevHash the accumulator adopts on Commit: the SHA256
	// of this checkpoint's signing payload.
	nextPrevHash string

	// tipCount is how many pending tips this checkpoint covers. Stage always
	// covers every tip pending at stage time, so tipCount == len(pending) then;
	// AddTip only appends and DropPending must not be called between Stage and
	// Commit, so at Commit time the covered tips are still exactly the prefix
	// pending[:tipCount] and anything added since survives.
	//
	// Note that Checkpoint.TraceTips is sorted by trace_id and is therefore NOT
	// index-aligned with the accumulator's pending slice — never match tips
	// between the two by index.
	tipCount int
}

// Stage creates and signs a checkpoint from all pending tips WITHOUT mutating
// accumulator state. trace_tips are sorted by trace_id before signing to ensure
// deterministic checkpointForSigning bytes across implementations.
//
// Stage and Commit must be paired by a single caller: do not stage a second
// checkpoint before the first has been committed or dropped, or the two will
// claim the same sequence number.
func (a *Accumulator) Stage(ts time.Time) (StagedCheckpoint, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stageLocked(ts)
}

// stageLocked is Stage's body; callers must hold a.mu.
func (a *Accumulator) stageLocked(ts time.Time) (StagedCheckpoint, error) {
	tips := make([]TraceTip, len(a.pending))
	copy(tips, a.pending)

	// Sort deterministically for cross-impl reproducibility.
	sort.Slice(tips, func(i, j int) bool {
		return tips[i].TraceID < tips[j].TraceID
	})

	cfs := checkpointForSigning{
		SchemaVersion:      record.SchemaVersion,
		CheckpointSeq:      a.seq + 1,
		Timestamp:          ts.UTC().Format(time.RFC3339),
		PrevCheckpointHash: a.prevHash,
		TraceTips:          tips,
		KeyID:              a.signer.KeyID(),
		Algorithm:          "ed25519",
	}

	payload, err := json.Marshal(cfs)
	if err != nil {
		return StagedCheckpoint{}, fmt.Errorf("checkpoint: marshal for signing: %w", err)
	}

	sig, err := a.signer.Sign(payload)
	if err != nil {
		return StagedCheckpoint{}, fmt.Errorf("checkpoint: signing: %w", err)
	}

	h := sha256.Sum256(payload)

	return StagedCheckpoint{
		Checkpoint: Checkpoint{
			SchemaVersion:      cfs.SchemaVersion,
			CheckpointSeq:      cfs.CheckpointSeq,
			Timestamp:          cfs.Timestamp,
			PrevCheckpointHash: cfs.PrevCheckpointHash,
			TraceTips:          tips,
			KeyID:              cfs.KeyID,
			Algorithm:          cfs.Algorithm,
			Signature:          base64.StdEncoding.EncodeToString(sig),
		},
		nextPrevHash: hex.EncodeToString(h[:]),
		tipCount:     len(tips),
	}, nil
}

// Commit applies st's state advance: it adopts st's sequence number and
// prev-hash and drops the tips st covers. Call it only after st.Checkpoint has
// been durably persisted.
//
// Commit returns an error and changes nothing if st does not directly succeed
// the accumulator's current state — a zero-value StagedCheckpoint, a second
// Commit of the same value, or one staged before an intervening Commit. Chain
// state is load-bearing, so a mis-paired Commit is reported rather than
// silently rewinding seq or discarding tips that no checkpoint covered.
func (a *Accumulator) Commit(st StagedCheckpoint) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.commitLocked(st)
}

// commitLocked is Commit's body; callers must hold a.mu.
func (a *Accumulator) commitLocked(st StagedCheckpoint) error {
	if st.nextPrevHash == "" || st.Checkpoint.CheckpointSeq != a.seq+1 {
		return fmt.Errorf(
			"checkpoint: commit of a checkpoint that does not succeed seq %d (got seq %d): stale, duplicate, or zero-value staged checkpoint",
			a.seq, st.Checkpoint.CheckpointSeq)
	}
	a.seq = st.Checkpoint.CheckpointSeq
	a.prevHash = st.nextPrevHash
	if st.tipCount >= len(a.pending) {
		a.pending = nil
		return nil
	}
	// Tips added after staging were not covered by st; keep them pending.
	rest := make([]TraceTip, len(a.pending)-st.tipCount)
	copy(rest, a.pending[st.tipCount:])
	a.pending = rest
	return nil
}

// Build creates and signs a checkpoint from all pending tips, advancing seq +
// prevHash and resetting the pending set immediately.
//
// Build is only appropriate when the checkpoint does not need to survive a
// crash — i.e. tests. Anything that persists the checkpoint must use
// Stage + Commit so the state advance happens only after a successful durable
// write; otherwise an IO error silently drops the pending tips and leaves the
// persisted chain with a sequence gap and a dangling prev_checkpoint_hash.
// See cmd/demo for the pattern to copy.
func (a *Accumulator) Build(ts time.Time) (Checkpoint, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	st, err := a.stageLocked(ts)
	if err != nil {
		return Checkpoint{}, err
	}
	if err := a.commitLocked(st); err != nil {
		// Unreachable: stageLocked always produces the direct successor of the
		// current state, and a.mu is held across both halves.
		return Checkpoint{}, err
	}
	return st.Checkpoint, nil
}

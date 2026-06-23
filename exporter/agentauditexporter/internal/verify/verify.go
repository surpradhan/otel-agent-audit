// Package verify provides chain and checkpoint verification.
// Used by tests and the exporter's self-check path; standalone CLI is deferred to B4.
package verify

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/canonical"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/chain"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/sign"
)

// maxScanTokenSize caps the bufio.Scanner token size for JSONL files.
// The 64 KB default is too small when CheckpointInterval is large; 4 MB provides headroom.
const maxScanTokenSize = 4 * 1024 * 1024

// VerifyError describes one verification failure.
type VerifyError struct {
	TraceID string
	Kind    string
	Detail  string
}

func (e VerifyError) Error() string {
	return fmt.Sprintf("verify[%s]: %s: %s", e.TraceID, e.Kind, e.Detail)
}

// Report summarizes a VerifyLog run.
type Report struct {
	TracesVerified      int
	CheckpointsVerified int
	Errors              []VerifyError
}

// VerifyChain verifies the hash chain of a set of log entries for a single trace.
// All entries must belong to the same trace, already in chain order (seq 0, 1, …).
// An empty entries slice returns nil.
func VerifyChain(entries []chain.LogEntry, pubKey ed25519.PublicKey) error {
	_, err := verifyChainReturnTip(entries, pubKey)
	return err
}

// verifyChainReturnTip verifies the chain and returns the hex-encoded SHA256 of
// the final sigPayload (the recomputed tip hash). Returns "" on an empty slice.
func verifyChainReturnTip(entries []chain.LogEntry, pubKey ed25519.PublicKey) (string, error) {
	if len(entries) == 0 {
		return "", nil
	}

	genesisSeed, err := chain.GenesisSeed(entries[0].Record.TraceID)
	if err != nil {
		return "", err
	}

	prev := genesisSeed
	var lastHash [32]byte
	for i, e := range entries {
		canonicalBytes, err := canonical.Marshal(e.Record)
		if err != nil {
			return "", fmt.Errorf("seq %d: canonical marshal: %w", i, err)
		}
		// Three-index slice prevents aliasing.
		sigPayload := append(canonicalBytes[:len(canonicalBytes):len(canonicalBytes)], prev...)

		// Verify signature.
		if err := sign.Verify(e.Signed, sigPayload, pubKey); err != nil {
			return "", fmt.Errorf("seq %d: %w", i, err)
		}

		// Verify stored entryHash.
		expectedHash := sha256.Sum256(sigPayload)
		if e.Signed.EntryHash != hex.EncodeToString(expectedHash[:]) {
			return "", fmt.Errorf("seq %d: entry_hash mismatch: stored %s, recomputed %s",
				i, e.Signed.EntryHash, hex.EncodeToString(expectedHash[:]))
		}

		prev = expectedHash[:]
		lastHash = expectedHash
	}
	return hex.EncodeToString(lastHash[:]), nil
}

// VerifyCheckpoint verifies a checkpoint's signature and prev_checkpoint_hash field.
// prevSignPayloadHash is the hex-encoded SHA256 of the previous checkpoint's
// signing payload (or chain.ZeroPrevCheckpointHash for the first checkpoint).
func VerifyCheckpoint(cp chain.Checkpoint, prevSignPayloadHash string, pubKey ed25519.PublicKey) error {
	// Reconstruct the signing payload (all fields except Signature, same JSON struct).
	cfs := checkpointSigningStruct{
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
		return fmt.Errorf("checkpoint marshal: %w", err)
	}

	if cp.PrevCheckpointHash != prevSignPayloadHash {
		return fmt.Errorf("prev_checkpoint_hash mismatch: got %s, want %s",
			cp.PrevCheckpointHash, prevSignPayloadHash)
	}

	sig, err := base64.StdEncoding.DecodeString(cp.Signature)
	if err != nil {
		return fmt.Errorf("checkpoint: decode signature: %w", err)
	}
	if !ed25519.Verify(pubKey, payload, sig) {
		return fmt.Errorf("checkpoint: signature verification failed")
	}
	return nil
}

// VerifyLog reads a JSONL log file and checkpoint file, verifies all chains and
// checkpoints, and returns a Report.
//
// Policy for traces not covered by any checkpoint: counted in TracesVerified
// but not reported as errors (they are "unchecked-by-checkpoint"). Rationale:
// the final batch before a crash may be in the log before the checkpoint was
// persisted; treating this as an error would produce false positives on restarts.
func VerifyLog(logPath, checkpointPath string, pubKey ed25519.PublicKey) (Report, error) {
	var report Report

	// Parse the log file, grouping by trace_id.
	traceEntries, err := readLogEntries(logPath)
	if err != nil {
		return report, err
	}

	// Verify each trace chain in sorted order for deterministic error output.
	traceIDs := make([]string, 0, len(traceEntries))
	for id := range traceEntries {
		traceIDs = append(traceIDs, id)
	}
	sort.Strings(traceIDs)

	// verifiedTips maps trace_id → the actual recomputed tip hash (hex of SHA256
	// of last sigPayload). Used to cross-check checkpoint tip_hash fields.
	verifiedTips := make(map[string]string, len(traceIDs))
	var verifyErrs []VerifyError
	for _, traceID := range traceIDs {
		entries := traceEntries[traceID]
		tipHash, err := verifyChainReturnTip(entries, pubKey)
		if err != nil {
			verifyErrs = append(verifyErrs, VerifyError{
				TraceID: traceID,
				Kind:    "chain",
				Detail:  err.Error(),
			})
		} else {
			verifiedTips[traceID] = tipHash
		}
		report.TracesVerified++
	}

	// Parse and verify checkpoints.
	checkpoints, err := readCheckpoints(checkpointPath)
	if err != nil {
		return report, err
	}

	prevHash := chain.ZeroPrevCheckpointHash
	for _, cp := range checkpoints {
		// Compute the signing payload hash BEFORE checking (VerifyCheckpoint checks the field).
		payload, err := checkpointSignPayload(cp)
		if err != nil {
			verifyErrs = append(verifyErrs, VerifyError{
				TraceID: "",
				Kind:    "checkpoint",
				Detail:  fmt.Sprintf("seq %d: %v", cp.CheckpointSeq, err),
			})
			report.CheckpointsVerified++
			continue
		}
		h := sha256.Sum256(payload)

		if err := VerifyCheckpoint(cp, prevHash, pubKey); err != nil {
			verifyErrs = append(verifyErrs, VerifyError{
				TraceID: "",
				Kind:    "checkpoint",
				Detail:  fmt.Sprintf("seq %d: %v", cp.CheckpointSeq, err),
			})
		}
		prevHash = hex.EncodeToString(h[:])
		report.CheckpointsVerified++

		// Cross-check each trace_tip's entry_count and tip_hash against the log.
		for _, tip := range cp.TraceTips {
			entries := traceEntries[tip.TraceID]
			if len(entries) != tip.EntryCount {
				verifyErrs = append(verifyErrs, VerifyError{
					TraceID: tip.TraceID,
					Kind:    "entry_count_mismatch",
					Detail:  fmt.Sprintf("checkpoint says %d, log has %d", tip.EntryCount, len(entries)),
				})
			}
			if actual, ok := verifiedTips[tip.TraceID]; ok && actual != tip.TipHash {
				verifyErrs = append(verifyErrs, VerifyError{
					TraceID: tip.TraceID,
					Kind:    "tip_hash_mismatch",
					Detail:  fmt.Sprintf("checkpoint tip_hash %s, recomputed %s", tip.TipHash, actual),
				})
			}
		}
	}

	report.Errors = verifyErrs
	return report, nil
}

// checkpointSigningStruct mirrors checkpointForSigning in checkpoint.go for verification.
// Must be kept in sync with Accumulator.Build's signing struct.
type checkpointSigningStruct struct {
	SchemaVersion      string           `json:"schema_version"`
	CheckpointSeq      uint64           `json:"checkpoint_seq"`
	Timestamp          string           `json:"timestamp"`
	PrevCheckpointHash string           `json:"prev_checkpoint_hash"`
	TraceTips          []chain.TraceTip `json:"trace_tips"`
	KeyID              string           `json:"key_id"`
	Algorithm          string           `json:"algorithm"`
}

// checkpointSignPayload reconstructs the signing payload for a checkpoint.
func checkpointSignPayload(cp chain.Checkpoint) ([]byte, error) {
	cfs := checkpointSigningStruct{
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

func readLogEntries(logPath string) (map[string][]chain.LogEntry, error) {
	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]chain.LogEntry{}, nil
		}
		return nil, fmt.Errorf("verify: open log %q: %w", logPath, err)
	}
	defer func() { _ = f.Close() }()

	result := map[string][]chain.LogEntry{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), maxScanTokenSize)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		e, err := chain.UnmarshalLogEntry(line)
		if err != nil {
			return nil, fmt.Errorf("verify: unmarshal log entry: %w", err)
		}
		result[e.Record.TraceID] = append(result[e.Record.TraceID], e)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Sort each trace's entries by seq_in_trace so VerifyChain sees them in
	// chain order regardless of log write order.
	for id := range result {
		entries := result[id]
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Record.SeqInTrace < entries[j].Record.SeqInTrace
		})
		result[id] = entries
	}
	return result, nil
}

func readCheckpoints(checkPath string) ([]chain.Checkpoint, error) {
	f, err := os.Open(checkPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("verify: open checkpoint %q: %w", checkPath, err)
	}
	defer func() { _ = f.Close() }()

	var cps []chain.Checkpoint
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), maxScanTokenSize)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var cp chain.Checkpoint
		if err := json.Unmarshal(line, &cp); err != nil {
			return nil, fmt.Errorf("verify: unmarshal checkpoint: %w", err)
		}
		cps = append(cps, cp)
	}
	return cps, scanner.Err()
}

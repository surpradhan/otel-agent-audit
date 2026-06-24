// Package verify provides chain and checkpoint verification.
// Used by tests, the exporter's self-check path, and the otel-agent-audit-verify CLI.
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
	"strings"

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
// TracesProcessed and CheckpointsProcessed count all entries seen (including
// those that failed verification); check Errors for per-entry failure details.
type Report struct {
	TracesProcessed      int
	CheckpointsProcessed int
	Errors               []VerifyError
}

// pubKeyID returns hex(SHA256(pubKey)) — the same fingerprint scheme used by
// sign.NewEd25519Signer so the verifier can compare key_id fields without
// needing to reconstruct a full Ed25519Signer.
func pubKeyID(pubKey ed25519.PublicKey) string {
	h := sha256.Sum256(pubKey)
	return hex.EncodeToString(h[:])
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
	payload, err := chain.CheckpointSigningPayload(cp)
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
// Key-id handling:
//   - The verifier computes the fingerprint of the supplied public key as
//     hex(SHA256(pubKey)) and pre-scans all entries and checkpoints.
//   - If the log contains more than one distinct key_id (a multi-epoch log),
//     VerifyLog returns a "multi_epoch_log" VerifyError and stops. Re-run once
//     per epoch with the key that matches that epoch's key_id.
//   - If the single key_id in the log does not match the supplied public key,
//     VerifyLog emits "key_id_mismatch" errors for every trace and checkpoint
//     without attempting chain verification (which would only produce misleading
//     signature-failure errors).
//
// Policy for traces not covered by any checkpoint: counted in TracesProcessed
// but not reported as errors (they are "unchecked-by-checkpoint"). Rationale:
// the final batch before a crash may be in the log before the checkpoint was
// persisted; treating this as an error would produce false positives on restarts.
func VerifyLog(logPath, checkpointPath string, pubKey ed25519.PublicKey) (Report, error) {
	var report Report

	// Parse the log file, grouping by trace_id.
	traceEntries, duplicateTraces, err := readLogEntries(logPath)
	if err != nil {
		return report, err
	}

	// Parse checkpoints.
	checkpoints, err := readCheckpoints(checkpointPath)
	if err != nil {
		return report, err
	}

	// Pre-scan: collect all distinct key_ids across log entries and checkpoints.
	// This allows us to distinguish "wrong key supplied" (key_id_mismatch) from
	// "bad signature" (chain error) and to detect multi-epoch logs early.
	suppliedKeyID := pubKeyID(pubKey)
	seenKeyIDs := make(map[string]struct{})
	for _, entries := range traceEntries {
		for _, e := range entries {
			if e.Signed.KeyID != "" {
				seenKeyIDs[e.Signed.KeyID] = struct{}{}
			}
		}
	}
	for _, cp := range checkpoints {
		if cp.KeyID != "" {
			seenKeyIDs[cp.KeyID] = struct{}{}
		}
	}

	// Multi-epoch check: more than one distinct key_id means the log spans a
	// key rotation. Re-run per epoch with the matching key.
	if len(seenKeyIDs) > 1 {
		ids := make([]string, 0, len(seenKeyIDs))
		for id := range seenKeyIDs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return report, fmt.Errorf("multi-epoch log: %d distinct key_ids found; re-run per epoch with the matching key (found: %s)",
			len(ids), strings.Join(ids, ", "))
	}

	// Single key_id check: if the log has exactly one key_id and it doesn't
	// match the supplied key, emit key_id_mismatch for every trace and checkpoint
	// rather than letting chain verification produce misleading signature errors.
	if len(seenKeyIDs) == 1 {
		var logKeyID string
		for id := range seenKeyIDs {
			logKeyID = id
		}
		if logKeyID != suppliedKeyID {
			detail := fmt.Sprintf("log signed by %s, supplied key is %s", logKeyID, suppliedKeyID)
			var verifyErrs []VerifyError

			traceIDs := make([]string, 0, len(traceEntries))
			for id := range traceEntries {
				traceIDs = append(traceIDs, id)
			}
			sort.Strings(traceIDs)
			for _, traceID := range traceIDs {
				verifyErrs = append(verifyErrs, VerifyError{
					TraceID: traceID,
					Kind:    "key_id_mismatch",
					Detail:  detail,
				})
				report.TracesProcessed++
			}
			for _, cp := range checkpoints {
				verifyErrs = append(verifyErrs, VerifyError{
					TraceID: "",
					Kind:    "key_id_mismatch",
					Detail:  fmt.Sprintf("checkpoint seq %d: %s", cp.CheckpointSeq, detail),
				})
				report.CheckpointsProcessed++
			}
			report.Errors = verifyErrs
			return report, nil
		}
	}

	// Verify each trace chain in sorted order for deterministic error output.
	traceIDs := make([]string, 0, len(traceEntries))
	for id := range traceEntries {
		traceIDs = append(traceIDs, id)
	}
	sort.Strings(traceIDs)

	// verifiedTips maps trace_id → the actual recomputed tip hash (hex of SHA256
	// of last sigPayload). Used to cross-check checkpoint tip_hash fields.
	// chainFailed records traces whose chain verification failed so the
	// cross-check loop can emit tip_hash_unverifiable instead of silently
	// skipping the comparison.
	verifiedTips := make(map[string]string, len(traceIDs))
	chainFailed := make(map[string]struct{}) // set of trace IDs whose chain verification failed
	var verifyErrs []VerifyError
	for _, traceID := range traceIDs {
		// Emit duplicate_trace_segment for post-compact double chains before
		// attempting chain verification, which would produce confusing results.
		if _, dup := duplicateTraces[traceID]; dup {
			verifyErrs = append(verifyErrs, VerifyError{
				TraceID: traceID,
				Kind:    "duplicate_trace_segment",
				Detail:  "more than one entry with the same seq_in_trace; likely an at-least-once re-delivery after WAL compaction — see docs/threat-model.md §5",
			})
			chainFailed[traceID] = struct{}{}
			report.TracesProcessed++
			continue
		}

		entries := traceEntries[traceID]
		tipHash, err := verifyChainReturnTip(entries, pubKey)
		if err != nil {
			verifyErrs = append(verifyErrs, VerifyError{
				TraceID: traceID,
				Kind:    "chain",
				Detail:  err.Error(),
			})
			chainFailed[traceID] = struct{}{}
		} else {
			verifiedTips[traceID] = tipHash
		}
		report.TracesProcessed++
	}

	prevHash := chain.ZeroPrevCheckpointHash
	for _, cp := range checkpoints {
		// Compute the signing payload hash BEFORE checking (VerifyCheckpoint checks the field).
		payload, err := chain.CheckpointSigningPayload(cp)
		if err != nil {
			verifyErrs = append(verifyErrs, VerifyError{
				TraceID: "",
				Kind:    "checkpoint",
				Detail:  fmt.Sprintf("seq %d: %v", cp.CheckpointSeq, err),
			})
			report.CheckpointsProcessed++
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
		// prevHash advances even when VerifyCheckpoint fails so that the next
		// checkpoint's prev_checkpoint_hash field is evaluated against the hash
		// of the corrupt/tampered entry's payload rather than the last good one.
		// This means a cascade of "prev_checkpoint_hash mismatch" errors from
		// subsequent checkpoints is suppressed, but each checkpoint's Ed25519
		// signature is still independently verified regardless.
		prevHash = hex.EncodeToString(h[:])
		report.CheckpointsProcessed++

		// Cross-check each trace_tip's entry_count and tip_hash against the log.
		// Errors are emitted once per (checkpoint, trace) pair — a trace covered
		// by N checkpoints produces N errors. This is intentional: each
		// checkpoint occurrence is an independent audit point.
		for _, tip := range cp.TraceTips {
			entries := traceEntries[tip.TraceID]
			if len(entries) != tip.EntryCount {
				verifyErrs = append(verifyErrs, VerifyError{
					TraceID: tip.TraceID,
					Kind:    "entry_count_mismatch",
					Detail:  fmt.Sprintf("checkpoint says %d, log has %d", tip.EntryCount, len(entries)),
				})
			}
			if _, ok := chainFailed[tip.TraceID]; ok {
				// Chain verification failed, so we cannot confirm the tip
				// hash. Report it explicitly instead of silently skipping.
				verifyErrs = append(verifyErrs, VerifyError{
					TraceID: tip.TraceID,
					Kind:    "tip_hash_unverifiable",
					Detail:  fmt.Sprintf("chain verification failed; checkpoint tip_hash %s cannot be confirmed", tip.TipHash),
				})
			} else if actual, ok := verifiedTips[tip.TraceID]; ok && actual != tip.TipHash {
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

// readLogEntries reads and parses all JSONL log entries, grouped by trace_id and
// sorted by seq_in_trace. The second return value is the set of trace IDs that
// have duplicate seq_in_trace values (a sign of at-least-once re-delivery after
// WAL compaction).
func readLogEntries(logPath string) (map[string][]chain.LogEntry, map[string]struct{}, error) {
	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]chain.LogEntry{}, map[string]struct{}{}, nil
		}
		return nil, nil, fmt.Errorf("verify: open log %q: %w", logPath, err)
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
			return nil, nil, fmt.Errorf("verify: unmarshal log entry: %w", err)
		}
		result[e.Record.TraceID] = append(result[e.Record.TraceID], e)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	// Sort each trace's entries by seq_in_trace and detect duplicates.
	duplicates := map[string]struct{}{}
	for id := range result {
		entries := result[id]
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Record.SeqInTrace < entries[j].Record.SeqInTrace
		})
		// Scan for consecutive entries with the same seq_in_trace.
		for i := 1; i < len(entries); i++ {
			if entries[i].Record.SeqInTrace == entries[i-1].Record.SeqInTrace {
				duplicates[id] = struct{}{}
				break
			}
		}
		result[id] = entries
	}
	return result, duplicates, nil
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

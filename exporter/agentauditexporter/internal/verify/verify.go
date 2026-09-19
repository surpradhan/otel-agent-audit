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
	// Severity is SeverityFatal or SeverityAdvisory (see those constants'
	// doc comments). Callers deciding exit codes or a Status: OK/FAILED line
	// should key off Severity, not merely off whether Errors is non-empty —
	// an advisory-only report is not a verification failure (issue #49).
	Severity string
}

func (e VerifyError) Error() string {
	return fmt.Sprintf("verify[%s]: %s: %s", e.TraceID, e.Kind, e.Detail)
}

// KindTornTrailingLine is the VerifyError.Kind for a torn final audit-log
// line (see VerifyLog's doc comment). Exported as a constant, unlike this
// package's other Kind strings, because it is the only one a caller outside
// this package needs to pattern-match on today: the CLI's human-readable
// output must label it differently from a checkpoint-level error, since both
// share an empty TraceID (see cmd/otel-agent-audit-verify's errorLabel).
const KindTornTrailingLine = "torn_trailing_line"

// SeverityFatal marks a VerifyError that means verification could not be
// completed, or completed and found the signed content untrustworthy. A
// report containing any SeverityFatal error should be treated as a
// verification failure (Status: FAILED, non-zero exit code).
const SeverityFatal = "fatal"

// SeverityAdvisory marks a VerifyError whose flagged entries were still
// fully verified against the supplied key despite the finding — the
// signature already proved the content authentic, so this is worth
// surfacing but is not by itself a reason to treat the log as untrustworthy.
// A report containing only SeverityAdvisory errors is not a verification
// failure.
const SeverityAdvisory = "advisory"

// Report summarizes a VerifyLog run.
// TracesProcessed and CheckpointsProcessed count all entries seen (including
// those that failed verification); check Errors for per-entry failure details.
type Report struct {
	TracesProcessed      int
	CheckpointsProcessed int
	Errors               []VerifyError

	// OtherClaimedKeyIDs lists, sorted and de-duplicated, the non-empty key_id
	// values claimed by log entries or checkpoints that differ from the key
	// this run verified against; empty (and omitted from JSON) when every claim
	// matches. It hints that part of the log may have been signed by a key this
	// run was not given (a rotation, or the wrong key), or that a key_id field
	// was edited — never a finding: it does not add to Errors, and FatalCount,
	// StatusLine and the CLI's exit code ignore it. Claims are untrusted text
	// taken as-is: an entry's key_id is unauthenticated (see VerifyLog), and a
	// checkpoint that did not verify against the supplied key is only a claim
	// too, so an empty list does not show that the log is single-epoch.
	// Provisional: issue #19's rotation-aware verification may supersede or
	// reshape it (issue #50).
	OtherClaimedKeyIDs []string `json:",omitempty"`
}

// FatalCount returns how many of r.Errors are not SeverityAdvisory. Callers
// deciding exit codes or a Status: OK/FAILED line should key off this, not
// len(r.Errors) — an advisory-only report is not a verification failure
// (issue #49). Deliberately fail-closed: an error whose Severity is empty or
// some future, unrecognized value counts as fatal here, not advisory — the
// two kinds this package treats as advisory (KindTornTrailingLine and
// key_id_field_mismatch) are the only ones that get the benefit of the
// doubt, and only because they always carry an explicit SeverityAdvisory.
func (r Report) FatalCount() int {
	n := 0
	for _, e := range r.Errors {
		if e.Severity != SeverityAdvisory {
			n++
		}
	}
	return n
}

// StatusLine returns the "Status: ..." summary line for r, e.g. "Status: OK",
// "Status: OK (2 advisory finding(s))", "Status: FAILED (1 error(s))", or
// "Status: FAILED (1 fatal, 2 advisory)". Only FatalCount decides OK vs
// FAILED, but the advisory count is always named too, so the line never
// undercounts what a caller's per-error printout will show underneath it.
// Both otel-agent-audit-verify and cmd/demo call this — a single, shared
// implementation instead of each CLI approximating it (issue #49).
func (r Report) StatusLine() string {
	fatal := r.FatalCount()
	advisory := len(r.Errors) - fatal
	switch {
	case fatal == 0 && advisory == 0:
		return "Status: OK"
	case fatal == 0:
		return fmt.Sprintf("Status: OK (%d advisory finding(s))", advisory)
	case advisory == 0:
		return fmt.Sprintf("Status: FAILED (%d error(s))", fatal)
	default:
		return fmt.Sprintf("Status: FAILED (%d fatal, %d advisory)", fatal, advisory)
	}
}

// pubKeyID returns hex(SHA256(pubKey)) — the same fingerprint scheme used by
// sign.NewEd25519Signer so the verifier can compare key_id fields without
// needing to reconstruct a full Ed25519Signer.
func pubKeyID(pubKey ed25519.PublicKey) string {
	h := sha256.Sum256(pubKey)
	return hex.EncodeToString(h[:])
}

// otherClaimedKeyIDs returns the sorted, de-duplicated non-empty key_id values
// claimed by any entry or checkpoint that differ from suppliedKeyID, or nil if
// there are none. Claims are read as-is, whether or not the entry or
// checkpoint carrying them verifies — see Report.OtherClaimedKeyIDs.
func otherClaimedKeyIDs(traceEntries map[string][]chain.LogEntry, checkpoints []chain.Checkpoint, suppliedKeyID string) []string {
	seen := map[string]struct{}{}
	claim := func(id string) {
		if id != "" && id != suppliedKeyID {
			seen[id] = struct{}{}
		}
	}
	for _, entries := range traceEntries {
		for _, e := range entries {
			claim(e.Signed.KeyID)
		}
	}
	for _, cp := range checkpoints {
		claim(cp.KeyID)
	}
	if len(seen) == 0 {
		return nil
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
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

	genesisSeed, err := chain.GenesisSeedForSchema(entries[0].Record.TraceID, entries[0].Record.SchemaVersion)
	if err != nil {
		return "", err
	}

	// The genesis seed comes from entries[0], and every entry is re-marshaled in
	// the shape of its own schema_version, so a chain whose entries disagree on
	// that field would otherwise reproduce every hash and pass. The format
	// forbids it — one chain, one schema version — and an invariant upheld only
	// by the writer is one a verifier cannot attest to, so check it here.
	chainSchemaVersion := entries[0].Record.SchemaVersion

	prev := genesisSeed
	var lastHash [32]byte
	for i, e := range entries {
		if e.Record.SchemaVersion != chainSchemaVersion {
			return "", fmt.Errorf("seq %d: schema_version %q does not match the chain's %q: entries of different schema versions must not share a chain",
				i, e.Record.SchemaVersion, chainSchemaVersion)
		}

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
//   - Every log entry carries a key_id field (hex(SHA256(pubKeyBytes))), but
//     sign.SignedEntry.KeyID sits beside the signature, not inside what gets
//     signed (see internal/sign) — it is not authenticated, and nothing stops
//     it being edited independently of a perfectly valid signature. VerifyLog
//     therefore never lets an entry's claimed key_id decide whether, or how,
//     its chain is verified: every entry is always verified directly against
//     the supplied public key.
//   - When a trace's chain verifies successfully, its entries' claimed
//     key_id is compared against the now-authenticated actual signer,
//     hex(SHA256(pubKey)). A disagreement there cannot mean the content is
//     forged — the signature already proved otherwise — so it is reported as
//     a non-fatal "key_id_field_mismatch" finding (stale or tampered
//     metadata on an otherwise-good entry) rather than something that blocks
//     verification.
//   - A checkpoint's key_id is different: chain.Checkpoint.KeyID is one of
//     the fields chain.CheckpointSigningPayload marshals into the bytes that
//     get signed (see chain.Accumulator.Stage), so it IS authenticated —
//     editing it invalidates the checkpoint's signature like editing any
//     other signed field, and VerifyCheckpoint reports that as an ordinary
//     "checkpoint" signature-failure error. There is no checkpoint-side
//     key_id_field_mismatch: a checkpoint that verifies has, by construction,
//     a key_id equal to the supplied key's fingerprint.
//   - An entry or checkpoint that does NOT verify against the supplied key
//     (wrong key, key rotation, or genuine tampering) produces the ordinary
//     "chain" / "checkpoint" signature-failure error. VerifyLog cannot and
//     does not try to tell those causes apart using a single candidate key.
//     Report.OtherClaimedKeyIDs is a non-gating hint alongside them: the
//     key_id values the log claims other than the supplied key's, taken as-is
//     (see that field; an empty list does not show the log is single-epoch),
//     never affecting Errors or the verdict. For the full picture, compare
//     claimed key_id values by hand (see docs/verification.md "Multi-epoch
//     logs") — always against the full, unsplit log and checkpoint files,
//     since filtering by key_id can exclude the very checkpoint that covers a
//     rotation-boundary trace (issue #35).
//
// Policy for traces not covered by any checkpoint: counted in TracesProcessed
// but not reported as errors (they are "unchecked-by-checkpoint"). Rationale:
// the final batch before a crash may be in the log before the checkpoint was
// persisted; treating this as an error would produce false positives on restarts.
//
// Policy for a torn trailing line in the audit log: the final line is
// tolerated if unparseable (a single write(2) can be interrupted mid-line by
// a crash) and reported as a "torn_trailing_line" entry in Report.Errors
// rather than silently dropped or hard-failed — entries before it are still
// fully verified. An unparseable line anywhere earlier remains a hard Go
// error, since only the last line can plausibly be an interrupted write.
func VerifyLog(logPath, checkpointPath string, pubKey ed25519.PublicKey) (Report, error) {
	var report Report

	// Parse the log file, grouping by trace_id. tornTailDetail is non-empty when
	// the log's final line was unparseable and tolerated as an interrupted write
	// rather than a hard error — see readLogEntries.
	traceEntries, duplicateTraces, tornTailDetail, err := readLogEntries(logPath)
	if err != nil {
		return report, err
	}

	// Parse checkpoints.
	checkpoints, err := readCheckpoints(checkpointPath)
	if err != nil {
		return report, err
	}

	// suppliedKeyID is the fingerprint of the key this run verifies against.
	// key_id_field_mismatch compares an entry's claimed key_id against it only
	// AFTER that entry's signature has been independently verified below;
	// OtherClaimedKeyIDs compares every claim against it as-is, but only ever
	// as a hint that never touches Errors. See VerifyLog's doc comment.
	suppliedKeyID := pubKeyID(pubKey)
	report.OtherClaimedKeyIDs = otherClaimedKeyIDs(traceEntries, checkpoints, suppliedKeyID)

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
				// Fatal, not advisory, despite "not evidence of tampering" in
				// docs/threat-model.md §7: that framing is about the
				// segment-split event itself, not a guarantee about the
				// entries under it — chain verification is skipped entirely
				// for this trace_id (see below), so unlike the two advisory
				// kinds, nothing here was actually cryptographically checked.
				Severity: SeverityFatal,
			})
			chainFailed[traceID] = struct{}{}
			report.TracesProcessed++
			continue
		}

		entries := traceEntries[traceID]
		tipHash, err := verifyChainReturnTip(entries, pubKey)
		if err != nil {
			verifyErrs = append(verifyErrs, VerifyError{
				TraceID:  traceID,
				Kind:     "chain",
				Detail:   err.Error(),
				Severity: SeverityFatal,
			})
			chainFailed[traceID] = struct{}{}
		} else {
			verifiedTips[traceID] = tipHash
			// The chain verified against the supplied key, so suppliedKeyID is
			// now this trace's authenticated signer. A claimed key_id that
			// disagrees is stale or tampered metadata, not a forged entry —
			// worth reporting, but not a reason to fail an otherwise-good
			// trace. Entries with an empty key_id (pre-key_id-field logs) are
			// skipped: there is nothing to compare.
			for _, e := range entries {
				if e.Signed.KeyID != "" && e.Signed.KeyID != suppliedKeyID {
					verifyErrs = append(verifyErrs, VerifyError{
						TraceID: traceID,
						Kind:    "key_id_field_mismatch",
						Detail: fmt.Sprintf("seq %d: entry key_id %s does not match verified signer %s",
							e.Record.SeqInTrace, e.Signed.KeyID, suppliedKeyID),
						Severity: SeverityAdvisory,
					})
				}
			}
		}
		report.TracesProcessed++
	}

	prevHash := chain.ZeroPrevCheckpointHash
	for _, cp := range checkpoints {
		// Compute the signing payload hash BEFORE checking (VerifyCheckpoint checks the field).
		payload, err := chain.CheckpointSigningPayload(cp)
		if err != nil {
			verifyErrs = append(verifyErrs, VerifyError{
				TraceID:  "",
				Kind:     "checkpoint",
				Detail:   fmt.Sprintf("seq %d: %v", cp.CheckpointSeq, err),
				Severity: SeverityFatal,
			})
			report.CheckpointsProcessed++
			continue
		}
		h := sha256.Sum256(payload)

		if err := VerifyCheckpoint(cp, prevHash, pubKey); err != nil {
			verifyErrs = append(verifyErrs, VerifyError{
				TraceID:  "",
				Kind:     "checkpoint",
				Detail:   fmt.Sprintf("seq %d: %v", cp.CheckpointSeq, err),
				Severity: SeverityFatal,
			})
		}
		// No checkpoint-side key_id_field_mismatch check here: unlike an
		// entry's key_id, cp.KeyID is one of the fields CheckpointSigningPayload
		// marshals into the signed bytes (see chain.Accumulator.Stage), so it is
		// authenticated. A checkpoint that reaches this point having verified
		// necessarily has cp.KeyID == suppliedKeyID already — Ed25519
		// verification succeeding is proof the exact payload, KeyID included,
		// was signed by the supplied key. Editing cp.KeyID alone changes the
		// signed bytes and fails verification above like any other tampered
		// field; it cannot reach here with a disagreeing value.
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
					TraceID:  tip.TraceID,
					Kind:     "entry_count_mismatch",
					Detail:   fmt.Sprintf("checkpoint says %d, log has %d", tip.EntryCount, len(entries)),
					Severity: SeverityFatal,
				})
			}
			if _, ok := chainFailed[tip.TraceID]; ok {
				// Chain verification failed, so we cannot confirm the tip
				// hash. Report it explicitly instead of silently skipping.
				// Fatal: this trace always also carries a chain or
				// duplicate_trace_segment error (both fatal) in the same
				// report, since that is the only way chainFailed gets set —
				// so this can never be the sole reason a report fails.
				verifyErrs = append(verifyErrs, VerifyError{
					TraceID:  tip.TraceID,
					Kind:     "tip_hash_unverifiable",
					Detail:   fmt.Sprintf("chain verification failed; checkpoint tip_hash %s cannot be confirmed", tip.TipHash),
					Severity: SeverityFatal,
				})
			} else if actual, ok := verifiedTips[tip.TraceID]; ok && actual != tip.TipHash {
				verifyErrs = append(verifyErrs, VerifyError{
					TraceID:  tip.TraceID,
					Kind:     "tip_hash_mismatch",
					Detail:   fmt.Sprintf("checkpoint tip_hash %s, recomputed %s", tip.TipHash, actual),
					Severity: SeverityFatal,
				})
			}
		}
	}

	if tornTailDetail != "" {
		verifyErrs = append(verifyErrs, VerifyError{Kind: KindTornTrailingLine, Detail: tornTailDetail, Severity: SeverityAdvisory})
	}
	report.Errors = verifyErrs
	return report, nil
}

// readLogEntries reads and parses all JSONL log entries, grouped by trace_id and
// sorted by seq_in_trace. The second return value is the set of trace IDs that
// have duplicate seq_in_trace values (a sign of at-least-once re-delivery after
// WAL compaction). The third return value is non-empty when the final line was
// unparseable and was tolerated as an interrupted write rather than a hard
// error; it describes the failure for inclusion in the caller's Report. Line
// numbers in both this detail and the hard-error path count only non-blank
// lines, matching readCheckpoints, not raw physical file lines.
func readLogEntries(logPath string) (map[string][]chain.LogEntry, map[string]struct{}, string, error) {
	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]chain.LogEntry{}, map[string]struct{}{}, "", nil
		}
		return nil, nil, "", fmt.Errorf("verify: open log %q: %w", logPath, err)
	}
	defer func() { _ = f.Close() }()

	// Collect all non-empty lines first so we can tell which one is last.
	var rawLines [][]byte
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), maxScanTokenSize)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		rawLines = append(rawLines, cp)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, "", err
	}

	result := map[string][]chain.LogEntry{}
	var tornTail string
	for i, line := range rawLines {
		e, err := chain.UnmarshalLogEntry(line)
		if err != nil {
			// The final line may be a partial write from a crash — a single
			// write(2) of a JSONL line is not atomic, the same reason
			// readCheckpoints tolerates a torn final checkpoint line (see
			// repairTrailingPartialLine in exporter.go and issue #24). Unlike
			// the checkpoint case, this is reported rather than silently
			// dropped: the audit log is the evidence itself, and hiding
			// exactly this line is what an attacker who could truncate the
			// file would want. Any earlier line failing to parse is
			// corruption or tampering, not an interrupted write, and remains
			// a hard error.
			if i == len(rawLines)-1 {
				tornTail = fmt.Sprintf("line %d: unparseable, likely a partial write from a crash: %v", i+1, err)
				break
			}
			return nil, nil, "", fmt.Errorf("verify: unmarshal log entry at line %d: %w", i+1, err)
		}
		result[e.Record.TraceID] = append(result[e.Record.TraceID], e)
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
	return result, duplicates, tornTail, nil
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

	// Collect all non-empty lines first so we can identify the last one.
	var rawLines [][]byte
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), maxScanTokenSize)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		rawLines = append(rawLines, cp)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("verify: scanning checkpoint %q: %w", checkPath, err)
	}

	var cps []chain.Checkpoint
	for i, line := range rawLines {
		var cp chain.Checkpoint
		if err := json.Unmarshal(line, &cp); err != nil {
			// The final line of a checkpoint file may be a partial write from a
			// crash; skip it (same tolerance as readLastCheckpoint in the exporter).
			// Any non-final unparseable line indicates corruption or tampering.
			if i == len(rawLines)-1 {
				continue
			}
			return nil, fmt.Errorf("verify: unmarshal checkpoint line %d: %w", i+1, err)
		}
		cps = append(cps, cp)
	}
	return cps, nil
}

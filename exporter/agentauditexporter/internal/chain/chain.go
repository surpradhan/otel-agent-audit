// Package chain implements the per-trace hash-chain protocol for the audit log.
//
// Chain protocol (B2):
//
//	genesis_seed = SHA256(hex.DecodeString(traceID) ‖ []byte(record.SchemaVersion))
//
//	for i, rec := range records:
//	    canonicalBytes = canonical.Marshal(rec)   // rec.SeqInTrace == i (set by caller)
//	    prev           = genesis_seed if i == 0, else entryHash[i-1]
//	    sigPayload[i]  = append(canonicalBytes[:len:len], prev...)
//	    entryHash[i]   = hex(SHA256(sigPayload[i]))
//	    signature[i]   = base64(ed25519.Sign(privKey, sigPayload[i]))
//
// Backward compatibility: for a single-span trace (seq=0), sigPayload[0] is
// identical to the B1 construction (canonical ‖ genesis_seed), so B1-produced
// log entries verify correctly against this protocol.
package chain

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/canonical"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/sign"
)

// LogEntry is the JSON object written per span to the audit log.
// Exported so internal/verify can decode the log without a circular import.
type LogEntry struct {
	Record record.AuditRecord `json:"record"`
	Signed sign.SignedEntry   `json:"signed"`
}

// ChainEntry holds the computed chain values for one span.
type ChainEntry struct {
	Record    record.AuditRecord
	EntryHash string // hex(SHA256(sigPayload))
	Signature string // base64(ed25519.Sign(privKey, sigPayload))
	KeyID     string
}

// SortRecords sorts records in-place by (StartTimeUnixNano ASC, SpanID ASC).
// This ordering is load-bearing: it determines SeqInTrace values and therefore
// the canonical bytes that are hashed. Any change here is a breaking chain-format change.
func SortRecords(records []record.AuditRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].StartTimeUnixNano != records[j].StartTimeUnixNano {
			return records[i].StartTimeUnixNano < records[j].StartTimeUnixNano
		}
		return records[i].SpanID < records[j].SpanID
	})
}

// GenesisSeedForSchema computes SHA256(hex.DecodeString(traceID) || []byte(schemaVersion)).
// Use this when the schema version must be taken from the log entry (e.g. in
// the verifier, which must handle both v1 and v2 logs).
func GenesisSeedForSchema(traceID, schemaVersion string) ([]byte, error) {
	traceIDBytes, err := hex.DecodeString(traceID)
	if err != nil {
		return nil, fmt.Errorf("chain: decoding trace ID %q: %w", traceID, err)
	}
	h := sha256.New()
	h.Write(traceIDBytes)
	h.Write([]byte(schemaVersion))
	return h.Sum(nil), nil
}

// GenesisSeed computes SHA256(hex.DecodeString(traceID) || []byte(record.SchemaVersion)).
// Returns an error if traceID is not valid lowercase hex (32 hex chars = 16 bytes).
func GenesisSeed(traceID string) ([]byte, error) {
	return GenesisSeedForSchema(traceID, record.SchemaVersion)
}

// TipHash returns the EntryHash of the last entry in a chain.
// Panics if entries is empty.
func TipHash(entries []ChainEntry) string {
	return entries[len(entries)-1].EntryHash
}

// BuildChain constructs a hash chain from a slice of AuditRecords.
//
// Precondition: records[i].SeqInTrace == i for all i.
// The caller must sort records (SortRecords) and assign SeqInTrace before calling BuildChain.
// BuildChain trusts the SeqInTrace values already embedded in the records; it
// does not set them itself.
//
// Chain protocol:
//   - prev[0] = genesisSeed
//   - prev[i] = entryHash[i-1] for i > 0
//   - sigPayload[i] = append(canonicalBytes[:len:len], prev...)
//   - entryHash[i]  = hex(SHA256(sigPayload[i]))
//   - signature[i]  = base64(ed25519.Sign(privKey, sigPayload[i]))
func BuildChain(records []record.AuditRecord, genesisSeed []byte, signer sign.Signer) ([]ChainEntry, error) {
	entries := make([]ChainEntry, len(records))
	prev := genesisSeed

	for i, rec := range records {
		canonicalBytes, err := canonical.Marshal(rec)
		if err != nil {
			return nil, fmt.Errorf("chain: canonical marshal for seq %d: %w", i, err)
		}

		// Three-index slice cap prevents append from aliasing canonicalBytes.
		sigPayload := append(canonicalBytes[:len(canonicalBytes):len(canonicalBytes)], prev...)

		hashArr := sha256.Sum256(sigPayload)
		entryHash := hex.EncodeToString(hashArr[:])

		sig, err := signer.Sign(sigPayload)
		if err != nil {
			return nil, fmt.Errorf("chain: signing entry %d: %w", i, err)
		}

		entries[i] = ChainEntry{
			Record:    rec,
			EntryHash: entryHash,
			Signature: base64.StdEncoding.EncodeToString(sig),
			KeyID:     signer.KeyID(),
		}
		prev = hashArr[:]
	}
	return entries, nil
}

// ToLogEntries converts a ChainEntry slice to a LogEntry slice for writing to the log file.
func ToLogEntries(entries []ChainEntry) []LogEntry {
	out := make([]LogEntry, len(entries))
	for i, e := range entries {
		out[i] = LogEntry{
			Record: e.Record,
			Signed: sign.SignedEntry{
				KeyID:     e.KeyID,
				Algorithm: "ed25519",
				EntryHash: e.EntryHash,
				Signature: e.Signature,
			},
		}
	}
	return out
}

// MarshalLogEntry marshals a LogEntry to compact JSON (no trailing newline).
func MarshalLogEntry(e LogEntry) ([]byte, error) {
	return json.Marshal(e)
}

// UnmarshalLogEntry parses a compact JSON line into a LogEntry.
func UnmarshalLogEntry(line []byte) (LogEntry, error) {
	var e LogEntry
	if err := json.Unmarshal(line, &e); err != nil {
		return LogEntry{}, err
	}
	return e, nil
}

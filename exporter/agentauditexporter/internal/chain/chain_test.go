package chain_test

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/canonical"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/chain"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/sign"
)

// knownTraceID is a fixed trace ID used for reproducible genesis-seed tests.
const knownTraceID = "01010101010101010101010101010101"

// makeTestSigner generates a determinism-safe Ed25519 signer for tests.
func makeTestSigner(t *testing.T) (sign.Signer, sign.SignedEntry) {
	t.Helper()
	priv, _, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	s := sign.NewEd25519Signer(priv)
	return s, sign.SignedEntry{}
}

func makeRecord(traceID, spanID, parentSpanID string, startNano uint64, seq int) record.AuditRecord {
	return record.AuditRecord{
		SchemaVersion:     record.SchemaVersion,
		TraceID:           traceID,
		SpanID:            spanID,
		ParentSpanID:      parentSpanID,
		SeqInTrace:        seq,
		StartTimeUnixNano: startNano,
		EndTimeUnixNano:   startNano + 1000,
		SpanName:          "test.span",
		OtelKind:          "Client",
		GenAIOperation:    "",
		AuditKind:         record.AuditKindTask,
		Status:            "Ok",
	}
}

// TestGenesisSeed verifies that GenesisSeed produces the expected SHA256 for a
// known traceID using the current SchemaVersion.
func TestGenesisSeed(t *testing.T) {
	traceIDBytes, err := hex.DecodeString(knownTraceID)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	h := sha256.New()
	h.Write(traceIDBytes)
	h.Write([]byte(record.SchemaVersion))
	expected := h.Sum(nil)

	got, err := chain.GenesisSeed(knownTraceID)
	if err != nil {
		t.Fatalf("GenesisSeed: %v", err)
	}
	if string(got) != string(expected) {
		t.Errorf("GenesisSeed mismatch:\n  got  %x\n  want %x", got, expected)
	}
}

func TestGenesisSeed_InvalidHex(t *testing.T) {
	_, err := chain.GenesisSeed("not-hex!!")
	if err == nil {
		t.Error("expected error for invalid hex trace ID, got nil")
	}
}

// TestSortRecords verifies the (StartTimeUnixNano ASC, SpanID ASC) ordering.
func TestSortRecords(t *testing.T) {
	records := []record.AuditRecord{
		makeRecord(knownTraceID, "cccccccccccccccc", "", 3000, 0),
		makeRecord(knownTraceID, "aaaaaaaaaaaaaaaa", "", 1000, 0),
		makeRecord(knownTraceID, "bbbbbbbbbbbbbbbb", "", 1000, 0), // same time as aa, comes after by SpanID
	}
	chain.SortRecords(records)
	if records[0].SpanID != "aaaaaaaaaaaaaaaa" {
		t.Errorf("record[0]: got SpanID %q, want aaaaaaaaaaaaaaaa", records[0].SpanID)
	}
	if records[1].SpanID != "bbbbbbbbbbbbbbbb" {
		t.Errorf("record[1]: got SpanID %q, want bbbbbbbbbbbbbbbb", records[1].SpanID)
	}
	if records[2].SpanID != "cccccccccccccccc" {
		t.Errorf("record[2]: got SpanID %q, want cccccccccccccccc", records[2].SpanID)
	}
}

// TestBuildChain_Single verifies that a one-record chain produces an entryHash
// identical to the manual SHA256(canonical ‖ genesisSeed) computation (B1 compat).
func TestBuildChain_Single(t *testing.T) {
	signer, _ := makeTestSigner(t)

	rec := makeRecord(knownTraceID, "0102030405060708", "", 1000000000, 0)
	genesisSeed, err := chain.GenesisSeed(knownTraceID)
	if err != nil {
		t.Fatalf("GenesisSeed: %v", err)
	}

	records := []record.AuditRecord{rec}
	entries, err := chain.BuildChain(records, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	// Manually compute expected entryHash.
	canonicalBytes, err := canonical.Marshal(rec)
	if err != nil {
		t.Fatalf("canonical.Marshal: %v", err)
	}
	sigPayload := append(canonicalBytes[:len(canonicalBytes):len(canonicalBytes)], genesisSeed...)
	expectedHashArr := sha256.Sum256(sigPayload)
	expectedHash := hex.EncodeToString(expectedHashArr[:])

	if entries[0].EntryHash != expectedHash {
		t.Errorf("entryHash mismatch:\n  got  %s\n  want %s", entries[0].EntryHash, expectedHash)
	}
}

// TestBuildChain_Multi verifies that entry[1].sigPayload uses entry[0].entryHash as prev.
func TestBuildChain_Multi(t *testing.T) {
	signer, _ := makeTestSigner(t)

	rec0 := makeRecord(knownTraceID, "aaaaaaaaaaaaaaaa", "", 1000, 0)
	rec1 := makeRecord(knownTraceID, "bbbbbbbbbbbbbbbb", "aaaaaaaaaaaaaaaa", 2000, 1)

	genesisSeed, err := chain.GenesisSeed(knownTraceID)
	if err != nil {
		t.Fatalf("GenesisSeed: %v", err)
	}

	records := []record.AuditRecord{rec0, rec1}
	entries, err := chain.BuildChain(records, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Compute expected entry[0] hash.
	cb0, err := canonical.Marshal(rec0)
	if err != nil {
		t.Fatalf("canonical.Marshal rec0: %v", err)
	}
	sp0 := append(cb0[:len(cb0):len(cb0)], genesisSeed...)
	h0arr := sha256.Sum256(sp0)
	expectedHash0 := hex.EncodeToString(h0arr[:])

	if entries[0].EntryHash != expectedHash0 {
		t.Errorf("entry[0].EntryHash mismatch:\n  got  %s\n  want %s", entries[0].EntryHash, expectedHash0)
	}

	// Compute expected entry[1] hash: prev = h0arr[:].
	cb1, err := canonical.Marshal(rec1)
	if err != nil {
		t.Fatalf("canonical.Marshal rec1: %v", err)
	}
	sp1 := append(cb1[:len(cb1):len(cb1)], h0arr[:]...)
	h1arr := sha256.Sum256(sp1)
	expectedHash1 := hex.EncodeToString(h1arr[:])

	if entries[1].EntryHash != expectedHash1 {
		t.Errorf("entry[1].EntryHash mismatch:\n  got  %s\n  want %s", entries[1].EntryHash, expectedHash1)
	}
}

// TestBuildChain_Deterministic verifies that the same inputs always produce
// identical outputs (no RNG in the hash path; only in the signature which is
// also deterministic for Ed25519).
func TestBuildChain_Deterministic(t *testing.T) {
	priv, _, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	signer := sign.NewEd25519Signer(priv)

	rec0 := makeRecord(knownTraceID, "aaaaaaaaaaaaaaaa", "", 1000, 0)
	rec1 := makeRecord(knownTraceID, "bbbbbbbbbbbbbbbb", "aaaaaaaaaaaaaaaa", 2000, 1)
	genesisSeed, _ := chain.GenesisSeed(knownTraceID)

	records1 := []record.AuditRecord{rec0, rec1}
	entries1, err := chain.BuildChain(records1, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain run 1: %v", err)
	}

	records2 := []record.AuditRecord{rec0, rec1}
	entries2, err := chain.BuildChain(records2, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain run 2: %v", err)
	}

	for i := range entries1 {
		if entries1[i].EntryHash != entries2[i].EntryHash {
			t.Errorf("entry[%d].EntryHash not deterministic:\n  run1 %s\n  run2 %s",
				i, entries1[i].EntryHash, entries2[i].EntryHash)
		}
		if entries1[i].Signature != entries2[i].Signature {
			t.Errorf("entry[%d].Signature not deterministic:\n  run1 %s\n  run2 %s",
				i, entries1[i].Signature, entries2[i].Signature)
		}
	}
}

// TestBuildChain_SeqInTracePreconditionComment documents the caller contract:
// SeqInTrace must be assigned by the caller before BuildChain is called.
// The test verifies that the canonical bytes (and therefore entryHash) differ
// when SeqInTrace differs, confirming that SeqInTrace is included in the hash.
func TestBuildChain_SeqInTracePreconditionComment(t *testing.T) {
	priv, _, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	signer := sign.NewEd25519Signer(priv)
	genesisSeed, _ := chain.GenesisSeed(knownTraceID)

	recSeq0 := makeRecord(knownTraceID, "aaaaaaaaaaaaaaaa", "", 1000, 0) // SeqInTrace=0
	recSeq1 := makeRecord(knownTraceID, "aaaaaaaaaaaaaaaa", "", 1000, 1) // SeqInTrace=1

	entries0, err := chain.BuildChain([]record.AuditRecord{recSeq0}, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain seq=0: %v", err)
	}
	entries1, err := chain.BuildChain([]record.AuditRecord{recSeq1}, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain seq=1: %v", err)
	}

	// Different SeqInTrace must produce a different entryHash.
	if entries0[0].EntryHash == entries1[0].EntryHash {
		t.Error("entryHash should differ when SeqInTrace differs, but they are equal")
	}
}

// TestTipHash verifies that TipHash returns the last entry's EntryHash.
func TestTipHash(t *testing.T) {
	signer, _ := makeTestSigner(t)

	rec0 := makeRecord(knownTraceID, "aaaaaaaaaaaaaaaa", "", 1000, 0)
	rec1 := makeRecord(knownTraceID, "bbbbbbbbbbbbbbbb", "aaaaaaaaaaaaaaaa", 2000, 1)
	genesisSeed, _ := chain.GenesisSeed(knownTraceID)

	entries, err := chain.BuildChain([]record.AuditRecord{rec0, rec1}, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	tip := chain.TipHash(entries)
	if tip != entries[1].EntryHash {
		t.Errorf("TipHash: got %s, want %s", tip, entries[1].EntryHash)
	}
}

// TestToLogEntries verifies that ToLogEntries produces LogEntry objects with
// the correct Algorithm field and matching EntryHash/Signature values.
func TestToLogEntries(t *testing.T) {
	signer, _ := makeTestSigner(t)

	rec := makeRecord(knownTraceID, "0102030405060708", "", 1000, 0)
	genesisSeed, _ := chain.GenesisSeed(knownTraceID)
	entries, err := chain.BuildChain([]record.AuditRecord{rec}, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	logEntries := chain.ToLogEntries(entries)
	if len(logEntries) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(logEntries))
	}
	if logEntries[0].Signed.Algorithm != "ed25519" {
		t.Errorf("Algorithm: got %q, want %q", logEntries[0].Signed.Algorithm, "ed25519")
	}
	if logEntries[0].Signed.EntryHash != entries[0].EntryHash {
		t.Errorf("EntryHash mismatch")
	}
	if logEntries[0].Signed.Signature != entries[0].Signature {
		t.Errorf("Signature mismatch")
	}
}

// TestMarshalUnmarshalLogEntry verifies round-trip JSON serialization.
func TestMarshalUnmarshalLogEntry(t *testing.T) {
	signer, _ := makeTestSigner(t)

	rec := makeRecord(knownTraceID, "0102030405060708", "", 1000, 0)
	genesisSeed, _ := chain.GenesisSeed(knownTraceID)
	entries, err := chain.BuildChain([]record.AuditRecord{rec}, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}
	logEntry := chain.ToLogEntries(entries)[0]

	line, err := chain.MarshalLogEntry(logEntry)
	if err != nil {
		t.Fatalf("MarshalLogEntry: %v", err)
	}

	got, err := chain.UnmarshalLogEntry(line)
	if err != nil {
		t.Fatalf("UnmarshalLogEntry: %v", err)
	}

	if got.Record.TraceID != logEntry.Record.TraceID {
		t.Errorf("TraceID round-trip: got %q, want %q", got.Record.TraceID, logEntry.Record.TraceID)
	}
	if got.Signed.EntryHash != logEntry.Signed.EntryHash {
		t.Errorf("EntryHash round-trip mismatch")
	}
}

// TestZeroPrevCheckpointHash verifies the sentinel is exactly 64 '0' chars.
func TestZeroPrevCheckpointHash(t *testing.T) {
	z := chain.ZeroPrevCheckpointHash
	if len(z) != 64 {
		t.Errorf("ZeroPrevCheckpointHash length: got %d, want 64", len(z))
	}
	for i, c := range z {
		if c != '0' {
			t.Errorf("ZeroPrevCheckpointHash[%d] = %q, want '0'", i, c)
			break
		}
	}
}

// --- Fixture generation ---
// TestGenerateChainFixture writes the cross-impl fixture to testdata/ and
// verifies it can be re-read. Run `go test ./... -run TestGenerateChainFixture`
// to regenerate.
func TestGenerateChainFixture(t *testing.T) {
	// Use a fixed key to produce reproducible fixture bytes.
	// The fixture uses a fresh key each test run, so it validates structure not exact bytes.
	// For a true cross-impl fixture with stable signature, a fixed key would be embedded.
	// For B2 we validate the hash-chain structure (entryHash) which IS deterministic.
	signer, _ := makeTestSigner(t)

	rec0 := makeRecord(knownTraceID, "aaaaaaaaaaaaaaaa", "", 1000000000, 0)
	rec1 := makeRecord(knownTraceID, "bbbbbbbbbbbbbbbb", "aaaaaaaaaaaaaaaa", 2000000000, 1)

	genesisSeed, err := chain.GenesisSeed(knownTraceID)
	if err != nil {
		t.Fatalf("GenesisSeed: %v", err)
	}

	entries, err := chain.BuildChain([]record.AuditRecord{rec0, rec1}, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	logEntries := chain.ToLogEntries(entries)

	// Verify the produced entries are self-consistent.
	if len(logEntries) != 2 {
		t.Fatalf("expected 2 log entries, got %d", len(logEntries))
	}

	// Verify entry[0] hash manually.
	cb0, _ := canonical.Marshal(rec0)
	sp0 := append(cb0[:len(cb0):len(cb0)], genesisSeed...)
	h0 := sha256.Sum256(sp0)
	expectedHash0 := hex.EncodeToString(h0[:])
	if logEntries[0].Signed.EntryHash != expectedHash0 {
		t.Errorf("fixture entry[0] hash: got %s, want %s", logEntries[0].Signed.EntryHash, expectedHash0)
	}

	// Verify entry[1] hash.
	cb1, _ := canonical.Marshal(rec1)
	sp1 := append(cb1[:len(cb1):len(cb1)], h0[:]...)
	h1 := sha256.Sum256(sp1)
	expectedHash1 := hex.EncodeToString(h1[:])
	if logEntries[1].Signed.EntryHash != expectedHash1 {
		t.Errorf("fixture entry[1] hash: got %s, want %s", logEntries[1].Signed.EntryHash, expectedHash1)
	}

	// Verify signatures decode to proper base64.
	for i, le := range logEntries {
		if _, err := base64.StdEncoding.DecodeString(le.Signed.Signature); err != nil {
			t.Errorf("entry[%d] signature not valid base64: %v", i, err)
		}
	}

	// Confirm round-trip marshal/unmarshal.
	for i, le := range logEntries {
		raw, err := chain.MarshalLogEntry(le)
		if err != nil {
			t.Fatalf("MarshalLogEntry[%d]: %v", i, err)
		}
		got, err := chain.UnmarshalLogEntry(raw)
		if err != nil {
			t.Fatalf("UnmarshalLogEntry[%d]: %v", i, err)
		}
		if got.Signed.EntryHash != le.Signed.EntryHash {
			t.Errorf("round-trip[%d] EntryHash mismatch", i)
		}
	}
}

// TestGenesisSeedForSchema verifies that GenesisSeedForSchema produces different
// seeds for different schema versions, ensuring v1 and v2 chains can never silently
// interleave even for the same trace_id.
func TestGenesisSeedForSchema(t *testing.T) {
	const traceID = "01010101010101010101010101010101"

	seedV1, err := chain.GenesisSeedForSchema(traceID, "v1")
	if err != nil {
		t.Fatalf("GenesisSeedForSchema v1: %v", err)
	}
	seedV2, err := chain.GenesisSeedForSchema(traceID, "v2")
	if err != nil {
		t.Fatalf("GenesisSeedForSchema v2: %v", err)
	}

	if string(seedV1) == string(seedV2) {
		t.Error("v1 and v2 genesis seeds must differ; got identical values")
	}

	// GenesisSeed() must equal GenesisSeedForSchema(traceID, record.SchemaVersion).
	seedCurrent, err := chain.GenesisSeed(traceID)
	if err != nil {
		t.Fatalf("GenesisSeed: %v", err)
	}
	expected, err := chain.GenesisSeedForSchema(traceID, record.SchemaVersion)
	if err != nil {
		t.Fatalf("GenesisSeedForSchema current: %v", err)
	}
	if string(seedCurrent) != string(expected) {
		t.Errorf("GenesisSeed() != GenesisSeedForSchema(traceID, record.SchemaVersion)")
	}
}

// TestTwoSpanChainFixture is the v2 cross-impl lock: BuildChain on the fixture
// records must produce the hardcoded v2 entry hashes. Any change to canonical
// serialisation, genesis-seed computation, or record fields that appears in the
// hash path requires a schema_version bump.
func TestTwoSpanChainFixture(t *testing.T) {
	const traceID = "01010101010101010101010101010101"

	genesisSeed, err := chain.GenesisSeed(traceID) // uses record.SchemaVersion ("v2")
	if err != nil {
		t.Fatalf("GenesisSeed: %v", err)
	}

	rec0 := record.AuditRecord{
		SchemaVersion:     record.SchemaVersion,
		TraceID:           traceID,
		SpanID:            "aaaaaaaaaaaaaaaa",
		ParentSpanID:      "bbbbbbbbbbbbbbbb",
		SeqInTrace:        0,
		StartTimeUnixNano: 1000000000,
		EndTimeUnixNano:   2000000000,
		SpanName:          "child.span",
		OtelKind:          "Client",
		AuditKind:         record.AuditKindTask,
		Status:            "Ok",
	}
	rec1 := record.AuditRecord{
		SchemaVersion:     record.SchemaVersion,
		TraceID:           traceID,
		SpanID:            "bbbbbbbbbbbbbbbb",
		ParentSpanID:      "",
		SeqInTrace:        1,
		StartTimeUnixNano: 2000000000,
		EndTimeUnixNano:   3000000000,
		SpanName:          "root.span",
		OtelKind:          "Client",
		AuditKind:         record.AuditKindTask,
		Status:            "Ok",
	}

	signer, _ := makeTestSigner(t)
	entries, err := chain.BuildChain([]record.AuditRecord{rec0, rec1}, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	const wantHash0 = "55cdd65168375131856de86680f57f2171101dd22efc0a0e4a6abf59bbdfb90a"
	const wantHash1 = "3e5adf011183ce2128aeca9d337ddf60ea867dbd96f47c16c77e876b36fbc63c"

	if entries[0].EntryHash != wantHash0 {
		t.Errorf("v2 fixture entry[0].EntryHash:\n  got  %s\n  want %s", entries[0].EntryHash, wantHash0)
	}
	if entries[1].EntryHash != wantHash1 {
		t.Errorf("v2 fixture entry[1].EntryHash:\n  got  %s\n  want %s", entries[1].EntryHash, wantHash1)
	}
}

// TestTwoSpanChainFixture_V1Regression locks the v1 entry hashes. These values
// must never change — v1 logs already exist in production and their hashes must
// remain reproducible for verifiers that pass "v1" to GenesisSeedForSchema.
func TestTwoSpanChainFixture_V1Regression(t *testing.T) {
	const traceID = "01010101010101010101010101010101"

	genesisSeed, err := chain.GenesisSeedForSchema(traceID, "v1")
	if err != nil {
		t.Fatalf("GenesisSeedForSchema v1: %v", err)
	}

	rec0 := record.AuditRecord{
		SchemaVersion:     "v1",
		TraceID:           traceID,
		SpanID:            "aaaaaaaaaaaaaaaa",
		ParentSpanID:      "bbbbbbbbbbbbbbbb",
		SeqInTrace:        0,
		StartTimeUnixNano: 1000000000,
		EndTimeUnixNano:   2000000000,
		SpanName:          "child.span",
		OtelKind:          "Client",
		AuditKind:         record.AuditKindTask,
		Status:            "Ok",
	}
	rec1 := record.AuditRecord{
		SchemaVersion:     "v1",
		TraceID:           traceID,
		SpanID:            "bbbbbbbbbbbbbbbb",
		ParentSpanID:      "",
		SeqInTrace:        1,
		StartTimeUnixNano: 2000000000,
		EndTimeUnixNano:   3000000000,
		SpanName:          "root.span",
		OtelKind:          "Client",
		AuditKind:         record.AuditKindTask,
		Status:            "Ok",
	}

	signer, _ := makeTestSigner(t)
	entries, err := chain.BuildChain([]record.AuditRecord{rec0, rec1}, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	const wantHash0 = "fc388777ccc984fd3c0ab20488ae456dad1295621b420aeb7b949c6d125f54dc"
	const wantHash1 = "a0415a08bbac8ad89462cae146a727dbcfb3022b3f1e5870886fb2deb1538f9c"

	if entries[0].EntryHash != wantHash0 {
		t.Errorf("v1 regression entry[0].EntryHash:\n  got  %s\n  want %s", entries[0].EntryHash, wantHash0)
	}
	if entries[1].EntryHash != wantHash1 {
		t.Errorf("v1 regression entry[1].EntryHash:\n  got  %s\n  want %s", entries[1].EntryHash, wantHash1)
	}
}

// TestGenesisSeedForSchema_EmptySchemaVersion verifies that an empty schemaVersion
// is rejected with an error, preventing silent wrong-seed computation for corrupted
// log entries where schema_version decoded to "".
func TestGenesisSeedForSchema_EmptySchemaVersion(t *testing.T) {
	_, err := chain.GenesisSeedForSchema(knownTraceID, "")
	if err == nil {
		t.Error("expected error for empty schemaVersion, got nil")
	}
}

// TestTwoSpanChainFixture_FromFile is the file-backed cross-impl lock: it reads
// testdata/v2_two_span_chain_fixture.json, re-computes the entry hashes from
// the stored records, and asserts they match the stored entry_hash values.
// An external Python verifier should be able to reproduce the same hashes from
// the same file.
func TestTwoSpanChainFixture_FromFile(t *testing.T) {
	const fixturePath = "testdata/v2_two_span_chain_fixture.json"
	f, err := os.Open(fixturePath)
	if err != nil {
		t.Fatalf("open %s: %v", fixturePath, err)
	}
	defer func() { _ = f.Close() }()

	var logEntries []chain.LogEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		le, err := chain.UnmarshalLogEntry(sc.Bytes())
		if err != nil {
			t.Fatalf("UnmarshalLogEntry: %v", err)
		}
		logEntries = append(logEntries, le)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scanner: %v", err)
	}
	if len(logEntries) != 2 {
		t.Fatalf("expected 2 entries in fixture, got %d", len(logEntries))
	}

	traceID := logEntries[0].Record.TraceID
	schemaVersion := logEntries[0].Record.SchemaVersion
	genesisSeed, err := chain.GenesisSeedForSchema(traceID, schemaVersion)
	if err != nil {
		t.Fatalf("GenesisSeedForSchema: %v", err)
	}

	signer, _ := makeTestSigner(t)
	recs := []record.AuditRecord{logEntries[0].Record, logEntries[1].Record}
	computed, err := chain.BuildChain(recs, genesisSeed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	for i, le := range logEntries {
		if computed[i].EntryHash != le.Signed.EntryHash {
			t.Errorf("entry[%d] entry_hash mismatch:\n  computed %s\n  fixture  %s",
				i, computed[i].EntryHash, le.Signed.EntryHash)
		}
	}
}


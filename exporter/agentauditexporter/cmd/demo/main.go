// Command demo generates a self-contained offline audit log fixture and verifies
// it end-to-end using the same engine as the production otel-agent-audit-verify CLI.
//
// Usage (from the repo root):
//
//	make demo
//
// Or directly:
//
//	cd exporter/agentauditexporter && go run ./cmd/demo
//
// No Collector, LLM key, or network connection is required. The demo:
//  1. Generates an Ed25519 key pair in a temporary directory.
//  2. Builds a 3-span agent-trace (two tool calls + root chat span).
//  3. Chains and signs all entries deterministically.
//  4. Writes audit.jsonl and checkpoint.jsonl.
//  5. Runs the verifier and prints a human-readable report.
//  6. Exits 0 on success, 1 on verification failure.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/chain"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/sign"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/verify"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "demo: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	dir, err := os.MkdirTemp("", "otel-agent-audit-demo-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// Step 1: generate an Ed25519 key pair.
	privKey, pubKey, err := sign.GenerateEd25519Key()
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}
	signer := sign.NewEd25519Signer(privKey)
	fmt.Printf("Signing key fingerprint (key_id): %s\n\n", signer.KeyID())

	// Step 2: build a 3-span trace — two tool calls + a root chat span.
	// Spans are sorted by (start_time_unix_nano, span_id) before chaining,
	// which is the same deterministic order the exporter uses at seal time.
	const traceID = "aabbccddeeff00112233445566778899"

	recs := []record.AuditRecord{
		{
			SchemaVersion:     record.SchemaVersion,
			TraceID:           traceID,
			SpanID:            "0102030405060708",
			ParentSpanID:      "0a0b0c0d0e0f0102",
			StartTimeUnixNano: 1_000_000_000,
			EndTimeUnixNano:   2_000_000_000,
			SpanName:          "tool.web_search",
			OtelKind:          "Client",
			GenAIOperation:    "execute_tool",
			AuditKind:         record.AuditKindTool,
			SelectedAttributes: []record.AttributeEntry{
				{Key: "gen_ai.operation.name", Value: "execute_tool"},
				{Key: "gen_ai.system", Value: "anthropic"},
			},
			Status: "Ok",
		},
		{
			SchemaVersion:     record.SchemaVersion,
			TraceID:           traceID,
			SpanID:            "0203040506070809",
			ParentSpanID:      "0a0b0c0d0e0f0102",
			StartTimeUnixNano: 2_000_000_000,
			EndTimeUnixNano:   3_000_000_000,
			SpanName:          "tool.read_file",
			OtelKind:          "Client",
			GenAIOperation:    "execute_tool",
			AuditKind:         record.AuditKindTool,
			SelectedAttributes: []record.AttributeEntry{
				{Key: "gen_ai.operation.name", Value: "execute_tool"},
				{Key: "gen_ai.system", Value: "anthropic"},
			},
			Status: "Ok",
		},
		{
			SchemaVersion:     record.SchemaVersion,
			TraceID:           traceID,
			SpanID:            "0a0b0c0d0e0f0102",
			ParentSpanID:      "",
			StartTimeUnixNano: 500_000_000,
			EndTimeUnixNano:   3_500_000_000,
			SpanName:          "gen_ai.chat",
			OtelKind:          "Client",
			GenAIOperation:    "chat",
			AuditKind:         record.AuditKindTask,
			SelectedAttributes: []record.AttributeEntry{
				{Key: "gen_ai.operation.name", Value: "chat"},
				{Key: "gen_ai.request.model", Value: "claude-sonnet-4-6"},
				{Key: "gen_ai.response.model", Value: "claude-sonnet-4-6"},
				{Key: "gen_ai.system", Value: "anthropic"},
				{Key: "gen_ai.usage.input_tokens", Value: "512"},
				{Key: "gen_ai.usage.output_tokens", Value: "128"},
			},
			Status: "Ok",
		},
	}

	// Deterministic sort + SeqInTrace assignment (mirrors exporter's sealTrace).
	chain.SortRecords(recs)
	for i := range recs {
		recs[i].SeqInTrace = i
	}

	genesisSeed, err := chain.GenesisSeed(traceID)
	if err != nil {
		return fmt.Errorf("genesis seed: %w", err)
	}
	entries, err := chain.BuildChain(recs, genesisSeed, signer)
	if err != nil {
		return fmt.Errorf("build chain: %w", err)
	}
	fmt.Printf("Built chain: %d entries\n", len(entries))
	fmt.Printf("Tip hash:    %s\n\n", chain.TipHash(entries))

	// Step 3: write audit.jsonl.
	logPath := filepath.Join(dir, "audit.jsonl")
	lf, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("create log: %w", err)
	}
	for _, le := range chain.ToLogEntries(entries) {
		line, _ := json.Marshal(le)
		_, _ = lf.Write(append(line, '\n'))
	}
	_ = lf.Close()
	fmt.Printf("Wrote %s\n", logPath)

	// Write checkpoint.jsonl.
	checkpointPath := filepath.Join(dir, "checkpoint.jsonl")
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)
	acc.AddTip(traceID, chain.TipHash(entries), len(entries))
	// Stage -> persist -> Commit: the accumulator's state only advances once the
	// checkpoint is durably on disk. The demo writes a single checkpoint and then
	// discards the accumulator, so Build would work here too, but this is the
	// pattern exporters must follow and the demo is exemplar code.
	staged, err := acc.Stage(time.Now())
	if err != nil {
		return fmt.Errorf("stage checkpoint: %w", err)
	}
	cf, err := os.Create(checkpointPath)
	if err != nil {
		return fmt.Errorf("create checkpoint: %w", err)
	}
	cpLine, err := json.Marshal(staged.Checkpoint)
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}
	if _, err := cf.Write(append(cpLine, '\n')); err != nil {
		_ = cf.Close()
		return fmt.Errorf("write checkpoint: %w", err)
	}
	if err := cf.Sync(); err != nil {
		_ = cf.Close()
		return fmt.Errorf("sync checkpoint: %w", err)
	}
	if err := cf.Close(); err != nil {
		return fmt.Errorf("close checkpoint: %w", err)
	}
	if err := acc.Commit(staged); err != nil {
		return fmt.Errorf("commit checkpoint: %w", err)
	}
	fmt.Printf("Wrote %s\n\n", checkpointPath)

	// Step 4: verify.
	fmt.Println("Running verifier...")
	report, err := verify.VerifyLog(logPath, checkpointPath, ed25519.PublicKey(pubKey))
	if err != nil {
		return fmt.Errorf("verifier: %w", err)
	}

	fmt.Printf("Traces processed:      %d\n", report.TracesProcessed)
	fmt.Printf("Checkpoints processed: %d\n", report.CheckpointsProcessed)
	if len(report.Errors) == 0 {
		fmt.Println("Status: OK")
		return nil
	}

	fmt.Printf("Status: FAILED (%d error(s))\n", len(report.Errors))
	for _, e := range report.Errors {
		fmt.Printf("  [%s] %s: %s\n", e.TraceID, e.Kind, e.Detail)
	}
	return fmt.Errorf("verification failed")
}

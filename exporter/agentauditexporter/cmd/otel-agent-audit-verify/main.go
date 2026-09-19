// otel-agent-audit-verify verifies an audit log produced by agentauditexporter.
//
// Usage:
//
//	otel-agent-audit-verify [-key <hex>] [-key-file <pem>] [-json] <log-file> <checkpoint-file>
//
// Flags:
//
//	-key       hex-encoded Ed25519 public key (64 hex chars = 32 bytes)
//	-key-file  path to PEM file with "PUBLIC KEY" block (PKIX/SubjectPublicKeyInfo)
//	-json      emit results as JSON instead of human-readable text
//
// Exactly one of -key or -key-file is required. Using both is an error.
//
// Exit codes:
//
//	0  all checks pass, or only advisory findings were reported
//	1  one or more fatal verification failures were reported
//	2  usage error, I/O error, or key parse error
//
// "Fatal" and "advisory" are verify.VerifyError.Severity: a fatal finding
// (e.g. chain, checkpoint, tip_hash_mismatch) means verification failed or
// could not be completed; an advisory finding (key_id_field_mismatch,
// torn_trailing_line) means the flagged entries were still fully verified
// despite the finding. Advisory findings are always printed but never
// affect the exit code or the Status line — see docs/verification.md.
//
// Separately, when the log's entries or checkpoints claim key_ids other than
// the supplied key's, the human-readable output ends with an informational
// "Note:" listing them, and -json carries them as OtherClaimedKeyIDs (issue
// #50). That is a hint, not a finding: it never affects the exit code or the
// Status line either.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/sign"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/verify"
)

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("otel-agent-audit-verify", flag.ContinueOnError)
	keyHex := fs.String("key", "", "hex-encoded Ed25519 public key (64 hex chars)")
	keyFile := fs.String("key-file", "", "path to PEM file with PUBLIC KEY block")
	jsonOut := fs.Bool("json", false, "emit results as JSON")

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if fs.NArg() != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <log-file> <checkpoint-file>\n", fs.Name())
		fs.PrintDefaults()
		return 2
	}
	if *keyHex == "" && *keyFile == "" {
		fmt.Fprintln(os.Stderr, "error: one of -key or -key-file is required")
		return 2
	}
	if *keyHex != "" && *keyFile != "" {
		fmt.Fprintln(os.Stderr, "error: -key and -key-file are mutually exclusive")
		return 2
	}

	logPath := fs.Arg(0)
	checkpointPath := fs.Arg(1)

	pubKey, err := loadPublicKey(*keyHex, *keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	report, err := verify.VerifyLog(logPath, checkpointPath, pubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	fatal := report.FatalCount()

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing JSON output: %v\n", err)
			return 2
		}
	} else {
		fmt.Print(formatReport(report))
	}

	if fatal > 0 {
		return 1
	}
	return 0
}

// formatReport renders the human-readable (non-JSON) report. The trailing
// "Note:" block appears only when the log claims key_ids other than the
// supplied key's (issue #50); it is a hint, never a finding, and does not
// affect the Status line or the exit code.
func formatReport(report verify.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Traces processed:      %d\n", report.TracesProcessed)
	fmt.Fprintf(&b, "Checkpoints processed: %d\n", report.CheckpointsProcessed)
	fmt.Fprintln(&b, report.StatusLine())
	for _, e := range report.Errors {
		fmt.Fprintf(&b, "  [%s] %s (%s): %s\n", errorLabel(e), e.Kind, e.Severity, e.Detail)
	}
	if n := len(report.OtherClaimedKeyIDs); n > 0 {
		fmt.Fprintf(&b, "Note: the log claims %d key_id(s) other than the supplied key's:\n", n)
		for _, id := range report.OtherClaimedKeyIDs {
			fmt.Fprintf(&b, "  %s\n", id)
		}
		fmt.Fprintln(&b, "  That may be a key rotation (re-run with the other epoch's key against the full, unsplit files), a wrong key, or an edited key_id.")
		fmt.Fprintln(&b, "  Informational only: entry key_ids are unauthenticated, and this never affects Status or the exit code. See \"Multi-epoch logs\" in docs/verification.md.")
	}
	return b.String()
}

// errorLabel returns the "[...]" prefix for one report line: the trace ID
// when the error is trace-scoped, or which file it came from otherwise. An
// empty TraceID alone does not imply a checkpoint-level error — the log-level
// torn_trailing_line finding also has no TraceID — so this checks Kind
// explicitly instead of assuming.
func errorLabel(e verify.VerifyError) string {
	switch {
	case e.TraceID != "":
		return e.TraceID
	case e.Kind == verify.KindTornTrailingLine:
		return "audit log"
	default:
		return "checkpoint"
	}
}

func loadPublicKey(hexKey, pemFile string) (ed25519.PublicKey, error) {
	if hexKey != "" {
		raw, err := hex.DecodeString(hexKey)
		if err != nil {
			return nil, fmt.Errorf("decoding -key hex: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("-key must be %d bytes (%d hex chars); got %d bytes",
				ed25519.PublicKeySize, ed25519.PublicKeySize*2, len(raw))
		}
		return ed25519.PublicKey(raw), nil
	}
	return sign.LoadEd25519PublicKeyPEM(pemFile)
}

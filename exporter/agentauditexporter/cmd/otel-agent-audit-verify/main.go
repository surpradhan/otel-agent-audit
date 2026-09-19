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
// "Note:" listing them (quoted, escaped and bounded: they are untrusted text),
// and -json carries them all as OtherClaimedKeyIDs (issue #50). That is a hint,
// not a finding: it never affects the exit code or the Status line either.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"unicode/utf8"

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
		writeReport(os.Stdout, report)
	}

	if fatal > 0 {
		return 1
	}
	return 0
}

// Limits on what the Note shows of the claimed key_ids. A real key_id is 64 hex
// characters, so these are generous for an honest log and bound what a log full
// of odd claims can make the terminal print. -json always lists every id.
const (
	maxNoteIDs     = 10
	maxNoteIDBytes = 128
)

// writeReport writes the human-readable (non-JSON) report to w as it goes, so a
// report with a great many findings is never held in memory a second time. The
// trailing "Note:" block appears only when the log claims key_ids other than
// the supplied key's (issue #50); it is a hint, never a finding, and does not
// affect the Status line or the exit code. Only its wording depends on whether
// anything failed: advice to try another epoch's key makes sense only next to
// findings, and even then must not read as explaining them away or promise a
// clean result that no single run can give.
func writeReport(w io.Writer, report verify.Report) {
	p := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	p("Traces processed:      %d\n", report.TracesProcessed)
	p("Checkpoints processed: %d\n", report.CheckpointsProcessed)
	p("%s\n", report.StatusLine())
	for _, e := range report.Errors {
		p("  [%s] %s (%s): %s\n", errorLabel(e), e.Kind, e.Severity, e.Detail)
	}

	n := len(report.OtherClaimedKeyIDs)
	if n == 0 {
		return
	}
	p("Note: the log claims %d key_id(s) other than the supplied key's:\n", n)
	shown := report.OtherClaimedKeyIDs
	if len(shown) > maxNoteIDs {
		shown = shown[:maxNoteIDs]
	}
	for _, id := range shown {
		p("  %s\n", quoteUntrusted(id, maxNoteIDBytes))
	}
	if more := n - len(shown); more > 0 {
		p("  ... and %d more not shown (-json lists them all)\n", more)
	}
	p("  These are unverified claims: an entry's key_id sits outside its signature, and a checkpoint that failed verification against the supplied key is only a claim too.\n")
	if report.FatalCount() > 0 {
		p("  This does not explain or excuse the findings above. Only if you know a key rotation happened, verify again with the other epoch's key (obtained independently of this log) against the same full, unsplit files.\n")
		p("  Each such run still reports the other epoch's entries and checkpoints as failures; a single run that reconciles both epochs is not implemented yet.\n")
	} else {
		p("  All entries and checkpoints that could be read verified against the supplied key; these claims concern key_id metadata only.\n")
	}
	p("  Informational only: this never affects Status or the exit code. See \"Multi-epoch logs\" in docs/verification.md.\n")
}

// quoteUntrusted renders s as a double-quoted, ASCII-only Go string literal, so
// text read from the log can neither forge output lines nor drive the terminal
// nor pass for the tool's own wording: the quotes delimit it, and a quote inside
// it is escaped. A key_id in its normal form, 64 lowercase hex characters, comes
// out as those characters inside the quotes, unchanged. If s is longer than
// maxBytes only a prefix, cut on a rune boundary, is shown, followed by the
// number of bytes left out; that note sits outside the quotes, so it is the tool
// speaking.
func quoteUntrusted(s string, maxBytes int) string {
	omitted := 0
	if len(s) > maxBytes {
		cut := maxBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		if cut == 0 {
			cut = maxBytes
		}
		s, omitted = s[:cut], len(s)-cut
	}
	q := strconv.QuoteToASCII(s)
	if omitted > 0 {
		q += fmt.Sprintf(" [truncated: %d more byte(s)]", omitted)
	}
	return q
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

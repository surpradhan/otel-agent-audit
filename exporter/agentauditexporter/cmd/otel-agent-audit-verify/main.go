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
//	0  all checks pass
//	1  one or more verification failures (chain or checkpoint)
//	2  usage error, I/O error, or key parse error
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/sign"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/verify"
)

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("otel-agent-audit-verify", flag.ContinueOnError)
	keyHex  := fs.String("key",      "", "hex-encoded Ed25519 public key (64 hex chars)")
	keyFile := fs.String("key-file", "", "path to PEM file with PUBLIC KEY block")
	jsonOut := fs.Bool("json",       false, "emit results as JSON")

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

	logPath        := fs.Arg(0)
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

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		fmt.Printf("Traces processed:      %d\n", report.TracesProcessed)
		fmt.Printf("Checkpoints processed: %d\n", report.CheckpointsProcessed)
		if len(report.Errors) == 0 {
			fmt.Println("Status: OK")
		} else {
			fmt.Printf("Status: FAILED (%d error(s))\n", len(report.Errors))
			for _, e := range report.Errors {
				if e.TraceID != "" {
					fmt.Printf("  [%s] %s: %s\n", e.TraceID, e.Kind, e.Detail)
				} else {
					fmt.Printf("  [checkpoint] %s: %s\n", e.Kind, e.Detail)
				}
			}
		}
	}

	if len(report.Errors) > 0 {
		return 1
	}
	return 0
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

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/chain"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/sign"
	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/verify"
)

// renderReport runs writeReport into a string, for assertions.
func renderReport(report verify.Report) string {
	var b strings.Builder
	writeReport(&b, report)
	return b.String()
}

// noteBody returns the lines of the Note block between its header and the tool's
// own fixed "These are unverified claims" line: the listed ids, and any marker
// saying how many were left out.
func noteBody(t *testing.T, out string) []string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	start := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "Note:") })
	if start < 0 {
		t.Fatalf("no Note in the output:\n%s", out)
	}
	var body []string
	for _, l := range lines[start+1:] {
		if strings.HasPrefix(l, "  These are unverified claims") {
			return body
		}
		body = append(body, l)
	}
	t.Fatalf("the Note has no fixed caveat line:\n%s", out)
	return nil
}

// TestWriteReport_LayoutWithoutOtherClaimedKeyIDs pins the human-readable
// layout byte for byte when there is nothing to hint at, so a report for an
// ordinary log reads exactly as it did before issue #50 added the Note block.
func TestWriteReport_LayoutWithoutOtherClaimedKeyIDs(t *testing.T) {
	report := verify.Report{
		TracesProcessed:      2,
		CheckpointsProcessed: 1,
		Errors: []verify.VerifyError{
			{TraceID: "abc123", Kind: "chain", Detail: "seq 0: signature verification failed", Severity: verify.SeverityFatal},
			{Kind: verify.KindTornTrailingLine, Detail: "line 3: unparseable", Severity: verify.SeverityAdvisory},
		},
	}
	want := "Traces processed:      2\n" +
		"Checkpoints processed: 1\n" +
		"Status: FAILED (1 fatal, 1 advisory)\n" +
		"  [abc123] chain (fatal): seq 0: signature verification failed\n" +
		"  [audit log] torn_trailing_line (advisory): line 3: unparseable\n"
	if got := renderReport(report); got != want {
		t.Errorf("writeReport mismatch\n got: %q\nwant: %q", got, want)
	}
}

// TestWriteReport_NoteFollowsTheFindings pins where the Note block goes and
// what it says when something failed: after the per-finding lines, one quoted
// ID per line, with the Status line above it untouched, and with advice that is
// explicit that it does not excuse the findings and that no single run can
// reconcile both epochs.
func TestWriteReport_NoteFollowsTheFindings(t *testing.T) {
	report := verify.Report{
		TracesProcessed:      2,
		CheckpointsProcessed: 2,
		Errors: []verify.VerifyError{
			{Kind: "checkpoint", Detail: "seq 2: checkpoint: signature verification failed", Severity: verify.SeverityFatal},
		},
		OtherClaimedKeyIDs: []string{"aaaa", "bbbb"},
	}
	got := renderReport(report)

	wantPrefix := "Traces processed:      2\n" +
		"Checkpoints processed: 2\n" +
		"Status: FAILED (1 error(s))\n" +
		"  [checkpoint] checkpoint (fatal): seq 2: checkpoint: signature verification failed\n" +
		"Note: the log claims 2 key_id(s) other than the supplied key's:\n" +
		"  \"aaaa\"\n" +
		"  \"bbbb\"\n"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("writeReport does not start with the expected findings + Note header\n got: %q\nwant prefix: %q", got, wantPrefix)
	}
	for _, phrase := range []string{
		"unverified claims",
		"only a claim too",
		"does not explain or excuse the findings above",
		"Only if you know a key rotation happened",
		"obtained independently of this log",
		"full, unsplit files",
		"Each such run still reports the other epoch's entries and checkpoints as failures",
		"not implemented yet",
		"never affects Status or the exit code",
		"docs/verification.md",
	} {
		if !strings.Contains(got, phrase) {
			t.Errorf("the Note should mention %q; got:\n%s", phrase, got)
		}
	}
	if strings.Contains(got, "key_id metadata only") {
		t.Errorf("the metadata-only wording is for reports with no fatal finding; got:\n%s", got)
	}
}

// TestWriteReport_NoteWithoutFatalFindings: when nothing failed — here the
// advisory-only report an edited entry key_id produces, where everything
// verified against the supplied key — the Note must not offer a rotation or a
// wrong key as an explanation for anything, must not tell the reader to verify
// again, and the report still reads Status: OK.
func TestWriteReport_NoteWithoutFatalFindings(t *testing.T) {
	got := renderReport(verify.Report{
		TracesProcessed:      1,
		CheckpointsProcessed: 1,
		Errors: []verify.VerifyError{
			{TraceID: "abc123", Kind: "key_id_field_mismatch", Detail: "seq 0: entry key_id bogus does not match verified signer real", Severity: verify.SeverityAdvisory},
		},
		OtherClaimedKeyIDs: []string{"bogus"},
	})

	wantPrefix := "Traces processed:      1\n" +
		"Checkpoints processed: 1\n" +
		"Status: OK (1 advisory finding(s))\n" +
		"  [abc123] key_id_field_mismatch (advisory): seq 0: entry key_id bogus does not match verified signer real\n" +
		"Note: the log claims 1 key_id(s) other than the supplied key's:\n" +
		"  \"bogus\"\n"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("writeReport does not start with the expected findings + Note header\n got: %q\nwant prefix: %q", got, wantPrefix)
	}
	if !strings.Contains(got, "key_id metadata only") {
		t.Errorf("with nothing failed the Note should say this concerns metadata only; got:\n%s", got)
	}
	if !strings.Contains(got, "that could be read verified against the supplied key") {
		t.Errorf("with nothing failed the Note should say what was verified, and only what could be read; got:\n%s", got)
	}
	for _, phrase := range []string{"rotation", "wrong key", "verify again", "explain or excuse", "Each such run", "not implemented"} {
		if strings.Contains(got, phrase) {
			t.Errorf("with nothing failed the Note must not mention %q; got:\n%s", phrase, got)
		}
	}
}

// TestWriteReport_NoteEscapesUntrustedIDs: the key_ids the Note lists are text
// read from the log, which anyone who can edit it controls. A newline in one
// must not be able to forge an output line (a fake "Status: OK"), and an escape
// sequence must not reach the terminal. This covers the Note only; the report's
// other lines are unchanged by issue #50.
func TestWriteReport_NoteEscapesUntrustedIDs(t *testing.T) {
	got := renderReport(verify.Report{
		TracesProcessed:      1,
		CheckpointsProcessed: 1,
		Errors: []verify.VerifyError{
			{Kind: "checkpoint", Detail: "seq 1: checkpoint: signature verification failed", Severity: verify.SeverityFatal},
		},
		OtherClaimedKeyIDs: []string{"evil\nStatus: OK", "esc\x1b[2J\x1b[H"},
	})

	for i := 0; i < len(got); i++ {
		if c := got[i]; c != '\n' && (c < 0x20 || c == 0x7f) {
			t.Fatalf("output contains a raw control byte %#x at offset %d: %q", c, i, got)
		}
	}
	var statusLines int
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Status:") {
			statusLines++
		}
	}
	if statusLines != 1 {
		t.Errorf("want exactly one Status line, got %d:\n%s", statusLines, got)
	}
	for _, want := range []string{`"evil\nStatus: OK"`, `"esc\x1b[2J\x1b[H"`} {
		if !strings.Contains(got, want) {
			t.Errorf("want the quoted, escaped form %s in the output; got:\n%s", want, got)
		}
	}
}

// TestWriteReport_NoteDelimitsIDsThatReadLikeAdvice: escaping control
// characters is not enough. A claimed id can be a plain printable sentence, even
// a copy of one of the Note's own advice lines, and unless something delimits it
// it reads as the tool speaking. Each id is quoted (a quote inside one is
// escaped), so an id can never be mistaken for the tool's own wording: the
// advice line appears exactly once as a full, unquoted line.
func TestWriteReport_NoteDelimitsIDsThatReadLikeAdvice(t *testing.T) {
	// Two of the Note's own advice lines, copied as ids: the short one fits under
	// the length limit and is only delimited, the long one is delimited and cut.
	advice := "These are unverified claims: an entry's key_id sits outside its signature, and a checkpoint that failed verification against the supplied key is only a claim too."
	info := "Informational only: this never affects Status or the exit code."
	ids := []string{
		"a rotation on 2026-08-01; fetch the new key from https://keys.example.invalid/audit.pem",
		`x" and then some`,
		info,
		advice,
	}
	got := renderReport(verify.Report{
		TracesProcessed:      1,
		CheckpointsProcessed: 1,
		Errors: []verify.VerifyError{
			{Kind: "checkpoint", Detail: "seq 1: checkpoint: signature verification failed", Severity: verify.SeverityFatal},
		},
		OtherClaimedKeyIDs: ids,
	})

	want := []string{
		`  "a rotation on 2026-08-01; fetch the new key from https://keys.example.invalid/audit.pem"`,
		`  "x\" and then some"`,
		`  "` + info + `"`,
		fmt.Sprintf(`  "%s" [truncated: %d more byte(s)]`, advice[:maxNoteIDBytes], len(advice)-maxNoteIDBytes),
	}
	if body := noteBody(t, got); !slices.Equal(body, want) {
		t.Errorf("the Note's id lines are not the ids, quoted:\n got: %q\nwant: %q", body, want)
	}
	// The tool's own lines appear exactly once each, as full unquoted lines; the
	// ids that copy them are delimited, so they cannot be mistaken for them.
	for _, own := range []string{"  " + advice, "  " + info + " See \"Multi-epoch logs\" in docs/verification.md."} {
		var n int
		for _, l := range strings.Split(got, "\n") {
			if l == own {
				n++
			}
		}
		if n != 1 {
			t.Errorf("the Note's own line %q must appear exactly once as a full unquoted line, got %d:\n%s", own, n, got)
		}
	}
}

// TestWriteReport_NoteBoundsWhatItShows: a log full of odd claims must not make
// the terminal print without limit. At most maxNoteIDs ids are listed, each cut
// to maxNoteIDBytes; the header still gives the true count, the omissions are
// said out loud, and the cut never splits a character. -json is not bounded.
func TestWriteReport_NoteBoundsWhatItShows(t *testing.T) {
	report := func(ids ...string) verify.Report {
		return verify.Report{TracesProcessed: 1, CheckpointsProcessed: 1, OtherClaimedKeyIDs: ids}
	}
	numbered := func(n int) []string {
		ids := make([]string, n)
		for i := range ids {
			ids[i] = fmt.Sprintf("id-%02d", i)
		}
		return ids
	}

	t.Run("more ids than the limit: the rest are counted, not shown", func(t *testing.T) {
		got := renderReport(report(numbered(25)...))
		if !strings.Contains(got, "Note: the log claims 25 key_id(s) other than the supplied key's:\n") {
			t.Errorf("the header must give the true count; got:\n%s", got)
		}
		body := noteBody(t, got)
		if len(body) != maxNoteIDs+1 {
			t.Fatalf("want %d id lines plus one marker line, got %d: %q", maxNoteIDs, len(body), body)
		}
		if body[0] != `  "id-00"` || body[maxNoteIDs-1] != `  "id-09"` {
			t.Errorf("want the first %d ids in order; got first %q and last shown %q", maxNoteIDs, body[0], body[maxNoteIDs-1])
		}
		want := fmt.Sprintf("  ... and 15 more not shown; the ids above are the first %d in sort order (-json lists them all)", maxNoteIDs)
		if body[maxNoteIDs] != want {
			t.Errorf("marker line = %q, want %q", body[maxNoteIDs], want)
		}
	})

	t.Run("exactly the limit: nothing is hidden", func(t *testing.T) {
		body := noteBody(t, renderReport(report(numbered(maxNoteIDs)...)))
		if len(body) != maxNoteIDs {
			t.Errorf("want exactly %d id lines and no marker, got %d: %q", maxNoteIDs, len(body), body)
		}
	})

	t.Run("one over the limit: one is counted, not shown", func(t *testing.T) {
		body := noteBody(t, renderReport(report(numbered(maxNoteIDs+1)...)))
		want := fmt.Sprintf("  ... and 1 more not shown; the ids above are the first %d in sort order (-json lists them all)", maxNoteIDs)
		if len(body) != maxNoteIDs+1 || body[maxNoteIDs] != want {
			t.Errorf("want %d id lines and a marker for one more; got %q", maxNoteIDs, body)
		}
	})

	t.Run("a long id is cut and says how much was left out", func(t *testing.T) {
		body := noteBody(t, renderReport(report(strings.Repeat("a", 1000))))
		want := `  "` + strings.Repeat("a", maxNoteIDBytes) + `" [truncated: 872 more byte(s)]`
		if len(body) != 1 || body[0] != want {
			t.Errorf("long id line = %q, want %q", body, want)
		}
	})

	t.Run("an id of exactly the limit is untouched, one byte over is cut", func(t *testing.T) {
		body := noteBody(t, renderReport(report(strings.Repeat("a", maxNoteIDBytes))))
		if want := `  "` + strings.Repeat("a", maxNoteIDBytes) + `"`; len(body) != 1 || body[0] != want {
			t.Errorf("an id of exactly %d bytes must be untouched; got %q", maxNoteIDBytes, body)
		}
		body = noteBody(t, renderReport(report(strings.Repeat("a", maxNoteIDBytes+1))))
		if want := `  "` + strings.Repeat("a", maxNoteIDBytes) + `" [truncated: 1 more byte(s)]`; len(body) != 1 || body[0] != want {
			t.Errorf("an id one byte over must be cut with a marker; got %q", body)
		}
	})

	t.Run("the limit counts bytes, not characters", func(t *testing.T) {
		// A hundred characters of three bytes each are under the limit counted as
		// characters and over it counted as bytes. Forty-two of them fit in 128 bytes.
		id := strings.Repeat(string(rune(0x2603)), 100)
		body := noteBody(t, renderReport(report(id)))
		want := `  "` + strings.Repeat(fmt.Sprintf("\\u%04x", 0x2603), 42) + `" [truncated: 174 more byte(s)]`
		if len(body) != 1 || body[0] != want {
			t.Errorf("cut line = %q, want %q (the limit is in bytes)", body, want)
		}
	})

	t.Run("the cut never splits a character", func(t *testing.T) {
		// A two-byte character straddles the limit, so cutting at the limit would
		// leave half of it and print it as a stray byte escape.
		id := strings.Repeat("a", maxNoteIDBytes-1) + string(rune(0xe9)) + "tail"
		body := noteBody(t, renderReport(report(id)))
		want := `  "` + strings.Repeat("a", maxNoteIDBytes-1) + `" [truncated: 6 more byte(s)]`
		if len(body) != 1 || body[0] != want {
			t.Errorf("cut line = %q, want %q (the cut must back up to a character boundary)", body, want)
		}
	})
}

// countingWriter counts Write calls, to tell a report written as it goes from
// one assembled in memory and then written in a single call.
type countingWriter struct {
	writes int
	buf    strings.Builder
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.writes++
	return c.buf.Write(p)
}

// TestWriteReport_WritesAsItGoes: the report is written line by line, so a run
// with a great many findings is never held in memory a second time as one big
// string before it is printed.
func TestWriteReport_WritesAsItGoes(t *testing.T) {
	errs := make([]verify.VerifyError, 50)
	for i := range errs {
		errs[i] = verify.VerifyError{TraceID: fmt.Sprintf("%032x", i), Kind: "chain", Detail: "seq 0: signature verification failed", Severity: verify.SeverityFatal}
	}
	var w countingWriter
	writeReport(&w, verify.Report{TracesProcessed: 50, Errors: errs})

	if lines := strings.Count(w.buf.String(), "\n"); w.writes < lines {
		t.Errorf("%d writes for %d lines: the report was assembled in memory and written at once", w.writes, lines)
	}
}

// TestQuoteUntrusted_CutWithNoBoundaryInReach: if no character boundary lies
// within the limit (a run of continuation bytes, which valid UTF-8 never
// contains and the JSON decoder never lets through, so this is defence in depth),
// nothing of the id is shown and the whole length is reported as left out: still
// bounded, still printable ASCII, and never a piece of a broken character.
func TestQuoteUntrusted_CutWithNoBoundaryInReach(t *testing.T) {
	id := string([]byte{0xf0}) + strings.Repeat(string([]byte{0x80}), 200)
	if got, want := quoteUntrusted(id, maxNoteIDBytes), `"" [truncated: 201 more byte(s)]`; got != want {
		t.Errorf("quoteUntrusted = %q, want %q", got, want)
	}
}

// TestQuoteUntrusted_LeavesPlainASCIIAlone: a key_id in its normal form (64
// lowercase hex characters) must print exactly as it is stored, inside its
// quotes, so the quoting never gets in the way of matching an id against a known
// key. No printable ASCII is altered either, spaces included: an id padded with
// spaces, or made only of them, must stay visible as what it is rather than
// being trimmed into an invisible or blank line.
func TestQuoteUntrusted_LeavesPlainASCIIAlone(t *testing.T) {
	for _, in := range []string{strings.Repeat("0123456789abcdef", 4), " a ", " ", "a b", ""} {
		if got, want := quoteUntrusted(in, maxNoteIDBytes), `"`+in+`"`; got != want {
			t.Errorf("quoteUntrusted(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestQuoteUntrusted_EscapesEveryUnsafeClass pins the classes of character
// quoteUntrusted promises to escape, with the exact quoted form and the property
// that matters: every byte that comes out is printable ASCII, so nothing in it
// can forge a line or drive a terminal. The classes are the ones a narrower
// implementation lets through: 8-bit C1 controls that some terminals honour,
// line and paragraph separators, bidi overrides, invalid UTF-8, and printable
// non-ASCII such as a Cyrillic look-alike of a hex digit. Those inputs, and the
// expected numeric escapes (formatted with fmt.Sprintf), are built from code
// points and bytes so this file never itself contains the characters under
// test; the newline, carriage-return, backslash and double-quote rows use
// ordinary escape sequences. This is a sample of classes;
// TestQuoteUntrusted_SweepsEveryCodePoint covers the whole range.
func TestQuoteUntrusted_EscapesEveryUnsafeClass(t *testing.T) {
	around := func(mid string) string { return "a" + mid + "b" }
	esc := func(kind string, width, v int) string {
		return "a" + fmt.Sprintf("\\%s%0*x", kind, width, v) + "b"
	}
	tests := []struct {
		name string
		in   string
		want string // the escaped text inside the quotes
	}{
		{"newline", around(string(rune(0x0a))), "a\\nb"},
		{"carriage return", around(string(rune(0x0d))), "a\\rb"},
		{"NUL", around(string(rune(0x00))), esc("x", 2, 0x00)},
		{"DEL", around(string(rune(0x7f))), esc("x", 2, 0x7f)},
		{"C1 control CSI (U+009B)", around(string(rune(0x9b))), esc("u", 4, 0x9b)},
		{"line separator (U+2028)", around(string(rune(0x2028))), esc("u", 4, 0x2028)},
		{"paragraph separator (U+2029)", around(string(rune(0x2029))), esc("u", 4, 0x2029)},
		{"bidi override (U+202E)", around(string(rune(0x202e))), esc("u", 4, 0x202e)},
		{"invalid UTF-8 byte", around(string([]byte{0xff})), esc("x", 2, 0xff)},
		{"Cyrillic look-alike of a hex digit (U+0430)", around(string(rune(0x430))), esc("u", 4, 0x430)},
		{"non-BMP character (U+1F600)", around(string(rune(0x1f600))), esc("U", 8, 0x1f600)},
		{"backslash", around("\\"), "a\\\\b"},
		{"double quote", around("\""), "a\\\"b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := quoteUntrusted(tt.in, maxNoteIDBytes)
			if want := "\"" + tt.want + "\""; got != want {
				t.Errorf("quoteUntrusted(%q) = %q, want %q", tt.in, got, want)
			}
			for i := 0; i < len(got); i++ {
				if c := got[i]; c < 0x20 || c > 0x7e {
					t.Errorf("quoteUntrusted(%q) = %q contains the non-printable-ASCII byte %#x at offset %d", tt.in, got, c, i)
				}
			}
		})
	}
}

// TestQuoteUntrusted_SweepsEveryCodePoint backs the class table above with a
// sweep instead of a sample. For every Unicode code point (surrogates aside,
// which cannot occur in valid UTF-8) and every lone byte 0x80-0xff, the output
// is printable ASCII only. For every C0 and C1 control, DEL and NUL included,
// the quoted form also reads back as exactly its input, so two different ids
// can never render as the same line and no control character is left for a
// terminal to act on.
func TestQuoteUntrusted_SweepsEveryCodePoint(t *testing.T) {
	const maxRune = 0x10FFFF
	printable := func(t *testing.T, in, got string) {
		t.Helper()
		for i := 0; i < len(got); i++ {
			if c := got[i]; c < 0x20 || c > 0x7e {
				t.Fatalf("quoteUntrusted(%q) = %q contains the non-printable-ASCII byte %#x at offset %d", in, got, c, i)
			}
		}
	}
	for r := rune(0); r <= maxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		in := "a" + string(r) + "b"
		got := quoteUntrusted(in, maxNoteIDBytes)
		printable(t, in, got)
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			if back, err := strconv.Unquote(got); err != nil || back != in {
				t.Errorf("quoteUntrusted(%q) = %q does not read back as its input: Unquote gave %q, %v", in, got, back, err)
			}
		}
	}
	for b := 0x80; b <= 0xff; b++ {
		in := "a" + string([]byte{byte(b)}) + "b"
		printable(t, in, quoteUntrusted(in, maxNoteIDBytes))
	}
}

// runCLI runs the CLI in-process with args and returns what it wrote to stdout
// and its exit code. run reads os.Args and writes to os.Stdout directly, so
// this swaps both for the duration of the call; callers must not run in
// parallel.
func runCLI(t *testing.T, args ...string) (stdout string, exitCode int) {
	t.Helper()
	origArgs, origStdout := os.Args, os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { os.Args, os.Stdout = origArgs, origStdout })
	os.Args = append([]string{"otel-agent-audit-verify"}, args...)
	os.Stdout = w

	captured := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		captured <- string(b)
	}()
	exitCode = run()
	os.Args, os.Stdout = origArgs, origStdout
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	stdout = <-captured
	_ = r.Close()
	return stdout, exitCode
}

// writeJSONLines writes each of vs as one JSON line to path.
func writeJSONLines(t *testing.T, path string, vs ...any) {
	t.Helper()
	var b strings.Builder
	for _, v := range vs {
		line, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal for %s: %v", path, err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeJSONLine writes v as a single JSON line to path.
func writeJSONLine(t *testing.T, path string, v any) {
	t.Helper()
	writeJSONLines(t, path, v)
}

// writeSingleKeyFixture writes a one-trace log and its checkpoint, both signed
// by one fresh key, and returns their paths and that key in the hex form -key
// takes.
func writeSingleKeyFixture(t *testing.T) (logPath, checkpointPath, pubHex string) {
	t.Helper()
	priv, pub, err := sign.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	signer := sign.NewEd25519Signer(priv)

	const traceID = "01010101010101010101010101010101"
	rec := record.AuditRecord{
		SchemaVersion: record.SchemaVersion,
		TraceID:       traceID,
		SpanID:        "0102030405060708",
		ParentSpanID:  "0000000000000000",
		SeqInTrace:    0,
		SpanName:      "root",
		OtelKind:      "Internal",
		AuditKind:     record.AuditKindTask,
		Status:        "Ok",
	}
	seed, err := chain.GenesisSeed(traceID)
	if err != nil {
		t.Fatalf("GenesisSeed: %v", err)
	}
	built, err := chain.BuildChain([]record.AuditRecord{rec}, seed, signer)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}
	acc := chain.NewAccumulator(signer, 0, chain.ZeroPrevCheckpointHash)
	acc.AddTip(traceID, chain.TipHash(built), len(built))
	cp, err := acc.Build(time.Unix(1757000000, 0).UTC())
	if err != nil {
		t.Fatalf("Build checkpoint: %v", err)
	}

	dir := t.TempDir()
	logPath = filepath.Join(dir, "audit.jsonl")
	checkpointPath = filepath.Join(dir, "checkpoint.jsonl")
	writeJSONLine(t, logPath, chain.ToLogEntries(built)[0])
	writeJSONLine(t, checkpointPath, cp)
	return logPath, checkpointPath, hex.EncodeToString(pub)
}

// readEntry returns the single log entry in logPath.
func readEntry(t *testing.T, logPath string) chain.LogEntry {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read %s: %v", logPath, err)
	}
	var e chain.LogEntry
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}
	return e
}

// setEntryKeyID rewrites the single entry in logPath to claim keyID. An entry's
// key_id sits outside what it signs, so the entry still verifies.
func setEntryKeyID(t *testing.T, logPath, keyID string) {
	t.Helper()
	e := readEntry(t, logPath)
	e.Signed.KeyID = keyID
	writeJSONLine(t, logPath, e)
}

// TestRun_OtherClaimedKeyIDs drives the real CLI entry point end to end. The
// property that matters most about the hint, that it never changes the exit
// code, is implemented in run, not in writeReport, so only a test of run can
// guard it.
func TestRun_OtherClaimedKeyIDs(t *testing.T) {
	t.Run("no hint: exit 0 and no Note", func(t *testing.T) {
		logPath, cpPath, pubHex := writeSingleKeyFixture(t)
		out, code := runCLI(t, "-key", pubHex, logPath, cpPath)
		if code != 0 {
			t.Errorf("exit code = %d, want 0; output:\n%s", code, out)
		}
		want := "Traces processed:      1\nCheckpoints processed: 1\nStatus: OK\n"
		if out != want {
			t.Errorf("output mismatch\n got: %q\nwant: %q", out, want)
		}
	})

	t.Run("hint only (edited entry key_id): still exit 0 and Status: OK", func(t *testing.T) {
		logPath, cpPath, pubHex := writeSingleKeyFixture(t)
		setEntryKeyID(t, logPath, "bogus-key-id")

		out, code := runCLI(t, "-key", pubHex, logPath, cpPath)
		if code != 0 {
			t.Errorf("exit code = %d, want 0: a hint alone must not fail verification; output:\n%s", code, out)
		}
		if !strings.Contains(out, "Status: OK (1 advisory finding(s))\n") {
			t.Errorf("want Status: OK with the one advisory finding; output:\n%s", out)
		}
		if !strings.Contains(out, "Note: the log claims 1 key_id(s) other than the supplied key's:\n  \"bogus-key-id\"\n") {
			t.Errorf("want the Note listing the edited key_id, quoted; output:\n%s", out)
		}
		if strings.Contains(out, "Each such run") {
			t.Errorf("with nothing failed the Note must not tell the reader to verify again; output:\n%s", out)
		}
	})

	t.Run("hint plus a fatal finding (wrong key): exit 1", func(t *testing.T) {
		logPath, cpPath, _ := writeSingleKeyFixture(t)
		realKeyID := readEntry(t, logPath).Signed.KeyID
		_, wrongPub, err := sign.GenerateEd25519Key()
		if err != nil {
			t.Fatalf("GenerateEd25519Key: %v", err)
		}

		out, code := runCLI(t, "-key", hex.EncodeToString(wrongPub), logPath, cpPath)
		if code != 1 {
			t.Errorf("exit code = %d, want 1; output:\n%s", code, out)
		}
		if !strings.Contains(out, "Status: FAILED") {
			t.Errorf("want Status: FAILED; output:\n%s", out)
		}
		if !strings.Contains(out, "Note: the log claims 1 key_id(s) other than the supplied key's:\n  \""+realKeyID+"\"\n") {
			t.Errorf("want the Note listing the log's real key_id %s, quoted; output:\n%s", realKeyID, out)
		}
		if !strings.Contains(out, "Each such run still reports the other epoch's entries and checkpoints as failures") {
			t.Errorf("next to findings the Note must set the expectation that every run still fails; output:\n%s", out)
		}
	})

	t.Run("-json carries the hint under its documented name", func(t *testing.T) {
		logPath, cpPath, _ := writeSingleKeyFixture(t)
		realKeyID := readEntry(t, logPath).Signed.KeyID
		_, wrongPub, err := sign.GenerateEd25519Key()
		if err != nil {
			t.Fatalf("GenerateEd25519Key: %v", err)
		}

		out, code := runCLI(t, "-json", "-key", hex.EncodeToString(wrongPub), logPath, cpPath)
		if code != 1 {
			t.Errorf("exit code = %d, want 1; output:\n%s", code, out)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(out), &fields); err != nil {
			t.Fatalf("output is not a JSON object: %v\n%s", err, out)
		}
		var got []string
		if err := json.Unmarshal(fields["OtherClaimedKeyIDs"], &got); err != nil {
			t.Fatalf("JSON key \"OtherClaimedKeyIDs\" is missing or not an array of strings: %v; output:\n%s", err, out)
		}
		if want := []string{realKeyID}; !slices.Equal(got, want) {
			t.Errorf("JSON key \"OtherClaimedKeyIDs\" = %q, want %q; output:\n%s", got, want, out)
		}
	})

	t.Run("-json with a hint but no fatal finding: exit 0 and the hint is still reported", func(t *testing.T) {
		logPath, cpPath, pubHex := writeSingleKeyFixture(t)
		setEntryKeyID(t, logPath, "bogus-key-id")

		out, code := runCLI(t, "-json", "-key", pubHex, logPath, cpPath)
		if code != 0 {
			t.Errorf("exit code = %d, want 0: a hint alone must not fail verification in -json mode either; output:\n%s", code, out)
		}
		var report verify.Report
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("output is not a JSON report: %v\n%s", err, out)
		}
		if want := []string{"bogus-key-id"}; !slices.Equal(report.OtherClaimedKeyIDs, want) {
			t.Errorf("OtherClaimedKeyIDs = %q, want %q; output:\n%s", report.OtherClaimedKeyIDs, want, out)
		}
		if len(report.Errors) != 1 || report.Errors[0].Kind != "key_id_field_mismatch" {
			t.Errorf("want exactly the advisory key_id_field_mismatch and nothing else; got %+v", report.Errors)
		}
	})

	t.Run("the Note is bounded but -json lists every claimed id in full", func(t *testing.T) {
		logPath, cpPath, pubHex := writeSingleKeyFixture(t)
		base := readEntry(t, logPath)
		// More claimed ids than the Note lists, one of them longer than it shows.
		long := strings.Repeat("z", 3*maxNoteIDBytes)
		claims := []string{long}
		for i := 0; i < maxNoteIDs+2; i++ {
			claims = append(claims, fmt.Sprintf("claim-%02d", i))
		}
		entries := make([]any, len(claims))
		for i, id := range claims {
			e := base
			e.Record.TraceID = fmt.Sprintf("%032x", i+1)
			e.Signed.KeyID = id
			entries[i] = e
		}
		writeJSONLines(t, logPath, entries...)
		want := slices.Clone(claims)
		slices.Sort(want)

		out, _ := runCLI(t, "-json", "-key", pubHex, logPath, cpPath)
		var report verify.Report
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("output is not a JSON report: %v", err)
		}
		if !slices.Equal(report.OtherClaimedKeyIDs, want) {
			t.Errorf("-json must carry all %d claimed ids in full, got %d ids", len(want), len(report.OtherClaimedKeyIDs))
		}

		human, _ := runCLI(t, "-key", pubHex, logPath, cpPath)
		if header := fmt.Sprintf("Note: the log claims %d key_id(s)", len(want)); !strings.Contains(human, header) {
			t.Errorf("the Note's header must give the true count (%q); output:\n%s", header, human)
		}
		if body := noteBody(t, human); len(body) != maxNoteIDs+1 {
			t.Errorf("the Note lists at most %d ids plus a marker line, got %d lines: %q", maxNoteIDs, len(body), body)
		}
	})
}

// TestErrorLabel pins the "[...]" prefix used for each report line, since an
// empty TraceID alone is not a safe proxy for "checkpoint-level" now that
// torn_trailing_line (log-level) also carries an empty TraceID.
func TestErrorLabel(t *testing.T) {
	tests := []struct {
		name string
		err  verify.VerifyError
		want string
	}{
		{
			name: "trace-scoped error",
			err:  verify.VerifyError{TraceID: "abc123", Kind: "chain"},
			want: "abc123",
		},
		{
			name: "checkpoint error",
			err:  verify.VerifyError{TraceID: "", Kind: "checkpoint"},
			want: "checkpoint",
		},
		{
			// Not a Kind verify.VerifyLog produces today (checkpoint and
			// torn_trailing_line are the only empty-TraceID kinds it emits —
			// see verify.go) — this pins errorLabel's fallback for any other
			// empty-TraceID kind, so a future addition defaults sanely without
			// needing its own case here.
			name: "unrecognized empty-TraceID kind falls back to checkpoint",
			err:  verify.VerifyError{TraceID: "", Kind: "some_future_kind"},
			want: "checkpoint",
		},
		{
			name: "torn trailing audit-log line",
			err:  verify.VerifyError{TraceID: "", Kind: verify.KindTornTrailingLine},
			want: "audit log",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errorLabel(tt.err); got != tt.want {
				t.Errorf("errorLabel(%+v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

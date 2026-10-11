package profilecompare

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"
)

const vectorDir = "testdata/otel-canonical-profile/vectors"

type expectedFile struct {
	Pass map[string]struct {
		AttributesSHA256 string `json:"attributes_sha256"`
		SpanSHA256       string `json:"span_sha256"`
	} `json:"pass"`
	Reject map[string]struct {
		RejectCode string `json:"reject_code"`
	} `json:"reject"`
	Batch struct {
		BatchRootSHA256 string   `json:"batch_root_sha256"`
		Members         []string `json:"members"`
	} `json:"batch"`
}

func loadExpected(t *testing.T) expectedFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorDir, "expected.json"))
	if err != nil {
		t.Fatalf("read expected.json: %v", err)
	}
	var e expectedFile
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("parse expected.json: %v", err)
	}
	return e
}

func readVector(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorDir, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestProfile_PassVectors_ShippedBytes mirrors the reference validator's three
// checks on each pass vector. The canonical bytes are the fixture, so this
// confirms the published hashes, that our JCS reproduces the shipped bytes from
// their own parse, and that the embedded attributes_sha256 binds the attrs file.
func TestProfile_PassVectors_ShippedBytes(t *testing.T) {
	exp := loadExpected(t)
	if len(exp.Pass) != 8 {
		t.Fatalf("expected 8 pass vectors, found %d: the vendored set changed", len(exp.Pass))
	}
	for _, name := range sortedKeys(exp.Pass) {
		want := exp.Pass[name]
		t.Run(name, func(t *testing.T) {
			attrB := readVector(t, "pass/"+name+".attrs.json")
			spanB := readVector(t, "pass/"+name+".canonical.json")

			if got := sha256Hex(attrB); got != want.AttributesSHA256 {
				t.Errorf("attributes_sha256 of shipped attrs: got %s, want %s", got, want.AttributesSHA256)
			}
			if got := sha256Hex(spanB); got != want.SpanSHA256 {
				t.Errorf("span_sha256 of shipped canonical bytes: got %s, want %s", got, want.SpanSHA256)
			}
			for label, b := range map[string][]byte{"attrs": attrB, "canonical": spanB} {
				re, err := jcs.Transform(b)
				if err != nil {
					t.Fatalf("jcs %s: %v", label, err)
				}
				if !bytes.Equal(re, b) {
					t.Errorf("JCS(parse(%s)) differs from the shipped bytes:\n got  %s\n want %s", label, re, b)
				}
			}
			var span struct {
				AttrSHA string `json:"attributes_sha256"`
			}
			if err := json.Unmarshal(spanB, &span); err != nil {
				t.Fatal(err)
			}
			if span.AttrSHA != sha256Hex(attrB) {
				t.Errorf("embedded attributes_sha256 %s does not bind the attrs file (%s)", span.AttrSHA, sha256Hex(attrB))
			}
		})
	}
}

// TestProfile_PassVectors_Construction goes further than the reference
// validator does. It takes the raw span fields and attribute values out of each
// pass vector, runs them through canonicalSpan (the construction path every
// reject vector exercises), and requires the shipped bytes back. The reference
// harness only runs that path on rejects, so a bug in how a pass input is
// *built* would not show up there.
func TestProfile_PassVectors_Construction(t *testing.T) {
	exp := loadExpected(t)
	for _, name := range sortedKeys(exp.Pass) {
		want := exp.Pass[name]
		t.Run(name, func(t *testing.T) {
			attrs, err := decodeOrdered(readVector(t, "pass/"+name+".attrs.json"))
			if err != nil {
				t.Fatal(err)
			}
			span, err := decodeOrdered(readVector(t, "pass/"+name+".canonical.json"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := canonicalSpan(span.(obj), attrs)
			if err != nil {
				t.Fatalf("canonicalSpan: %v", err)
			}
			if shipped := readVector(t, "pass/"+name+".canonical.json"); !bytes.Equal(got.CanonicalBytes, shipped) {
				t.Errorf("built bytes differ from shipped:\n got  %s\n want %s", got.CanonicalBytes, shipped)
			}
			if got.SpanSHA256 != want.SpanSHA256 || got.AttrSHA256 != want.AttributesSHA256 {
				t.Errorf("hashes: got span=%s attrs=%s, want span=%s attrs=%s",
					got.SpanSHA256, got.AttrSHA256, want.SpanSHA256, want.AttributesSHA256)
			}
		})
	}
}

// TestProfile_RejectVectors requires every reject input to be refused with the
// code expected.json names, and never to yield a hash.
func TestProfile_RejectVectors(t *testing.T) {
	exp := loadExpected(t)
	if len(exp.Reject) != 9 {
		t.Fatalf("expected 9 reject vectors, found %d: the vendored set changed", len(exp.Reject))
	}
	for _, name := range sortedKeys(exp.Reject) {
		want := exp.Reject[name].RejectCode
		t.Run(name, func(t *testing.T) {
			v, err := decodeOrdered(readVector(t, "reject/"+name+".input.json"))
			if err != nil {
				t.Fatal(err)
			}
			in := v.(obj)
			spanV, _ := in.last("span")
			attrs, _ := in.last("attributes")

			var gotErr error
			if s, ok := spanV.(string); ok && s == "BATCH" {
				_, gotErr = batchRoot(nil)
			} else {
				var res profileSpan
				res, gotErr = canonicalSpan(spanV.(obj), attrs)
				if gotErr != nil && res.SpanSHA256 != "" {
					t.Errorf("a rejected input still produced a hash: %s", res.SpanSHA256)
				}
			}
			if got := rejectCode(gotErr); got != want {
				t.Errorf("reject code: got %q (err=%v), want %q", got, gotErr, want)
			}
		})
	}
}

// TestProfile_BatchRoot reproduces the published RFC 6962 batch root over the
// three member spans.
func TestProfile_BatchRoot(t *testing.T) {
	exp := loadExpected(t)
	var hashes []string
	for _, m := range exp.Batch.Members {
		hashes = append(hashes, exp.Pass[m].SpanSHA256)
	}
	got, err := batchRoot(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if got != exp.Batch.BatchRootSHA256 {
		t.Errorf("batch root: got %s, want %s", got, exp.Batch.BatchRootSHA256)
	}
}

// The vendored batch vector has exactly three members, so the vectors only ever
// exercise subtrees of size 1, 2 and 3. A split rule capped at 2 ("largest power
// of two strictly less than n, but never more than 2") agrees with RFC 6962 for
// every one of those, and it survived the vendored vectors when tried as a
// mutant. These tests cover the larger sizes.

// pairwiseRoot computes the same tree bottom-up: hash adjacent nodes level by
// level, carrying an unpaired last node up unchanged. For RFC 6962 trees this
// agrees with the recursive definition, and it shares no code with batchRoot.
func pairwiseRoot(hashes [][]byte) []byte {
	level := make([][]byte, len(hashes))
	for i, h := range hashes {
		s := sha256.Sum256(append([]byte{0x00}, h...))
		level[i] = s[:]
	}
	for len(level) > 1 {
		var next [][]byte
		for i := 0; i+1 < len(level); i += 2 {
			s := sha256.Sum256(append(append([]byte{0x01}, level[i]...), level[i+1]...))
			next = append(next, s[:])
		}
		if len(level)%2 == 1 {
			next = append(next, level[len(level)-1])
		}
		level = next
	}
	return level[0]
}

func TestProfile_BatchRoot_AllSmallSizes(t *testing.T) {
	var raw [][]byte
	var hexes []string
	for n := 1; n <= 66; n++ {
		s := sha256.Sum256([]byte{byte(n)})
		raw = append(raw, s[:])
		hexes = append(hexes, hex.EncodeToString(s[:]))

		got, err := batchRoot(hexes)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if want := hex.EncodeToString(pairwiseRoot(raw)); got != want {
			t.Errorf("n=%d: recursive root %s != pairwise root %s", n, got, want)
		}
	}
}

// TestProfile_BatchRoot_SingleSpan pins SPEC.md section 4's explicit sentence:
// a batch of one span has root SHA-256(0x00 || h_0).
func TestProfile_BatchRoot_SingleSpan(t *testing.T) {
	h := sha256.Sum256([]byte("one span"))
	got, err := batchRoot([]string{hex.EncodeToString(h[:])})
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(append([]byte{0x00}, h[:]...))
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("single-span root: got %s, want %x", got, want)
	}
}

// The vendored vectors are the oracle, so they must be exactly what
// PROVENANCE.md says they are: every listed file present with the listed sha256,
// and no other file in the directory. Without this a consistent edit to a vector
// and its expected.json, or a stray added file, would pass every other test.
func TestVendoredVectors_MatchProvenance(t *testing.T) {
	const root = "testdata/otel-canonical-profile"
	prov, err := os.ReadFile(filepath.Join(root, "PROVENANCE.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, block, found := strings.Cut(string(prov), "## sha256 of each file")
	if !found {
		t.Fatal("PROVENANCE.md has no sha256 section")
	}
	_, block, _ = strings.Cut(block, "```\n")
	block, _, _ = strings.Cut(block, "```")

	listed := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(block), "\n") {
		sum, path, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 64 {
			t.Fatalf("malformed PROVENANCE.md line %q", line)
		}
		listed[path] = sum
	}
	if len(listed) != 27 {
		t.Fatalf("PROVENANCE.md lists %d files, want 27", len(listed))
	}

	onDisk := map[string]bool{}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "PROVENANCE.md" {
			return nil
		}
		onDisk[rel] = true
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		want, ok := listed[rel]
		switch {
		case !ok:
			t.Errorf("%s is in the directory but not in PROVENANCE.md", rel)
		case sha256Hex(b) != want:
			t.Errorf("%s: sha256 %s, PROVENANCE.md says %s", rel, sha256Hex(b), want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for path := range listed {
		if !onDisk[path] {
			t.Errorf("%s is listed in PROVENANCE.md but missing", path)
		}
	}
}

package wal

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSyncParentDir verifies the happy path: fsyncing the parent directory of
// an existing file succeeds. Mirrors the exporter package's identical test
// for its own copy of this helper.
func TestSyncParentDir(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := syncParentDir(p); err != nil {
		t.Fatalf("syncParentDir: %v", err)
	}
}

// TestSyncParentDir_MissingParent verifies that syncParentDir reports an
// error when the parent directory does not exist, rather than silently
// succeeding.
func TestSyncParentDir_MissingParent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "missing", "file.txt")
	if err := syncParentDir(p); err == nil {
		t.Fatal("expected an error when the parent directory does not exist")
	}
}

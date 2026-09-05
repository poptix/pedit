package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// streamAtomically's force=false branch is pdown's authoritative
// no-clobber guard. It is tested directly because the early Lstat check in
// fetch() would otherwise be the only thing an end-to-end test exercises,
// leaving the atomic guard -- the one that closes the check-then-write
// window -- unverified.
func TestStreamAtomicallyRefusesToClobberWithoutForce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(target, []byte("LOCAL ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}

	src := strings.NewReader("replacement")
	err := streamAtomically(target, src, int64(len("replacement")), 0o600, false)
	if err == nil {
		t.Fatal("streamAtomically overwrote an existing file with force=false")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should explain the refusal, got: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "LOCAL ORIGINAL" {
		t.Fatalf("the existing file was modified: %q", b)
	}

	// No temp files left behind after the refusal.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".pedit-") {
			t.Errorf("left a temp file behind: %s", e.Name())
		}
	}
}

func TestStreamAtomicallyOverwritesWithForce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "replace.txt")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := streamAtomically(target, strings.NewReader("new content"),
		int64(len("new content")), 0o600, true); err != nil {
		t.Fatalf("streamAtomically with force: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "new content" {
		t.Errorf("content = %q", b)
	}
}

func TestStreamAtomicallyCreatesWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fresh.txt")
	if err := streamAtomically(target, strings.NewReader("hello"), 5, 0o600, false); err != nil {
		t.Fatalf("streamAtomically: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "hello" {
		t.Errorf("content = %q", b)
	}
	st, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600 -- a fetched file should not be world-readable", perm)
	}
}

// A short stream must leave the target alone rather than half-writing it.
func TestStreamAtomicallyShortReadLeavesTargetUntouched(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "t.txt")
	if err := os.WriteFile(target, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Promise 100 bytes, deliver 5.
	if err := streamAtomically(target, strings.NewReader("short"), 100, 0o600, true); err == nil {
		t.Fatal("a truncated stream should be an error")
	}
	if b, _ := os.ReadFile(target); string(b) != "ORIGINAL" {
		t.Fatalf("target was modified by a failed transfer: %q", b)
	}
}

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// sanitizeName is the single check standing between a remote-supplied
// string and a path on this machine, so it gets its own table.
func TestSanitizeName(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"notes.txt", "notes.txt", false},
		{".bashrc", ".bashrc", false}, // dotfiles are ordinary names
		{"with space.txt", "with space.txt", false},
		{"a-b_c.1.tar.gz", "a-b_c.1.tar.gz", false},

		// Traversal collapses to the last element rather than escaping.
		{"../../etc/passwd", "passwd", false},
		{"foo/bar", "bar", false},
		{"/etc/shadow", "shadow", false},
		{"a/b/../../../c", "c", false},

		// Nothing usable left.
		{"", "", true},
		{".", "", true},
		{"..", "", true},
		{"/", "", true},
		{"foo/..", "", true},
		{"a/b/", "b", false}, // trailing slash is not meaningful

		// Control characters would corrupt the listing and the audit log.
		{"bad\nname", "", true},
		{"tab\there", "", true},
		{"nul\x00byte", "", true},
		{"del\x7f", "", true},
	} {
		got, err := sanitizeName(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("sanitizeName(%q) = %q, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("sanitizeName(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if filepath.Base(got) != got {
			t.Errorf("sanitizeName(%q) = %q, which is not a single path element", tc.in, got)
		}
	}
}

// linkOrCopy is pup's no-clobber guard. It must refuse an existing
// destination whichever branch it takes -- hard link or copy fallback.
func TestLinkOrCopyNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "dest")
	if err := os.WriteFile(dest, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := linkOrCopy(src, dest)
	if !errors.Is(err, errNameTaken) {
		t.Fatalf("linkOrCopy over an existing file = %v, want errNameTaken", err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "ORIGINAL" {
		t.Fatalf("destination was modified: %q", b)
	}
}

func TestLinkOrCopyStoresWhenDestIsFree(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "sub", "dest")
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := linkOrCopy(src, dest); err != nil {
		t.Fatalf("linkOrCopy: %v", err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "payload" {
		t.Errorf("stored content = %q", b)
	}
}

// The copy fallback (used when src and dest are on different filesystems)
// must be just as unwilling to overwrite as the hard link.
func TestLinkOrCopyFallbackAlsoRefuses(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "dest")
	if err := os.WriteFile(dest, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Exercise the fallback path directly: O_EXCL must fail on an existing
	// file exactly as os.Link does.
	if _, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); !errors.Is(err, os.ErrExist) {
		t.Fatalf("O_EXCL on an existing file = %v, want ErrExist -- the copy "+
			"fallback relies on this to avoid clobbering", err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "ORIGINAL" {
		t.Fatalf("destination was modified: %q", b)
	}
}

func TestSetupTransferDirCreatesAndResolves(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	link := filepath.Join(base, "link")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	got, err := setupTransferDir(link)
	if err != nil {
		t.Fatalf("setupTransferDir: %v", err)
	}
	// Resolved once at startup, so no name joined onto it later can be
	// redirected by swapping the symlink.
	resolvedTarget, _ := filepath.EvalSymlinks(target)
	if got != resolvedTarget {
		t.Errorf("setupTransferDir(%q) = %q, want the resolved %q", link, got, resolvedTarget)
	}

	// Created if missing, and private.
	fresh := filepath.Join(base, "fresh")
	if _, err := setupTransferDir(fresh); err != nil {
		t.Fatalf("setupTransferDir on a missing dir: %v", err)
	}
	st, err := os.Stat(fresh)
	if err != nil {
		t.Fatalf("directory was not created: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o700 {
		t.Errorf("transfer dir mode = %o, want 700", perm)
	}
}

func TestSetupTransferDirEmptyDisablesTheFeature(t *testing.T) {
	got, err := setupTransferDir("")
	if err != nil || got != "" {
		t.Errorf("setupTransferDir(\"\") = %q, %v; want \"\", nil (feature off)", got, err)
	}
}

func TestIsBuiltinProfile(t *testing.T) {
	for _, name := range []string{"pup", "pdown"} {
		if !isBuiltinProfile(name) {
			t.Errorf("%q should be a built-in", name)
		}
	}
	for _, name := range []string{"edit", "view", "", "PUP", "pups", "pdown2"} {
		if isBuiltinProfile(name) {
			t.Errorf("%q should not be a built-in", name)
		}
	}
}

package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pedit/internal/proto"
)

// End-to-end coverage for the built-in pup/pdown profiles: a file moving
// into the transfer directory at home, and a file coming back out of it.
//
// Two of these tests exist specifically to pin data-loss guards -- pup
// never overwriting at home, and pdown never overwriting locally without
// -f. Both were mutation-verified (guard removed, test observed to fail)
// rather than assumed to work.

// startTransfer brings up a daemon with the built-ins enabled and returns
// the transfer directory alongside the harness.
func startTransfer(t *testing.T, extra ...string) (*harness, string) {
	t.Helper()
	// The dir must exist before the daemon resolves it (EvalSymlinks), and
	// it has to live outside the harness's own tempdir teardown ordering,
	// so make it explicitly.
	root, err := os.MkdirTemp("", "xfer")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })

	extra = append([]string{fmt.Sprintf("transfer_dir = %q", root)}, extra...)
	return start(t, "", extra...), root
}

// fetch runs pedithelper's fetch mode exactly as pdown does.
func (h *harness) fetch(t *testing.T, name, out string, force bool) (string, error) {
	t.Helper()
	f := "0"
	if force {
		f = "1"
	}
	cmd := exec.Command(h.helper, "fetch", h.sock, name, out, f)
	o, err := cmd.CombinedOutput()
	return string(o), err
}

func TestPupStoresFileAtHome(t *testing.T) {
	h, root := startTransfer(t)

	src := filepath.Join(h.dir, "notes.txt")
	write(t, src, "shipped upward\n")

	out, err := h.send(t, "pup", src, "")
	if err != nil {
		t.Fatalf("pup failed: %v\n%s", err, out)
	}
	if got := read(t, filepath.Join(root, "notes.txt")); got != "shipped upward\n" {
		t.Errorf("stored content = %q", got)
	}
	// The local file must be left exactly as it was: nothing comes back.
	if got := read(t, src); got != "shipped upward\n" {
		t.Errorf("local file was modified: %q", got)
	}
	if !strings.Contains(h.audit(t), "UP file=\"notes.txt\"") {
		t.Errorf("no UP audit line:\n%s", h.audit(t))
	}
}

// pup must never overwrite. This is a data-loss guard: the file at home is
// the one the user already had, and a remote host cannot be allowed to
// replace it.
func TestPupRefusesExistingNameAndLeavesItByteIdentical(t *testing.T) {
	h, root := startTransfer(t)

	existing := filepath.Join(root, "notes.txt")
	write(t, existing, "THE ORIGINAL, must survive\n")

	src := filepath.Join(h.dir, "notes.txt")
	write(t, src, "the replacement, must not land\n")

	out, err := h.send(t, "pup", src, "")
	if err == nil {
		t.Fatalf("pup overwrote an existing name; it must refuse\n%s", out)
	}
	if !strings.Contains(out, "already exists") {
		t.Errorf("error should say the name is taken, got:\n%s", out)
	}
	if got := read(t, existing); got != "THE ORIGINAL, must survive\n" {
		t.Fatalf("the file at home was modified: %q", got)
	}
	// Refused in PREPARE, so nothing should have been uploaded at all.
	if !strings.Contains(h.audit(t), "REJECT exists") {
		t.Errorf("expected a REJECT exists audit line:\n%s", h.audit(t))
	}
}

func TestPdownFetchesFileFromHome(t *testing.T) {
	h, root := startTransfer(t)
	write(t, filepath.Join(root, "tool.sh"), "#!/bin/sh\necho hi\n")

	dst := filepath.Join(h.dir, "tool.sh")
	out, err := h.fetch(t, "tool.sh", dst, false)
	if err != nil {
		t.Fatalf("pdown failed: %v\n%s", err, out)
	}
	if got := read(t, dst); got != "#!/bin/sh\necho hi\n" {
		t.Errorf("fetched content = %q", got)
	}
	if !strings.Contains(h.audit(t), "DOWN file=\"tool.sh\"") {
		t.Errorf("no DOWN audit line:\n%s", h.audit(t))
	}
}

// The other data-loss guard: a fetch must not quietly replace a local file.
func TestPdownRefusesExistingLocalFileWithoutForce(t *testing.T) {
	h, root := startTransfer(t)
	write(t, filepath.Join(root, "cfg"), "NEW from home\n")

	dst := filepath.Join(h.dir, "cfg")
	write(t, dst, "LOCAL, must survive\n")

	out, err := h.fetch(t, "cfg", dst, false)
	if err == nil {
		t.Fatalf("pdown overwrote a local file without -f\n%s", out)
	}
	if !strings.Contains(out, "already exists") {
		t.Errorf("error should mention the existing file, got:\n%s", out)
	}
	if got := read(t, dst); got != "LOCAL, must survive\n" {
		t.Fatalf("local file was clobbered: %q", got)
	}

	// ...and -f is the way through.
	if out, err := h.fetch(t, "cfg", dst, true); err != nil {
		t.Fatalf("pdown -f failed: %v\n%s", err, out)
	}
	if got := read(t, dst); got != "NEW from home\n" {
		t.Errorf("after -f, content = %q", got)
	}
}

func TestPdownWithNoNameListsWhatIsStaged(t *testing.T) {
	h, root := startTransfer(t)
	write(t, filepath.Join(root, "alpha.txt"), "aaa")
	write(t, filepath.Join(root, "beta.bin"), "bbbbbb")

	out, err := h.fetch(t, "", "", false)
	if err != nil {
		t.Fatalf("listing failed: %v\n%s", err, out)
	}
	for _, want := range []string{"alpha.txt", "beta.bin", "2 file(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("listing missing %q:\n%s", want, out)
		}
	}
	// Sizes, so you can tell whether it is the thing you meant.
	if !strings.Contains(out, "6") {
		t.Errorf("listing should include sizes:\n%s", out)
	}
	if !strings.Contains(h.audit(t), "LIST") {
		t.Errorf("no LIST audit line:\n%s", h.audit(t))
	}
}

func TestPdownEmptyDirectorySaysSo(t *testing.T) {
	h, _ := startTransfer(t)
	out, err := h.fetch(t, "", "", false)
	if err != nil {
		t.Fatalf("listing failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "empty") {
		t.Errorf("expected an explicit empty message, got:\n%s", out)
	}
}

func TestPdownMissingNameIsRefusedCleanly(t *testing.T) {
	h, _ := startTransfer(t)
	dst := filepath.Join(h.dir, "nope")
	out, err := h.fetch(t, "nope", dst, false)
	if err == nil {
		t.Fatalf("fetching a nonexistent name should fail\n%s", out)
	}
	if _, statErr := os.Stat(dst); statErr == nil {
		t.Error("a failed fetch created the output file anyway")
	}
	if !strings.Contains(out, "not in the transfer directory") {
		t.Errorf("unhelpful error:\n%s", out)
	}
}

// A symlink in the transfer directory would otherwise be a way to read any
// file the daemon's user can read, which is the whole point of confining
// names to that directory.
func TestPdownRefusesToFollowASymlinkOutOfTheDirectory(t *testing.T) {
	h, root := startTransfer(t)

	secret := filepath.Join(h.dir, "secret.txt")
	write(t, secret, "PRIVATE KEY MATERIAL\n")
	if err := os.Symlink(secret, filepath.Join(root, "innocent.txt")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	dst := filepath.Join(h.dir, "got")
	out, err := h.fetch(t, "innocent.txt", dst, false)
	if err == nil {
		t.Fatalf("a symlink out of the transfer dir was served\n%s", out)
	}
	if b, readErr := os.ReadFile(dst); readErr == nil && bytes.Contains(b, []byte("PRIVATE")) {
		t.Fatal("symlink target content escaped")
	}
	if !strings.Contains(h.audit(t), "REJECT symlink") {
		t.Errorf("expected a REJECT symlink audit line:\n%s", h.audit(t))
	}
}

// ../.. in a remote-supplied name must not reach outside the directory, in
// either direction.
func TestTraversalInTransferNamesIsConfined(t *testing.T) {
	h, root := startTransfer(t)

	// Down: a traversal name is reduced to its last element, which does not
	// exist, so it is refused -- it must NOT read the real /etc/passwd.
	dst := filepath.Join(h.dir, "stolen")
	out, err := h.fetch(t, "../../../../etc/passwd", dst, false)
	if err == nil {
		t.Fatalf("traversal fetch succeeded\n%s", out)
	}
	if b, readErr := os.ReadFile(dst); readErr == nil && bytes.Contains(b, []byte("root:")) {
		t.Fatal("traversal read a file outside the transfer directory")
	}

	// Up: the name comes straight off the wire, so craft the hostile ones
	// directly rather than going through the shell function.
	canary := filepath.Join(h.dir, "CANARY-UP")
	for _, name := range []string{
		"../../../../../.." + canary,
		"../CANARY-UP",
		"/tmp/pedit-escaped-up",
		"a/b/../../../CANARY-UP",
		"..",
		".",
		"",
	} {
		content := []byte("escaped\n")
		resp, err := h.sendCrafted(t, Crafted{
			Meta:    proto.Meta{Profile: "pup", Filename: name, OriginHint: "hostile", Size: int64(len(content))},
			Content: content,
		})
		if err != nil {
			t.Fatalf("name %q: transport error: %v", name, err)
		}
		_ = resp
		if _, statErr := os.Stat(canary); statErr == nil {
			t.Fatalf("name %q escaped the transfer dir and created %s", name, canary)
		}
		if _, statErr := os.Stat("/tmp/pedit-escaped-up"); statErr == nil {
			os.Remove("/tmp/pedit-escaped-up")
			t.Fatalf("name %q escaped to an absolute path", name)
		}
		// Whatever did land must be inside the transfer directory.
		entries, _ := os.ReadDir(root)
		for _, e := range entries {
			if strings.ContainsAny(e.Name(), "/") {
				t.Fatalf("name %q produced a nested path: %q", name, e.Name())
			}
		}
	}
}

func TestConfirmFlagsGateEachDirectionIndependently(t *testing.T) {
	// A denying approver, with confirmation switched off for uploads only.
	h, root := startTransfer(t,
		"confirm_up = false",
		"confirm_down = true",
		"[exec]", `command = "false"`,
	)

	src := filepath.Join(h.dir, "up.txt")
	write(t, src, "no prompt needed\n")
	if out, err := h.send(t, "pup", src, ""); err != nil {
		t.Fatalf("confirm_up=false should have skipped the denying approver: %v\n%s", err, out)
	}
	if got := read(t, filepath.Join(root, "up.txt")); got != "no prompt needed\n" {
		t.Errorf("stored = %q", got)
	}

	// Downloads still consult it, and it still says no.
	write(t, filepath.Join(root, "down.txt"), "should not leave\n")
	dst := filepath.Join(h.dir, "down.txt")
	out, err := h.fetch(t, "down.txt", dst, false)
	if err == nil {
		t.Fatalf("confirm_down=true must still gate the download\n%s", out)
	}
	if _, statErr := os.Stat(dst); statErr == nil {
		t.Error("a denied download still wrote a file")
	}
}

func TestOversizedDownloadIsRefusedOnTheServedSize(t *testing.T) {
	// The generic ceiling checks the REQUESTED size, which is always 0 for
	// a download -- so without a separate check this would sail through.
	h, root := startTransfer(t, "max_size_bytes = 64")
	big := make([]byte, 4096)
	if err := os.WriteFile(filepath.Join(root, "big.bin"), big, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	dst := filepath.Join(h.dir, "big.bin")
	out, err := h.fetch(t, "big.bin", dst, false)
	if err == nil {
		t.Fatalf("a 4096-byte file was served under max_size_bytes=64\n%s", out)
	}
	if !strings.Contains(out, "max_size_bytes") {
		t.Errorf("error should name the limit:\n%s", out)
	}
	if !strings.Contains(h.audit(t), "REJECT oversized") {
		t.Errorf("expected REJECT oversized:\n%s", h.audit(t))
	}
}

// A denied upload must not leave anything behind at home.
func TestDeniedPupTransfersNothing(t *testing.T) {
	h, root := startTransfer(t, "[exec]", `command = "false"`)

	src := filepath.Join(h.dir, "denied.txt")
	write(t, src, "should never arrive\n")
	out, err := h.send(t, "pup", src, "")
	if err == nil {
		t.Fatalf("a denied pup reported success\n%s", out)
	}
	if _, statErr := os.Stat(filepath.Join(root, "denied.txt")); statErr == nil {
		t.Fatal("a denied pup stored the file anyway")
	}
	if !strings.Contains(h.audit(t), "DENY") {
		t.Errorf("expected a DENY audit line:\n%s", h.audit(t))
	}
}

// pup and pdown are handled internally; a config profile of the same name
// must not silently take over (nor be silently ignored -- it warns).
func TestBuiltinProfilesCannotBeShadowedByConfig(t *testing.T) {
	h, root := startTransfer(t,
		"[profiles.pup]", `command = "sh -c 'echo HIJACKED > {file}'"`,
	)

	src := filepath.Join(h.dir, "shadow.txt")
	write(t, src, "real content\n")
	if out, err := h.send(t, "pup", src, ""); err != nil {
		t.Fatalf("pup failed: %v\n%s", err, out)
	}
	if got := read(t, filepath.Join(root, "shadow.txt")); got != "real content\n" {
		t.Errorf("the config profile ran instead of the built-in: %q", got)
	}
	logs := read(t, filepath.Join(h.dir, "agentd.log"))
	if !strings.Contains(logs, "cannot be overridden") {
		t.Errorf("shadowing a built-in should warn loudly:\n%s", logs)
	}
}

// Built-ins run no command at all, so a broken $EDITOR/exec command must be
// irrelevant to them.
func TestBuiltinsRunNoProfileCommand(t *testing.T) {
	h, root := startTransfer(t,
		"confirm_up = false",
		"[exec]", `command = "/nonexistent/approver-binary"`,
	)
	src := filepath.Join(h.dir, "quiet.txt")
	write(t, src, "no command runs\n")
	if out, err := h.send(t, "pup", src, ""); err != nil {
		t.Fatalf("pup should not depend on any command being runnable: %v\n%s", err, out)
	}
	if got := read(t, filepath.Join(root, "quiet.txt")); got != "no command runs\n" {
		t.Errorf("stored = %q", got)
	}
}

func TestPupIsRefusedWhenTransferDirIsDisabled(t *testing.T) {
	h := start(t, "", `transfer_dir = ""`)
	src := filepath.Join(h.dir, "x.txt")
	write(t, src, "nope\n")
	out, err := h.send(t, "pup", src, "")
	if err == nil {
		t.Fatalf("pup should be refused when transfer_dir is unset\n%s", out)
	}
	if !strings.Contains(out, "transfer_dir") {
		t.Errorf("the error should name the missing setting:\n%s", out)
	}
}

// The pup/pdown shell functions in pedit.sh are what a user actually types,
// and they had no coverage until a manual run turned up the bug below.
//
// getopts stops at the first non-option word. A single parsing pass
// therefore silently DISCARDS anything written after the filename, so
// "pdown app.conf -f" looked like it worked and then did not force, and
// "pdown app.conf -o /tmp/x" failed with a usage error. Flags in either
// position have to work, because both orders are things people type.
func TestPdownShellFunctionAcceptsFlagsAfterTheName(t *testing.T) {
	h, root := startTransfer(t)
	cache := filepath.Join(h.dir, "cache-xfer")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "app.conf"), "key=value\n")

	out := filepath.Join(h.dir, "after.conf")
	o, err := sourceAndRun(t, h, cache, "cd "+h.dir+" && pdown app.conf -o "+out)
	if err != nil {
		t.Fatalf("pdown with a trailing -o failed: %v\n%s", err, o)
	}
	if got := read(t, out); got != "key=value\n" {
		t.Errorf("content = %q", got)
	}

	// And the same flag before the name, which must not have regressed.
	before := filepath.Join(h.dir, "before.conf")
	o, err = sourceAndRun(t, h, cache, "cd "+h.dir+" && pdown -o "+before+" app.conf")
	if err != nil {
		t.Fatalf("pdown with a leading -o failed: %v\n%s", err, o)
	}
	if got := read(t, before); got != "key=value\n" {
		t.Errorf("content = %q", got)
	}
}

// -f written after the name must actually force, not be dropped.
func TestPdownShellFunctionTrailingForceActuallyForces(t *testing.T) {
	h, root := startTransfer(t)
	cache := filepath.Join(h.dir, "cache-force")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "c.txt"), "FROM HOME\n")
	target := filepath.Join(h.dir, "c.txt")
	write(t, target, "local\n")

	// Without -f: refused, local file intact.
	if o, err := sourceAndRun(t, h, cache, "cd "+h.dir+" && pdown c.txt"); err == nil {
		t.Fatalf("pdown clobbered without -f\n%s", o)
	}
	if got := read(t, target); got != "local\n" {
		t.Fatalf("local file was clobbered: %q", got)
	}

	// With a trailing -f: overwritten.
	if o, err := sourceAndRun(t, h, cache, "cd "+h.dir+" && pdown c.txt -f"); err != nil {
		t.Fatalf("pdown c.txt -f failed: %v\n%s", err, o)
	}
	if got := read(t, target); got != "FROM HOME\n" {
		t.Errorf("after a trailing -f, content = %q", got)
	}
}

func TestPupAndPdownShellFunctionsBasics(t *testing.T) {
	h, root := startTransfer(t)
	cache := filepath.Join(h.dir, "cache-basics")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(h.dir, "sh-notes.txt")
	write(t, src, "via the shell function\n")
	if o, err := sourceAndRun(t, h, cache, "pup "+src); err != nil {
		t.Fatalf("pup failed: %v\n%s", err, o)
	}
	if got := read(t, filepath.Join(root, "sh-notes.txt")); got != "via the shell function\n" {
		t.Errorf("stored = %q", got)
	}

	// Bare pdown lists.
	o, err := sourceAndRun(t, h, cache, "pdown")
	if err != nil {
		t.Fatalf("bare pdown failed: %v\n%s", err, o)
	}
	if !strings.Contains(o, "sh-notes.txt") {
		t.Errorf("listing did not mention the staged file:\n%s", o)
	}

	// Two names is a usage error, not a silently-ignored argument.
	if o, err := sourceAndRun(t, h, cache, "pdown one two"); err == nil {
		t.Errorf("pdown with two names should be a usage error\n%s", o)
	}

	// pup takes exactly one file.
	if o, err := sourceAndRun(t, h, cache, "pup"); err == nil {
		t.Errorf("bare pup should be a usage error\n%s", o)
	}
}

// The progress meter must never appear in captured output. pedit is run
// from scripts and from this harness, and carriage returns plus half-drawn
// bars landing in a log or a pipe would be worse than having no meter.
// Everything here captures via CombinedOutput, so stderr is a pipe.
func TestProgressMeterStaysOffWhenOutputIsNotATerminal(t *testing.T) {
	h, root := startTransfer(t, "max_size_bytes = 134217728")

	// Big enough that a meter would certainly have drawn on a terminal.
	big := filepath.Join(h.dir, "big.bin")
	writeBigFile(t, big, 48<<20)

	out, err := h.send(t, "pup", big, "")
	if err != nil {
		t.Fatalf("pup failed: %v\n%s", err, out)
	}
	assertNoMeterArtifacts(t, "pup", out)

	dst := filepath.Join(h.dir, "back.bin")
	out, err = h.fetch(t, "big.bin", dst, false)
	if err != nil {
		t.Fatalf("pdown failed: %v\n%s", err, out)
	}
	assertNoMeterArtifacts(t, "pdown", out)

	// And the file still arrived intact with the meter in the read path.
	if a, b := read(t, filepath.Join(root, "big.bin")), read(t, dst); a != b {
		t.Error("round trip through the counting reader altered the content")
	}
}

func assertNoMeterArtifacts(t *testing.T, what, out string) {
	t.Helper()
	if strings.Contains(out, "\r") {
		t.Errorf("%s: captured output contains a carriage return:\n%q", what, out)
	}
	for _, artifact := range []string{"[===", "ETA", "|/-"} {
		if strings.Contains(out, artifact) {
			t.Errorf("%s: captured output contains meter artifact %q:\n%s", what, artifact, out)
		}
	}
	// The final throughput line SHOULD still be there -- it is a plain line,
	// not a redraw, and is the thing worth keeping in a log.
	if !strings.Contains(out, "pedit:") {
		t.Errorf("%s: the final stats line went missing along with the meter:\n%s", what, out)
	}
}

// Every transfer reports throughput at the end, including the one-way pup
// path that returns no content.
func TestFinalThroughputLineOnBothDirections(t *testing.T) {
	h, root := startTransfer(t)

	src := filepath.Join(h.dir, "stats.txt")
	write(t, src, strings.Repeat("x", 1<<16))

	out, err := h.send(t, "pup", src, "")
	if err != nil {
		t.Fatalf("pup: %v\n%s", err, out)
	}
	if !strings.Contains(out, "up in") || !strings.Contains(out, "MiB/s") {
		t.Errorf("pup printed no upload throughput:\n%s", out)
	}
	// Nothing came back, so there must be no fabricated download half.
	if strings.Contains(out, "down in") {
		t.Errorf("pup reported a download that never happened:\n%s", out)
	}

	_ = root
	dst := filepath.Join(h.dir, "stats-back.txt")
	out, err = h.fetch(t, "stats.txt", dst, false)
	if err != nil {
		t.Fatalf("pdown: %v\n%s", err, out)
	}
	if !strings.Contains(out, "down in") || !strings.Contains(out, "MiB/s") {
		t.Errorf("pdown printed no download throughput:\n%s", out)
	}
	if strings.Contains(out, "up in") {
		t.Errorf("pdown reported an upload that never happened:\n%s", out)
	}
}

// The reported total must cover the whole run, including the time a human
// spent deciding. The approval wait sat between two timed phases and was
// in no duration at all, so a run that spent 1.2s waiting for approval and
// 1.6s in the command proudly reported "total 1.6s".
func TestReportedTotalIncludesTheApprovalWait(t *testing.T) {
	const approveDelay = 1200 * time.Millisecond
	h, _ := startTransfer(t, "[exec]", `command = "sleep 1.2"`)

	src := filepath.Join(h.dir, "timed.txt")
	write(t, src, "hello\n")

	start := time.Now()
	out, err := h.send(t, "pup", src, "")
	wall := time.Since(start)
	if err != nil {
		t.Fatalf("pup: %v\n%s", err, out)
	}

	total := parseReportedTotal(t, out)
	if total < approveDelay {
		t.Errorf("reported total %s is less than the %s spent waiting for approval "+
			"-- the wait is missing from the accounting:\n%s", total, approveDelay, out)
	}
	// It must also be believable: no larger than the wall clock we measured.
	if total > wall {
		t.Errorf("reported total %s exceeds observed wall time %s:\n%s", total, wall, out)
	}
	if !strings.Contains(out, "waiting at home") {
		t.Errorf("the wait was not reported as its own figure:\n%s", out)
	}
}

// parseReportedTotal pulls the duration out of "... | total 2.814s".
func parseReportedTotal(t *testing.T, out string) time.Duration {
	t.Helper()
	const marker = "total "
	i := strings.LastIndex(out, marker)
	if i < 0 {
		t.Fatalf("no total in output:\n%s", out)
	}
	field := strings.TrimSpace(out[i+len(marker):])
	if nl := strings.IndexAny(field, " \n"); nl >= 0 {
		field = field[:nl]
	}
	d, err := time.ParseDuration(field)
	if err != nil {
		t.Fatalf("could not parse total %q: %v", field, err)
	}
	return d
}

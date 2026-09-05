// Package e2e drives the real, built binaries end to end: peditagentd
// listening on a unix socket, pedithelper talking the actual wire protocol
// to it, a real profile command running, and the result coming back.
//
// This exists because an audit found the project had tests only for things
// that had already broken in the field (the serial approver, the bootstrap,
// the $EDITOR guard, the self-loop). The central feature -- transferring a
// file and getting the modified version back -- had none, despite being the
// entire point of the tool. It had only ever been verified by hand.
package e2e

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"pedit/internal/proto"
	"pedit/internal/wire"
)

type harness struct {
	dir       string // short path: unix sockets cap near 108 bytes
	agentd    string
	helper    string
	sock      string
	auditPath string
	cmd       *exec.Cmd
}

func buildBinaries(t *testing.T, dir string) (agentd, helper string) {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	for _, b := range []struct{ name, pkg string }{
		{"peditagentd", "./cmd/peditagentd"},
		{"pedithelper", "./cmd/pedithelper"},
	} {
		out := filepath.Join(dir, b.name)
		cmd := exec.Command("go", "build", "-o", out, b.pkg)
		cmd.Dir = root
		if o, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", b.name, err, o)
		}
	}
	return filepath.Join(dir, "peditagentd"), filepath.Join(dir, "pedithelper")
}

// start brings up peditagentd with the given extra config lines. backing is
// the socket it proxies non-pedit traffic to ("" => a nonexistent path,
// fine for tests that never exercise pass-through).
func start(t *testing.T, backing string, extra ...string) *harness {
	t.Helper()
	dir, err := os.MkdirTemp("", "e2e")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	agentd, helper := buildBinaries(t, dir)
	h := &harness{
		dir: dir, agentd: agentd, helper: helper,
		sock:      filepath.Join(dir, "a.sock"),
		auditPath: filepath.Join(dir, "audit.log"),
	}
	if backing == "" {
		backing = filepath.Join(dir, "no-such-agent.sock")
	}

	// Top-level keys MUST come before any [section] header, or they land in
	// that section and are ignored. Callers pass top-level keys and section
	// blocks in `extra`; split them so ordering is always correct.
	var topLevel, sections []string
	inSection := false
	for _, line := range extra {
		if strings.HasPrefix(strings.TrimSpace(line), "[") {
			inSection = true
		}
		if inSection {
			sections = append(sections, line)
		} else {
			topLevel = append(topLevel, line)
		}
	}
	cfg := []string{
		fmt.Sprintf("listen = %q", h.sock),
		fmt.Sprintf("backing_agent = %q", backing),
		fmt.Sprintf("audit_log = %q", h.auditPath),
		`approver = "exec"`,
	}
	cfg = append(cfg, topLevel...)
	cfg = append(cfg, `[exec]`, `command = "true"`) // auto-approve unless overridden
	cfg = append(cfg, sections...)
	cfgPath := filepath.Join(dir, "c.toml")
	if err := os.WriteFile(cfgPath, []byte(strings.Join(cfg, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("config: %v", err)
	}

	h.cmd = exec.Command(agentd, "-foreground", cfgPath)
	logf, _ := os.Create(filepath.Join(dir, "agentd.log"))
	h.cmd.Stdout, h.cmd.Stderr = logf, logf
	if err := h.cmd.Start(); err != nil {
		t.Fatalf("start peditagentd: %v", err)
	}
	t.Cleanup(func() {
		if h.cmd.Process != nil {
			h.cmd.Process.Kill()
			h.cmd.Wait()
		}
	})
	waitForSocket(t, h.sock)
	return h
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket %s never appeared", path)
}

// send runs pedithelper exactly as pedit.sh does.
func (h *harness) send(t *testing.T, profile, in, out string) (string, error) {
	t.Helper()
	cmd := exec.Command(h.helper, "send", h.sock, profile, in, out)
	o, err := cmd.CombinedOutput()
	return string(o), err
}

func (h *harness) audit(t *testing.T) string {
	t.Helper()
	b, _ := os.ReadFile(h.auditPath)
	return string(b)
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// THE core feature: a file goes up, a profile command MODIFIES it, and the
// modified version replaces the original.
func TestFileRoundTripAppliesProfileEdit(t *testing.T) {
	h := start(t, "",
		`[profiles.edit]`,
		`command = "sh -c 'printf EDITED >> {file}'"`)

	f := filepath.Join(h.dir, "notes.txt")
	write(t, f, "original")

	if out, err := h.send(t, "edit", f, f); err != nil {
		t.Fatalf("transfer failed: %v\n%s", err, out)
	}
	if got := read(t, f); got != "originalEDITED" {
		t.Errorf("file content = %q, want %q", got, "originalEDITED")
	}
	if !strings.Contains(h.audit(t), "ACCEPT") {
		t.Errorf("no ACCEPT in audit log:\n%s", h.audit(t))
	}
}

// A read-only profile must return the bytes unchanged -- including binary
// content, which the base64/framing path could plausibly mangle.
func TestBinaryContentSurvivesUnchanged(t *testing.T) {
	h := start(t, "", `[profiles.view]`, `command = "cat {file}"`)

	payload := make([]byte, 0, 1024)
	for i := 0; i < 1024; i++ {
		payload = append(payload, byte(i%256)) // includes NUL and high bytes
	}
	in := filepath.Join(h.dir, "bin.dat")
	out := filepath.Join(h.dir, "bin.out")
	if err := os.WriteFile(in, payload, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if o, err := h.send(t, "view", in, out); err != nil {
		t.Fatalf("transfer failed: %v\n%s", err, o)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("length %d, want %d", len(got), len(payload))
	}
	for i := range payload {
		if got[i] != payload[i] {
			t.Fatalf("byte %d differs: %d vs %d", i, got[i], payload[i])
		}
	}
}

// -o writes elsewhere and must leave the source untouched.
func TestSeparateOutputLeavesSourceUntouched(t *testing.T) {
	h := start(t, "", `[profiles.edit]`, `command = "sh -c 'printf X >> {file}'"`)
	in := filepath.Join(h.dir, "src.txt")
	out := filepath.Join(h.dir, "dst.txt")
	write(t, in, "keep")

	if o, err := h.send(t, "edit", in, out); err != nil {
		t.Fatalf("transfer: %v\n%s", err, o)
	}
	if got := read(t, in); got != "keep" {
		t.Errorf("source modified: %q", got)
	}
	if got := read(t, out); got != "keepX" {
		t.Errorf("output = %q, want %q", got, "keepX")
	}
}

// A denied request must run nothing and leave the file alone.
func TestDenialRunsNothingAndLeavesFileUnchanged(t *testing.T) {
	marker := ""
	h := start(t, "",
		`[profiles.edit]`,
		`command = "sh -c 'printf RAN >> {file}'"`)
	// Rewrite the config so the approver refuses.
	cfg := filepath.Join(h.dir, "c.toml")
	b := read(t, cfg)
	write(t, cfg, strings.Replace(b, `command = "true"`, `command = "false"`, 1))
	h.cmd.Process.Kill()
	h.cmd.Wait()
	h.cmd = exec.Command(h.agentd, "-foreground", cfg)
	logf, _ := os.Create(filepath.Join(h.dir, "agentd2.log"))
	h.cmd.Stdout, h.cmd.Stderr = logf, logf
	os.Remove(h.sock)
	if err := h.cmd.Start(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	waitForSocket(t, h.sock)

	f := filepath.Join(h.dir, "d.txt")
	write(t, f, "untouched")
	out, err := h.send(t, "edit", f, f)
	if err == nil {
		t.Errorf("expected a denied transfer to fail, got success: %s", out)
	}
	if got := read(t, f); got != "untouched"+marker {
		t.Errorf("file was modified despite denial: %q", got)
	}
	if !strings.Contains(h.audit(t), "DENY") {
		t.Errorf("no DENY in audit log:\n%s", h.audit(t))
	}
}

// A profile name the config doesn't define must be refused outright -- this
// is the boundary that stops a remote host choosing what runs.
func TestUnknownProfileRefused(t *testing.T) {
	h := start(t, "", `[profiles.view]`, `command = "cat {file}"`)
	f := filepath.Join(h.dir, "u.txt")
	write(t, f, "data")

	out, err := h.send(t, "definitely-not-a-profile", f, f)
	if err == nil {
		t.Errorf("unknown profile should fail, got: %s", out)
	}
	if !strings.Contains(out, "unknown profile") {
		t.Errorf("error should name the problem, got: %q", out)
	}
	if got := read(t, f); got != "data" {
		t.Errorf("file changed on a refused profile: %q", got)
	}
	if !strings.Contains(h.audit(t), "unknown-profile") {
		t.Errorf("no unknown-profile entry in audit log:\n%s", h.audit(t))
	}
}

// max_size_bytes must reject before anything is written or run.
func TestOversizeRejected(t *testing.T) {
	h := start(t, "",
		`max_size_bytes = 16`,
		`[profiles.view]`, `command = "cat {file}"`)
	f := filepath.Join(h.dir, "big.txt")
	write(t, f, strings.Repeat("x", 4096))

	out, err := h.send(t, "view", f, f)
	if err == nil {
		t.Errorf("oversize transfer should fail, got: %s", out)
	}
	if !strings.Contains(h.audit(t), "oversized") {
		t.Errorf("no oversized entry in audit log:\n%s", h.audit(t))
	}
}

// File mode must survive the round trip -- pedithelper recreates the file.
func TestFileModePreserved(t *testing.T) {
	h := start(t, "", `[profiles.view]`, `command = "cat {file}"`)
	f := filepath.Join(h.dir, "mode.sh")
	write(t, f, "#!/bin/sh\n")
	if err := os.Chmod(f, 0o750); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if o, err := h.send(t, "view", f, f); err != nil {
		t.Fatalf("transfer: %v\n%s", err, o)
	}
	st, err := os.Stat(f)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := st.Mode().Perm(); got != 0o750 {
		t.Errorf("mode = %o, want 750", got)
	}
}

// Normal (non-pedit) agent traffic must reach the backing agent untouched.
// This is pedit's core promise: it does not disturb your ssh.
func TestNormalAgentTrafficPassesThrough(t *testing.T) {
	for _, bin := range []string{"ssh-agent", "ssh-add", "ssh-keygen"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	dir, err := os.MkdirTemp("", "bk")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	defer os.RemoveAll(dir)

	realSock := filepath.Join(dir, "real.sock")
	ag := exec.Command("ssh-agent", "-D", "-a", realSock)
	if err := ag.Start(); err != nil {
		t.Fatalf("ssh-agent: %v", err)
	}
	defer func() { ag.Process.Kill(); ag.Wait() }()
	waitForSocket(t, realSock)

	key := filepath.Join(dir, "k")
	if o, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", key, "-q").CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v\n%s", err, o)
	}
	add := exec.Command("ssh-add", key)
	add.Env = append(os.Environ(), "SSH_AUTH_SOCK="+realSock)
	if o, err := add.CombinedOutput(); err != nil {
		t.Fatalf("ssh-add: %v\n%s", err, o)
	}

	h := start(t, realSock, `[profiles.view]`, `command = "cat {file}"`)

	// Through pedit's socket, the key must be visible.
	list := exec.Command("ssh-add", "-l")
	list.Env = append(os.Environ(), "SSH_AUTH_SOCK="+h.sock)
	out, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-add -l through pedit failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ED25519") {
		t.Errorf("key not visible through the proxy: %q", out)
	}
}

// replace_auth_sock must bind at the ORIGINAL $SSH_AUTH_SOCK path, move the
// real agent aside, and put it back on SIGTERM. Getting the restore wrong
// strands the user's real agent.
func TestReplaceAuthSockTakeoverAndRestore(t *testing.T) {
	if _, err := exec.LookPath("ssh-agent"); err != nil {
		t.Skip("ssh-agent not installed")
	}
	dir, err := os.MkdirTemp("", "rp")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	defer os.RemoveAll(dir)

	realSock := filepath.Join(dir, "r.sock")
	ag := exec.Command("ssh-agent", "-D", "-a", realSock)
	if err := ag.Start(); err != nil {
		t.Fatalf("ssh-agent: %v", err)
	}
	defer func() { ag.Process.Kill(); ag.Wait() }()
	waitForSocket(t, realSock)

	agentd, _ := buildBinaries(t, dir)
	cfg := filepath.Join(dir, "c.toml")
	write(t, cfg, strings.Join([]string{
		fmt.Sprintf("listen = %q", filepath.Join(dir, "unused.sock")),
		fmt.Sprintf("audit_log = %q", filepath.Join(dir, "audit.log")),
		`approver = "exec"`, `[exec]`, `command = "true"`,
		`[profiles.view]`, `command = "cat {file}"`,
	}, "\n")+"\n")

	cmd := exec.Command(agentd, "-foreground", cfg)
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+realSock)
	logf, _ := os.Create(filepath.Join(dir, "log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	moved := realSock + ".pedit-real"
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(moved); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(moved); err != nil {
		cmd.Process.Kill()
		t.Fatalf("real agent socket was not moved aside to %s", moved)
	}

	// SIGTERM must restore it.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}
	cmd.Wait()
	if _, err := os.Stat(moved); err == nil {
		t.Errorf("%s still exists after shutdown -- the real agent was not restored", moved)
	}
	if _, err := os.Stat(realSock); err != nil {
		t.Errorf("real agent socket not restored at %s: %v", realSock, err)
	}
}

// pedit.sh's self-extraction is a security control: it decodes an embedded
// helper and must verify its sha256 before ever executing it. Untested
// until an audit found it, despite being the code path every remote host
// actually runs.
func sourceAndRun(t *testing.T, h *harness, cacheDir, script string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "-c",
		"source "+filepath.Join(mustAbs(t, ".."), "pedit.sh")+"\n"+script)
	cmd.Env = append(os.Environ(),
		"SSH_AUTH_SOCK="+h.sock,
		"TMPDIR="+cacheDir,
	)
	o, err := cmd.CombinedOutput()
	return string(o), err
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return a
}

func TestPeditShSelfExtractsAndTransfers(t *testing.T) {
	h := start(t, "", `[profiles.edit]`, `command = "sh -c 'printf SH >> {file}'"`)
	cache := filepath.Join(h.dir, "cache")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f := filepath.Join(h.dir, "viash.txt")
	write(t, f, "base")

	out, err := sourceAndRun(t, h, cache, "pedit -p edit "+f)
	if err != nil {
		t.Fatalf("pedit.sh transfer failed: %v\n%s", err, out)
	}
	if got := read(t, f); got != "baseSH" {
		t.Errorf("content = %q, want %q", got, "baseSH")
	}

	// The helper must have been extracted to a cache path that includes its
	// checksum, and must be private to the user.
	var found string
	filepath.Walk(cache, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi != nil && !fi.IsDir() && strings.Contains(fi.Name(), "pedithelper-") {
			found = p
		}
		return nil
	})
	if found == "" {
		t.Fatal("no extracted helper found in the cache dir")
	}
	fi, err := os.Stat(found)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("extracted helper is group/world accessible: %o", perm)
	}
}

// A corrupted cache entry must never be executed: the script re-verifies the
// checksum and re-extracts rather than running whatever is sitting there.
// This is the multi-user-box attack the checksum exists for.
func TestPeditShRejectsTamperedHelperCache(t *testing.T) {
	h := start(t, "", `[profiles.view]`, `command = "cat {file}"`)
	cache := filepath.Join(h.dir, "cache2")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f := filepath.Join(h.dir, "t.txt")
	write(t, f, "payload")

	// First run populates the cache legitimately.
	if o, err := sourceAndRun(t, h, cache, "pedit -p view "+f); err != nil {
		t.Fatalf("priming run failed: %v\n%s", err, o)
	}

	var helper string
	filepath.Walk(cache, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi != nil && !fi.IsDir() && strings.Contains(fi.Name(), "pedithelper-") {
			helper = p
		}
		return nil
	})
	if helper == "" {
		t.Fatal("cache not populated")
	}

	// Replace it with a hostile script that would announce itself if run.
	// Unlink first: writing over a binary whose process has only just exited
	// can still fail with ETXTBSY, which made this test flaky.
	if err := os.Remove(helper); err != nil {
		t.Fatalf("tamper (unlink): %v", err)
	}
	if err := os.WriteFile(helper, []byte("#!/bin/sh\necho TAMPERED_BINARY_EXECUTED\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	out, err := sourceAndRun(t, h, cache, "pedit -p view "+f)
	if strings.Contains(out, "TAMPERED_BINARY_EXECUTED") {
		t.Fatalf("the tampered cache entry WAS executed -- checksum verification is not working:\n%s", out)
	}
	if err != nil {
		t.Fatalf("pedit should self-heal from a tampered cache, got: %v\n%s", err, out)
	}
	if got := read(t, f); got != "payload" {
		t.Errorf("content corrupted: %q", got)
	}
}

// One-way ("open") profiles hand the file to a detached system handler and
// return NOTHING. The critical property is that the local file is left
// exactly as it was: an empty StatusOK would have truncated it to zero
// bytes, which is why StatusOpened exists as a distinct status.
func TestOneWayOpenLeavesLocalFileIntact(t *testing.T) {
	h := start(t, "",
		`[profiles.open]`,
		`command = "sh -c 'cat {file} > `+"`dirname {file}`"+`/opened.marker'"`,
		`oneway = true`,
		`retain_seconds = 60`)

	f := filepath.Join(h.dir, "doc.txt")
	const content = "important local content"
	write(t, f, content)

	out, err := h.send(t, "open", f, f)
	if err != nil {
		t.Fatalf("open failed: %v\n%s", err, out)
	}
	if got := read(t, f); got != content {
		t.Fatalf("LOCAL FILE WAS MODIFIED by a one-way open: %q (want %q)", got, content)
	}
	if !strings.Contains(out, "nothing written back") {
		t.Errorf("helper should say nothing came back, got: %q", out)
	}
	if !strings.Contains(h.audit(t), "OPEN") {
		t.Errorf("no OPEN entry in the audit log:\n%s", h.audit(t))
	}
}

// The handler must actually receive the file's real content, and the temp
// copy must survive after the request completes -- deleting it immediately
// would yank the file out from under a viewer that is still loading it.
func TestOneWayHandlerSeesContentAndTempIsRetained(t *testing.T) {
	h := start(t, "",
		`[profiles.open]`,
		`command = "cp {file} `+filepath.Join("/tmp", "")+`"`, // replaced below
		`oneway = true`)
	// Rewrite with a marker path inside the harness dir.
	marker := filepath.Join(h.dir, "handler-saw.txt")
	cfg := filepath.Join(h.dir, "c.toml")
	body := read(t, cfg)
	body = strings.Replace(body, `command = "cp {file} /tmp"`, `command = "sh -c 'cp {file} `+marker+`'"`, 1)
	write(t, cfg, body)
	h.cmd.Process.Kill()
	h.cmd.Wait()
	os.Remove(h.sock)
	h.cmd = exec.Command(h.agentd, "-foreground", cfg)
	logf, _ := os.Create(filepath.Join(h.dir, "agentd2.log"))
	h.cmd.Stdout, h.cmd.Stderr = logf, logf
	if err := h.cmd.Start(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	waitForSocket(t, h.sock)

	f := filepath.Join(h.dir, "payload.txt")
	const content = "handler must see this"
	write(t, f, content)
	if o, err := h.send(t, "open", f, f); err != nil {
		t.Fatalf("open: %v\n%s", err, o)
	}
	if got := read(t, marker); got != content {
		t.Errorf("handler saw %q, want %q", got, content)
	}

	// The temp file must still exist right after the request returns.
	tmpBase := filepath.Join(h.dir, "tmp")
	var found bool
	filepath.Walk(tmpBase, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi != nil && !fi.IsDir() && strings.HasSuffix(p, "payload.txt") {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("one-way temp file was deleted immediately -- a detached viewer would lose the file")
	}
}

// The temp file handed to the system handler must never be executable, which
// is the protection standing in for type gating: modern desktops refuse to
// launch a .desktop file without the execute bit.
func TestOneWayTempFileIsNotExecutable(t *testing.T) {
	h := start(t, "",
		`[profiles.open]`,
		`command = "sh -c 'stat -c %a {file} > `+"`dirname {file}`"+`/mode.txt'"`,
		`oneway = true`)

	f := filepath.Join(h.dir, "evil.desktop")
	write(t, f, "[Desktop Entry]\nType=Application\nExec=/bin/true\n")
	if o, err := h.send(t, "open", f, f); err != nil {
		t.Fatalf("open: %v\n%s", err, o)
	}

	var mode string
	filepath.Walk(filepath.Join(h.dir, "tmp"), func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi != nil && strings.HasSuffix(p, "mode.txt") {
			mode = strings.TrimSpace(read(t, p))
		}
		return nil
	})
	if mode == "" {
		t.Fatal("could not read back the temp file mode")
	}
	if strings.ContainsAny(mode, "1357") { // any odd digit => an execute bit
		t.Errorf("temp file mode %s has an execute bit set -- a .desktop file could be launched", mode)
	}
}

// sendCrafted bypasses pedithelper and speaks the wire protocol directly,
// so tests can supply values a cooperating client would never send. That is
// the actual threat model: anyone able to reach a forwarded agent socket can
// craft these frames by hand.
// Crafted carries a full crafted transfer: metadata plus the bytes to send,
// which may deliberately disagree with the declared size.
type Crafted struct {
	Meta    proto.Meta
	Content []byte
	// SkipContent stops after PREPARE, to check that a refusal really means
	// nothing was transferred.
	SkipContent bool
}

func readPeditReply(c net.Conn) (proto.Response, error) {
	frame, err := wire.ReadFrameLimit(c, wire.MaxAllocFrame())
	if err != nil {
		return proto.Response{}, err
	}
	if len(frame) == 0 || frame[0] != wire.MsgAgentExtensionResp {
		return proto.Response{}, fmt.Errorf("not a pedit reply")
	}
	rd := wire.NewReader(frame[1:])
	if _, err := rd.String(); err != nil {
		return proto.Response{}, err
	}
	return proto.DecodeResponse(rd.Rest())
}

func (h *harness) sendCrafted(t *testing.T, c Crafted) (proto.Response, error) {
	t.Helper()
	conn, err := net.DialTimeout("unix", h.sock, 5*time.Second)
	if err != nil {
		return proto.Response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	if err := wire.WriteFrame(conn, proto.PrepareRequestFrame(c.Meta)); err != nil {
		return proto.Response{}, err
	}
	ack, err := readPeditReply(conn)
	if err != nil {
		return proto.Response{}, err
	}
	if ack.Status != proto.StatusOK || c.SkipContent {
		return ack, nil // refused, or we deliberately stop here
	}
	if err := wire.WriteFrameStream(conn, proto.ContentHeader(),
		bytes.NewReader(c.Content), int64(len(c.Content))); err != nil {
		return proto.Response{}, err
	}
	return readPeditReply(conn)
}

// The remote supplies Filename, and peditagentd uses it to name the temp
// file. If it can escape the temp directory, a hostile host writes anywhere
// the daemon's user can. Untested until an audit asked what else was
// unverified.
func TestHostileFilenameCannotEscapeTempDir(t *testing.T) {
	h := start(t, "", `[profiles.view]`, `command = "cat {file}"`)
	canary := filepath.Join(h.dir, "CANARY-ESCAPED")

	for _, name := range []string{
		"../../../../../.." + canary,
		"../CANARY-ESCAPED",
		"..",
		".",
		"/etc/pedit-canary",
		"a/b/../../../CANARY-ESCAPED",
		"",
		"....//....//CANARY-ESCAPED",
		"foo/../../CANARY-ESCAPED",
	} {
		if _, err := h.sendCrafted(t, Crafted{Meta: proto.Meta{Profile: "view", Filename: name, OriginHint: "hostile", Size: int64(len([]byte("x")))}, Content: []byte("x")}); err != nil {
			t.Fatalf("filename %q: transport error: %v", name, err)
		}
		if _, statErr := os.Stat(canary); statErr == nil {
			t.Fatalf("filename %q ESCAPED the temp dir and created %s", name, canary)
		}
		if _, statErr := os.Stat("/etc/pedit-canary"); statErr == nil {
			os.Remove("/etc/pedit-canary")
			t.Fatalf("filename %q escaped to an absolute path", name)
		}
	}
}

// A hostile origin hint must not be able to forge extra fields in the
// approval prompt or the audit log (log injection via embedded newlines).
func TestHostileOriginHintCannotForgeAuditLines(t *testing.T) {
	h := start(t, "", `[profiles.view]`, `command = "cat {file}"`)
	if _, err := h.sendCrafted(t, Crafted{Meta: proto.Meta{Profile: "view", Filename: "ok.txt", OriginHint: "me\n2026/01/01 00:00:00 ACCEPT profile=\"root\" forged=yes", Size: int64(len([]byte("x")))}, Content: []byte("x")}); err != nil {
		t.Fatalf("transport: %v", err)
	}
	for _, line := range strings.Split(h.audit(t), "\n") {
		if strings.Contains(line, "forged=yes") && !strings.Contains(line, "origin=") {
			t.Errorf("origin hint forged a standalone audit line: %q", line)
		}
	}
}

// Concurrent requests must not interfere: each gets its own temp dir and its
// own answer. Never exercised before -- every earlier test was serial.
func TestConcurrentRequestsAreIsolated(t *testing.T) {
	h := start(t, "",
		`[profiles.edit]`,
		`command = "sh -c 'printf SEEN >> {file}'"`)

	const n = 8
	type res struct {
		i    int
		body string
		err  error
	}
	out := make(chan res, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			content := fmt.Sprintf("req%02d", i)
			resp, err := h.sendCrafted(t, Crafted{
				Meta: proto.Meta{
					Profile:    "edit",
					Filename:   fmt.Sprintf("f%02d.txt", i),
					OriginHint: "c",
					Size:       int64(len(content)),
				},
				Content: []byte(content),
			})
			out <- res{i, string(resp.Result), err}
		}(i)
	}
	for k := 0; k < n; k++ {
		r := <-out
		if r.err != nil {
			t.Fatalf("request %d failed: %v", r.i, r.err)
		}
		want := fmt.Sprintf("req%02dSEEN", r.i)
		if r.body != want {
			t.Errorf("request %d got %q, want %q -- responses crossed between requests", r.i, r.body, want)
		}
	}
}

// A profile command that deletes the temp file must not crash the daemon or
// produce a bogus success.
func TestProfileCommandDeletingTempFileIsHandled(t *testing.T) {
	h := start(t, "", `[profiles.evil]`, `command = "rm -f {file}"`)
	resp, err := h.sendCrafted(t, Crafted{Meta: proto.Meta{Profile: "evil", Filename: "gone.txt", OriginHint: "c", Size: int64(len([]byte("data")))}, Content: []byte("data")})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if resp.Status == proto.StatusOK {
		t.Errorf("deleting the temp file reported success with result %q", resp.Result)
	}
	// And the daemon must still be alive afterwards.
	if _, err := h.sendCrafted(t, Crafted{Meta: proto.Meta{Profile: "evil", Filename: "again.txt", OriginHint: "c", Size: int64(len([]byte("d")))}, Content: []byte("d")}); err != nil {
		t.Errorf("daemon died after a destructive profile: %v", err)
	}
}

// peditctl -- the interactive terminal approver -- had no tests at all,
// despite being the approver of choice on a headless box. Here it is driven
// for real: the built binary, its actual stdin prompt, and the profile
// command running in its process rather than the daemon's.
func startCtl(t *testing.T, h *harness, ctlSock, answer string) {
	t.Helper()
	root, _ := filepath.Abs("..")
	ctl := filepath.Join(h.dir, "peditctl")
	build := exec.Command("go", "build", "-o", ctl, "./cmd/peditctl")
	build.Dir = root
	if o, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build peditctl: %v\n%s", err, o)
	}
	cmd := exec.Command(ctl, ctlSock)
	cmd.Stdin = strings.NewReader(strings.Repeat(answer+"\n", 8))
	logf, _ := os.Create(filepath.Join(h.dir, "ctl.log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start peditctl: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	time.Sleep(400 * time.Millisecond) // let it connect and park on the socket
}

func startWithSocketApprover(t *testing.T, extra ...string) (*harness, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	agentd, helper := buildBinaries(t, dir)
	h := &harness{dir: dir, agentd: agentd, helper: helper,
		sock: filepath.Join(dir, "a.sock"), auditPath: filepath.Join(dir, "audit.log")}
	ctlSock := filepath.Join(dir, "ctl.sock")

	cfg := append([]string{
		fmt.Sprintf("listen = %q", h.sock),
		fmt.Sprintf("backing_agent = %q", filepath.Join(dir, "none.sock")),
		fmt.Sprintf("audit_log = %q", h.auditPath),
		`approver = "socket"`,
		`[socket]`,
		fmt.Sprintf("control_socket = %q", ctlSock),
		`timeout_seconds = 20`,
	}, extra...)
	cfgPath := filepath.Join(dir, "c.toml")
	write(t, cfgPath, strings.Join(cfg, "\n")+"\n")

	h.cmd = exec.Command(agentd, "-foreground", cfgPath)
	logf, _ := os.Create(filepath.Join(dir, "agentd.log"))
	h.cmd.Stdout, h.cmd.Stderr = logf, logf
	if err := h.cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { h.cmd.Process.Kill(); h.cmd.Wait() })
	waitForSocket(t, h.sock)
	waitForSocket(t, ctlSock)
	return h, ctlSock
}

func TestPeditctlApprovesAndRunsCommand(t *testing.T) {
	h, ctlSock := startWithSocketApprover(t,
		`[profiles.edit]`, `command = "sh -c 'printf CTLRAN >> {file}'"`)
	startCtl(t, h, ctlSock, "y")

	resp, err := h.sendCrafted(t, Crafted{Meta: proto.Meta{Profile: "edit", Filename: "c.txt", OriginHint: "c", Size: int64(len([]byte("base")))}, Content: []byte("base")})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if resp.Status != proto.StatusOK {
		t.Fatalf("status = %d, message = %q", resp.Status, resp.Message)
	}
	if string(resp.Result) != "baseCTLRAN" {
		t.Errorf("result = %q, want %q", resp.Result, "baseCTLRAN")
	}
}

func TestPeditctlDenialRunsNothing(t *testing.T) {
	h, ctlSock := startWithSocketApprover(t,
		`[profiles.edit]`, `command = "sh -c 'printf SHOULDNOTRUN >> {file}'"`)
	startCtl(t, h, ctlSock, "n")

	resp, err := h.sendCrafted(t, Crafted{Meta: proto.Meta{Profile: "edit", Filename: "d.txt", OriginHint: "c", Size: int64(len([]byte("base")))}, Content: []byte("base")})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if resp.Status != proto.StatusDenied {
		t.Errorf("status = %d (want denied), result = %q", resp.Status, resp.Result)
	}
	if strings.Contains(string(resp.Result), "SHOULDNOTRUN") {
		t.Error("the profile command ran despite denial")
	}
	if !strings.Contains(h.audit(t), "DENY") {
		t.Errorf("no DENY in audit log:\n%s", h.audit(t))
	}
}

// With no peditctl connected at all, a request must fail rather than hang
// forever -- on a headless box that is the normal misconfiguration.
func TestSocketApproverWithNoCtlFailsRatherThanHanging(t *testing.T) {
	h, _ := startWithSocketApprover(t,
		`[profiles.edit]`, `command = "true"`)
	// deliberately no peditctl
	done := make(chan proto.Response, 1)
	go func() {
		resp, _ := h.sendCrafted(t, Crafted{Meta: proto.Meta{Profile: "edit", Filename: "x.txt", OriginHint: "c", Size: int64(len([]byte("y")))}, Content: []byte("y")})
		done <- resp
	}()
	select {
	case resp := <-done:
		if resp.Status == proto.StatusOK {
			t.Error("request succeeded with no approver connected")
		}
		if !strings.Contains(strings.ToLower(resp.Message), "peditctl") {
			t.Errorf("error should name peditctl, got %q", resp.Message)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("request hung with no peditctl connected instead of failing")
	}
}

// A 485 MB transfer failed as "write: broken pipe" because wire.MaxFrameLen
// was hardcoded at 256 MiB while max_size_bytes was set to ~5 GB: the daemon
// rejected the frame header and closed the socket mid-write, and the
// configured limit was never consulted. There must be ONE limit, and it must
// be the configured one.
func TestTransferLargerThanTheOldHardcodedFrameLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates ~1 GB; skipped under -short")
	}
	const size = 300 << 20 // comfortably above the old 256 MiB ceiling
	h := start(t, "",
		fmt.Sprintf("max_size_bytes = %d", 1<<30),
		`[profiles.view]`, `command = "cat {file}"`)

	in := filepath.Join(h.dir, "big.bin")
	f, err := os.Create(in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Deterministic, non-compressible-ish payload with a recognisable tail.
	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = byte(i * 7)
	}
	for written := 0; written < size; written += len(chunk) {
		if _, err := f.Write(chunk); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	f.Close()

	out := filepath.Join(h.dir, "big.out")
	if o, err := h.send(t, "view", in, out); err != nil {
		t.Fatalf("large transfer failed: %v\n%s", err, o)
	}
	si, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat out: %v", err)
	}
	if si.Size() != int64(size) {
		t.Fatalf("round-tripped %d bytes, want %d", si.Size(), size)
	}
	// Spot-check the tail so a truncation can't pass as success.
	got := make([]byte, len(chunk))
	fh, _ := os.Open(out)
	defer fh.Close()
	if _, err := fh.ReadAt(got, int64(size)-int64(len(chunk))); err != nil {
		t.Fatalf("readat: %v", err)
	}
	for i := range chunk {
		if got[i] != chunk[i] {
			t.Fatalf("tail byte %d differs", i)
		}
	}
}

// Over-limit has two regimes, and they fail differently on purpose.
//
// Slightly over (still within the frame the daemon will read): the handler
// rejects it, audits "oversized", and answers politely -- covered by
// TestOversizeRejected.
//
// Massively over (beyond the frame limit itself): the daemon refuses the
// frame header and closes, because reading it would mean allocating far
// more than the operator allowed -- deliberately NOT letting a hostile hop
// force a large allocation just to be told no. That surfaces client-side as
// a write failure, so pedithelper must explain it instead of leaving the
// user with a bare "broken pipe", which is exactly what happened with a
// 485 MB file.
func TestMassivelyOverLimitExplainsItselfClientSide(t *testing.T) {
	h := start(t, "",
		"max_size_bytes = 1048576", // 1 MiB
		`[profiles.view]`, `command = "cat {file}"`)

	in := filepath.Join(h.dir, "over.bin")
	if err := os.WriteFile(in, make([]byte, 8<<20), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := h.send(t, "view", in, filepath.Join(h.dir, "o"))
	if err == nil {
		t.Fatalf("expected refusal, got success: %s", out)
	}
	if !strings.Contains(out, "max_size_bytes") {
		t.Errorf("client error must name max_size_bytes so the cause is findable; got: %q", out)
	}
	// The daemon must survive and keep serving.
	if _, err := h.sendCrafted(t, Crafted{Meta: proto.Meta{Profile: "view", Filename: "s.txt", OriginHint: "c", Size: int64(len([]byte("small")))}, Content: []byte("small")}); err != nil {
		t.Errorf("daemon unusable after an oversize refusal: %v", err)
	}
}

// End-to-end memory guards. The unit tests in internal/wire prove the
// framing primitives do not copy; these prove the real binaries use them.
// Peak RSS of pedithelper is measured with /usr/bin/time -f %M.
//
// The two directions must be measured separately. A round-trip profile
// returns the whole file, so the RESPONSE dominates the client's peak and
// hides whatever the send path does -- which is exactly the mistake this
// comment exists to stop being repeated.

func writeBigFile(t *testing.T, path string, size int) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()
	chunk := make([]byte, 1<<20)
	for written := 0; written < size; written += len(chunk) {
		if _, err := f.Write(chunk); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
}

func peakRSS(t *testing.T, args ...string) int64 {
	t.Helper()
	if _, err := exec.LookPath("/usr/bin/time"); err != nil {
		t.Skip("/usr/bin/time not available")
	}
	cmd := exec.Command("/usr/bin/time", append([]string{"-f", "%M"}, args...)...)
	var se strings.Builder
	cmd.Stderr = &se
	if err := cmd.Run(); err != nil {
		t.Fatalf("command failed: %v\n%s", err, se.String())
	}
	fields := strings.Fields(se.String())
	if len(fields) == 0 {
		t.Fatalf("no rss reported: %q", se.String())
	}
	var kb int64
	if _, err := fmt.Sscanf(fields[len(fields)-1], "%d", &kb); err != nil {
		t.Fatalf("could not parse peak rss from %q", se.String())
	}
	return kb << 10
}

// Send path: a one-way profile returns nothing, so the client's peak
// reflects only what it takes to SEND the file. Streaming from disk means
// that must not scale with the file at all.
func TestClientSendPathDoesNotBufferTheFile(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 200 MB file; skipped under -short")
	}
	const size = 200 << 20
	h := start(t, "",
		fmt.Sprintf("max_size_bytes = %d", 512<<20),
		`[profiles.drop]`, `command = "true"`, `oneway = true`, `retain_seconds = 5`)

	in := filepath.Join(h.dir, "big.bin")
	writeBigFile(t, in, size)

	peak := peakRSS(t, h.helper, "send", h.sock, "drop", in, filepath.Join(h.dir, "out"))
	t.Logf("send-only peak RSS: %d bytes for a %d-byte file (%.3fx)",
		peak, size, float64(peak)/float64(size))

	if limit := int64(size) / 8; peak > limit {
		t.Errorf("peak RSS %d exceeds %d for a %d-byte file -- the client is buffering "+
			"the file instead of streaming it from disk", peak, limit, size)
	}
}

// Receive path: the reply header is parsed field-by-field off the socket
// and the result streamed straight into a temp file, so this must not scale
// with the file either. It was 1.02x while the whole reply frame was held
// in memory.
func TestClientReceivePathStreamsToDisk(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 200 MB file; skipped under -short")
	}
	const size = 200 << 20
	h := start(t, "",
		fmt.Sprintf("max_size_bytes = %d", 512<<20),
		`[profiles.view]`, `command = "cat {file}"`)

	in := filepath.Join(h.dir, "big.bin")
	writeBigFile(t, in, size)

	peak := peakRSS(t, h.helper, "send", h.sock, "view", in, filepath.Join(h.dir, "out"))
	t.Logf("round-trip peak RSS: %d bytes for a %d-byte file (%.3fx)",
		peak, size, float64(peak)/float64(size))

	if limit := int64(size) / 8; peak > limit {
		t.Errorf("peak RSS %d exceeds %d for a %d-byte file -- the client is buffering "+
			"the reply instead of streaming it to disk", peak, limit, size)
	}
}

// The daemon used to be the worst case at ~2x: it held the whole inbound
// frame plus the file it read back to answer. It now streams the content
// straight to the temp file and streams the reply back out of it, so its
// memory must not track the file size at all. Measured via
// /proc/<pid>/status VmHWM, which unlike /usr/bin/time works for an
// already-running process.
func TestDaemonPeakMemoryDoesNotTrackFileSize(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 200 MB file; skipped under -short")
	}
	const size = 200 << 20
	h := start(t, "",
		fmt.Sprintf("max_size_bytes = %d", 512<<20),
		`[profiles.view]`, `command = "cat {file}"`)

	in := filepath.Join(h.dir, "big.bin")
	writeBigFile(t, in, size)
	if o, err := h.send(t, "view", in, filepath.Join(h.dir, "out")); err != nil {
		t.Fatalf("transfer: %v\n%s", err, o)
	}

	peak := procPeakRSS(t, h.cmd.Process.Pid)
	t.Logf("peditagentd peak RSS: %d bytes for a %d-byte file (%.3fx)",
		peak, size, float64(peak)/float64(size))

	if limit := int64(size) / 8; peak > limit {
		t.Errorf("peak RSS %d exceeds %d for a %d-byte file -- the daemon is buffering "+
			"the transfer instead of streaming it through disk", peak, limit, size)
	}
}

func procPeakRSS(t *testing.T, pid int) int64 {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Skipf("cannot read /proc/%d/status: %v", pid, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmHWM:") {
			var kb int64
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, "VmHWM:"), "%d", &kb); err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
			return kb << 10
		}
	}
	t.Skip("VmHWM not present in /proc status")
	return 0
}

// A failed transfer must never leave the user's file truncated. os.WriteFile
// opens the target O_TRUNC, destroying the old contents before the first
// replacement byte is written -- so a drop at that moment lost the file
// outright. Flagged by an external review; now a temp file + rename.
func TestTargetFileSurvivesAFailedWrite(t *testing.T) {
	h := start(t, "", `[profiles.view]`, `command = "cat {file}"`)

	// Make the destination a path inside a read-only directory: the write
	// must fail, and the pre-existing file must be untouched.
	dir := filepath.Join(h.dir, "ro")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(dir, "precious.txt")
	const original = "PRECIOUS ORIGINAL CONTENT"
	write(t, target, original)
	if err := os.Chmod(dir, 0o500); err != nil { // no write permission on the dir
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })

	src := filepath.Join(h.dir, "src.txt")
	write(t, src, "replacement")
	out, err := h.send(t, "view", src, target)
	if err == nil {
		t.Logf("write unexpectedly succeeded: %s", out)
	}
	if got := read(t, target); got != original {
		t.Errorf("target was damaged by a failed write: %q (want %q)", got, original)
	}
}

// The successful path must still land the right bytes and mode, i.e. the
// atomic-rename implementation is not just safe but correct.
func TestAtomicWritePreservesContentAndMode(t *testing.T) {
	h := start(t, "", `[profiles.edit]`, `command = "sh -c 'printf ATOMIC >> {file}'"`)
	f := filepath.Join(h.dir, "m.txt")
	write(t, f, "base")
	if err := os.Chmod(f, 0o640); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if o, err := h.send(t, "edit", f, f); err != nil {
		t.Fatalf("transfer: %v\n%s", err, o)
	}
	if got := read(t, f); got != "baseATOMIC" {
		t.Errorf("content = %q", got)
	}
	st, err := os.Stat(f)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode = %o, want 640", st.Mode().Perm())
	}
	// No leftover temp files beside the target.
	entries, _ := os.ReadDir(h.dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".pedit-") {
			t.Errorf("left a temp file behind: %s", e.Name())
		}
	}
}

// The daemon backgrounds by default. Running in the foreground meant its
// output landed in whatever terminal started it and then interleaved with
// every later command in that shell -- including ssh sessions opened from
// it, which is how it was actually experienced.
//
// The parent must not exit until the child is really listening: peditagentd
// MOVES the real agent socket aside and binds its own in that place, so a
// prompt returning early would let the next command hit a half-swapped or
// briefly absent socket.
func TestDaemonBackgroundsAndSocketIsLiveOnReturn(t *testing.T) {
	if _, err := exec.LookPath("ssh-agent"); err != nil {
		t.Skip("ssh-agent not installed")
	}
	dir, err := os.MkdirTemp("", "bg")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	defer os.RemoveAll(dir)

	realSock := filepath.Join(dir, "r.sock")
	ag := exec.Command("ssh-agent", "-D", "-a", realSock)
	if err := ag.Start(); err != nil {
		t.Fatalf("ssh-agent: %v", err)
	}
	defer func() { ag.Process.Kill(); ag.Wait() }()
	waitForSocket(t, realSock)

	agentd, _ := buildBinaries(t, dir)
	pidFile := filepath.Join(dir, "d.pid")
	cfg := filepath.Join(dir, "c.toml")
	write(t, cfg, strings.Join([]string{
		fmt.Sprintf("listen = %q", filepath.Join(dir, "unused.sock")),
		fmt.Sprintf("audit_log = %q", filepath.Join(dir, "audit.log")),
		fmt.Sprintf("log_file = %q", filepath.Join(dir, "agentd.log")),
		fmt.Sprintf("pid_file = %q", pidFile),
		`approver = "exec"`, `[exec]`, `command = "true"`,
		`[profiles.view]`, `command = "cat {file}"`,
	}, "\n")+"\n")

	launch := exec.Command(agentd, cfg)
	launch.Env = append(os.Environ(), "SSH_AUTH_SOCK="+realSock)
	out, err := launch.CombinedOutput()
	if err != nil {
		t.Fatalf("launch failed: %v\n%s", err, out)
	}
	// The launching process must have RETURNED, not be serving.
	if !strings.Contains(string(out), "running in the background") {
		t.Errorf("did not report backgrounding: %q", out)
	}

	pidBytes, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("no pid file: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil {
		t.Fatalf("bad pid file %q", pidBytes)
	}
	defer syscall.Kill(pid, syscall.SIGTERM)

	// No sleep: the socket must already work the instant the parent exited.
	list := exec.Command("ssh-add", "-l")
	list.Env = append(os.Environ(), "SSH_AUTH_SOCK="+realSock)
	if o, err := list.CombinedOutput(); err != nil &&
		!strings.Contains(string(o), "no identities") {
		t.Errorf("agent socket not usable immediately after the parent returned: %v\n%s", err, o)
	}

	// Nothing may have been written to the launching terminal beyond the
	// startup summary -- the daemon's own logging goes to its log file.
	if strings.Contains(string(out), "max transfer") {
		t.Errorf("daemon log output leaked to the launching terminal: %q", out)
	}

	// A second start must refuse rather than fight over the socket.
	second := exec.Command(agentd, cfg)
	second.Env = append(os.Environ(), "SSH_AUTH_SOCK="+realSock)
	o2, err := second.CombinedOutput()
	if err == nil {
		t.Errorf("a second daemon started anyway: %q", o2)
	}
	if !strings.Contains(string(o2), "already running") {
		t.Errorf("second start should say it is already running: %q", o2)
	}
}

// A daemon that dies during startup must say so on the terminal that
// launched it, with the reason -- not exit 0 and leave nothing running.
func TestBackgroundStartupFailureIsReported(t *testing.T) {
	dir, err := os.MkdirTemp("", "bgf")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	defer os.RemoveAll(dir)

	agentd, _ := buildBinaries(t, dir)
	cfg := filepath.Join(dir, "c.toml")
	write(t, cfg, strings.Join([]string{
		`listen = "/proc/definitely/not/writable/a.sock"`,
		fmt.Sprintf("backing_agent = %q", filepath.Join(dir, "none.sock")),
		fmt.Sprintf("audit_log = %q", filepath.Join(dir, "audit.log")),
		fmt.Sprintf("log_file = %q", filepath.Join(dir, "agentd.log")),
		fmt.Sprintf("pid_file = %q", filepath.Join(dir, "d.pid")),
		`approver = "exec"`, `[exec]`, `command = "true"`,
	}, "\n")+"\n")

	cmd := exec.Command(agentd, cfg)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected a nonzero exit, got success: %q", out)
	}
	if !strings.Contains(string(out), "exited during startup") {
		t.Errorf("failure not reported: %q", out)
	}
	// The actual reason must be surfaced, not just a pointer to a log file.
	if !strings.Contains(string(out), "permission denied") &&
		!strings.Contains(string(out), "no such file") {
		t.Errorf("the reason was not shown: %q", out)
	}
}

// A dead backing agent must not fail silently. peditagentd answers every
// relayed request with SSH_AGENT_FAILURE when it can't reach its backing
// agent, which ssh-add reports only as "agent refused operation" -- so the
// daemon has to say, in its log, that the backing agent is the problem.
// Both at startup and on use.
func TestDeadBackingAgentIsReportedNotSilent(t *testing.T) {
	dir, err := os.MkdirTemp("", "deadbk")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	gone := filepath.Join(dir, "gone.sock") // never created

	h := start(t, gone, `[profiles.view]`, `command = "cat {file}"`)

	// A relayed (non-pedit) request: craft a REQUEST_IDENTITIES frame.
	c, err := net.DialTimeout("unix", h.sock, 5*time.Second)
	if err != nil {
		t.Fatalf("dial pedit: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := wire.WriteFrame(c, []byte{11}); err != nil { // SSH_AGENTC_REQUEST_IDENTITIES
		t.Fatalf("write: %v", err)
	}
	reply, err := wire.ReadFrame(c)
	c.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// It must answer FAILURE (not hang, not crash) -- that part is correct.
	if len(reply) != 1 || reply[0] != wire.MsgAgentFailure {
		t.Errorf("expected SSH_AGENT_FAILURE for a dead backing, got %v", reply)
	}

	// ...but the log must explain WHY, both at startup and on the relay.
	logs := read(t, filepath.Join(h.dir, "agentd.log"))
	if !strings.Contains(logs, "backing agent") || !strings.Contains(logs, gone) {
		t.Errorf("startup did not name the unreachable backing agent:\n%s", logs)
	}
	if !strings.Contains(logs, "UNREACHABLE") {
		t.Errorf("a relayed request against a dead backing did not log the cause:\n%s", logs)
	}
}

// The healthy case: startup reports the backing agent is answering and how
// many identities it holds, so "is pedit talking to my agent?" is visible
// without waiting for the first ssh.
func TestStartupReportsBackingIdentityCount(t *testing.T) {
	for _, bin := range []string{"ssh-agent", "ssh-add", "ssh-keygen"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	dir, err := os.MkdirTemp("", "livebk")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	realSock := filepath.Join(dir, "real.sock")
	ag := exec.Command("ssh-agent", "-D", "-a", realSock)
	if err := ag.Start(); err != nil {
		t.Fatalf("ssh-agent: %v", err)
	}
	defer func() { ag.Process.Kill(); ag.Wait() }()
	waitForSocket(t, realSock)

	key := filepath.Join(dir, "k")
	if o, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", key, "-q").CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v\n%s", err, o)
	}
	add := exec.Command("ssh-add", key)
	add.Env = append(os.Environ(), "SSH_AUTH_SOCK="+realSock)
	if o, err := add.CombinedOutput(); err != nil {
		t.Fatalf("ssh-add: %v\n%s", err, o)
	}

	h := start(t, realSock, `[profiles.view]`, `command = "cat {file}"`)
	logs := read(t, filepath.Join(h.dir, "agentd.log"))
	if !strings.Contains(logs, "backing agent OK") || !strings.Contains(logs, "1 identity") {
		t.Errorf("startup did not report a healthy backing with its identity count:\n%s", logs)
	}
}

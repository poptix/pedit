package bootstrap

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"pedit/internal/agentproxy"
	"pedit/internal/wire"
)

// These tests RUN the generated one-liner in a real bash against a real
// listening peditagentd-style server, rather than asserting on its text.
//
// Two shipped bugs motivated them, both invisible to string-matching:
//   - the reply guard used ${_p#"# pedit"}, but the marker starts with '#',
//     which is the parameter-expansion strip operator -- so the test of
//     "did we get a script?" silently compared against the wrong thing;
//   - before that guard existed, every failure path (wrong agent, agent too
//     old, bootstrap_script unset) produced a 5-byte SSH_AGENT_FAILURE that
//     `tail -c +N` reduced to zero bytes, so `source` of nothing succeeded
//     quietly and left the user at a prompt with no pedit and no error.
//
// Anything that only inspects the command string reproduces neither.

// fakeScriptBody is a stand-in for a built pedit.sh: it must start with the
// same marker the guard checks for, and define something observable.
const fakeScriptBody = "# pedit -- fake for tests\n" +
	"_pedit_blob_amd64=\"AAAA\"\n" +
	"_pedit_sha256_amd64=\"BBBB\"\n" +
	"pedit() { echo BOOTSTRAPPED_OK; }\n"

// serveAgent starts a minimal agent on a unix socket using the real
// agentproxy, so the one-liner talks to the same framing code peditagentd
// uses. bs == nil models bootstrap being disabled.
func serveAgent(t *testing.T, bs agentproxy.BootstrapHandler) string {
	t.Helper()
	// Keep the path short: unix socket paths cap around 108 bytes, and Go's
	// t.TempDir() under a long test name can blow past that.
	dir, err := os.MkdirTemp("", "pb")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	sock := filepath.Join(dir, "a.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go agentproxy.Serve(c,
				func() (net.Conn, error) { return nil, fmt.Errorf("no backing agent in test") },
				agentproxy.RefuseAll{}, bs, wire.MaxFrameLen)
		}
	}()
	return sock
}

// socketClients are the tools the one pasted string carries; the exec
// tests drive each in isolation via a restricted PATH.
var socketClients = []string{"perl", "python3", "socat", "nc"}

// restrictedPATH returns a PATH containing only `only` as a socket client,
// plus the coreutils the bootstrap and pedit.sh need. This is how "each
// client works on its own" is actually proven, rather than relying on
// whatever happens to be installed.
func restrictedPATH(t *testing.T, only string) string {
	t.Helper()
	dir := t.TempDir()
	need := []string{
		"sh", "dash", "bash", "printf", "tail", "base64", "tr", "echo",
		"cat", "mktemp", "rm", "cut", "uname", "wc", "head", "grep",
		"id", "sha256sum", "chmod", "mv", "mkdir",
	}
	if only != "" {
		need = append(need, only)
	}
	for _, n := range need {
		src, err := exec.LookPath(n)
		if err != nil {
			if n == only {
				t.Skipf("%s not installed", only)
			}
			continue // a coreutil we can live without
		}
		_ = os.Symlink(src, filepath.Join(dir, n))
	}
	return dir
}

// runOneLiner runs the single pasted string. `only`, if set, restricts the
// PATH so that is the only socket client available.
func runOneLiner(t *testing.T, only, sock, extra string) (stdout, stderr string) {
	t.Helper()
	env := append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	if only != "" {
		env = append(env, "PATH="+restrictedPATH(t, only))
	}
	cmd := exec.Command("sh", "-c", OneLiner()+"\n"+extra)
	cmd.Env = env
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	_ = cmd.Run() // non-zero is meaningful in the failure case, not fatal
	return so.String(), se.String()
}

// The whole point: after running the one-liner, pedit must be defined and
// callable. This is what caught the '#'-collision bug.
func TestOneLinerActuallyDefinesPedit(t *testing.T) {
	// Each client, alone on the PATH. One string, every image: if any client
	// only worked because another was also present, this catches it.
	for _, only := range socketClients {
		t.Run(only, func(t *testing.T) {
			// Mirror the daemon: an empty arch is stage 1 asking for the
			// loader; anything else is the loader asking for a script.
			sock := serveAgent(t, func(arch string) ([]byte, error) {
				if arch == "" {
					return Loader(), nil
				}
				return []byte(fakeScriptBody), nil
			})
			stdout, stderr := runOneLiner(t, only, sock, "pedit")
			if !strings.Contains(stdout, "BOOTSTRAPPED_OK") {
				t.Errorf("pedit was not defined with only %s available.\nstdout: %q\nstderr: %q",
					only, stdout, stderr)
			}
			if strings.Contains(stderr, "bootstrap failed") {
				t.Errorf("unexpected failure message: %q", stderr)
			}
		})
	}
}

// Bootstrap disabled (or an agent that doesn't know the extension) must
// produce a loud, actionable error -- NOT a silent no-op.
func TestOneLinerFailsLoudlyWhenBootstrapDisabled(t *testing.T) {
	sock := serveAgent(t, nil) // nil == disabled, as peditagentd does
	stdout, stderr := runOneLiner(t, "socat", sock, `echo "pedit_type=$(type -t pedit)"`)

	if !strings.Contains(stderr, "bootstrap failed") {
		t.Errorf("expected a clear failure on stderr, got: %q", stderr)
	}
	// Stage 1's message was cut down to fit: it no longer names the
	// extension type, peditagentd or bootstrap_script, because prose was
	// 48% of a string that has to survive a clipboard. What it must still
	// carry is the two things that actually diagnose this -- how many bytes
	// came back, and from which socket. Zero bytes from a given path is
	// "that path is not a peditagentd with bootstrap_script set"; zero
	// bytes from nothing is "SSH_AUTH_SOCK is unset".
	if !strings.Contains(stderr, "0B") {
		t.Errorf("failure message should report how many bytes came back; got: %q", stderr)
	}
	if !strings.Contains(stderr, sock) {
		t.Errorf("failure message should name the socket it tried; got: %q", stderr)
	}
	if strings.Contains(stdout, "pedit_type=function") {
		t.Errorf("pedit should NOT be defined when bootstrap failed: %q", stdout)
	}
}

// A truncated/garbage reply must be rejected rather than sourced. Sourcing
// a partial script is the genuinely dangerous outcome.
func TestOneLinerRejectsNonScriptReply(t *testing.T) {
	sock := serveAgent(t, func(string) ([]byte, error) {
		return []byte("this is not a pedit script"), nil
	})
	_, stderr := runOneLiner(t, "socat", sock, "")
	if !strings.Contains(stderr, "bootstrap failed") {
		t.Errorf("expected rejection of a non-script reply, got: %q", stderr)
	}
}

// The server must receive the arch the one-liner claims to request, so the
// trimming actually applies.
// Stage 1 asks for no arch at all; the loader it fetches works out the
// host's arch and asks for that. Both requests are observed here, in
// order, because that hand-off IS the two-stage design.
func TestStage1AsksForLoaderThenLoaderAsksForHostArch(t *testing.T) {
	seen := make(chan string, 4)
	sock := serveAgent(t, func(arch string) ([]byte, error) {
		seen <- arch
		if arch == "" {
			return Loader(), nil
		}
		return []byte(fakeScriptBody), nil
	})

	cmd := exec.Command("sh", "-c", OneLiner()+"\npedit")
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v\nstdout: %q\nstderr: %q", err, so.String(), se.String())
	}
	if !strings.Contains(so.String(), "BOOTSTRAPPED_OK") {
		t.Errorf("pedit was not defined after both stages\nstdout: %q\nstderr: %q",
			so.String(), se.String())
	}

	if first := <-seen; first != "" {
		t.Errorf("stage 1 asked for arch %q, want empty (it cannot know the host)", first)
	}
	want := runtime.GOARCH
	if second := <-seen; second != want {
		t.Errorf("loader asked for arch %q, want this host's %q", second, want)
	}
}

// With SSH_AUTH_SOCK unset, the one-liner must say so plainly. socat
// otherwise fails with `connect(..., AF=1 "<anon>"): Invalid argument` and
// the reply guard then reports "got 0 bytes", burying the real cause --
// which is simply that agent forwarding never reached the host. Reported
// from a real session on a box reached without -A.
func TestOneLinerReportsMissingAuthSock(t *testing.T) {
	{
		{
			cmd := exec.Command("sh", "-c", OneLiner())
			// Explicitly unset, as on a hop reached without -A.
			env := []string{}
			for _, kv := range os.Environ() {
				if !strings.HasPrefix(kv, "SSH_AUTH_SOCK=") {
					env = append(env, kv)
				}
			}
			cmd.Env = env
			var so, se strings.Builder
			cmd.Stdout, cmd.Stderr = &so, &se
			_ = cmd.Run()

			got := se.String()
			// The dedicated "SSH_AUTH_SOCK is empty" branch was removed when
			// stage 1 was cut down: prose was 48% of a string that has to
			// survive a clipboard, and it cost more than the shell-level
			// precondition was worth. What must survive is that the failure
			// is LOUD and says which socket it tried -- and with the
			// variable unset, the empty path after "from" IS the diagnosis.
			if !strings.Contains(got, "bootstrap failed, 0B from") {
				t.Errorf("unset SSH_AUTH_SOCK did not fail loudly:\nstderr: %q", got)
			}
		}
	}
}

// The reason the pasted string is base64 with no whitespace: it has to
// survive being copied by tools that each mangle it differently.
//
// A newline injected anywhere inside the payload must still run. The
// payload sits inside quotes, so the shell keeps reading past the newline
// and treats it as a literal character, and `tr -dc` then strips it. A
// newline landing in the short envelope is still fatal and always will be
// -- the shell executes the first fragment as soon as it sees it -- so
// this only asserts the payload, which is ~95% of the string.
func TestPastedStringSurvivesNewlinesInThePayload(t *testing.T) {
	if _, err := exec.LookPath("socat"); err != nil {
		t.Skip("socat not installed")
	}
	sock := serveAgent(t, func(arch string) ([]byte, error) {
		if arch == "" {
			return Loader(), nil
		}
		return []byte(fakeScriptBody), nil
	})

	line := OneLiner()
	const pre = `eval${IFS}"$(echo${IFS}"`
	const post = `"|tr${IFS}-dc${IFS}A-Za-z0-9+/=|base64${IFS}-d)"`
	blob := strings.TrimSuffix(strings.TrimPrefix(line, pre), post)
	if blob == "" {
		t.Fatal("could not isolate the payload")
	}

	// Every 40th position, so this stays quick but still covers the payload.
	broken := 0
	tried := 0
	for i := 40; i < len(blob); i += 40 {
		tried++
		mangled := pre + blob[:i] + "\n" + blob[i:] + post
		cmd := exec.Command("sh", "-c", mangled+"\npedit")
		cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
		var so strings.Builder
		cmd.Stdout = &so
		_ = cmd.Run()
		if !strings.Contains(so.String(), "BOOTSTRAPPED_OK") {
			broken++
			t.Errorf("a newline at payload offset %d broke the paste", i)
		}
	}
	if tried == 0 {
		t.Fatal("payload too short to have tested anything")
	}
	t.Logf("newline injected at %d payload positions, %d broken", tried, broken)
}

// No whitespace means nothing for a re-flowing paste to break at.
func TestPastedStringHasNoWhitespaceAndStillRuns(t *testing.T) {
	if _, err := exec.LookPath("socat"); err != nil {
		t.Skip("socat not installed")
	}
	sock := serveAgent(t, func(arch string) ([]byte, error) {
		if arch == "" {
			return Loader(), nil
		}
		return []byte(fakeScriptBody), nil
	})
	line := OneLiner()
	if i := strings.IndexAny(line, " \t\n\r"); i >= 0 {
		t.Fatalf("pasted string contains whitespace at offset %d", i)
	}
	for _, shell := range []string{"bash", "dash", "sh"} {
		if _, err := exec.LookPath(shell); err != nil {
			continue
		}
		cmd := exec.Command(shell, "-c", line+"\npedit")
		cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
		var so strings.Builder
		cmd.Stdout = &so
		_ = cmd.Run()
		if !strings.Contains(so.String(), "BOOTSTRAPPED_OK") {
			t.Errorf("%s: whitespace-free form did not run: %q", shell, so.String())
		}
	}
}

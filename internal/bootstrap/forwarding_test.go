package bootstrap

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"pedit/internal/agentproxy"
	"pedit/internal/proto"
	"pedit/internal/wire"
)

// The bootstrap shipped broken through `ssh -A` while working perfectly over
// a direct socket, so none of the existing tests caught it.
//
// Cause, measured against a real sshd: OpenSSH's agent forwarding tears the
// channel down as soon as it sees EOF from the client, discarding any reply
// still in flight. socat (default) and `nc -N` both half-close the moment
// `printf` EOFs, so the server sent all 2810178 bytes and the client read 0.
// Without half-close the same transfer arrives intact.
//
// fakeForwarder reproduces exactly that behaviour, so this runs in a normal
// `go test` with no sshd, and fails if anyone reintroduces a half-close.

// fakeForwarder relays front->back like sshd's auth-agent channel, and --
// crucially -- tears the whole thing down when the client half-closes,
// dropping any reply the backend was still writing.
type fakeForwarder struct {
	front string
	l     net.Listener
	wg    sync.WaitGroup
}

func newFakeForwarder(t *testing.T, backend string) *fakeForwarder {
	t.Helper()
	dir, err := os.MkdirTemp("", "fw")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	front := filepath.Join(dir, "f.sock")
	l, err := net.Listen("unix", front)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeForwarder{front: front, l: l}
	t.Cleanup(func() { l.Close(); f.wg.Wait() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			f.wg.Add(1)
			go func(client net.Conn) {
				defer f.wg.Done()
				defer client.Close()
				back, err := net.Dial("unix", backend)
				if err != nil {
					return
				}
				defer back.Close()

				done := make(chan struct{})
				go func() {
					// Reply path. When the backend closes (peditagentd does
					// so after a bootstrap reply), propagate that close to
					// the client so it sees EOF -- sshd does the same, and
					// without it a non-half-closing client waits forever.
					io.Copy(client, back)
					client.Close()
					close(done)
				}()
				io.Copy(back, client) // request path; returns on client EOF
				// THE BEHAVIOUR UNDER TEST: on client EOF, tear everything
				// down immediately instead of half-closing and waiting for
				// the reply. This is what OpenSSH does, and it is why a
				// half-closing bootstrap client receives nothing.
				back.Close()
				client.Close()
				<-done
			}(c)
		}
	}()
	return f
}

func serveBootstrapAgent(t *testing.T, script []byte) string {
	return serveBootstrapAgentDelayed(t, script, 0)
}

// serveBootstrapAgentDelayed adds latency before the bootstrap reply.
//
// The half-close negative control below is otherwise a race: it asserts
// that the forwarder's teardown beats the reply, and with a tiny script
// answered instantly the reply sometimes wins on a loaded machine (seen
// once in a full-suite run, never in isolation). A real peditagentd reads
// pedit.sh from disk and answers with megabytes, so some latency is the
// faithful model, not a fudge -- and the positive tests pass with it too.
func serveBootstrapAgentDelayed(t *testing.T, script []byte, delay time.Duration) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ag")
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
				func() (net.Conn, error) { return nil, fmt.Errorf("no backing agent") },
				agentproxy.RefuseAll{},
				func(arch string) ([]byte, error) {
					if delay > 0 {
						time.Sleep(delay)
					}
					// Same two-stage shape as the daemon: empty arch is
					// stage 1 asking for the loader.
					if arch == "" {
						return Loader(), nil
					}
					return script, nil
				}, wire.MaxFrameLen)
		}
	}()
	return sock
}

// Every generated one-liner must survive a forwarder that kills the channel
// on client EOF -- i.e. must not half-close.
func TestOneLinersSurviveAgentForwarding(t *testing.T) {
	agent := serveBootstrapAgent(t, []byte(fakeScriptBody))
	fwd := newFakeForwarder(t, agent)

	for _, only := range socketClients {
		t.Run(only, func(t *testing.T) {
			cmd := exec.Command("sh", "-c", OneLiner()+"\npedit")
			cmd.Env = append(os.Environ(),
				"SSH_AUTH_SOCK="+fwd.front,
				"PATH="+restrictedPATH(t, only))
			var so, se strings.Builder
			cmd.Stdout, cmd.Stderr = &so, &se
			_ = cmd.Run()
			if !strings.Contains(so.String(), "BOOTSTRAPPED_OK") {
				t.Errorf("bootstrap failed through a forwarding-like channel "+
					"(does this client half-close?)\nstdout: %q\nstderr: %q", so.String(), se.String())
			}
		})
	}
}

// Negative control: proves the forwarder above actually reproduces the
// hazard. A deliberately half-closing client must get nothing back -- if
// this ever starts passing, the test above has stopped proving anything.
func TestHalfCloseLosesReplyThroughForwarder(t *testing.T) {
	agent := serveBootstrapAgentDelayed(t, []byte(fakeScriptBody), 150*time.Millisecond)
	fwd := newFakeForwarder(t, agent)

	c, err := net.Dial("unix", fwd.front)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if err := wire.WriteFrame(c, proto.BuildBootstrapRequestFrame("amd64")); err != nil {
		t.Fatalf("write: %v", err)
	}
	c.(*net.UnixConn).CloseWrite() // the fatal half-close
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))

	got, err := io.ReadAll(c)
	if err == nil && len(got) > 0 {
		t.Fatalf("expected the reply to be lost on half-close, but read %d bytes -- "+
			"the forwarder is no longer reproducing the real failure", len(got))
	}
}

// And the same request WITHOUT half-closing must come back whole, which is
// what makes the fix possible at all.
func TestNoHalfCloseGetsFullReplyThroughForwarder(t *testing.T) {
	script := []byte(fakeScriptBody)
	agent := serveBootstrapAgent(t, script)
	fwd := newFakeForwarder(t, agent)

	c, err := net.Dial("unix", fwd.front)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if err := wire.WriteFrame(c, proto.BuildBootstrapRequestFrame("amd64")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))

	// peditagentd closes after a bootstrap reply, so reading to EOF is exactly
	// what the shell one-liners do.
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) <= proto.BootstrapPrefixLen {
		t.Fatalf("reply too short: %d bytes", len(got))
	}
	if body := got[proto.BootstrapPrefixLen:]; string(body) != string(script) {
		t.Errorf("script came back altered: %d bytes vs %d", len(body), len(script))
	}
}

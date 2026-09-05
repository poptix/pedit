package agentproxy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pedit/internal/wire"
)

// Regression test for the failure that took out a live peditagentd:
// starting a second instance renamed the FIRST instance's own listening
// socket onto the ".pedit-real" path the first was using as its backing
// agent. The first instance then dialed itself for every request,
// recursing until "accept4: too many open files", while a retry-immediately
// accept loop flooded the console.
//
// IsPeditAgent is the guard that makes the second start refuse. These tests
// pin down both halves: a real peditagentd must be recognised, and anything
// else (notably a plain ssh-agent, which answers unknown extensions with
// SSH_AGENT_FAILURE) must not be.

func shortSock(t *testing.T, name string) string {
	t.Helper()
	// unix socket paths are capped near 108 bytes; t.TempDir() plus a long
	// test name can exceed that.
	dir, err := os.MkdirTemp("", "sl")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

// servePedit starts a real agentproxy on sock, as peditagentd does.
func servePedit(t *testing.T, sock string) {
	t.Helper()
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
			go Serve(c,
				func() (net.Conn, error) { return nil, fmt.Errorf("no backing agent") },
				RefuseAll{}, nil, wire.MaxFrameLen)
		}
	}()
}

// servePlainAgent imitates a stock ssh-agent: every request it doesn't
// understand gets SSH_AGENT_FAILURE.
func servePlainAgent(t *testing.T, sock string) {
	t.Helper()
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
			go func(c net.Conn) {
				defer c.Close()
				for {
					if _, err := wire.ReadFrame(c); err != nil {
						return
					}
					if wire.WriteFrame(c, []byte{wire.MsgAgentFailure}) != nil {
						return
					}
				}
			}(c)
		}
	}()
}

func TestIsPeditAgentDetectsOurOwnAgent(t *testing.T) {
	sock := shortSock(t, "p.sock")
	servePedit(t, sock)
	if !IsPeditAgent(sock) {
		t.Fatal("a running peditagentd was not recognised -- a second instance " +
			"would take over its socket and make it proxy to itself")
	}
}

func TestIsPeditAgentIgnoresPlainSshAgent(t *testing.T) {
	sock := shortSock(t, "a.sock")
	servePlainAgent(t, sock)
	if IsPeditAgent(sock) {
		t.Fatal("a plain ssh-agent was misidentified as peditagentd; " +
			"replace_auth_sock would then refuse to start in the normal case")
	}
}

func TestIsPeditAgentOnDeadSocket(t *testing.T) {
	// A stale socket file with nothing behind it must not be reported as a
	// pedit agent, or a restart after an unclean exit could never proceed.
	sock := shortSock(t, "dead.sock")
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	done := make(chan bool, 1)
	go func() { done <- IsPeditAgent(sock) }()
	select {
	case got := <-done:
		if got {
			t.Fatal("dead socket reported as a pedit agent")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("IsPeditAgent hung on a dead socket")
	}
}

// The ping must be answered even with every optional feature disabled --
// it's the one thing that must always work for the guard to be reliable.
func TestPingAnsweredWithFeaturesDisabled(t *testing.T) {
	sock := shortSock(t, "min.sock")
	servePedit(t, sock) // nil bootstrap handler, erroring backing agent
	if !IsPeditAgent(sock) {
		t.Fatal("ping unanswered when bootstrap is disabled and no backing agent exists")
	}
}

// pedit's max_size_bytes must not shrink what an ordinary agent message may
// be: this proxy sits in front of the user's real ssh-agent and has to stay
// transparent. A tiny max_size_bytes previously made the proxy refuse
// perfectly legitimate large agent traffic, and separately the backing
// agent's replies were bounded by a different constant than the client's
// requests -- the disagreeing-ceilings bug, fixed in one direction only.
// Both found by an external review.
func TestSmallPeditLimitDoesNotBreakPassThrough(t *testing.T) {
	backendSock := shortSock(t, "b.sock")
	// A backing "agent" that replies with a frame much larger than a tiny
	// pedit max_size_bytes would allow.
	const replySize = 4 << 20
	bl, err := net.Listen("unix", backendSock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { bl.Close() })
	go func() {
		for {
			c, err := bl.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					if _, err := wire.ReadFrame(c); err != nil {
						return
					}
					body := make([]byte, replySize)
					body[0] = wire.MsgAgentSuccess
					if wire.WriteFrame(c, body) != nil {
						return
					}
				}
			}(c)
		}
	}()

	frontSock := shortSock(t, "f.sock")
	fl, err := net.Listen("unix", frontSock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { fl.Close() })
	// readLimit as if max_size_bytes were 1 KiB -- absurdly small on purpose.
	const tinyPeditLimit = 1024
	go func() {
		for {
			c, err := fl.Accept()
			if err != nil {
				return
			}
			go Serve(c,
				func() (net.Conn, error) { return net.Dial("unix", backendSock) },
				RefuseAll{}, nil, tinyPeditLimit)
		}
	}()

	c, err := net.Dial("unix", frontSock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	// An ordinary (non-pedit) agent request, larger than the tiny pedit
	// limit, must still reach the backing agent.
	req := make([]byte, 64<<10)
	req[0] = 11 // SSH_AGENTC_REQUEST_IDENTITIES
	if err := wire.WriteFrame(c, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := wire.ReadFrameLimit(c, wire.MaxAllocFrame())
	if err != nil {
		t.Fatalf("pass-through of a %d-byte agent request failed with a %d-byte pedit "+
			"limit: %v", len(req), tinyPeditLimit, err)
	}
	if len(got) != replySize {
		t.Errorf("relayed reply was %d bytes, want %d", len(got), replySize)
	}
}

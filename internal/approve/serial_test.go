package approve

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// These tests simulate the ESP32 side with a socat-created PTY pair rather
// than real hardware -- exercising the exact same line protocol
// (HELLO/PEDIT-APPROVER v1, REQ/YES/NO) the real firmware in
// ../../firmware/pedit-approver speaks, just driven by a fake in the test
// process instead of a physical button.

func mustPTYPair(t *testing.T) (devA, devB string, cleanup func()) {
	t.Helper()
	if _, err := exec.LookPath("socat"); err != nil {
		t.Skip("socat not installed, skipping simulated-serial test")
	}
	dir := t.TempDir()
	devA = dir + "/pty-a"
	devB = dir + "/pty-b"
	cmd := exec.Command("socat", "-d", "-d",
		fmt.Sprintf("pty,raw,echo=0,link=%s", devA),
		fmt.Sprintf("pty,raw,echo=0,link=%s", devB))
	if err := cmd.Start(); err != nil {
		t.Fatalf("start socat: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, errA := os.Stat(devA)
		_, errB := os.Stat(devB)
		if errA == nil && errB == nil {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatalf("socat never created both PTY links")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return devA, devB, func() { cmd.Process.Kill(); cmd.Wait() }
}

// fakeFirmware stands in for the ESP32: answers HELLO and then, for each
// REQ line it sees, replies with whatever's next in the responses queue (or
// simply doesn't reply, to simulate a timed-out button).
type fakeFirmware struct {
	f    *os.File
	reqs chan string
}

func newFakeFirmware(t *testing.T, dev string) *fakeFirmware {
	t.Helper()
	f, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open fake firmware side %s: %v", dev, err)
	}
	fw := &fakeFirmware{f: f, reqs: make(chan string, 8)}
	go fw.serve(t)
	return fw
}

func (fw *fakeFirmware) serve(t *testing.T) {
	r := bufio.NewReader(fw.f)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = trimEOL(line)
		switch {
		case line == "HELLO":
			fmt.Fprintf(fw.f, "PEDIT-APPROVER v1\n")
		case len(line) >= 4 && line[:4] == "REQ ":
			fw.reqs <- line[4:]
		}
	}
}

// respond answers the next pending REQ (waiting for it to arrive first) --
// or, if resp == "", deliberately doesn't answer, to simulate a button that
// never got pressed. Echoes a "# pending: ..." comment line first, exactly
// like the real firmware's handleRequest does, so these tests exercise the
// client's comment-skipping the same way real hardware does -- caught a
// real bug the first time real hardware was tested: the client was
// treating that echo line itself as the answer.
func (fw *fakeFirmware) respond(t *testing.T, resp string) string {
	t.Helper()
	select {
	case body := <-fw.reqs:
		fmt.Fprintf(fw.f, "# pending: %s\n", body)
		if resp != "" {
			fmt.Fprintf(fw.f, "%s\n", resp)
		}
		return body
	case <-time.After(2 * time.Second):
		t.Fatalf("fake firmware never saw a REQ")
		return ""
	}
}

func (fw *fakeFirmware) Close() { fw.f.Close() }

func TestSerialApproverApprove(t *testing.T) {
	devA, devB, cleanup := mustPTYPair(t)
	defer cleanup()
	fw := newFakeFirmware(t, devB)
	defer fw.Close()

	a, err := NewSerialApprover(devA, 115200, 2*time.Second)
	if err != nil {
		t.Fatalf("NewSerialApprover: %v", err)
	}

	done := make(chan struct {
		approved bool
		err      error
	})
	go func() {
		approved, err := a.ApproveTransfer(Summary{Profile: "view", Filename: "notes.txt", OriginHint: "u@h", Size: 5})
		done <- struct {
			approved bool
			err      error
		}{approved, err}
	}()
	body := fw.respond(t, "YES")
	// dir= comes first and is always present: whoever is looking at the
	// board has to be able to tell an incoming file from an outgoing one,
	// and an unset Direction must still render as "up" rather than blank.
	if body != "dir=up profile=view file=notes.txt origin=u@h size=5" {
		t.Errorf("unexpected request body: %q", body)
	}
	res := <-done
	if res.err != nil || !res.approved {
		t.Fatalf("expected approved, got approved=%v err=%v", res.approved, res.err)
	}
}

func TestSerialApproverDeny(t *testing.T) {
	devA, devB, cleanup := mustPTYPair(t)
	defer cleanup()
	fw := newFakeFirmware(t, devB)
	defer fw.Close()

	a, err := NewSerialApprover(devA, 115200, 2*time.Second)
	if err != nil {
		t.Fatalf("NewSerialApprover: %v", err)
	}

	done := make(chan struct {
		approved bool
		err      error
	})
	go func() {
		approved, err := a.ApproveTransfer(Summary{Profile: "view"})
		done <- struct {
			approved bool
			err      error
		}{approved, err}
	}()
	fw.respond(t, "NO")
	res := <-done
	if res.err != nil || res.approved {
		t.Fatalf("expected denied, got approved=%v err=%v", res.approved, res.err)
	}
}

func TestSerialApproverTimeout(t *testing.T) {
	devA, devB, cleanup := mustPTYPair(t)
	defer cleanup()
	fw := newFakeFirmware(t, devB)
	defer fw.Close()

	a, err := NewSerialApprover(devA, 115200, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("NewSerialApprover: %v", err)
	}

	done := make(chan struct {
		approved bool
		err      error
	})
	go func() {
		approved, err := a.ApproveTransfer(Summary{Profile: "view"})
		done <- struct {
			approved bool
			err      error
		}{approved, err}
	}()
	fw.respond(t, "") // never answer -- button not pressed
	res := <-done
	if res.err == nil || res.approved {
		t.Fatalf("expected a timeout error, got approved=%v err=%v", res.approved, res.err)
	}
}

func TestSerialApproverBadHandshake(t *testing.T) {
	devA, devB, cleanup := mustPTYPair(t)
	defer cleanup()

	// A peer that never answers HELLO correctly -- simulates plugging into
	// a board that isn't running the pedit-approver firmware at all.
	f, err := os.OpenFile(devB, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	if _, err := NewSerialApprover(devA, 115200, time.Second); err == nil {
		t.Fatalf("expected handshake failure, got a working approver")
	}
}

// Approval now happens before any content exists, so there is no sniffed
// type to display. The board line carries only what a human can act on:
// which profile, which name, from where, how big.
func TestSerialApproverLineHasNoContentType(t *testing.T) {
	devA, devB, cleanup := mustPTYPair(t)
	defer cleanup()
	fw := newFakeFirmware(t, devB)
	defer fw.Close()

	a, err := NewSerialApprover(devA, 115200, 2*time.Second)
	if err != nil {
		t.Fatalf("NewSerialApprover: %v", err)
	}
	done := make(chan bool, 1)
	go func() {
		ok, _ := a.ApproveTransfer(Summary{
			Profile: "open", Filename: "holiday.jpg", OriginHint: "u@h", Size: 9,
		})
		done <- ok
	}()
	body := fw.respond(t, "YES")
	if strings.Contains(body, "type=") {
		t.Errorf("board line still advertises a content type: %q", body)
	}
	if !strings.Contains(body, "size=9") {
		t.Errorf("board line missing the size: %q", body)
	}
	<-done
}

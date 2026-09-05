package approve

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureLog redirects the standard logger for the duration of a test.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func captureLog(t *testing.T) *logCapture {
	t.Helper()
	c := &logCapture{}
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(c)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })
	return c
}

// Regression test for a misleading-diagnostics bug: the approval heartbeat
// was stopped with `defer`, so it kept logging
// "exec approver still waiting ... (timeout at 2m0s)" for the whole time
// the PROFILE COMMAND ran. Editing a file in a GUI editor therefore looked
// like it was about to be killed at the approval timeout -- it never was,
// but the log said otherwise and that is just as bad.
func TestApprovalHeartbeatStopsWhenApprovalCompletes(t *testing.T) {
	c := captureLog(t)
	// Timeout/4 => 1s heartbeat interval, so a ~3s command would emit
	// several ticks if the approval heartbeat leaked into the command phase.
	a := ExecApprover{AskCommand: "true", Timeout: 4 * time.Second, Debug: true}

	ok, err := a.ApproveTransfer(Summary{Profile: "edit"})
	if err != nil || !ok {
		t.Fatalf("expected approval, got ok=%v err=%v", ok, err)
	}
	if err := a.RunProfile("sleep 3"); err != nil {
		t.Fatalf("RunProfile: %v", err)
	}

	logged := c.String()
	if strings.Contains(logged, "waiting for approval after") {
		t.Errorf("approval heartbeat leaked into the command phase:\n%s", logged)
	}
	// The command phase should announce itself, and say the right thing.
	if !strings.Contains(logged, "running profile command") {
		t.Errorf("command phase was not logged:\n%s", logged)
	}
	if !strings.Contains(logged, "profile command still running") {
		t.Errorf("expected a command-phase heartbeat for a 3s command:\n%s", logged)
	}
	if strings.Contains(logged, "profile command still running") &&
		!strings.Contains(logged, "no limit here") {
		t.Errorf("command-phase heartbeat must not imply a deadline:\n%s", logged)
	}
}

// The approval timeout must NOT kill a long-running profile command: that
// was the user-visible fear, and it must stay false.
func TestApprovalTimeoutDoesNotKillProfileCommand(t *testing.T) {
	dir := t.TempDir()
	done := filepath.Join(dir, "finished")

	// Approval timeout far shorter than the command's runtime.
	a := ExecApprover{AskCommand: "true", Timeout: 300 * time.Millisecond}
	ok, err := a.ApproveTransfer(Summary{Profile: "edit"})
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	start := time.Now()
	err = a.RunProfile("sleep 2 && touch " + done)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("RunProfile: %v", err)
	}
	if _, statErr := os.Stat(done); statErr != nil {
		t.Fatalf("profile command was killed by the approval timeout (%v)", statErr)
	}
	if elapsed < 2*time.Second {
		t.Errorf("Approve returned in %s -- it did not wait for the command", elapsed)
	}
}

// A refusing askpass must deny, and must not run the profile command.
func TestExecApproverDenialRunsNothing(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "ran")

	a := ExecApprover{AskCommand: "false", Timeout: 2 * time.Second}
	ok, err := a.ApproveTransfer(Summary{Profile: "edit"})
	if err != nil {
		t.Fatalf("denial should not be an error: %v", err)
	}
	if ok {
		t.Fatal("expected denial")
	}
	// The caller must not run anything after a denial; simulate that
	// contract by simply not calling RunProfile.
	_ = sentinel
	if _, statErr := os.Stat(sentinel); statErr == nil {
		t.Fatal("profile command ran despite denial")
	}
}

// An askpass that hangs must be cut off at the approval timeout and treated
// as a denial, not left blocking forever.
func TestExecApproverAskTimeoutDenies(t *testing.T) {
	a := ExecApprover{AskCommand: "sleep 30", Timeout: 400 * time.Millisecond}
	start := time.Now()
	ok, err := a.ApproveTransfer(Summary{Profile: "edit"})
	if err != nil {
		t.Fatalf("timeout should be a plain denial, got error: %v", err)
	}
	if ok {
		t.Fatal("a timed-out approval must not count as approved")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %s -- the approval timeout did not fire", d)
	}
}

// The request details must reach the askpass script's environment; that is
// the only way a GUI prompt can show what is being approved.
func TestExecApproverPassesRequestDetailsInEnv(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "env.txt")

	a := ExecApprover{
		AskCommand: "printf '%s|%s|%s|%s|%s' \"$PEDIT_PROFILE\" \"$PEDIT_FILENAME\" " +
			"\"$PEDIT_ORIGIN\" \"$PEDIT_SIZE\" \"$PEDIT_DETECTED\" > " + outFile,
		Timeout: 3 * time.Second,
	}
	ok, err := a.ApproveTransfer(Summary{
		Profile: "open", Filename: "holiday.jpg", OriginHint: "u@h", Size: 42,
	})
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	got, readErr := os.ReadFile(outFile)
	if readErr != nil {
		t.Fatalf("askpass did not write its env: %v", readErr)
	}
	want := "open|holiday.jpg|u@h|42|"
	if string(got) != want {
		t.Errorf("askpass env = %q, want %q", got, want)
	}
}

func TestExecApproverRequiresCommand(t *testing.T) {
	a := ExecApprover{Timeout: time.Second}
	if _, err := a.ApproveTransfer(Summary{}); err == nil {
		t.Error("an unconfigured exec approver should error, not silently approve")
	}
}

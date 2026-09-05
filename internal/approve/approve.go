// Package approve implements peditagentd's human-in-the-loop gate. A
// hostile host anywhere in an agent-forwarding chain can craft a
// pedit@hallacy.com extension request itself, not just via the `pedit`
// bash function -- so every request must be explicitly approved here
// before anything runs, and approval always deals in fixed local profiles,
// never a remote-supplied command string.
//
// Approval and execution are one operation (not two) because who ends up
// running the resolved command depends on how approval happened: a GUI
// askpass approval runs it locally (fine for commands that don't need a
// controlling terminal), while a terminal-based approval must run it in
// that same terminal (needed when $EDITOR is something like vim, which a
// headless background daemon has no TTY to attach to).
package approve

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"pedit/internal/wire"
)

// Directions a request can take. Which one it is changes what the human is
// actually being asked to allow, so it is shown in every prompt rather than
// left to be inferred from the profile name.
const (
	DirUp   = "up"   // a file is arriving here from the remote host
	DirDown = "down" // a file is leaving here for the remote host
	DirList = "list" // the transfer directory's contents are being disclosed
)

type Summary struct {
	Profile    string
	Filename   string
	OriginHint string
	Size       int

	// Direction is one of DirUp/DirDown/DirList. Empty means DirUp, which
	// is what every profile-based transfer has always been.
	Direction string

	// OneWay marks a profile that hands the file to a detached system
	// handler and returns nothing. Worth surfacing: nothing comes back, and
	// the temp file outlives the approval.
	OneWay bool
}

// Approver is split in two because the two halves now happen at different
// points in the transfer. ApproveTransfer runs BEFORE any content is
// accepted, so a refusal costs nothing; RunProfile runs after the bytes are
// on disk. They used to be one call, which forced the daemon to ingest the
// whole file before it could ask.
//
// They stay on one interface because who executes still depends on how
// approval happened: a GUI askpass approval can run the command in the
// daemon, while a terminal approval must run it in the terminal that has a
// TTY (needed for vim and friends).
type Approver interface {
	// ApproveTransfer decides whether to accept a transfer at all. No
	// content exists yet -- only the metadata in req.
	ApproveTransfer(req Summary) (approved bool, err error)

	// RunProfile executes the already-substituted profile command against
	// the received file and blocks until it finishes.
	RunProfile(resolvedCmd string) error
}

func summaryEnv(req Summary) []string {
	return append(os.Environ(),
		"PEDIT_PROFILE="+req.Profile,
		"PEDIT_FILENAME="+req.Filename,
		"PEDIT_ORIGIN="+req.OriginHint,
		"PEDIT_SIZE="+fmt.Sprint(req.Size),
		"PEDIT_DIRECTION="+Direction(req),
	)
}

// Direction normalises Summary.Direction, defaulting to DirUp so an
// approver never has to special-case the empty value.
func Direction(req Summary) string {
	if req.Direction == "" {
		return DirUp
	}
	return req.Direction
}

// ExecApprover asks via an askpass-style command (the SSH_ASKPASS
// convention: exit 0 = approve, anything else = deny) and, on approval,
// runs resolvedCmd itself. Suitable when peditagentd runs on a host with a
// desktop session and the profile commands are GUI apps that don't need a
// controlling terminal (notify-send for the prompt, `code --wait` or
// similar for the profile).
type ExecApprover struct {
	AskCommand string
	Timeout    time.Duration
	Debug      bool
}

func (a ExecApprover) ApproveTransfer(req Summary) (bool, error) {
	if a.AskCommand == "" {
		return false, fmt.Errorf("no exec.command configured")
	}
	// Deliberately NOT exec.CommandContext. Two problems with it here:
	// it kills only the direct child, so `sh -c` leaves grandchildren
	// running; and because Stdout/Stderr are buffers rather than *os.File,
	// exec spawns copy goroutines that Wait() blocks on until every holder
	// of the pipe exits. Net effect, measured: an askpass running `sleep 30`
	// ignored a 400ms timeout entirely and blocked for the full 30s. A
	// misbehaving prompt could hang peditagentd indefinitely.
	//
	// Instead: put the child in its own process group and kill the whole
	// group on timeout, so grandchildren die too and the pipes close.
	ask := exec.Command("/bin/sh", "-c", a.AskCommand)
	ask.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	ask.Env = summaryEnv(req)

	// Previously left nil, which silently discards the ask command's
	// output -- a real blind spot: a broken askpass script (missing
	// notify-send, no session bus, wrong path) just looked identical to a
	// plain denial, with no way to tell them apart short of running the
	// command by hand.
	var out bytes.Buffer
	ask.Stdout = &out
	ask.Stderr = &out

	// The approval heartbeat must stop the moment the ask command returns.
	// It used to be torn down with `defer`, i.e. when Approve returned --
	// which is after the PROFILE COMMAND finishes. The result was
	// "exec approver still waiting ... (timeout at 2m0s)" printing
	// throughout an editing session, strongly implying a 2-minute limit on
	// editing. There is no such limit (see the command phase below); the
	// message was simply wrong, and alarming because of it.
	askDone := make(chan struct{})
	if a.Debug {
		log.Printf("pedit: debug: exec approver running: %s", a.AskCommand)
		go a.heartbeat(askDone, "waiting for approval",
			fmt.Sprintf("approval times out at %s", a.Timeout))
	}
	err, timedOut := runWithTimeout(ask, a.Timeout)
	close(askDone)

	if a.Debug {
		log.Printf("pedit: debug: exec approver finished: err=%v timed_out=%v output=%q",
			err, timedOut, out.String())
	}
	if err != nil {
		return false, nil // nonzero exit or timeout: treated as a plain deny, not an error
	}
	return true, nil
}

// RunProfile runs the command in the daemon's own process. Deliberately
// exec.Command, not CommandContext: the approval timeout must NOT apply
// here. Editing is human-paced and a GUI editor may stay open for a long
// time. The only real bound is the remote client's connection deadline
// (pedithelper: 30 minutes by default, PEDIT_TIMEOUT_SECONDS to change).
func (a ExecApprover) RunProfile(resolvedCmd string) error {
	runDone := make(chan struct{})
	if a.Debug {
		log.Printf("pedit: debug: running profile command: %s", resolvedCmd)
		go a.heartbeat(runDone, "profile command still running",
			"no limit here; the remote client gives up at its own deadline (pedithelper default 30m)")
	}
	run := exec.Command("/bin/sh", "-c", resolvedCmd)
	run.Stdin, run.Stdout, run.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := run.Run()
	close(runDone)
	if err != nil {
		return fmt.Errorf("command exited with error: %w", err)
	}
	return nil
}

// runWithTimeout starts cmd (which must have Setpgid set), waits for it, and
// on timeout SIGKILLs its whole process group so grandchildren cannot keep
// the output pipes open and stall Wait(). Returns whether the timeout fired.
//
// If Wait still does not return shortly after the kill, it gives up on that
// goroutine rather than blocking the caller forever: a stuck approval must
// fail closed, not wedge the daemon.
func runWithTimeout(cmd *exec.Cmd, timeout time.Duration) (err error, timedOut bool) {
	if err := cmd.Start(); err != nil {
		return err, false
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return err, false
	case <-time.After(timeout):
	}

	// Negative pid = the whole process group (see Setpgid above).
	if cmd.Process != nil {
		if kerr := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); kerr != nil {
			_ = cmd.Process.Kill() // fall back to just the child
		}
	}
	select {
	case err := <-done:
		return err, true
	case <-time.After(2 * time.Second):
		return fmt.Errorf("askpass timed out after %s and did not exit", timeout), true
	}
}

// heartbeat logs progress until stop is closed. what/note describe which
// phase is being waited on -- conflating the two phases is what made the
// old single message misleading.
func (a ExecApprover) heartbeat(stop <-chan struct{}, what, note string) {
	interval := a.Timeout / 4
	if interval > 15*time.Second {
		interval = 15 * time.Second
	}
	if interval < time.Second {
		interval = time.Second
	}
	start := time.Now()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			log.Printf("pedit: debug: %s after %s (%s)",
				what, time.Since(start).Round(time.Second), note)
		}
	}
}

// SocketApprover hands approval and execution to a companion `peditctl`
// process connected over a local control socket, so the profile command
// runs attached to a real interactive terminal -- for a headless "home"
// host where peditagentd has no TTY or desktop session of its own. Only one
// request is handled at a time by design: with at most one thing pending,
// which approval you're answering is never ambiguous.
type SocketApprover struct {
	mu      sync.Mutex
	timeout time.Duration
	waiters chan net.Conn
	held    net.Conn // the connection between ApproveTransfer and RunProfile
}

func NewSocketApprover(sockPath string, timeout time.Duration) (*SocketApprover, error) {
	os.Remove(sockPath)
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		return nil, err
	}
	a := &SocketApprover{timeout: timeout, waiters: make(chan net.Conn)}
	go a.acceptLoop(l)
	return a, nil
}

func (a *SocketApprover) acceptLoop(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		select {
		case a.waiters <- c:
		case <-time.After(2 * time.Second):
			c.Close() // nothing pending right now; peditctl just retries
		}
	}
}

// Message kinds on the peditctl control socket. Approval and execution are
// now separate round trips because they happen at different times.
const (
	CtlAsk byte = 1 // decide whether to accept a transfer (no content yet)
	CtlRun byte = 2 // run this command, in peditctl's terminal
)

// hold keeps the peditctl connection for the whole transfer, so the ask and
// the later run reach the same terminal.
func (a *SocketApprover) grab() (net.Conn, error) {
	select {
	case conn := <-a.waiters:
		return conn, nil
	case <-time.After(a.timeout):
		return nil, fmt.Errorf("no peditctl connected to answer (run `peditctl` on the agent host)")
	}
}

func (a *SocketApprover) ApproveTransfer(req Summary) (bool, error) {
	if !a.mu.TryLock() {
		return false, fmt.Errorf("another approval is already in progress, try again shortly")
	}
	// Unlocked by RunProfile, or here on refusal/error: the peditctl
	// connection has to survive between the two calls.
	conn, err := a.grab()
	if err != nil {
		a.mu.Unlock()
		return false, err
	}
	conn.SetDeadline(time.Now().Add(a.timeout))

	buf := new(wire.Buffer)
	buf.Byte(CtlAsk).String(req.Profile).String(req.Filename).String(req.OriginHint).
		Uint32(uint32(req.Size)).String(Direction(req))
	if err := wire.WriteFrame(conn, buf.Out()); err != nil {
		conn.Close()
		a.mu.Unlock()
		return false, fmt.Errorf("peditctl: %w", err)
	}
	frame, err := wire.ReadFrame(conn)
	if err != nil {
		conn.Close()
		a.mu.Unlock()
		return false, fmt.Errorf("peditctl disconnected before answering: %w", err)
	}
	status, err := wire.NewReader(frame).Byte()
	if err != nil || status == 0 {
		conn.Close()
		a.mu.Unlock()
		return false, nil // denied (or malformed, which is treated as denial)
	}
	a.held = conn
	return true, nil
}

func (a *SocketApprover) RunProfile(resolvedCmd string) error {
	conn := a.held
	a.held = nil
	if conn == nil {
		a.mu.Unlock()
		return fmt.Errorf("peditctl: no approved session to run in")
	}
	defer func() { conn.Close(); a.mu.Unlock() }()

	// No deadline while a human edits: the remote client's own deadline is
	// the only bound that should apply.
	conn.SetDeadline(time.Time{})
	buf := new(wire.Buffer)
	buf.Byte(CtlRun).String(resolvedCmd)
	if err := wire.WriteFrame(conn, buf.Out()); err != nil {
		return fmt.Errorf("peditctl: %w", err)
	}
	frame, err := wire.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("peditctl disconnected while running the command: %w", err)
	}
	rd := wire.NewReader(frame)
	status, err := rd.Byte()
	if err != nil {
		return fmt.Errorf("malformed peditctl response")
	}
	if status != 1 {
		msg, _ := rd.String()
		return fmt.Errorf("peditctl: %s", msg)
	}
	return nil
}

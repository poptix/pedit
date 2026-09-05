package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Backgrounding is done by re-exec rather than fork: a Go program cannot
// fork() safely once its runtime has started threads. The parent starts a
// copy of itself with PEDIT_DAEMONIZED set, waits for it to report that it
// is actually listening, prints that, and exits.
//
// The wait matters. peditagentd typically MOVES the real agent socket aside
// and binds its own in that place, so if the shell prompt came back before
// that finished, the very next command could reach a socket that is
// half-swapped or briefly absent.
const daemonEnvVar = "PEDIT_DAEMONIZED"

// readyFD is the inherited pipe the child reports startup on. Fd 0/1/2 are
// the usual three, so ExtraFiles[0] lands on 3.
const readyFD = 3

func isDaemonChild() bool { return os.Getenv(daemonEnvVar) != "" }

// signalReady tells the parent the daemon is up. Safe to call when not
// daemonized: fd 3 simply is not a pipe then.
func signalReady(msg string) {
	if !isDaemonChild() {
		return
	}
	f := os.NewFile(readyFD, "ready")
	if f == nil {
		return
	}
	fmt.Fprintf(f, "ready %d %s\n", os.Getpid(), msg)
	f.Close()
}

// daemonize re-executes this program in the background and does not return:
// it exits the parent process either way.
func daemonize(logPath, pidPath string) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "pedit: %v\n", err)
		os.Exit(1)
	}
	if pid, ok := runningDaemon(pidPath); ok {
		fmt.Fprintf(os.Stderr, "pedit: already running as pid %d (%s). Stop it first, "+
			"or use -foreground to run another deliberately.\n", pid, pidPath)
		os.Exit(1)
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pedit: log file %s: %v\n", logPath, err)
		os.Exit(1)
	}
	defer logFile.Close()

	rd, wr, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pedit: %v\n", err)
		os.Exit(1)
	}

	self, err := os.Executable()
	if err != nil {
		self = os.Args[0]
	}
	cmd := exec.Command(self, os.Args[1:]...)
	cmd.Env = append(os.Environ(), daemonEnvVar+"=1")
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.ExtraFiles = []*os.File{wr}
	// Setsid detaches from the controlling terminal, so Ctrl-C in the shell
	// that started it does not take the daemon with it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "pedit: could not start background process: %v\n", err)
		os.Exit(1)
	}
	wr.Close() // the child holds the only writer now; EOF means it died

	line, err := bufio.NewReader(rd).ReadString('\n')
	rd.Close()
	if err != nil || !strings.HasPrefix(line, "ready ") {
		// The child exited (or was killed) before reporting. Its own output
		// went to the log, which is the only place the reason exists.
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		fmt.Fprintf(os.Stderr, "pedit: the background process exited during startup. "+
			"See %s for why.\n", logPath)
		if tail := lastLines(logPath, 5); tail != "" {
			fmt.Fprintf(os.Stderr, "%s", tail)
		}
		os.Exit(1)
	}

	fields := strings.Fields(line)
	pid := cmd.Process.Pid
	if len(fields) > 1 {
		if n, convErr := strconv.Atoi(fields[1]); convErr == nil {
			pid = n
		}
	}
	writePidFile(pidPath, pid)

	fmt.Printf("pedit: running in the background as pid %d\n", pid)
	fmt.Printf("pedit: %s", strings.TrimPrefix(strings.Join(fields[2:], " ")+"\n", " "))
	fmt.Printf("pedit: log %s\n", logPath)
	fmt.Printf("pedit: stop it with: kill %d\n", pid)
	os.Exit(0)
}

// runningDaemon reports whether the pid in pidPath is alive. A stale file
// from a crash must not block a restart, so a pid that no longer exists is
// treated as absent.
func runningDaemon(pidPath string) (int, bool) {
	b, err := os.ReadFile(pidPath)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return 0, false
	}
	// Signal 0 checks for existence without touching the process.
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return 0, false
	}
	return pid, true
}

func writePidFile(path string, pid int) {
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0o600)
}

func lastLines(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return "  " + strings.Join(lines, "\n  ") + "\n"
}

var _ = io.Discard

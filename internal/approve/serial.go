package approve

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// SerialApprover gates approval on a physical button press on an attached
// ESP32 running the firmware in ../../firmware/pedit-approver (see that
// directory's README for the exact line protocol and wiring). Like
// ExecApprover, approval and execution are one operation: once the board
// signals YES, SerialApprover runs resolvedCmd itself, since the board
// obviously can't run desktop commands -- it only decides yes/no.
//
// The connection is opened once and kept open for peditagentd's lifetime
// rather than per-request. On a serial error mid-request, one reconnect is
// attempted before failing closed.
//
// Two things verified empirically against real hardware (an ESP32-S3 on its
// CH340 bridge), not assumed from documentation:
//   - Opening the port leaves RTS asserted by default, and this board's
//     auto-reset circuit treats a held-high RTS as "hold EN in reset" -- the
//     chip sits silently in reset for as long as the port stays open, with
//     zero output, unless something explicitly pulses RTS low again.
//     `esptool`'s own "hard reset" does exactly this; connect() replicates
//     it (pulseReset) rather than trusting the driver's default state.
//   - The ROM bootloader itself prints a startup banner at the same baud
//     rate before our sketch ever runs, which a naive single-line read after
//     reset will pick up instead of our handshake response. connect() drains
//     it first.
type SerialApprover struct {
	mu      sync.Mutex
	dev     string
	baud    int
	timeout time.Duration

	f *os.File
	r *bufio.Reader
}

func NewSerialApprover(dev string, baud int, timeout time.Duration) (*SerialApprover, error) {
	if dev == "" {
		return nil, fmt.Errorf("no serial.device configured")
	}
	a := &SerialApprover{dev: dev, baud: baud, timeout: timeout}
	if err := a.connect(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *SerialApprover) connect() error {
	if a.f != nil {
		a.f.Close()
	}
	if err := configureSerial(a.dev, a.baud); err != nil {
		return fmt.Errorf("configure %s: %w", a.dev, err)
	}
	// os.OpenFile has no portable O_NOCTTY (a device we don't want to
	// become our controlling terminal), so open via syscall directly. That
	// means wrapping the fd with os.NewFile ourselves, which -- unlike
	// os.OpenFile -- only registers it with Go's runtime poller (needed for
	// SetReadDeadline/SetWriteDeadline to work at all) if the fd is already
	// non-blocking; without this SetNonblock, every deadline call below
	// fails with "file type does not support deadline".
	fd, err := syscall.Open(a.dev, syscall.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", a.dev, err)
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("set nonblocking %s: %w", a.dev, err)
	}
	f := os.NewFile(uintptr(fd), a.dev)
	a.f = f
	a.r = bufio.NewReader(f)

	if err := pulseReset(fd); err != nil {
		f.Close()
		return fmt.Errorf("reset pulse: %w", err)
	}
	// The chip is now coming up through the ROM bootloader into our
	// sketch's setup() -- give the banner time to fully arrive, then
	// discard it via a deadline-bounded read so it can't be mistaken for
	// our handshake response.
	time.Sleep(600 * time.Millisecond)
	drainAvailable(f, 300*time.Millisecond)

	if err := f.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		f.Close()
		return fmt.Errorf("set write deadline: %w", err)
	}
	if _, err := fmt.Fprintf(a.f, "HELLO\n"); err != nil {
		f.Close()
		return fmt.Errorf("handshake write: %w", err)
	}
	line, err := readLineDeadline(f, a.r, 5*time.Second)
	if err != nil {
		f.Close()
		return fmt.Errorf("handshake: %w (is the board running the pedit-approver firmware?)", err)
	}
	if line != "PEDIT-APPROVER v1" {
		f.Close()
		return fmt.Errorf("handshake: unexpected response %q", line)
	}
	return nil
}

func configureSerial(dev string, baud int) error {
	cmd := exec.Command("stty", "-F", dev, fmt.Sprint(baud), "raw", "-echo", "-echoe", "-echok", "-hupcl")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

// pulseReset clears DTR (so GPIO0/BOOT-select stays high -- normal run, not
// bootloader) and pulses RTS high-then-low (asserts, then releases, EN) --
// the same sequence esptool's "hard reset" uses. Pseudo-terminals (used by
// serial_test.go's simulated board) don't implement modem-control lines at
// all and return ENOTTY here; that's expected and not fatal, since a fake
// test peer has no reset circuit to release in the first place.
func pulseReset(fd int) error {
	dtr := int32(syscall.TIOCM_DTR)
	if err := tiocm(fd, syscall.TIOCMBIC, &dtr); err != nil && err != syscall.ENOTTY {
		return err
	}
	rts := int32(syscall.TIOCM_RTS)
	if err := tiocm(fd, syscall.TIOCMBIS, &rts); err != nil {
		if err == syscall.ENOTTY {
			return nil
		}
		return err
	}
	time.Sleep(100 * time.Millisecond)
	return tiocm(fd, syscall.TIOCMBIC, &rts)
}

func tiocm(fd int, req uintptr, bits *int32) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(bits)))
	if errno != 0 {
		return errno
	}
	return nil
}

func (a *SerialApprover) ApproveTransfer(req Summary) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Fields are space-joined for a human reading the board's serial
	// console, not parsed by the firmware -- it only ever treats the text
	// after "REQ " as one opaque line to display.
	line := fmt.Sprintf("REQ dir=%s profile=%s file=%s origin=%s size=%d",
		Direction(req),
		sanitizeField(req.Profile), sanitizeField(req.Filename), sanitizeField(req.OriginHint),
		req.Size)

	if err := a.sendLine(line); err != nil {
		if rerr := a.connect(); rerr != nil {
			return false, fmt.Errorf("serial approver unreachable: %w (original error: %v)", rerr, err)
		}
		if err := a.sendLine(line); err != nil {
			return false, fmt.Errorf("serial approver: %w", err)
		}
	}

	resp, err := readLineDeadline(a.f, a.r, a.timeout)
	if err != nil {
		return false, fmt.Errorf("serial approver: no response: %w", err)
	}
	switch resp {
	case "YES":
		return true, nil
	case "NO":
		return false, nil
	default:
		return false, fmt.Errorf("serial approver: unexpected response %q", resp)
	}
}

// RunProfile runs in the daemon's process: the board decides, it cannot
// host an editor.
func (a *SerialApprover) RunProfile(resolvedCmd string) error {
	run := exec.Command("/bin/sh", "-c", resolvedCmd)
	run.Stdin, run.Stdout, run.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := run.Run(); err != nil {
		return fmt.Errorf("command exited with error: %w", err)
	}
	return nil
}

func (a *SerialApprover) sendLine(line string) error {
	if err := a.f.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(a.f, "%s\n", line)
	return err
}

// sanitizeField strips characters that would break the one-line protocol
// (a newline in an attacker-supplied filename could otherwise inject a
// fake "YES" line) and caps length for the board's small display/console.
func sanitizeField(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' {
			continue
		}
		out = append(out, r)
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return string(out)
}

// readLineDeadline reads the next non-comment line, bounded by a single
// real fd-level deadline covering the whole call even though it may read
// several lines (character devices/PTYs support real deadlines via Go's
// poller, unlike a bare goroutine-vs-timer race, so a timed-out attempt can
// never leave a dangling read in flight to steal bytes a later call wants).
// Lines starting with "#" are the firmware's own human-readable echo of a
// pending request (see pedit-approver.ino's handleRequest) -- meant for
// someone watching a raw serial monitor, not a protocol response, so they're
// skipped rather than mistaken for the actual YES/NO/handshake reply.
func readLineDeadline(f *os.File, r *bufio.Reader, timeout time.Duration) (string, error) {
	if err := f.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", fmt.Errorf("set deadline: %w", err)
	}
	defer f.SetReadDeadline(time.Time{})
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		if line = trimEOL(line); !strings.HasPrefix(line, "#") {
			return line, nil
		}
	}
}

func trimEOL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// drainAvailable discards whatever's readable within window, if anything --
// used to flush the ROM bootloader's banner after a reset before starting
// the real handshake read.
func drainAvailable(f *os.File, window time.Duration) {
	if err := f.SetReadDeadline(time.Now().Add(window)); err != nil {
		return
	}
	defer f.SetReadDeadline(time.Time{})
	buf := make([]byte, 4096)
	f.Read(buf)
}

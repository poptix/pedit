package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// newTestMeter builds a meter with an explicit sink and width, bypassing
// the terminal detection in newMeter. render/bar/clock are pure, so most
// of this file needs no goroutine at all.
func newTestMeter(label string, total int64, width int, out io.Writer) *meter {
	return &meter{label: label, total: total, start: time.Now(), out: out, width: width}
}

// The single most important property: nothing is drawn when stderr is not
// a terminal. pedit runs from scripts and from the e2e harness, both of
// which capture output -- carriage returns and half-drawn bars landing in
// a log or a pipe would be worse than no meter at all.
func TestMeterIsInertWhenNotATerminal(t *testing.T) {
	// Under `go test`, stderr is a pipe, not a char device.
	m := newMeter("up", 1<<20)
	if m.stop != nil {
		t.Fatal("meter started a render loop with a non-terminal stderr")
	}
	// It must still be usable: counting works, finish is a no-op.
	var sink bytes.Buffer
	r := m.reader(strings.NewReader("hello"))
	if _, err := io.Copy(&sink, r); err != nil {
		t.Fatal(err)
	}
	m.finish()
	if sink.String() != "hello" {
		t.Errorf("data was altered: %q", sink.String())
	}
}

func TestProgressDisabledByEnv(t *testing.T) {
	for _, v := range []string{"PEDIT_PROGRESS", "PEDIT_STATS"} {
		t.Setenv(v, "0")
		if progressEnabled() {
			t.Errorf("%s=0 did not disable progress", v)
		}
	}
}

// The counting reader must pass bytes through untouched -- it sits in the
// path of every transfer, so a bug here corrupts files rather than just
// mis-drawing a bar.
func TestCountingReaderIsTransparentAndCounts(t *testing.T) {
	payload := bytes.Repeat([]byte("abcdefgh"), 4096) // 32 KiB
	m := newTestMeter("up", int64(len(payload)), 80, io.Discard)

	var got bytes.Buffer
	if _, err := io.Copy(&got, m.reader(bytes.NewReader(payload))); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatal("counting reader altered the data")
	}
	if m.n != int64(len(payload)) {
		t.Errorf("counted %d bytes, want %d", m.n, len(payload))
	}
}

func TestRenderDeterminateLayout(t *testing.T) {
	m := newTestMeter("up", 1000, 100, io.Discard)
	line := m.render(500, 1<<20) // 50%, 1 MiB/s

	for _, want := range []string{"pedit: up", "50%", "1.00MiB/s", "ETA", "[", "]", ">"} {
		if !strings.Contains(line, want) {
			t.Errorf("line missing %q:\n%s", want, line)
		}
	}
	if len(line) != m.width-1 {
		t.Errorf("line is %d chars, want exactly %d so the columns never move",
			len(line), m.width-1)
	}
}

// Every frame must be the same length, or the bar resizes as humanBytes
// changes width ("1007.00MiB" -> "1.04GiB") and the right edge visibly
// jitters. This was real, and caught by eye before it was caught here.
func TestRenderLineWidthIsConstantAcrossAFullTransfer(t *testing.T) {
	const total = int64(1) << 31 // 2 GiB, so the unit changes mid-transfer
	m := newTestMeter("down", total, 100, io.Discard)

	seen := map[int]bool{}
	for i := int64(0); i <= 100; i++ {
		n := total * i / 100
		rate := float64(1<<20) * float64(1+i) // rate crosses MiB -> GiB too
		seen[len(m.render(n, rate))] = true
	}
	if len(seen) != 1 {
		t.Errorf("frame width varied across the transfer: %v", seen)
	}
}

func TestRenderIndeterminateShowsElapsedAndNoDeadline(t *testing.T) {
	m := newTestMeter("waiting for approval at home", 0, 100, io.Discard)
	line := m.render(0, 0)

	if !strings.Contains(line, "waiting for approval at home") {
		t.Errorf("label missing:\n%s", line)
	}
	if !strings.Contains(line, "0:00:0") {
		t.Errorf("elapsed clock missing:\n%s", line)
	}
	// It must not imply a limit. A previous heartbeat elsewhere in this
	// project printed a timeout that did not apply to the phase it was
	// shown in, and the user reasonably believed they were on a clock.
	for _, forbidden := range []string{"timeout", "ETA", "%", "remaining", "deadline"} {
		if strings.Contains(strings.ToLower(line), strings.ToLower(forbidden)) {
			t.Errorf("indeterminate meter implies a deadline via %q:\n%s", forbidden, line)
		}
	}
}

// A terminal too narrow for a bar must still produce something sane rather
// than a negative-width bar or a wrapped mess.
func TestRenderNarrowTerminalDropsTheBar(t *testing.T) {
	for _, w := range []int{20, 30, 45, 60} {
		m := newTestMeter("down", 1<<30, w, io.Discard)
		line := m.render(1<<29, 1<<20)
		if len(line) > w-1 {
			t.Errorf("width %d: line is %d chars, must not exceed %d", w, len(line), w-1)
		}
		if strings.Contains(line, "[") && !strings.Contains(line, "]") {
			t.Errorf("width %d: truncated bar left an unbalanced bracket:\n%s", w, line)
		}
	}
}

func TestBarFillTracksPercent(t *testing.T) {
	if got := bar(10, 0); strings.Count(got, "=") != 0 || strings.Count(got, ">") != 0 {
		t.Errorf("0%% bar should be empty, got %q", got)
	}
	full := bar(10, 100)
	if strings.Count(full, "=")+strings.Count(full, ">") != 10 {
		t.Errorf("100%% bar should be full, got %q", full)
	}
	if strings.Contains(full, " ") {
		t.Errorf("100%% bar should have no gap, got %q", full)
	}
	// Over 100% (a file that grew) must clamp rather than overflow.
	over := bar(10, 150)
	if len(over) != 12 {
		t.Errorf("over-100%% bar must clamp to width, got %q (%d)", over, len(over))
	}
}

func TestClockFormat(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{0, "0:00:00"},
		{5 * time.Second, "0:00:05"},
		{75 * time.Second, "0:01:15"},
		{3725 * time.Second, "1:02:05"},
		{-time.Second, "0:00:00"}, // never a negative ETA
	} {
		if got := clock(tc.d); got != tc.want {
			t.Errorf("clock(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

// A transfer that finishes inside renderDelay must print nothing at all --
// otherwise every `pup` of a small config file flashes a bar.
func TestFastTransferDrawsNothing(t *testing.T) {
	var out bytes.Buffer
	m := newTestMeter("up", 1000, 80, &out)
	m.stop = make(chan struct{})
	m.done = make(chan struct{})
	go m.run()

	time.Sleep(renderDelay / 6)
	m.finish()

	if out.Len() != 0 {
		t.Errorf("a fast transfer drew %d bytes: %q", out.Len(), out.String())
	}
}

// ...and a slow one draws, then wipes its line so the final stats start
// on a clean row.
func TestSlowTransferDrawsThenClearsTheLine(t *testing.T) {
	var out bytes.Buffer
	m := newTestMeter("up", 1000, 80, &out)
	m.stop = make(chan struct{})
	m.done = make(chan struct{})
	go m.run()

	time.Sleep(renderDelay + 3*renderInterval)
	m.finish()

	s := out.String()
	if !strings.Contains(s, "pedit: up") {
		t.Fatalf("nothing was drawn:\n%q", s)
	}
	if !strings.HasSuffix(s, "\r") {
		t.Error("the meter did not wipe its line before finishing")
	}
	// Only carriage returns; a newline would scroll a line per frame.
	if strings.Contains(s, "\n") {
		t.Error("the meter emitted a newline; it must redraw in place")
	}
}

func TestFinishIsIdempotent(t *testing.T) {
	var out bytes.Buffer
	m := newTestMeter("up", 1000, 80, &out)
	m.stop = make(chan struct{})
	m.done = make(chan struct{})
	go m.run()
	time.Sleep(renderDelay / 6)
	m.finish()
	m.finish() // must not panic on a re-closed channel
	m.finish()
}

func TestTerminalWidthFallsBackSanely(t *testing.T) {
	// os.Stderr under `go test` is not a terminal, so the ioctl fails and
	// the fallbacks decide.
	t.Setenv("COLUMNS", "")
	if w := terminalWidth(nullFile(t)); w != defaultWidth {
		t.Errorf("width with no COLUMNS = %d, want %d", w, defaultWidth)
	}
	t.Setenv("COLUMNS", "120")
	if w := terminalWidth(nullFile(t)); w != 120 {
		t.Errorf("width from COLUMNS=120 = %d", w)
	}
	// Junk and absurd values must not be trusted.
	for _, bad := range []string{"abc", "0", "5", "-40", "99999999"} {
		t.Setenv("COLUMNS", bad)
		if w := terminalWidth(nullFile(t)); w != defaultWidth {
			t.Errorf("COLUMNS=%q gave width %d, want the %d fallback", bad, w, defaultWidth)
		}
	}
}

// nullFile gives terminalWidth a real *os.File that is definitely not a
// terminal, so only the fallbacks are exercised.
func nullFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

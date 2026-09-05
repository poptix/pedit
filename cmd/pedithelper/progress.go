package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// A pv-style progress meter, in stdlib only -- no terminal library, no
// dependency. pedithelper is a static binary that gets base64'd into a
// shell snippet and pasted onto random hosts, so anything it links is
// something every remote host has to carry.
//
// Two shapes:
//
//	pedit: up 118MiB/485MiB [==========>      ]  24% 62.4MiB/s ETA 0:00:05
//	pedit: waiting for approval at home 0:00:07 /
//
// The second exists because the two-phase protocol means a transfer can sit
// for minutes waiting on a human, and a frozen terminal is indistinguishable
// from a hung one. It shows elapsed time and NOTHING resembling a deadline,
// deliberately: an earlier heartbeat here printed a timeout that did not
// apply to the phase it was printed in, and cost real confusion.

const (
	// Nothing is drawn until a transfer has lasted this long. Small files
	// finish first and print nothing at all, so a quick `pup` of a config
	// file does not flash a bar on screen.
	renderDelay = 300 * time.Millisecond

	renderInterval = 100 * time.Millisecond

	defaultWidth = 80
)

type meter struct {
	// n MUST stay the first field. 64-bit atomics require 8-byte alignment,
	// and on 386/arm -- both build targets -- only the first word of an
	// allocated struct is guaranteed to have it. Moving this down the
	// struct makes atomic.AddInt64 panic on those arches and nowhere else.
	n int64

	label string
	total int64 // 0 means indeterminate: elapsed time and a spinner
	start time.Time
	out   io.Writer
	width int

	stop chan struct{} // nil when the meter is inert (not a terminal, etc)
	done chan struct{}
	once sync.Once

	mu    sync.Mutex
	drawn bool
}

// newMeter starts a meter. total=0 gives the indeterminate form. The
// returned meter is always usable: when progress is switched off or stderr
// is not a terminal it simply draws nothing, so callers never branch.
func newMeter(label string, total int64) *meter {
	m := &meter{label: label, total: total, start: time.Now(), out: os.Stderr}
	if !progressEnabled() {
		return m
	}
	m.width = terminalWidth(os.Stderr)
	m.stop = make(chan struct{})
	m.done = make(chan struct{})
	go m.run()
	return m
}

// reader wraps r so bytes read through it are counted. Reading is what
// both directions have in common: an upload reads the file, a download
// reads the socket.
func (m *meter) reader(r io.Reader) io.Reader { return &countingReader{r: r, m: m} }

type countingReader struct {
	r io.Reader
	m *meter
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		atomic.AddInt64(&c.m.n, int64(n))
	}
	return n, err
}

// finish stops the meter and wipes its line, so whatever the caller prints
// next starts on a clean row. Safe to call more than once, and safe on an
// inert meter.
func (m *meter) finish() {
	if m.stop == nil {
		return
	}
	m.once.Do(func() {
		close(m.stop)
		<-m.done
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.drawn {
			fmt.Fprintf(m.out, "\r%s\r", strings.Repeat(" ", m.width-1))
		}
	})
}

func (m *meter) run() {
	defer close(m.done)

	select {
	case <-m.stop:
		return // finished inside renderDelay; nothing was ever worth drawing
	case <-time.After(renderDelay):
	}

	tick := time.NewTicker(renderInterval)
	defer tick.Stop()

	// Seed the rate window from the start of the transfer, not from now:
	// renderDelay has already elapsed and those bytes are real data. Seeding
	// from the current count instead made the first frame measure a window
	// microseconds wide and print "0B/s ETA --:--:--".
	lastN := int64(0)
	lastAt := m.start
	var rate float64

	for {
		now := time.Now()
		cur := atomic.LoadInt64(&m.n)
		// Rate is smoothed rather than averaged over the whole transfer:
		// an average hides a stall, which is exactly the thing you are
		// watching the meter to notice.
		if dt := now.Sub(lastAt).Seconds(); dt > 0 {
			inst := float64(cur-lastN) / dt
			if rate == 0 {
				rate = inst
			} else {
				rate = 0.7*rate + 0.3*inst
			}
		}
		lastN, lastAt = cur, now

		m.draw(m.render(cur, rate))

		select {
		case <-m.stop:
			return
		case <-tick.C:
		}
	}
}

func (m *meter) draw(line string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.width - 1
	if len(line) > w {
		line = line[:w]
	}
	// Pad to full width so a shrinking line cannot leave the tail of the
	// previous one behind.
	fmt.Fprintf(m.out, "\r%-*s", w, line)
	m.drawn = true
}

func (m *meter) render(n int64, rate float64) string {
	elapsed := time.Since(m.start)
	if m.total <= 0 {
		return truncate(fmt.Sprintf("pedit: %s %s %s",
			m.label, clock(elapsed), spinner(elapsed)), m.width-1)
	}

	pct := 0.0
	if m.total > 0 {
		pct = float64(n) / float64(m.total) * 100
	}
	eta := "--:--:--"
	if rate > 1 && n < m.total {
		eta = clock(time.Duration(float64(m.total-n) / rate * float64(time.Second)))
	}

	// Every field is fixed-width. humanBytes is not ("1.04GiB" vs
	// "1007.00MiB"), so without padding the bar is recomputed to a
	// different size on almost every frame and the right-hand edge visibly
	// jitters. %-4s also lines "up" up with "down" across the two phases of
	// one run.
	left := fmt.Sprintf("pedit: %-4s %10s/%-10s ", m.label, humanBytes(n), humanBytes(m.total))
	right := fmt.Sprintf(" %3.0f%% %11s ETA %s", pct, humanBytes(int64(rate))+"/s", eta)

	// The bar gets whatever is left over. On a terminal too narrow to hold
	// one, fall back to a compact form and clip it -- dropping just the bar
	// still left a line wider than the terminal, which wraps and then
	// scrolls a fresh copy on every frame.
	barWidth := (m.width - 1) - len(left) - len(right) - 2
	if barWidth < 4 {
		return truncate(fmt.Sprintf("pedit: %s %s/%s %3.0f%%",
			m.label, humanBytes(n), humanBytes(m.total), pct), m.width-1)
	}
	return left + bar(barWidth, pct) + right
}

func truncate(s string, w int) string {
	if w < 0 {
		w = 0
	}
	if len(s) > w {
		return s[:w]
	}
	return s
}

func bar(w int, pct float64) string {
	filled := int(float64(w) * pct / 100)
	if filled > w {
		filled = w
	}
	var b strings.Builder
	b.Grow(w + 2)
	b.WriteByte('[')
	for i := 0; i < w; i++ {
		switch {
		case i < filled-1:
			b.WriteByte('=')
		case i == filled-1:
			b.WriteByte('>')
		default:
			b.WriteByte(' ')
		}
	}
	b.WriteByte(']')
	return b.String()
}

// clock formats like pv does: H:MM:SS.
func clock(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int(d / time.Second)
	return fmt.Sprintf("%d:%02d:%02d", s/3600, (s/60)%60, s%60)
}

func spinner(d time.Duration) string {
	const frames = `|/-\`
	return string(frames[int(d/(renderInterval*2))%len(frames)])
}

// progressEnabled reports whether to draw anything at all. Piped or
// redirected output gets nothing: the escape sequences would end up in
// whatever is capturing it, and pedit is used from scripts.
func progressEnabled() bool {
	if os.Getenv("PEDIT_PROGRESS") == "0" || os.Getenv("PEDIT_STATS") == "0" {
		return false
	}
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// terminalWidth asks the terminal, falling back to $COLUMNS and then 80.
// TIOCGWINSZ is the standard ioctl for this and is in the syscall package
// on every arch pedithelper is built for, so it costs no dependency.
func terminalWidth(f *os.File) int {
	var ws struct{ Row, Col, Xpixel, Ypixel uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(),
		uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if errno == 0 && ws.Col > 20 {
		return int(ws.Col)
	}
	if c := os.Getenv("COLUMNS"); c != "" {
		if n, err := parseUint(c); err == nil && n > 20 {
			return n
		}
	}
	return defaultWidth
}

func parseUint(s string) (int, error) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(r-'0')
		if n > 100000 {
			return 0, fmt.Errorf("absurd")
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("empty")
	}
	return n, nil
}

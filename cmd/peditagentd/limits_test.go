package main

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"pedit/internal/wire"
)

// docs/limits.md and the README publish these numbers and this behaviour.
// If the arithmetic drifts, the documentation becomes wrong -- which is
// worse than absent, because the whole point of that document is that
// three disagreeing ceilings once failed silently.

func withLog(t *testing.T, f func()) string {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) }()
	f()
	return buf.String()
}

func TestFrameLimitLeavesRoomForTheEnvelope(t *testing.T) {
	const configured = 10 << 20
	var got int64
	out := withLog(t, func() { got = frameLimitFor(configured) })

	if got <= configured {
		t.Errorf("frame limit %d must exceed max_size_bytes %d, or a file exactly at "+
			"the limit cannot fit with its protocol fields", got, configured)
	}
	if got > configured+(1<<20) {
		t.Errorf("envelope of %d bytes is larger than intended", got-configured)
	}
	// A reachable setting must be reported plainly, with no cap noise.
	if strings.Contains(out, "capped") || strings.Contains(out, "WARNING") {
		t.Errorf("reachable limit should not warn:\n%s", out)
	}
	if !strings.Contains(out, "max transfer 10485760 bytes") {
		t.Errorf("effective size not reported:\n%s", out)
	}
}

// The exact value that failed in the field: above BOTH the uint32 frame
// length and the largest single frame a 64-bit build accepts.
func TestUnreachableConfigWarnsAndReportsEffectiveSize(t *testing.T) {
	const configured = 5048576000
	var got int64
	out := withLog(t, func() { got = frameLimitFor(configured) })

	if got > wire.MaxAllocFrame() {
		t.Errorf("frame limit %d exceeds this build's single-frame ceiling (%d)", got, wire.MaxAllocFrame())
	}
	if got > wire.ProtocolMaxFrame {
		t.Errorf("frame limit %d exceeds the uint32 frame length", got)
	}
	for _, want := range []string{"uint32", "single frame", "capped"} {
		if !strings.Contains(out, want) {
			t.Errorf("startup output should explain %q:\n%s", want, out)
		}
	}
	// The effective number must be the capped one, not the configured one:
	// reporting 5048576000 after capping to ~2 GiB is how an operator comes
	// to believe a limit is in force when it is not.
	if strings.Contains(out, "max transfer 5048576000") {
		t.Errorf("reported the configured size as effective:\n%s", out)
	}
	if !strings.Contains(out, "configured 5048576000") {
		t.Errorf("should still say what was configured:\n%s", out)
	}
}

func TestZeroOrNegativeFallsBackToADefault(t *testing.T) {
	for _, v := range []int64{0, -1} {
		var got int64
		withLog(t, func() { got = frameLimitFor(v) })
		if got <= 0 {
			t.Errorf("frameLimitFor(%d) = %d; must fall back to a usable default", v, got)
		}
	}
}

// The published ceilings themselves.
func TestPublishedCeilings(t *testing.T) {
	if wire.ProtocolMaxFrame != 1<<32-1 {
		t.Errorf("ProtocolMaxFrame = %d; docs say 4 GiB-1 (the uint32 length field)",
			wire.ProtocolMaxFrame)
	}
	alloc := wire.MaxAllocFrame()
	if ^uint(0)>>32 == 0 {
		if alloc != 512<<20 {
			t.Errorf("32-bit buffer ceiling = %d; docs say 512 MiB", alloc)
		}
	} else if alloc != 2<<30 {
		t.Errorf("64-bit buffer ceiling = %d; docs say 2 GiB", alloc)
	}
	if alloc > wire.ProtocolMaxFrame {
		t.Error("the buffer ceiling must not exceed the protocol ceiling")
	}
}

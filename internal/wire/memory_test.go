package wire

import (
	"bytes"
	"encoding/binary"
	"io"
	"runtime"
	"testing"
)

// Memory regression tests.
//
// pedit moves whole files, so an extra copy in the framing path is not a
// micro-optimisation: building a frame the obvious way (encode the payload
// into a buffer, then append that buffer into a frame buffer) cost THREE
// full copies of the file on each side, so a 485 MB transfer wanted around
// 1.5 GB per end. Nothing failed -- it was simply invisible until someone
// looked. These tests make it visible.
//
// They measure runtime.MemStats.TotalAlloc, i.e. cumulative bytes
// allocated, which is exactly the right signal: it counts every copy even
// if each is short-lived and GC'd immediately, unlike a heap-size snapshot.
// Thresholds are expressed as a multiple of the payload so they describe
// intent ("about one copy") rather than a magic number.

// payloadSize is large enough that per-test noise (a few KB) is negligible
// against the multiples being asserted, but small enough to stay quick.
const payloadSize = 32 << 20 // 32 MiB

func allocatedDuring(f func()) int64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return int64(after.TotalAlloc - before.TotalAlloc)
}

// WriteFrameStream must not buffer the body at all: it exists so a client
// can send a file straight from disk.
func TestWriteFrameStreamDoesNotBufferTheBody(t *testing.T) {
	payload := make([]byte, payloadSize)
	header := []byte{0x1b, 0, 0, 0, 4, 't', 'e', 's', 't'}

	alloc := allocatedDuring(func() {
		// bytes.Reader over an existing slice, io.Discard sink: any
		// significant allocation here is the framing layer copying.
		if err := WriteFrameStream(io.Discard, header, bytes.NewReader(payload), int64(len(payload))); err != nil {
			t.Fatal(err)
		}
	})

	// io.CopyN uses a 32 KiB staging buffer; anything near the payload size
	// means the body was buffered.
	if limit := int64(payloadSize) / 8; alloc > limit {
		t.Errorf("WriteFrameStream allocated %d bytes for a %d-byte body (limit %d) -- "+
			"the body is being buffered instead of streamed", alloc, payloadSize, limit)
	}
}

// WriteFrameParts must reference its parts rather than joining them.
func TestWriteFramePartsDoesNotJoinInMemory(t *testing.T) {
	payload := make([]byte, payloadSize)
	header := []byte{0x1d, 0, 0, 0, 4, 't', 'e', 's', 't'}

	alloc := allocatedDuring(func() {
		if err := WriteFrameParts(io.Discard, header, payload); err != nil {
			t.Fatal(err)
		}
	})
	if limit := int64(payloadSize) / 8; alloc > limit {
		t.Errorf("WriteFrameParts allocated %d bytes for a %d-byte payload (limit %d) -- "+
			"parts are being concatenated", alloc, payloadSize, limit)
	}
}

// The old path, kept for callers that want a single buffer, should cost
// about one copy -- not several. This is the guard against someone
// reintroducing nested buffer-building.
func TestBufferBuildCostsAboutOneCopy(t *testing.T) {
	payload := make([]byte, payloadSize)

	alloc := allocatedDuring(func() {
		b := new(Buffer)
		b.Byte(0x1b).String("ext@example.com").Bytes32(payload)
		_ = b.Out()
	})

	// About one copy. No preallocation helper is needed for this: Go's
	// append right-sizes a single large append rather than doubling, which
	// was verified by measurement -- an earlier Grow() method made no
	// difference at all and was removed rather than kept as decoration.
	if limit := int64(float64(payloadSize) * 1.5); alloc > limit {
		t.Errorf("preallocated Buffer build allocated %d bytes for a %d-byte payload "+
			"(limit %d) -- more than one copy", alloc, payloadSize, limit)
	}
}

// Reading a frame should cost one allocation of the frame, and decoding
// fields out of it must not copy them again (Bytes32 returns a slice).
func TestReadFrameAndDecodeCostOneCopy(t *testing.T) {
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i) // non-zero, so a mis-parse cannot look like success
	}
	// type byte, then a properly uint32-length-prefixed field.
	header := []byte{0x1b, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	var framed bytes.Buffer
	if err := WriteFrameParts(&framed, header, payload); err != nil {
		t.Fatal(err)
	}
	raw := framed.Bytes()

	alloc := allocatedDuring(func() {
		f, err := ReadFrameLimit(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatal(err)
		}
		r := NewReader(f[1:])
		got, err := r.Bytes32()
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got) != len(payload) {
			t.Fatalf("decoded %d bytes, want %d", len(got), len(payload))
		}
	})
	if limit := int64(float64(payloadSize) * 1.5); alloc > limit {
		t.Errorf("read+decode allocated %d bytes for a %d-byte payload (limit %d) -- "+
			"decoding is copying fields instead of slicing the frame", alloc, payloadSize, limit)
	}
}

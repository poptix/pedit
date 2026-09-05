package wire

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// wire.go is the layer every other feature sits on -- a framing bug here
// corrupts file transfers silently rather than failing loudly. It had no
// tests at all until an audit found that.

func TestFrameRoundTrip(t *testing.T) {
	for _, body := range [][]byte{
		{0x05},
		[]byte("hello"),
		bytes.Repeat([]byte{0xAB}, 70000), // larger than any plausible buffer
	} {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, body); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("round trip altered a %d-byte body", len(body))
		}
	}
}

func TestReadFrameRejectsZeroLength(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 0})); err == nil {
		t.Error("zero-length frame should be an error, not an empty success")
	}
}

// A peer claiming a huge length must be refused rather than allowed to
// drive an unbounded allocation.
func TestReadFrameRejectsAbsurdLength(t *testing.T) {
	hdr := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	_, err := ReadFrame(bytes.NewReader(hdr))
	if err == nil {
		t.Fatal("absurd length accepted")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("want a 'too large' error, got %v", err)
	}
}

func TestReadFrameTruncatedBody(t *testing.T) {
	// declares 10 bytes, supplies 3
	in := append([]byte{0, 0, 0, 10}, []byte("abc")...)
	if _, err := ReadFrame(bytes.NewReader(in)); err == nil {
		t.Error("truncated body should error")
	}
}

func TestBufferAndReaderRoundTrip(t *testing.T) {
	b := new(Buffer)
	b.Byte(27).String("ext@example.com").Uint32(0xDEADBEEF).Bytes32([]byte{1, 2, 3}).Raw([]byte("tail"))

	r := NewReader(b.Out())
	if v, err := r.Byte(); err != nil || v != 27 {
		t.Fatalf("Byte = %v, %v", v, err)
	}
	if v, err := r.String(); err != nil || v != "ext@example.com" {
		t.Fatalf("String = %q, %v", v, err)
	}
	if v, err := r.Uint32(); err != nil || v != 0xDEADBEEF {
		t.Fatalf("Uint32 = %x, %v", v, err)
	}
	if v, err := r.Bytes32(); err != nil || !bytes.Equal(v, []byte{1, 2, 3}) {
		t.Fatalf("Bytes32 = %v, %v", v, err)
	}
	if got := string(r.Rest()); got != "tail" {
		t.Errorf("Rest = %q, want %q", got, "tail")
	}
}

// Malformed input must produce errors, never a panic or silent truncation:
// these bytes can come from a hostile hop.
func TestReaderHandlesMalformedInput(t *testing.T) {
	cases := [][]byte{
		{},                       // empty
		{0, 0, 0},                // short length prefix
		{0, 0, 0, 9, 'a'},        // string longer than remaining
		{0xFF, 0xFF, 0xFF, 0xFF}, // absurd string length
	}
	for i, c := range cases {
		r := NewReader(c)
		if _, err := r.String(); err == nil {
			t.Errorf("case %d: expected an error for %v", i, c)
		}
	}
	// Byte past the end
	r := NewReader(nil)
	if _, err := r.Byte(); err != io.ErrUnexpectedEOF {
		t.Errorf("Byte on empty = %v, want ErrUnexpectedEOF", err)
	}
}

func TestEmptyStringAndBytesAreValid(t *testing.T) {
	b := new(Buffer)
	b.String("").Bytes32(nil)
	r := NewReader(b.Out())
	if v, err := r.String(); err != nil || v != "" {
		t.Errorf("empty string round trip: %q %v", v, err)
	}
	if v, err := r.Bytes32(); err != nil || len(v) != 0 {
		t.Errorf("empty bytes round trip: %v %v", v, err)
	}
}

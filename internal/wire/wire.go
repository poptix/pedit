// Package wire implements the length-prefixed framing and primitive value
// encoding shared by every SSH agent protocol message (RFC 9987), plus the
// handful of message-type constants pedit actually needs. It does not
// attempt to be a general ssh-agent client/server library -- only extension
// requests/responses and generic pass-through framing.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	MsgAgentFailure       = 5
	MsgAgentSuccess       = 6
	MsgAgentcExtension    = 27
	MsgAgentExtensionResp = 29
)

// ProtocolMaxFrame is the largest frame the wire format can even express:
// the length prefix is a uint32. A configured size limit above this is
// simply unreachable, and saying so at startup beats failing mid-transfer.
const ProtocolMaxFrame int64 = 1<<32 - 1

// MaxFrameLen is the DEFAULT read limit, used by clients that have no
// configured limit of their own. It exists to stop a peer claiming an absurd
// length and forcing a huge allocation.
//
// peditagentd does NOT use this: it derives its limit from max_size_bytes so
// there is exactly one number in play. Having a second, smaller, hardcoded
// ceiling is what made a 485 MB transfer fail as "write: broken pipe" -- the
// daemon rejected the frame header and closed the socket while the client
// was still writing, with the configured 5 GB limit never consulted.
const MaxFrameLen = 256 * 1024 * 1024

// MaxAllocFrame caps what this build could plausibly buffer in memory.
// Frames are held whole in RAM, so on a 32-bit build anything near 2 GiB
// cannot be allocated at all.
func MaxAllocFrame() int64 {
	if ^uint(0)>>32 == 0 { // 32-bit build
		return 512 << 20
	}
	return 2 << 30
}

// ReadFrameHeader reads only the 4-byte length prefix, so a caller can
// decide what to do with the body -- buffer it, relay it, or stream it to
// disk -- without first allocating for it.
func ReadFrameHeader(r io.Reader) (int64, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, err
	}
	n := int64(binary.BigEndian.Uint32(lenBuf[:]))
	if n == 0 {
		return 0, errors.New("wire: zero-length frame")
	}
	return n, nil
}

// ReadFrameBody reads exactly n bytes of an already-headered frame.
//
// Deliberately io.ReadFull on the connection rather than anything buffered:
// a bufio.Reader would read ahead past the end of this frame and silently
// consume the beginning of the next one, desyncing the socket for the rest
// of the process's life.
func ReadFrameBody(r io.Reader, n int64) ([]byte, error) {
	if n > MaxAllocFrame() {
		return nil, fmt.Errorf("wire: frame of %d bytes exceeds what this build can buffer (%d)", n, MaxAllocFrame())
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ReadFrame reads one length-prefixed message using the default limit.
func ReadFrame(r io.Reader) ([]byte, error) {
	return ReadFrameLimit(r, MaxFrameLen)
}

// ReadFrameLimit reads one length-prefixed SSH agent protocol message (the
// type byte is included in the returned slice), refusing anything larger
// than max bytes.
func ReadFrameLimit(r io.Reader, max int64) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int64(binary.BigEndian.Uint32(lenBuf[:]))
	if n == 0 {
		return nil, errors.New("wire: zero-length frame")
	}
	if n > max {
		return nil, fmt.Errorf("wire: frame too large (%d bytes, limit %d)", n, max)
	}
	if n > MaxAllocFrame() {
		return nil, fmt.Errorf("wire: frame of %d bytes exceeds what this build can buffer (%d)", n, MaxAllocFrame())
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// WriteFrameParts writes the concatenation of parts as one length-prefixed
// message WITHOUT joining them in memory first. Building a frame by
// appending a payload into a fresh buffer costs a full extra copy of that
// payload, which for a large file transfer is the difference between one
// copy and three.
func WriteFrameParts(w io.Writer, parts ...[]byte) error {
	var total int64
	for _, p := range parts {
		total += int64(len(p))
	}
	if total > ProtocolMaxFrame {
		return fmt.Errorf("wire: frame of %d bytes exceeds the protocol maximum %d", total, ProtocolMaxFrame)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(total))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	for _, p := range parts {
		if _, err := w.Write(p); err != nil {
			return err
		}
	}
	return nil
}

// WriteFrameStream writes header followed by exactly bodyLen bytes read
// from body, as one length-prefixed message. The body is never held in
// memory, so a client can send a file straight from disk.
//
// A short body is a protocol desync, not a recoverable error: the declared
// length has already gone out. It is reported so the caller abandons the
// connection rather than leaving the peer waiting for bytes that will never
// arrive (which is what a file truncated between stat and read would do).
func WriteFrameStream(w io.Writer, header []byte, body io.Reader, bodyLen int64) error {
	total := int64(len(header)) + bodyLen
	if total > ProtocolMaxFrame {
		return fmt.Errorf("wire: frame of %d bytes exceeds the protocol maximum %d", total, ProtocolMaxFrame)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(total))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	n, err := io.CopyN(w, body, bodyLen)
	if err != nil {
		return err
	}
	if n != bodyLen {
		return fmt.Errorf("wire: declared %d body bytes but sent %d (file changed under us?)", bodyLen, n)
	}
	return nil
}

// WriteFrame writes body as one length-prefixed SSH agent protocol message.
func WriteFrame(w io.Writer, body []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// Buffer is a small append-only builder for SSH-wire primitive values.
type Buffer struct{ b []byte }

func (b *Buffer) Byte(v byte) *Buffer { b.b = append(b.b, v); return b }

func (b *Buffer) Uint32(v uint32) *Buffer {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	b.b = append(b.b, tmp[:]...)
	return b
}

// String appends a uint32-length-prefixed UTF-8 string.
func (b *Buffer) String(s string) *Buffer {
	b.Uint32(uint32(len(s)))
	b.b = append(b.b, s...)
	return b
}

// Bytes32 appends a uint32-length-prefixed raw byte slice.
func (b *Buffer) Bytes32(v []byte) *Buffer {
	b.Uint32(uint32(len(v)))
	b.b = append(b.b, v...)
	return b
}

// Raw appends bytes with no length prefix (used to splice an
// already-encoded sub-message onto the end of a frame).
func (b *Buffer) Raw(v []byte) *Buffer { b.b = append(b.b, v...); return b }

func (b *Buffer) Out() []byte { return b.b }

// Reader parses SSH-wire primitives out of a message body in order.
type Reader struct {
	b   []byte
	pos int
}

func NewReader(b []byte) *Reader { return &Reader{b: b} }

func (r *Reader) Byte() (byte, error) {
	if r.pos >= len(r.b) {
		return 0, io.ErrUnexpectedEOF
	}
	v := r.b[r.pos]
	r.pos++
	return v, nil
}

func (r *Reader) Uint32() (uint32, error) {
	if r.pos+4 > len(r.b) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.BigEndian.Uint32(r.b[r.pos : r.pos+4])
	r.pos += 4
	return v, nil
}

func (r *Reader) String() (string, error) {
	v, err := r.Bytes32()
	if err != nil {
		return "", err
	}
	return string(v), nil
}

func (r *Reader) Bytes32() ([]byte, error) {
	n, err := r.Uint32()
	if err != nil {
		return nil, err
	}
	// Bounded only by what is actually left in the buffer. It used to also
	// enforce MaxFrameLen independently, which made it a THIRD size ceiling:
	// a 300 MB content field inside a frame the caller had already accepted
	// was rejected here as "malformed request". The frame length was
	// validated when it was read; re-imposing a different cap on a field
	// inside it can only disagree with that decision.
	if int64(n) > int64(len(r.b)-r.pos) {
		return nil, io.ErrUnexpectedEOF
	}
	v := r.b[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return v, nil
}

// Rest returns whatever bytes remain unparsed.
func (r *Reader) Rest() []byte { return r.b[r.pos:] }

// Exact field readers, for parsing a frame's prefix straight off a
// connection without buffering the whole frame.
//
// Every one reads exactly the bytes of its field and no more. That is the
// point: a bufio.Reader would read ahead past the field, and past the end
// of the frame, silently swallowing the start of whatever comes next and
// desyncing the socket permanently.

func ReadByteExact(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func ReadUint32Exact(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

// ReadStringExact reads a uint32-length-prefixed string, refusing anything
// longer than max -- the length is attacker-supplied.
func ReadStringExact(r io.Reader, max uint32) (string, error) {
	n, err := ReadUint32Exact(r)
	if err != nil {
		return "", err
	}
	if n > max {
		return "", fmt.Errorf("wire: string of %d bytes exceeds %d", n, max)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

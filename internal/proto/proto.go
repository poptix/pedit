// Package proto defines pedit's own application-layer payload carried
// inside a generic RFC 9987 SSH_AGENTC_EXTENSION request/response -- the
// only thing pedithelper and peditagentd need to agree on. It is deliberately
// separate from wire.go: wire.go knows the SSH agent protocol, proto.go
// knows nothing about sockets or agents, just these two byte layouts.
package proto

import (
	"fmt"
	"os"

	"pedit/internal/wire"
)

// ExtensionType is the RFC 9987 vendor-namespaced extension name. It only
// needs to be a name nobody else uses, not a live/resolvable address.
const ExtensionType = "pedit@hallacy.com"

// PingExtensionType lets one peditagentd recognise another. It exists to
// stop a second instance from taking over a socket the first is already
// listening on: os.Rename happily clobbers, so a naive second start moves
// instance #1's own listening socket onto the ".pedit-real" path that #1
// uses as its backing agent -- at which point #1 dials itself, recurses,
// and exhausts its file descriptors within seconds.
const PingExtensionType = "pedit-ping@hallacy.com"

// BootstrapExtensionType serves pedit.sh itself back down the agent socket,
// so a remote host can source it without scp or a giant clipboard paste.
//
// It's a separate extension rather than a pedit@ profile because it has to
// be reachable *before* pedit.sh exists on the remote side -- i.e. without
// pedithelper, using only whatever generic socket tool happens to be
// installed (socat, nc -U, python). That constrains the wire format: the
// request must be something `printf` can emit as one fixed byte string, so
// it carries a single `string arch` and nothing else. Empty arch = send the
// full multi-arch script.
const BootstrapExtensionType = "pedit-bootstrap@hallacy.com"

// Opcodes for the pedit extension payload. A transfer is two exchanges:
//
//	PREPARE{profile, filename, origin, size} -> {status}      (human approves HERE)
//	CONTENT{raw bytes}                       -> {status, result}
//
// Approval happens before any content is read, so a request the operator
// declines costs nothing: the daemon never allocates for it, never writes
// it to disk, and never reads it off the socket. The previous single-frame
// design ingested up to max_size_bytes and only then asked.
//
// The second exchange carries no length prefix of its own -- the frame
// length delimits the content. One source of truth: a separate inner
// length could disagree with the frame, and the size approved at PREPARE is
// enforced against what the frame actually contains.
const (
	OpPrepare byte = 1
	OpContent byte = 2
)

const (
	StatusOK     byte = 0
	StatusDenied byte = 1
	StatusError  byte = 2

	// StatusOpened means the home side handled the file (handed it to the
	// system handler) and is deliberately returning NO content. The client
	// must leave the local file alone.
	//
	// This needs its own status rather than StatusOK-with-empty-Result:
	// pedithelper writes Result over the target path, so an empty OK would
	// truncate the user's file to zero bytes. Older helpers fall into their
	// default branch and report an error, which is the safe way to fail.
	StatusOpened byte = 3
)

// Meta is everything about a transfer except its bytes. Filename and
// OriginHint are self-reported by the remote and are not a security
// boundary; Size is enforced against the frame that follows.
type Meta struct {
	Profile    string
	Filename   string
	OriginHint string
	Size       int64
}

// MaxMetaField bounds the cosmetic strings so a hostile peer cannot make
// the daemon hold a large "filename". They are shown to a human and used
// for a temp-file basename; nothing needs kilobytes.
const MaxMetaField = 4096

func EncodePrepare(m Meta) []byte {
	buf := new(wire.Buffer)
	buf.Byte(OpPrepare).String(m.Profile).String(m.Filename).String(m.OriginHint).Uint32(uint32(m.Size))
	return buf.Out()
}

// DecodePrepare parses a PREPARE payload (opcode byte already consumed by
// the caller's dispatch is NOT assumed -- pass the full payload).
func DecodePrepare(b []byte) (Meta, error) {
	rd := wire.NewReader(b)
	op, err := rd.Byte()
	if err != nil {
		return Meta{}, fmt.Errorf("proto: opcode: %w", err)
	}
	if op != OpPrepare {
		return Meta{}, fmt.Errorf("proto: expected PREPARE, got opcode %d", op)
	}
	var m Meta
	if m.Profile, err = rd.String(); err != nil {
		return m, fmt.Errorf("proto: profile: %w", err)
	}
	if m.Filename, err = rd.String(); err != nil {
		return m, fmt.Errorf("proto: filename: %w", err)
	}
	if m.OriginHint, err = rd.String(); err != nil {
		return m, fmt.Errorf("proto: origin-hint: %w", err)
	}
	size, err := rd.Uint32()
	if err != nil {
		return m, fmt.Errorf("proto: size: %w", err)
	}
	m.Size = int64(size)
	if n := len(rd.Rest()); n != 0 {
		return m, fmt.Errorf("proto: %d trailing bytes after PREPARE", n)
	}
	for name, v := range map[string]string{
		"profile": m.Profile, "filename": m.Filename, "origin": m.OriginHint,
	} {
		if len(v) > MaxMetaField {
			return m, fmt.Errorf("proto: %s field is %d bytes (max %d)", name, len(v), MaxMetaField)
		}
	}
	return m, nil
}

// ContentHeader is the fixed prefix of a CONTENT frame; the content is
// whatever follows it in the frame, with no length of its own.
func ContentHeader() []byte {
	buf := new(wire.Buffer)
	buf.Byte(wire.MsgAgentcExtension).String(ExtensionType).Byte(OpContent)
	return buf.Out()
}

// PrepareRequestFrame is the complete first-exchange frame body.
func PrepareRequestFrame(m Meta) []byte {
	buf := new(wire.Buffer)
	buf.Byte(wire.MsgAgentcExtension).String(ExtensionType).Raw(EncodePrepare(m))
	return buf.Out()
}

// Response is sent by peditagentd (the home side) after the profile command
// has run (or been denied/failed).
type Response struct {
	Status  byte
	Message string // human-readable; only meaningful for Denied/Error
	Result  []byte // small/in-memory result; empty when ResultPath is used

	// ResultPath names a file to stream back instead of holding the result
	// in memory. The daemon sets this for real transfers: the profile has
	// just written the file, so reading it back into a []byte only to frame
	// it would double the daemon's peak memory for no reason.
	ResultPath string

	// ResultFile is an already-open file to stream back, used in preference
	// to ResultPath. It exists because re-opening by path re-resolves the
	// name: pdown deliberately opens its source with O_NOFOLLOW to refuse a
	// symlink out of the transfer directory, and a later open-by-path would
	// hand that check straight back to whoever could win the race. Handing
	// over the open descriptor closes that window. The receiver owns it and
	// must close it.
	ResultFile *os.File
}

// Encode matches the streamed layout exactly: status, message, then the
// result bytes with NO length of their own -- the frame length delimits
// them. Keeping an inner length here would give the reply two sources of
// truth that could disagree.
func (r Response) Encode() []byte {
	buf := new(wire.Buffer)
	buf.Byte(r.Status).String(r.Message).Raw(r.Result)
	return buf.Out()
}

// ResponseHeader is the fixed prefix of a reply. The result bytes (if any)
// follow it in the same frame, delimited by the frame length -- so a reply
// can be streamed straight from the file the profile produced.
func ResponseHeader(status byte, message string) []byte {
	buf := new(wire.Buffer)
	buf.Byte(wire.MsgAgentExtensionResp).String(ExtensionType).Byte(status).String(message)
	return buf.Out()
}

// ResponseParts is the vectored form for replies whose result is already in
// memory (small ones, and errors). Large results use ResponseHeader plus
// wire.WriteFrameStream instead.
func ResponseParts(resp Response) [][]byte {
	return [][]byte{ResponseHeader(resp.Status, resp.Message), resp.Result}
}

// DecodeResponse parses a reply: status, message, and whatever result bytes
// remain in the frame.
func DecodeResponse(b []byte) (Response, error) {
	rd := wire.NewReader(b)
	var resp Response
	var err error
	if resp.Status, err = rd.Byte(); err != nil {
		return resp, fmt.Errorf("proto: status: %w", err)
	}
	if resp.Message, err = rd.String(); err != nil {
		return resp, fmt.Errorf("proto: message: %w", err)
	}
	resp.Result = rd.Rest()
	return resp, nil
}

// BuildBootstrapRequestFrame builds the fixed request the one-liner emits.
// Kept here (rather than only as a literal in docs) so the byte layout has
// exactly one definition, and BootstrapPrefixLen below stays honest.
func BuildBootstrapRequestFrame(arch string) []byte {
	buf := new(wire.Buffer)
	buf.Byte(wire.MsgAgentcExtension).String(BootstrapExtensionType).String(arch)
	return buf.Out()
}

// BuildBootstrapResponseFrame returns the script as the entire payload,
// with no status byte or length prefix in front of it. That's deliberate:
// the bootstrap client is `tail -c +N`, not a parser, so everything before
// the script must be a fixed, precomputed number of bytes.
func BuildBootstrapResponseFrame(script []byte) []byte {
	buf := new(wire.Buffer)
	buf.Byte(wire.MsgAgentExtensionResp).String(BootstrapExtensionType).Raw(script)
	return buf.Out()
}

// BootstrapResponseParts is the vectored form of
// BuildBootstrapResponseFrame: the script is referenced, not copied.
func BootstrapResponseParts(script []byte) [][]byte {
	buf := new(wire.Buffer)
	buf.Byte(wire.MsgAgentExtensionResp).String(BootstrapExtensionType)
	return [][]byte{buf.Out(), script}
}

// BootstrapPrefixLen is how many leading bytes of the raw socket response
// precede the script: the 4-byte frame length, the 1-byte message type, and
// the length-prefixed extension-type string. `tail -c +(N+1)` strips it.
const BootstrapPrefixLen = 4 + 1 + 4 + len(BootstrapExtensionType)

// BuildExtensionResponseFrame wraps an encoded Response as a complete
// SSH_AGENT_EXTENSION_RESPONSE message body.
func BuildExtensionResponseFrame(resp Response) []byte {
	buf := new(wire.Buffer)
	buf.Byte(wire.MsgAgentExtensionResp).String(ExtensionType).Raw(resp.Encode())
	return buf.Out()
}

// BuildPingRequestFrame / BuildPingResponseFrame implement the liveness
// probe used to detect an existing peditagentd on a socket.
func BuildPingRequestFrame() []byte {
	buf := new(wire.Buffer)
	buf.Byte(wire.MsgAgentcExtension).String(PingExtensionType)
	return buf.Out()
}

func BuildPingResponseFrame() []byte {
	buf := new(wire.Buffer)
	buf.Byte(wire.MsgAgentExtensionResp).String(PingExtensionType)
	return buf.Out()
}

// IsPingResponse reports whether a raw response frame is our own pong.
func IsPingResponse(frame []byte) bool {
	if len(frame) < 1 || frame[0] != wire.MsgAgentExtensionResp {
		return false
	}
	t, err := wire.NewReader(frame[1:]).String()
	return err == nil && t == PingExtensionType
}

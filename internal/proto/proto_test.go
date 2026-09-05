package proto

import (
	"bytes"
	"strings"
	"testing"

	"pedit/internal/wire"
)

func TestPrepareRoundTrip(t *testing.T) {
	in := Meta{Profile: "edit", Filename: "notes.txt", OriginHint: "user@host", Size: 1 << 20}
	got, err := DecodePrepare(EncodePrepare(in))
	if err != nil {
		t.Fatalf("DecodePrepare: %v", err)
	}
	if got != in {
		t.Errorf("round trip differs: %+v vs %+v", got, in)
	}
}

// Metadata is attacker-supplied and is only ever shown to a human or used
// for a temp-file basename; nothing needs kilobytes of it.
func TestPrepareRejectsOversizedMetadata(t *testing.T) {
	huge := strings.Repeat("A", MaxMetaField+1)
	for _, m := range []Meta{
		{Profile: huge, Filename: "f", OriginHint: "o"},
		{Profile: "p", Filename: huge, OriginHint: "o"},
		{Profile: "p", Filename: "f", OriginHint: huge},
	} {
		if _, err := DecodePrepare(EncodePrepare(m)); err == nil {
			t.Error("oversized metadata field accepted")
		}
	}
}

// A PREPARE payload that is not a PREPARE must be refused rather than
// silently misread as one.
func TestDecodePrepareRejectsWrongOpcode(t *testing.T) {
	b := EncodePrepare(Meta{Profile: "p"})
	b[0] = OpContent
	if _, err := DecodePrepare(b); err == nil {
		t.Error("accepted a CONTENT opcode as PREPARE")
	}
}

func TestResponseRoundTrip(t *testing.T) {
	in := Response{Status: StatusDenied, Message: "denied", Result: []byte{1, 2, 3}}
	got, err := DecodeResponse(in.Encode())
	if err != nil {
		t.Fatalf("DecodeResponse: %v", err)
	}
	if got.Status != in.Status || got.Message != in.Message || !bytes.Equal(got.Result, in.Result) {
		t.Errorf("round trip differs: %+v vs %+v", got, in)
	}
}

func TestZeroSizeTransferRoundTrips(t *testing.T) {
	got, err := DecodePrepare(EncodePrepare(Meta{Profile: "p"}))
	if err != nil {
		t.Fatalf("zero-size prepare should decode: %v", err)
	}
	if got.Size != 0 || got.Profile != "p" {
		t.Errorf("got %+v", got)
	}
}

// Truncated/garbage payloads arrive from untrusted hops; they must error
// cleanly rather than panic or yield half-populated structs.
func TestDecodeRejectsTruncatedInput(t *testing.T) {
	full := EncodePrepare(Meta{Profile: "edit", Filename: "f", OriginHint: "o", Size: 2})
	for n := 0; n < len(full); n++ {
		if _, err := DecodePrepare(full[:n]); err == nil {
			t.Errorf("DecodePrepare accepted a %d-byte truncation of %d", n, len(full))
		}
	}
	// A response has no inner result length -- the frame delimits it -- so
	// only truncations that cut into status/message are detectable. Anything
	// after the message IS the result, by definition.
	fullResp := Response{Status: StatusOK, Message: "m", Result: []byte("z")}.Encode()
	headerLen := len(Response{Status: StatusOK, Message: "m"}.Encode())
	for n := 0; n < headerLen; n++ {
		if _, err := DecodeResponse(fullResp[:n]); err == nil {
			t.Errorf("DecodeResponse accepted a %d-byte truncation of its %d-byte header", n, headerLen)
		}
	}
}

// Every extension frame must be a well-formed SSH_AGENTC_EXTENSION whose
// type string an agent can dispatch on -- that's what makes unrelated
// agents answer FAILURE instead of misinterpreting our bytes.
func TestExtensionFramesAreWellFormed(t *testing.T) {
	for name, frame := range map[string][]byte{
		ExtensionType:          PrepareRequestFrame(Meta{Profile: "p"}),
		BootstrapExtensionType: BuildBootstrapRequestFrame("amd64"),
		PingExtensionType:      BuildPingRequestFrame(),
	} {
		if frame[0] != wire.MsgAgentcExtension {
			t.Errorf("%s: type byte = %d, want %d", name, frame[0], wire.MsgAgentcExtension)
		}
		got, err := wire.NewReader(frame[1:]).String()
		if err != nil || got != name {
			t.Errorf("%s: extension type = %q, %v", name, got, err)
		}
	}
}

// Vendor-namespacing is required by RFC 9987 so we can't collide with
// another implementation's extension names.
func TestExtensionTypesAreVendorNamespaced(t *testing.T) {
	for _, n := range []string{ExtensionType, BootstrapExtensionType, PingExtensionType} {
		if !strings.Contains(n, "@") {
			t.Errorf("%q is not vendor-namespaced", n)
		}
	}
}

func TestPingResponseDetection(t *testing.T) {
	if !IsPingResponse(BuildPingResponseFrame()) {
		t.Error("our own ping response was not recognised")
	}
	if IsPingResponse([]byte{wire.MsgAgentFailure}) {
		t.Error("SSH_AGENT_FAILURE misread as a ping response")
	}
	if IsPingResponse(BuildExtensionResponseFrame(Response{})) {
		t.Error("a pedit file response misread as a ping response")
	}
	if IsPingResponse(nil) {
		t.Error("empty frame misread as a ping response")
	}
}

// The CONTENT frame carries no length of its own: the frame length
// delimits the payload. Two lengths that can disagree is a desync waiting
// to happen, so there is exactly one.
func TestContentFrameHasNoRedundantLength(t *testing.T) {
	hdr := ContentHeader()
	rd := wire.NewReader(hdr[1:])
	ext, err := rd.String()
	if err != nil || ext != ExtensionType {
		t.Fatalf("ext = %q, %v", ext, err)
	}
	op, err := rd.Byte()
	if err != nil || op != OpContent {
		t.Fatalf("opcode = %d, %v", op, err)
	}
	if n := len(rd.Rest()); n != 0 {
		t.Errorf("content header has %d trailing bytes; the payload should follow "+
			"the frame directly with no inner length", n)
	}
}

// Same for the response split.
func TestResponsePartsMatchEncodedForm(t *testing.T) {
	resp := Response{Status: StatusOK, Message: "msg", Result: []byte("result bytes")}
	whole := BuildExtensionResponseFrame(resp)
	var joined []byte
	for _, p := range ResponseParts(resp) {
		joined = append(joined, p...)
	}
	if !bytes.Equal(whole, joined) {
		t.Fatalf("split framing differs:\n whole: %x\n parts: %x", whole, joined)
	}
}

// Trailing bytes must be rejected, not ignored. A sender that appends
// opaque data to an otherwise well-formed request would otherwise have it
// silently accepted, and the framing becomes ambiguous for any future
// field. Found by an external review of the protocol.
func TestDecodeRejectsTrailingBytes(t *testing.T) {
	pre := EncodePrepare(Meta{Profile: "edit", Filename: "f", OriginHint: "o", Size: 2})
	if _, err := DecodePrepare(append(pre, 'J', 'U', 'N', 'K')); err == nil {
		t.Error("DecodePrepare accepted trailing bytes")
	}
	// No equivalent check for responses: with no inner length, bytes after
	// the message are the result, so there is no such thing as trailing
	// garbage to reject. Verify that reading instead.
	resp := Response{Status: StatusOK, Message: "m", Result: []byte("z")}
	got, err := DecodeResponse(append(resp.Encode(), 'M', 'O', 'R', 'E'))
	if err != nil {
		t.Fatalf("DecodeResponse: %v", err)
	}
	if string(got.Result) != "zMORE" {
		t.Errorf("result = %q; bytes after the message are part of the result", got.Result)
	}
	// The exact forms must still decode.
	if _, err := DecodePrepare(pre); err != nil {
		t.Errorf("well-formed prepare rejected: %v", err)
	}
	if _, err := DecodeResponse(resp.Encode()); err != nil {
		t.Errorf("well-formed response rejected: %v", err)
	}
}

// Package agentproxy makes peditagentd stand in for the real ssh-agent at
// $SSH_AUTH_SOCK: every normal request is relayed byte-for-byte to the real
// backing agent so signing/identities are completely unaffected, and only
// pedit's own extension type is intercepted and handled locally.
package agentproxy

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"pedit/internal/proto"
	"pedit/internal/wire"
)

// Handler is the daemon's side of a transfer, split in two so that content
// never has to exist in memory.
//
// Prepare runs BEFORE any content is read: it asks a human and hands back
// an open file to stream into. A refusal therefore costs nothing -- no
// allocation, no disk write, and the content is never pulled off the
// socket. Complete runs once the bytes are on disk.
type Handler interface {
	Prepare(meta proto.Meta) (dst *os.File, path string, refusal *proto.Response)
	Complete(meta proto.Meta, path string) proto.Response
}

// BootstrapHandler returns the pedit.sh source to hand back to a remote
// host, optionally trimmed to a single architecture. nil disables the
// bootstrap extension entirely.
type BootstrapHandler func(arch string) ([]byte, error)

// Serve handles one client connection for its whole lifetime. Frames are
// processed strictly in request/response order, matching how a single
// ssh-agent client connection actually behaves.
//
// readLimit bounds a pedit transfer specifically. Ordinary agent messages
// get the larger of that and the generic sanity limit, because this proxy
// sits in front of the user's real agent and must not narrow what it will
// relay.
func Serve(client net.Conn, dialBacking func() (net.Conn, error), handler Handler, bootstrap BootstrapHandler, readLimit int64) {
	defer client.Close()
	var backing net.Conn
	defer func() {
		if backing != nil {
			backing.Close()
		}
	}()

	// Per-connection transfer state. The connection itself is the
	// capability: content is accepted only immediately after an approved
	// PREPARE on this same connection, and only for exactly the approved
	// number of bytes. No token registry, no cross-connection replay,
	// nothing to garbage collect.
	var pending *pendingTransfer
	defer func() {
		if pending != nil {
			pending.abandon()
		}
	}()

	clientLimit := readLimit
	if wire.MaxFrameLen > clientLimit {
		clientLimit = wire.MaxFrameLen
	}

	for {
		frameLen, err := wire.ReadFrameHeader(client)
		if err != nil {
			return
		}

		// A CONTENT frame is expected only while a transfer is pending, and
		// it is the one frame that may be huge. The state machine has
		// already established that it is ours, so it streams straight to
		// disk -- no peeking at attacker-controlled extension names, and
		// the generic relay path below is untouched.
		if pending != nil {
			p := pending
			pending = nil
			resp, ok := p.consume(client, frameLen, handler)
			if !ok {
				return // desync: the only safe move is to hang up
			}
			if !writeResponse(client, resp) {
				return
			}
			continue
		}

		if frameLen > clientLimit {
			return
		}
		frame, err := wire.ReadFrameBody(client, frameLen)
		if err != nil {
			return
		}

		if parts, handled, closeAfter, p := tryHandlePeditExtension(frame, handler, bootstrap); handled {
			pending = p
			if parts != nil && wire.WriteFrameParts(client, parts...) != nil {
				return
			}
			if closeAfter {
				return
			}
			continue
		}

		if backing == nil {
			backing, err = dialBacking()
			if err != nil {
				_ = wire.WriteFrame(client, []byte{wire.MsgAgentFailure})
				continue
			}
		}
		if err := wire.WriteFrame(backing, frame); err != nil {
			backing.Close()
			backing = nil
			_ = wire.WriteFrame(client, []byte{wire.MsgAgentFailure})
			continue
		}
		// The backing agent is the user's own, on a local socket: bound its
		// replies by what we can buffer, not by pedit's transfer policy.
		respFrame, err := wire.ReadFrameLimit(backing, wire.MaxAllocFrame())
		if err != nil {
			backing.Close()
			backing = nil
			_ = wire.WriteFrame(client, []byte{wire.MsgAgentFailure})
			continue
		}
		if wire.WriteFrame(client, respFrame) != nil {
			return
		}
	}
}

// pendingTransfer is an approved-but-not-yet-received transfer.
type pendingTransfer struct {
	meta proto.Meta
	dst  *os.File
	path string
}

func (p *pendingTransfer) abandon() {
	if p.dst != nil {
		p.dst.Close()
		p.dst = nil
	}
	if p.path != "" {
		os.RemoveAll(filepath.Dir(p.path))
	}
}

// consume streams the CONTENT frame to disk and runs the profile. ok=false
// means the stream can no longer be trusted to be in sync and the caller
// must close: a partly-read frame leaves the next read starting mid-message.
func (p *pendingTransfer) consume(client net.Conn, frameLen int64, handler Handler) (proto.Response, bool) {
	hdr := proto.ContentHeader()
	if frameLen < int64(len(hdr)) {
		p.abandon()
		return proto.Response{}, false
	}
	got, err := wire.ReadFrameBody(client, int64(len(hdr)))
	if err != nil {
		p.abandon()
		return proto.Response{}, false
	}
	if string(got) != string(hdr) {
		// Something other than our CONTENT frame arrived mid-transfer. Its
		// remaining bytes belong to a message we have already partly
		// consumed, so there is no safe way to continue.
		p.abandon()
		return proto.Response{}, false
	}

	content := frameLen - int64(len(hdr))
	// Enforce what was approved: a sender that promised N bytes at PREPARE
	// does not get to deliver a different number afterwards.
	if content != p.meta.Size {
		p.abandon()
		return proto.Response{}, false
	}

	if n, err := io.CopyN(p.dst, client, content); err != nil || n != content {
		p.abandon()
		return proto.Response{}, false
	}
	if err := p.dst.Sync(); err != nil {
		p.abandon()
		return proto.Response{Status: proto.StatusError, Message: "could not write the transfer to disk"}, true
	}
	p.dst.Close()
	p.dst = nil

	return handler.Complete(p.meta, p.path), true
}

// writeResponse sends a reply, streaming the result from disk when the
// handler produced a file rather than a buffer.
func writeResponse(client net.Conn, resp proto.Response) bool {
	f := resp.ResultFile
	if f == nil {
		if resp.ResultPath == "" {
			return wire.WriteFrameParts(client, proto.ResponseParts(resp)...) == nil
		}
		var err error
		f, err = os.Open(resp.ResultPath)
		if err != nil {
			return wire.WriteFrameParts(client, proto.ResponseParts(proto.Response{
				Status: proto.StatusError, Message: "result vanished before it could be sent"})...) == nil
		}
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return wire.WriteFrameStream(client, proto.ResponseHeader(resp.Status, resp.Message), f, st.Size()) == nil
}

// tryHandlePeditExtension reports handled=false for anything that isn't a
// SSH_AGENTC_EXTENSION frame naming one of pedit's own extension types --
// including other, unrelated extension types (e.g. openssh's own
// session-bind@openssh.com), which must fall through to the backing agent
// untouched.
func tryHandlePeditExtension(frame []byte, handler Handler, bootstrap BootstrapHandler) (parts [][]byte, handled bool, closeAfter bool, pending *pendingTransfer) {
	if len(frame) < 1 || frame[0] != wire.MsgAgentcExtension {
		return nil, false, false, nil
	}
	rd := wire.NewReader(frame[1:])
	extType, err := rd.String()
	if err != nil {
		return nil, false, false, nil
	}

	switch extType {
	case proto.PingExtensionType:
		// Always answered, even when every other pedit feature is off --
		// its only job is to let a starting instance detect that this
		// socket already belongs to a peditagentd.
		return [][]byte{proto.BuildPingResponseFrame()}, true, false, nil

	case proto.ExtensionType:
		meta, err := proto.DecodePrepare(rd.Rest())
		if err != nil {
			return proto.ResponseParts(proto.Response{
				Status: proto.StatusError, Message: "malformed request"}), true, false, nil
		}
		dst, path, refusal := handler.Prepare(meta)
		if refusal != nil {
			return proto.ResponseParts(*refusal), true, false, nil
		}
		// Approved: acknowledge, and expect exactly one CONTENT frame next.
		return proto.ResponseParts(proto.Response{Status: proto.StatusOK}), true, false,
			&pendingTransfer{meta: meta, dst: dst, path: path}

	case proto.BootstrapExtensionType:
		if bootstrap == nil {
			// Disabled: answer a plain failure rather than forwarding to the
			// real agent, which would only answer failure anyway.
			return [][]byte{{wire.MsgAgentFailure}}, true, true, nil
		}
		arch, err := wire.NewReader(rd.Rest()).String()
		if err != nil {
			return [][]byte{{wire.MsgAgentFailure}}, true, true, nil
		}
		script, err := bootstrap(arch)
		if err != nil {
			return [][]byte{{wire.MsgAgentFailure}}, true, true, nil
		}
		return proto.BootstrapResponseParts(script), true, true, nil
	}
	return nil, false, false, nil
}

// IsPeditAgent reports whether the agent listening on sockPath is itself a
// peditagentd. Used before taking a socket over, so a second instance can
// refuse instead of renaming the first instance's own listening socket onto
// its backing path -- which makes it dial itself and burn through fds.
//
// A plain ssh-agent answers the unknown extension with SSH_AGENT_FAILURE,
// so a false here means "safe to take over".
func IsPeditAgent(sockPath string) bool {
	c, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := wire.WriteFrame(c, proto.BuildPingRequestFrame()); err != nil {
		return false
	}
	frame, err := wire.ReadFrame(c)
	if err != nil {
		return false
	}
	return proto.IsPingResponse(frame)
}

// HandlerFuncs adapts plain functions to Handler. Useful for tests and for
// callers that have no state to carry.
type HandlerFuncs struct {
	PrepareFn  func(proto.Meta) (*os.File, string, *proto.Response)
	CompleteFn func(proto.Meta, string) proto.Response
}

func (h HandlerFuncs) Prepare(m proto.Meta) (*os.File, string, *proto.Response) {
	if h.PrepareFn == nil {
		r := proto.Response{Status: proto.StatusError, Message: "no prepare handler"}
		return nil, "", &r
	}
	return h.PrepareFn(m)
}

func (h HandlerFuncs) Complete(m proto.Meta, path string) proto.Response {
	if h.CompleteFn == nil {
		return proto.Response{Status: proto.StatusError, Message: "no complete handler"}
	}
	return h.CompleteFn(m, path)
}

// RefuseAll is a Handler that declines everything, for tests that only care
// about pass-through or the bootstrap.
type RefuseAll struct{}

func (RefuseAll) Prepare(proto.Meta) (*os.File, string, *proto.Response) {
	r := proto.Response{Status: proto.StatusError, Message: "not used here"}
	return nil, "", &r
}
func (RefuseAll) Complete(proto.Meta, string) proto.Response {
	return proto.Response{Status: proto.StatusError}
}

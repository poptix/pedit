// peditagentd is the long-running daemon at "home": it becomes the new
// $SSH_AUTH_SOCK, proxying every normal request to the real backing agent
// untouched, and locally handling pedit@hallacy.com extension requests --
// profile lookup, size limits, human approval, running the profile command,
// and shipping the result back. See ../../README.md.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"pedit/internal/agentproxy"
	"pedit/internal/approve"
	"pedit/internal/bootstrap"
	"pedit/internal/config"
	"pedit/internal/profile"
	"pedit/internal/proto"
	"pedit/internal/wire"
)

func main() {
	fg := flag.Bool("foreground", false, "stay in the foreground instead of backgrounding")
	flag.Parse()

	cfgPath := "config.toml"
	if flag.NArg() > 0 {
		cfgPath = flag.Arg(0)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("pedit: config: %v", err)
	}

	// Background by default. Running in the foreground meant the daemon's
	// output landed in whatever terminal started it, and then interleaved
	// with every later command in that shell -- including ssh sessions
	// opened from it.
	if !*fg && !cfg.Foreground && !isDaemonChild() {
		daemonize(cfg.LogFile, cfg.PidFile)
		return // daemonize never actually returns
	}

	// Surface misplaced/unknown config keys loudly. A top-level key written
	// below a [section] header parses fine and does nothing -- for something
	// like max_size_bytes that silently removes a limit.
	for _, w := range cfg.Warnings {
		log.Printf("pedit: WARNING: config: %s", w)
	}

	readLimit := frameLimitFor(cfg.MaxSizeBytes)

	backing, listenPath, restorePath := resolveSockets(cfg)
	if backing == listenPath {
		log.Fatalf("pedit: backing_agent and the listen socket are the same path (%s) -- "+
			"that would make peditagentd proxy to itself, recursing until it runs out of "+
			"file descriptors. Point backing_agent at the REAL agent socket.", backing)
	}

	if err := os.MkdirAll(filepath.Dir(listenPath), 0o700); err != nil {
		log.Fatalf("pedit: %v", err)
	}
	os.Remove(listenPath)
	l, err := net.Listen("unix", listenPath)
	if err != nil {
		log.Fatalf("pedit: listen %s: %v", listenPath, err)
	}
	if err := os.Chmod(listenPath, 0o600); err != nil {
		log.Fatalf("pedit: %v", err)
	}
	if restorePath != "" {
		signalReady(fmt.Sprintf("listening at %s (the real agent moved to %s)", listenPath, restorePath))
		log.Printf("pedit: now listening AT the original SSH_AUTH_SOCK path (%s) -- nothing else needs to change; real agent moved to %s", listenPath, restorePath)
		restoreOnSignal(listenPath, restorePath)
	} else {
		signalReady(fmt.Sprintf("listening on %s -- export SSH_AUTH_SOCK=%s to use it", listenPath, listenPath))
		log.Printf("pedit: listening on %s -- export SSH_AUTH_SOCK=%s in shells that should use this", listenPath, listenPath)
	}

	auditPath := cfg.AuditLog
	if err := os.MkdirAll(filepath.Dir(auditPath), 0o700); err != nil {
		log.Fatalf("pedit: %v", err)
	}
	auditFile, err := os.OpenFile(auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Fatalf("pedit: audit log: %v", err)
	}
	audit := log.New(auditFile, "", log.LstdFlags)

	approver, err := buildApprover(cfg)
	if err != nil {
		log.Fatalf("pedit: %v", err)
	}

	// Deliberately not derived from listenPath: in replace-in-place mode
	// that's the real agent's own ephemeral socket directory, and it's not
	// ours to scatter temp files or a tmp/ subdir into.
	tempBase := filepath.Join(filepath.Dir(auditPath), "tmp")
	if err := os.MkdirAll(tempBase, 0o700); err != nil {
		log.Fatalf("pedit: %v", err)
	}

	transferRoot, err := setupTransferDir(cfg.TransferDir)
	if err != nil {
		log.Fatalf("pedit: transfer_dir %s: %v", cfg.TransferDir, err)
	}
	if transferRoot == "" {
		log.Printf("pedit: transfer_dir is unset -- pup/pdown are disabled")
	} else {
		log.Printf("pedit: pup/pdown use %s (confirm_up=%v confirm_down=%v)",
			transferRoot, cfg.ConfirmUp, cfg.ConfirmDown)
	}
	// pup/pdown are handled internally and cannot be redefined. Silently
	// ignoring a config profile of the same name would leave someone
	// believing their own command was running when it never is.
	for _, name := range []string{ProfileUp, ProfileDown} {
		if _, shadowed := cfg.Profiles[name]; shadowed {
			log.Printf("pedit: WARNING: config defines [profiles.%s], but %q is a built-in "+
				"and cannot be overridden -- the built-in is being used and your command "+
				"will never run. Rename that profile.", name, name)
		}
	}

	if cfg.Debug {
		log.Printf("pedit: debug mode on")
	}
	// Say plainly what we proxy to, and whether it actually answers. A dead
	// backing agent otherwise only shows up as "agent refused operation"
	// the first time the user runs ssh, with nothing in the log.
	log.Printf("pedit: proxying non-pedit requests to backing agent %s", backing)
	if n, err := probeBacking(backing); err != nil {
		log.Printf("pedit: WARNING: backing agent %s did not answer at startup: %v -- "+
			"ssh/ssh-add through pedit will get 'agent refused operation' until it does", backing, err)
	} else {
		log.Printf("pedit: backing agent OK (%d identit%s loaded)", n, plural(n))
	}

	handler := &transferHandler{cfg: cfg, approver: approver, tempBase: tempBase,
		audit: audit, transferRoot: transferRoot}
	bootstrapFn := makeBootstrap(cfg, audit)

	// Back off on accept errors instead of retrying instantly. Under fd
	// exhaustion (EMFILE) an immediate `continue` spins at full CPU and
	// floods the console with thousands of identical lines per second,
	// which is how this failure mode first showed up.
	var acceptDelay time.Duration
	for {
		client, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Fatalf("pedit: listen socket closed: %v", err)
			}
			if acceptDelay == 0 {
				acceptDelay = 50 * time.Millisecond
			} else if acceptDelay < 5*time.Second {
				acceptDelay *= 2
			}
			log.Printf("pedit: accept: %v (backing off %s)", err, acceptDelay)
			time.Sleep(acceptDelay)
			continue
		}
		acceptDelay = 0
		if cfg.Debug {
			log.Printf("pedit: debug: accepted a client connection")
		}
		go agentproxy.Serve(client, func() (net.Conn, error) {
			c, derr := net.DialTimeout("unix", backing, 5*time.Second)
			if derr != nil {
				logBackingUnreachable(backing, derr)
				return nil, derr
			}
			if cfg.Debug {
				log.Printf("pedit: debug: dialed backing agent %s for relay", backing)
			}
			return c, derr
		}, handler, bootstrapFn, readLimit)
	}
}

// logBackingUnreachable reports, at most once every 5 seconds, that the
// backing agent could not be reached. Without this a dead backing_agent is
// completely silent: peditagentd answers every relayed request with
// SSH_AGENT_FAILURE, and the user sees only "agent refused operation" from
// ssh/ssh-add with no hint that the daemon cannot reach the real agent
// behind it. This was a real, undiagnosable failure.
func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

var backingLogMu sync.Mutex
var backingLogAt time.Time

func logBackingUnreachable(path string, err error) {
	backingLogMu.Lock()
	defer backingLogMu.Unlock()
	if time.Since(backingLogAt) < 5*time.Second {
		return
	}
	backingLogAt = time.Now()
	log.Printf("pedit: BACKING AGENT UNREACHABLE at %s: %v -- every relayed ssh "+
		"request is being answered with failure ('agent refused operation'). "+
		"The real agent behind pedit is gone or moved; restart it, or restart "+
		"peditagentd against a live one.", path, err)
}

// probeBacking dials the backing agent and asks it for its identity list, so
// startup can say plainly whether the thing pedit proxies to is actually
// answering. Returns the number of identities it reported.
func probeBacking(path string) (int, error) {
	c, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// SSH_AGENTC_REQUEST_IDENTITIES = 11.
	if err := wire.WriteFrame(c, []byte{11}); err != nil {
		return 0, err
	}
	frame, err := wire.ReadFrameLimit(c, wire.MaxAllocFrame())
	if err != nil {
		return 0, err
	}
	// Expected: SSH_AGENT_IDENTITIES_ANSWER = 12, then uint32 count.
	if len(frame) < 5 || frame[0] != 12 {
		return 0, fmt.Errorf("unexpected reply type %d (not an ssh-agent?)", frame[0])
	}
	n, err := wire.NewReader(frame[1:]).Uint32()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// resolveSockets decides where peditagentd listens and what it proxies
// normal requests to. When backing_agent isn't pinned in config, it
// defaults to capturing $SSH_AUTH_SOCK -- and by default (replace_auth_sock)
// takes over that exact path by moving the real agent's socket aside and
// listening there itself, so nothing else (existing shells, cron, whatever
// else has SSH_AUTH_SOCK cached) ever needs to change. restorePath is
// non-empty only when that move happened, so it can be undone on shutdown.
func resolveSockets(cfg config.Config) (backing, listenPath, restorePath string) {
	listenPath = cfg.Listen
	backing = cfg.BackingAgent
	if backing != "" {
		return backing, listenPath, ""
	}

	original := os.Getenv("SSH_AUTH_SOCK")
	if original == "" {
		log.Fatalf("pedit: no backing_agent configured and $SSH_AUTH_SOCK is unset -- " +
			"start peditagentd before repointing SSH_AUTH_SOCK at it, or set backing_agent explicitly")
	}

	if !cfg.ReplaceAuthSock {
		log.Printf("pedit: capturing $SSH_AUTH_SOCK at startup as the backing agent: %s "+
			"(pin this as backing_agent in config.toml for reliability across restarts)", original)
		return original, listenPath, ""
	}

	movedPath := original + ".pedit-real"

	// Guard 1: is a peditagentd already listening there? If so, taking over
	// would rename ITS listening socket onto movedPath -- which is the very
	// path it uses as its backing agent -- making it dial itself and spin
	// until it runs out of file descriptors. Seen in the wild.
	if agentproxy.IsPeditAgent(original) {
		log.Fatalf("pedit: $SSH_AUTH_SOCK (%s) is already served by a peditagentd. "+
			"Refusing to start a second one on the same socket: it would make the "+
			"running instance proxy to itself and exhaust its file descriptors. "+
			"Stop the existing instance first (it restores the real agent socket on "+
			"SIGTERM), or set backing_agent explicitly to run a second one deliberately.",
			original)
	}

	// Guard 2: a leftover .pedit-real means a previous instance died without
	// restoring. Clobbering it would destroy the only remaining reference to
	// the real agent socket.
	if _, err := os.Lstat(movedPath); err == nil {
		log.Fatalf("pedit: %s already exists -- a previous peditagentd exited without "+
			"restoring it. Move it back (mv %s %s) or delete it if the real agent is "+
			"gone, then start again.", movedPath, movedPath, original)
	}

	if err := os.Rename(original, movedPath); err != nil {
		log.Printf("pedit: replace_auth_sock is on but couldn't move %s aside (%v) -- "+
			"falling back to a separate socket; export SSH_AUTH_SOCK=%s yourself", original, err, listenPath)
		return original, listenPath, ""
	}
	return movedPath, original, movedPath
}

// restoreOnSignal moves the real agent's socket back to its original path
// on a clean shutdown, so stopping peditagentd doesn't strand it.
func restoreOnSignal(listenPath, restorePath string) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("pedit: restoring the real agent's socket at %s", listenPath)
		os.Remove(listenPath)
		if err := os.Rename(restorePath, listenPath); err != nil {
			log.Printf("pedit: could not restore %s -> %s: %v", restorePath, listenPath, err)
		}
		os.Exit(0)
	}()
}

func buildApprover(cfg config.Config) (approve.Approver, error) {
	switch cfg.Approver {
	case "exec":
		return approve.ExecApprover{
			AskCommand: cfg.ExecCommand,
			Timeout:    time.Duration(cfg.ExecTimeoutSec) * time.Second,
			Debug:      cfg.Debug,
		}, nil
	case "socket":
		sockPath := cfg.ControlSocket
		a, err := approve.NewSocketApprover(sockPath, time.Duration(cfg.SocketTimeoutSec)*time.Second)
		if err != nil {
			return nil, err
		}
		log.Printf("pedit: run `peditctl %s` in a terminal on this host to approve requests", sockPath)
		return a, nil
	case "serial":
		a, err := approve.NewSerialApprover(cfg.SerialDevice, cfg.SerialBaud, time.Duration(cfg.SerialTimeoutSec)*time.Second)
		if err != nil {
			return nil, fmt.Errorf("serial approver: %w", err)
		}
		log.Printf("pedit: serial approver ready on %s -- requests wait for the board's button", cfg.SerialDevice)
		return a, nil
	default:
		return nil, &configError{cfg.Approver}
	}
}

type configError struct{ approver string }

func (e *configError) Error() string {
	return "unknown approver \"" + e.approver + "\" (must be \"exec\" or \"socket\")"
}

// makeBootstrap serves pedit.sh over the bootstrap extension. Returns nil
// (feature disabled) when no script path is configured.
//
// Deliberately NOT gated behind the approver: it hands back pedit's own
// public shell script, containing no secrets and executing nothing on this
// end, and prompting for a touch every time someone bootstraps a shell
// would make the feature useless. It is audit-logged so the requests are
// still visible.
func makeBootstrap(cfg config.Config, audit *log.Logger) agentproxy.BootstrapHandler {
	if cfg.BootstrapScript == "" {
		return nil
	}
	path := cfg.BootstrapScript
	return func(arch string) ([]byte, error) {
		script, err := bootstrap.Load(path, arch)
		if err != nil {
			audit.Printf("ERROR bootstrap arch=%q err=%v", arch, err)
			return nil, err
		}
		audit.Printf("BOOTSTRAP arch=%q bytes=%d", arch, len(script))
		if cfg.Debug {
			log.Printf("pedit: debug: served bootstrap script (arch=%q, %d bytes)", arch, len(script))
		}
		return script, nil
	}
}

// transferHandler implements agentproxy.Handler. Approval happens in
// Prepare, before a single content byte is read off the socket, so a
// declined request costs nothing: no allocation, no disk, no ingest.
type transferHandler struct {
	cfg      config.Config
	approver approve.Approver
	tempBase string
	audit    *log.Logger

	// transferRoot is the resolved transfer_dir used by the built-in
	// pup/pdown profiles. "" disables them.
	transferRoot string
}

func (h *transferHandler) debugf(format string, args ...interface{}) {
	if h.cfg.Debug {
		log.Printf("pedit: debug: "+format, args...)
	}
}

func refuse(status byte, msg string) *proto.Response {
	r := proto.Response{Status: status, Message: msg}
	return &r
}

func (h *transferHandler) Prepare(meta proto.Meta) (*os.File, string, *proto.Response) {
	h.debugf("PREPARE profile=%q file=%q origin=%q size=%d", meta.Profile, meta.Filename, meta.OriginHint, meta.Size)

	if h.cfg.MaxSizeBytes > 0 && meta.Size > h.cfg.MaxSizeBytes {
		h.audit.Printf("REJECT oversized profile=%q file=%q origin=%q size=%d",
			meta.Profile, meta.Filename, meta.OriginHint, meta.Size)
		return nil, "", refuse(proto.StatusError, "file exceeds max_size_bytes")
	}

	// The built-ins move files in and out of the transfer directory and run
	// nothing, so they bypass the profile table entirely.
	if isBuiltinProfile(meta.Profile) {
		return h.prepareBuiltin(meta)
	}

	prof, ok := h.cfg.Profiles[meta.Profile]
	if !ok {
		h.audit.Printf("REJECT unknown-profile profile=%q file=%q origin=%q",
			meta.Profile, meta.Filename, meta.OriginHint)
		return nil, "", refuse(proto.StatusError, "unknown profile: "+meta.Profile)
	}

	tempDir, tempPath, resolvedCmd, err := prepareTemp(h.tempBase, meta, prof.Command)
	if err != nil {
		h.audit.Printf("ERROR prepare profile=%q file=%q err=%v", meta.Profile, meta.Filename, err)
		return nil, "", refuse(proto.StatusError, "failed to prepare temp file")
	}

	// Ask BEFORE the content exists. The prompt answers "did I start this?",
	// which is what a human can actually judge -- the content type used to
	// be shown here but required ingesting the file first, and whoever ran
	// `pedit` already knows what they sent.
	h.debugf("asking approver (%T) before accepting content...", h.approver)
	start := time.Now()
	approved, err := h.approver.ApproveTransfer(approve.Summary{
		Profile: meta.Profile, Filename: meta.Filename,
		OriginHint: meta.OriginHint, Size: int(meta.Size), OneWay: prof.OneWay,
	})
	h.debugf("approver returned after %s: approved=%v err=%v", time.Since(start), approved, err)
	if err != nil {
		os.RemoveAll(tempDir)
		h.audit.Printf("ERROR approve profile=%q file=%q origin=%q err=%v",
			meta.Profile, meta.Filename, meta.OriginHint, err)
		return nil, "", refuse(proto.StatusError, err.Error())
	}
	if !approved {
		os.RemoveAll(tempDir)
		h.audit.Printf("DENY profile=%q file=%q origin=%q size=%d (nothing was transferred)",
			meta.Profile, meta.Filename, meta.OriginHint, meta.Size)
		return nil, "", refuse(proto.StatusDenied, "denied")
	}

	f, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, "", refuse(proto.StatusError, "failed to open temp file")
	}
	h.debugf("approved; streaming %d bytes to %s (command: %s)", meta.Size, tempPath, resolvedCmd)
	return f, tempPath, nil
}

func (h *transferHandler) Complete(meta proto.Meta, tempPath string) proto.Response {
	if isBuiltinProfile(meta.Profile) {
		return h.completeBuiltin(meta, tempPath)
	}

	tempDir := filepath.Dir(tempPath)
	prof := h.cfg.Profiles[meta.Profile]
	resolvedCmd := profile.Resolve(prof.Command, tempPath)

	// The type is sniffed for the audit trail, not for a decision: approval
	// already happened, and no type gating is applied by design.
	detected := sniffTypeFile(tempPath)

	keepTemp := false
	defer func() {
		if !keepTemp {
			os.RemoveAll(tempDir)
		}
	}()

	start := time.Now()
	if err := h.approver.RunProfile(resolvedCmd); err != nil {
		h.audit.Printf("ERROR run profile=%q file=%q err=%v", meta.Profile, meta.Filename, err)
		return proto.Response{Status: proto.StatusError, Message: err.Error()}
	}
	runDur := time.Since(start)

	if prof.OneWay {
		// Nothing comes back, and the temp file must NOT be deleted yet: a
		// detached handler (xdg-open et al) has only just been handed the
		// path and is still loading it.
		retain := prof.RetainSeconds
		if retain <= 0 {
			retain = config.DefaultRetain
		}
		keepTemp = true
		time.AfterFunc(time.Duration(retain)*time.Second, func() { os.RemoveAll(tempDir) })
		h.audit.Printf("OPEN profile=%q file=%q origin=%q type=%q size=%d retain=%ds run=%s",
			meta.Profile, meta.Filename, meta.OriginHint, detected, meta.Size, retain, runDur)
		return proto.Response{Status: proto.StatusOpened,
			Message: fmt.Sprintf("opened with the system handler (%s); nothing written back", detected)}
	}

	st, err := os.Stat(tempPath)
	if err != nil {
		h.audit.Printf("ERROR readback profile=%q file=%q err=%v", meta.Profile, meta.Filename, err)
		return proto.Response{Status: proto.StatusError, Message: "failed to read back result"}
	}
	h.audit.Printf("ACCEPT profile=%q file=%q origin=%q type=%q size=%d->%d run=%s",
		meta.Profile, meta.Filename, meta.OriginHint, detected, meta.Size, st.Size(), runDur)

	// Streamed from disk by the proxy; the daemon never holds the result.
	// The temp dir must outlive this return, so the proxy can read it.
	keepTemp = true
	time.AfterFunc(30*time.Second, func() { os.RemoveAll(tempDir) })
	return proto.Response{Status: proto.StatusOK, ResultPath: tempPath}
}

// frameLimitFor turns max_size_bytes into the largest frame the daemon will
// accept, adding room for the protocol envelope. It also reports settings
// that cannot actually be honoured, rather than letting a transfer fail
// obscurely mid-write.
func frameLimitFor(maxSize int64) int64 {
	const envelope = 64 << 10
	if maxSize <= 0 {
		maxSize = 10 << 20
	}
	limit := maxSize + envelope

	if limit > wire.ProtocolMaxFrame {
		log.Printf("pedit: WARNING: max_size_bytes=%d exceeds the protocol's uint32 frame "+
			"length field; capping at %d bytes. Transfers larger than that are impossible, "+
			"not merely disallowed.", maxSize, wire.ProtocolMaxFrame-envelope)
		limit = wire.ProtocolMaxFrame
	}
	if limit > wire.MaxAllocFrame() {
		log.Printf("pedit: WARNING: max_size_bytes=%d is larger than the biggest single "+
			"frame this build accepts (%d); capping there.", maxSize, wire.MaxAllocFrame())
		limit = wire.MaxAllocFrame()
	}
	effective := limit - envelope
	if effective == maxSize {
		log.Printf("pedit: max transfer %d bytes", effective)
	} else {
		log.Printf("pedit: max transfer %d bytes (configured %d, capped as above)", effective, maxSize)
	}
	return limit
}

// sniffTypeFile sniffs an on-disk file. Recorded in the audit trail only:
// approval now happens before the content exists, so this cannot inform it.
func sniffTypeFile(path string) string {
	bin, err := exec.LookPath("file")
	if err != nil {
		return ""
	}
	out, err := exec.Command(bin, "--mime-type", "--brief", path).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func prepareTemp(baseDir string, req proto.Meta, cmdTemplate string) (tempDir, tempPath, resolvedCmd string, err error) {
	tempDir, err = os.MkdirTemp(baseDir, "pedit-")
	if err != nil {
		return
	}
	name := filepath.Base(req.Filename)
	if name == "" || name == "." || name == string(filepath.Separator) {
		name = "file"
	}
	tempPath = filepath.Join(tempDir, name)
	resolvedCmd = profile.Resolve(cmdTemplate, tempPath)
	return
}

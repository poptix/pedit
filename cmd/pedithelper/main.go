// pedithelper is the tiny static binary that runs on the remote/deep host.
// It never touches identities or signing -- its whole job is: connect to
// $SSH_AUTH_SOCK, send one pedit@hallacy.com SSH_AGENTC_EXTENSION request
// carrying a file, and write back whatever peditagentd returns. It is what
// pedit.sh self-extracts and execs; it is not meant to be run by hand.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pedit/internal/proto"
	"pedit/internal/wire"
)

func main() {
	switch {
	case len(os.Args) == 6 && os.Args[1] == "send":
		send(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
	case len(os.Args) == 6 && os.Args[1] == "fetch":
		fetch(os.Args[2], os.Args[3], os.Args[4], os.Args[5] == "1")
	default:
		fmt.Fprintln(os.Stderr, "usage: pedithelper send  <sock> <profile> <infile> <outfile>")
		fmt.Fprintln(os.Stderr, "       pedithelper fetch <sock> <name> <outfile> <force:0|1>")
		os.Exit(2)
	}
}

// send pushes a local file up to peditagentd and writes back whatever comes
// out of the profile. An EMPTY outfile means "no content is expected back"
// (pup): if content arrives anyway, that is an error rather than something
// to quietly write somewhere.
func send(sock, profile, infile, outfile string) {

	// Two exchanges: PREPARE (metadata only -- the human approves here,
	// before a single content byte leaves this host) then CONTENT, streamed
	// straight from disk. A declined transfer therefore sends nothing.
	readStart := time.Now()
	src, err := os.Open(infile)
	if err != nil {
		fatalf("open %s: %v", infile, err)
	}
	defer src.Close()
	// fstat the OPEN file rather than the path: stat-then-open lets the file
	// be replaced in between, so metadata and content could describe
	// different objects.
	info, err := src.Stat()
	if err != nil {
		fatalf("stat %s: %v", infile, err)
	}
	if info.IsDir() {
		fatalf("%s is a directory", infile)
	}
	size := info.Size()
	if size > wire.ProtocolMaxFrame {
		fatalf("%s is %d bytes; the protocol's frame length is a uint32, so %d bytes is the absolute maximum",
			infile, size, int64(wire.ProtocolMaxFrame))
	}
	// A round trip has to fit this build's single-frame ceiling in both
	// directions, so a file we can upload may be one we cannot take back.
	// Refuse up front rather than after a full upload -- but only when
	// something IS coming back: an empty outfile (pup) gets no reply
	// content at all, so a round-trip ceiling has nothing to say about it.
	if lim := wire.MaxAllocFrame(); outfile != "" && size > lim {
		fatalf("%s is %d bytes, over this build's single-frame ceiling of %d for a round trip. "+
			"Use `pup` (one way, no reply), or split the file.", infile, size, lim)
	}
	readDur := time.Since(readStart)

	dialStart := time.Now()
	conn, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		fatalf("connect %s: %v (is agent forwarding enabled at every hop back to peditagentd?)", sock, err)
	}
	defer conn.Close()
	if d := deadline(); d > 0 {
		conn.SetDeadline(time.Now().Add(d))
	}
	dialDur := time.Since(dialStart)

	// --- exchange 1: ask permission, send nothing ---
	meta := proto.Meta{
		Profile: profile, Filename: filepath.Base(infile),
		OriginHint: originHint(), Size: size,
	}
	if err := wire.WriteFrame(conn, proto.PrepareRequestFrame(meta)); err != nil {
		fatalf("send request: %v", err)
	}
	// A human is deciding at the other end, which can take as long as it
	// takes. Show that something is happening rather than a dead terminal.
	//
	// Timed, because it used to fall between two timed phases and so was
	// missing from the reported total: a run that spent 1.2s waiting for
	// approval and 1.6s in the command reported "total 1.6s".
	approveStart := time.Now()
	waiting := newMeter("waiting for approval at home", 0)
	ack, err := readPeditResponse(conn)
	waiting.finish()
	approveDur := time.Since(approveStart)
	if err != nil {
		fatalf("%v", err)
	}
	switch ack.Status {
	case proto.StatusOK: // approved
	case proto.StatusDenied:
		fatalf("denied: %s (nothing was transferred)", ack.Message)
	default:
		fatalf("error: %s", ack.Message)
	}

	// --- exchange 2: stream the bytes ---
	sendStart := time.Now()
	up := newMeter("up", size)
	err = wire.WriteFrameStream(conn, proto.ContentHeader(), up.reader(src), size)
	up.finish()
	if err != nil {
		fatalf("send content failed: %v\n"+
			"  The far end approved the transfer and then stopped reading.\n"+
			"  Check max_size_bytes in peditagentd's config.", err)
	}
	sendDur := time.Since(sendStart)

	recvStart := time.Now()
	// The reply header does not arrive until the profile command at home
	// has finished, so this covers someone editing in vim. No deadline is
	// implied or shown: there isn't one on this phase.
	running := newMeter("running at home", 0)
	resp, resultLen, err := readReplyHeader(conn)
	running.finish()
	if err != nil {
		fatalf("%v", err)
	}
	recvDur := time.Since(recvStart) // dominated by the remote command's own run time

	switch resp.Status {
	case proto.StatusOK:
		if outfile == "" {
			fatalf("the far end returned %d bytes of content, but this request "+
				"was not expecting any back -- nothing was written", resultLen)
		}
		writeStart := time.Now()
		down := newMeter("down", resultLen)
		err := streamAtomically(outfile, down.reader(conn), resultLen, info.Mode().Perm(), true)
		down.finish()
		if err != nil {
			fatalf("write %s: %v", outfile, err)
		}
		writeDur := time.Since(writeStart)
		printStats(size, resultLen, readDur, dialDur, sendDur, approveDur+recvDur, writeDur)
	case proto.StatusOpened:
		// One-way profile: nothing comes back. Writing an empty result here
		// would truncate the user's file, so deliberately touch nothing.
		msg := resp.Message
		if msg == "" {
			msg = "opened on the remote side; nothing written back"
		}
		fmt.Fprintf(os.Stderr, "pedit: %s\n", msg)
		// Nothing comes back, but the upload still happened and is still
		// worth a throughput number -- this is the pup path.
		printStats(size, 0, readDur, dialDur, sendDur, approveDur+recvDur, 0)
	case proto.StatusDenied:
		fatalf("denied: %s", resp.Message)
	default:
		fatalf("error: %s", resp.Message)
	}
}

// readReplyHeader parses a reply's prefix field by field, directly off the
// connection, and returns how many result bytes remain in the frame. The
// result is never buffered: the caller streams it.
//
// Exact reads only -- no bufio anywhere near this socket, or it would read
// past the end of the frame and desync everything after it.
func readReplyHeader(conn net.Conn) (resp proto.Response, resultLen int64, err error) {
	frameLen, err := wire.ReadFrameHeader(conn)
	if err != nil {
		return resp, 0, fmt.Errorf("read response: %w", err)
	}
	consumed := int64(0)

	msgType, err := wire.ReadByteExact(conn)
	if err != nil {
		return resp, 0, fmt.Errorf("read response: %w", err)
	}
	consumed++
	if msgType != wire.MsgAgentExtensionResp {
		return resp, 0, fmt.Errorf(
			"agent at the far end does not understand %s (denied at the protocol level, "+
				"or peditagentd isn't running there)", proto.ExtensionType)
	}

	ext, err := wire.ReadStringExact(conn, 256)
	if err != nil || ext != proto.ExtensionType {
		return resp, 0, fmt.Errorf("unexpected extension response")
	}
	consumed += 4 + int64(len(ext))

	if resp.Status, err = wire.ReadByteExact(conn); err != nil {
		return resp, 0, fmt.Errorf("read response status: %w", err)
	}
	consumed++

	if resp.Message, err = wire.ReadStringExact(conn, 64<<10); err != nil {
		return resp, 0, fmt.Errorf("read response message: %w", err)
	}
	consumed += 4 + int64(len(resp.Message))

	resultLen = frameLen - consumed
	if resultLen < 0 {
		return resp, 0, fmt.Errorf("malformed response framing")
	}
	return resp, resultLen, nil
}

// readPeditResponse reads a reply whose result is small enough to hold --
// used for the PREPARE acknowledgement, which carries no result at all.
func readPeditResponse(conn net.Conn) (proto.Response, error) {
	resp, resultLen, err := readReplyHeader(conn)
	if err != nil {
		return resp, err
	}
	if resultLen > 0 {
		// Drain so the connection stays usable, but do not keep it.
		if _, err := io.CopyN(io.Discard, conn, resultLen); err != nil {
			return resp, err
		}
	}
	return resp, nil
}

// streamAtomically copies exactly n bytes from src into a temp file beside
// path, then puts it at path. Nothing is held in memory, and the original
// survives untouched if anything fails part-way.
//
// force chooses how the last step happens, and the difference matters:
// rename replaces whatever is at path, while link fails with EEXIST and
// leaves it alone. The link is what makes `pdown` unable to clobber a file
// you did not say you wanted clobbered -- checking with Stat first would
// leave a window between the check and the write.
func streamAtomically(path string, src io.Reader, n int64, mode os.FileMode, force bool) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".pedit-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	got, err := io.CopyN(tmp, src, n)
	if err != nil {
		tmp.Close()
		return err
	}
	if got != n {
		tmp.Close()
		return fmt.Errorf("expected %d bytes, received %d", n, got)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	if force {
		return os.Rename(tmpName, path)
	}
	// Same directory as the temp file, so EXDEV cannot happen here.
	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists (use -f to overwrite it)", path)
		}
		return err
	}
	return nil
}

// fetch asks peditagentd for a file out of its transfer directory. The
// request itself carries no content: a PREPARE with size 0, then an empty
// CONTENT frame to satisfy the state machine. An empty name asks for a
// listing, which is printed rather than saved.
func fetch(sock, name, outfile string, force bool) {
	listing := name == ""

	// Refuse a doomed download before anyone is asked to approve it. The
	// authoritative check is the O_EXCL link in streamAtomically; this one
	// exists so you don't approve a transfer that cannot land.
	if !listing && !force {
		if _, err := os.Lstat(outfile); err == nil {
			fatalf("%s already exists; refusing to overwrite it (use -f to allow it)", outfile)
		}
	}

	dialStart := time.Now()
	conn, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		fatalf("connect %s: %v (is agent forwarding enabled at every hop back to peditagentd?)", sock, err)
	}
	defer conn.Close()
	if d := deadline(); d > 0 {
		conn.SetDeadline(time.Now().Add(d))
	}
	dialDur := time.Since(dialStart)

	meta := proto.Meta{
		Profile: "pdown", Filename: name,
		OriginHint: originHint(), Size: 0,
	}
	if err := wire.WriteFrame(conn, proto.PrepareRequestFrame(meta)); err != nil {
		fatalf("send request: %v", err)
	}
	approveStart := time.Now()
	waiting := newMeter("waiting for approval at home", 0)
	ack, err := readPeditResponse(conn)
	waiting.finish()
	approveDur := time.Since(approveStart)
	if err != nil {
		fatalf("%v", err)
	}
	switch ack.Status {
	case proto.StatusOK: // approved
	case proto.StatusDenied:
		fatalf("denied: %s (nothing was transferred)", ack.Message)
	default:
		fatalf("error: %s", ack.Message)
	}

	// The state machine expects exactly one CONTENT frame after an approved
	// PREPARE, and exactly meta.Size bytes in it -- zero, here.
	if err := wire.WriteFrameStream(conn, proto.ContentHeader(), bytes.NewReader(nil), 0); err != nil {
		fatalf("send request body: %v", err)
	}

	recvStart := time.Now()
	resp, resultLen, err := readReplyHeader(conn)
	if err != nil {
		fatalf("%v", err)
	}
	recvDur := time.Since(recvStart)

	switch resp.Status {
	case proto.StatusOK:
		if listing {
			if _, err := io.CopyN(os.Stdout, conn, resultLen); err != nil {
				fatalf("read listing: %v", err)
			}
			return
		}
		writeStart := time.Now()
		// 0600: the mode at the far end says nothing about what is
		// appropriate here, and a fetched file should not land readable by
		// everyone on a shared jump host.
		down := newMeter("down", resultLen)
		err := streamAtomically(outfile, down.reader(conn), resultLen, 0o600, force)
		down.finish()
		if err != nil {
			fatalf("write %s: %v", outfile, err)
		}
		writeDur := time.Since(writeStart)
		printStats(0, resultLen, 0, dialDur, 0, approveDur+recvDur, writeDur)
	case proto.StatusDenied:
		fatalf("denied: %s", resp.Message)
	default:
		fatalf("error: %s", resp.Message)
	}
}

// writeAtomically writes via a temp file in the same directory and renames
// over the target, so a failure part-way cannot leave the user with a
// truncated or half-written file.
//
// os.WriteFile opens the target O_TRUNC: it destroys the existing contents
// before the first byte of the replacement is written. For a tool whose
// whole job is "edit my file and give it back", a dropped connection or a
// full disk at that moment means the original is simply gone.
func writeAtomically(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".pedit-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	// fsync before rename: a rename is atomic with respect to the directory
	// entry, but says nothing about whether the data reached disk.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// printStats reports the final line of real transfer timing on every
// successful run, so throughput is always visible rather than something
// you have to wrap in `time` yourself. Halves that did not happen are
// omitted: a pup has no download, a pdown has no upload.
//
// waitDur is reported separately rather than folded into the download.
// It covers everything between "content sent" and "reply header arrives"
// -- approval, plus the profile command's own run time -- which for an
// edit profile is however long you spent in vim. Dividing the downloaded
// bytes by that produced a "MiB/s" that mostly measured how fast someone
// types, which is not a transfer rate.
func printStats(sentBytes, recvBytes int64, readDur, dialDur, sendDur, waitDur, downDur time.Duration) {
	if os.Getenv("PEDIT_STATS") == "0" {
		return
	}
	total := readDur + dialDur + sendDur + waitDur + downDur

	var parts []string
	if sentBytes > 0 {
		parts = append(parts, fmt.Sprintf("%s up in %s (%.2f MiB/s)",
			humanBytes(sentBytes), sendDur.Round(time.Millisecond), mibPerSec(sentBytes, sendDur)))
	}
	if recvBytes > 0 {
		parts = append(parts, fmt.Sprintf("%s down in %s (%.2f MiB/s)",
			humanBytes(recvBytes), downDur.Round(time.Millisecond), mibPerSec(recvBytes, downDur)))
	}
	if waitDur >= 100*time.Millisecond {
		parts = append(parts, fmt.Sprintf("%s waiting at home", waitDur.Round(time.Millisecond)))
	}
	parts = append(parts, "total "+total.Round(time.Millisecond).String())

	fmt.Fprintf(os.Stderr, "pedit: %s\n", strings.Join(parts, " | "))
}

func mibPerSec(n int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(n) / d.Seconds() / (1024 * 1024)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// deadline defaults to 30 minutes (a human may be interactively editing at
// the other end) and can be overridden via PEDIT_TIMEOUT_SECONDS; 0 disables it.
func deadline() time.Duration {
	if v := os.Getenv("PEDIT_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return 30 * time.Minute
}

func originHint() string {
	host, _ := os.Hostname()
	uname := "?"
	if u, err := user.Current(); err == nil {
		uname = u.Username
	}
	return fmt.Sprintf("%s@%s", uname, host)
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "pedithelper: "+format+"\n", args...)
	os.Exit(1)
}

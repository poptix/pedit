package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"pedit/internal/approve"
	"pedit/internal/config"
	"pedit/internal/proto"
)

// The built-in profiles. They share the -p namespace and the same approval
// gate as configured profiles, but their behaviour lives here rather than
// in a `command =` template, for three reasons:
//
//   - Confining a remote-supplied name to one directory is a security
//     boundary. It does not belong in a shell string.
//   - "Don't overwrite" has to be atomic. `cp -n` is not.
//   - Neither of them executes anything at all: RunProfile is never called
//     on this path, so there is strictly less to go wrong than any
//     command-template version of the same feature.
const (
	ProfileUp   = "pup"
	ProfileDown = "pdown"
)

func isBuiltinProfile(name string) bool {
	return name == ProfileUp || name == ProfileDown
}

var errNameTaken = errors.New("name already exists")

// sanitizeName reduces a remote-supplied name to a single path element
// inside the transfer directory. filepath.Base is what makes traversal
// impossible: "../../.ssh/authorized_keys" becomes "authorized_keys",
// which lands in the transfer directory like anything else.
func sanitizeName(name string) (string, error) {
	base := filepath.Base(name)
	switch base {
	case "", ".", "..", string(filepath.Separator):
		return "", fmt.Errorf("%q is not a usable filename", name)
	}
	// Base cannot return a separator, but assert it rather than trust it:
	// this is the one check standing between a remote string and a path.
	if strings.ContainsRune(base, filepath.Separator) {
		return "", fmt.Errorf("%q is not a usable filename", name)
	}
	for _, r := range base {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("filename contains a control character")
		}
	}
	return base, nil
}

// prepareBuiltin handles the approval half of pup/pdown. Everything that
// can refuse does so here, before any content moves in either direction --
// including "that name is already taken", which would otherwise only be
// discovered after a full upload.
func (h *transferHandler) prepareBuiltin(meta proto.Meta) (*os.File, string, *proto.Response) {
	if h.transferRoot == "" {
		return nil, "", refuse(proto.StatusError,
			"pup/pdown are disabled on this agent (transfer_dir is not set)")
	}

	switch meta.Profile {
	case ProfileUp:
		return h.prepareUp(meta)
	case ProfileDown:
		return h.prepareDown(meta)
	}
	return nil, "", refuse(proto.StatusError, "unknown built-in: "+meta.Profile)
}

func (h *transferHandler) prepareUp(meta proto.Meta) (*os.File, string, *proto.Response) {
	name, err := sanitizeName(meta.Filename)
	if err != nil {
		h.audit.Printf("REJECT bad-name profile=%q file=%q origin=%q err=%v",
			meta.Profile, meta.Filename, meta.OriginHint, err)
		return nil, "", refuse(proto.StatusError, err.Error())
	}
	dest := filepath.Join(h.transferRoot, name)

	// Refuse a taken name NOW. The final guard in completeUp is the
	// authoritative one (it is atomic), but discovering the collision only
	// after a 485 MB upload has crossed five hops would be useless.
	if _, err := os.Lstat(dest); err == nil {
		h.audit.Printf("REJECT exists profile=%q file=%q origin=%q dest=%q",
			meta.Profile, meta.Filename, meta.OriginHint, dest)
		return nil, "", refuse(proto.StatusError, fmt.Sprintf(
			"%q already exists in the transfer directory and pup never overwrites -- "+
				"rename it on your end, or move the existing one out of the way at home", name))
	}

	if h.cfg.ConfirmUp {
		ok, refusal := h.ask(approve.Summary{
			Profile: meta.Profile, Filename: name, OriginHint: meta.OriginHint,
			Size: int(meta.Size), Direction: approve.DirUp,
		}, meta)
		if !ok {
			return nil, "", refusal
		}
	}

	// Stream into a temp file first, then move it into place atomically, so
	// a dropped connection cannot leave a half-file in the transfer dir.
	tempDir, tempPath, _, err := prepareTemp(h.tempBase, meta, "")
	if err != nil {
		h.audit.Printf("ERROR prepare profile=%q file=%q err=%v", meta.Profile, meta.Filename, err)
		return nil, "", refuse(proto.StatusError, "failed to prepare temp file")
	}
	f, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, "", refuse(proto.StatusError, "failed to open temp file")
	}
	h.debugf("pup approved; streaming %d bytes for %s", meta.Size, dest)
	return f, tempPath, nil
}

func (h *transferHandler) prepareDown(meta proto.Meta) (*os.File, string, *proto.Response) {
	// A download request carries no payload. Anything else is a client that
	// does not mean what this profile means.
	if meta.Size != 0 {
		return nil, "", refuse(proto.StatusError,
			"pdown requests carry no content; got a non-zero size")
	}

	listing := meta.Filename == ""
	name := ""
	var size int64

	if !listing {
		var err error
		name, err = sanitizeName(meta.Filename)
		if err != nil {
			h.audit.Printf("REJECT bad-name profile=%q file=%q origin=%q err=%v",
				meta.Profile, meta.Filename, meta.OriginHint, err)
			return nil, "", refuse(proto.StatusError, err.Error())
		}
		src := filepath.Join(h.transferRoot, name)
		st, err := os.Lstat(src)
		if err != nil {
			h.audit.Printf("REJECT missing profile=%q file=%q origin=%q",
				meta.Profile, name, meta.OriginHint)
			return nil, "", refuse(proto.StatusError, fmt.Sprintf(
				"%q is not in the transfer directory (run `pdown` with no name to list it)", name))
		}
		// Regular files only. A symlink here would be a way out of the
		// transfer directory, and a directory is not a thing to send.
		if st.Mode()&os.ModeSymlink != 0 {
			h.audit.Printf("REJECT symlink profile=%q file=%q origin=%q",
				meta.Profile, name, meta.OriginHint)
			return nil, "", refuse(proto.StatusError, fmt.Sprintf(
				"%q is a symlink; pdown serves regular files only", name))
		}
		if st.IsDir() {
			return nil, "", refuse(proto.StatusError, fmt.Sprintf(
				"%q is a directory; pdown serves regular files only", name))
		}
		if !st.Mode().IsRegular() {
			return nil, "", refuse(proto.StatusError, fmt.Sprintf(
				"%q is not a regular file", name))
		}
		size = st.Size()

		// The generic ceiling in Prepare tests meta.Size, which is always 0
		// for a download -- so it would never fire here. Check what is
		// actually about to be sent.
		if h.cfg.MaxSizeBytes > 0 && size > h.cfg.MaxSizeBytes {
			h.audit.Printf("REJECT oversized profile=%q file=%q origin=%q size=%d",
				meta.Profile, name, meta.OriginHint, size)
			return nil, "", refuse(proto.StatusError, fmt.Sprintf(
				"%q is %d bytes, over max_size_bytes (%d)", name, size, h.cfg.MaxSizeBytes))
		}
	}

	if h.cfg.ConfirmDown {
		dir, shown := approve.DirDown, name
		if listing {
			dir, shown = approve.DirList, "(directory listing)"
		}
		// Size comes from the stat, not from meta: the requester sends 0 and
		// a prompt reading "0 bytes" for every download would be a lie.
		ok, refusal := h.ask(approve.Summary{
			Profile: meta.Profile, Filename: shown, OriginHint: meta.OriginHint,
			Size: int(size), Direction: dir,
		}, meta)
		if !ok {
			return nil, "", refusal
		}
	}

	// A temp file to absorb the zero-byte CONTENT frame that follows. The
	// state machine always writes one, so give it somewhere to go.
	tempDir, tempPath, _, err := prepareTemp(h.tempBase, meta, "")
	if err != nil {
		return nil, "", refuse(proto.StatusError, "failed to prepare temp file")
	}
	f, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, "", refuse(proto.StatusError, "failed to open temp file")
	}
	return f, tempPath, nil
}

// ask runs the approver and maps its outcome onto a refusal response,
// logging the same way the profile path does.
func (h *transferHandler) ask(sum approve.Summary, meta proto.Meta) (bool, *proto.Response) {
	h.debugf("asking approver (%T) for %s %q", h.approver, sum.Direction, sum.Filename)
	approved, err := h.approver.ApproveTransfer(sum)
	if err != nil {
		h.audit.Printf("ERROR approve profile=%q file=%q origin=%q err=%v",
			meta.Profile, sum.Filename, meta.OriginHint, err)
		return false, refuse(proto.StatusError, err.Error())
	}
	if !approved {
		h.audit.Printf("DENY profile=%q file=%q origin=%q dir=%s (nothing was transferred)",
			meta.Profile, sum.Filename, meta.OriginHint, sum.Direction)
		return false, refuse(proto.StatusDenied, "denied")
	}
	return true, nil
}

// completeBuiltin runs after the CONTENT frame has been consumed. Nothing
// here executes a command.
func (h *transferHandler) completeBuiltin(meta proto.Meta, tempPath string) proto.Response {
	tempDir := filepath.Dir(tempPath)
	if meta.Profile == ProfileUp {
		defer os.RemoveAll(tempDir)
		return h.completeUp(meta, tempPath)
	}
	// pdown's temp file only ever held the empty CONTENT frame; the result
	// it returns is an open descriptor to a file outside this directory, so
	// removing it now is safe.
	os.RemoveAll(tempDir)
	return h.completeDown(meta)
}

func (h *transferHandler) completeUp(meta proto.Meta, tempPath string) proto.Response {
	name, err := sanitizeName(meta.Filename)
	if err != nil {
		return proto.Response{Status: proto.StatusError, Message: err.Error()}
	}
	dest := filepath.Join(h.transferRoot, name)

	st, err := os.Stat(tempPath)
	if err != nil {
		h.audit.Printf("ERROR readback profile=%q file=%q err=%v", meta.Profile, name, err)
		return proto.Response{Status: proto.StatusError, Message: "failed to stat the received file"}
	}

	if err := linkOrCopy(tempPath, dest); err != nil {
		if errors.Is(err, errNameTaken) {
			h.audit.Printf("REJECT exists-race profile=%q file=%q origin=%q dest=%q",
				meta.Profile, name, meta.OriginHint, dest)
			return proto.Response{Status: proto.StatusError, Message: fmt.Sprintf(
				"%q appeared in the transfer directory while this was uploading; "+
					"nothing was overwritten", name)}
		}
		h.audit.Printf("ERROR store profile=%q file=%q dest=%q err=%v",
			meta.Profile, name, dest, err)
		return proto.Response{Status: proto.StatusError, Message: "failed to store the file at home"}
	}

	h.audit.Printf("UP file=%q origin=%q size=%d dest=%q",
		name, meta.OriginHint, st.Size(), dest)
	// StatusOpened, not OK: it tells the client no content is coming back,
	// so it leaves the local file alone instead of truncating it.
	return proto.Response{Status: proto.StatusOpened,
		Message: fmt.Sprintf("stored as %s (%d bytes)", dest, st.Size())}
}

func (h *transferHandler) completeDown(meta proto.Meta) proto.Response {
	if meta.Filename == "" {
		listing, n, err := h.listTransferDir()
		if err != nil {
			h.audit.Printf("ERROR list origin=%q err=%v", meta.OriginHint, err)
			return proto.Response{Status: proto.StatusError, Message: "could not read the transfer directory"}
		}
		h.audit.Printf("LIST origin=%q entries=%d", meta.OriginHint, n)
		return proto.Response{Status: proto.StatusOK, Result: listing}
	}

	name, err := sanitizeName(meta.Filename)
	if err != nil {
		return proto.Response{Status: proto.StatusError, Message: err.Error()}
	}
	src := filepath.Join(h.transferRoot, name)

	// O_NOFOLLOW, then fstat the descriptor we actually hold: between the
	// check in Prepare and this open, the name could have been swapped for
	// a symlink pointing anywhere. Opening with O_NOFOLLOW refuses that
	// outright, and statting the open fd describes the same object we are
	// about to send rather than whatever the name means now. The descriptor
	// itself is handed back so nothing re-resolves the path a third time.
	f, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		h.audit.Printf("ERROR serve profile=%q file=%q err=%v", meta.Profile, name, err)
		return proto.Response{Status: proto.StatusError,
			Message: fmt.Sprintf("could not open %q to send", name)}
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return proto.Response{Status: proto.StatusError,
			Message: fmt.Sprintf("%q is no longer a regular file", name)}
	}
	if h.cfg.MaxSizeBytes > 0 && st.Size() > h.cfg.MaxSizeBytes {
		f.Close()
		return proto.Response{Status: proto.StatusError,
			Message: fmt.Sprintf("%q grew past max_size_bytes before it could be sent", name)}
	}

	h.audit.Printf("DOWN file=%q origin=%q size=%d", name, meta.OriginHint, st.Size())
	return proto.Response{Status: proto.StatusOK, ResultFile: f}
}

// listTransferDir renders the staged files for a human at the far end.
// Regular files only: a symlink or subdirectory in there cannot be fetched,
// so listing it would only invite a request that gets refused.
func (h *transferHandler) listTransferDir() ([]byte, int, error) {
	entries, err := os.ReadDir(h.transferRoot)
	if err != nil {
		return nil, 0, err
	}
	type row struct {
		name string
		size int64
		mod  time.Time
	}
	var rows []row
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		rows = append(rows, row{e.Name(), info.Size(), info.ModTime()})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })

	var b strings.Builder
	if len(rows) == 0 {
		b.WriteString("the transfer directory at home is empty\n")
		return []byte(b.String()), 0, nil
	}
	fmt.Fprintf(&b, "%d file(s) available -- fetch one with: pdown <name>\n", len(rows))
	for _, r := range rows {
		fmt.Fprintf(&b, "  %-40s %12d  %s\n", r.name, r.size, r.mod.Format("2006-01-02 15:04"))
	}
	return []byte(b.String()), len(rows), nil
}

// linkOrCopy puts src at dest without ever overwriting an existing dest.
//
// The hard link is tried first because it is both atomic (it fails with
// EEXIST rather than clobbering) and free regardless of file size. It only
// works within one filesystem, though, and the temp directory lives beside
// the audit log rather than beside the transfer directory -- so the
// fallback is a copy into an O_EXCL file, which is equally unwilling to
// overwrite.
func linkOrCopy(src, dest string) error {
	err := os.Link(src, dest)
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrExist) {
		return errNameTaken
	}
	// EXDEV: different filesystems. EPERM: a filesystem that refuses hard
	// links at all. Anything else is a real failure.
	if !errors.Is(err, syscall.EXDEV) && !errors.Is(err, syscall.EPERM) {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errNameTaken
		}
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dest) // never leave a partial file staged
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(dest)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(dest)
		return err
	}
	return nil
}

// setupTransferDir creates the shared directory and resolves it once, so
// every later name is joined onto a path with no symlinks left in it.
// Returns "" when the feature is switched off.
func setupTransferDir(configured string) (string, error) {
	if configured == "" {
		return "", nil
	}
	path := config.ExpandHome(configured)
	if err := os.MkdirAll(path, 0o700); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

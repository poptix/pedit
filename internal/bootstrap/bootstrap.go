// Package bootstrap serves pedit.sh back down the agent socket so a remote
// host can source it without scp or an 11 MB clipboard paste.
package bootstrap

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"pedit/internal/proto"
)

// requestBytes is exactly what goes on the wire: the 4-byte frame length
// followed by the extension request body.
func requestBytes(arch string) []byte {
	body := proto.BuildBootstrapRequestFrame(arch)
	out := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	return append(out, body...)
}

// KnownArches are the values build.sh emits blobs for, and the only values
// Trim will accept -- an unknown arch returns the untrimmed script rather
// than silently producing one with no usable helper in it.
var KnownArches = []string{"amd64", "arm64", "386", "arm"}

// Load reads pedit.sh and, if arch is one of KnownArches, strips the
// embedded base64 blobs for every *other* architecture. The full script is
// ~11 MB because it carries four ~2.8 MB base64 helpers; trimming takes it
// to roughly a quarter of that, which matters a lot when the bootstrap has
// to cross several ssh hops on a slow link.
//
// Blob lines are recognised structurally (`_pedit_blob_<arch>=` /
// `_pedit_sha256_<arch>=`, one per line, as build.sh generates them) rather
// than by parsing shell, so this stays correct as long as build.sh keeps
// emitting one assignment per line.
func Load(path, arch string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// An empty arch is stage 1 asking for the loader, not for the whole
	// untrimmed script: it has no way to know what the remote host is, so
	// the loader goes and works that out there.
	if arch == "" {
		return Loader(), nil
	}
	if !known(arch) {
		return raw, nil
	}
	return Trim(raw, arch), nil
}

func known(arch string) bool {
	for _, a := range KnownArches {
		if a == arch {
			return true
		}
	}
	return false
}

// Trim removes the blob/checksum assignments for every arch except keep.
func Trim(script []byte, keep string) []byte {
	var out bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(script))
	// Blob lines are megabytes long; the default 64 KB scanner limit would
	// error out partway and silently truncate the script.
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Text()
		if drop(line, keep) {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return script // don't hand back a half-written script
	}
	return out.Bytes()
}

func drop(line, keep string) bool {
	for _, a := range KnownArches {
		if a == keep {
			continue
		}
		if strings.HasPrefix(line, "_pedit_blob_"+a+"=") ||
			strings.HasPrefix(line, "_pedit_sha256_"+a+"=") {
			return true
		}
	}
	return false
}

// OneLiner returns stage 1: the single string you paste.
//
// It is base64 with no whitespace anywhere, because a pasted string has to
// survive being copied by tools that all mangle it differently. Two
// properties do the work:
//
//   - No spaces or tabs at all, so anything that wraps or re-flows at
//     whitespace has nothing to break at. `${IFS}` supplies the separators
//     the shell needs.
//   - The payload sits inside quotes and is filtered through
//     `tr -dc A-Za-z0-9+/=`, so a newline injected anywhere inside it is
//     absorbed as a literal character and then stripped. Measured: a
//     newline at every single position inside the payload still runs.
//
// A newline landing in the ~60-character envelope itself is still fatal --
// nothing can survive that, because the shell executes the first fragment
// the moment it sees the newline. The payload is the overwhelming majority
// of the string, so that is where breaks land.
//
// It takes no arguments. There is exactly one string, and it carries every
// socket client (see `clients`), trying each on the host that runs it. The
// machine generating the string is not the machine that will run it, so it
// cannot know which client is present -- picking one at generation time was
// the mistake this replaces.
//
// OneLinerReadable returns the same command undisguised, for reading before
// you paste something opaque into a shell.
func OneLiner() string {
	blob := base64.StdEncoding.EncodeToString([]byte(stage1Command()))
	return `eval${IFS}"$(echo${IFS}"` + blob + `"|tr${IFS}-dc${IFS}A-Za-z0-9+/=|base64${IFS}-d)"`
}

// OneLinerReadable is what OneLiner encodes: the actual stage-1 command,
// spaces and all. Pasting a base64 blob you cannot read into a shell is a
// bad habit to build, so the plain form stays available.
func OneLinerReadable() string { return stage1Command() }

// Loader is stage 2: the script peditagentd serves when a bootstrap
// request carries an EMPTY arch. It is fetched by the short line from
// OneLiner and then fetches the real pedit.sh itself.
//
// Splitting it this way is the whole point. The pasted line has to survive
// a clipboard, tmux and several ssh hops, so it must be short and one
// line. Everything that is long, or that has to stay in step with the wire
// format, lives here instead -- served by the daemon, versioned with it.
func Loader() []byte { return []byte(loaderScript) }

const loaderScript = `# pedit loader -- served by peditagentd, not pasted. Stage 1 is a short
# line you paste; it fetches this, and this fetches the real pedit.sh for
# whatever architecture the host actually is. Everything version-specific
# lives here, where it ships with the daemon instead of in your clipboard.
_pedit_load() {
  _px=pedit-bootstrap@hallacy.com
  case $(uname -m) in
    x86_64|amd64)        _pa=amd64 ;;
    aarch64|arm64)       _pa=arm64 ;;
    i386|i486|i586|i686) _pa=386 ;;
    arm*)                _pa=arm ;;
    *) echo "pedit: no helper for architecture $(uname -m)" >&2; return 1 ;;
  esac
  _pby() { printf "\\$(printf '%03o' "$1")"; }
  _prq() {
    printf '\000\000\000'; _pby $((9 + ${#_px} + ${#_pa}))
    printf '\033\000\000\000'; _pby ${#_px}; printf '%s' "$_px"
    printf '\000\000\000'; _pby ${#_pa}; printf '%s' "$_pa"
  }
  # Same client set and order as stage 1 (perl, python3, socat, nc); this
  # is served, so verbosity is free.
  for _pt in perl python3 socat nc; do
    command -v "$_pt" >/dev/null 2>&1 || continue
    case $_pt in
      perl)    _ps=$(_prq | perl -e 'use Socket;socket S,AF_UNIX,SOCK_STREAM,0;connect S,sockaddr_un $ENV{SSH_AUTH_SOCK};syswrite S,do{local$/;<STDIN>};print while sysread S,$_,9999' 2>/dev/null | tail -c +37) ;;
      python3) _ps=$(_prq | python3 -c 'import socket,sys,os;s=socket.socket(1);s.connect(os.environ["SSH_AUTH_SOCK"]);s.sendall(sys.stdin.buffer.read());[sys.stdout.buffer.write(c)for c in iter(lambda:s.recv(9999),b"")]' 2>/dev/null | tail -c +37) ;;
      socat)   _ps=$(_prq | socat -t30 - UNIX-CONNECT:"$SSH_AUTH_SOCK",shut-none 2>/dev/null | tail -c +37) ;;
      nc)      _ps=$(_prq | nc -U "$SSH_AUTH_SOCK" 2>/dev/null | tail -c +37) ;;
    esac
    case "$_ps" in "# pedit"*) break ;; *) _ps= ;; esac
  done
  if [ -z "$_ps" ]; then
    echo "pedit: could not fetch the $_pa helper. Needs perl, python3, socat or a netcat with -U on this host." >&2
    unset _px _pa _ps _pt; unset -f _pby _prq; return 1
  fi
  eval "$_ps"
  unset _px _pa _ps _pt; unset -f _pby _prq
}
_pedit_load; unset -f _pedit_load
`

// clients are the ways to speak to a unix socket from a shell, tried in
// order until one produces a script. They are all carried in the one
// pasted string rather than chosen when it is generated, because the
// machine generating it is not the machine that will run it.
//
// Order is by reliability, not popularity: socat is purpose-built, perl and
// python3 are explicit about buffering, and nc is last because -U is absent
// from GNU and busybox netcat.
//
// NONE of them may half-close. OpenSSH's agent forwarding tears the channel
// down when it sees EOF from the client and discards the pending reply --
// measured over a real forwarded agent as 2810178 bytes without half-close,
// 0 with it. socat needs shut-none for this, and nc must not be given -N.
//
// perl uses syswrite rather than print: buffered output never reaches the
// server, so the request is never sent and the read blocks forever. That
// hangs rather than fails, which is worse.
var clients = []string{
	// perl first: on Debian/Ubuntu perl-base is an Essential package
	// (Priority: required), so it survives on minimal/slim/container images
	// where python3 is stripped, and on RHEL it is in @core. AF_UNIX is via
	// the core Socket module (sockaddr_un) -- NOT IO::Socket::UNIX, which is
	// a separate package. Golfed: barewords, no binmode (Linux has no text
	// mode), $x scratch var.
	`perl -e 'use Socket;socket S,AF_UNIX,SOCK_STREAM,0;` +
		`connect S,sockaddr_un $ENV{SSH_AUTH_SOCK};syswrite S,do{local$/;<STDIN>};` +
		`print while sysread S,$_,9999'`,

	// python3 second: default on RHEL/Fedora minimal and standard Ubuntu.
	// socket.socket(1) is AF_UNIX on Linux. iter(...,b"") reads to EOF.
	`python3 -c 'import socket,sys,os;s=socket.socket(1);` +
		`s.connect(os.environ["SSH_AUTH_SOCK"]);s.sendall(sys.stdin.buffer.read());` +
		`[sys.stdout.buffer.write(c)for c in iter(lambda:s.recv(9999),b"")]'`,

	// socat when present is the least ambiguous, but it is never the *only*
	// client on a base image, so it comes after the interpreters that might
	// be. shut-none: it must not half-close, or ssh -A drops the reply.
	`socat -t30 - UNIX-CONNECT:"$SSH_AUTH_SOCK",shut-none`,

	// nc last: -U is absent from GNU netcat and its half-close behaviour
	// varies, so it is the fallback, not the default. Plain -U, never -N.
	`nc -U "$SSH_AUTH_SOCK"`,
}

// stage1Command builds the command the pasted string carries. It takes no
// arguments: the architecture is the loader's job, and the socket tool is
// decided on the host that runs it by trying each in turn.
//
// The request emitter is a function because each attempt needs its own copy
// of the bytes -- a single pipeline would hand them to the first client and
// leave the rest with empty stdin.
//
// De-framing happens inside each pipeline, not after. The reply's prefix
// contains NUL bytes and command substitution drops them, so capturing
// first and stripping later would strip the wrong number of bytes.
//
// The guard is not optional. Every failure here -- a plain ssh-agent at the
// far end, an agent too old to know the extension, bootstrap_script unset,
// SSH_AUTH_SOCK empty, or no usable client on the host -- ends with zero
// bytes, and evaluating nothing succeeds silently, leaving you at a prompt
// with no pedit and no error. The byte count and socket path are what make
// it diagnosable: "0B from " with nothing after it is an unset variable.
//
// `case` rather than ${_p#prefix} for the marker test: the marker starts
// with '#', which collides with the parameter-expansion strip operator.
func stage1Command() string {
	req := octalEscape(requestBytes(""))
	strip := proto.BootstrapPrefixLen + 1 // tail -c is 1-indexed

	var b strings.Builder
	fmt.Fprintf(&b, `_r(){ printf '%s';};for _t in`, req)
	for i := range clients {
		fmt.Fprintf(&b, " %d", i+1)
	}
	b.WriteString(`;do case $_t in `)
	for i, c := range clients {
		fmt.Fprintf(&b, `%d)_p=$(_r|%s 2>/dev/null|tail -c+%d);;`, i+1, c, strip)
	}
	fmt.Fprintf(&b, `esac;case "$_p" in %q*)break;;esac;done;`, scriptMarker)
	fmt.Fprintf(&b, `case "$_p" in %q*)eval "$_p";;`+
		`*)echo "pedit: bootstrap failed, ${#_p}B from $SSH_AUTH_SOCK">&2;;`+
		`esac;unset _p _t;unset -f _r`, scriptMarker)
	return b.String()
}

// scriptMarker is the literal first bytes of a generated pedit.sh (see the
// HEADER block in build.sh). Used only as a sanity check that we got a
// script back rather than a protocol failure.
const scriptMarker = "# pedit"

func octalEscape(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		// Printable, non-special ASCII passes through so the command stays
		// readable; everything else is octal, which every POSIX printf takes.
		if c >= 0x20 && c < 0x7f && c != '\\' && c != '\'' && c != '%' {
			sb.WriteByte(c)
			continue
		}
		fmt.Fprintf(&sb, `\%03o`, c)
	}
	return sb.String()
}

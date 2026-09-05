# Protocol and architecture

## Why this works at all

[RFC 9987](https://www.rfc-editor.org/rfc/rfc9987) defines a generic
`SSH_AGENTC_EXTENSION` request that any client may send to an agent,
answered with an extension-specific response or a failure. Agent forwarding
at every `ssh -A` hop is a dumb, length-prefixed byte relay — it does not
parse message types — so a vendor-namespaced extension sent from the bottom
of an arbitrarily deep hop chain transits every hop untouched and lands on
whatever is bound to `$SSH_AUTH_SOCK` at the top.

pedit puts a daemon there instead of a stock agent.

## The three pieces

- **`pedit.sh`** — a plain bash function, pastable into any remote shell. On
  first use it self-extracts an embedded static binary to a private temp
  dir, verifying its checksum before executing it. Needs only coreutils
  (`base64`, `mktemp`, `sha256sum`): no python, perl, socat or netcat in the
  critical path. Bash cannot open a unix socket, which is the constraint the
  whole design is built around.
- **`pedithelper`** — the extracted static binary. Connects to
  `$SSH_AUTH_SOCK`, speaks the extension, writes back what comes back. Never
  touches identities or signing.
- **`peditagentd`** — the daemon at home. It becomes the new
  `$SSH_AUTH_SOCK`: every normal request (`SIGN_REQUEST`,
  `REQUEST_IDENTITIES`, any other extension type) is relayed byte-for-byte
  to the real backing agent, unaffected. Only pedit's own extension types
  are intercepted.

Extension types: `pedit@hallacy.com` (transfers),
`pedit-bootstrap@hallacy.com` (serving `pedit.sh`), `pedit-ping@hallacy.com`
(so one instance can recognise another and refuse to take over its socket).

## Two-phase transfer

A transfer is two exchanges on one connection:

1. **PREPARE** — metadata only: profile, filename, origin hint, size. The
   human approves here, before any content leaves the remote host. A refusal
   costs nothing on either end.
2. **CONTENT** — the bytes, streamed straight from disk to disk. The daemon
   enforces exactly the size that was approved.

The connection itself is the capability: content is accepted only
immediately after an approved PREPARE on that same connection, and only for
that many bytes. No token registry, no cross-connection replay, nothing to
garbage collect.

A download (`pdown`) reuses the same shape with `Size = 0` and an empty
CONTENT frame, so it needs no new wire format.

## Framing rules that are load-bearing

- **Never use `bufio` on the agent socket.** Read-ahead consumes bytes past
  the end of a frame and desyncs everything after it, permanently. Fields
  are read with exact-length reads.
- **The reply carries no inner result length.** The frame length delimits
  it. Two lengths that can disagree is a desync waiting to happen, so there
  is exactly one.
- **Trailing bytes are rejected**, not ignored, so the framing stays
  unambiguous for any future field.

## The bootstrap

`pedit.sh` is about 12 MB (four embedded architecture helpers), so pasting
it is unpleasant and `scp` may be exactly what you cannot do. With
`bootstrap_script` set, `peditagentd` serves the script back over the same
forwarded socket, trimmed to one architecture (about 3 MB):

```bash
peditbootstrap   # the string to paste, no arguments
```

**It is two stages.** What you paste is deliberately short and one line,
because it has to survive a clipboard, tmux and several ssh hops. It asks
for an *empty* arch, which `peditagentd` answers with a small loader
(`bootstrap.Loader`) rather than the ~12 MB script. The loader then runs
`uname -m` on the remote host and fetches the real `pedit.sh` for that
architecture. Anything long, and anything that has to stay in step with the
wire format, lives in the loader -- served by the daemon and versioned with
it, rather than sitting in your clipboard.

Stage 1, as generated (one line; wrapped here for reading):

```bash
if [ -z "$SSH_AUTH_SOCK" ]; then echo "pedit: \$SSH_AUTH_SOCK is empty ..." >&2; else
_p=$(printf '\000\000\000$\033\000\000\000\033pedit-bootstrap@hallacy.com\000\000\000\000' \
  | socat -t30 - UNIX-CONNECT:"$SSH_AUTH_SOCK",shut-none | tail -c +37)
case "$_p" in "# pedit"*) eval "$_p";;
  *) echo "pedit: bootstrap failed (${#_p} bytes) ..." >&2;; esac; unset _p; fi
```

It uses `eval`, not `source`/`<<<`, so it runs in dash and busybox sh as
well as bash.

### Surviving a clipboard

What `peditbootstrap` actually prints is that command base64'd inside a
whitespace-free envelope, because a pasted string gets copied by tools that
each mangle it differently:

```
eval${IFS}"$(echo${IFS}"aWYgWyAteiAiJFNTSF9BVVRIX1NPQ0si..."|tr${IFS}-dc${IFS}A-Za-z0-9+/=|base64${IFS}-d)"
```

Two properties do the work:

- **No spaces or tabs anywhere**, so anything that wraps or re-flows at
  whitespace has nothing to break at. `${IFS}` supplies the separators the
  shell needs.
- **The payload is quoted and filtered.** A newline injected anywhere
  inside it is absorbed as a literal character (the shell keeps reading to
  the closing quote) and then stripped by `tr -dc A-Za-z0-9+/=`. Measured
  against a live daemon: a newline at every tested position inside the
  payload still bootstraps.

A newline landing in the ~60-character envelope itself is still fatal, and
nothing can change that — the shell runs the first fragment the moment it
sees the newline. The payload is around 95% of the string, so that is where
breaks land.

`peditbootstrap -readable` prints the decoded command. Pasting a base64
blob you cannot read into a shell is a bad habit, so the plain form stays
available.

### One string, every image

`peditbootstrap` takes **no arguments**. There is exactly one string and it
works on any host, because it carries every way to speak to a unix socket
from a shell and tries each in turn until one reaches the agent:

1. **perl** -- on Debian/Ubuntu `perl-base` is an Essential package
   (Priority: required), so it survives on minimal/slim/container images
   where `python3` is stripped out; on RHEL it is in `@core`. AF_UNIX is via
   the core `Socket` module, not `IO::Socket::UNIX` (a separate package).
2. **python3** -- default on RHEL/Fedora minimal and standard Ubuntu.
3. **socat** -- unambiguous when present, but never the *only* client on a
   base image, so it follows the interpreters.
4. **nc -U** -- last: `-U` is absent from GNU netcat and its half-close
   behaviour varies, so it is a fallback, not a default.

Between them these cover Debian/Ubuntu (perl), RHEL/Fedora (python3/nc),
Alpine (busybox nc), and anything with socat. `curl --unix-socket` is
deliberately NOT used: it speaks HTTP, not the raw framed bytes this
protocol needs.

The cost is length -- carrying four inline clients plus the base64 envelope
is about 1232 characters (`peditbootstrap -readable` shows the decoded
command). That is the price of "no arguments, works everywhere": the
earlier per-tool form was ~400 characters but only worked if the single
tool it was generated for happened to be installed.

The guard stays: every failure ends with zero bytes, and evaluating nothing
succeeds silently, so the string reports the byte count and socket path --
`0B from ` with nothing after it is an unset `SSH_AUTH_SOCK`; `0B from
/path` is a socket that is not a peditagentd with `bootstrap_script` set.
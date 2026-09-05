# Size limits, and why each one exists

pedit has several ceilings on how big a single transfer can be. They exist
for different reasons and fail in different ways, and for a while they
disagreed with each other — which is how a 485 MB file came to fail as
`write: broken pipe` under a 5 GB configured limit. This is the whole
picture.

## The numbers

| Limit | Value | Set by | Can you change it? |
|---|---|---|---|
| Protocol frame length | 4 GiB − 1 (`uint32`) | The SSH agent wire format | No |
| Largest single frame | 2 GiB (64-bit) / 512 MiB (32-bit) | Cap on one contiguous frame | Only in source |
| `max_size_bytes` | default 10 MiB | You, in `config.toml` | Yes — this is the knob |
| Client default frame limit | 256 MiB | `wire.MaxFrameLen` | Only in source |

`peditagentd` derives its wire frame limit from `max_size_bytes` (plus a
64 KiB envelope for the protocol fields), so **`max_size_bytes` is the only
size knob an operator needs**. It logs the **effective** limit at
startup and warns if you configured something unreachable — reporting the
configured number after silently capping it is how an operator comes to
believe a 5 GB limit is in force when the real ceiling is ~2 GiB:

```
pedit: WARNING: max_size_bytes=5048576000 exceeds the protocol's uint32 frame length field ...
pedit: WARNING: max_size_bytes=5048576000 is larger than this build can buffer in memory (2147483648) ...
pedit: max transfer 2147418112 bytes (configured 5048576000, capped as above)
```

## Why each exists

**The `uint32` frame length — 4 GiB − 1.** Every SSH agent protocol message
is a 4-byte big-endian length followed by that many bytes. pedit rides
inside `SSH_AGENTC_EXTENSION` messages, so it inherits the framing. This is
not a policy choice and cannot be raised without leaving the protocol —
which would mean giving up the property the whole tool is built on, that an
unmodified `ssh -A` chain relays our messages without understanding them.

**Largest single frame — 2 GiB, or 512 MiB on 32-bit.** Transfers
themselves stream and are never held whole (see the measurements below), so
this no longer bounds how big a file can be moved. It bounds the frames that
*are* read whole: ordinary agent messages relayed to and from your real
agent, which are small, and it doubles as a sanity cap on any single frame.
A frame is one contiguous `[]byte`, so a 32-bit build cannot address
anything near 2 GiB, and on 64-bit a multi-gigabyte allocation is a poor bet
on a machine also running a desktop. Refusing early beats an OOM kill.

**`max_size_bytes` — operator policy.** Anyone who can reach a forwarded
agent socket at any hop can send pedit a frame; this bounds what they can
make the daemon allocate and write to disk. It is deliberately small by
default (10 MiB) because the common case is editing a config file, not
moving archives.

**The 256 MiB client default.** `pedithelper` and the bootstrap client have
no config file to read, but still must not trust a length claimed by
whatever is on the other end of the socket. They need *some* bound, and this
is it. `peditagentd` does **not** use it — that was the bug.

## Memory model (measured)

Peak RSS for a 200 MB transfer, measured in the e2e suite and enforced
there so it cannot regress:

| Process | Peak RSS | × file size |
|---|---|---|
| `pedithelper` sending | 3.4 MB | **0.016×** |
| `pedithelper` round trip | 3.4 MB | **0.016×** |
| `peditagentd` | 5.5 MB | **0.026×** |

Nothing holds a transfer in memory on either end any more: memory is
O(copy buffer), not O(file). A 485 MB transfer needs a few megabytes.

It took three rounds to get here, and the history is the useful part:

1. **~3× per side.** A frame was built by encoding the payload into a
   buffer and then appending that whole buffer into a second one.
2. **Client send → 0.019×, daemon → 2.03×.** `wire.WriteFrameStream` and
   `wire.WriteFrameParts` removed the redundant copies, and the client
   started sending straight from an open file. The daemon still held the
   inbound frame whole and read the result back to reply.
3. **Everything → ~0.02×.** The daemon streams the incoming content field
   directly to its temp file and streams the reply back out of it; the
   client parses the reply prefix field-by-field off the socket and streams
   the result into a temp file which it then renames into place.

Step 3 was initially declined on the grounds that incremental parsing in
the proxy would endanger the byte-for-byte pass-through of unrecognised
agent messages. An external review of the protocol said that reasoning was
wrong -- pass-through needs unmodified *bytes*, not a contiguous `[]byte` --
and it was right. What actually made it safe was unrelated: two-phase
approval means the large frame arrives when the connection is already in a
known state, so it is streamed without parsing anything unknown at all. The
generic relay path is untouched.

The decode path never copied: `wire.Reader.Bytes32` returns a slice into the
frame it was given.

A preallocation helper (`Buffer.Grow`) was also written, measured, and
removed: Go's `append` already right-sizes a single large append, so it made
no difference. Recorded because "obviously preallocate" looks like a win and
is not.

Regression tests: `internal/wire/memory_test.go` measures
`runtime.MemStats.TotalAlloc` around the framing primitives (cumulative
allocated bytes, so a copy counts even if freed immediately), and `e2e`
measures real peak RSS of both binaries. Both express limits as a fraction
of the payload, and both were mutation-verified: reintroducing a buffered
read in the daemon takes it back to 1.028× and the test fails.

## Over-limit fails two different ways, on purpose

**Slightly over** — the request still fits inside a frame the daemon is
willing to read. It is rejected by the handler, logged as
`REJECT oversized` in the audit log, and the client gets a clean
`file exceeds max_size_bytes`.

**Massively over** — the frame length itself exceeds the daemon's limit. The
daemon refuses at the header and closes the connection **without
allocating**. This is deliberate: reading a 5 GB frame in order to politely
say "too big" would let any hostile hop force a 5 GB allocation on demand.
The cost is that this path cannot carry a protocol-level error — the client
only sees its write fail — so `pedithelper` explains it:

```
send request failed after N bytes: ... broken pipe
  This usually means peditagentd rejected the size and closed the socket.
  Check max_size_bytes in its config ...
```

`pedithelper` pre-flights the file before sending anything, against the
protocol's `uint32` frame length and against the single-frame cap above.
Neither direction buffers a transfer any more, so the second is a
conservative ceiling rather than a memory requirement — but finding out
after a full upload that the round trip is refused is no use, so it is
checked up front.

It is skipped when **no reply content is expected** — `pup`, which stores
the file at home and returns only a status. The helper knows because `pup`
passes an empty output path, which also makes any content arriving on that
path an error rather than something quietly written somewhere.

### Both directions, two different sizes

`max_size_bytes` governs `pdown` as well, but it cannot be checked the same
way. A download request declares `Size = 0` — it carries no payload — so
the generic ceiling in `Prepare`, which tests the *declared* size, can
never fire for one. The served file's size is therefore checked separately,
twice: once against `Lstat` before asking for approval (so the prompt shows
a real number rather than `0 bytes`), and again against `fstat` on the
open descriptor before streaming, in case it grew in between.

(An earlier version of this document claimed the helper pre-flighted its
own buffer capacity when it only checked the protocol ceiling. The claim
was written, the streaming rewrite removed the check it described, and the
document was not updated — caught by an external review of the protocol,
not by anything here. Documentation drifts silently; the arithmetic is now
pinned by `cmd/peditagentd/limits_test.go`.)

## What the disagreement cost (why this document exists)

A 485 MB file, `max_size_bytes = 5048576000`:

1. `wire.MaxFrameLen` was hardcoded at 256 MiB and used by the daemon, so
   the frame header was refused and the socket closed while the client was
   still writing. The user saw `write: broken pipe` and nothing else. The
   configured 5 GB was never consulted.
2. Fixing that surfaced a **second** hidden ceiling: `wire.Reader.Bytes32`
   independently re-checked the content field against the same 256 MiB
   constant, so a 300 MB transfer then failed as `malformed request`. A
   field inside an already-accepted frame cannot sensibly enforce a
   different cap than the frame did.
3. `5048576000` was itself above the `uint32` frame length — unreachable no
   matter what else was fixed, and nothing said so.

Three ceilings, none of them agreeing, and the smallest one failing
silently. Hence: one knob, derived limits, and startup warnings for
settings that cannot be honoured.

## Practical guidance

- Leave `max_size_bytes` small unless you have a reason. 10 MiB covers
  editing config files, which is what pedit is for.
- If you do need large transfers, set it to something achievable —
  `2000000000` (≈1.9 GiB) is about the ceiling on a 64-bit build — and
  check the startup line reporting the effective limit.
- On a 32-bit target (`386`, `arm`), the ceiling is 512 MiB regardless.
- **For genuinely large files, prefer `scp`/`rsync` through a jump host if
  you have any path for it.** pedit exists for the case where no other
  channel is available and is not optimised for throughput. Measured
  roughly 45–65 MiB/s between LAN peers and ~5 MiB/s over a routed tailnet
  hop.

## If you need to exceed this

Buffering used to be the binding constraint; it is not any more, because
both directions stream. What remains is the protocol's `uint32` frame
length, and that one is inherited rather than chosen.

Going past it would mean chunking a file across multiple extension messages
with an application-level sequence and offset, so no single frame approaches
`uint32`. The agent-forwarding relay would not care. It would also mean
reworking the approval model, which currently approves one whole file once,
and adding resume semantics to be worth the trouble. Not attempted.

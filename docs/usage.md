# Usage

## Profiles

A profile maps a name to a command. The remote side sends only the name.

```toml
[profiles.edit]
command = "vim -u NONE --cmd 'set nomodeline' {file}"

[profiles.view]
command = "less {file}"
```

`{file}` is replaced with the path of the received temp file. Whatever the
command leaves in that file is what goes back.

`pedit -p view notes.txt` picks a profile; the default is `edit`.

## Opening instead of editing

`oneway = true` hands the file to the system's file-type handler rather than
running an editor against it:

```toml
[profiles.open]
command = "xdg-open {file}"
oneway = true
retain_seconds = 900
```

Three things differ, all forced by the fact that GUI handlers detach
immediately:

- **Nothing is written back.** The remote file is left byte-for-byte as it
  was. This needs its own status (`StatusOpened`) rather than an empty
  success, because the client writes the response over the target path — an
  empty success would truncate the file to zero bytes.
- **The daemon does not wait.** `xdg-open` returns long before the viewer
  has loaded, so there is nothing meaningful to wait for.
- **The temp copy is retained** for `retain_seconds` (default 900) instead
  of being deleted when the command exits, because a detached viewer is
  still reading it.

The temp file is written mode 0600 with **no execute bit**, which is what
stops a hostile host getting a `.desktop` file launched — desktops refuse to
launch one that is not executable. pedit does not restrict which types may
be opened. A handler that interprets what it opens (a browser running
JavaScript in an `.html`) still does so; approve accordingly.

## `pup` and `pdown`

`pedit` edits a file and hands it back. These two just move files, through
one shared directory at home:

```bash
pup notes.txt                 # -> ~/pedit-transfers/ at home
pdown                         # list what is staged there
pdown installer.sh            # fetch into ./installer.sh
pdown installer.sh -o /tmp/i  # or elsewhere
pdown installer.sh -f         # allow overwriting a local file
```

Flags work before or after the name.

### What they will not do

**`pup` never overwrites.** If the name is taken at home the transfer is
refused, and there is no force flag for it. The refusal happens during
`PREPARE`, before a byte is uploaded, so a large file fails immediately
rather than after crossing five hops.

**`pdown` never overwrites without `-f`.** Two independent guards: the
client checks before you are asked to approve anything, and the final write
uses `link(2)`, which fails rather than replacing. The second closes the gap
between the check and the write.

**Neither runs a command.** They are built into the daemon rather than being
profiles with a `command` template, so the execution path is never reached.
A `[profiles.pup]` in config is ignored with a warning rather than silently
taking over.

**Names cannot escape the directory.** Anything arriving from the remote
host is reduced to a single path element, so `../../.ssh/authorized_keys`
lands as `authorized_keys`. Symlinks inside `transfer_dir` are never
followed.

### Confirmation is per direction

`confirm_up` and `confirm_down` are separate because they are not the same
decision. An upload only ever adds a file to a directory you chose; a
download hands a file from your machine to whoever asked. The prompt says
which:

```
--- pedit DOWNLOAD request (a file leaves this host) ---
  profile: pdown
  file:    id_rsa
  from:    root@jumphost (self-reported, unverified)
  what:    the remote host is asking THIS machine for a file
  size:    2602 bytes would be sent to it
accept? [y/N]
```

Turning `confirm_up` off is reasonable if you push files constantly. Leaving
`confirm_down` on is strongly recommended — it is the direction that moves
data outward.

## Progress

Transfers draw a meter; the phases where a human is deciding or an editor is
open get an elapsed clock and a spinner instead, and deliberately show **no**
deadline, because there is none on those phases:

```
pedit: up    714.91MiB/1.37GiB  [==============>      ]  51%  965.25MiB/s ETA 0:00:01
pedit: waiting for approval at home 0:00:07 /
pedit: running at home 0:01:42 -
pedit: 1.37GiB up in 1.399s (1000.46 MiB/s) | total 1.4s
```

- Nothing is drawn unless stderr is a terminal, so scripts and logs get only
  the final line.
- Nothing is drawn for transfers under 300ms, so a small `pup` does not
  flash a bar.
- The rate is smoothed, not averaged: an average hides a stall, which is the
  main thing you watch a meter to notice.
- `PEDIT_PROGRESS=0` disables the meter; `PEDIT_STATS=0` disables the final
  line too.

The final line reports waiting separately rather than folding it into the
download rate. Dividing bytes received by time spent waiting for approval
and an editor produced a "MiB/s" that mostly measured typing speed.

## Troubleshooting

**Something hangs.** Set `debug = true` first. It logs each step, and for the
`exec` approver the askpass command's captured output plus a periodic "still
waiting" line. A hang is almost always the askpass command itself failing
silently — `notify-send` with no session bus on a headless box, for
instance — which looks identical to pedit being stuck until you can see it.

**"agent at the far end does not understand pedit@hallacy.com".** The
request reached a stock ssh-agent rather than `peditagentd`. Usually
`SSH_AUTH_SOCK` still points at the old agent in that shell, or the daemon
was started after it was repointed.

**A profile that uses `$EDITOR` fails loudly.** That is deliberate. With
`EDITOR` unset, POSIX `sh` treats the empty expansion as "no command word"
and shifts the quoted file path into the command-name position — silently
trying to *execute* the file you meant to open. `internal/profile` catches
it instead.

**Timeouts.** The client gives up after 30 minutes; `PEDIT_TIMEOUT_SECONDS`
changes it, `0` disables it. The approval timeout is separate and does not
apply once the profile command is running — editing has no deadline.

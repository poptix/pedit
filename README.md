# pedit

Move a file between an isolated host and your own machine over the ssh-agent
socket you are already forwarding. No install on the far end, no new outbound
connection, however many `ssh -A` hops deep you are.

The forwarded agent socket is often the only channel that still reaches home
from a locked-down host. pedit puts a small daemon at the far end of it and
uses a vendor-namespaced [RFC 9987](https://www.rfc-editor.org/rfc/rfc9987)
extension, which every intermediate hop relays untouched.

## Commands

Run on the remote host, after sourcing `pedit.sh`:

| Command | What it does |
|---|---|
| `pedit [-p profile] [-o out] <file>` | Send a file home, run a profile on it, write the result back |
| `pup <file>` | Copy a file into the transfer directory at home. Never overwrites |
| `pdown` | List what is staged at home |
| `pdown [-o out] [-f] <name>` | Fetch a file from home. Needs `-f` to overwrite |

Every transfer shows a `pv`-style meter and its throughput:

```
pedit: up    714.91MiB/1.37GiB  [==============>      ]  51%  965.25MiB/s ETA 0:00:01
pedit: 1.37GiB up in 1.399s (1000.46 MiB/s) | total 1.4s
```

## Quick start

At home:

```bash
go build -o peditagentd ./cmd/peditagentd     # Go, no other dependencies
go build -o peditctl ./cmd/peditctl
./build.sh                                    # builds pedithelper, regenerates pedit.sh

cp config.example.toml config.toml            # define your [profiles.*]
./peditagentd config.toml
```

Start it **before** repointing `SSH_AUTH_SOCK` anywhere: it captures the
current value to find your real agent, then binds its own socket at that same
path so nothing else needs to change. Set `backing_agent` explicitly to skip
that ordering requirement. It backgrounds itself and returns once it is
actually listening; `-foreground` for systemd or debugging.

On the remote host, either paste `pedit.sh` in, or fetch it over the same
agent socket:

```bash
peditbootstrap        # the string to paste, no arguments (add -readable to see it decoded)
```

## Configuration

| Key | Default | |
|---|---|---|
| `approver` | `"exec"` | `exec` (askpass/GUI), `socket` (peditctl in a terminal), `serial` (ESP32 button) |
| `max_size_bytes` | 10 MiB | Applies both directions |
| `transfer_dir` | `~/pedit-transfers` | Shared directory for `pup`/`pdown`; `""` disables them |
| `confirm_up` / `confirm_down` | `true` | Approval per direction |
| `bootstrap_script` | `""` (off) | Path to `pedit.sh` to serve over the agent socket |
| `audit_log` | `~/.cache/pedit/audit.log` | Every attempt, accepted or not |
| `debug` | `false` | Log each step. Start here when something hangs |

`[profiles.NAME]` takes `command` (with `{file}` substituted), `oneway`, and
`retain_seconds`. See `config.example.toml`, which is commented in full.

If your editor is a terminal program (vim, less), use `approver = "socket"`
and run `peditctl` in a real terminal — a background daemon has no TTY to
attach one to.

## Security

- **Profiles, never commands.** The remote side picks a profile *name*; only
  your local config maps it to a command. No command string crosses the wire.
- **Every request needs approval.** Anyone who can reach a forwarded agent
  socket at any hop can craft one of these requests by hand, not just you.
- **Not a new trust boundary.** Anyone who could already abuse a forwarded
  socket to get a signature out of your agent still can — that is inherent
  to `-A`. What pedit adds is additive and gated.
- **Everything is logged**, accepted or refused.

Full model, approver trade-offs and residual risks: [docs/security.md](docs/security.md).

## Documentation

- [docs/usage.md](docs/usage.md) — profiles, `pup`/`pdown`, progress, troubleshooting
- [docs/security.md](docs/security.md) — trust model, approvers, hardware gating
- [docs/protocol.md](docs/protocol.md) — wire format, the bootstrap, agent-forwarding constraints
- [docs/limits.md](docs/limits.md) — size ceilings and memory behaviour
- [firmware/pedit-approver/](firmware/pedit-approver/) — ESP32 button approver
- [firmware/pico-fido/](firmware/pico-fido/) — FIDO2 key custody

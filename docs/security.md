# Security model

## What pedit does and does not change

pedit does **not** create a new trust boundary. Anyone who can reach a
forwarded agent socket at any hop could already use it to get a signature
out of your real agent — that is inherent to `ssh -A` and out of scope
here. What pedit adds on top is additive and constrained:

- **Profiles, never commands.** A request carries a profile *name*. Only
  `peditagentd`'s local config maps that name to a command. No command
  string ever crosses the wire, so there is nothing to inject.
- **Every request requires explicit approval.** Anyone reaching the socket
  can craft a `pedit@hallacy.com` request by hand — it is not only reachable
  via the `pedit` shell function. Nothing runs without an accept, every time.
- **Approval happens before content.** The daemon asks *before* reading a
  single content byte, so declining costs nothing: no allocation, no disk
  write, no ingest.
- **Everything is logged** to `audit_log` — accepted, denied, malformed,
  unknown-profile, oversized — with a timestamp and the origin hint.

The origin hint is **self-reported and unverified**. It is a convenience for
recognising your own request, not an identity.

## Choosing an approver

| `approver` | Prompt | Runs the profile command | Use when |
|---|---|---|---|
| `exec` | askpass-style command | in the daemon | Desktop session, GUI editors |
| `socket` | `peditctl` in a terminal | in that terminal | Terminal editors (vim, less) |
| `serial` | Physical button on an ESP32 | in the daemon | You want a hardware gate |

Approval and execution are one operation because *who* runs the command
depends on how approval happened: a GUI askpass approval can run it in the
daemon, but a terminal approval must run it in the terminal that actually
has a TTY.

All three fail closed. A missing board, a wrong-firmware handshake, a
timeout, or an approver that cannot be reached all deny.

## Hardware approver

`approver = "serial"` gates approval on a physical button press on an
attached ESP32-S3 running `firmware/pedit-approver`, over USB-serial —
chosen over BLE to avoid pairing and session-lifecycle brittleness. Each
request is shown on the board's console and waits for a press.

`internal/approve/serial_test.go` exercises the whole protocol
(approve/deny/timeout/bad-handshake) against a simulated board over a PTY
pair, so `go test` needs no hardware.

Confirmed end to end on real hardware, 2026-09-02. Two things only real
hardware surfaced, both now handled: opening the port does not start the
sketch (the CH340 auto-reset circuit holds the chip in reset until something
pulses RTS the way `esptool` does), and the ROM bootloader prints a banner
before the sketch starts, which the handshake now drains. Details in
[`firmware/pedit-approver/README.md`](../firmware/pedit-approver/README.md).

This hardens *pedit's file-drop approval* against a remote attacker. It does
**not** provide key custody: a compromised host running `peditagentd` could
still forge the approved signal in software.

## Hardware key custody (FIDO2)

For key custody, move the signing key itself onto hardware. `peditagentd`
needs **zero changes** — `backing_agent` is an opaque ssh-agent socket and
every non-pedit frame is relayed byte-for-byte, so what sits behind it is
invisible to pedit.

Built and verified on real hardware, 2026-09-02, using
[pico-fido](https://github.com/polhenarejos/pico-fido) on an ESP32-S3. The
full walkthrough and every trap is in
[`firmware/pico-fido/README.md`](../firmware/pico-fido/README.md). Two
things worth knowing before you start:

- **Touch is OFF by default.** `pico-keys-sdk` auto-approves user presence
  unless an UP button has been explicitly commissioned. A freshly flashed
  device signs with no physical gate at all — verified here by enrolling a
  key in about a second with nobody touching anything. Flash-and-stop leaves
  you with something that looks like a security key and is not.
  `firmware/pico-fido/phy_config.py --set-up-btn 15` commissions it.
- **Verify by testing signing, not enrollment.** On this firmware
  enrollment does not require a touch but signing does.

Note the friction this buys against pedit's "many hops deep" premise: FIDO2
forbids caching user presence across operations, so it is a fresh touch on
*every* hop that authenticates with that identity, not once per session.

## Residual risks

- **Opening attacker-influenced content in a real parser** is not risk-free.
  Default `view` to a pager, and harden any editor profile against the file
  it is about to open (disable vim modelines and plugins).
- **No content-type gating.** The daemon sniffs the type for the *audit log
  only* — approval happens before the content exists, so the prompt cannot
  show it. The prompt answers "did I start this?", which is the question a
  human can actually judge.
- **Not end-to-end encrypted** beyond what each hop's own SSH transport
  provides — the same as agent forwarding always implies.
- **`pup` writes into your filesystem.** It is confined to `transfer_dir`
  and cannot overwrite, but an approved upload does put a file on your disk.

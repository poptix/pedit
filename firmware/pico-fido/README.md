# pico-fido as a hardware-custody backing agent

Turning a spare ESP32-S3 into a FIDO2 security key with
[pico-fido](https://github.com/polhenarejos/pico-fido), so the SSH key
behind `peditagentd`'s `backing_agent` lives in hardware and every
signature needs a physical touch.

This is a *different concern* from `../pedit-approver/` — that board gates
pedit's own file-drop approval; this one gates actual SSH signing. Use two
separate boards; a board runs one firmware at a time.

**Status: built and verified end to end on real hardware, 2026-09-02.**
Board `a0:85:e3:e3:5a:58` on `waldo`, pico-fido v8.0, ESP-IDF v5.5.4.
Confirmed: signing without a touch fails after the UP timeout; signing with
a touch succeeds. No PIN anywhere in the flow (possession-only). Running a
locally-built firmware carrying `led-idle-off.patch` (see
"Silencing the idle LED" below), not the stock release binary.

## The headline gotcha: touch is OFF by default

`pico-keys-sdk`'s `button_wait_start()` (`src/button.c`) does this:

```c
/* Disabled by default. As LED may not be properly configured,
   it will not be possible to indicate button press unless it
   is commissioned. */
uint32_t button_timeout = phy_data.up_btn_present ? phy_data.up_btn * 1000 : 0;
if (button_timeout == 0 && !force_button_wait) {
    ... queue EV_BUTTON_PRESSED; return;      // auto-approve, no press
}
```

A freshly-flashed device **signs on request with no physical gate at all.**
Verified empirically here: `ssh-keygen -t ecdsa-sk` completed in ~1s with
stdin on `/dev/null` and nobody touching anything. If you stop after
flashing, you have a device that *looks* like a security key and isn't one.

The vendor's only documented way to fix this is the **paid** PicoKey App
(EUR 29.49) — "presence button timeout" lives under its Configuration and
Commissioning features. `phy_config.py` in this directory does it for free
over the device's CCID interface instead.

## 1. Flash

Grab the ESP32-S3 asset from
[releases](https://github.com/polhenarejos/pico-fido/releases/latest)
(`pico_fido_esp32-s3_<ver>.bin`) and write it at offset `0x0`. It is a
merged image — verified by inspection: `0xE9` ESP image header at byte 0,
partition table magic `0xAA50` at `0x8000`, app image at `0x20000` (note:
*not* the ESP-IDF default `0x10000`, which is erased `0xFF`s).

```bash
esptool --chip esp32s3 --port "$DEV" erase-flash
esptool --chip esp32s3 --port "$DEV" write-flash 0x0 pico_fido_esp32-s3_8.0.bin
```

Flashing over the **CH340/uart port** works fine (that's what was used
here), despite pico-keys' own docs describing native-USB DFU mode. On
`waldo`, prefix with `PATH=/root/esp32-rid-venv/bin:$PATH` — esptool needs
pyserial, which isn't in the system python.

## 2. Booting it — `--after watchdog-reset` is mandatory

The FIDO HID interface is served by the SoC's **native** USB port (TinyUSB /
USB-OTG), not the CH340 one. Move the cable there after flashing.

But a normal reset will *not* run the app on that port: the ESP32-S3's
USB-Serial/JTAG and USB-OTG peripherals share one internal PHY, and after
an RTS-style reset the chip comes up with the PHY on the ROM's
USB-Serial/JTAG — enumerating as `303a:1001 USB JTAG/serial debug unit`
with no HID at all, or dropping into `DOWNLOAD(USB/UART0)` outright. Same
trap the `esp32-rid-test` project hit. The fix:

```bash
esptool --chip esp32s3 --port "$DEV" --after watchdog-reset flash-id
```

Then it enumerates properly:

```
$ lsusb | grep 2e8a
Bus 001 Device 011: ID 2e8a:10fe Pol Henarejos Pico Key
$ fido2-token -L
/dev/hidraw0: vendor=0x2e8a, product=0x10fe (Pol Henarejos Pico Key)
```

Also beware: a DTR+RTS-both-asserted toggle pulls GPIO0 low and forces
download mode. To reset cleanly over serial, clear DTR (GPIO0 high) and
pulse RTS alone.

## 3. Let pcscd see the CCID interface

The device exposes four USB interfaces — two HID (FIDO + keyboard), one
**Chip/SmartCard (CCID)**, one vendor-specific. CCID is enabled by default
(`PHY_USB_ITF_ALL`), and that's how `phy_config.py` reaches the rescue
applet.

pcscd whitelists CCID readers by VID/PID, so it ignores `2e8a:10fe` until
you add it to `/etc/libccid_Info.plist` — one `<string>` appended to each of
the three parallel arrays (`ifdVendorID`, `ifdProductID`,
`ifdFriendlyName`), in matching positions:

```
ifdVendorID    -> <string>0x2E8A</string>
ifdProductID   -> <string>0x10FE</string>
ifdFriendlyName-> <string>Pico Key CCID</string>
```

Back the file up first, then `systemctl restart pcscd`. Verify:

```bash
$ python3 -c "from smartcard.System import readers; print(readers())"
['Pico Key CCID (585AE3E385A00000) 00 00']
```

Needs: `apt install pcscd pcsc-tools python3-pyscard fido2-tools`
(`python3-pyscard` from apt, not pip — the pip build needs pcsclite headers).

## 4. Commission the touch requirement

```bash
python3 phy_config.py                      # read current config
python3 phy_config.py --set-up-btn 15      # enable touch, 15s timeout
```

The button fires on **release**, so tap it — don't hold it. Once UP_BTN is
set, writing config itself needs a touch, which is why the tool offers
several windows.

Sanity-check the output afterward: it warns loudly if no `UP_BTN` tag is
present. Expected good state:

```
  tag 0x00 VIDPID           = 2e8a10fe
  tag 0x04 LED_GPIO         = 30
  tag 0x06 OPTS             = 0000
  tag 0x08 UP_BTN           = 0f  <- touch timeout: 15s
  tag 0x0B ENABLED_USB_ITF  = 1f
  tag 0x0C LED_DRIVER       = 05
```

## 5. Generate the SSH key — `ecdsa-sk`, not `ed25519-sk`

This device advertises `es256, es384` and no `eddsa`, so:

```
$ ssh-keygen -t ed25519-sk ...
Key enrollment failed: requested feature not supported
```

Use `ecdsa-sk` (`sk-ecdsa-sha2-nistp256@openssh.com`):

```bash
ssh-keygen -t ecdsa-sk -f ~/.ssh/id_ecdsa_sk
```

No `-O resident` and no `-O verify-required` — the device reports
`noclientPin` and needs no PIN at all, which is the possession-only model
this was set up for. The file written to `~/.ssh/` is an encrypted key
handle, useless without the physical token.

(Ed25519 *is* enable-able: `PHY_ENABLED_CURVES` tag `0x0A` is a 4-byte
bitmask with `PHY_CURVE_ED25519 = 0x80`. Untested — and setting it means
sending the whole curve bitmask, so you'd need to enumerate every curve you
want to keep. `ecdsa-sk` works, so this wasn't pursued.)

## 5b. Silencing the idle LED (`led-idle-off.patch`)

Stock firmware blinks constantly at idle — on an always-plugged-in board
that's `MODE_SUSPENDED`, a slow blue flash (1s on / 2s off), because a USB
host suspends an idle key. Annoying on a desk.

**No config option can fix this.** Every LED mode hardcodes `MAX_BTNESS`
and `PHY_LED_BTNESS` is a single global multiplier, so config can only dim
or kill *everything* uniformly, including the touch prompt:

```c
brightness = (mode_brightness/MAX) * (phy_led_brightness/MAX) * progress;
```

(`PHY_OPT_LED_STEADY` is not the answer either — it forces `progress = 1`,
i.e. steady *on*.)

`led-idle-off.patch` sets the three "nothing is happening" modes
(`MODE_NOT_MOUNTED`, `MODE_MOUNTED`, `MODE_SUSPENDED`) to `0`, leaving
`MODE_PROCESSING` and `MODE_BUTTON` alone. Result: dark at idle, yellow
when it wants your touch. Upstream values are preserved in comments.
Explicit `led_blink_n_times()` success blinks bypass modes entirely and
still work.

Building it (done in a dev container, not on the Proxmox host — waldo only
needs `esptool`; costs ~4.5 GB of toolchain):

```bash
git clone -b v8.0 --depth 1 --recursive https://github.com/polhenarejos/pico-fido
git clone -b v5.5.4 --depth 1 --recursive https://github.com/espressif/esp-idf
./esp-idf/install.sh esp32s3          # needs cmake + ninja-build present
cd pico-fido
git -C pico-keys-sdk apply ../path/to/led-idle-off.patch
. ../esp-idf/export.sh
idf.py set-target esp32s3 && idf.py build
```

**Flash the app partition only** — do NOT `erase-flash` or write the full
merged image, or you lose the PHY config (UP_BTN commissioning lives in
`part0` at `0x200000`) and have to re-tap through commissioning:

```bash
esptool --chip esp32s3 --port "$CH340_DEV" write-flash 0x20000 build/pico_fido.bin
```

Flashing needs the **CH340** port (the running app occupies the native port
as HID+CCID, so there's no serial device there to talk to). Afterwards move
back to native and `--after watchdog-reset` as in step 2. Confirm the
config survived with `phy_config.py` — and note the absence of
`First initialization (or corrupted!)` in the boot log, which would mean
the config partition *was* wiped.

## 6. Verify the gate actually holds

Do this, not just a successful keygen — **enrollment does not require a
touch on this firmware, but signing does**, and signing is what matters:

```bash
# should FAIL after ~15s with nobody touching the board:
ssh-keygen -Y sign -f ~/.ssh/id_ecdsa_sk -n test somefile </dev/null
# -> "Confirm user presence for key ECDSA-SK ..." then fails

# should SUCCEED when you tap the button during that window:
ssh-keygen -Y sign -f ~/.ssh/id_ecdsa_sk -n test somefile
```

OpenSSH reports the declined case as `incorrect passphrase supplied to
decrypt private key`, which is misleading — it's a UP timeout, not a
passphrase problem.

## 7. Wire it into the agent on the target machine

The token must be readable by whichever machine runs the **backing
ssh-agent** — that's the machine `peditagentd` proxies to, not any remote
hop. Worked example: `peditagentd` runs as user `poptix` on `i9-desktop`,
a VM on the Proxmox host `i9`.

### 7a. Pass the USB device into the VM (Proxmox host)

```bash
lsusb | grep 2e8a          # host sees the token
lsusb -t                   # find its port path, e.g. "Bus 001 ... Port 003 -> Port 001" = 1-3.1
qm set <vmid> -usb0 host=1-3.1
```

**Prefer the port path over `host=2e8a:10fe`.** This device changes USB
identity depending on what it's doing:

| State | VID:PID |
|---|---|
| app running (what you want) | `2e8a:10fe` |
| ROM bootloader / download mode | `303a:1001` |
| CH340 side (flashing) | `1a86:55d3` |

Bind passthrough to `2e8a:10fe` and the moment the board comes up in ROM
mode the VM stops seeing it *and* can't run `esptool` to recover it,
because the recovery device is the very `303a:1001` you didn't pass
through. A port-path binding forwards whatever is on that physical port,
so the guest can fix itself. A config change here generally needs a VM
restart.

### 7b. Non-root access — usually nothing to do

**Try it first; don't pre-emptively write a udev rule.** As the agent's
user, not root:

```bash
fido2-token -L      # lists the token? then you're done, skip the rest
```

Modern systemd (v250+, e.g. 257 on Debian 13) ships
`/usr/lib/udev/rules.d/60-fido-id.rules`, which identifies FIDO tokens by
their **HID report descriptor** — generically, with no VID/PID list
involved. Verified on this device with no configuration at all:

```
$ udevadm info --query=property --name=/dev/hidraw0
ID_SECURITY_TOKEN=1
TAGS=:seat:security-device:uaccess:
```

(Note Debian's old `libu2f-udev` package is now docs-only — its VID/PID
rule list is history. Don't go looking for `70-u2f.rules`.)

The catch is `uaccess`: it grants access by **ACL to the user of an active
local seat session**. So:

- **Desktop VM with the agent's user logged in locally** → works
  automatically, nothing needed.
- **Headless box, SSH-only user, or a systemd service** → the device is
  still *tagged* `uaccess` but no ACL is granted, because there is no seat
  session. Confirmed on headless `waldo`: `getfacl /dev/hidraw0` shows no
  user entry despite the `uaccess` tag.

Only in that second case add a rule — and key it off systemd's own tag
rather than hardcoding a VID/PID, so it keeps working for any other FIDO
key you plug in later:

```
# /etc/udev/rules.d/70-fido-group.rules
SUBSYSTEM=="hidraw", TAG=="security-device", GROUP="plugdev", MODE="0660"
```

```bash
sudo udevadm control --reload-rules && sudo udevadm trigger   # then replug
```

### 7b-bis. Should you change the device's USB ID instead?

Upstream's README suggests VID/PID as the lever ("you should modify
Info.plist of CCID driver to add these VID/PID or use the PicoKey App"),
and `PHY_VIDPID` is settable at runtime — `usb.c:85` overrides the
descriptor from stored config, so `phy_config.py` could change it with no
rebuild, and there are build presets (`Yubikey5` = `1050:0407`,
`NitroFIDO2` = `20A0:42B1`, `Gnuk` = `234B:0000`, `GnuPG` = `1209:2440`).

**It does not help the SSH path.** hidraw/FIDO detection is by HID report
descriptor, not VID/PID (above), so the ID is irrelevant there.

Where it *would* help is the **CCID/pcscd** side — that genuinely is
VID/PID-whitelisted (step 3), so an ID already in `libccid_Info.plist`
would avoid editing that file on every machine. But you only need CCID to
run `phy_config.py`, not for normal signing, so it's rarely worth it. And
the ready-made presets impersonate vendors you don't own: upstream permits
this "for internal purposes" but explicitly forbids *distributing* such a
binary, and a fake Yubico ID can confuse tooling that applies
vendor-specific quirks — especially if you also own real YubiKeys.
`1209:2440` (pid.codes, a registry for open-source hardware) is the
honest choice if you do want to change it.

### 7c. Key + agent, as the agent's user

```bash
ssh -Q key | grep sk-                      # confirm this OpenSSH has FIDO2
ssh-keygen -t ecdsa-sk -f ~/.ssh/id_ecdsa_sk   # no -O resident/-O verify-required
ssh-copy-id -i ~/.ssh/id_ecdsa_sk.pub <target>  # or paste into authorized_keys
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ecdsa_sk && ssh-add -l   # should list the ECDSA-SK key
```

The key-handle file is tied to the *token*, not the host, so it can be
copied between machines — but it is useless without the token plugged in.

### 7d. Point peditagentd at that agent

Pick **one** of these; they're mutually exclusive, because setting
`backing_agent` explicitly disables the socket takeover:

**Explicit** (best for a systemd unit — no dependency on inherited env):
```toml
backing_agent = "/run/user/1000/ssh-agent.sock"   # the REAL agent, not pedit's
listen         = "~/.cache/pedit/agent.sock"
```
then `export SSH_AUTH_SOCK=~/.cache/pedit/agent.sock` wherever you `ssh -A`.

**Takeover** (simplest interactively): leave `backing_agent = ""` with
`replace_auth_sock = true`, and start `peditagentd` from a shell whose
`SSH_AUTH_SOCK` already points at the real agent. It renames that socket to
`<path>.pedit-real` and binds at the original path, so nothing else needs
to change.

### 7e. Verify the whole chain

```bash
SSH_AUTH_SOCK=~/.cache/pedit/agent.sock ssh-add -l   # SK key visible through the proxy
ssh -A <target>                                       # LED goes yellow; tap to authenticate
```
Then from a remote hop, `pedit somefile` should still gate on the *other*
approver (peditctl or the `pedit-approver` board) — two independent
physical gates for two different trust boundaries.

### Operational caveats

- **A fresh touch per hop.** FIDO2 forbids caching user-presence, so every
  hop authenticating through this identity needs another tap. That's real
  friction against pedit's "many hops deep" premise.
- **Token unplugged** → the agent refuses that identity (it doesn't hang);
  some setups need the agent restarted after a replug due to a stale
  device handle.
- **Cold-boot behaviour is unverified.** Twice here, a fresh plug into the
  native port came up as `303a:1001` (ROM) rather than running the app,
  needing `esptool --after watchdog-reset`. If that also happens on VM/host
  power-cycle, the token won't come back as a FIDO device unattended —
  test a full power-cycle before depending on this in a setup you can't
  physically reach.

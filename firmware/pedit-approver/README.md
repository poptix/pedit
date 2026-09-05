# pedit-approver firmware

The ESP32-S3 side of `peditagentd`'s `serial` approver
(`internal/approve/serial.go`): a physical button gate for file-drop
approvals, so a hostile intermediate SSH hop can't get anything to run just
by crafting a `pedit@hallacy.com` extension request — a human has to be
standing at the board and press it.

**Confirmed working end to end** (2026-09-02) on an ESP32-S3-WROOM-1-N16R8
devkit on `waldo` (MAC `a0:85:e3:e3:5a:58`, not yet in the mpls911 fleet's
udev table — see below), including a real physical BOOT-button press
approving a real `pedit` file transfer.

## Hardware assumptions

- An ESP32-S3 dev board. The mpls911 project's fleet on `waldo` (see
  `../../../mpls911/esp32-rid-test/README.md` for MACs and udev rules) works
  fine to borrow for this — that's what's been tested.
- **Use the CH340 "uart" port, not the native USB port.** These boards have
  two independent USB-C ports; only the CH340 one is wired to `Serial`
  (UART0) with the default board config used here — no `USBMode` build flag
  needed, unlike sketches that want a console on the native port instead.
  Plugging into the native port instead gives you a working flash target but
  a silent sketch with no serial communication at all.
- BOOT button (GPIO0) doubles as the approve button — standard on every
  ESP32-S3 devkit, no extra wiring.
- Onboard addressable RGB LED (Espressif ESP32-S3-DevKitC-1) for status
  color: off = idle, amber = request pending, green = approved, red =
  denied/timed out. The LED moved from GPIO48 (original board) to GPIO38
  (v1.1, after a PSRAM voltage fix) between hardware revisions -- the
  firmware drives both pins rather than guessing which revision this board
  is, so it's correct either way. Set `USE_LED 0` in the sketch to disable
  it cleanly on a board with no LED at all. The serial console output
  (`# pending: ...`, `YES`, `NO`) is the authoritative UI either way; the
  LED is a convenience on top of it, not a replacement.
- A fresh/unknown board won't have a stable `/dev/esp32/...` symlink from
  the mpls911 udev rules -- use `/dev/serial/by-id/usb-1a86_USB_Single_Serial_<CH340-serial>-if00`
  instead (always stable, present the moment the board's CH340 port
  enumerates), or add an entry to `99-esp32-rid-test.rules` for permanence.

## The reset circuit is not optional to understand

**Opening the port alone does not run the sketch.** These boards' CH340
auto-reset circuit holds the ESP32 in reset for as long as RTS stays
asserted — and RTS reads back `True` immediately after a plain open (via
`pyserial`, or a bare `syscall.Open`/`stty`+`exec`), so a naive
open-then-read sits in total, indefinite silence. `esptool`'s "hard reset"
and `serial.go`'s `pulseReset` both explicitly clear DTR and pulse RTS
high-then-low to actually release the chip into normal boot. This cost real
debugging time the first time this firmware was brought up on real
hardware — total silence looked exactly like a dead board or bad firmware,
when the fix was one RTS pulse.

**The ROM bootloader also prints its own banner** at the same baud rate
before the sketch's `setup()` ever runs — a client that reads exactly one
line right after reset will get `ESP-ROM:esp32s3-20210327...`, not the
firmware's handshake response, unless it drains that banner first.
`serial.go`'s `connect()` sleeps past it, then does a deadline-bounded
drain read before sending `HELLO`.

## Flashing

```
arduino-cli compile --fqbn esp32:esp32:esp32s3 pedit-approver
arduino-cli upload  --fqbn esp32:esp32:esp32s3 -p <ch340-uart-device> pedit-approver
```

On `waldo`, `esptool`/`mpremote` need pyserial, which isn't in the system
Python -- prefix with `PATH=/root/esp32-rid-venv/bin:$PATH` (that venv
already has it, set up for the mpls911 project).

## Verifying it by hand before wiring up peditagentd

Plain `stty` + `exec 3<>` is not enough here — it won't pulse RTS, so the
chip just sits in reset and every read blocks forever. Use `pyserial`
directly to replicate the real reset sequence:

```python
python3 - <<'PY'
import serial, time
s = serial.Serial('/dev/serial/by-id/usb-1a86_USB_Single_Serial_<serial>-if00', 115200, timeout=2)
s.dtr = False
s.rts = True; time.sleep(0.1); s.rts = False   # esptool-style hard reset: release EN
time.sleep(0.6)
s.read(4096)                                    # drain the ROM boot banner
s.write(b'HELLO\n')
print(s.readline())                             # expect: PEDIT-APPROVER v1
s.write(b'REQ profile=view file=test.txt origin=me size=42\n')
print(s.readline())                             # "# pending: ..." echo -- not the answer
print(s.readline())                             # press BOOT now -- expect: YES (or NO on timeout)
PY
```

## Config on the peditagentd side

```toml
approver = "serial"

[serial]
device = "/dev/serial/by-id/usb-1a86_USB_Single_Serial_<serial>-if00"
baud = 115200
timeout_seconds = 120
```

#!/usr/bin/env python3
"""Read/write a pico-fido device's PHY configuration over its CCID interface.

This is the free alternative to the vendor's paid PicoKey App (EUR 29.49),
which is otherwise the only documented way to set the "presence button
timeout" -- i.e. to enable the physical touch requirement at all. That
matters a lot more than it sounds: pico-keys-sdk's button_wait_start()
AUTO-APPROVES user presence when no UP button is commissioned, so a
freshly-flashed device signs on request with no physical gate whatsoever.

Everything here was derived from pico-keys-sdk source (src/rescue.c,
src/fs/phy.c, src/button.c) and verified against real hardware; none of it
is documented by the vendor.

  rescue applet AID : A0 58 3F C1 9B 7E 4F 21
  CLA               : 0x80  (NOT 0x00 -- 0x00 reaches the U2F applet instead
                      and answers 6D00/6E00, which is a confusing dead end)
  INS_WRITE / P1=1  : 0x1C, write PHY config (TLV payload)
  INS_READ  / P1=1  : 0x1E, read PHY config
  PHY_UP_BTN tag    : 0x08, len 1, value = touch timeout in SECONDS

Two traps worth knowing:

1. A write REPLACES the entire config. phy_unserialize_data() memsets the
   struct before parsing, so any TLV you omit is silently cleared -- it is
   NOT a merge. `--set-up-btn` therefore reads current config first and
   re-sends everything. Getting this wrong wipes VIDPID/LED_GPIO/LED_DRIVER.
2. Once UP_BTN is set, writing config itself requires a physical touch
   (rescue_require_user_presence). The button fires on RELEASE, so tap it,
   don't hold it. Hence --attempts.

Requires: pcscd running, python3-pyscard, and the device's VID:PID added to
/etc/libccid_Info.plist (pcscd whitelists CCID readers by VID/PID and will
not see 2e8a:10fe otherwise). See README.md in this directory.
"""

import argparse
import sys

try:
    from smartcard.System import readers
except ImportError:
    sys.exit("need pyscard: apt install python3-pyscard")

RESCUE_AID = [0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21]
CLA = 0x80
INS_WRITE = 0x1C
INS_READ = 0x1E
P1_PHY = 0x01

TAGS = {
    0x00: "VIDPID",
    0x04: "LED_GPIO",
    0x05: "LED_BTNESS",
    0x06: "OPTS",
    0x08: "UP_BTN",
    0x09: "USB_PRODUCT",
    0x0A: "ENABLED_CURVES",
    0x0B: "ENABLED_USB_ITF",
    0x0C: "LED_DRIVER",
}
TAG_UP_BTN = 0x08


def connect():
    rs = readers()
    if not rs:
        sys.exit("no CCID reader found -- is pcscd running, and is the "
                 "device's VID:PID in /etc/libccid_Info.plist? (see README)")
    conn = rs[0].createConnection()
    conn.connect()
    data, sw1, sw2 = conn.transmit(
        [0x00, 0xA4, 0x04, 0x00, len(RESCUE_AID)] + RESCUE_AID)
    if (sw1 << 8 | sw2) != 0x9000:
        sys.exit("SELECT rescue applet failed: SW=%02X%02X" % (sw1, sw2))
    return conn, rs[0], bytes(data)


def read_tlv(conn):
    data, sw1, sw2 = conn.transmit([CLA, INS_READ, P1_PHY, 0x00, 0x00])
    sw = sw1 << 8 | sw2
    if sw != 0x9000:
        sys.exit("READ PHY failed: SW=%04X" % sw)
    return list(data)


def parse_tlv(body):
    """-> list of (tag, value_bytes), preserving order."""
    out, i = [], 0
    while i + 2 <= len(body):
        tag, ln = body[i], body[i + 1]
        out.append((tag, bytes(body[i + 2:i + 2 + ln])))
        i += 2 + ln
    return out


def build_tlv(entries):
    buf = []
    for tag, val in entries:
        buf += [tag, len(val)] + list(val)
    return buf


def show(entries):
    for tag, val in entries:
        name = TAGS.get(tag, "?")
        extra = ""
        if tag == TAG_UP_BTN:
            extra = "  <- touch timeout: %ds" % val[0]
        print("  tag 0x%02X %-16s = %s%s" % (tag, name, val.hex(), extra))
    if not any(t == TAG_UP_BTN for t, _ in entries):
        print("\n  *** NO UP_BTN SET: user presence is AUTO-APPROVED. ***")
        print("  *** This device will sign with no physical touch.     ***")


def write_tlv(conn, entries, attempts):
    """Write config, retrying so a human has several windows to tap the button."""
    payload = build_tlv(entries)
    for n in range(1, attempts + 1):
        if attempts > 1:
            print("attempt %d/%d: tap+release the button now..." % (n, attempts),
                  flush=True)
        _, sw1, sw2 = conn.transmit(
            [CLA, INS_WRITE, P1_PHY, 0x00, len(payload)] + payload)
        sw = sw1 << 8 | sw2
        if sw == 0x9000:
            print("write OK")
            return True
        if sw == 0x6985:
            print("  -> SW=6985 (no touch registered)", flush=True)
            continue
        sys.exit("write failed: SW=%04X" % sw)
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--set-up-btn", type=int, metavar="SECS",
                    help="enable the physical touch requirement with this "
                         "timeout in seconds (e.g. 15). Preserves all other "
                         "config values.")
    ap.add_argument("--attempts", type=int, default=6,
                    help="how many touch windows to offer when writing "
                         "(default 6; each is one UP timeout long)")
    args = ap.parse_args()

    conn, reader, sel = connect()
    print("reader: %s" % reader)
    # SELECT response: [mcu, proto, major, minor, <serial...>]; mcu 2 = ESP32-S3
    print("device: mcu=%d fw=%d.%d serial=%s"
          % (sel[0], sel[2], sel[3], sel[4:10].hex()))

    entries = parse_tlv(read_tlv(conn))
    print("\ncurrent PHY config:")
    show(entries)

    if args.set_up_btn is None:
        return

    if not 1 <= args.set_up_btn <= 255:
        sys.exit("--set-up-btn must be 1..255 seconds")

    # Rebuild the FULL config with UP_BTN replaced/added -- a write is a
    # replace, not a merge (see module docstring).
    kept = [(t, v) for t, v in entries if t != TAG_UP_BTN]
    kept.append((TAG_UP_BTN, bytes([args.set_up_btn])))
    print("\nwriting UP_BTN=%ds (plus %d preserved tag(s))..."
          % (args.set_up_btn, len(kept) - 1))
    if not write_tlv(conn, kept, args.attempts):
        sys.exit("gave up -- no touch registered")

    print("\nresulting PHY config:")
    show(parse_tlv(read_tlv(conn)))


if __name__ == "__main__":
    main()

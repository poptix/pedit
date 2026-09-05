#!/bin/sh
# Default "exec" approver command: a graphical yes/no prompt via notify-send
# --wait -A (libnotify >= 0.7.7 / most modern notification daemons). Exit 0
# means approved. peditagentd sets PEDIT_PROFILE / PEDIT_FILENAME /
# PEDIT_ORIGIN / PEDIT_SIZE in the environment for this command; see
# config.example.toml for how it's wired in.
#
# Needs a desktop session (DISPLAY/WAYLAND_DISPLAY + a notification daemon
# that supports actions). If peditagentd runs headless, use the "socket"
# approver + peditctl instead -- see README.md.

set -eu

action=$(notify-send \
  --app-name=pedit \
  --urgency=critical \
  --wait \
  -A "yes=Approve" -A "no=Deny" \
  "pedit: ${PEDIT_PROFILE:-?} request from ${PEDIT_ORIGIN:-unknown}" \
  "file: ${PEDIT_FILENAME:-?}  (${PEDIT_SIZE:-?} bytes, self-reported origin, unverified)")

[ "$action" = "yes" ]

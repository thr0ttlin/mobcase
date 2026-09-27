#!/usr/bin/env bash
#
# iOS needs the usbmuxd daemon. Pick ONE of two modes:
#
#   A) bridge the host daemon (recommended: reuses the working host usbmuxd,
#      no --privileged, no conflict):
#        -v /var/run/usbmuxd:/var/run/usbmuxd \
#        -v /var/lib/lockdown:/var/lib/lockdown:ro       # pairing records
#      This script then leaves usbmuxd alone.
#
#   B) pass the USB bus through and run usbmuxd IN the container:
#        --privileged -v /dev/bus/usb:/dev/bus/usb
#      First stop the host daemon (sudo systemctl stop usbmuxd) or the two
#      instances fight over the device (hangs / no devices).
#
# adb: starts its own server on first use (needs USB passthrough, or reach the
# host server with --network host / ADB_SERVER_SOCKET=tcp:host:5037).
#
set -e

SOCK="${USBMUXD_SOCKET_ADDRESS:-/var/run/usbmuxd}"

# Start usbmuxd only when NO socket is bridged in AND we actually have USB access.
if [ ! -S "$SOCK" ] && [ -d /dev/bus/usb ]; then
    usbmuxd 2>/dev/null || true
fi

exec "$@"
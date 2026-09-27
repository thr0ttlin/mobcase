#!/usr/bin/env bash
#
# Install mobcase's external tools on Debian/Ubuntu.
# Python deps come from pyproject.toml (pip install .); this covers the binaries
# the toolkit orchestrates.
#
#   Android : adb, apktool (wrapper + latest jar), apksigner, zipalign, aapt (need a JRE)
#   iOS     : libimobiledevice-utils, ideviceinstaller, usbmuxd, ldid
#   packing : zip, unzip
#
set -euo pipefail

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

echo "==> apt packages (installing only what's missing from PATH)"
pkgs=()
_need() { command -v "$1" >/dev/null 2>&1 || pkgs+=("$2"); }
_need adb adb
_need apksigner apksigner
_need zipalign zipalign
_need aapt aapt
_need ideviceinstaller ideviceinstaller
_need idevice_id libimobiledevice-utils
_need usbmuxd usbmuxd
_need zip zip
_need unzip unzip
_need curl curl

if [ "${#pkgs[@]}" -gt 0 ]; then
    if printf '%s\n' "${pkgs[@]}" | grep -qx apksigner && ! command -v java >/dev/null 2>&1; then
        pkgs+=(default-jre-headless)
    fi
    pkgs+=(ca-certificates)
    echo "    installing: ${pkgs[*]}"
    $SUDO apt-get update
    $SUDO apt-get install -y --no-install-recommends "${pkgs[@]}"
else
    echo "    all apt tools already present: skipping"
fi

# apktool: the apt package lags badly and fails to rebuild apps targeting recent
# SDKs. Install it the official way instead: the wrapper script + the latest
# apktool jar (https://apktool.org/docs/install).
if command -v apktool >/dev/null 2>&1 && apktool --version >/dev/null 2>&1; then
    echo "==> apktool already present ($(apktool --version 2>/dev/null | head -n1)): skipping"
else
    echo "==> apktool (official wrapper + latest jar)"

CURL_DL="curl -fsSL --retry 5 --retry-delay 2 --connect-timeout 15 --max-time 180"

_apktool_ok=1
_wrapper_url="${APKTOOL_WRAPPER_URL:-https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool}"
if $SUDO $CURL_DL -o /usr/local/bin/apktool "$_wrapper_url"; then
    $SUDO chmod +x /usr/local/bin/apktool
else
    _apktool_ok=0
fi

if [ "$_apktool_ok" = "1" ]; then
    if [ -n "${APKTOOL_JAR_URL:-}" ]; then
        _jar_url="$APKTOOL_JAR_URL"
    else
        # the old bitbucket downloads page now redirects to GitHub Releases
        _jar_url="$($CURL_DL https://api.github.com/repos/iBotPeaches/Apktool/releases/latest 2>/dev/null \
            | grep -oE '"browser_download_url": *"[^"]*apktool_[0-9.]+\.jar"' \
            | head -n1 | cut -d'"' -f4 || true)"
    fi
    if [ -n "${_jar_url:-}" ] && $SUDO $CURL_DL -o /usr/local/bin/apktool.jar "$_jar_url"; then
        echo "    $_jar_url"
        $SUDO chmod +r /usr/local/bin/apktool.jar
    else
        _apktool_ok=0
    fi
fi

if [ "$_apktool_ok" != "1" ]; then
    echo "!! WARNING: could not install apktool (network to GitHub?)" >&2
    echo "   'mbcpack build/extract' will be unavailable until it's installed." >&2
    echo "   Fix: re-run with network, or set a mirror:" >&2
    echo "     APKTOOL_WRAPPER_URL=<url> APKTOOL_JAR_URL=<url> $0" >&2
    echo "   or drop the jar manually at /usr/local/bin/apktool.jar + wrapper at /usr/local/bin/apktool" >&2
fi
fi

echo "==> ldid (not in apt: prebuilt static binary from ProcursusTeam)"
if command -v ldid >/dev/null 2>&1; then
    echo "    ldid already present ($(command -v ldid)): skipping"
else
if [ -n "${LDID_URL:-}" ]; then
    _ldid_url="$LDID_URL"
else
    case "$(uname -m)" in
        aarch64|arm64) _ldid_arch=aarch64 ;;
        *)             _ldid_arch=x86_64 ;;
    esac
    _ldid_url="https://github.com/ProcursusTeam/ldid/releases/latest/download/ldid_linux_${_ldid_arch}"
fi
if $SUDO curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 120 \
        -o /usr/local/bin/ldid "$_ldid_url"; then
    $SUDO chmod +x /usr/local/bin/ldid
else
    echo "!! could not fetch ldid from $_ldid_url: iOS repack/sign will be unavailable" >&2
    echo "   install it later into /usr/local/bin/ldid (or set LDID_URL to a mirror)" >&2
fi
fi

echo "==> versions"
apktool --version 2>/dev/null | sed 's/^/    apktool /' || true

cat <<'EOF2'

==> external tools installed.

Next:
  pipx install -e .            # mobcase + Python deps (androguard, pymobiledevice3, ...)

Optional (iOS app launch / instrumentation): pin to your device's frida-server
MAJOR version, they must match:
  pip install 'frida==17.x'
EOF2
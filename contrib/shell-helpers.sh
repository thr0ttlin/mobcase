#!/usr/bin/env bash
# mobcase: shell helpers (contrib)
#
# Source this from your ~/.bashrc / ~/.zshrc and adapt to your setup:
#
#   source /path/to/mobcase/contrib/shell-helpers.sh
#
# Assumptions:
#   - Wi-Fi / network SSH: an `iphone` Host entry in ~/.ssh/config pointing at
#     the device (HostName + User mobile), so `ssh mobile@iphone` just works.
#     Rename `iphone` throughout to your own host alias.
#   - USB SSH: libimobiledevice's `iproxy`, forwarding localhost:2222 -> device:22.
#   - `scp -O` uses the legacy SCP protocol (needed by many on-device SSH daemons).

# --- Wi-Fi / network SSH -----------------------------------------------------
alias issh="ssh mobile@iphone"

# iscp <files...> [iphone_folder]  : copy files ONTO the device (default: ~/)
iscp() {
  if [ $# -lt 1 ]; then
    echo "usage: iscp <files...> [iphone_folder]"
    return 1
  fi
  local dest="~/"
  if [ $# -gt 1 ] && [ ! -e "${!#}" ]; then
    dest="${!#}"
    set -- "${@:1:$#-1}"
  fi
  scp -O -r "$@" "mobile@iphone:$dest"
}

# iget <remote> [local]  : copy a file/dir OFF the device
iget() {
  scp -O -r "mobile@iphone:$1" "${2:-.}"
}

# --- USB SSH (over usbmux via iproxy) ----------------------------------------
alias isshlocal="ssh -p 2222 mobile@localhost"

# isshusb  : bring up `iproxy 2222 22`, open an SSH shell, tear iproxy down on exit
isshusb() (
    local iproxy_pid=""
    local rc
    echo "spawn iproxy 2222 22"
    unload_iproxy() {
        kill "$iproxy_pid" 2>/dev/null
        wait "$iproxy_pid" 2>/dev/null
        echo "iproxy uloaded"
    }
    cleanup() {
        trap - INT TERM EXIT
        if [[ -n "$iproxy_pid" ]] &&
           kill -0 "$iproxy_pid" 2>/dev/null; then
            unload_iproxy
        fi
    }
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap cleanup EXIT
    command iproxy 2222 22 >/tmp/iproxy-2222.log 2>&1 &
    iproxy_pid=$!
    #sleep 0.5
    if ! kill -0 "$iproxy_pid" 2>/dev/null; then
        echo "iproxy is not running:"
        cat /tmp/iproxy-2222.log
        exit 1
    fi
    ssh -p 2222 mobile@localhost
    rc=$?
    #unload_iproxy
    exit "$rc"
)
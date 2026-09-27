#!/usr/bin/env bash
#
# mobcase one-shot installer.
#
#   curl -fsSL https://raw.githubusercontent.com/thr0ttlin/mobcase/main/scripts/bootstrap.sh | bash
#
# Or, safer (read it first, then run):
#   curl -fsSLO https://raw.githubusercontent.com/thr0ttlin/mobcase/main/scripts/bootstrap.sh
#   less bootstrap.sh && bash bootstrap.sh
#
# What it does:
#   1. installs the external tools mobcase orchestrates (apt + apktool + ldid),
#   2. ensures pipx,
#   3. clones/updates the repo into ~/.mobcase-src,
#   4. installs mobcase with pipx so the mbc* commands land on your PATH,
#   5. installs frida into the venv (latest by default; pin with FRIDA_VERSION).
#
# Env knobs:
#   MOBCASE_REPO   git URL           (default: https://github.com/thr0ttlin/mobcase.git)
#   MOBCASE_REF    branch/tag        (default: main)
#   MOBCASE_SRC    checkout dir      (default: ~/.mobcase-src)
#   FRIDA_VERSION  e.g. 17.19.0      (pin frida; default installs the latest)
#   SKIP_FRIDA=1   don't install frida at all
#   SKIP_DEPS=1    skip external-tool install (pipx-only)
#
set -euo pipefail

MOBCASE_REPO="${MOBCASE_REPO:-https://github.com/thr0ttlin/mobcase.git}"
MOBCASE_REF="${MOBCASE_REF:-main}"
MOBCASE_SRC="${MOBCASE_SRC:-$HOME/.mobcase-src}"

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

command -v git >/dev/null 2>&1 || die "git is required (install git and re-run)"
command -v python3 >/dev/null 2>&1 || die "python3 is required"

# 1. clone or update the repo -------------------------------------------------
if [ -d "$MOBCASE_SRC/.git" ]; then
    log "updating $MOBCASE_SRC ($MOBCASE_REF)"
    git -C "$MOBCASE_SRC" fetch --depth 1 origin "$MOBCASE_REF"
    git -C "$MOBCASE_SRC" checkout -q "$MOBCASE_REF"
    git -C "$MOBCASE_SRC" reset --hard -q "origin/$MOBCASE_REF" || git -C "$MOBCASE_SRC" reset --hard -q "$MOBCASE_REF"
else
    log "cloning $MOBCASE_REPO -> $MOBCASE_SRC"
    git clone --depth 1 --branch "$MOBCASE_REF" "$MOBCASE_REPO" "$MOBCASE_SRC"
fi

# 2. external tools (apt + apktool + ldid) ------------------------------------
if [ "${SKIP_DEPS:-0}" = "1" ]; then
    log "use SKIP_DEPS=1: skipping external tools"
else
    log "installing external tools (scripts/install-deps.sh)"
    bash "$MOBCASE_SRC/scripts/install-deps.sh"
fi

# 3. ensure pipx --------------------------------------------------------------
if ! command -v pipx >/dev/null 2>&1; then
    log "installing pipx"
    if command -v apt-get >/dev/null 2>&1 && [ "${SKIP_DEPS:-0}" != "1" ]; then
        $SUDO apt-get install -y --no-install-recommends pipx || python3 -m pip install --user pipx
    else
        python3 -m pip install --user pipx
    fi
    python3 -m pipx ensurepath >/dev/null 2>&1 || true
    export PATH="$HOME/.local/bin:$PATH"
fi
command -v pipx >/dev/null 2>&1 || die "pipx not on PATH: open a new shell (pipx ensurepath) and re-run"

# 4. install (or reinstall) mobcase with pipx --------------------------------
# Re-running should update to the freshly cloned code. pipx won't recreate an
# existing venv (and the uv backend errors "venv already exists" even on
# --force), so remove it first, then install clean. We also force-delete the
# venv dir in case a wedged/orphaned one is left that pipx won't touch
# ("not created in this session").
log "installing mobcase (pipx)"
pipx uninstall mobcase >/dev/null 2>&1 || true
_venvs="$(pipx environment --value PIPX_LOCAL_VENVS 2>/dev/null || true)"
[ -z "$_venvs" ] && _venvs="${PIPX_HOME:-$HOME/.local/share/pipx}/venvs"
if [ -d "$_venvs/mobcase" ]; then
    log "removing stale venv $_venvs/mobcase"
    rm -rf "$_venvs/mobcase"
fi
pipx install "$MOBCASE_SRC"

# 5. frida into the mobcase venv (default: latest; pin with FRIDA_VERSION) ----
# frida powers iOS start/stop. Its wheel is Python- and platform-specific, so on
# a very new Python it may have no prebuilt wheel yet: the inject is best-effort
# and won't fail the install. Pin to your device's frida-server MAJOR with
# FRIDA_VERSION; skip entirely with SKIP_FRIDA=1.
if [ "${SKIP_FRIDA:-0}" = "1" ]; then
    log "use SKIP_FRIDA=1: not installing frida"
elif [ -n "${FRIDA_VERSION:-}" ]; then
    log "injecting frida==$FRIDA_VERSION into the mobcase venv"
    pipx inject mobcase "frida==${FRIDA_VERSION}" \
        || log "frida inject failed (optional) - use: pipx inject mobcase 'frida==${FRIDA_VERSION}'"
else
    log "injecting latest frida into the mobcase venv"
    pipx inject mobcase frida \
        || log "frida inject failed (optional; no wheel for this Python?) — add later: pipx inject mobcase 'frida==<device-major>.x'"
fi

log "done. Open a new shell (or run: source ~/.bashrc) so the mbc* commands are on PATH."
echo "    try:  mbcinfo --help   |   mbcdev list"
echo "    frida is installed by default; match your device's frida-server major with"
echo "    FRIDA_VERSION=<ver>, or re-pin later: pipx inject --force mobcase 'frida==<ver>'"
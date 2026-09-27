<h1 align="center"> mobcase </h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/platform-Android%20%7C%20iOS-lightyellow.svg" alt="Platforms">
  <img src="https://img.shields.io/badge/status-alpha-orange.svg" alt="Status: alpha">
</p>

Cross-platform (Android + iOS) mobile app testing toolkit: a set of small,
fast console utilities under a common `mbc` prefix, built on a shared core.

## Commands

| Command    | Purpose                                                                                          |
| ---------- | ------------------------------------------------------------------------------------------------ |
| `mbcinfo`  | Static analysis of an artifact (APK / split bundle / IPA / directory)                            |
| `mbcdev`   | Everything device-side: list, installed-app info, pull, install, start, stop, remove, log, proxy |
| `mbcstore` | Store recon by package / bundle id or name (Play, App Store)                                     |
| `mbcpack`  | `extract` / `build` / `sign` a package (build + sign in one step)                                |

**Output contract** Every command supports `--json` (clean machine output on
stdout: feedback/spinners go to stderr, so e.g. `| jq` always sees pure payload), `-v` / `-q` (verbosity), and `--no-color`.

**Passwordless by default (iOS)** Where a device operation can avoid the SSH
password prompt, it does: and only falls back to SSH when needed (to force SSH, use `--via ssh`):

| Operation           | Default channel           |
| ------------------- | ------------------------- |
| `info` (containers) | afc2 (usbmux)             |
| `start`             | frida                     |
| `stop`              | frida                     |
| `install`           | usbmux (ideviceinstaller) |
| `pull`, `log`       | SSH / usbmux              |

## Install

### One command (recommended)

```sh
curl -fsSL https://raw.githubusercontent.com/thr0ttlin/mobcase/main/scripts/bootstrap.sh | bash
```

This installs the external tools, ensures **pipx**, clones the repo into `~/.mobcase-src`, and installs mobcase with pipx so the `mbc*` commands land on
your PATH.

Prefer to read before running (it's a security toolkit, after all):

```sh
curl -fsSLO https://raw.githubusercontent.com/thr0ttlin/mobcase/main/scripts/bootstrap.sh
less bootstrap.sh && bash bootstrap.sh
```

Knobs: frida is installed by default (latest); `FRIDA_VERSION=17.19.0` pins it to
your device's frida-server major, `SKIP_FRIDA=1` skips it. `SKIP_DEPS=1`
(pipx-only, tools already present), `MOBCASE_REF=<branch/tag>`. Update later by
re-running the same command; uninstall with `pipx uninstall mobcase`.

### Manual install

#### 1. Get the code

```sh
git clone https://github.com/thr0ttlin/mobcase.git
cd mobcase
```

#### 2. External tools

mobcase orchestrates the platform toolchains. On Debian/Ubuntu:

```sh
./scripts/install-deps.sh
```

This apt-installs (only what's missing) the Android CLI tools (`adb`, `apksigner`, `zipalign`, `aapt` + a JRE), the iOS stack (`libimobiledevice-utils`, `ideviceinstaller`, `usbmuxd`) and `zip`/`unzip`, installs `apktool` the official way (wrapper script + latest jar), and fetches `ldid` (not in apt) as a prebuilt binary. Tools already on your PATH (e.g. an Android SDK) are left alone.

#### 3. The package (Python)

```sh
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

or:

```sh
pipx install .
```

This pulls the Python deps (androguard, asn1crypto, pymobiledevice3, paramiko,
google-play-scraper) and creates the `mbc*` commands on your PATH. Type `mbc` then <Tab> to see them all.

#### 4. frida (iOS `start` / `stop` / instrumentation)

The one-command installer adds frida automatically (latest, or the
`FRIDA_VERSION` you pass; `SKIP_FRIDA=1` to skip). Its version should match the
**frida-server** on your device (major versions must match). For a manual venv
install, add it yourself:

```sh
pip install 'frida==17.x'      # or, with pipx:  pipx inject mobcase 'frida==17.x'
```

`start`/`stop` also work through the `frida` **CLI** (frida-tools) if the Python
module isn't in the venv: whichever is present is used.

#### 5. iOS device setup (jailbroken)

- **usbmux tunnel** for the SSH channel (`pull`, and any `--via ssh`):
`iproxy 2222 22` forwards `localhost:2222` → device `:22`. Defaults assume
`mobile@localhost:2222` (a palera1n + iproxy setup); override with
`--ssh-host/--ssh-port/--ssh-user` and `--password` (omit `--password` to be
prompted only if/when SSH is actually used).
- **afc2** (`com.apple.afc2`, an unsandboxed-AFC jailbreak tweak) enables the
passwordless `info --via afc2` container enumeration over usbmux. Without it,
`info` falls back to SSH automatically.
- **frida-server** on the device enables `start`/`stop` without a password.

## Docker

It works, but it's a bit of a kludge: use it only if you're certain that Docker is absolutely necessary for your use case.

```sh
docker build -t mobcase .
docker build --build-arg FRIDA_VERSION=17.19.0 -t mobcase .   # pin frida (default: latest)
```

The build fetches apktool and `ldid` from GitHub as best-effort with bounded
timeouts - a slow or blocked GitHub won't hang or fail the build. If your build
network can't reach GitHub, build with host networking or point at mirrors:

```sh
docker build --network=host -t mobcase .
docker build --build-arg APKTOOL_JAR_URL=<url> --build-arg LDID_URL=<url> -t mobcase .
```

### Running with devices

USB access from a container is fiddly. **Before mounting the usbmuxd socket,
find its real path and confirm it is a socket**: mounting a path that doesn't
exist makes Docker silently create a *directory* there, which breaks usbmuxd on
the host (`unlink(...) failed: Is a directory`).

```sh
ss -xlp | grep -i usbmux      # real socket path: usually /run/usbmuxd
ls -la /run/usbmuxd           # must start with 's' (srwx...), a socket
```

**Recommended: reuse the host usbmuxd + adb (no --privileged):**

```sh
docker run --rm -it --network host \
  -v /run/usbmuxd:/run/usbmuxd \
  -v /var/lib/lockdown:/var/lib/lockdown:ro \
  mobcase mbcdev list
```

- `/run/usbmuxd`: the host's usbmux socket (iOS). Mount the exact path from `ss`.
- `/var/lib/lockdown`: iOS pairing records, so lockdown works without re-pairing.
- `--network host`: lets the container reach the host's adb server (Android).

File-only commands (`mbcinfo`, `mbcstore`, `mbcpack`) need no device: just
mount your working directory:

```sh
docker run --rm -it -v "$PWD":/work -w /work mobcase mbcinfo app.apk
```

## Usage

### mbcinfo: static analysis (files only)

```sh
mbcinfo app.apk                  # components, perms, signing, NSC, deep links, misconfig
mbcinfo app.ipa                  # iOS: entitlements, signing, ATS
mbcinfo app.apk -e               # include non-exported components
mbcinfo ./split-dir/             # split bundle / apk dir (manifests merged across splits)
mbcinfo app.apk --json | jq      # machine-readable
```

Handles single APKs, split bundles (`.xapk`/`.apkm`/`.apks` and pulled split
dirs: component manifests are merged across `base` + splits), apktool-decoded
directories, IPAs, and `.app` bundles.

### mbcdev: devices & actions

```sh
mbcdev list                              # connected devices (both platforms)
mbcdev info  com.example                 # installed-app info + paths/containers
mbcdev info  com.example.ios --via ssh   # iOS: force SSH for container enumeration
mbcdev pull  com.example -o ./out        # fetch the package -> feed to mbcinfo
mbcdev install app.apk                    # apk / split bundle / ipa
mbcdev install app.ipa --via ssh          # iOS: upload + on-device installer (appinst/installipa)
mbcdev install app.ipa --via ssh --installer 'appinst {ipa}'
mbcdev start com.example                   # launch (iOS: frida by default)
mbcdev start com.example --via ssh         # iOS: uiopen/open on device
mbcdev stop  com.example                   # kill (iOS: frida by default)
mbcdev remove com.example                  # uninstall
mbcdev log   com.example                   # stream logs (Android logcat / iOS syslog)
mbcdev setproxy 10.0.0.5:8080              # Android HTTP proxy (':0' clears; iOS unsupported)
```

Device selection: `-s/--serial` (adb serial / iOS UDID), `--platform`. iOS SSH
options (`--ssh-host/--ssh-port/--ssh-user/--password`) apply to SSH-channel
operations; the password prompt appears only if an SSH connection is actually
opened.

### mbcstore: store recon

```sh
mbcstore com.example                 # lookup by id (Play / App Store auto-detected)
mbcstore "Example App" --search      # search by name
mbcstore com.example -l fr -c fr     # language / storefront country
mbcstore com.example -n 10           # limit results
```

### mbcpack: extract / build / sign (offline)

```sh
mbcpack extract app.apk              # apktool decode (Android) / unzip (iOS)  [alias: x]
mbcpack build   app.src              # rebuild (+ sign by default)             [alias: b]
mbcpack build   app.src --nosign     # rebuild only
mbcpack sign    app.apk              # sign an existing apk / ipa / .app
```

- Android `build` auto-relaxes private framework resource references
(`@android:` ~ `@*android:`) that aapt2 would otherwise reject, then rebuilds.
- iOS `build` accepts a bare `.app` (as from `mbcdev pull`) or a `Payload/` tree, and names the `.ipa` after the app.

## Shell helpers (contrib)

`contrib/shell-helpers.sh` bundles small conveniences for the *manual* side of
iOS work over SSH. They're optional and not part of the toolkit; source it and
adapt the `iphone` host alias / paths to your setup:

```sh
source contrib/shell-helpers.sh
issh                          # ssh mobile@iphone (Wi-Fi, via ~/.ssh/config or /etc/hosts)
isshusb                       # bring up iproxy 2222->22, ssh over USB, tear down on exit
iscp file ...  [dest]         # copy files onto the device (scp -O)
iget /remote/path [local]     # copy off the device
```

## Limitations & notes

- **App Store IPAs are FairPlay-encrypted.** `pull` fetches the bundle and
`mbcinfo` reads everything outside the encrypted region (Info.plist, embedded
plists, entitlements, signing); on-device decryption is out of scope (may be supported in the future).
- **apktool is not perfectly reversible.** `build` handles the common
private-resource failure automatically, but heavily obfuscated or unusual
resource tables may still need manual fixes.
- **iOS proxy** can't be set programmatically (per-Wi-Fi, no public service);
`setproxy` is Android-only.
- **CA trust** is intentionally not automated: on modern setups it's better
handled by a Magisk cert module (Android) or a configuration profile (iOS).

## Requirements

Python deps (installed by `pip install .`): androguard, asn1crypto,
pymobiledevice3, paramiko, google-play-scraper. Optional: frida (`[frida]` extra).

External tools (installed by `scripts/install-deps.sh`):

- Android: `adb`, `apktool`, `apksigner`, `zipalign`, `aapt` (+ a JRE)
- iOS: `libimobiledevice-utils`, `ideviceinstaller`, `usbmuxd`, `ldid`
- packing: `zip`, `unzip`

## License

MIT.
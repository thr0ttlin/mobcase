"""mbc.transport.ios: iOS backend. The scatter, hidden behind one interface.

Channels, one per capability:
    run / push / pull      -> SSH / SFTP via paramiko (pure python)
    install / uninstall    -> ideviceinstaller (usbmux; no jailbreak needed)
    device discovery       -> pymobiledevice3 usbmux (async, pure python)

SSH is paramiko rather than shelling out to ssh/scp: the password is handled
in memory (never on argv, never a tty prompt that collides with our output),
and there's no dependency on an external sshpass. Defaults suit a palera1n +
iproxy setup: root/mobile@localhost:2222. `serial` is the device UDID
(usbmux-side); the SSH endpoint is separate.
"""

from __future__ import annotations

import os
import stat as _stat

from .base import (
    Device, Platform, RunResult, Transport, TransportError, UnsupportedOperation,
    locate_tool, run_argv,
)
from .. import ui


class IosTransport(Transport):
    platform = Platform.IOS

    def __init__(self, serial: str | None = None, *,
                 ssh_host: str = "localhost", ssh_port: int = 2222,
                 ssh_user: str = "mobile", password: str | None = None,
                 ssh_timeout: float = 15.0) -> None:
        super().__init__(serial)                      # serial = UDID
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.password = password
        self.ssh_timeout = ssh_timeout
        self._client = None

    # -- SSH channel (paramiko) : run / push / pull ------------------------- #

    def _ssh(self):
        if self._client is not None:
            return self._client
        try:
            import paramiko
        except Exception as e:  # pragma: no cover
            raise TransportError("paramiko is required for iOS SSH operations") from e

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # password may be a str, None (try keys/agent), or a callable provider
        # (e.g. a getpass prompt) invoked lazily: only now, when SSH is needed.
        pw = self.password() if callable(self.password) else self.password
        self.password = pw
        use_keys = pw is None
        try:
            client.connect(
                hostname=self.ssh_host, port=self.ssh_port, username=self.ssh_user,
                password=pw, look_for_keys=use_keys, allow_agent=use_keys,
                timeout=self.ssh_timeout, auth_timeout=self.ssh_timeout,
            )
        except Exception as e:
            import paramiko
            ep = f"{self.ssh_user}@{self.ssh_host}:{self.ssh_port}"
            if isinstance(e, paramiko.AuthenticationException):
                msg = f"SSH auth failed for {ep} - wrong password?"
            elif isinstance(e, (paramiko.ssh_exception.NoValidConnectionsError,
                                ConnectionError, TimeoutError, OSError, EOFError)):
                msg = (f"SSH connect to {self.ssh_host}:{self.ssh_port} failed - is the "
                       f"tunnel up? start it, e.g.  iproxy {self.ssh_port} 22   ({e})")
            else:
                msg = f"SSH to {ep} failed: {e}"
            raise TransportError(msg) from e
        self._client = client
        return client

    def run(self, command, *, timeout=None, check=False) -> RunResult:
        if isinstance(command, (list, tuple)):
            import shlex
            command = shlex.join(command)
        ui.console.verbose(f"ssh$ {command}")
        chan_stdin, chan_out, chan_err = self._ssh().exec_command(
            command, timeout=timeout)
        out = chan_out.read().decode(errors="replace")
        err = chan_err.read().decode(errors="replace")
        rc = chan_out.channel.recv_exit_status()
        r = RunResult(rc, out, err)
        return r.check() if check else r

    def push(self, local, remote) -> None:
        ui.console.verbose(f"sftp put {local} -> {remote}")
        sftp = self._ssh().open_sftp()
        try:
            sftp.put(str(local), str(remote))
        finally:
            sftp.close()

    def pull(self, remote, local, *, recursive=False) -> None:
        ui.console.verbose(f"sftp get {remote} -> {local}")
        sftp = self._ssh().open_sftp()
        try:
            if recursive:
                # mirror `scp -r`: create <local>/<basename(remote)> and recurse
                target = os.path.join(str(local), str(remote).rstrip("/").rsplit("/", 1)[-1])
                _sftp_get_dir(sftp, str(remote), target)
            else:
                sftp.get(str(remote), str(local))
        finally:
            sftp.close()

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    # -- SFTP helpers (reuse the SSH channel; no device-side tools needed) --- #

    def _sftp(self):
        if getattr(self, "_sftp_client", None) is None:
            self._sftp_client = self._ssh().open_sftp()
        return self._sftp_client

    def listdir(self, path: str) -> list[str]:
        try:
            return self._sftp().listdir(path)
        except TransportError:
            raise                         # connection failure -> surface it
        except Exception:
            return []                     # path missing / not readable

    def read_file(self, path: str) -> bytes:
        # connection errors propagate (TransportError from _ssh); per-file errors
        # are the caller's to handle
        with self._sftp().open(path, "rb") as f:
            return f.read()

    # -- lifecycle : ideviceinstaller (usbmux) ------------------------------ #

    def _idev_base(self) -> list[str]:
        b = [locate_tool("ideviceinstaller")]
        if self.serial:
            b += ["-u", self.serial]
        return b

    def install(self, path, *, reinstall=True) -> RunResult:
        paths = path if isinstance(path, (list, tuple)) else [path]
        if len(paths) != 1:
            raise UnsupportedOperation("iOS install takes a single .ipa")
        return run_argv(self._idev_base() + ["install", str(paths[0])])

    def uninstall(self, identifier) -> RunResult:
        return run_argv(self._idev_base() + ["uninstall", identifier])

    def list_installed(self) -> list[str]:
        r = run_argv(self._idev_base() + ["list"]).check()
        out: list[str] = []
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line or line.lower().startswith(("total", "bundleid", "cfbundle")):
                continue
            out.append(line.split(",")[0].strip().strip('"'))
        return sorted(b for b in out if b)

    # -- discovery : pymobiledevice3 usbmux (pure python, async in 11.x) ----- #

    @classmethod
    def list_devices(cls) -> list[Device]:
        try:
            import asyncio
            from pymobiledevice3 import usbmux
            from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError
        except Exception:
            return []

        async def _collect() -> list[Device]:
            try:
                muxdevs = await usbmux.list_devices()
            except ConnectionFailedToUsbmuxdError:
                return []
            except Exception:
                return []
            out: list[Device] = []
            for md in muxdevs:
                udid = getattr(md, "serial", "") or ""
                if not udid:
                    continue
                name = await cls._describe(udid)
                out.append(Device(
                    serial=udid, platform=Platform.IOS, name=name,
                    extra={"connection": str(getattr(md, "connection_type", ""))},
                ))
            return out

        try:
            return asyncio.run(_collect())
        except Exception:
            return []

    @staticmethod
    async def _describe(udid: str) -> str:
        import inspect
        try:
            from pymobiledevice3.lockdown import create_using_usbmux
            ld = await create_using_usbmux(serial=udid, autopair=False)
        except Exception:
            return "iOS device"
        try:
            async def val(key: str):
                try:
                    return await ld.get_value(key=key)
                except Exception:
                    return None
            name = await val("DeviceName")
            ptype = await val("ProductType")
            pver = await val("ProductVersion")
            parts = [p for p in (name, ptype, f"iOS {pver}" if pver else None) if p]
            return " · ".join(parts) if parts else "iOS device"
        finally:
            for m in ("aclose", "close"):
                fn = getattr(ld, m, None)
                if fn:
                    try:
                        r = fn()
                        if inspect.isawaitable(r):
                            await r
                    except Exception:
                        pass
                    break


def _sftp_get_dir(sftp, remote: str, local: str) -> None:
    """Recursively download a remote directory over SFTP (paramiko has no
    recursive get). Directories become directories; files are fetched."""
    os.makedirs(local, exist_ok=True)
    for entry in sftp.listdir_attr(remote):
        rpath = f"{remote}/{entry.filename}"
        lpath = os.path.join(local, entry.filename)
        if _stat.S_ISDIR(entry.st_mode):
            _sftp_get_dir(sftp, rpath, lpath)
        else:
            sftp.get(rpath, lpath)
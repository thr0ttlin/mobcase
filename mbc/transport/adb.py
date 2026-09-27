"""mbc.transport.adb: Android backend. One bridge does everything."""

from __future__ import annotations

import shlex

from .base import (
    Device, Platform, RunResult, Transport, TransportError,
    locate_tool, run_argv, stream_argv,
)

_SDK_FALLBACKS = ["~/Android/Sdk/platform-tools/adb"]


class AdbTransport(Transport):
    platform = Platform.ANDROID

    def __init__(self, serial: str | None = None, adb_path: str | None = None) -> None:
        super().__init__(serial)
        self.adb = adb_path or locate_tool("adb", _SDK_FALLBACKS)

    @property
    def _base(self) -> list[str]:
        b = [self.adb]
        if self.serial:
            b += ["-s", self.serial]
        return b

    def run(self, command, *, timeout=None, check=False) -> RunResult:
        if isinstance(command, (list, tuple)):
            command = shlex.join(command)
        r = run_argv(self._base + ["shell", command], timeout=timeout)
        return r.check() if check else r

    def push(self, local, remote) -> None:
        run_argv(self._base + ["push", str(local), str(remote)]).check()

    def pull(self, remote, local, *, recursive=False) -> None:
        run_argv(self._base + ["pull", str(remote), str(local)]).check()  # adb pull recurses dirs

    def install(self, path, *, reinstall=True) -> RunResult:
        paths = [str(p) for p in (path if isinstance(path, (list, tuple)) else [path])]
        verb = "install-multiple" if len(paths) > 1 else "install"
        argv = self._base + [verb] + (["-r"] if reinstall else []) + paths
        return run_argv(argv)

    def uninstall(self, identifier) -> RunResult:
        return run_argv(self._base + ["uninstall", identifier])

    def stream(self, subargs: list[str]) -> int:
        """Stream a long-lived adb subcommand (e.g. logcat) to stdout."""
        return stream_argv(self._base + list(subargs))

    def adb_root(self) -> RunResult:
        """Restart adbd as root (userdebug/eng builds); no-op-ish on user builds."""
        return run_argv(self._base + ["root"])

    def list_installed(self) -> list[str]:
        r = run_argv(self._base + ["shell", "pm", "list", "packages"]).check()
        return sorted(
            line[len("package:"):].strip()
            for line in r.stdout.splitlines()
            if line.startswith("package:")
        )

    # -- discovery ----------------------------------------------------------- #

    @classmethod
    def list_devices(cls, adb_path: str | None = None) -> list[Device]:
        try:
            adb = adb_path or locate_tool("adb", _SDK_FALLBACKS)
        except TransportError:
            return []
        r = run_argv([adb, "devices", "-l"])
        devices: list[Device] = []
        for line in r.stdout.splitlines()[1:]:      # skip "List of devices attached"
            parts = line.split()
            if len(parts) < 2 or parts[1] != "device":   # skip offline/unauthorized
                continue
            model = next((t[len("model:"):] for t in parts[2:]
                          if t.startswith("model:")), "")
            devices.append(Device(serial=parts[0], platform=Platform.ANDROID,
                                  name=model.replace("_", " ")))
        return devices
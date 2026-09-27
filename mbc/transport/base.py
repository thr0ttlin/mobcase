"""mbc.transport.base: the device-I/O contract.

One interface (Transport) with the operations every command needs:
run / push / pull / install / uninstall / list_installed. Android satisfies
all of them through a single bridge (adb); iOS routes each to a different
channel (SSH, ideviceinstaller, usbmux): that scatter is hidden here.

All subprocess use funnels through run_argv(), the single chokepoint: it
logs every command line to the verbose channel and normalises results.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence

from .. import ui


class Platform(str, Enum):
    ANDROID = "android"
    IOS = "ios"


# -- errors ------------------------------------------------------------------ #

class TransportError(Exception):
    """Any device-I/O failure."""


class UnsupportedOperation(TransportError):
    """This backend can't do this op (e.g. shell on a stock iPhone)."""


class ToolNotFound(TransportError):
    """A required external binary (adb, ssh, ideviceinstaller...) is missing."""


# -- value types ------------------------------------------------------------- #

@dataclass
class Device:
    serial: str                 # adb serial, or iOS UDID
    platform: Platform
    name: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class RunResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def check(self) -> "RunResult":
        if not self.ok:
            msg = self.stderr.strip() or self.stdout.strip() or f"exit {self.returncode}"
            raise TransportError(msg)
        return self


# -- helpers ----------------------------------------------------------------- #

def locate_tool(name: str, fallbacks: Sequence[str] = ()) -> str:
    """Find an external tool in PATH, else in known fallback locations
    (mirrors appquick's check_and_init_tool with its SDK path guesses)."""
    found = shutil.which(name)
    if found:
        return found
    for fb in fallbacks:
        fb = os.path.expanduser(str(fb))
        if os.path.isfile(fb) and os.access(fb, os.X_OK):
            return fb
    hint = " or known locations" if fallbacks else ""
    raise ToolNotFound(f"{name} not found in PATH{hint}")


def run_argv(argv: Sequence[str], *, timeout: float | None = None,
             input_bytes: bytes | None = None, cwd: str | None = None) -> RunResult:
    """The single subprocess chokepoint. Logs to verbose, returns RunResult."""
    argv = [str(a) for a in argv]
    ui.console.verbose("$ " + shlex.join(argv))
    try:
        proc = subprocess.run(
            argv, capture_output=True, timeout=timeout, input=input_bytes, cwd=cwd,
        )
    except FileNotFoundError as e:
        raise ToolNotFound(str(e)) from e
    except subprocess.TimeoutExpired as e:
        raise TransportError(f"timeout after {timeout}s: {shlex.join(argv)}") from e
    return RunResult(
        proc.returncode,
        proc.stdout.decode(errors="replace"),
        proc.stderr.decode(errors="replace"),
    )


def stream_argv(argv: Sequence[str]) -> int:
    """Run a long-lived command and stream its output to stdout until it ends
    or the user hits Ctrl-C (logcat / syslog). Returns the exit code."""
    import sys
    argv = [str(a) for a in argv]
    ui.console.verbose("$ " + shlex.join(argv))
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
    except FileNotFoundError as e:
        raise ToolNotFound(str(e)) from e
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
    except KeyboardInterrupt:
        proc.terminate()
    finally:
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    return proc.returncode or 0


# -- the interface ----------------------------------------------------------- #

class Transport(ABC):
    """Common device operations. A backend may raise UnsupportedOperation for
    ops it genuinely can't perform (e.g. arbitrary shell on non-jailbroken iOS)."""

    platform: Platform

    def __init__(self, serial: str | None = None) -> None:
        self.serial = serial

    @abstractmethod
    def run(self, command: str | Sequence[str], *,
            timeout: float | None = None, check: bool = False) -> RunResult:
        """Execute a shell command on the device."""

    @abstractmethod
    def push(self, local: str, remote: str) -> None:
        """Copy host -> device."""

    @abstractmethod
    def pull(self, remote: str, local: str, *, recursive: bool = False) -> None:
        """Copy device -> host (recursive for directories where the backend needs it)."""

    @abstractmethod
    def install(self, path: str | Sequence[str], *, reinstall: bool = True) -> RunResult:
        """Install an app package (list of paths = split install where supported)."""

    @abstractmethod
    def uninstall(self, identifier: str) -> RunResult:
        """Remove an app by package name / bundle id."""

    @abstractmethod
    def list_installed(self) -> list[str]:
        """Installed package names (Android) / bundle ids (iOS)."""

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.platform.value}:{self.serial or 'default'}>"
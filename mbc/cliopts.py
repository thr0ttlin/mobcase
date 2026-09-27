"""mbc.cliopts: small argparse helpers shared across commands."""

from __future__ import annotations


def add_ssh_args(sp) -> None:
    """iOS SSH options for subcommands that use the SSH channel."""
    sp.add_argument("--ssh-host", default="localhost", help="iOS SSH host (default: localhost)")
    sp.add_argument("--ssh-port", type=int, default=2222, help="iOS SSH port (default: 2222)")
    sp.add_argument("--ssh-user", default="mobile", help="iOS SSH user (default: mobile)")
    sp.add_argument("--password", help="iOS SSH password (omit to be prompted when needed)")


def ssh_opts(args) -> dict:
    """Build the ssh option dict from parsed args (only meaningful for iOS).

    When --password isn't given, password is a *lazy provider*: a getpass prompt
    that the transport invokes only if it actually opens an SSH connection (iOS
    stop/start/pull/log). Android and usbmux-only iOS ops never trigger it.
    """
    password = getattr(args, "password", None)
    if password is None:
        from . import ui
        password = lambda: ui.console.ask_password("iOS SSH password: ")   # noqa: E731
    return {
        "ssh_host": getattr(args, "ssh_host", "localhost"),
        "ssh_port": getattr(args, "ssh_port", 2222),
        "ssh_user": getattr(args, "ssh_user", "mobile"),
        "password": password,
    }
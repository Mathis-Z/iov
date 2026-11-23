"""Shared plumbing for the host data sources.

Every source returns None when its data is unavailable -- the command is not
installed, the file is unreadable, there is no systemd in the container, and so
on -- and never raises for that reason. The only exception a source raises on
purpose is SandboxLimit, when a script asks for more than the sandbox allows.

Results are cached until reset_caches(), so a script (or a whole evaluation
pass) that inspects the same source twice only pays for it once.
"""

import functools
import io
import logging
import os
import subprocess
import sys
import time
from collections.abc import Callable
from typing import TypeVar

from ..logging_setup import LOGGER_NAME

log = logging.getLogger(LOGGER_NAME)

MAX_FILE_BYTES = 1024 * 1024   # per file a script reads, per the IoV specification
MAX_ENTRIES = 10_000           # per list a built-in returns, per the IoV specification
COMMAND_TIMEOUT = 15

F = TypeVar("F", bound=Callable)

_cached_functions: list = []


def cached(func: F) -> F:
    """functools.cache, registered so reset_caches() can clear it."""
    wrapped = functools.cache(func)
    _cached_functions.append(wrapped)
    return wrapped  # type: ignore[return-value]


def reset_caches() -> None:
    """Forget every cached host fact.

    Caching for the lifetime of the process is right for a one-shot run, but a
    daemon lives for weeks and would otherwise keep reporting the module list
    and package inventory it saw at boot. The daemon calls this once per
    evaluation pass -- not between IoVs, so a single pass still sees one
    consistent snapshot and pays for `rpm -qa` only once.
    """
    for func in _cached_functions:
        func.cache_clear()


# ── Sandbox limits ────────────────────────────────────────────────────────────

class SandboxLimit(Exception):
    """A script exceeded a sandbox limit (time or result size)."""


_deadline: float | None = None


def set_deadline(seconds: float | None) -> None:
    """Start (or, with None, clear) the wall-clock limit for the running script."""
    global _deadline
    _deadline = None if seconds is None else time.monotonic() + seconds


def check_deadline() -> None:
    """Raise SandboxLimit if the running script is past its wall-clock limit."""
    if _deadline is not None and time.monotonic() > _deadline:
        raise SandboxLimit("the script exceeded its time limit")


def limit_entries(items: list, what: str) -> list:
    """Return the list, or raise SandboxLimit if it has more than MAX_ENTRIES items."""
    if len(items) > MAX_ENTRIES:
        raise SandboxLimit(f"{what} returned more than {MAX_ENTRIES} entries")
    return items


# ── Commands and files ────────────────────────────────────────────────────────

def _host_environment() -> dict[str, str] | None:
    """The environment for host commands, or None to inherit ours unchanged.

    The packaged binary's bootloader points LD_LIBRARY_PATH at its bundled
    libraries (saving the original as LD_LIBRARY_PATH_ORIG); rpm, dpkg and
    friends must run against the host's own libraries instead.
    """
    if not getattr(sys, "frozen", False):
        return None
    env = dict(os.environ)
    original = env.pop("LD_LIBRARY_PATH_ORIG", None)
    if original is None:
        env.pop("LD_LIBRARY_PATH", None)
    else:
        env["LD_LIBRARY_PATH"] = original
    return env


def run_process(*cmd: str) -> subprocess.CompletedProcess | None:
    """Run a command, or return None if it could not be run at all."""
    log.debug("running command: %s", list(cmd))
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=COMMAND_TIMEOUT,
            env=_host_environment(),
        )
    except FileNotFoundError:
        # Most of these tools are optional (no ip, no systemctl, dpkg on an RPM
        # host, ...), so a missing one is normal rather than noteworthy.
        log.debug("command %s is not installed", cmd[0])
    except Exception as exc:
        log.warning("command %s failed to execute: %s", list(cmd), exc)
    return None


def run_command(*cmd: str) -> str | None:
    """Run a command and return its stdout, or None if it failed."""
    proc = run_process(*cmd)
    if proc is None:
        return None
    if proc.returncode != 0:
        log.warning(
            "command %s exited with code %d; stderr=%r",
            list(cmd), proc.returncode, (proc.stderr or "").strip(),
        )
        return None
    log.debug("command %s succeeded (%d bytes of stdout)", list(cmd), len(proc.stdout))
    return proc.stdout


def read_text(path: str, limit: int | None = MAX_FILE_BYTES) -> str | None:
    """Read a file as UTF-8 text, truncated to `limit` bytes, or None if unreadable.

    The limit counts bytes, not decoded characters, so a script can never read
    more than MAX_FILE_BYTES of a file. Undecodable bytes are replaced.
    """
    data = read_bytes(path, limit)
    if data is None:
        return None
    with io.TextIOWrapper(io.BytesIO(data), encoding="utf-8", errors="replace") as handle:
        return handle.read()  # TextIOWrapper translates newlines like open() does


def read_bytes(path: str, limit: int | None = MAX_FILE_BYTES) -> bytes | None:
    """Read a file's bytes, truncated to `limit`, or None if unreadable."""
    try:
        with open(path, "rb") as handle:
            return handle.read() if limit is None else handle.read(limit)
    except OSError as exc:
        log.debug("could not read %s: %s", path, exc)
        return None

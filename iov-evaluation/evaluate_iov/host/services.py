"""systemd units and the service_exposed standard-library helper."""

import ipaddress
import logging
import os
import re
from pathlib import Path

from ..logging_setup import LOGGER_NAME
from .base import cached, limit_entries, run_command
from .network import listening_sockets, process_cgroups, processes

log = logging.getLogger(LOGGER_NAME)

_PROPERTIES = {
    "Id": "name", "LoadState": "load_state", "ActiveState": "active_state",
    "SubState": "sub_state", "UnitFileState": "unit_file_state",
    "FragmentPath": "fragment_path", "TriggeredBy": "triggered_by", "Triggers": "triggers",
    "Requires": "requires", "Wants": "wants", "Listen": "listen",
}
_LIST_PROPERTIES = {"triggered_by", "triggers", "requires", "wants"}
EXECUTABLE_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")


def systemd_running() -> bool:
    """Whether systemd is the init system."""
    # The same test sd_booted(3) uses.
    return Path("/run/systemd/system").is_dir()


def _parse_show(output: str) -> list[dict]:
    """Parse `systemctl show` output: one block of Key=Value lines per unit."""
    units = []
    for block in output.split("\n\n"):
        unit = {field: [] if field in _LIST_PROPERTIES or field == "listen" else ""
                for field in _PROPERTIES.values()}
        seen = False
        for line in block.splitlines():
            key, sep, value = line.partition("=")
            field = _PROPERTIES.get(key)
            if not sep or field is None:
                continue
            seen = True
            if field == "listen":
                if value:
                    unit["listen"].append(value)
            elif field in _LIST_PROPERTIES:
                unit[field] = value.split()
            else:
                unit[field] = value
        if seen:
            units.append(unit)
    return units


def _show(names: list[str]) -> list[dict] | None:
    if not systemd_running():
        return None
    if not names:
        return []
    out = run_command("systemctl", "show", "--no-pager",
                      "-p", ",".join(_PROPERTIES), "--", *names)
    return None if out is None else _parse_show(out)


@cached
def systemd_unit(name: str) -> dict | None:
    """The state of one systemd unit, or None without systemd."""
    units = _show([name])
    if not units:
        return None
    unit = units[0]
    unit["name"] = unit["name"] or name
    return unit


@cached
def _all_unit_names() -> list[str] | None:
    if not systemd_running():
        return None
    names = set()
    for cmd in (("systemctl", "list-units", "--all", "--no-legend", "--plain", "--no-pager"),
                ("systemctl", "list-unit-files", "--no-legend", "--no-pager")):
        out = run_command(*cmd)
        if out is None:
            return None
        for line in out.splitlines():
            fields = line.split()
            if fields:
                names.add(fields[0].lstrip("●* "))
    return sorted(n for n in names if n)


def systemd_units(name_regex: str) -> list[dict] | None:
    """The state of every loaded or installed unit whose name matches the regex."""
    pattern = re.compile(name_regex)
    names = _all_unit_names()
    if names is None:
        return None
    matching = limit_entries([n for n in names if pattern.search(n)], "systemd_units()")
    return _show(matching)


def systemd_unit_property(name: str, prop: str) -> str | None:
    """One raw `systemctl show` property of a unit, or None without systemd."""
    if not systemd_running():
        return None
    out = run_command("systemctl", "show", "--no-pager", "-p", prop, "--value", "--", name)
    return None if out is None else out.rstrip("\n")


# ── service_exposed ───────────────────────────────────────────────────────────

def _listen_is_local(entry: str) -> bool:
    """Is a socket unit's Listen entry (e.g. '[::]:22 (Stream)') local-only?"""
    address = entry.rsplit(" (", 1)[0].strip()
    if address.startswith(("/", "@")):
        return True  # a UNIX socket is not reachable over the network
    host, sep, _ = address.rpartition(":")
    if not sep:
        return False  # a bare port listens on every address
    host = host.strip("[]")
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False  # an interface-bound or otherwise unusual address


def service_exposed(names: list[str]) -> str | None:
    """How reachable a daemon is, from processes, sockets and systemd units:
    "network", "loopback", "running", "installed" or "absent".

    `names` are process, executable or unit base names. Sockets of matching
    processes and the Listen addresses of active socket units decide between
    network and loopback.
    """
    procs = processes()
    sockets = listening_sockets()
    if procs is None or sockets is None:
        return None

    names = [n for n in names if n]
    cgroups = process_cgroups()
    service_suffixes = tuple(f"/{n}.service" for n in names)
    pids = {
        p["pid"] for p in procs
        if p["name"] in names or (p["exe"] and os.path.basename(p["exe"]) in names)
        or cgroups.get(p["pid"], "").endswith(service_suffixes)
    }
    local_flags = [s["loopback"] for s in sockets if s["pid"] in pids]

    units = []
    for name in names:
        for suffix in (".service", ".socket"):
            unit = systemd_unit(name + suffix)
            if unit is not None:
                units.append(unit)
    for unit in units:
        if unit["name"].endswith(".socket") and unit["active_state"] == "active":
            local_flags.extend(_listen_is_local(entry) for entry in unit["listen"])

    if local_flags:
        return "loopback" if all(local_flags) else "network"
    if pids or any(u["name"].endswith(".service") and u["active_state"] == "active" for u in units):
        return "running"
    if any(u["load_state"] == "loaded" for u in units) or any(
        os.path.isfile(os.path.join(d, n)) for d in EXECUTABLE_DIRS for n in names
    ):
        return "installed"
    return "absent"

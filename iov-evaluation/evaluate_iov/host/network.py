"""Processes, listening sockets, interfaces and routes."""

import contextlib
import ipaddress
import json
import logging
import os
import socket
import struct
from pathlib import Path

from ..logging_setup import LOGGER_NAME
from .base import cached, limit_entries, read_text, run_command

log = logging.getLogger(LOGGER_NAME)

# Capability bit -> name, from linux/capability.h.
CAPABILITIES = [
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
    "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW",
    "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE",
    "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ",
    "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE",
]

# /proc/net/{tcp,udp}* state column: 0A = TCP LISTEN, 07 = UDP unconnected.
_SOCKET_TABLES = (
    ("/proc/net/tcp",  "tcp", "ipv4", "0A"),
    ("/proc/net/tcp6", "tcp", "ipv6", "0A"),
    ("/proc/net/udp",  "udp", "ipv4", "07"),
    ("/proc/net/udp6", "udp", "ipv6", "07"),
)


# ── Sockets ───────────────────────────────────────────────────────────────────

def _decode_address(hex_address: str, family: str) -> str:
    raw = bytes.fromhex(hex_address)
    if family == "ipv4":
        return socket.inet_ntop(socket.AF_INET, struct.pack("<I", struct.unpack(">I", raw)[0]))
    # IPv6 addresses are four 32-bit words, each in host (little-endian) order.
    words = struct.unpack("<4I", raw)
    return socket.inet_ntop(socket.AF_INET6, struct.pack(">4I", *words))


@cached
def _socket_table() -> list[dict] | None:
    """Every listening socket, without owner information."""
    entries = []
    read_any = False
    for path, protocol, family, state in _SOCKET_TABLES:
        text = read_text(path, limit=None)
        if text is None:
            continue
        read_any = True
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[3].upper() != state:
                continue
            address_hex, _, port_hex = fields[1].partition(":")
            try:
                address = _decode_address(address_hex, family)
                parsed = ipaddress.ip_address(address)
            except (ValueError, struct.error, OSError):
                continue
            mapped = getattr(parsed, "ipv4_mapped", None)
            effective = mapped or parsed
            entries.append({
                "protocol": protocol,
                "family": family,
                "local_address": address,
                "local_port": int(port_hex, 16),
                "wildcard": parsed.is_unspecified,
                "loopback": effective.is_loopback,
                "uid": int(fields[7]) if fields[7].isdigit() else -1,
                "inode": fields[9],
            })
    return entries if read_any else None


@cached
def _socket_inodes_by_pid() -> dict[int, set[str]]:
    owners: dict[int, set[str]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        inodes = set()
        try:
            for fd in (entry / "fd").iterdir():
                try:
                    target = os.readlink(fd)
                except OSError:
                    continue
                # target looks like "socket:[119492]"
                if target.startswith("socket:[") and target.endswith("]"):
                    inodes.add(target[8:-1])
        except OSError:
            continue  # not readable, or the process exited
        if inodes:
            owners[int(entry.name)] = inodes
    return owners


def listening_sockets() -> list[dict] | None:
    """Listening TCP and unconnected UDP sockets with their owning process.
    None if /proc/net is unreadable.
    """
    table = _socket_table()
    if table is None:
        return None
    owner_of: dict[str, int] = {}
    for pid, inodes in sorted(_socket_inodes_by_pid().items()):
        for inode in inodes:
            owner_of.setdefault(inode, pid)
    by_pid = {p["pid"]: p for p in processes() or []}

    result = []
    for entry in table:
        pid = owner_of.get(entry["inode"], -1)
        process = by_pid.get(pid, {})
        socket_entry = {key: value for key, value in entry.items() if key != "inode"}
        socket_entry.update(pid=pid, program=process.get("name", ""), exe=process.get("exe", ""))
        result.append(socket_entry)
    return limit_entries(result, "listening_sockets()")


# ── Processes ─────────────────────────────────────────────────────────────────

def _tty_name(tty_nr: int) -> str:
    if tty_nr == 0:
        return ""
    major = (tty_nr >> 8) & 0xFFF
    minor = (tty_nr & 0xFF) | ((tty_nr >> 12) & 0xFFF00)
    if 136 <= major <= 143:
        return f"pts/{(major - 136) * 256 + minor}"
    if major == 4:
        return f"tty{minor}" if minor < 64 else f"ttyS{minor - 64}"
    return f"{major}:{minor}"


@cached
def _boot_time() -> int | None:
    text = read_text("/proc/stat", limit=None) or ""
    for line in text.splitlines():
        if line.startswith("btime "):
            return int(line.split()[1])
    return None


def _selinux_enabled() -> bool:
    return Path("/sys/fs/selinux/enforce").exists()


def _read_process(entry: Path, listening: set[str], owners: dict[int, set[str]],
                  ticks: int, boot_time: int | None, selinux: bool) -> dict | None:
    pid = int(entry.name)
    try:
        name = (entry / "comm").read_text().strip()
    except OSError:
        return None  # the process exited while we were walking /proc

    def link(name: str) -> str:
        try:
            return os.readlink(entry / name)
        except OSError:
            return ""  # kernel threads and some sandboxed processes have none

    try:
        raw = (entry / "cmdline").read_bytes()
        cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except OSError:
        cmdline = ""

    status: dict[str, str] = {}
    try:
        for line in (entry / "status").read_text().splitlines():
            key, _, value = line.partition(":")
            status[key] = value.strip()
    except OSError:
        pass

    def status_int(key: str, index: int = 0) -> int:
        try:
            return int(status[key].split()[index])
        except (KeyError, IndexError, ValueError):
            return -1

    capabilities = None
    if "CapEff" in status:
        try:
            mask = int(status["CapEff"], 16)
            capabilities = [cap for bit, cap in enumerate(CAPABILITIES) if mask >> bit & 1]
        except ValueError:
            pass

    session_id = tty = start_time = -1
    tty_name = ""
    try:
        stat = (entry / "stat").read_text()
        # comm may contain spaces and parentheses; the fields follow the last ')'.
        fields = stat[stat.rindex(")") + 2:].split()
        session_id, tty = int(fields[3]), int(fields[4])
        tty_name = _tty_name(tty)
        if boot_time is not None:
            start_time = boot_time + int(fields[19]) // ticks
    except (OSError, ValueError, IndexError):
        pass

    loginuid = -1
    try:
        value = int((entry / "loginuid").read_text().strip())
        loginuid = -1 if value == 4294967295 else value
    except (OSError, ValueError):
        pass

    selinux_context = ""
    if selinux:
        with contextlib.suppress(OSError):
            selinux_context = (entry / "attr" / "current").read_text().strip("\x00\n ")

    return {
        "pid": pid,
        "ppid": status_int("PPid"),
        "name": name,
        "exe": link("exe"),
        "cmdline": cmdline,
        "cwd": link("cwd"),
        "uid": status_int("Uid", 0),
        "euid": status_int("Uid", 1),
        "gid": status_int("Gid", 0),
        "loginuid": loginuid,
        "session_id": session_id,
        "tty": tty_name,
        "start_time": start_time,
        "capabilities": capabilities,
        "selinux_context": selinux_context,
        "has_listening_socket": bool(owners.get(pid, set()) & listening),
    }


@cached
def processes() -> list[dict] | None:
    """Every running process from /proc."""
    try:
        entries = [e for e in Path("/proc").iterdir() if e.name.isdigit()]
    except OSError:
        return None
    listening = {s["inode"] for s in _socket_table() or []}
    owners = _socket_inodes_by_pid()
    ticks = os.sysconf("SC_CLK_TCK")
    boot_time = _boot_time()
    selinux = _selinux_enabled()

    collected = []
    for entry in entries:
        process = _read_process(entry, listening, owners, ticks, boot_time, selinux)
        if process is not None:
            collected.append(process)
    log.debug("collected %d process(es)", len(collected))
    return collected


def process_environ(pid: int) -> dict[str, str] | None:
    """A process's environment, or None if it cannot be read."""
    try:
        raw = Path(f"/proc/{int(pid)}/environ").read_bytes()
    except (OSError, ValueError):
        return None
    environment = {}
    for item in raw.split(b"\x00"):
        key, sep, value = item.decode("utf-8", errors="replace").partition("=")
        if sep and key:
            environment[key] = value
    return environment


@cached
def process_cgroups() -> dict[int, str]:
    """pid -> the cgroup v2 path (or the systemd hierarchy path on cgroup v1)."""
    cgroups: dict[int, str] = {}
    for process in processes() or []:
        text = read_text(f"/proc/{process['pid']}/cgroup", limit=None) or ""
        chosen = ""
        for line in text.splitlines():
            parts = line.split(":", 2)
            if len(parts) == 3 and (parts[0] == "0" or parts[1] == "name=systemd"):
                chosen = parts[2]
        cgroups[process["pid"]] = chosen
    return cgroups


# ── Interfaces and routes ─────────────────────────────────────────────────────

_IFF_FLAGS = [(0x1, "UP"), (0x2, "BROADCAST"), (0x8, "LOOPBACK"), (0x10, "POINTOPOINT"),
              (0x80, "NOARP"), (0x100, "PROMISC"), (0x200, "ALLMULTI"), (0x400, "MASTER"),
              (0x800, "SLAVE"), (0x1000, "MULTICAST")]


def _ip_json(*args: str) -> list | None:
    out = run_command("ip", "-j", *args)
    if out is None:
        return None
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, list) else None


def _interfaces_from_sysfs() -> list[dict] | None:
    try:
        names = sorted(p.name for p in Path("/sys/class/net").iterdir())
    except OSError:
        return None
    result = []
    for name in names:
        base = f"/sys/class/net/{name}"
        try:
            flags_value = int((read_text(f"{base}/flags") or "0").strip(), 16)
        except ValueError:
            flags_value = 0
        flags = [label for bit, label in _IFF_FLAGS if flags_value & bit]
        if (read_text(f"{base}/operstate") or "").strip() == "up":
            flags.append("RUNNING")
        mac = (read_text(f"{base}/address") or "").strip()
        mtu = (read_text(f"{base}/mtu") or "").strip()
        result.append({
            "name": name,
            "mac": "" if mac in ("", "00:00:00:00:00:00") else mac,
            "mtu": int(mtu) if mtu.isdigit() else -1,
            "flags": flags,
            "addresses": None,
        })
    return result


@cached
def interfaces() -> list[dict] | None:
    """Network interfaces from `ip -j address`, falling back to sysfs (which
    has no addresses).
    """
    data = _ip_json("address", "show")
    if data is None:
        return _interfaces_from_sysfs()
    result = []
    for entry in data:
        mac = entry.get("address", "")
        if entry.get("link_type") == "loopback" or mac == "00:00:00:00:00:00":
            mac = ""
        result.append({
            "name": entry.get("ifname", ""),
            "mac": mac,
            "mtu": entry.get("mtu", -1),
            "flags": list(entry.get("flags", [])),
            "addresses": [f"{a['local']}/{a['prefixlen']}" for a in entry.get("addr_info", [])
                          if "local" in a and "prefixlen" in a],
        })
    return result


@cached
def routes() -> list[dict] | None:
    """IPv4 and IPv6 routes of the main table from `ip -j route`."""
    result = []
    for family, flag, default in (("ipv4", "-4", "0.0.0.0/0"), ("ipv6", "-6", "::/0")):
        data = _ip_json(flag, "route", "show", "table", "main")
        if data is None:
            return None
        for entry in data:
            destination = entry.get("dst", "")
            if destination == "default":
                destination = default
            elif destination and "/" not in destination:
                destination += "/32" if family == "ipv4" else "/128"
            result.append({
                "family": family,
                "destination": destination,
                "gateway": entry.get("gateway", ""),
                "interface": entry.get("dev", ""),
                "metric": entry.get("metric", 0),
            })
    return result

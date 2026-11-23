"""Hardware, mounts, local accounts and the security modules."""

import fnmatch
import logging
import os
import re
from pathlib import Path

from ..logging_setup import LOGGER_NAME
from .base import cached, read_text
from .kernel import kernel_release

log = logging.getLogger(LOGGER_NAME)

PCI_IDS_PATHS = ("/usr/share/hwdata/pci.ids", "/usr/share/misc/pci.ids", "/usr/share/pci.ids")
NETWORK_FILESYSTEMS = {"nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph", "glusterfs",
                       "9p", "afs", "fuse.sshfs", "fuse.glusterfs", "lustre"}


# ── CPU ───────────────────────────────────────────────────────────────────────

@cached
def cpu() -> dict | None:
    """The first CPU's identity and flags, and the kernel's CPU vulnerability
    status from /sys/devices/system/cpu/vulnerabilities.
    """
    text = read_text("/proc/cpuinfo", limit=None)
    if text is None:
        return None
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if fields:
                break  # only the first CPU
            continue
        key, _, value = line.partition(":")
        fields.setdefault(key.strip(), value.strip())

    def number(key: str) -> int:
        value = fields.get(key, "")
        try:
            return int(value, 0)
        except ValueError:
            return -1

    vulnerabilities = {}
    directory = Path("/sys/devices/system/cpu/vulnerabilities")
    try:
        for path in sorted(directory.iterdir()):
            vulnerabilities[path.name] = (read_text(str(path)) or "").strip()
    except OSError:
        vulnerabilities = None

    return {
        "vendor": fields.get("vendor_id", fields.get("CPU implementer", "")),
        "family": number("cpu family"),
        "model": number("model"),
        "stepping": number("stepping"),
        "microcode": fields.get("microcode", ""),
        "flags": (fields.get("flags") or fields.get("Features") or "").split(),
        "vulnerabilities": vulnerabilities,
    }


# ── PCI ───────────────────────────────────────────────────────────────────────

@cached
def _pci_names() -> dict[str, tuple[str, dict[str, str]]]:
    """vendor id -> (vendor name, {device id -> device name}) from pci.ids."""
    text = None
    for path in PCI_IDS_PATHS:
        text = read_text(path, limit=None)
        if text is not None:
            break
    names: dict[str, tuple[str, dict[str, str]]] = {}
    current: dict[str, str] | None = None
    for line in (text or "").splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("C "):
            break  # the device class section follows the vendors
        if not line.startswith("\t"):
            vendor_id, _, name = line.partition("  ")
            current = {}
            names[vendor_id.strip().lower()] = (name.strip(), current)
        elif not line.startswith("\t\t") and current is not None:
            device_id, _, name = line.strip().partition("  ")
            current[device_id.lower()] = name.strip()
    return names


@cached
def _pci_aliases() -> list[tuple[str, str]]:
    """(pattern, module) pairs for PCI devices from modules.alias."""
    release = kernel_release()
    aliases = []
    for base in ("/lib/modules", "/usr/lib/modules"):
        text = read_text(f"{base}/{release}/modules.alias", limit=None)
        if text is None:
            continue
        for line in text.splitlines():
            fields = line.split()
            if len(fields) == 3 and fields[0] == "alias" and fields[1].startswith("pci:"):
                aliases.append((fields[1], fields[2]))
        break
    return aliases


def _pci_attribute(device: Path, name: str) -> str:
    """A sysfs PCI ID attribute, lowercased and without its '0x' prefix."""
    value = (read_text(str(device / name)) or "").strip().lower()
    return value[2:] if value.startswith("0x") else value


@cached
def pci_devices() -> list[dict] | None:
    """PCI devices with names from pci.ids, the bound driver, and the modules
    whose aliases match the device.
    """
    try:
        devices = sorted(Path("/sys/bus/pci/devices").iterdir())
    except OSError:
        return None
    names = _pci_names()
    aliases = _pci_aliases()
    result = []
    for device in devices:
        vendor_id, device_id = _pci_attribute(device, "vendor"), _pci_attribute(device, "device")
        vendor_name, device_names = names.get(vendor_id, ("", {}))
        try:
            driver = os.path.basename(os.readlink(device / "driver"))
        except OSError:
            driver = ""
        modalias = (read_text(str(device / "modalias")) or "").strip()
        modules = sorted({module for pattern, module in aliases
                          if modalias and fnmatch.fnmatchcase(modalias, pattern)})
        result.append({
            "slot": device.name,
            "class": _pci_attribute(device, "class")[:4],
            "vendor_id": vendor_id,
            "device_id": device_id,
            "subsystem_vendor_id": _pci_attribute(device, "subsystem_vendor"),
            "subsystem_device_id": _pci_attribute(device, "subsystem_device"),
            "vendor": vendor_name,
            "device": device_names.get(device_id, ""),
            "driver": driver,
            "modules": modules,
        })
    return result


# ── Mounts ────────────────────────────────────────────────────────────────────

def _unescape(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), value)


@cached
def mounts() -> list[dict] | None:
    """Mounted file systems from /proc/self/mountinfo."""
    text = read_text("/proc/self/mountinfo", limit=None)
    if text is None:
        return None
    result = []
    for line in text.splitlines():
        before, sep, after = line.partition(" - ")
        fields, tail = before.split(), after.split()
        if not sep or len(fields) < 6 or len(tail) < 2:
            continue
        mount_point, fs_type = _unescape(fields[4]), tail[0]
        size = free = -1
        # statvfs on an unreachable network file system can hang.
        if fs_type not in NETWORK_FILESYSTEMS:
            try:
                st = os.statvfs(mount_point)
                size, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
            except OSError:
                pass
        result.append({
            "device": _unescape(tail[1]),
            "mount_point": mount_point,
            "fs_type": fs_type,
            "options": fields[5].split(","),
            "size_bytes": size,
            "free_bytes": free,
        })
    return result


# ── Accounts ──────────────────────────────────────────────────────────────────

def _int(value: str) -> int:
    return int(value) if value.strip().lstrip("-").isdigit() else -1


def _colon_file(path: str, width: int) -> list[list[str]] | None:
    text = read_text(path, limit=None)
    if text is None:
        return None
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split(":")
        rows.append(fields + [""] * (width - len(fields)))
    return rows


@cached
def users() -> list[dict] | None:
    """Local accounts from /etc/passwd."""
    rows = _colon_file("/etc/passwd", 7)
    if rows is None:
        return None
    return [{"name": r[0], "uid": _int(r[2]), "gid": _int(r[3]), "gecos": r[4],
             "home": r[5], "shell": r[6]} for r in rows]


@cached
def groups() -> list[dict] | None:
    """Local groups from /etc/group."""
    rows = _colon_file("/etc/group", 4)
    if rows is None:
        return None
    return [{"name": r[0], "gid": _int(r[2]), "members": [m for m in r[3].split(",") if m]}
            for r in rows]


_HASH_PREFIXES = [("$y$", "yescrypt"), ("$gy$", "yescrypt"), ("$6$", "sha512"),
                  ("$5$", "sha256"), ("$2a$", "bcrypt"), ("$2b$", "bcrypt"),
                  ("$2y$", "bcrypt"), ("$1$", "md5")]


def _hash_algorithm(field: str) -> str:
    value = field.lstrip("!*")
    for prefix, name in _HASH_PREFIXES:
        if value.startswith(prefix):
            return name
    if re.fullmatch(r"[./0-9A-Za-z]{13}", value):
        return "des"
    return ""


@cached
def shadow() -> list[dict] | None:
    """Password state and aging from /etc/shadow; never the hash itself."""
    rows = _colon_file("/etc/shadow", 9)
    if rows is None:
        return None
    result = []
    for r in rows:
        password = r[1]
        if password == "":
            state = "empty"
        elif password.startswith(("!", "*")):
            state = "locked"
        else:
            state = "hashed"
        result.append({
            "name": r[0], "password_state": state, "hash_algorithm": _hash_algorithm(password),
            "last_change": _int(r[2]), "min_days": _int(r[3]), "max_days": _int(r[4]),
            "warn_days": _int(r[5]), "inactive_days": _int(r[6]), "expire_date": _int(r[7]),
        })
    return result


# ── Security modules ──────────────────────────────────────────────────────────

@cached
def selinux() -> dict:
    """SELinux mode, policy and booleans; mode "disabled" if SELinux is off."""
    enforce = read_text("/sys/fs/selinux/enforce")
    if enforce is None:
        return {"mode": "disabled", "policy": "", "booleans": {}}

    policy = ""
    for line in (read_text("/etc/selinux/config") or "").splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "SELINUXTYPE":
            policy = value.strip().strip('"')

    booleans = {}
    try:
        for path in sorted(Path("/sys/fs/selinux/booleans").iterdir()):
            value = (read_text(str(path)) or "").split()
            if value:
                booleans[path.name] = value[0] == "1"
    except OSError:
        booleans = None

    return {"mode": "enforcing" if enforce.strip() == "1" else "permissive",
            "policy": policy, "booleans": booleans}


@cached
def apparmor() -> dict:
    """Whether AppArmor is enabled, and the mode of each loaded profile."""
    enabled = (read_text("/sys/module/apparmor/parameters/enabled") or "").strip() == "Y"
    profiles = None
    text = read_text("/sys/kernel/security/apparmor/profiles", limit=None)
    if text is not None:
        profiles = {}
        for line in text.splitlines():
            match = re.match(r"^(.*) \(([a-z]+)\)$", line.strip())
            if match:
                profiles[match.group(1)] = match.group(2)
    return {"enabled": enabled, "profiles": profiles}

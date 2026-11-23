"""The installed-package databases of dpkg, rpm, apk and pacman."""

import logging
import os
import re
from pathlib import Path
from typing import NamedTuple

from .. import releases
from ..logging_setup import LOGGER_NAME
from .base import cached, read_text, run_command, run_process

log = logging.getLogger(LOGGER_NAME)

MANAGERS = ("dpkg", "rpm", "apk", "pacman")
APK_DB = "/lib/apk/db/installed"
PACMAN_LOCAL = "/var/lib/pacman/local"

_RPM_SIGNATURE = (
    "%|RSAHEADER?{%{RSAHEADER:pgpsig}}:{%|DSAHEADER?{%{DSAHEADER:pgpsig}}:"
    "{%|SIGGPG?{%{SIGGPG:pgpsig}}:{%|SIGPGP?{%{SIGPGP:pgpsig}}:{(none)}|}|}|}|"
)
_RPM_QUERYFORMAT = (
    "%{NAME}\\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\t"
    + _RPM_SIGNATURE + "\\n"
)


class InstalledPackage(NamedTuple):
    """One installed binary package as the package manager reports it."""
    name: str
    version: str           # as the range versions are written, including the epoch
    arch: str
    source: str            # source package name, "" if unknown
    manager: str
    signature: str = ""    # rpm only: the signing key ID (16 hex digits), "" if unsigned

    def label(self) -> str:
        return f"{self.name} {self.version} ({self.arch})"


class Inventory(NamedTuple):
    """The installed packages and the package manager they come from."""
    manager: str
    packages: list[InstalledPackage]


# ── Reading the databases ─────────────────────────────────────────────────────

def _read_dpkg() -> list[InstalledPackage] | None:
    out = run_command(
        "dpkg-query", "-W", "-f",
        "${db:Status-Status}\\t${Package}\\t${Version}\\t${Architecture}\\t${Source}\\n",
    )
    if out is None:
        return None
    packages = []
    for line in out.splitlines():
        fields = line.split("\t")
        # Removed packages stay in the database with their config files and no
        # version; only "installed" ones carry the vulnerable code.
        if len(fields) == 5 and fields[0] == "installed" and fields[2]:
            source = fields[4].split(" ", 1)[0] or fields[1]
            packages.append(InstalledPackage(fields[1], fields[2], fields[3], source, "dpkg"))
    return packages


def rpm_key_id(signature: str) -> str:
    """The key ID from an rpm pgpsig string such as
    'RSA/SHA256, Tue Apr 16 2024, Key ID 199e2f91fd431d51'."""
    match = re.search(r"Key (?:ID|fingerprint:?)\s*([0-9A-Fa-f]+)", signature)
    return match.group(1)[-16:].lower() if match else ""


def _read_rpm() -> list[InstalledPackage] | None:
    out = run_command("rpm", "-qa", "--qf", _RPM_QUERYFORMAT)
    if out is None:
        return None
    packages = []
    for line in out.splitlines():
        fields = line.split("\t")
        if len(fields) != 5 or not fields[0] or fields[0] == "gpg-pubkey":
            continue
        # 'openssh-8.7p1-38.el9.src.rpm' -> 'openssh'
        source = fields[3].rsplit("-", 2)[0] if fields[3].endswith(".src.rpm") else ""
        packages.append(InstalledPackage(fields[0], fields[1], fields[2], source, "rpm",
                                         rpm_key_id(fields[4])))
    return packages


@cached
def _apk_database() -> list[tuple[InstalledPackage, list[str]]] | None:
    text = read_text(APK_DB, limit=None)
    if text is None:
        return None
    entries = []
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        files: list[str] = []
        directory = ""
        for line in block.splitlines():
            key, sep, value = line.partition(":")
            if not sep:
                continue
            if key == "F":
                directory = value
            elif key == "R":
                files.append(f"/{directory}/{value}" if directory else f"/{value}")
            else:
                fields.setdefault(key, value)
        if "P" in fields and "V" in fields:
            package = InstalledPackage(fields["P"], fields["V"], fields.get("A", ""),
                                       fields.get("o", fields["P"]), "apk")
            entries.append((package, files))
    return entries


def _read_apk() -> list[InstalledPackage] | None:
    database = _apk_database()
    return None if database is None else [package for package, _ in database]


def _pacman_desc(directory: Path) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current = None
    for line in (read_text(str(directory / "desc"), limit=None) or "").splitlines():
        if line.startswith("%") and line.endswith("%"):
            current = sections.setdefault(line.strip("%"), [])
        elif line and current is not None:
            current.append(line)
    return sections


def _read_pacman() -> list[InstalledPackage] | None:
    try:
        directories = sorted(p for p in Path(PACMAN_LOCAL).iterdir() if p.is_dir())
    except OSError:
        return None
    packages = []
    for directory in directories:
        desc = _pacman_desc(directory)
        if desc.get("NAME") and desc.get("VERSION"):
            name = desc["NAME"][0]
            packages.append(InstalledPackage(
                name, desc["VERSION"][0], (desc.get("ARCH") or [""])[0],
                (desc.get("BASE") or [name])[0], "pacman",
            ))
    return packages


_READERS = {"dpkg": _read_dpkg, "rpm": _read_rpm, "apk": _read_apk, "pacman": _read_pacman}


def _manager_present(manager: str) -> bool:
    return {
        "dpkg": lambda: Path("/var/lib/dpkg/status").exists(),
        "rpm": lambda: any(Path(p).exists() for p in ("/var/lib/rpm", "/usr/lib/sysimage/rpm")),
        "apk": lambda: Path(APK_DB).exists(),
        "pacman": lambda: Path(PACMAN_LOCAL).is_dir(),
    }[manager]()


@cached
def inventory() -> Inventory | None:
    """The installed packages of the package manager bound to the host's
    distribution, falling back to the first one present."""
    preferred = releases.PACKAGE_MANAGERS.get(releases.host_release().dist_id or "")
    order = ([preferred] if preferred else []) + [m for m in MANAGERS if m != preferred]
    for manager in order:
        if not _manager_present(manager):
            continue
        packages = _READERS[manager]()
        if packages is not None:
            log.info("read %d installed package(s) from %s", len(packages), manager)
            return Inventory(manager, packages)
    log.warning("no package manager available (tried %s)", ", ".join(order))
    return None


# ── Files, owners, verification ───────────────────────────────────────────────

def _strip_epoch(version: str) -> str:
    head, sep, tail = version.partition(":")
    return tail if sep and head.isdigit() else version


@cached
def package_files(package: InstalledPackage) -> list[str] | None:
    """The files a package installed, or None if its file list is unavailable."""
    if package.manager == "dpkg":
        for name in (f"{package.name}:{package.arch}", package.name):
            text = read_text(f"/var/lib/dpkg/info/{name}.list", limit=None)
            if text is not None:
                return [line for line in text.splitlines() if line]
        return None
    if package.manager == "rpm":
        nevra = f"{package.name}-{_strip_epoch(package.version)}.{package.arch}"
        out = run_command("rpm", "-ql", nevra)
        if out is None:
            return None
        return [line for line in out.splitlines() if line.startswith("/")]
    if package.manager == "apk":
        for candidate, files in _apk_database() or []:
            if candidate == package:
                return files
        return None
    if package.manager == "pacman":
        text = read_text(f"{PACMAN_LOCAL}/{package.name}-{package.version}/files", limit=None)
        if text is None:
            return None
        files, in_files = [], False
        for line in text.splitlines():
            if line.startswith("%"):
                in_files = line == "%FILES%"
            elif in_files and line:
                files.append("/" + line)
        return files
    return None


def package_owner(path: str) -> list[str] | None:
    """Names of the packages that own a path: [] if none does or the path does
    not exist, None if the package database cannot be queried.
    """
    current = inventory()
    if current is None:
        return None
    if not os.path.lexists(path):
        return []
    manager = current.manager
    if manager == "dpkg":
        proc = run_process("dpkg-query", "-S", path)
        if proc is None:
            return None
        owners = set()
        for line in proc.stdout.splitlines():
            names, sep, owned = line.rpartition(": ")
            if sep and owned == path:
                owners.update(n.strip().split(":")[0] for n in names.split(","))
        return sorted(owners)
    if manager == "rpm":
        proc = run_process("rpm", "-qf", "--qf", "%{NAME}\\n", path)
    elif manager == "apk":
        proc = run_process("apk", "info", "--who-owns", path)
        if proc is None:
            return None
        return sorted({m.group(1).rsplit("-", 2)[0]
                       for m in re.finditer(r"is owned by (\S+)", proc.stdout)})
    else:
        proc = run_process("pacman", "-Qqo", path)
    if proc is None:
        return None
    if proc.returncode != 0:
        return []  # not owned by any package
    return sorted({line.strip() for line in proc.stdout.splitlines() if line.strip()})


# rpm -V / dpkg --verify attribute columns.
_VERIFY_COLUMNS = {0: "size_changed", 1: "mode_changed", 2: "digest_changed",
                   5: "owner_changed", 6: "owner_changed", 7: "mtime_changed"}
_VERIFY_LINE_RE = re.compile(r"^(missing|[.?SM5DLUGTP]{8,9})\s+([cdglr]?)\s*(/.*)$")
_PACMAN_CHECKS = {"Size mismatch": "size_changed", "Permissions mismatch": "mode_changed",
                  "UID mismatch": "owner_changed", "GID mismatch": "owner_changed",
                  "Modification time mismatch": "mtime_changed",
                  "checksum mismatch": "digest_changed",
                  "No such file or directory": "missing"}
_VERIFY_FIELDS = ("missing", "digest_changed", "size_changed", "mode_changed",
                  "owner_changed", "mtime_changed")


def _verify_rpm_style(output: str, supported: set[str]) -> list[dict]:
    results = []
    for line in output.splitlines():
        match = _VERIFY_LINE_RE.match(line.strip())
        if match is None:
            continue
        flags, kind, path = match.groups()
        entry = {"path": path, "config": kind == "c"}
        if flags == "missing":
            entry.update(dict.fromkeys(_VERIFY_FIELDS, None), missing=True)
        else:
            entry["missing"] = False
            for field in _VERIFY_FIELDS[1:]:
                entry[field] = False if field in supported else None
            for column, field in _VERIFY_COLUMNS.items():
                if field not in supported:
                    continue
                if flags[column] == "?":
                    entry[field] = None
                elif flags[column] != ".":
                    entry[field] = True
        results.append(entry)
    return results


def package_verify(name: str) -> list[dict] | None:
    """Files of an installed package that differ from the package database
    (rpm -V, dpkg --verify, pacman -Qkk). None if the package is not
    installed or the manager cannot verify (apk).
    """
    current = inventory()
    if current is None or not any(p.name == name for p in current.packages):
        return None
    if current.manager == "rpm":
        proc = run_process("rpm", "-V", name)
        if proc is None:
            return None
        return _verify_rpm_style(proc.stdout, set(_VERIFY_FIELDS))
    if current.manager == "dpkg":
        proc = run_process("dpkg", "--verify", name)
        if proc is None:
            return None
        return _verify_rpm_style(proc.stdout, {"missing", "digest_changed"})
    if current.manager == "pacman":
        proc = run_process("pacman", "-Qkk", name)
        if proc is None:
            return None
        by_path: dict[str, dict] = {}
        for line in (proc.stdout + proc.stderr).splitlines():
            match = re.match(rf"^warning: {re.escape(name)}: (/.*?) \((.*)\)$", line.strip())
            if match is None:
                continue
            path, message = match.groups()
            entry = by_path.setdefault(path, {"path": path, "config": None,
                                              **dict.fromkeys(_VERIFY_FIELDS, False)})
            for text, field in _PACMAN_CHECKS.items():
                if text in message:
                    entry[field] = True
        return list(by_path.values())
    return None  # apk cannot verify a single package

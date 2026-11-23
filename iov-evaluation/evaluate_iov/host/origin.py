"""Deciding whether an installed package is a build of the host's distribution,
for range sets with "origin": "distribution".

Each check answers (verified, explanation). verified is True for a distribution
build, False for a build from elsewhere, and None when the origin cannot be
determined; only True lets a range set apply.

  rpm     the key that signed the package header is a distribution key: the key
          that signed the distribution's release package, or a key shipped in
          /etc/pki/rpm-gpg or /usr/lib/rpm/gnupg/keys by a package signed with it
  dpkg    APT sources whose Release file names one of the distribution's origins
  apk     repositories `apk policy` lists that match the distribution's URLs
  pacman  the distribution's sync databases

dpkg, apk and pacman record no signature for an installed package, so the check
compares the installed version with what the configured sources offer. It is a
distribution build if a distribution source offers exactly that version, or if
no other source offers it and it sorts at or below the newest distribution
build: distribution archives drop superseded versions, so a host that lags
behind its updates would otherwise never verify. A build that another source
offers, or that is newer than anything the distribution ships, is not verified.
"""

import base64
import bz2
import glob
import gzip
import hashlib
import io
import logging
import lzma
import os
import re
import tarfile
from functools import cmp_to_key
from pathlib import Path

from .. import releases
from ..logging_setup import LOGGER_NAME
from ..versions import COMPARATORS
from .base import cached, read_text, run_command, run_process
from .pkgdb import InstalledPackage, inventory, package_files, package_owner

log = logging.getLogger(LOGGER_NAME)

RPM_KEY_DIRS = ("/etc/pki/rpm-gpg", "/usr/lib/rpm/gnupg/keys")
APT_LISTS = "/var/lib/apt/lists"
APT_HELPER = "/usr/lib/apt/apt-helper"
PACMAN_SYNC = "/var/lib/pacman/sync"

APT_ORIGINS = {
    "debian": {"Debian", "Debian Backports"},
    "ubuntu": {"Ubuntu", "UbuntuESM", "UbuntuESMApps", "UbuntuFIPS", "UbuntuFIPSUpdates"},
    "raspbian": {"Raspbian", "Raspberry Pi Foundation"},
    "kali": {"Kali"},
    "devuan": {"Devuan"},
    "linuxmint": {"linuxmint", "Ubuntu"},
    "pop": {"Ubuntu"},
}
APK_REPOSITORIES = {
    "alpine": re.compile(r"/alpine/(v[0-9]+\.[0-9]+|edge)/(main|community)/?$"),
    "wolfi": re.compile(r"packages\.wolfi\.dev/os/?$"),
    "postmarketos": re.compile(
        r"(/alpine/(v[0-9]+\.[0-9]+|edge)/(main|community)|/postmarketos/[^/]+)/?$"),
}
PACMAN_REPOSITORIES = {
    "arch": {"core", "extra", "multilib", "core-testing", "extra-testing", "multilib-testing"},
    "archarm": {"core", "extra", "alarm", "aur"},
    "manjaro": {"core", "extra", "multilib"},
    "endeavouros": {"core", "extra", "multilib", "endeavouros"},
}


def is_distribution_build(package: InstalledPackage) -> tuple[bool | None, str]:
    """Whether the package was built by the host's distribution:
    (verified, explanation), see the module docstring.
    """
    dist_id = releases.host_release().dist_id or ""
    check = {"rpm": _check_rpm, "dpkg": _check_dpkg, "apk": _check_apk,
             "pacman": _check_pacman}.get(package.manager)
    if check is None:
        return None, f"origin checks are not supported for {package.manager}"
    return check(package, dist_id)


# ── rpm ───────────────────────────────────────────────────────────────────────

def _openpgp_key_ids(armored: str) -> set[str]:
    """Key IDs of every primary key and subkey in ASCII-armored OpenPGP blocks."""
    ids = set()
    for block in re.findall(
        r"-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----",
        armored, re.S,
    ):
        body = block.strip().split("\n\n", 1)[-1]
        lines = [line for line in body.splitlines() if line and not line.startswith("=")]
        try:
            data = base64.b64decode("".join(lines))
        except ValueError:
            continue
        ids |= _key_ids_from_packets(data)
    return ids


def _key_ids_from_packets(data: bytes) -> set[str]:
    ids = set()
    pos = 0
    while pos < len(data):
        header = data[pos]
        if not header & 0x80:
            break
        if header & 0x40:                       # new packet format
            tag = header & 0x3F
            first = data[pos + 1]
            if first < 192:
                length, pos = first, pos + 2
            elif first < 224:
                length, pos = ((first - 192) << 8) + data[pos + 2] + 192, pos + 3
            elif first == 255:
                length, pos = int.from_bytes(data[pos + 2:pos + 6], "big"), pos + 6
            else:
                break                           # partial lengths never occur in keys
        else:                                   # old packet format
            tag = (header >> 2) & 0x0F
            size = {0: 1, 1: 2, 2: 4}.get(header & 0x03)
            if size is None:
                break
            length = int.from_bytes(data[pos + 1:pos + 1 + size], "big")
            pos += 1 + size
        body = data[pos:pos + length]
        pos += length
        if tag in (6, 14) and body:             # public key, public subkey
            version = body[0]
            if version == 4:
                fingerprint = hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).digest()
                ids.add(fingerprint[-8:].hex())
            elif version in (5, 6):
                prefix = b"\x9a" if version == 5 else b"\x9b"
                fingerprint = hashlib.sha256(prefix + len(body).to_bytes(4, "big") + body).digest()
                ids.add(fingerprint[:8].hex())
    return ids


@cached
def _trusted_rpm_keys() -> frozenset[str]:
    current = inventory()
    if current is None:
        return frozenset()
    by_name: dict[str, list[InstalledPackage]] = {}
    for package in current.packages:
        by_name.setdefault(package.name, []).append(package)

    def signers(names: list[str] | None) -> set[str]:
        return {p.signature for n in names or [] for p in by_name.get(n, []) if p.signature}

    # The release package is always a distribution build.
    release_owners = set()
    for path in ("/etc/os-release", os.path.realpath("/etc/os-release")):
        release_owners.update(package_owner(path) or [])
    trusted = signers(sorted(release_owners))

    # Key files shipped by packages that the distribution signed are
    # distribution keys. One batched query finds the owners of every key file.
    key_files = [path for directory in RPM_KEY_DIRS for path in sorted(glob.glob(f"{directory}/*"))]
    proc = run_process("rpm", "-qf", "--qf", "%{NAME}\\n", "--", *key_files) if key_files else None
    owners = set()
    if proc is not None:
        owners = {line.strip() for line in proc.stdout.splitlines()
                  if line.strip() and not line.startswith("file ")}
    for name in sorted(owners):
        for package in by_name.get(name, []):
            if package.signature not in trusted:
                continue
            for path in package_files(package) or []:
                if path.startswith(tuple(f"{d}/" for d in RPM_KEY_DIRS)):
                    trusted |= _openpgp_key_ids(read_text(path, limit=None) or "")
    log.debug("trusted rpm signing keys: %s", sorted(trusted))
    return frozenset(trusted)


def _check_rpm(package: InstalledPackage, dist_id: str) -> tuple[bool | None, str]:
    if not package.signature:
        return None, "it is unsigned"
    trusted = _trusted_rpm_keys()
    if not trusted:
        return None, "the distribution's signing keys could not be determined"
    if package.signature in trusted:
        return True, f"signed with distribution key {package.signature}"
    return False, f"it is signed with key {package.signature}, which is not a {dist_id} key"


# ── Offers: dpkg, apk, pacman ─────────────────────────────────────────────────

# (version, offered by a distribution source)
Offer = tuple[str, bool]


def _decide(package: InstalledPackage, offers: list[Offer] | None, dist_id: str,
            unavailable: str) -> tuple[bool | None, str]:
    if offers is None:
        return None, unavailable
    trusted = [version for version, ours in offers if ours]
    if package.version in trusted:
        return True, "offered by a distribution source"
    if any(version == package.version for version, ours in offers if not ours):
        return False, f"version {package.version} comes from a non-{dist_id} source"
    if not trusted:
        return None, f"no {dist_id} source offers {package.name}"
    compare = COMPARATORS[package.manager]
    try:
        newest = max(trusted, key=cmp_to_key(compare))
        older = compare(package.version, newest) <= 0
    except ValueError:
        return None, f"version {package.version} cannot be compared with the {dist_id} builds"
    if older:
        return True, f"an older {dist_id} build ({dist_id} now ships {newest})"
    return None, (f"version {package.version} is newer than every {dist_id} build ({newest}) "
                  "and no configured source offers it")


# ── dpkg ──────────────────────────────────────────────────────────────────────

def _open_list(path: str):
    suffix = Path(path).suffix
    opener = {".gz": gzip.open, ".xz": lzma.open, ".bz2": bz2.open}.get(suffix)
    if opener is not None:
        return opener(path, "rt", errors="replace")
    if suffix in (".lz4", ".zst"):
        # Python cannot decompress these; apt's own helper reads anything apt can.
        text = run_command(APT_HELPER, "cat-file", path)
        return None if text is None else io.StringIO(text)
    return open(path, errors="replace")


def _stanzas(handle):
    fields: dict[str, str] = {}
    for line in handle:
        line = line.rstrip("\n")
        if not line:
            if fields:
                yield fields
            fields = {}
        elif not line[0].isspace():
            key, _, value = line.partition(":")
            if key in ("Package", "Version", "Architecture"):
                fields[key] = value.strip()
    if fields:
        yield fields


@cached
def _apt_offers(dist_id: str) -> dict[tuple[str, str], list[Offer]] | None:
    """(package, architecture) -> every version the APT sources offer."""
    origins = APT_ORIGINS.get(dist_id)
    if origins is None:
        return None
    try:
        names = os.listdir(APT_LISTS)
    except OSError:
        return None

    # Release file prefix -> Origin
    prefixes: dict[str, str] = {}
    for name in names:
        if name.endswith(("_InRelease", "_Release")):
            prefix = name.rsplit("_", 1)[0] + "_"
            for line in (read_text(f"{APT_LISTS}/{name}", limit=None) or "").splitlines():
                if line.startswith("Origin:"):
                    prefixes[prefix] = line.split(":", 1)[1].strip()
                    break

    offers: dict[tuple[str, str], list[Offer]] = {}
    for name in names:
        if "_Packages" not in name:
            continue
        matching = [p for p in prefixes if name.startswith(p)]
        ours = bool(matching) and prefixes[max(matching, key=len)] in origins
        handle = _open_list(f"{APT_LISTS}/{name}")
        if handle is None:
            continue
        with handle:
            for fields in _stanzas(handle):
                if "Package" in fields and "Version" in fields:
                    key = (fields["Package"], fields.get("Architecture", ""))
                    offers.setdefault(key, []).append((fields["Version"], ours))
    return offers


def _check_dpkg(package: InstalledPackage, dist_id: str) -> tuple[bool | None, str]:
    offers = _apt_offers(dist_id)
    matching = None
    if offers is not None:
        matching = (offers.get((package.name, package.arch), [])
                    + offers.get((package.name, "all"), []))
    return _decide(package, matching, dist_id, f"the APT sources of {dist_id} could not be read")


# ── apk ───────────────────────────────────────────────────────────────────────

def _apk_offers(package: InstalledPackage, pattern: re.Pattern) -> list[Offer] | None:
    out = run_command("apk", "policy", package.name)
    if out is None:
        return None
    offers, version = [], None
    for line in out.splitlines():
        stripped = line.strip()
        if line.startswith("  ") and not line.startswith("    ") and stripped.endswith(":"):
            version = stripped[:-1]
        elif version is not None and line.startswith("    ") and "://" in stripped:
            offers.append((version, bool(pattern.search(stripped))))
    return offers


def _check_apk(package: InstalledPackage, dist_id: str) -> tuple[bool | None, str]:
    pattern = APK_REPOSITORIES.get(dist_id)
    if pattern is None:
        return None, f"no repository list is known for {dist_id}"
    return _decide(package, _apk_offers(package, pattern), dist_id, "`apk policy` failed")


# ── pacman ────────────────────────────────────────────────────────────────────

@cached
def _pacman_offers(dist_id: str) -> dict[str, list[Offer]] | None:
    repositories = PACMAN_REPOSITORIES.get(dist_id)
    if repositories is None:
        return None
    offers: dict[str, list[Offer]] = {}
    for path in sorted(glob.glob(f"{PACMAN_SYNC}/*.db")):
        ours = Path(path).stem in repositories
        try:
            with tarfile.open(path, "r:*") as archive:
                for member in archive:
                    if not member.name.endswith("/desc"):
                        continue
                    handle = archive.extractfile(member)
                    text = handle.read().decode(errors="replace") if handle else ""
                    sections = dict(re.findall(r"%([A-Z]+)%\n([^\n]*)", text))
                    if "NAME" in sections and "VERSION" in sections:
                        offers.setdefault(sections["NAME"], []).append((sections["VERSION"], ours))
        except (OSError, tarfile.TarError) as exc:
            log.debug("cannot read %s: %s", path, exc)
    return offers


def _check_pacman(package: InstalledPackage, dist_id: str) -> tuple[bool | None, str]:
    offers = _pacman_offers(dist_id)
    return _decide(package, None if offers is None else offers.get(package.name, []), dist_id,
                   f"no repository list is known for {dist_id}")

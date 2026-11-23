"""Distribution release identification and matching.

The host's release is the unquoted ID and VERSION_ID of /etc/os-release. An IoV
range set lists releases in one of three forms:

    ID              every release of the distribution        (specificity 0)
    ID:             only hosts without a VERSION_ID          (specificity 1)
    ID:VERSIONS     a comma-separated list of versions       (specificity 1 + dots)

A token 'A-B' inside VERSIONS whose sides are digits and dots is a numeric range
and expands to every version in between.
"""

import logging
import re
from typing import NamedTuple

from .host.base import cached, read_text
from .logging_setup import LOGGER_NAME

log = logging.getLogger(LOGGER_NAME)

OS_RELEASE_PATHS = ("/etc/os-release", "/usr/lib/os-release")

# The package manager whose version strings and comparison algorithm the range
# sets of each distribution use. IDs not listed fall back to the host's native
# package manager.
PACKAGE_MANAGERS = {
    **dict.fromkeys(
        ("debian", "ubuntu", "linuxmint", "pop", "kali", "raspbian", "devuan"), "dpkg"),
    **dict.fromkeys(
        ("rhel", "centos", "fedora", "rocky", "almalinux", "ol", "amzn", "sles", "sled",
         "sles_sap", "opensuse-leap", "opensuse-tumbleweed", "azurelinux", "mariner",
         "photon"), "rpm"),
    **dict.fromkeys(("alpine", "wolfi", "postmarketos"), "apk"),
    **dict.fromkeys(("arch", "archarm", "manjaro", "endeavouros"), "pacman"),
}


class Release(NamedTuple):
    """The host's distribution release, as in /etc/os-release."""
    dist_id: str | None
    version_id: str | None        # None if VERSION_ID is unset or empty

    def __str__(self) -> str:
        if self.dist_id is None:
            return "unknown"
        return f"{self.dist_id}:{self.version_id or ''}"


class ReleaseEntry(NamedTuple):
    """One expanded release: the distribution ID, the version it pins (None for
    the bare 'ID' form, "" for the no-VERSION_ID form 'ID:'), and its
    specificity."""
    dist_id: str
    version: str | None
    specificity: int

    def __str__(self) -> str:
        if self.version is None:
            return self.dist_id
        return f"{self.dist_id}:{self.version}"


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse_os_release(text: str) -> dict[str, str]:
    """Parse os-release(5) text into unquoted fields."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if sep:
            fields[key.strip()] = _unquote(value)
    return fields


@cached
def os_release() -> dict[str, str] | None:
    """The fields of /etc/os-release (or /usr/lib/os-release), unquoted."""
    for path in OS_RELEASE_PATHS:
        text = read_text(path)
        if text is not None:
            return parse_os_release(text)
    log.warning("could not read os-release; the host's release is unknown")
    return None


def host_release(text: str | None = None) -> Release:
    """Return the host's (ID, VERSION_ID). VERSION_ID is None if unset."""
    fields = parse_os_release(text) if text is not None else os_release()
    if fields is None:
        return Release(None, None)
    dist_id = fields.get("ID") or None
    version_id = fields.get("VERSION_ID")
    if version_id is not None and not version_id.strip():
        version_id = None
    log.debug("host release: ID=%r VERSION_ID=%r", dist_id, version_id)
    return Release(dist_id, version_id)


def _expand_numeric_range(token: str) -> list[str] | None:
    """Expand '8.7-8.10' to ['8.7', '8.8', '8.9', '8.10'], or None if the token
    is not a well-formed numeric range."""
    low, sep, high = token.partition("-")
    if not sep or not re.fullmatch(r"[0-9.]+", low) or not re.fullmatch(r"[0-9.]+", high):
        return None

    low_parts = low.split(".")
    high_parts = high.split(".")
    if len(low_parts) != len(high_parts) or low_parts[:-1] != high_parts[:-1]:
        log.warning("malformed numeric release range %r; ignoring it", token)
        return None
    try:
        start, stop = int(low_parts[-1]), int(high_parts[-1])
    except ValueError:
        return None
    if start > stop:
        log.warning("descending numeric release range %r; ignoring it", token)
        return None

    prefix = low_parts[:-1]
    return [".".join(prefix + [str(n)]) for n in range(start, stop + 1)]


def parse_release_spec(spec: str) -> list[ReleaseEntry]:
    """Expand one release string into its (id, version, specificity) entries."""
    dist_id, sep, versions = spec.partition(":")
    dist_id = dist_id.strip()
    if not dist_id:
        log.warning("release spec %r has no distribution ID; ignoring it", spec)
        return []

    if not sep:
        return [ReleaseEntry(dist_id, None, 0)]
    if not versions.strip():
        return [ReleaseEntry(dist_id, "", 1)]

    entries: list[ReleaseEntry] = []
    for token in versions.split(","):
        token = token.strip()
        if not token:
            continue
        expanded = _expand_numeric_range(token) or [token]
        entries.extend(ReleaseEntry(dist_id, v, 1 + v.count(".")) for v in expanded)
    return entries


def entry_matches(entry: ReleaseEntry, host: Release) -> bool:
    """Does one expanded release entry match the host?"""
    if host.dist_id is None or entry.dist_id != host.dist_id:
        return False
    if entry.version is None:          # bare 'ID': every release of the distribution
        return True
    if entry.version == "":            # 'ID:': only hosts without a VERSION_ID
        return host.version_id is None
    if host.version_id is None:
        return False
    # Version matching respects dot boundaries, so 'rhel:9.1' does not match 9.10.
    return host.version_id == entry.version or host.version_id.startswith(entry.version + ".")


def best_match(specs: list[str], host: Release) -> ReleaseEntry | None:
    """Return the most specific release among the specs that matches the host,
    or None if none of them does."""
    best: ReleaseEntry | None = None
    for spec in specs:
        for entry in parse_release_spec(spec):
            if not entry_matches(entry, host):
                continue
            if best is None or entry.specificity > best.specificity:
                best = entry
    return best

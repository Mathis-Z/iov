"""Installed-package matching against an IoV's 'packages' entries."""

import logging
import re
from collections.abc import Callable
from typing import NamedTuple

from . import releases
from .host import kernel, origin, pkgdb
from .host.pkgdb import InstalledPackage
from .logging_setup import LOGGER_NAME
from .releases import Release

log = logging.getLogger(LOGGER_NAME)

AFFECTED   = "AFFECTED"
UNAFFECTED = "UNAFFECTED"
UNKNOWN    = "UNKNOWN"

_CONDITION_RE = re.compile(r"^\s*(<=|>=|<|>)\s*([A-Za-z0-9._+~:^_-]+)\s*$")
_KERNEL_PATH_RE = re.compile(r"^(/boot/vmlinuz-|/(usr/)?lib/modules/[^/]+/)")

Compare = Callable[[str, str], int]


class PackageResult(NamedTuple):
    """The classification of one installed package under one IoV key."""
    key: str
    name: str | None          # None for the per-key "no running kernel" UNKNOWN
    version: str | None
    arch: str | None
    release: str | None       # the chosen release, e.g. "debian:12"; None if none matched
    state: str
    detail: str               # why, in words, for the result's reason

    def as_dict(self) -> dict:
        return {"key": self.key, "name": self.name, "version": self.version,
                "arch": self.arch, "release": self.release, "state": self.state}


# ── Relevant packages ─────────────────────────────────────────────────────────

def _compile_key(key: str) -> re.Pattern | None:
    """Compile an anchored regex key, or return None for a plain package name."""
    if not (key.startswith("^") and key.endswith("$")):
        return None
    try:
        return re.compile(key)
    except re.error as exc:
        log.warning("package key %r is not a valid regex: %s", key, exc)
        return None


def packages_by_key(keys: list[str],
                    installed: list[InstalledPackage]) -> dict[str, list[InstalledPackage]]:
    """Group the installed packages under the IoV keys they are evaluated for.

    A package is evaluated under the key equal to its name; if no key equals its
    name, it is evaluated under every regex key it matches.
    """
    exact = {key for key in keys if _compile_key(key) is None}
    regexes = [(key, pattern) for key in keys if (pattern := _compile_key(key)) is not None]

    grouped: dict[str, list[InstalledPackage]] = {key: [] for key in keys}
    for package in installed:
        if package.name in exact:
            grouped[package.name].append(package)
            continue
        for key, pattern in regexes:
            if pattern.search(package.name):
                grouped[key].append(package)
    return {key: found for key, found in grouped.items() if found}


def kernel_image_state(package: InstalledPackage, release: str) -> str | None:
    """Whether a package ships the kernel with the given release.

    Returns "running" if it owns /boot/vmlinuz-<release> or a file under
    /lib/modules/<release>/, "other" if it ships a different kernel, and None
    if it ships no kernel image or its file list is unavailable.
    """
    files = pkgdb.package_files(package)
    if not files:
        return None
    kernel_files = [f for f in files if _KERNEL_PATH_RE.match(f)]
    if not kernel_files:
        return None
    running_prefixes = (f"/boot/vmlinuz-{release}", f"/lib/modules/{release}/",
                        f"/usr/lib/modules/{release}/")
    if any(f == running_prefixes[0] or f.startswith(running_prefixes[1:]) for f in kernel_files):
        return "running"
    return "other"


def relevant_packages(key: str,
                      found: list[InstalledPackage]) -> tuple[list[InstalledPackage], bool]:
    """Drop kernel images other than the running kernel's.

    Returns the relevant packages and whether kernel images were installed under
    the key without any of them belonging to the running kernel.
    """
    release = kernel.kernel_release()
    relevant, other_kernels, running_kernels = [], [], []
    for package in found:
        state = kernel_image_state(package, release)
        if state == "other":
            other_kernels.append(package)
        else:
            relevant.append(package)
            if state == "running":
                running_kernels.append(package)
    if other_kernels:
        log.info("key %r: ignoring kernel images that are not running: %s",
                 key, [p.label() for p in other_kernels])
    return relevant, bool(other_kernels) and not running_kernels


# ── Ranges ────────────────────────────────────────────────────────────────────

def parse_range(text: str) -> list[tuple[str, str]] | None:
    """Parse a version range into its conditions, or None if it is malformed.

    The wildcard "*" parses to an empty condition list, which every version
    satisfies.
    """
    if text.strip() == "*":
        return []
    conditions = []
    for part in text.split(","):
        match = _CONDITION_RE.match(part)
        if match is None:
            log.warning("malformed version range condition %r in %r", part, text)
            return None
        conditions.append((match.group(1), match.group(2)))
    return conditions


def range_matches(version: str, conditions: list[tuple[str, str]], compare: Compare) -> bool:
    """Whether the version satisfies every condition of a range.

    Raises ValueError if the comparison algorithm cannot parse a version.
    """
    for operator, bound in conditions:
        result = compare(version, bound)
        if operator == "<" and not result < 0:
            return False
        if operator == "<=" and not result <= 0:
            return False
        if operator == ">" and not result > 0:
            return False
        if operator == ">=" and not result >= 0:
            return False
    return True


def classify_version(version: str, range_set: dict, compare: Compare) -> tuple[str, str]:
    """Classify a version against one range set.

    Returns (state, the range that decided). 'affected' wins over 'unaffected';
    a version in neither range, or a malformed range, is UNKNOWN.
    """
    for field, state in (("affected", AFFECTED), ("unaffected", UNAFFECTED)):
        text = range_set.get(field)
        if text is None:
            continue
        conditions = parse_range(text)
        if conditions is not None and range_matches(version, conditions, compare):
            return state, f"{field}: {text}"
    return UNKNOWN, ""


def choose_range_set(entry: dict, host: Release,
                     arch: str) -> tuple[dict, releases.ReleaseEntry] | None:
    """Pick the range set that applies to a package on this host.

    Among the range sets whose 'arches' admits the package, this is the one
    owning the most specific release that matches the host; on a tie, a range
    set with 'arches' beats one without.
    """
    best = None
    best_rank = None
    for range_set in entry.get("ranges", []):
        arches = range_set.get("arches")
        if arches is not None and arch not in arches:
            continue
        matched = releases.best_match(range_set.get("releases", []), host)
        if matched is None:
            continue
        rank = (matched.specificity, arches is not None)
        if best_rank is None or rank > best_rank:
            best, best_rank = (range_set, matched), rank
    return best


def classify(key: str, package: InstalledPackage, entry: dict, host: Release,
             compare: Compare) -> PackageResult:
    """Classify one installed package under one 'packages' entry as AFFECTED,
    UNAFFECTED or UNKNOWN."""
    def result(release, state, detail):
        return PackageResult(key, package.name, package.version, package.arch,
                             release, state, detail)

    chosen = choose_range_set(entry, host, package.arch)
    if chosen is None:
        return result(None, UNKNOWN, f"{package.label()} has no range set for {host} "
                                     f"and architecture {package.arch}")
    range_set, matched = chosen
    release = str(matched)

    if range_set.get("origin") == "distribution":
        verified, explanation = origin.is_distribution_build(package)
        if verified is not True:
            return result(release, UNKNOWN, f"{package.label()} is not a verifiable "
                                            f"{host.dist_id} build ({explanation})")

    try:
        state, decided_by = classify_version(package.version, range_set, compare)
    except ValueError as exc:
        return result(release, UNKNOWN, f"{package.label()} cannot be compared on {release}: {exc}")
    if state == UNKNOWN:
        return result(release, UNKNOWN, f"{package.label()} matches no range on {release}")
    verb = "is affected" if state == AFFECTED else "is unaffected"
    return result(release, state, f"{package.label()} {verb} on {release} ({decided_by})")

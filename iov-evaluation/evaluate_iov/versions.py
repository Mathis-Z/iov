"""Version comparison.

Ports of the algorithms the package managers use, so that the agent does not
have to shell out to `dpkg --compare-versions`, `rpmdev-vercmp`, `apk version
-t` or `vercmp`:

  * compare_dpkg   -- dpkg's verrevcmp (lib/dpkg/version.c)
  * compare_rpm    -- rpm's rpmvercmp (rpmio/rpmvercmp.c)
  * compare_apk    -- apk-tools' version ordering (src/version.c)
  * compare_pacman -- libalpm's alpm_pkg_vercmp (lib/libalpm/version.c)

plus two schemes for versions no package manager tracks, which scripts can use
through version_compare():

  * compare_semver  -- SemVer 2.0.0 precedence
  * compare_generic -- numeric and alphabetic segments

All return -1, 0 or 1, and raise ValueError for a version the scheme cannot
parse (apk and semver only; the others order every string).
"""

import re


def _split_evr(version: str, revision_sep: str) -> tuple[int, str, str]:
    """Split '[epoch:]version[<sep>release]' into (epoch, version, release)."""
    epoch = 0
    rest = version
    head, sep, tail = version.partition(":")
    if sep and head.isdigit():
        epoch = int(head)
        rest = tail
    upstream, sep, revision = rest.rpartition(revision_sep)
    if not sep:
        upstream, revision = revision, ""
    return epoch, upstream, revision


def _cmp(a, b) -> int:
    return (a > b) - (a < b)


# Version strings come from the host package manager, so restrict the character
# classes to ASCII rather than trusting str.isdigit()/isalpha() with Unicode.
def _isdigit(c: str) -> bool:
    return "0" <= c <= "9"


def _isalpha(c: str) -> bool:
    return "a" <= c <= "z" or "A" <= c <= "Z"


def _isalnum(c: str) -> bool:
    return _isdigit(c) or _isalpha(c)


# ── dpkg ──────────────────────────────────────────────────────────────────────

def _dpkg_order(c: str) -> int:
    """dpkg's character ordering: '~' sorts before the end of the string, which
    sorts before letters, which sort before every other character."""
    if _isdigit(c):
        return 0
    if _isalpha(c):
        return ord(c)
    if c == "~":
        return -1
    if c:
        return ord(c) + 256
    return 0


def _dpkg_verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0

        while (i < len(a) and not _isdigit(a[i])) or (j < len(b) and not _isdigit(b[j])):
            ac = _dpkg_order(a[i] if i < len(a) else "")
            bc = _dpkg_order(b[j] if j < len(b) else "")
            if ac != bc:
                return _cmp(ac, bc)
            i += 1
            j += 1

        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1

        while i < len(a) and _isdigit(a[i]) and j < len(b) and _isdigit(b[j]):
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1

        if i < len(a) and _isdigit(a[i]):
            return 1
        if j < len(b) and _isdigit(b[j]):
            return -1
        if first_diff:
            return _cmp(first_diff, 0)

    return 0


def compare_dpkg(a: str, b: str) -> int:
    """Compare two Debian versions '[epoch:]upstream[-revision]'."""
    epoch_a, upstream_a, revision_a = _split_evr(a, "-")
    epoch_b, upstream_b, revision_b = _split_evr(b, "-")

    if epoch_a != epoch_b:
        return _cmp(epoch_a, epoch_b)
    rc = _dpkg_verrevcmp(upstream_a, upstream_b)
    if rc:
        return rc
    return _dpkg_verrevcmp(revision_a, revision_b)


# ── rpm ───────────────────────────────────────────────────────────────────────

def _rpm_vercmp(a: str, b: str) -> int:
    if a == b:
        return 0

    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not _isalnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < len(b) and not _isalnum(b[j]) and b[j] not in "~^":
            j += 1

        # '~' sorts before everything, including the end of the string, so that
        # 1.0~rc1 < 1.0.
        if (i < len(a) and a[i] == "~") or (j < len(b) and b[j] == "~"):
            if i >= len(a) or a[i] != "~":
                return 1
            if j >= len(b) or b[j] != "~":
                return -1
            i += 1
            j += 1
            continue

        # '^' is the inverse: it sorts after the end of the string but before
        # any real segment, so that 1.0 < 1.0^ < 1.0.1.
        if (i < len(a) and a[i] == "^") or (j < len(b) and b[j] == "^"):
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue

        if i >= len(a) or j >= len(b):
            break

        start_a, start_b = i, j
        isnum = _isdigit(a[i])
        if isnum:
            while i < len(a) and _isdigit(a[i]):
                i += 1
            while j < len(b) and _isdigit(b[j]):
                j += 1
        else:
            while i < len(a) and _isalpha(a[i]):
                i += 1
            while j < len(b) and _isalpha(b[j]):
                j += 1

        seg_a = a[start_a:i]
        seg_b = b[start_b:j]
        # The two sides disagree on segment type: numeric beats alphabetic.
        if not seg_b:
            return 1 if isnum else -1

        if isnum:
            seg_a = seg_a.lstrip("0")
            seg_b = seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return _cmp(len(seg_a), len(seg_b))
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1

    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def compare_rpm(a: str, b: str) -> int:
    """Compare two RPM versions '[epoch:]version[-release]'."""
    epoch_a, version_a, release_a = _split_evr(a, "-")
    epoch_b, version_b, release_b = _split_evr(b, "-")

    if epoch_a != epoch_b:
        return _cmp(epoch_a, epoch_b)
    rc = _rpm_vercmp(version_a, version_b)
    if rc:
        return rc
    return _rpm_vercmp(release_a, release_b)


# ── apk ───────────────────────────────────────────────────────────────────────

# Suffix order: pre-releases sort before the plain version, post-releases after.
_APK_SUFFIXES = {"alpha": 0, "beta": 1, "pre": 2, "rc": 3, "": 4,
                 "cvs": 5, "svn": 6, "git": 7, "hg": 8, "p": 9}
_APK_RE = re.compile(
    r"^(?P<numbers>[0-9]+(?:\.[0-9]+)*)(?P<letter>[a-z]?)"
    r"(?P<suffixes>(?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)[0-9]*)*)"
    r"(?:~(?P<hash>[0-9a-f]+))?(?:-r(?P<revision>[0-9]+))?$"
)


def _apk_key(version: str):
    match = _APK_RE.match(version)
    if match is None:
        raise ValueError(f"not an apk version: {version!r}")
    parts = match.group("numbers").split(".")
    suffixes = [
        (_APK_SUFFIXES[name], int(number or 0))
        for name, number in re.findall(r"_([a-z]+)([0-9]*)", match.group("suffixes"))
    ]
    return (
        parts, match.group("letter"), suffixes, match.group("hash") or "",
        int(match.group("revision") or 0),
    )


def _apk_compare_numbers(a: list[str], b: list[str]) -> int:
    for index, (x, y) in enumerate(zip(a, b, strict=False)):
        # apk compares the leading number numerically and later ones as
        # fractions when they carry a leading zero ('1.01' < '1.1').
        if index > 0 and (x.startswith("0") or y.startswith("0")):
            rc = _cmp(x.rstrip("0") or "0", y.rstrip("0") or "0")
        else:
            rc = _cmp(int(x), int(y))
        if rc:
            return rc
    return _cmp(len(a), len(b))


def compare_apk(a: str, b: str) -> int:
    """Compare two Alpine versions; raises ValueError for a malformed one."""
    numbers_a, letter_a, suffixes_a, hash_a, revision_a = _apk_key(a)
    numbers_b, letter_b, suffixes_b, hash_b, revision_b = _apk_key(b)

    rc = _apk_compare_numbers(numbers_a, numbers_b)
    if rc:
        return rc
    rc = _cmp(letter_a, letter_b)
    if rc:
        return rc
    # A missing suffix sorts as the plain version: after _rc, before _p.
    plain = (_APK_SUFFIXES[""], 0)
    for index in range(max(len(suffixes_a), len(suffixes_b))):
        x = suffixes_a[index] if index < len(suffixes_a) else plain
        y = suffixes_b[index] if index < len(suffixes_b) else plain
        rc = _cmp(x, y)
        if rc:
            return rc
    rc = _cmp(hash_a, hash_b)
    if rc:
        return rc
    return _cmp(revision_a, revision_b)


# ── pacman ────────────────────────────────────────────────────────────────────

def _alpm_vercmp(a: str, b: str) -> int:
    """libalpm's rpmvercmp: an older rpmvercmp without '~'/'^' handling, but
    with separator-length comparison."""
    if a == b:
        return 0
    i = j = 0
    prev_i = prev_j = 0
    while i < len(a) and j < len(b):
        while i < len(a) and not _isalnum(a[i]):
            i += 1
        while j < len(b) and not _isalnum(b[j]):
            j += 1
        if i >= len(a) or j >= len(b):
            break
        # Differing separator lengths decide: '1.0' < '1..0'.
        if (i - prev_i) != (j - prev_j):
            return -1 if (i - prev_i) < (j - prev_j) else 1

        start_a, start_b = i, j
        isnum = _isdigit(a[i])
        if isnum:
            while i < len(a) and _isdigit(a[i]):
                i += 1
            while j < len(b) and _isdigit(b[j]):
                j += 1
        else:
            while i < len(a) and _isalpha(a[i]):
                i += 1
            while j < len(b) and _isalpha(b[j]):
                j += 1
        seg_a, seg_b = a[start_a:i], b[start_b:j]
        if not seg_b:
            return 1 if isnum else -1
        if isnum:
            seg_a = seg_a.lstrip("0")
            seg_b = seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return _cmp(len(seg_a), len(seg_b))
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1
        prev_i, prev_j = i, j

    rest_a, rest_b = a[i:], b[j:]
    if not rest_a and not rest_b:
        return 0
    # A remaining alphabetic part never beats an empty string.
    if (not rest_a and not _isalpha(rest_b[:1])) or _isalpha(rest_a[:1]):
        return -1
    return 1


def compare_pacman(a: str, b: str) -> int:
    """Compare two pacman versions '[epoch:]pkgver[-pkgrel]'."""
    epoch_a, version_a, release_a = _split_evr(a, "-")
    epoch_b, version_b, release_b = _split_evr(b, "-")
    if epoch_a != epoch_b:
        return _cmp(epoch_a, epoch_b)
    rc = _alpm_vercmp(version_a, version_b)
    if rc:
        return rc
    # pkgrel only counts when both versions carry one.
    if release_a and release_b:
        return _alpm_vercmp(release_a, release_b)
    return 0


# ── semver and generic ────────────────────────────────────────────────────────

_SEMVER_RE = re.compile(
    r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def compare_semver(a: str, b: str) -> int:
    """Compare two SemVer 2.0.0 versions (an optional leading 'v' is accepted);
    raises ValueError for anything else.
    """
    parsed = []
    for version in (a, b):
        match = _SEMVER_RE.match(version.strip())
        if match is None:
            raise ValueError(f"not a SemVer 2.0.0 version: {version!r}")
        parsed.append(match)
    ma, mb = parsed

    rc = _cmp(tuple(int(ma.group(n)) for n in (1, 2, 3)),
              tuple(int(mb.group(n)) for n in (1, 2, 3)))
    if rc:
        return rc
    pre_a, pre_b = ma.group(4), mb.group(4)
    # A version without a pre-release has higher precedence than one with.
    if pre_a is None or pre_b is None:
        return _cmp(pre_a is None, pre_b is None)
    for x, y in zip(pre_a.split("."), pre_b.split("."), strict=False):
        if x.isdigit() and y.isdigit():
            rc = _cmp(int(x), int(y))
        elif x.isdigit() or y.isdigit():
            rc = -1 if x.isdigit() else 1      # numeric identifiers sort first
        else:
            rc = _cmp(x, y)
        if rc:
            return rc
    return _cmp(len(pre_a.split(".")), len(pre_b.split(".")))


def compare_generic(a: str, b: str) -> int:
    """Split into numeric and alphabetic segments; numbers compare numerically,
    letters lexically, a number beats letters, and a missing segment sorts
    lower."""
    segments_a = re.findall(r"[0-9]+|[A-Za-z]+", a)
    segments_b = re.findall(r"[0-9]+|[A-Za-z]+", b)
    for x, y in zip(segments_a, segments_b, strict=False):
        if x.isdigit() and y.isdigit():
            rc = _cmp(int(x), int(y))
        elif x.isdigit() != y.isdigit():
            rc = 1 if x.isdigit() else -1
        else:
            rc = _cmp(x, y)
        if rc:
            return rc
    return _cmp(len(segments_a), len(segments_b))


COMPARATORS = {
    "dpkg":    compare_dpkg,
    "rpm":     compare_rpm,
    "apk":     compare_apk,
    "pacman":  compare_pacman,
    "semver":  compare_semver,
    "generic": compare_generic,
}

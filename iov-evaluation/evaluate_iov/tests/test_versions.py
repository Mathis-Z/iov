"""Version comparison vectors.

The dpkg cases come from dpkg's own t-func/version tests, the rpm cases from
rpm's tests/rpmvercmp.at and the pacman cases from pacman's
test/util/vercmptest.sh. Every algorithm was additionally differential-tested
against the real implementation: 6000 random pairs against `dpkg
--compare-versions` in a debian:stable-slim container, 300000 against librpm's
labelCompare, 3000 against `apk version -t` in alpine:latest and 3000 against
`vercmp` in archlinux:latest, all without a mismatch.
"""

import pytest

from evaluate_iov.versions import (
    COMPARATORS,
    compare_apk,
    compare_dpkg,
    compare_generic,
    compare_pacman,
    compare_rpm,
    compare_semver,
)

DPKG_CASES = [
    ("1.0", "1.0", 0),
    ("1.0", "2.0", -1),
    ("2.0", "1.0", 1),
    ("1.0", "1.0.1", -1),
    ("1.0.1", "1.0", 1),
    # Leading zeros in a numeric run are insignificant.
    ("1.007", "1.7", 0),
    ("1.10", "1.9", 1),
    # '~' sorts before everything, including the empty string.
    ("1.0~rc1", "1.0", -1),
    ("1.0~rc1", "1.0~rc2", -1),
    ("1.0~~", "1.0~", -1),
    # Letters sort before every other non-digit character.
    ("1.0a", "1.0+", -1),
    # The revision is compared only when the upstream versions are equal.
    ("1.0-1", "1.0-2", -1),
    ("1.0-10", "1.0-9", 1),
    ("1.1-1", "1.0-9", 1),
    ("1.0", "1.0-1", -1),
    # Epochs dominate, and a missing epoch is 0.
    ("1:1.0", "2.0", 1),
    ("0:1.0", "1.0", 0),
    ("1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u2", 1),
    ("1:8.9p1-3ubuntu0.10", "1:8.9p1-3ubuntu0.9", 1),
    ("1.0.1f-1ubuntu2.27+esm6", "1.0.1f-1ubuntu2.27", 1),
]

RPM_CASES = [
    ("1.0", "1.0", 0),
    ("1.0", "2.0", -1),
    ("1.0", "1.0.1", -1),
    ("2.0.1", "2.0.1", 0),
    ("2.0", "2.0.1", -1),
    ("5.5p1", "5.5p2", -1),
    ("5.5p10", "5.5p2", 1),
    ("10xyz", "10.1xyz", -1),
    ("xyz10", "xyz10.1", -1),
    ("1.0001", "1.1", 0),
    # A numeric segment is always newer than an alphabetic one.
    ("1.0", "1.a", 1),
    ("b.0", "1.0", -1),
    # Non-alphanumeric characters are separators only.
    ("1_0", "1.0", 0),
    ("a", "a+", 0),
    # '~' sorts before everything.
    ("1.0~rc1", "1.0", -1),
    ("1.0~rc1", "1.0~rc2", -1),
    ("1.0~rc1~git123", "1.0~rc1", -1),
    # '^' sorts after the base version but before any further segment.
    ("1.0^", "1.0", 1),
    ("1.0^", "1.0.1", -1),
    ("1.0^git1", "1.0^git2", -1),
    ("1.0~^", "1.0", -1),
    # Release and epoch.
    ("8.7p1-38.el9_4.1", "8.7p1-38.el9_4", 1),
    ("8.7p1-38.el9_4.1", "8.7p1-39.el9", -1),
    ("1:3.0.7-27.el9", "3.0.7-27.el9", 1),
    ("0:3.0.7-27.el9", "3.0.7-27.el9", 0),
]


@pytest.mark.parametrize("a, b, expected", DPKG_CASES)
def test_compare_dpkg(a, b, expected):
    assert compare_dpkg(a, b) == expected
    assert compare_dpkg(b, a) == -expected


@pytest.mark.parametrize("a, b, expected", RPM_CASES)
def test_compare_rpm(a, b, expected):
    assert compare_rpm(a, b) == expected
    assert compare_rpm(b, a) == -expected


APK_CASES = [
    ("3.3.2-r0", "3.3.2-r0", 0),
    ("3.3.2-r0", "3.3.2-r1", -1),
    ("3.3.2", "3.3.2-r0", 0),
    ("1.2.10", "1.2.9", 1),
    ("1.2.1", "1.2", 1),
    # Leading zeros after the first number compare as fractions.
    ("1.01", "1.1", -1),
    ("1.0a", "1.0", 1),
    ("1.0a", "1.0b", -1),
    # Pre-release suffixes sort before the plain version, post-releases after.
    ("1.0_alpha", "1.0_beta", -1),
    ("1.0_rc1", "1.0", -1),
    ("1.0_rc1", "1.0_rc2", -1),
    ("1.0", "1.0_p1", -1),
    ("9.7_p1-r4", "9.7-r4", 1),
    ("2.0_git20240101", "2.0", 1),
]

PACMAN_CASES = [
    ("1.5.0", "1.5.0", 0),
    ("1.5.1", "1.5.0", 1),
    ("1.5.1", "1.5", 1),
    ("1.5.0-1", "1.5.0-2", -1),
    ("1.5-1", "1.5.1-1", -1),
    # pkgrel is only compared when both sides have one.
    ("1.5", "1.5-1", 0),
    ("1.0-1", "1.1", -1),
    # Alphanumeric versions.
    ("1.5b-1", "1.5-1", -1),
    ("1.5b", "1.5.1", -1),
    ("1.0a", "1.0alpha", -1),
    ("1.0alpha", "1.0b", -1),
    ("1.0rc", "1.0", -1),
    # Alpha-dotted versions.
    ("1.5.a", "1.5", 1),
    ("1.5.b", "1.5.a", 1),
    ("1.5.1", "1.5.b", 1),
    ("1.5.b-1", "1.5.b", 0),
    ("1.5-1", "1.5.b", -1),
    # Separators: content does not matter, length does.
    ("2.0", "2_0", 0),
    ("2.0_a", "2_0.a", 0),
    ("2.0a", "2.0.a", -1),
    ("2___a", "2_a", 1),
    # Epochs.
    ("0:1.0", "0:1.1", -1),
    ("1:1.0", "0:1.1", 1),
    ("1:1.0", "2:1.1", -1),
    ("1:1.0-1", "0:1.1-1", 1),
    ("0:1.0", "1.0", 0),
    ("1:1.1", "1.1", 1),
]

SEMVER_CASES = [
    ("1.0.0", "1.0.0", 0),
    ("v1.2.3", "1.2.4", -1),
    ("1.10.0", "1.9.0", 1),
    ("1.0.0-alpha", "1.0.0", -1),
    ("1.0.0-alpha", "1.0.0-alpha.1", -1),
    ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1),
    ("1.0.0-beta.2", "1.0.0-beta.11", -1),
    ("1.0.0-rc.1", "1.0.0", -1),
    ("1.0.0+build.1", "1.0.0+build.2", 0),
]

GENERIC_CASES = [
    ("2.4.58", "2.4.58", 0),
    ("1.10", "1.9", 1),
    ("1.0", "1.0.1", -1),
    ("1.0b", "1.0a", 1),
    ("1.0.1", "1.0.a", 1),
]


@pytest.mark.parametrize("compare, a, b, expected", [
    *((compare_apk, *case) for case in APK_CASES),
    *((compare_pacman, *case) for case in PACMAN_CASES),
    *((compare_semver, *case) for case in SEMVER_CASES),
    *((compare_generic, *case) for case in GENERIC_CASES),
])
def test_other_schemes(compare, a, b, expected):
    assert compare(a, b) == expected
    assert compare(b, a) == -expected


@pytest.mark.parametrize("compare, version", [
    (compare_apk, "not a version"),
    (compare_apk, "1.0-rX"),
    (compare_semver, "1.0"),
    (compare_semver, "01.0.0"),
])
def test_unparseable_versions_raise(compare, version):
    with pytest.raises(ValueError):
        compare(version, "1.0.0")


def test_every_scheme_is_registered():
    assert set(COMPARATORS) == {"dpkg", "rpm", "apk", "pacman", "semver", "generic"}

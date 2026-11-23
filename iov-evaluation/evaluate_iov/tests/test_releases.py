import pytest

from evaluate_iov.releases import (
    PACKAGE_MANAGERS,
    Release,
    best_match,
    host_release,
    parse_release_spec,
)

OS_RELEASE = '''NAME="Debian GNU/Linux"
ID=debian
VERSION_ID="12"
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
'''


def test_host_release_unquotes_values():
    assert host_release(OS_RELEASE) == Release("debian", "12")
    assert str(host_release(OS_RELEASE)) == "debian:12"


def test_host_release_without_version_id():
    assert host_release('ID=debian\nVERSION_ID=""\n') == Release("debian", None)
    assert host_release("ID=debian\n") == Release("debian", None)
    assert str(Release("debian", None)) == "debian:"


@pytest.mark.parametrize("spec, expected", [
    ("debian",          [("debian", None, 0)]),
    ("debian:",         [("debian", "", 1)]),
    ("rhel:9",          [("rhel", "9", 1)]),
    ("rhel:9.0",        [("rhel", "9.0", 2)]),
    ("ubuntu:22.04,22.10", [("ubuntu", "22.04", 2), ("ubuntu", "22.10", 2)]),
])
def test_parse_release_spec(spec, expected):
    assert parse_release_spec(spec) == expected


def test_numeric_range_expansion():
    assert [v for _, v, _ in parse_release_spec("fedora:37-45")] == [str(n) for n in range(37, 46)]
    assert [v for _, v, _ in parse_release_spec("rhel:8.7-8.10")] == ["8.7", "8.8", "8.9", "8.10"]


def test_malformed_numeric_range_is_kept_verbatim():
    # Differing in more than the last part is not a range, so the token stays
    # as-is and simply never matches a real VERSION_ID.
    assert parse_release_spec("rhel:8.7-9.1") == [("rhel", "8.7-9.1", 3)]
    assert best_match(["rhel:8.7-9.1"], Release("rhel", "8.7")) is None


@pytest.mark.parametrize("specs, dist_id, version_id, expected", [
    (["debian:12"],       "debian", "12",   1),
    (["debian:12"],       "debian", "11",   None),
    (["debian"],          "debian", "11",   0),
    (["debian:"],         "debian", None,   1),
    (["debian:"],         "debian", "12",   None),
    (["debian:12"],       "ubuntu", "12",   None),
    # A version matches on dot boundaries only.
    (["rhel:9"],          "rhel",   "9.4",  1),
    (["rhel:9"],          "rhel",   "9",    1),
    (["rhel:9.1"],        "rhel",   "9.10", None),
    (["amzn:2"],          "amzn",   "2023", None),
    # ID_LIKE is not considered.
    (["rhel:9"],          "almalinux", "9.4", None),
    # The most specific matching release wins.
    (["rhel:9", "rhel:9.0"], "rhel", "9.0",  2),
])
def test_best_match(specs, dist_id, version_id, expected):
    matched = best_match(specs, Release(dist_id, version_id))
    assert (None if matched is None else matched.specificity) == expected


def test_best_match_reports_the_matching_release():
    assert str(best_match(["rhel:8.7-8.10"], Release("rhel", "8.9"))) == "rhel:8.9"
    assert str(best_match(["arch"], Release("arch", None))) == "arch"
    assert str(best_match(["debian:12", "debian:"], Release("debian", None))) == "debian:"


def test_every_distribution_is_bound_to_a_known_package_manager():
    assert set(PACKAGE_MANAGERS.values()) == {"dpkg", "rpm", "apk", "pacman"}
    assert PACKAGE_MANAGERS["alpine"] == "apk"
    assert PACKAGE_MANAGERS["almalinux"] == "rpm"

import pytest
from conftest import pkg

from evaluate_iov import packages
from evaluate_iov.packages import (
    AFFECTED,
    UNAFFECTED,
    UNKNOWN,
    choose_range_set,
    classify,
    classify_version,
    packages_by_key,
    parse_range,
    range_matches,
    relevant_packages,
)
from evaluate_iov.releases import Release
from evaluate_iov.versions import compare_dpkg, compare_rpm

KERNEL_KEY = r"^linux-image-6\.1\.0-[0-9]+-amd64$"
DEBIAN_12 = Release("debian", "12")


@pytest.fixture
def kernel_files(monkeypatch):
    """Pin the running kernel and the file lists of installed packages."""
    def configure(release, file_lists):
        monkeypatch.setattr(packages.kernel, "kernel_release", lambda: release)
        monkeypatch.setattr(packages.pkgdb, "package_files",
                            lambda p: file_lists.get((p.name, p.version), file_lists.get(p.name)))
    return configure


# ── Grouping ──────────────────────────────────────────────────────────────────

def test_exact_key_wins_over_a_regex_key():
    installed = [pkg("openssh-server", "1:9.2p1")]
    assert packages_by_key(["openssh-server", "^openssh-.*$"], installed) == {"openssh-server": installed}


def test_a_package_matches_every_regex_key_when_no_name_matches():
    installed = [pkg("nodejs", "18.19.0")]
    assert packages_by_key(["^node.*$", "^.*js$"], installed) == {"^node.*$": installed, "^.*js$": installed}


def test_unanchored_keys_are_treated_as_exact_names():
    assert packages_by_key(["linux-image"], [pkg("linux-image-6.1.0-18-amd64", "6.1.76-1")]) == {}


def test_multilib_instances_are_all_relevant():
    installed = [pkg("glibc", "2.34-100.el9", "x86_64", "rpm"), pkg("glibc", "2.34-100.el9", "i686", "rpm")]
    assert packages_by_key(["glibc"], installed) == {"glibc": installed}


# ── The running kernel ────────────────────────────────────────────────────────

def test_only_the_running_kernel_image_is_relevant(kernel_files):
    old, new = pkg("linux-image-6.1.0-13-amd64", "6.1.55-1"), pkg("linux-image-6.1.0-18-amd64", "6.1.76-1")
    kernel_files("6.1.0-18-amd64", {
        old.name: ["/boot/vmlinuz-6.1.0-13-amd64", "/lib/modules/6.1.0-13-amd64/kernel/fs/ext4.ko"],
        new.name: ["/boot/vmlinuz-6.1.0-18-amd64", "/lib/modules/6.1.0-18-amd64/kernel/fs/ext4.ko"],
    })
    assert relevant_packages(KERNEL_KEY, [old, new]) == ([new], False)


def test_rpm_kernels_are_recognised_by_their_module_tree(kernel_files):
    old, new = pkg("kernel-core", "5.14.0-70.el9", "x86_64", "rpm"), pkg("kernel-core", "5.14.0-427.el9", "x86_64", "rpm")
    kernel_files("5.14.0-427.el9.x86_64", {
        ("kernel-core", old.version): ["/lib/modules/5.14.0-70.el9.x86_64/vmlinuz"],
        ("kernel-core", new.version): ["/lib/modules/5.14.0-427.el9.x86_64/vmlinuz"],
    })
    assert relevant_packages("kernel-core", [old, new]) == ([new], False)


def test_a_self_built_running_kernel_flags_the_key(kernel_files):
    image = pkg("linux-image-6.1.0-13-amd64", "6.1.55-1")
    kernel_files("6.9.0-custom", {image.name: ["/boot/vmlinuz-6.1.0-13-amd64"]})
    assert relevant_packages(KERNEL_KEY, [image]) == ([], True)


def test_packages_without_a_kernel_image_are_untouched(kernel_files):
    installed = [pkg("libssl3", "3.0.11-1"), pkg("linux-headers-6.1.0-13-amd64", "6.1.55-1")]
    kernel_files("6.1.0-18-amd64", {"libssl3": ["/usr/lib/x86_64-linux-gnu/libssl.so.3"],
                                    "linux-headers-6.1.0-13-amd64": ["/usr/src/linux-headers-6.1.0-13-amd64/Makefile"]})
    assert relevant_packages("^.*$", installed) == (installed, False)


def test_an_unavailable_file_list_keeps_the_package(kernel_files):
    kernel_files("6.1.0-18-amd64", {})
    installed = [pkg("linux-image-6.1.0-13-amd64", "6.1.55-1")]
    assert relevant_packages(KERNEL_KEY, installed) == (installed, False)


# ── Ranges ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("text, expected", [
    ("*", []),
    ("< 1.0", [("<", "1.0")]),
    (">=1:3.0.1-47.el9_1", [(">=", "1:3.0.1-47.el9_1")]),
    (">= 2.0-1, < 2.0-5", [(">=", "2.0-1"), ("<", "2.0-5")]),
    ("< 9.7_p1-r4", [("<", "9.7_p1-r4")]),
])
def test_parse_range(text, expected):
    assert parse_range(text) == expected


@pytest.mark.parametrize("text", ["", "1.0", "<", "< 1.0 2.0", "!= 1.0", "< 1.0,"])
def test_malformed_ranges_are_rejected(text):
    assert parse_range(text) is None


def test_range_matches_requires_every_condition():
    conditions = parse_range(">= 2.4.0-1, < 2.4.7-3")
    assert range_matches("2.4.5-1", conditions, compare_dpkg)
    assert not range_matches("2.3.9-1", conditions, compare_dpkg)
    assert not range_matches("2.4.7-3", conditions, compare_dpkg)
    assert range_matches("anything", [], compare_dpkg)


def test_classify_version_prefers_affected():
    range_set = {"affected": "< 3.0.11", "unaffected": "*"}
    assert classify_version("3.0.10", range_set, compare_dpkg) == (AFFECTED, "affected: < 3.0.11")
    assert classify_version("3.0.11", range_set, compare_dpkg) == (UNAFFECTED, "unaffected: *")
    assert classify_version("3.5.0", {"affected": ">= 3.0.0, < 3.0.11"}, compare_rpm)[0] == UNKNOWN


# ── Choosing the range set ────────────────────────────────────────────────────

GLIBC = {"ranges": [
    {"releases": ["rhel:9"], "arches": ["i686"], "affected": "< 2.34-101.el9", "unaffected": ">= 2.34-101.el9"},
    {"releases": ["rhel:9"], "unaffected": "*"},
]}


def test_an_arch_specific_range_set_wins_at_equal_specificity():
    chosen, release = choose_range_set(GLIBC, Release("rhel", "9.4"), "i686")
    assert chosen is GLIBC["ranges"][0] and str(release) == "rhel:9"
    chosen, _ = choose_range_set(GLIBC, Release("rhel", "9.4"), "x86_64")
    assert chosen is GLIBC["ranges"][1]


def test_a_more_specific_release_beats_arches():
    entry = {"ranges": [
        {"releases": ["rhel:9"], "arches": ["x86_64"], "affected": "< 2.0"},
        {"releases": ["rhel:9.0"], "unaffected": "*"},
    ]}
    chosen, release = choose_range_set(entry, Release("rhel", "9.0"), "x86_64")
    assert chosen is entry["ranges"][1] and str(release) == "rhel:9.0"


def test_no_range_set_for_the_architecture():
    entry = {"ranges": [{"releases": ["rhel:9"], "arches": ["i686"], "affected": "< 2.0"}]}
    assert choose_range_set(entry, Release("rhel", "9.4"), "x86_64") is None


# ── Classification ────────────────────────────────────────────────────────────

def test_classify_reports_release_state_and_detail():
    entry = {"ranges": [{"releases": ["debian:12"], "affected": "< 1:9.2p1-2+deb12u3",
                         "unaffected": ">= 1:9.2p1-2+deb12u3"}]}
    result = classify("openssh-server", pkg("openssh-server", "1:9.2p1-2+deb12u2"), entry, DEBIAN_12, compare_dpkg)
    assert (result.release, result.state) == ("debian:12", AFFECTED)
    assert result.detail == ("openssh-server 1:9.2p1-2+deb12u2 (amd64) is affected on debian:12 "
                             "(affected: < 1:9.2p1-2+deb12u3)")


def test_multilib_builds_are_classified_separately():
    x86_64 = classify("glibc", pkg("glibc", "2.34-100.el9", "x86_64", "rpm"), GLIBC, Release("rhel", "9.4"), compare_rpm)
    i686 = classify("glibc", pkg("glibc", "2.34-100.el9", "i686", "rpm"), GLIBC, Release("rhel", "9.4"), compare_rpm)
    assert (x86_64.state, i686.state) == (UNAFFECTED, AFFECTED)


@pytest.mark.parametrize("verified, expected", [(True, AFFECTED), (False, UNKNOWN), (None, UNKNOWN)])
def test_origin_gates_the_comparison(monkeypatch, verified, expected):
    monkeypatch.setattr(packages.origin, "is_distribution_build",
                        lambda p: (verified, "signed with key 0123456789abcdef"))
    entry = {"ranges": [{"releases": ["ubuntu:22.04"], "origin": "distribution",
                         "affected": "< 1.18.0-6ubuntu14.4", "unaffected": ">= 1.18.0-6ubuntu14.4"}]}
    result = classify("nginx", pkg("nginx", "1.18.0-6ubuntu14.3"), entry, Release("ubuntu", "22.04"), compare_dpkg)
    assert result.state == expected
    if expected == UNKNOWN:
        assert "not a verifiable ubuntu build (signed with key 0123456789abcdef)" in result.detail


def test_origin_is_not_checked_without_the_constraint(monkeypatch):
    monkeypatch.setattr(packages.origin, "is_distribution_build", lambda p: pytest.fail("checked"))
    entry = {"ranges": [{"releases": ["debian:12"], "unaffected": "*"}]}
    assert classify("x", pkg("x", "1.0"), entry, DEBIAN_12, compare_dpkg).state == UNAFFECTED


def test_an_uncomparable_version_is_unknown():
    from evaluate_iov.versions import compare_apk
    entry = {"ranges": [{"releases": ["alpine:3.20"], "affected": "< 3.3.2-r0"}]}
    result = classify("libssl3", pkg("libssl3", "garbage!", "x86_64", "apk"), entry, Release("alpine", "3.20.3"), compare_apk)
    assert result.state == UNKNOWN and "cannot be compared" in result.detail


def test_an_unfixed_release_affects_every_version():
    assert classify_version("6.8.0-90.91", {"affected": "*"}, compare_dpkg) == (AFFECTED, "affected: *")
    range_set = {"affected": ">= 6.8.0-1.1", "unaffected": "*"}
    assert classify_version("6.8.0-90.91", range_set, compare_dpkg)[0] == AFFECTED
    assert classify_version("6.5.0-44.44", range_set, compare_dpkg)[0] == UNAFFECTED

from datetime import UTC, datetime

import pytest
from conftest import pkg

from evaluate_iov import evaluation, packages
from evaluate_iov.evaluation import evaluate, results_document
from evaluate_iov.host.pkgdb import Inventory
from evaluate_iov.packages import AFFECTED, UNAFFECTED, UNKNOWN
from evaluate_iov.releases import Release

OPENSSH = {
    "openssh-server": {
        "ranges": [
            {"releases": ["debian:12"],
             "affected": "< 1:9.2p1-2+deb12u3", "unaffected": ">= 1:9.2p1-2+deb12u3"},
            {"releases": ["ubuntu:22.04"],
             "affected": "< 1:8.9p1-3ubuntu0.10", "unaffected": ">= 1:8.9p1-3ubuntu0.10"},
        ]
    }
}


def iov(**parts) -> dict:
    return {"schema_version": 2, "uuid": "2e6b1f0a-9c84-4f3e-bf7a-1d2e5c8a9b3f",
            "cve": "CVE-2026-0001", "description": "test", **parts}


@pytest.fixture
def host(monkeypatch):
    """Pin the host's release, running kernel, installed packages and file lists."""
    def configure(dist_id, version_id, installed, manager="dpkg",
                  kernel_release="6.1.0-18-amd64", file_lists=None):
        monkeypatch.setattr(evaluation.releases, "host_release", lambda: Release(dist_id, version_id))
        monkeypatch.setattr(evaluation.pkgdb, "inventory",
                            lambda: Inventory(manager, [pkg(*p) if isinstance(p, tuple) else p
                                                        for p in installed]))
        monkeypatch.setattr(packages.kernel, "kernel_release", lambda: kernel_release)
        monkeypatch.setattr(packages.pkgdb, "package_files", lambda p: (file_lists or {}).get(p.name))
    return configure


def states(result) -> dict:
    return {f"{p.name} {p.version}": p.state for p in result.packages}


# ── Document checks ───────────────────────────────────────────────────────────

def test_a_format_version_1_document_is_rejected():
    result = evaluate({"uuid": "2e6b1f0a-9c84-4f3e-bf7a-1d2e5c8a9b3f", "cve": "CVE-2026-0001",
                       "description": "test", "script": "return HIGH"})
    assert result.score is None
    assert "format version 1" in result.reason and "regenerated" in result.reason


def test_an_unknown_format_version_is_rejected():
    result = evaluate(iov(schema_version=3, script="return HIGH"))
    assert result.score is None and "format version 3" in result.reason


def test_a_schema_violation_is_reported_with_its_location():
    result = evaluate(iov(packages={"openssh-server": {"ranges": [
        {"releases": ["debian:12"], "affected": "= 1.0"}]}}))
    assert result.score is None
    assert result.reason.startswith("The IoV violates the schema: /packages/openssh-server/ranges/0")


def test_a_document_without_packages_or_script_is_invalid():
    assert "violates the schema" in evaluate(iov()).reason


def test_an_invalid_regex_key_is_a_schema_violation():
    result = evaluate(iov(packages={"^linux-image-(unclosed$": {"ranges": [
        {"releases": ["debian:12"], "unaffected": "*"}]}}))
    assert "not a valid regex" in result.reason


def test_unknown_built_ins_are_rejected_before_running():
    result = evaluate(iov(script="let x := kernel_module_loaded(\"nf_tables\")\nreturn HIGH"))
    assert result.score is None
    assert result.reason == ("The script uses built-ins this agent does not provide: "
                             "kernel_module_loaded().")
    assert result.script is None


# ── Package matching ──────────────────────────────────────────────────────────

def test_uncovered_release_is_inconclusive(host):
    host("debian", "11", [("openssh-server", "1:8.4p1-5")])
    result = evaluate(iov(packages=OPENSSH))
    assert result.score is None
    assert result.reason == "Release debian:11 is not covered by any range set of this IoV."


def test_unknown_host_release_is_inconclusive(host):
    host(None, None, [])
    assert "could not be determined" in evaluate(iov(packages=OPENSSH)).reason


def test_affected_without_script_is_default(host):
    host("debian", "12", [("openssh-server", "1:9.2p1-2+deb12u2")])
    result = evaluate(iov(packages=OPENSSH))
    assert result.score == 2
    assert states(result) == {"openssh-server 1:9.2p1-2+deb12u2": AFFECTED}
    assert result.reason == (
        "openssh-server 1:9.2p1-2+deb12u2 (amd64) is affected on debian:12 "
        "(affected: < 1:9.2p1-2+deb12u3); the IoV has no script, so the result is DEFAULT."
    )


def test_unaffected_is_absent(host):
    host("debian", "12", [("openssh-server", "1:9.2p1-2+deb12u3")])
    result = evaluate(iov(packages=OPENSSH))
    assert result.score == 0
    assert result.reason.startswith("Every relevant package is unaffected: openssh-server")


def test_covered_release_without_the_package_is_absent(host):
    host("debian", "12", [("nginx", "1.22.1-9")])
    result = evaluate(iov(packages=OPENSSH))
    assert (result.score, result.packages) == (0, [])
    assert result.reason == "No package listed by this IoV is installed on the covered release debian:12."


def test_package_outside_every_range_is_unknown(host):
    doc = iov(packages={"libssl3": {"ranges": [
        {"releases": ["debian:12"], "affected": ">= 3.0.0, < 3.0.11-1~deb12u2"}]}})
    host("debian", "12", [("libssl3", "3.5.0-1")])
    result = evaluate(doc)
    assert result.score is None
    assert result.reason == ("No installed package is affected, but libssl3 3.5.0-1 (amd64) matches "
                             "no range on debian:12, so the IoV makes no statement.")


def test_affected_beats_unknown(host):
    doc = iov(packages={
        "openssh-server": OPENSSH["openssh-server"],
        "libssl3": {"ranges": [{"releases": ["debian:12"], "affected": "< 3.0.0"}]},
    })
    host("debian", "12", [("openssh-server", "1:9.2p1-2+deb12u2"), ("libssl3", "3.5.0-1")])
    assert evaluate(doc).score == 2


def test_wildcard_unaffected_covers_the_release(host):
    doc = iov(packages={"libssl3t64": {"ranges": [{"releases": ["ubuntu:24.04"], "unaffected": "*"}]}})
    host("ubuntu", "24.04", [("libssl3t64", "3.0.13-0ubuntu3")])
    assert evaluate(doc).score == 0


def test_most_specific_release_wins(host):
    doc = iov(packages={"kernel-core": {"ranges": [
        {"releases": ["rhel:9"], "affected": "< 5.14.0-500.el9", "unaffected": ">= 5.14.0-500.el9"},
        {"releases": ["rhel:9.0"], "unaffected": "*"},
    ]}})
    host("rhel", "9.0", [("kernel-core", "5.14.0-70.el9", "x86_64", "rpm")], "rpm")
    assert evaluate(doc).score == 0
    host("rhel", "9.4", [("kernel-core", "5.14.0-70.el9", "x86_64", "rpm")], "rpm")
    assert evaluate(doc).score == 2


def test_the_release_decides_the_comparison_algorithm(host):
    # 1.0~rc1 < 1.0 under dpkg and rpm, but apk would reject it as unparseable.
    doc = iov(packages={"foo": {"ranges": [{"releases": ["debian:12"], "affected": "< 1.0",
                                            "unaffected": ">= 1.0"}]}})
    host("debian", "12", [("foo", "1.0~rc1")], manager="dpkg")
    assert evaluate(doc).score == 2


def test_arch_specific_range_sets(host):
    doc = iov(packages={"glibc": {"ranges": [
        {"releases": ["rhel:9"], "arches": ["i686"], "affected": "< 2.34-101.el9",
         "unaffected": ">= 2.34-101.el9"},
        {"releases": ["rhel:9"], "unaffected": "*"},
    ]}})
    host("rhel", "9.4", [("glibc", "2.34-100.el9", "x86_64", "rpm")], "rpm")
    assert evaluate(doc).score == 0
    host("rhel", "9.4", [("glibc", "2.34-100.el9", "x86_64", "rpm"),
                         ("glibc", "2.34-100.el9", "i686", "rpm")], "rpm")
    result = evaluate(doc)
    assert result.score == 2
    assert [(p.arch, p.state) for p in result.packages] == [("x86_64", UNAFFECTED), ("i686", AFFECTED)]


def test_a_non_distribution_build_is_inconclusive(host, monkeypatch):
    monkeypatch.setattr(packages.origin, "is_distribution_build",
                        lambda p: (None, "version 1.26.1-1~jammy is not available from any ubuntu APT source"))
    doc = iov(packages={"nginx": {"ranges": [{"releases": ["ubuntu:22.04"], "origin": "distribution",
                                              "affected": "< 1.18.0-6ubuntu14.4",
                                              "unaffected": ">= 1.18.0-6ubuntu14.4"}]}})
    host("ubuntu", "22.04", [("nginx", "1.26.1-1~jammy")])
    result = evaluate(doc)
    assert result.score is None
    assert "nginx 1.26.1-1~jammy (amd64) is not a verifiable ubuntu build" in result.reason


def test_only_the_running_kernel_is_evaluated(host):
    doc = iov(packages={r"^linux-image-6\.1\.0-[0-9]+-amd64$": {"ranges": [
        {"releases": ["debian:12"], "affected": "< 6.1.76-1", "unaffected": ">= 6.1.76-1"}]}})
    host("debian", "12", [("linux-image-6.1.0-13-amd64", "6.1.55-1"),
                          ("linux-image-6.1.0-18-amd64", "6.1.76-1")],
         kernel_release="6.1.0-18-amd64",
         file_lists={"linux-image-6.1.0-13-amd64": ["/boot/vmlinuz-6.1.0-13-amd64"],
                     "linux-image-6.1.0-18-amd64": ["/boot/vmlinuz-6.1.0-18-amd64"]})
    result = evaluate(doc)
    # The old, vulnerable kernel is installed but not running.
    assert result.score == 0
    assert states(result) == {"linux-image-6.1.0-18-amd64 6.1.76-1": UNAFFECTED}


def test_a_self_built_kernel_is_inconclusive(host):
    key = r"^linux-image-6\.1\.0-[0-9]+-amd64$"
    doc = iov(packages={key: {"ranges": [{"releases": ["debian:12"], "affected": "< 6.1.76-1",
                                          "unaffected": ">= 6.1.76-1"}]}})
    host("debian", "12", [("linux-image-6.1.0-13-amd64", "6.1.55-1")], kernel_release="6.9.0-custom",
         file_lists={"linux-image-6.1.0-13-amd64": ["/boot/vmlinuz-6.1.0-13-amd64"]})
    result = evaluate(doc)
    assert result.score is None
    assert "none belongs to the running kernel 6.9.0-custom" in result.reason
    assert [(p.key, p.name, p.state) for p in result.packages] == [(key, None, UNKNOWN)]


def test_regex_key_matches_a_package_family(host):
    doc = iov(packages={r"^linux-image-6\.1\.0-[0-9]+-amd64$": {"ranges": [
        {"releases": ["debian:12"], "affected": "< 6.1.99-1", "unaffected": ">= 6.1.99-1"}]}})
    host("debian", "12", [("linux-image-6.1.0-18-amd64", "6.1.76-1")])
    assert evaluate(doc).score == 2
    host("debian", "12", [("linux-image-amd64", "6.1.76-1"), ("linux-headers-6.1.0-18-amd64", "6.1.76-1")])
    assert evaluate(doc).score == 0


def test_a_package_under_several_keys_is_reported_per_key(host):
    doc = iov(packages={
        "^node.*$": {"ranges": [{"releases": ["debian:12"], "affected": "< 1.0"}]},
        "^.*js$":   {"ranges": [{"releases": ["debian:12"], "unaffected": "*"}]},
    })
    host("debian", "12", [("nodejs", "18.19.0")])
    result = evaluate(doc)
    # UNKNOWN under the first key, UNAFFECTED under the second: UNKNOWN wins.
    assert [(p.key, p.state) for p in result.packages] == [("^node.*$", UNKNOWN), ("^.*js$", UNAFFECTED)]
    assert result.score is None


def test_missing_package_manager_is_inconclusive(host, monkeypatch):
    host("debian", "12", [])
    monkeypatch.setattr(evaluation.pkgdb, "inventory", lambda: None)
    result = evaluate(iov(packages=OPENSSH))
    assert result.score is None and "could not be enumerated" in result.reason


def test_long_package_lists_are_summarized_in_the_reason(host):
    doc = iov(packages={"^lib.*$": {"ranges": [{"releases": ["debian:12"], "affected": "< 9.0"}]}})
    host("debian", "12", [(f"lib{n}", "1.0") for n in range(8)])
    assert evaluate(doc).reason.count(" is affected on ") == 5
    assert "; and 3 more;" in evaluate(doc).reason


# ── Combining packages and script ─────────────────────────────────────────────

AFFECTED_HOST = ("debian", "12", [("openssh-server", "1:9.2p1-2+deb12u2")])


def test_script_result_overrides_default_when_a_package_is_affected(host):
    host(*AFFECTED_HOST)
    result = evaluate(iov(packages=OPENSSH, script="return LOW"))
    assert (result.score, result.script.value) == (1, 1)
    assert result.reason.endswith("; the script returned LOW.")


def test_script_may_return_absent(host):
    host(*AFFECTED_HOST)
    assert evaluate(iov(packages=OPENSSH, script="return ABSENT")).score == 0


@pytest.mark.parametrize("script, reason", [
    ("return null", "the script made no statement, so the result is DEFAULT."),
    ("let x := 1", "the script made no statement, so the result is DEFAULT."),
    ("return undefined", "the script failed (line 1: evaluating 'undefined' failed"),
    ("if true\nreturn HIGH", "the script failed (parse error: line 1: 'if' is never closed by 'end')"),
])
def test_failing_script_falls_back_to_default(host, script, reason):
    host(*AFFECTED_HOST)
    result = evaluate(iov(packages=OPENSSH, script=script))
    assert (result.score, result.script.value) == (2, None)
    assert reason in result.reason


def test_a_sandbox_limit_is_named(host, monkeypatch):
    from evaluate_iov.script import interpreter
    monkeypatch.setattr(interpreter, "MAX_STATEMENTS", 2)
    host(*AFFECTED_HOST)
    result = evaluate(iov(packages=OPENSSH, script="let a := 1\nlet b := 2\nlet c := 3\nreturn HIGH"))
    assert result.score == 2 and result.script.limit
    assert "the script exceeded a sandbox limit (the script exceeded 2 statements)" in result.reason


def test_script_does_not_run_when_no_package_is_affected(host):
    host("debian", "12", [("openssh-server", "1:9.2p1-2+deb12u3")])
    result = evaluate(iov(packages=OPENSSH, script="return HIGH"))
    assert (result.score, result.script) == (0, None)


def test_script_only_iov():
    assert evaluate(iov(script="return HIGH")).score == 3
    assert evaluate(iov(script="return HIGH")).reason == "The script returned HIGH."
    result = evaluate(iov(script="return null"))
    assert result.score is None
    assert result.reason == "The script made no statement, so the result is INCONCLUSIVE."
    assert evaluate(iov(script="return undefined")).score is None


# ── Results document ──────────────────────────────────────────────────────────

def test_results_document(host):
    host(*AFFECTED_HOST)
    document = iov(packages=OPENSSH, script="return LOW", updated="2026-09-25T10:00:00Z")
    result = evaluate(document)
    at = datetime(2026, 9, 26, 8, 15, 2, tzinfo=UTC)
    assert results_document(document, result, at) == {
        "iov_uuid": "2e6b1f0a-9c84-4f3e-bf7a-1d2e5c8a9b3f",
        "cve": "CVE-2026-0001",
        "schema_version": 2,
        "iov_updated": "2026-09-25T10:00:00Z",
        "evaluated_at": "2026-09-26T08:15:02Z",
        "agent_version": evaluation.AGENT_VERSION,
        "host_release": "debian:12",
        "packages": [{"key": "openssh-server", "name": "openssh-server",
                      "version": "1:9.2p1-2+deb12u2", "arch": "amd64", "release": "debian:12",
                      "state": "AFFECTED"}],
        "script": {"ran": True, "returned": 1, "error": None},
        "iov_score": 1,
        "reason": result.reason,
    }


def test_results_document_of_an_inconclusive_result():
    document = iov(script="return null")
    report = results_document(document, evaluate(document))
    assert report["iov_score"] == -1
    assert report["script"] == {"ran": True, "returned": None, "error": None}

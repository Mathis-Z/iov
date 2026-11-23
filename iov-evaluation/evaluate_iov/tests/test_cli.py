import json
import logging

import pytest

from evaluate_iov import cli
from evaluate_iov.evaluation import Result
from evaluate_iov.packages import PackageResult
from evaluate_iov.script.interpreter import ScriptOutcome

IOV = {"schema_version": 2, "uuid": "2e6b1f0a-9c84-4f3e-bf7a-1d2e5c8a9b3f", "cve": "CVE-2026-0001",
       "description": "test", "script": "return HIGH"}

AFFECTED_BASH = PackageResult("bash", "bash", "5.2-1", "amd64", "debian:12", "AFFECTED",
                              "bash 5.2-1 (amd64) is affected on debian:12 (affected: < 5.2-2)")


@pytest.fixture
def iov_file(tmp_path):
    def write(document):
        path = tmp_path / "test.iov.json"
        path.write_text(json.dumps(document))
        return str(path)
    return write


@pytest.fixture
def result(monkeypatch):
    def configure(value):
        monkeypatch.setattr(cli, "evaluate", lambda iov: value)
    return configure


def test_summary_output(capsys, iov_file, result):
    result(Result(3, "bash is affected; the script returned HIGH.", [AFFECTED_BASH], ScriptOutcome(3), "debian:12"))
    assert cli.main([iov_file(IOV)]) == 0
    assert capsys.readouterr().out == (
        "CVE-2026-0001: HIGH (3)\n"
        "  bash is affected; the script returned HIGH.\n"
        "  bash 5.2-1 (amd64)  debian:12  AFFECTED\n"
    )


def test_summary_of_an_inconclusive_result(capsys, iov_file, result):
    result(Result(None, "Release debian:13 is not covered by any range set of this IoV."))
    cli.main([iov_file(IOV)])
    assert capsys.readouterr().out == (
        "CVE-2026-0001: INCONCLUSIVE (-1)\n"
        "  Release debian:13 is not covered by any range set of this IoV.\n"
    )


def test_json_output_is_the_results_document(capsys, iov_file, result):
    result(Result(1, "reason", [AFFECTED_BASH], ScriptOutcome(1), "debian:12"))
    cli.main(["--json", iov_file(IOV)])
    report = json.loads(capsys.readouterr().out)
    assert report["iov_uuid"] == IOV["uuid"] and report["cve"] == "CVE-2026-0001"
    assert report["iov_score"] == 1 and report["reason"] == "reason"
    assert report["script"] == {"ran": True, "returned": 1, "error": None}
    assert report["packages"] == [{"key": "bash", "name": "bash", "version": "5.2-1", "arch": "amd64",
                                   "release": "debian:12", "state": "AFFECTED"}]


def test_the_evaluated_document_is_the_file_contents(capsys, iov_file, monkeypatch):
    seen = []

    def record(iov):
        seen.append(iov)
        return Result(3, "r")

    monkeypatch.setattr(cli, "evaluate", record)
    cli.main([iov_file(IOV)])
    assert seen == [IOV]


def test_script_only_iov_end_to_end(capsys, iov_file):
    # No monkeypatching: the real evaluator runs a script that needs no host data.
    cli.main([iov_file(IOV)])
    assert capsys.readouterr().out == "CVE-2026-0001: HIGH (3)\n  The script returned HIGH.\n"


def test_a_version_1_document_is_reported_not_evaluated(capsys, iov_file):
    document = {key: value for key, value in IOV.items() if key != "schema_version"}
    cli.main([iov_file(document)])
    out = capsys.readouterr().out
    assert out.startswith("CVE-2026-0001: INCONCLUSIVE (-1)\n") and "format version 1" in out


@pytest.mark.parametrize("contents", ["not json", '"a string, not an object"'])
def test_unusable_input_exits_nonzero(tmp_path, contents):
    path = tmp_path / "bad.json"
    path.write_text(contents)
    with pytest.raises(SystemExit) as exit_info:
        cli.main([str(path)])
    assert exit_info.value.code != 0


def test_missing_file_exits_nonzero(tmp_path):
    with pytest.raises(SystemExit) as exit_info:
        cli.main([str(tmp_path / "nope.json")])
    assert exit_info.value.code != 0


def test_log_level_argument_is_applied(iov_file, result, monkeypatch):
    monkeypatch.delenv("EVALUATE_IOV_LOG_LEVEL", raising=False)
    result(Result(3, "r"))
    cli.main(["--log-level", "DEBUG", iov_file(IOV)])
    assert logging.getLogger("evaluate-iov").level == logging.DEBUG
    cli.main([iov_file(IOV)])
    assert logging.getLogger("evaluate-iov").level == logging.WARNING

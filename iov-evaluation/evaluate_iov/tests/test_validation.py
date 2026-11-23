import json
from pathlib import Path

import pytest

from evaluate_iov import validation

PROMPT = Path(__file__).resolve().parents[3] / "iov_server" / "prompt" / "prompt6.txt"
SCHEMA = json.loads(validation.SCHEMA_PATH.read_text())


def test_the_schema_is_the_one_in_the_prompt():
    if not PROMPT.exists():
        pytest.skip("the IoV server's prompt is not part of this checkout")
    text = PROMPT.read_text()
    start = text.index("<<< START OF IOV SCHEMA >>>") + len("<<< START OF IOV SCHEMA >>>")
    assert json.loads(text[start:text.index("<<< END OF IOV SCHEMA >>>")]) == SCHEMA


@pytest.mark.parametrize("example", SCHEMA["examples"], ids=lambda e: e["cve"])
def test_the_examples_are_valid(example):
    assert validation.unsupported_version(example) is None
    assert validation.validation_error(example) is None


def test_version_1_documents_are_unsupported():
    assert "format version 1" in validation.unsupported_version({"cve": "CVE-2024-6387"})
    assert "format version 3" in validation.unsupported_version({"schema_version": 3})
    assert validation.unsupported_version({"schema_version": True}) is not None


@pytest.mark.parametrize("change, location", [
    (lambda d: d.pop("uuid"), "/"),
    (lambda d: d.update(cve="CVE-24-1"), "/cve"),
    (lambda d: d["packages"]["openssh-server"]["ranges"][0].update(origin="vendor"),
     "/packages/openssh-server/ranges/0/origin"),
    (lambda d: d["packages"]["openssh-server"]["ranges"][0].update(arches=[]),
     "/packages/openssh-server/ranges/0/arches"),
    (lambda d: d["references"][0].pop("id") and d["references"][0].pop("url"), "/references/0"),
    (lambda d: d.update(created="yesterday"), "/created"),
])
def test_violations_name_their_location(change, location):
    document = json.loads(json.dumps(SCHEMA["examples"][0]))
    change(document)
    error = validation.validation_error(document)
    assert error is not None and error.startswith(location)

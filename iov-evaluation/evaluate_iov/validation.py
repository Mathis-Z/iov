"""Validating an IoV document against the format version 2 schema.

iov.schema.json is a copy of the schema embedded in the IoV server's prompt6.txt,
which is the source of truth; tests/test_validation.py keeps the two in sync.
"""

import functools
import json
import re
from pathlib import Path

import jsonschema
from jsonschema.exceptions import best_match

SCHEMA_VERSION = 2
SCHEMA_PATH = Path(__file__).with_name("iov.schema.json")


@functools.cache
def _validator() -> jsonschema.Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text())
    return jsonschema.Draft202012Validator(schema)


def _location(error: jsonschema.ValidationError) -> str:
    return "/" + "/".join(str(part) for part in error.absolute_path)


def unsupported_version(iov: dict) -> str | None:
    """Explain why the document's format version is unsupported, or None."""
    if "schema_version" not in iov:
        return ("The IoV has no schema_version, so it uses format version 1, which this agent "
                "no longer supports; it must be regenerated in format version 2.")
    version = iov["schema_version"]
    if version != SCHEMA_VERSION or isinstance(version, bool):
        return (f"The IoV uses format version {version!r}; this agent supports only "
                f"format version {SCHEMA_VERSION}.")
    return None


def validation_error(iov: dict) -> str | None:
    """Describe the most relevant schema violation, or None if the IoV is valid."""
    error = best_match(_validator().iter_errors(iov))
    if error is not None:
        return f"{_location(error)}: {error.message}"
    for key in iov.get("packages", {}):
        if key.startswith("^") and key.endswith("$"):
            try:
                re.compile(key)
            except re.error as exc:
                return f"/packages: key {key!r} is not a valid regex: {exc}"
    return None

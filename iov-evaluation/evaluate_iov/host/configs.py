"""Structured configuration parsers: keyword/value files, INI, XML, JSON, YAML."""

import datetime
import json
import logging
import os
import re

import jsonpath_rfc9535
import yaml
from lxml import etree

from ..logging_setup import LOGGER_NAME
from .base import limit_entries, read_bytes, read_text
from .files import expand_paths, require_absolute

log = logging.getLogger(LOGGER_NAME)

PRECEDENCES = ("first", "last", "all")
MAX_INCLUDE_DEPTH = 16

# 'Keyword value' or 'Keyword=value' (sshd accepts both).
_DIRECTIVE_RE = re.compile(r"^([^\s=]+)\s*(?:=\s*|\s+|$)(.*)$")


# ── Keyword/value files ───────────────────────────────────────────────────────

def _strip_value(value: str) -> str:
    value = value.strip()
    if value.endswith(";"):
        value = value[:-1].rstrip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return value


def _collect_directives(path: str, keyword: str, values: list[str], depth: int) -> bool:
    """Append the global values of `keyword` in `path`, following includes.
    Returns whether the file could be read."""
    text = read_text(path)
    if text is None:
        return False

    block_depth = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Apache-style <Section> ... </Section>
        if line.startswith("<") and line.endswith(">"):
            block_depth += -1 if line.startswith("</") else 1
            continue
        # nginx-style blocks: a line opening or inside { ... } is not global.
        opens, closes = line.count("{"), line.count("}")
        if block_depth > 0 or opens:
            block_depth = max(0, block_depth + opens - closes)
            continue

        match = _DIRECTIVE_RE.match(line)
        if match is None:
            continue
        name, value = match.group(1).lower(), match.group(2)
        if name in ("match", "host"):
            break  # sshd/ssh: everything after a Match or Host line is conditional
        if name in ("include", "includeoptional"):
            if depth >= MAX_INCLUDE_DEPTH:
                log.warning("include depth exceeded in %s", path)
                continue
            for pattern in value.split():
                pattern = pattern.strip('"')
                if not pattern.startswith("/"):
                    pattern = os.path.join(os.path.dirname(path), pattern)
                for included in expand_paths([pattern]):
                    _collect_directives(included, keyword, values, depth + 1)
            continue
        if name == keyword.lower():
            values.append(_strip_value(value))
    return True


def directive_values(paths: list[str], keyword: str, precedence: str) -> list[str] | None:
    """Values of a keyword in sshd-style 'Keyword value' files.

    Only global directives count: Match/Host sections and Apache or nginx
    blocks are skipped, and Include lines are followed. `precedence` picks the
    first value (sshd), the last value, or all of them. None if no file is
    readable.
    """
    if precedence not in PRECEDENCES:
        raise ValueError(f"precedence must be one of {PRECEDENCES}, got {precedence!r}")
    values: list[str] = []
    read_any = False
    for path in expand_paths(paths):
        read_any |= _collect_directives(path, keyword, values, 0)
    if not read_any:
        return None
    if precedence == "first":
        return values[:1]
    if precedence == "last":
        return values[-1:]
    return limit_entries(values, "directive_values()")


# ── INI ───────────────────────────────────────────────────────────────────────

def ini_values(path: str, section: str, key: str) -> list[str] | None:
    """Every value of `key` in `section` of an INI file ("" is the part before any
    section header). None if the file is unreadable.
    """
    require_absolute(path)
    text = read_text(path)
    if text is None:
        return None
    current = ""
    values = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith((";", "#")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            continue
        separator = min((i for i in (line.find("="), line.find(":")) if i >= 0), default=-1)
        if separator < 0:
            continue
        if current == section and line[:separator].strip() == key:
            values.append(line[separator + 1:].strip())
    return limit_entries(values, "ini_values()")


# ── XML, JSON, YAML ───────────────────────────────────────────────────────────

def _xpath_value(item) -> str:
    if isinstance(item, etree._Element):
        return "".join(item.itertext())
    if isinstance(item, bool):
        return "true" if item else "false"
    if isinstance(item, float) and item.is_integer():
        return str(int(item))
    return str(item)


def xml_query(path: str, xpath: str) -> list[str] | None:
    """The string values an XPath expression selects in an XML file. Entities
    and DTDs are never loaded. None if the file is unreadable or malformed.
    """
    require_absolute(path)
    data = read_bytes(path)
    if data is None:
        return None
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False,
                             huge_tree=False)
    try:
        tree = etree.fromstring(data, parser=parser)
    except etree.XMLSyntaxError as exc:
        log.debug("%s is not well-formed XML: %s", path, exc)
        return None
    try:
        result = tree.xpath(xpath)
    except etree.XPathError as exc:
        raise ValueError(f"invalid XPath {xpath!r}: {exc}") from exc
    items = result if isinstance(result, list) else [result]
    return limit_entries([_xpath_value(item) for item in items], "xml_query()")


def _plain(value):
    """Reduce parsed YAML to JSON-like values."""
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, (datetime.date, datetime.datetime)):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _query(documents: list, expression: str, what: str) -> list:
    try:
        query = jsonpath_rfc9535.compile(expression)
    except jsonpath_rfc9535.JSONPathError as exc:
        raise ValueError(f"invalid JSONPath {expression!r}: {exc}") from exc
    values = []
    for document in documents:
        values.extend(query.find(document).values())
    return limit_entries(values, what)


def json_query(path: str, expression: str) -> list | None:
    """The values an RFC 9535 JSONPath selects in a JSON file. None if the file
    is unreadable or not JSON.
    """
    require_absolute(path)
    text = read_text(path)
    if text is None:
        return None
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        log.debug("%s is not valid JSON: %s", path, exc)
        return None
    return _query([document], expression, "json_query()")


def yaml_query(path: str, expression: str) -> list | None:
    """The values an RFC 9535 JSONPath selects across every document of a YAML
    file. None if the file is unreadable or not YAML.
    """
    require_absolute(path)
    text = read_text(path)
    if text is None:
        return None
    try:
        documents = [_plain(d) for d in yaml.safe_load_all(text)]
    except yaml.YAMLError as exc:
        log.debug("%s is not valid YAML: %s", path, exc)
        return None
    return _query(documents, expression, "yaml_query()")


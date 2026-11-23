"""Where the dashboard's data comes from.

- indexer: the live Wazuh indexer. Reads iov-results and, unless disabled,
  Wazuh's own vulnerability detections, so CVEs without an IoV are ranked too.
- demo:    the exported iov-results sample plus generated hosts and CVEs, for
  developing and presenting the dashboard without a Wazuh.

Only the indexer is used, never the Wazuh API: the dashboard needs no API
token and works while the manager is restarting.
"""
import csv
import json
import logging
import time
from pathlib import Path
from urllib.parse import quote

import requests
import urllib3

from config import (
    DASHBOARD_DATA_SOURCE,
    DASHBOARD_DEMO_CSV,
    DASHBOARD_INCLUDE_DETECTIONS,
    WAZUH_INDEXER_HOST,
    WAZUH_INDEXER_PASSWORD,
    WAZUH_INDEXER_PORT,
    WAZUH_INDEXER_USER,
)

logger = logging.getLogger("etso.dashboard")

# Same self-signed indexer certificate the rest of ETSO talks to.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

IOV_INDEX = "iov-results"  # external.wazuh.Wazuh.IOV_INDEX_NAME, not imported to keep this light
VULN_INDEX = "wazuh-states-vulnerabilities-*"
# No description: it is half the bytes of every detection and only the detail
# view shows it, which fetches it with detection_details().
VULN_FIELDS = [
    "agent.id", "agent.name", "host.os.full", "package.name", "package.version",
    "vulnerability.id", "vulnerability.severity", "vulnerability.score",
    "vulnerability.reference", "vulnerability.detected_at", "vulnerability.published_at",
]
# The IoV each verdict was evaluated from: several KB per document, and only
# the detail view shows it, one at a time, through evaluated_iov().
IOV_BULK_SOURCE = {"excludes": ["iov_document"]}
PAGE_SIZE = 1000
SCROLL_KEEPALIVE = "2m"

DEFAULT_DEMO_CSV = Path(__file__).parent / "demo_data" / "iov-results-export.csv"


class SourceError(RuntimeError):
    pass


# ── Indexer ──────────────────────────────────────────────────────────────────

def _indexer(path: str, body: dict | None, method: str = "post") -> requests.Response:
    return requests.request(
        method,
        f"https://{WAZUH_INDEXER_HOST}:{WAZUH_INDEXER_PORT}/{path}",
        json=body,
        auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
        verify=False,
        timeout=60,
    )


def _search_all(index: str, query: dict, fields: list[str] | dict | None = None) -> list[dict]:
    """Every hit's _source, limited by fields (a list to include, or the
    indexer's {"excludes": [...]}). A scroll in index order: the dashboard
    reads whole indices, and unlike search_after on _id this needs no sort,
    which on the vulnerability index made each page cost a second."""
    body = {"query": query, "size": PAGE_SIZE, "sort": ["_doc"]}
    if fields:
        body["_source"] = fields
    resp = _indexer(f"{index}/_search?scroll={SCROLL_KEEPALIVE}", body)
    if resp.status_code == 404:
        return []  # index not created yet: nothing projected so far
    resp.raise_for_status()

    results = []
    page = resp.json()
    scroll_id = page.get("_scroll_id")
    try:
        while page["hits"]["hits"]:
            results.extend(hit["_source"] for hit in page["hits"]["hits"])
            resp = _indexer("_search/scroll", {"scroll": SCROLL_KEEPALIVE, "scroll_id": scroll_id})
            resp.raise_for_status()
            page = resp.json()
            scroll_id = page.get("_scroll_id", scroll_id)
    finally:
        if scroll_id:
            try:
                _indexer("_search/scroll", {"scroll_id": scroll_id}, method="delete")
            except requests.RequestException:
                pass  # expires on its own after SCROLL_KEEPALIVE
    return results


def detection_details(agent_id: str, cve_id: str) -> dict | None:
    """The fields the bulk read leaves out, for one finding's detail view."""
    if DASHBOARD_DATA_SOURCE == "demo":
        return None
    resp = _indexer(f"{VULN_INDEX}/_search", {
        "size": 1,
        "_source": ["vulnerability.description", "vulnerability.reference"],
        "query": {"bool": {"filter": [
            {"term": {"agent.id": agent_id}},
            {"term": {"vulnerability.id": cve_id}},
        ]}},
    })
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    hits = resp.json()["hits"]["hits"]
    return (hits[0]["_source"].get("vulnerability") or {}) if hits else None


def evaluated_iov(agent_id: str, cve_id: str) -> dict | None:
    """One verdict's evaluated IoV, which the bulk read leaves out, as
    {"iov_document", "iov_uuid", "evaluated_at"}; None if there is no such
    verdict. iov_document is None when the agent sent the verdict without it."""
    if DASHBOARD_DATA_SOURCE == "demo":
        return None
    doc_id = quote(f"{agent_id}:{cve_id}", safe="")
    resp = _indexer(
        f"{IOV_INDEX}/_doc/{doc_id}?_source_includes=iov_document,iov_uuid,evaluated_at",
        None, method="get",
    )
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json().get("_source") or {}


def _epss_for(cve_ids: list[str]) -> dict[str, dict]:
    """EPSS for CVEs without an IoV document, through ETSO's Redis-cached
    FIRST lookup. Best effort: without it they are ranked on an assumed EPSS."""
    if not cve_ids:
        return {}
    try:
        from external.cve_info import query_epss
        return query_epss(cve_ids)
    except Exception as exc:  # Redis or FIRST unreachable
        logger.warning("EPSS lookup for %d CVE(s) without IoV failed: %s", len(cve_ids), exc)
        return {}


def load_indexer() -> dict:
    started = time.monotonic()
    try:
        iov_docs = _search_all(IOV_INDEX, {"match_all": {}}, IOV_BULK_SOURCE)
        detections = None
        if DASHBOARD_INCLUDE_DETECTIONS:
            detections = _search_all(VULN_INDEX, {"match_all": {}}, VULN_FIELDS)
    except requests.RequestException as exc:
        raise SourceError(f"Wazuh indexer at {WAZUH_INDEXER_HOST}:{WAZUH_INDEXER_PORT} unreachable: {exc}") from exc
    read_at = time.monotonic()

    with_epss = {d["cve_id"] for d in iov_docs if (d.get("epss") or {}).get("score") is not None}
    missing = sorted({(d.get("vulnerability") or {}).get("id") for d in detections or []} - with_epss - {None})
    epss = _epss_for(missing)
    logger.info(
        "Dashboard data: %d IoV verdict(s), %s detection(s) read in %.1fs; EPSS for %d of %d CVE(s) in %.1fs",
        len(iov_docs), "no" if detections is None else len(detections), read_at - started,
        len(epss), len(missing), time.monotonic() - read_at,
    )
    return {
        "iov_docs": iov_docs,
        "detections": detections,
        "epss": epss,
        "source": {
            "kind": "indexer",
            "label": "Live · Wazuh indexer",
            "detail": f"{IOV_INDEX}" + (f" + {VULN_INDEX}" if detections is not None else ""),
        },
    }


# ── Demo ─────────────────────────────────────────────────────────────────────

def _unflatten(row: dict) -> dict:
    """A Dashboards "Discover" CSV row ('_source.cvss.metrics.v3_1.baseScore')
    back into the nested document the indexer would return."""
    doc: dict = {}
    for column, raw in row.items():
        if not column.startswith("_source."):
            continue
        value = raw.strip() if isinstance(raw, str) else raw
        if value in ("", "-", None):
            continue
        node = doc
        *parents, leaf = column.removeprefix("_source.").split(".")
        for part in parents:
            node = node.setdefault(part, {})
        node[leaf] = value
    return doc


def _coerce(doc: dict) -> dict:
    """Restore the types the CSV export flattened into strings."""
    def num(v, cast=float):
        try:
            return cast(v)
        except (TypeError, ValueError):
            return None

    doc["iov_score"] = num(doc.get("iov_score"), int)
    doc["script_result"] = num(doc.get("script_result"), int)
    doc["script_ran"] = str(doc.get("script_ran")).lower() == "true"
    try:
        doc["packages"] = json.loads(doc.get("packages") or "[]")
    except json.JSONDecodeError:
        doc["packages"] = []
    for key in ("score", "percentile"):
        if key in doc.get("epss", {}):
            doc["epss"][key] = num(doc["epss"][key])
    if "base_score" in doc.get("cvss", {}):
        doc["cvss"]["base_score"] = num(doc["cvss"]["base_score"])
    return doc


def read_export_csv(path: Path) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as fh:
        return [_coerce(_unflatten(row)) for row in csv.DictReader(fh)]


def load_demo() -> dict:
    from dashboard.demo_data import generate

    path = Path(DASHBOARD_DEMO_CSV) if DASHBOARD_DEMO_CSV else DEFAULT_DEMO_CSV
    exported = read_export_csv(path) if path.exists() else []
    iov_docs, detections, epss = generate(exported)
    return {
        "iov_docs": iov_docs,
        "detections": detections,
        "epss": epss,
        "source": {
            "kind": "demo",
            "label": "Demo data",
            "detail": f"{len(exported)} exported verdicts from {path.name} + generated hosts",
        },
    }


def load() -> dict:
    """The raw data, read fresh. routes.py caches what is built from it."""
    data = load_demo() if DASHBOARD_DATA_SOURCE == "demo" else load_indexer()
    data["loaded_at"] = time.time()
    return data

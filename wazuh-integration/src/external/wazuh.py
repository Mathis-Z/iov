"""ETSO's access to Wazuh: the Wazuh API (agent list) and the Wazuh indexer
(verdict alerts, detections, and the iov-results index ETSO maintains)."""
import base64
import binascii
import json
import logging
import zlib
from datetime import UTC, datetime

import requests

from config import (
    WAZUH_ALERTS_INDEX,
    WAZUH_API_HOST,
    WAZUH_API_PASSWORD,
    WAZUH_API_PORT,
    WAZUH_API_USER,
    WAZUH_INDEXER_HOST,
    WAZUH_INDEXER_PASSWORD,
    WAZUH_INDEXER_PORT,
    WAZUH_INDEXER_USER,
)

logger = logging.getLogger("etso.wazuh")


def _restore_nulls(value):
    """Turn the string "null" back into None, throughout a decoded alert field.

    analysisd's JSON decoder writes a JSON null as the string "null" (its
    json_null_field option defaults to "string"), so a verdict whose script
    did not run arrives with script_result "null", which an integer field
    rejects.
    """
    if value == "null":
        return None
    if isinstance(value, dict):
        return {k: _restore_nulls(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_restore_nulls(v) for v in value]
    return value

_instance = None


def _utc_iso(value):
    """Normalise a timestamp to UTC ISO 8601 with second precision, so that
    evaluated_at values compare correctly as strings. Anything unparseable is
    passed through unchanged."""
    if not isinstance(value, str):
        return value
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat(timespec="seconds")


# The daemon attaches the evaluated IoV in this encoding (see
# iov-evaluation/evaluate_iov/daemon.py, encode_document).
IOV_DOCUMENT_ENCODING = "zlib+base64"
# Far above any real IoV; stops a malformed event from inflating without bound.
MAX_IOV_DOCUMENT_BYTES = 4 * 1024 * 1024


def _decode_iov_document(iov: dict) -> dict | None:
    """The IoV the verdict was evaluated from, or None if the event carries
    none (an older daemon, or the IoV was too large to attach) or it cannot
    be decoded."""
    encoded = iov.get("document")
    if not encoded:
        return None
    if iov.get("document_encoding") != IOV_DOCUMENT_ENCODING:
        logger.warning("%s: unknown IoV document encoding %r",
                       iov.get("cve"), iov.get("document_encoding"))
        return None
    try:
        inflater = zlib.decompressobj()
        raw = inflater.decompress(base64.b64decode(encoded, validate=True), MAX_IOV_DOCUMENT_BYTES)
        if inflater.unconsumed_tail:
            raise ValueError(f"over {MAX_IOV_DOCUMENT_BYTES} bytes decompressed")
        document = json.loads(raw)
    except (binascii.Error, zlib.error, ValueError) as exc:
        logger.warning("%s: could not decode the attached IoV: %s", iov.get("cve"), exc)
        return None
    return document if isinstance(document, dict) else None


class Wazuh:
    """Process-wide client, created on first use. Creating it logs in to the
    Wazuh API, so every caller shares one session."""

    def __new__(cls):
        global _instance
        if _instance is None:
            _instance = super().__new__(cls)
            _instance._init()
        return _instance

    def check_missing_configs(self):
        required = [
            "WAZUH_API_HOST", "WAZUH_API_PORT", "WAZUH_API_USER", "WAZUH_API_PASSWORD",
            "WAZUH_INDEXER_HOST", "WAZUH_INDEXER_PORT", "WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASSWORD",
        ]
        missing = [var for var in required if not globals().get(var)]
        if missing:
            raise OSError(f"Missing required environment variables: {', '.join(missing)}")

    def _init(self):
        self.check_missing_configs()

        self._base = f"https://{WAZUH_API_HOST}:{WAZUH_API_PORT}"
        self._indexer_base = f"https://{WAZUH_INDEXER_HOST}:{WAZUH_INDEXER_PORT}"
        self._indexer_auth = (WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD)

        self._api_session = requests.Session()
        self._api_session.verify = False

        resp = self._api_session.post(
            f"{self._base}/security/user/authenticate",
            auth=(WAZUH_API_USER, WAZUH_API_PASSWORD),
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"Wazuh authentication failed ({resp.status_code}): {resp.text}"
            )

        token = resp.json()["data"]["token"]
        self._api_session.headers.update({"Authorization": f"Bearer {token}"})

    def list_agents(self, status: str = "active", limit: int = 500) -> list[dict]:
        """Active agents from the Wazuh API, without the manager itself."""
        resp = self._api_session.get(
            f"{self._base}/agents",
            params={"status": status, "limit": limit},
        )
        resp.raise_for_status()
        return [agent for agent in resp.json()["data"]["affected_items"] if agent["lastKeepAlive"] != '9999-12-31T23:59:59+00:00']

    def detected_cves(self, agent_id: str) -> dict[str, float | None]:
        """The CVEs Wazuh's vulnerability detector reports for an agent, with
        their CVSS base score (None if Wazuh has none), highest first."""
        hits = self._search_all(
            "wazuh-states-vulnerabilities-*",
            {"term": {"agent.id": agent_id}},
            [{"_id": "asc"}],
            ["vulnerability.id", "vulnerability.score.base"],
        )
        cves: dict[str, float | None] = {}
        for hit in hits:
            vuln = hit["_source"].get("vulnerability") or {}
            if vuln.get("id"):
                cves.setdefault(vuln["id"], (vuln.get("score") or {}).get("base"))
        return dict(sorted(cves.items(), key=lambda item: -(item[1] or 0)))

    # ------------------------------------------------------------------
    # IoV results index
    # ------------------------------------------------------------------

    # Projected out of the alerts index by pipeline.py from the verdicts
    # wazuh-evaluate-iov-daemon reports through the agent socket.
    # One document per agent and CVE, so a re-evaluation replaces the previous
    # one.
    IOV_INDEX_NAME = "iov-results"

    # Added by pipeline.enrich() when the score is known; a document never
    # carries them as null.
    IOV_ENRICHMENT_FIELDS = {"epss", "cvss"}

    IOV_INDEX_MAPPINGS = {
        "settings": {
            "number_of_shards":   1,
            "number_of_replicas": 0,  # single-node: no replica placement → stays Green
        },
        "mappings": {
            # cvss.metrics is NVD's per-version data, which differs between
            # CVSS versions, so it is mapped dynamically: strings as keywords
            # (so Dashboards can aggregate them), whole numbers as floats (so
            # a "10" seen first does not make the field an integer).
            "dynamic_templates": [
                {"cvss_metric_strings": {
                    "path_match": "cvss.metrics.*",
                    "match_mapping_type": "string",
                    "mapping": {"type": "keyword"},
                }},
                {"cvss_metric_numbers": {
                    "path_match": "cvss.metrics.*",
                    "match_mapping_type": "long",
                    "mapping": {"type": "float"},
                }},
            ],
            "properties": {
                "agent_id":      {"type": "keyword"},
                "agent_name":    {"type": "keyword"},
                "cve_id":        {"type": "keyword"},
                "iov_uuid":      {"type": "keyword"},
                # -1 INCONCLUSIVE, 0 ABSENT, 1 LOW, 2 MEDIUM/DEFAULT, 3 HIGH.
                # -1 is "no statement", not evidence of safety.
                "iov_score":     {"type": "integer"},
                "iov_level":     {"type": "keyword"},
                # Why the agent reached the score, as a sentence.
                "reason":        {"type": "text"},
                "script_result": {"type": "integer"},
                "script_ran":    {"type": "boolean"},
                "script_error":  {"type": "text"},
                "packages": {
                    "type": "nested",
                    "properties": {
                        "key":     {"type": "keyword"},
                        "name":    {"type": "keyword"},
                        "version": {"type": "keyword"},
                        "arch":    {"type": "keyword"},
                        "release": {"type": "keyword"},
                        "state":   {"type": "keyword"},
                    },
                },
                "evaluated_at":  {"type": "date"},
                "rule_id":       {"type": "keyword"},
                # The IoV the verdict was evaluated from, exactly as the agent
                # had it, for showing what led to the result. Stored but not
                # indexed: every IoV has its own keys, which would otherwise
                # grow the mapping without bound. null when the agent sent
                # none.
                "iov_document":  {"type": "object", "enabled": False},
                # From FIRST (api.first.org).
                "epss": {
                    "properties": {
                        "score":      {"type": "float"},
                        "percentile": {"type": "float"},
                        "date":       {"type": "date"},
                    },
                },
                # From NVD. The headline fields come from one CVSS version
                # (see cve_info.cvss_from_nvd_metrics); "metrics" holds every
                # version NVD has, keyed v2 / v3_0 / v3_1 / v4_0, including
                # the vector components and sub-scores.
                "cvss": {
                    "properties": {
                        "base_score": {"type": "float"},
                        "version":    {"type": "keyword"},
                        "severity":   {"type": "keyword"},
                        "vector":     {"type": "keyword"},
                        "metrics":    {"type": "object", "dynamic": True},
                    },
                },
            }
        }
    }

    def _ensure_index_pattern(self, index_name: str, time_field: str) -> None:
        """Register an index pattern in OpenSearch Dashboards (.kibana index)
        so the index is immediately selectable in the Dashboard UI."""
        pattern_id = f"index-pattern:{index_name}"
        url = f"{self._indexer_base}/.kibana/_doc/{pattern_id}"

        resp = requests.head(url, auth=self._indexer_auth, verify=False)
        if resp.status_code == 200:
            return

        resp = requests.put(
            url,
            json={
                "type": "index-pattern",
                "index-pattern": {
                    "title":         index_name,
                    "timeFieldName": time_field,
                },
            },
            auth=self._indexer_auth,
            verify=False,
        )
        if resp.status_code in (200, 201):
            print(f"Registered index pattern '{index_name}' in Dashboards")
        else:
            # Non-fatal: dashboards may use a different kibana index name
            print(f"WARNING: could not register index pattern ({resp.status_code}): {resp.text}")

    def _ensure_index(self, index_name: str, mappings: dict, time_field: str) -> None:
        """Create an index if it does not already exist, then ensure it is
        registered as a Dashboard index pattern."""
        url = f"{self._indexer_base}/{index_name}"
        resp = requests.head(url, auth=self._indexer_auth, verify=False)

        if resp.status_code == 404:
            resp = requests.put(
                url,
                json=mappings,
                auth=self._indexer_auth,
                verify=False,
            )
            resp.raise_for_status()
            print(f"Created index '{index_name}'")
        elif resp.status_code != 200:
            resp.raise_for_status()  # unexpected status

        self._ensure_index_pattern(index_name, time_field)

    def ensure_iov_index(self) -> None:
        """Create the index the pipeline writes verdicts into, and bring an
        existing one's mapping up to date (once per process)."""
        self._ensure_index(self.IOV_INDEX_NAME, self.IOV_INDEX_MAPPINGS, "evaluated_at")
        if not getattr(self, "_iov_mapping_current", False):
            self._update_mapping(self.IOV_INDEX_NAME, self.IOV_INDEX_MAPPINGS["mappings"])
            self._iov_mapping_current = True

    def _update_mapping(self, index_name: str, mappings: dict) -> None:
        """Add fields introduced since the index was created. The indexer
        accepts new fields and unchanged ones; a changed field type is
        refused, and needs the index recreated."""
        resp = requests.put(
            f"{self._indexer_base}/{index_name}/_mapping",
            json=mappings,
            auth=self._indexer_auth,
            verify=False,
        )
        if resp.status_code != 200:
            print(f"WARNING: could not update the mapping of '{index_name}' "
                  f"({resp.status_code}): {resp.text}")

    # Painless for _bulk_upsert: a verdict only replaces one that is not newer.
    # evaluated_at is always UTC ISO 8601 (see _iov_alert_to_index_doc), so
    # comparing the strings compares the times.
    _NEWER_WINS = (
        "if (ctx._source.evaluated_at != null && params.doc.evaluated_at != null"
        " && ctx._source.evaluated_at.compareTo(params.doc.evaluated_at) > 0) {"
        " ctx.op = 'none' } else { ctx._source.putAll(params.doc) }"
    )

    def _bulk(self, actions: list[tuple[dict, dict]]) -> int:
        """Send (action, body) pairs to _bulk. Returns how many the indexer
        accepted, and prints the first few failures."""
        if not actions:
            return 0

        bulk_lines: list[str] = []
        for action, body in actions:
            bulk_lines.append(json.dumps(action))
            bulk_lines.append(json.dumps(body))

        resp = requests.post(
            f"{self._indexer_base}/_bulk",
            data="\n".join(bulk_lines) + "\n",
            headers={"Content-Type": "application/x-ndjson"},
            auth=self._indexer_auth,
            verify=False,
        )
        resp.raise_for_status()
        failed = [
            item for item in resp.json().get("items", [])
            if next(iter(item.values()), {}).get("error")
        ]
        if failed:
            print(f"WARNING: {len(failed)} bulk operation(s) failed: {failed[:3]}")
        return len(actions) - len(failed)

    def _bulk_upsert(self, index_name: str, docs_by_id: dict[str, dict]) -> int:
        """Upsert verdict documents by explicit ID, so re-running overwrites
        rather than duplicating, and an older verdict arriving late never
        replaces a newer one. Fields a document leaves out keep their stored
        value, which is what keeps an EPSS or CVSS score the verdict was not
        given. Returns the number of documents the indexer accepted."""
        return self._bulk([
            (
                {"update": {"_index": index_name, "_id": doc_id}},
                {"script": {"lang": "painless", "source": self._NEWER_WINS, "params": {"doc": doc}},
                 "upsert": doc},
            )
            for doc_id, doc in docs_by_id.items()
        ])

    def _bulk_update(self, index_name: str, fields_by_id: dict[str, dict]) -> int:
        """Merge fields into existing documents; a document that no longer
        exists is reported as failed, not recreated."""
        return self._bulk([
            ({"update": {"_index": index_name, "_id": doc_id}}, {"doc": fields})
            for doc_id, fields in fields_by_id.items()
        ])

    def _search_all(self, index: str, query: dict, sort: list, source) -> list[dict]:
        """Every hit of a query, paged with search_after (see
        https://opensearch.org/docs/latest/api-reference/search/#the-search_after-parameter),
        since a single _search is capped by index.max_result_window."""
        page_size = 500
        results: list[dict] = []
        search_after = None

        while True:
            body = {"query": query, "size": page_size, "sort": sort, "_source": source}
            if search_after is not None:
                body["search_after"] = search_after

            resp = requests.post(
                f"{self._indexer_base}/{index}/_search",
                json=body,
                auth=self._indexer_auth,
                verify=False,
            )
            resp.raise_for_status()
            hits = resp.json()["hits"]["hits"]
            results.extend(hits)

            if len(hits) < page_size:
                break
            search_after = hits[-1]["sort"]

        return results

    def list_iov_results(self) -> list[dict]:
        """Every iov-results document's ID and CVE, as {"_id", "cve_id"}."""
        hits = self._search_all(
            self.IOV_INDEX_NAME, {"match_all": {}}, [{"_id": "asc"}], ["cve_id"]
        )
        return [{"_id": hit["_id"], "cve_id": hit["_source"]["cve_id"]} for hit in hits]

    # ------------------------------------------------------------------
    # IoV verdict alerts
    # ------------------------------------------------------------------

    def fetch_iov_alerts(self, since_ms: int, agent_id: str | None = None) -> list[dict]:
        """Fetch the IoV verdict alerts at or after since_ms (epoch millis),
        newest first, for one agent or (agent_id None) for all of them.

        Returns the raw hits: "_id" identifies the alert, "_source" is the
        alert, and "sort"[0] is its @timestamp in epoch millis.

        Agents publish verdicts through the Wazuh agent socket; the manager's
        rules (installation/manager/iov_rules.xml) tag them with the iov_evaluation
        group.
        """
        filters = [
            {"term": {"rule.groups": "iov_evaluation"}},
            {"range": {"@timestamp": {"gte": since_ms, "format": "epoch_millis"}}},
        ]
        if agent_id is not None:
            filters.append({"term": {"agent.id": agent_id}})

        return self._search_all(
            WAZUH_ALERTS_INDEX,
            {"bool": {"filter": filters}},
            # Newest first, so the first alert seen for an (agent, CVE) is the
            # current verdict. _id breaks ties so paging is stable.
            [{"@timestamp": "desc"}, {"_id": "asc"}],
            True,
        )

    @staticmethod
    def _iov_alert_to_index_doc(alert: dict) -> dict | None:
        """Flatten one alert into an IoV evaluation document, or None if the
        alert carries no IoV payload."""
        iov = _restore_nulls((alert.get("data") or {}).get("iov") or alert.get("iov"))
        if not iov or not iov.get("cve"):
            return None

        agent = alert.get("agent") or {}
        return {
            "agent_id":      agent.get("id", "000"),
            "agent_name":    agent.get("name", ""),
            "cve_id":        iov["cve"],
            "iov_uuid":      iov.get("uuid"),
            "iov_score":     iov.get("score", -1),
            "iov_level":     iov.get("level", "INCONCLUSIVE"),
            "reason":        iov.get("reason", ""),
            "script_result": iov.get("script_result"),
            "script_ran":    iov.get("script_ran", False),
            "script_error":  iov.get("script_error"),
            "packages":      iov.get("packages", []),
            "evaluated_at":  _utc_iso(iov.get("evaluated_at") or alert.get("@timestamp")),
            "rule_id":       (alert.get("rule") or {}).get("id"),
            # Always set, so a verdict sent without its IoV does not leave an
            # earlier verdict's IoV in place.
            "iov_document":  _decode_iov_document(iov),
        }


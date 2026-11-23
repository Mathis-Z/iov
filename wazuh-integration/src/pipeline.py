import logging
import time

import redis

from config import (
    IOV_PROJECTION_LOOKBACK,
    NVD_MAX_LOOKUPS_PER_RUN,
    POLL_OVERLAP,
    REDIS_URL,
)
from external.cve_info import query_cvss, query_epss
from external.wazuh import Wazuh

logger = logging.getLogger("etso.pipeline")


def _now_ms() -> int:
    return int(time.time() * 1000)


def latest_verdicts(alerts: list[dict]) -> dict[str, dict]:
    """The newest verdict per agent and CVE, keyed "<agent_id>:<cve_id>".

    Expects the alerts newest first, as fetch_iov_alerts returns them, so the
    first one seen for a key wins.
    """
    documents: dict[str, dict] = {}
    for alert in alerts:
        doc = Wazuh._iov_alert_to_index_doc(alert)
        if doc is None:
            continue
        documents.setdefault(f"{doc['agent_id']}:{doc['cve_id']}", doc)
    return documents


def scores_for(cve_ids, nvd_lookups: int) -> tuple[dict[str, dict], dict[str, dict]]:
    """EPSS and CVSS per CVE. With nvd_lookups 0 only cached CVSS is used,
    because an NVD lookup takes up to 6 s."""
    cve_ids = sorted(set(cve_ids))
    return query_epss(cve_ids), query_cvss(cve_ids, max_lookups=nvd_lookups)


def enrich(documents: dict[str, dict], nvd_lookups: int = NVD_MAX_LOOKUPS_PER_RUN) -> dict[str, int]:
    """Add the "epss" and "cvss" fields to the documents in place.

    A CVE without a score gets no field at all rather than a null, so the
    upsert keeps whatever was stored before. Returns how many CVEs got each
    score.
    """
    epss, cvss = scores_for((doc["cve_id"] for doc in documents.values()), nvd_lookups)

    for doc in documents.values():
        if doc["cve_id"] in epss:
            doc["epss"] = epss[doc["cve_id"]]
        if doc["cve_id"] in cvss:
            doc["cvss"] = cvss[doc["cve_id"]]

    cves = len({doc["cve_id"] for doc in documents.values()})
    return {"cves": cves, "epss": len(epss), "cvss": len(cvss)}


def _write(wazuh: Wazuh, documents: dict[str, dict], summary: dict) -> dict:
    # Before the write: the indexer auto-creates an unknown index, and the
    # verdicts would land under a guessed dynamic mapping ('packages' as an
    # object rather than nested, iov_score as text).
    wazuh.ensure_iov_index()
    written = wazuh._bulk_upsert(Wazuh.IOV_INDEX_NAME, documents)
    summary["failed"] = len(documents) - written
    return summary


# ── On demand: re-project a window ────────────────────────────────────────────

def process_iov_results(
    agent_id: str | None = None,
    lookback_seconds: int = IOV_PROJECTION_LOOKBACK,
    dry_run: bool = False,
    wazuh: Wazuh | None = None,
) -> dict:
    """Re-project the latest IoV verdicts of one agent, or of every agent when
    agent_id is None, from the last lookback_seconds of alerts into
    iov-results, with the EPSS and CVSS scores of their CVEs.

    The poll does this continuously for new alerts; this is the manual way to
    rebuild. Idempotent: documents are keyed "<agent_id>:<cve_id>" and a
    verdict never replaces a newer one.
    """
    wazuh = wazuh or Wazuh()

    scope = f"agent {agent_id}" if agent_id is not None else "all agents"
    logger.info("Processing IoV results for %s", scope)

    hits = wazuh.fetch_iov_alerts(_now_ms() - lookback_seconds * 1000, agent_id=agent_id)
    documents = latest_verdicts([hit["_source"] for hit in hits])
    scored = enrich(documents)

    summary = {
        "scanned": len(hits),
        "indexed": len(documents),
        "agents":  len({doc["agent_id"] for doc in documents.values()}),
        **scored,
    }

    if dry_run:
        summary["dry_run"] = True
        return summary | {"documents": documents}

    # Even with nothing to write, so the index exists after a manual run.
    _write(wazuh, documents, summary)
    print(f"IoV results for {scope}: {summary}")
    return summary


# ── Continuous: poll for new alerts ───────────────────────────────────────────

class PollState:
    """Where the poll left off, in Redis.

    The cursor is the newest alert @timestamp handled (epoch millis). Alert
    IDs handled within the overlap window are kept too, scored by timestamp,
    so re-reading the overlap does not write them again.
    """

    CURSOR_KEY = "iov:poll:cursor"
    SEEN_KEY = "iov:poll:seen"

    def __init__(self, client=None):
        self._redis = client or redis.from_url(REDIS_URL, decode_responses=True)

    def cursor(self) -> int | None:
        value = self._redis.get(self.CURSOR_KEY)
        return int(value) if value is not None else None

    def unseen(self, hits: list[dict]) -> list[dict]:
        if not hits:
            return []
        scores = self._redis.zmscore(self.SEEN_KEY, [hit["_id"] for hit in hits])
        return [hit for hit, score in zip(hits, scores, strict=True) if score is None]

    def advance(self, hits: list[dict], cursor: int, overlap_ms: int) -> None:
        """Record hits as handled, move the cursor, and forget IDs that have
        fallen out of the overlap window."""
        pipe = self._redis.pipeline()
        if hits:
            pipe.zadd(self.SEEN_KEY, {hit["_id"]: hit["sort"][0] for hit in hits})
        pipe.set(self.CURSOR_KEY, cursor)
        pipe.zremrangebyscore(self.SEEN_KEY, "-inf", f"({cursor - overlap_ms}")
        pipe.execute()


def poll_new_verdicts(
    wazuh: Wazuh | None = None,
    state: PollState | None = None,
    overlap_seconds: int = POLL_OVERLAP,
) -> dict:
    """Push the verdicts of alerts not handled yet into iov-results.

    Reads from overlap_seconds before the cursor, because an alert can reach
    the indexer after later ones; alerts handled before are skipped by ID. On
    the first poll there is no cursor, and it reads IOV_PROJECTION_LOOKBACK
    back so the current verdicts of every agent are picked up.

    Scores come from cache and FIRST only; CVEs with no cached CVSS get it
    from the next refresh_scores run.
    """
    wazuh = wazuh or Wazuh()
    state = state or PollState()
    overlap_ms = overlap_seconds * 1000

    cursor = state.cursor()
    since = cursor - overlap_ms if cursor is not None else _now_ms() - IOV_PROJECTION_LOOKBACK * 1000

    hits = state.unseen(wazuh.fetch_iov_alerts(since))
    summary = {"new_alerts": len(hits), "indexed": 0}
    if not hits:
        logger.debug("No new IoV verdicts")
        return summary

    documents = latest_verdicts([hit["_source"] for hit in hits])
    scored = enrich(documents, nvd_lookups=0)
    summary |= {
        "indexed": len(documents),
        "agents":  len({doc["agent_id"] for doc in documents.values()}),
        **scored,
    }
    _write(wazuh, documents, summary)

    # Only after the write: a failed poll is retried from the same cursor.
    newest = max(hit["sort"][0] for hit in hits)
    state.advance(hits, max(newest, cursor or 0), overlap_ms)

    print(f"New IoV verdicts: {summary}")
    return summary


# ── Periodic: keep scores current ─────────────────────────────────────────────

def refresh_scores(wazuh: Wazuh | None = None, nvd_lookups: int = NVD_MAX_LOOKUPS_PER_RUN) -> dict:
    """Update EPSS and CVSS on every document in iov-results.

    EPSS changes daily, and the poll only attaches CVSS that is already
    cached, so this backfills CVSS for new CVEs (at most nvd_lookups NVD
    lookups per run) and refreshes EPSS as the cache expires. Documents
    whose scores did not change are no-ops in the indexer.
    """
    wazuh = wazuh or Wazuh()
    # Also brings the index into existence before the first verdict arrives.
    wazuh.ensure_iov_index()

    results = wazuh.list_iov_results()
    epss, cvss = scores_for((r["cve_id"] for r in results), nvd_lookups)

    updates: dict[str, dict] = {}
    for result in results:
        fields = {}
        if result["cve_id"] in epss:
            fields["epss"] = epss[result["cve_id"]]
        if result["cve_id"] in cvss:
            fields["cvss"] = cvss[result["cve_id"]]
        if fields:
            updates[result["_id"]] = fields

    written = wazuh._bulk_update(Wazuh.IOV_INDEX_NAME, updates)
    summary = {
        "documents": len(results),
        "cves":      len({r["cve_id"] for r in results}),
        "epss":      len(epss),
        "cvss":      len(cvss),
        "failed":    len(updates) - written,
    }
    print(f"Score refresh: {summary}")
    return summary

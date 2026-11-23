"""EPSS scores from FIRST and CVSS metrics from NVD, cached in Redis.

Both lookups return only the CVEs they have data for. A CVE left out means
"unknown", never a zero score.
"""
import json
import logging
import time
from itertools import islice

import redis
import requests

from config import (
    CVSS_CACHE_TTL,
    CVSS_MISS_CACHE_TTL,
    EPSS_CACHE_TTL,
    NVD_API_KEY,
    NVD_MAX_LOOKUPS_PER_RUN,
    REDIS_URL,
)

logger = logging.getLogger("etso.cve_info")

_redis = redis.from_url(REDIS_URL, decode_responses=True)

EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD allows 5 requests per rolling 30 s without an API key and 50 with one.
NVD_REQUEST_INTERVAL = 0.6 if NVD_API_KEY else 6.0

# NVD's metric lists and the key each is stored under (no dots: the indexer
# would read "v3.1" as a nested path). The order is the preference for the
# headline score: v3.x first, because nearly every CVE has one, so the
# headline stays comparable across CVEs. v4.0 and v2 remain in "metrics".
_NVD_METRICS = [
    ("cvssMetricV31", "v3_1"),
    ("cvssMetricV30", "v3_0"),
    ("cvssMetricV40", "v4_0"),
    ("cvssMetricV2",  "v2"),
]


def _epss_key(cve_id: str) -> str:
    return f"cve-info:epss:{cve_id}"


def _cvss_key(cve_id: str) -> str:
    return f"cve-info:cvss:{cve_id}"


def chunked(iterable, size):
    it = iter(iterable)
    while chunk := list(islice(it, size)):
        yield chunk


def _cached(key: str) -> tuple[bool, dict | None]:
    """(hit, value). A hit with value None is a cached "no data"."""
    raw = _redis.get(key)
    if raw is None:
        return False, None
    return True, json.loads(raw)


def query_epss(cve_ids: list[str]) -> dict[str, dict]:
    """EPSS score, percentile and date per CVE, as {"score", "percentile", "date"}.

    FIRST takes up to 100 CVEs per request. A failed request is logged and its
    CVEs are left out, so one bad batch does not fail the whole run.
    """
    result: dict[str, dict] = {}
    uncached: list[str] = []

    # One MGET rather than a GET per CVE: the dashboard asks for thousands.
    unique = list(dict.fromkeys(cve_ids))
    cached = _redis.mget([_epss_key(cve_id) for cve_id in unique]) if unique else []
    for cve_id, raw in zip(unique, cached, strict=True):
        if raw is None:
            uncached.append(cve_id)
        elif (entry := json.loads(raw)) is not None:  # a cached "no data" is JSON null
            result[cve_id] = entry

    for batch in chunked(uncached, EPSS_BATCH_SIZE):
        try:
            resp = requests.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=30)
            resp.raise_for_status()
            data = resp.json().get("data", [])
        except (requests.RequestException, ValueError) as exc:
            logger.warning("EPSS lookup failed for %d CVE(s): %s", len(batch), exc)
            continue

        found = {
            entry["cve"]: {
                "score":      float(entry["epss"]),
                "percentile": float(entry["percentile"]),
                "date":       entry.get("date"),
            }
            for entry in data
        }
        # CVEs FIRST has no score for are cached as misses too.
        for cve_id in batch:
            _redis.setex(_epss_key(cve_id), EPSS_CACHE_TTL, json.dumps(found.get(cve_id)))
        result.update(found)

    return result


def cvss_from_nvd_metrics(metrics: dict) -> dict | None:
    """Shape an NVD "metrics" object into the iov-results "cvss" field.

    Keeps one assessment per CVSS version (NVD's own "Primary" one when there
    is one, else the first CNA one), with cvssData flattened into it, and
    picks a headline score for sorting and filtering. None when NVD has no
    CVSS for the CVE.
    """
    per_version: dict[str, dict] = {}
    for nvd_key, name in _NVD_METRICS:
        entries = metrics.get(nvd_key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        flat = {k: v for k, v in entry.items() if k != "cvssData"}
        flat.update(entry.get("cvssData") or {})
        per_version[name] = flat

    if not per_version:
        return None

    headline = next(per_version[name] for _, name in _NVD_METRICS if name in per_version)
    return {
        "base_score": headline.get("baseScore"),
        "version":    headline.get("version"),
        # v2 carries baseSeverity outside cvssData; flattening covers both.
        "severity":   headline.get("baseSeverity"),
        "vector":     headline.get("vectorString"),
        "metrics":    per_version,
    }


def _fetch_nvd_cvss(cve_id: str) -> dict | None:
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    resp = requests.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=30)
    resp.raise_for_status()
    vulnerabilities = resp.json().get("vulnerabilities") or []
    if not vulnerabilities:
        return None
    return cvss_from_nvd_metrics(vulnerabilities[0]["cve"].get("metrics") or {})


def query_cvss(cve_ids: list[str], max_lookups: int = NVD_MAX_LOOKUPS_PER_RUN) -> dict[str, dict]:
    """CVSS metrics per CVE from NVD, shaped by cvss_from_nvd_metrics.

    NVD takes one CVE per request and is heavily rate limited, so at most
    max_lookups uncached CVEs are fetched per call; later runs pick up the
    rest once the earlier ones are cached. A rate-limit response stops the
    lookups for this call.
    """
    result: dict[str, dict] = {}
    lookups = 0
    deferred = 0

    for cve_id in dict.fromkeys(cve_ids):
        hit, entry = _cached(_cvss_key(cve_id))
        if hit:
            if entry is not None:
                result[cve_id] = entry
            continue

        if lookups >= max_lookups:
            deferred += 1
            continue
        if lookups:
            time.sleep(NVD_REQUEST_INTERVAL)
        lookups += 1

        try:
            entry = _fetch_nvd_cvss(cve_id)
        except (requests.RequestException, ValueError, KeyError) as exc:
            logger.warning("NVD lookup failed for %s: %s", cve_id, exc)
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status in (403, 429):
                # Rate limited: every further request this run would fail too.
                max_lookups = lookups
            continue

        ttl = CVSS_CACHE_TTL if entry is not None else CVSS_MISS_CACHE_TTL
        _redis.setex(_cvss_key(cve_id), ttl, json.dumps(entry))
        if entry is not None:
            result[cve_id] = entry

    if deferred:
        logger.info("Deferred NVD lookups for %d CVE(s) to later runs", deferred)
    return result

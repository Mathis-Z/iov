"""Shaping, dedupe and enrichment for the alerts -> iov-results projection.

No indexer, Redis or network required: the lookups are stubbed. Run from wazuh-integration/ with:

    PYTHONPATH=src python3 -m pytest src/tests/test_iov_projection.py
"""

import base64
import json
import zlib

import pytest

import pipeline
from external.cve_info import cvss_from_nvd_metrics
from external.wazuh import Wazuh

to_doc = Wazuh._iov_alert_to_index_doc


def alert(cve="CVE-2026-0001", agent_id="004", level="HIGH", score=3, timestamp="2026-09-24T18:00:00.000+0000"):
    return {
        "@timestamp": timestamp,
        "rule": {"id": "100203", "level": 10, "groups": ["iov", "iov_evaluation"]},
        "agent": {"id": agent_id, "name": f"host-{agent_id}"},
        "location": "evaluate-iov",
        "data": {"iov": {
            "cve": cve,
            "uuid": "2e6b1f0a-9c84-4f3e-bf7a-1d2e5c8a9b3f",
            "score": score,
            "level": level,
            "reason": "kernel-core is affected; the script returned HIGH.",
            "script_result": score,
            "script_ran": True,
            "evaluated_at": "2026-09-24T17:58:31+00:00",
            "packages": [{"name": "kernel-core", "version": "7.2.5-200.fc44", "state": "AFFECTED"}],
        }},
    }


def test_shapes_an_alert_into_an_index_document():
    doc = to_doc(alert())

    assert doc == {
        "agent_id": "004",
        "agent_name": "host-004",
        "cve_id": "CVE-2026-0001",
        "iov_uuid": "2e6b1f0a-9c84-4f3e-bf7a-1d2e5c8a9b3f",
        "iov_score": 3,
        "iov_level": "HIGH",
        "reason": "kernel-core is affected; the script returned HIGH.",
        "script_result": 3,
        "script_ran": True,
        "script_error": None,
        "packages": [{"name": "kernel-core", "version": "7.2.5-200.fc44", "state": "AFFECTED"}],
        "evaluated_at": "2026-09-24T17:58:31+00:00",
        "rule_id": "100203",
        "iov_document": None,
    }


IOV = {"schema_version": 2, "cve": "CVE-2026-0001", "script": "return HIGH",
       "packages": {"kernel": {"names": ["kernel-core"]}}}


def encoded(document):
    return base64.b64encode(zlib.compress(json.dumps(document).encode())).decode()


def with_document(**fields):
    entry = alert()
    entry["data"]["iov"].update(fields)
    return entry


def test_the_attached_iov_is_decoded():
    doc = to_doc(with_document(document=encoded(IOV), document_encoding="zlib+base64"))

    assert doc["iov_document"] == IOV


@pytest.mark.parametrize("fields", [
    {"document_omitted": "true"},                                    # too large to attach
    {"document": "null"},                                            # Wazuh's null
    {"document": encoded(IOV), "document_encoding": "gzip"},         # unknown encoding
    {"document": "!!not base64!!", "document_encoding": "zlib+base64"},
    {"document": base64.b64encode(b"not zlib").decode(), "document_encoding": "zlib+base64"},
    {"document": encoded(["not", "an", "object"]), "document_encoding": "zlib+base64"},
])
def test_a_missing_or_broken_iov_is_null(fields):
    assert to_doc(with_document(**fields))["iov_document"] is None


def test_a_decompression_bomb_is_refused(monkeypatch):
    import external.wazuh as wazuh_module
    monkeypatch.setattr(wazuh_module, "MAX_IOV_DOCUMENT_BYTES", 1000)
    big = {"script": "x" * 5000}

    assert to_doc(with_document(document=encoded(big), document_encoding="zlib+base64"))["iov_document"] is None


def test_every_mapped_field_is_produced():
    # The document must not drift from the index mapping it is written against.
    # EPSS and CVSS are added later by the enrichment, and only when known.
    mapped = set(Wazuh.IOV_INDEX_MAPPINGS["mappings"]["properties"])
    assert set(to_doc(alert())) == mapped - Wazuh.IOV_ENRICHMENT_FIELDS


@pytest.mark.parametrize("unrelated", [
    {"rule": {"id": "5710"}, "data": {"srcip": "1.2.3.4"}},   # someone else's alert
    {"data": {"iov": {}}},                                     # no cve
    {"data": {}},
    {},
])
def test_alerts_without_an_iov_payload_are_ignored(unrelated):
    assert to_doc(unrelated) is None


def test_a_top_level_iov_key_also_works():
    assert to_doc({"agent": {"id": "007"}, "iov": {"cve": "CVE-2026-0002"}})["cve_id"] == "CVE-2026-0002"


def test_wazuh_null_strings_become_real_nulls():
    # analysisd turns the daemon's JSON nulls into the string "null"; an
    # integer field rejects that, so the whole document would fail to index.
    entry = alert()
    entry["data"]["iov"].update(script_result="null", script_ran="false", script_error="null")
    entry["data"]["iov"]["packages"][0]["version"] = "null"

    doc = to_doc(entry)

    assert doc["script_result"] is None
    assert doc["script_error"] is None
    assert doc["packages"][0]["version"] is None


def test_missing_fields_fall_back_to_inconclusive():
    doc = to_doc({"iov": {"cve": "CVE-2026-0003"}, "@timestamp": "2026-09-24T18:00:00.000+0000"})

    assert doc["iov_score"] == -1
    assert doc["iov_level"] == "INCONCLUSIVE"
    assert doc["script_ran"] is False
    assert doc["reason"] == ""
    assert doc["agent_id"] == "000"
    # Falls back to the alert's own timestamp when the agent sent none,
    # normalised to UTC ISO 8601 so evaluated_at values compare as strings.
    assert doc["evaluated_at"] == "2026-09-24T18:00:00+00:00"


@pytest.mark.parametrize("sent, stored", [
    ("2026-09-24T17:58:31+00:00", "2026-09-24T17:58:31+00:00"),
    ("2026-09-24T19:58:31+02:00", "2026-09-24T17:58:31+00:00"),
    ("2026-09-24T17:58:31.123Z",  "2026-09-24T17:58:31+00:00"),
    ("garbage",                   "garbage"),
])
def test_evaluated_at_is_normalised_to_utc(sent, stored):
    entry = alert()
    entry["data"]["iov"]["evaluated_at"] = sent
    assert to_doc(entry)["evaluated_at"] == stored


# ── Dedupe: newest verdict per (agent, CVE) wins ──────────────────────────────

project = pipeline.latest_verdicts


def test_newest_alert_wins_for_the_same_agent_and_cve():
    # fetch_iov_alerts sorts @timestamp desc, so the newest arrives first.
    newest = alert(level="LOW", score=1, timestamp="2026-09-24T18:00:00.000+0000")
    oldest = alert(level="HIGH", score=3, timestamp="2026-09-23T18:00:00.000+0000")

    documents = project([newest, oldest])

    assert len(documents) == 1
    assert documents["004:CVE-2026-0001"]["iov_level"] == "LOW"


def test_documents_are_keyed_per_agent_and_cve():
    documents = project([
        alert(cve="CVE-2026-0001", agent_id="004"),
        alert(cve="CVE-2026-0002", agent_id="004"),
        alert(cve="CVE-2026-0001", agent_id="005"),
    ])

    assert set(documents) == {"004:CVE-2026-0001", "004:CVE-2026-0002", "005:CVE-2026-0001"}


# ── The index is created when needed, never by hand ──────────────────────────

EPSS = {"CVE-2026-0001": {"score": 0.42, "percentile": 0.97, "date": "2026-09-25"}}
CVSS = {"CVE-2026-0001": {"base_score": 7.8, "version": "3.1", "severity": "HIGH",
                          "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "metrics": {}}}


@pytest.fixture(autouse=True)
def stub_lookups(monkeypatch):
    """Stand in for FIRST and NVD: only CVE-2026-0001 has scores."""
    monkeypatch.setattr(pipeline, "query_epss", lambda cve_ids: {c: EPSS[c] for c in cve_ids if c in EPSS})
    monkeypatch.setattr(pipeline, "query_cvss",
                        lambda cve_ids, max_lookups: {c: CVSS[c] for c in cve_ids if c in CVSS})


# Alert timestamps in these tests are offsets from now, so the first poll's
# lookback window includes them.
NOW = pipeline._now_ms()


def hit(entry, alert_id, ts_ms):
    """An alert as fetch_iov_alerts returns it: the raw search hit."""
    return {"_id": alert_id, "_source": entry, "sort": [ts_ms, alert_id]}


class _RecordingWazuh:
    """A Wazuh with the network bits stubbed, so the pipeline can be driven.

    Takes alerts or hits; alerts are wrapped as hits newest first."""

    def __init__(self, alerts, results=()):
        self.hits = [a if "_source" in a else hit(a, f"a{i}", NOW - i) for i, a in enumerate(alerts)]
        self.results = list(results)
        self.ensured = 0
        self.fetched_for = "not fetched"
        self.fetched_since = None
        self.written = None
        self.updated = None
        self.fail_writes = False

    def ensure_iov_index(self):
        self.ensured += 1

    def fetch_iov_alerts(self, since_ms, agent_id=None):
        self.fetched_for = agent_id
        self.fetched_since = since_ms
        return [h for h in self.hits if h["sort"][0] >= since_ms]

    def _bulk_upsert(self, index_name, docs_by_id):
        if self.fail_writes:
            raise ConnectionError("indexer down")
        self.written = (index_name, docs_by_id)
        return len(docs_by_id)

    def _bulk_update(self, index_name, fields_by_id):
        self.updated = (index_name, fields_by_id)
        return len(fields_by_id)

    def list_iov_results(self):
        return self.results


def run_pipeline(instance, **kwargs):
    return pipeline.process_iov_results(lookback_seconds=3600, wazuh=instance, **kwargs)


def test_the_index_is_ensured_before_anything_is_written():
    # The indexer auto-creates an unknown index on write, which would give the
    # verdicts a guessed dynamic mapping. Ensuring must come first.
    fake = _RecordingWazuh([alert()])

    run_pipeline(fake)

    assert fake.ensured == 1
    assert fake.written[0] == Wazuh.IOV_INDEX_NAME == "iov-results"


def test_the_index_is_ensured_even_with_no_verdicts_to_write():
    # Nothing has been evaluated yet, but the index should still come into
    # existence rather than waiting for the first verdict.
    fake = _RecordingWazuh([])

    summary = run_pipeline(fake)

    assert fake.ensured == 1
    assert summary["indexed"] == 0


def test_a_dry_run_creates_nothing():
    fake = _RecordingWazuh([alert()])

    summary = run_pipeline(fake, dry_run=True)

    assert fake.ensured == 0
    assert fake.written is None
    assert summary["dry_run"] is True
    assert set(summary["documents"]) == {"004:CVE-2026-0001"}


def test_all_agents_by_default_or_one_on_request():
    everyone = _RecordingWazuh([])
    run_pipeline(everyone)
    one = _RecordingWazuh([])
    run_pipeline(one, agent_id="004")

    assert everyone.fetched_for is None
    assert one.fetched_for == "004"


# ── EPSS and CVSS ─────────────────────────────────────────────────────────────

def test_scores_are_added_to_every_document_of_the_cve():
    fake = _RecordingWazuh([alert(agent_id="004"), alert(agent_id="005")])

    summary = run_pipeline(fake)

    docs = fake.written[1]
    for doc_id in ("004:CVE-2026-0001", "005:CVE-2026-0001"):
        assert docs[doc_id]["epss"] == EPSS["CVE-2026-0001"]
        assert docs[doc_id]["cvss"] == CVSS["CVE-2026-0001"]
    assert summary["cves"] == summary["epss"] == summary["cvss"] == 1


def test_an_unknown_score_is_left_out_not_nulled():
    # Absent rather than null, so the upsert keeps what an earlier run stored.
    fake = _RecordingWazuh([alert(cve="CVE-2026-0404")])

    run_pipeline(fake)

    doc = fake.written[1]["004:CVE-2026-0404"]
    assert "epss" not in doc and "cvss" not in doc


NVD_METRICS = {
    "cvssMetricV40": [{
        "source": "cna@example.org", "type": "Secondary",
        "cvssData": {"version": "4.0", "baseScore": 8.5, "baseSeverity": "HIGH",
                     "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
    }],
    "cvssMetricV31": [
        {"source": "cna@example.org", "type": "Secondary",
         "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL",
                      "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
         "exploitabilityScore": 3.9, "impactScore": 5.9},
        {"source": "nvd@nist.gov", "type": "Primary",
         "cvssData": {"version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH",
                      "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                      "attackVector": "NETWORK"},
         "exploitabilityScore": 3.9, "impactScore": 3.6},
    ],
    "cvssMetricV2": [{
        "source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "MEDIUM",
        "cvssData": {"version": "2.0", "baseScore": 5.0, "vectorString": "AV:N/AC:L/Au:N/C:N/I:N/A:P"},
        "exploitabilityScore": 10.0, "impactScore": 2.9,
    }],
}


def test_nvd_metrics_keep_one_assessment_per_version_preferring_nvds_own():
    cvss = cvss_from_nvd_metrics(NVD_METRICS)

    assert set(cvss["metrics"]) == {"v4_0", "v3_1", "v2"}
    v31 = cvss["metrics"]["v3_1"]
    assert v31["source"] == "nvd@nist.gov"
    # cvssData is flattened next to the sub-scores.
    assert v31["attackVector"] == "NETWORK"
    assert (v31["exploitabilityScore"], v31["impactScore"]) == (3.9, 3.6)
    assert "cvssData" not in v31


def test_the_headline_score_prefers_cvss_3():
    cvss = cvss_from_nvd_metrics(NVD_METRICS)

    assert (cvss["base_score"], cvss["version"], cvss["severity"]) == (7.5, "3.1", "HIGH")
    assert cvss["vector"].startswith("CVSS:3.1/")


def test_a_v2_only_cve_takes_its_severity_from_outside_cvss_data():
    cvss = cvss_from_nvd_metrics({"cvssMetricV2": NVD_METRICS["cvssMetricV2"]})

    assert (cvss["base_score"], cvss["version"], cvss["severity"]) == (5.0, "2.0", "MEDIUM")


def test_no_cvss_at_all_is_none():
    assert cvss_from_nvd_metrics({}) is None
    assert cvss_from_nvd_metrics({"cvssMetricV31": []}) is None


# ── Polling ───────────────────────────────────────────────────────────────────

class _FakeRedis:
    """Just enough of redis-py for PollState."""

    def __init__(self):
        self.strings = {}
        self.zset = {}

    def get(self, key):
        return self.strings.get(key)

    def set(self, key, value):
        self.strings[key] = str(value)

    def zmscore(self, key, members):
        return [self.zset.get(m) for m in members]

    def zadd(self, key, mapping):
        self.zset.update(mapping)

    def zremrangebyscore(self, key, lo, hi):
        bound = float(hi.lstrip("("))
        self.zset = {m: sc for m, sc in self.zset.items() if sc >= bound}

    def pipeline(self):
        return self

    def execute(self):
        pass


@pytest.fixture
def state():
    return pipeline.PollState(_FakeRedis())


def poll(fake, state, overlap_seconds=60):
    return pipeline.poll_new_verdicts(wazuh=fake, state=state, overlap_seconds=overlap_seconds)


def test_the_first_poll_reads_the_whole_lookback(state, monkeypatch):
    monkeypatch.setattr(pipeline, "_now_ms", lambda: NOW + 5_000)
    fake = _RecordingWazuh([alert()])

    summary = poll(fake, state)

    assert fake.fetched_since == NOW + 5_000 - pipeline.IOV_PROJECTION_LOOKBACK * 1000
    assert summary["indexed"] == 1
    # The newest alert handled, not the current time: later alerts can still
    # carry earlier timestamps.
    assert state.cursor() == NOW


def test_later_polls_read_from_the_cursor_minus_the_overlap(state):
    fake = _RecordingWazuh([alert()])
    poll(fake, state)

    poll(fake, state, overlap_seconds=60)

    assert fake.fetched_since == NOW - 60_000


def test_alerts_already_handled_are_not_written_again(state):
    fake = _RecordingWazuh([alert()])
    poll(fake, state)
    fake.written = None

    summary = poll(fake, state)

    assert summary == {"new_alerts": 0, "indexed": 0}
    assert fake.written is None


def test_a_late_alert_inside_the_overlap_is_picked_up(state):
    fake = _RecordingWazuh([hit(alert(cve="CVE-2026-0001"), "new", NOW)])
    poll(fake, state)
    # Reaches the indexer after the cursor moved past it, but within the overlap.
    fake.hits.append(hit(alert(cve="CVE-2026-0002"), "late", NOW - 10_000))

    summary = poll(fake, state, overlap_seconds=60)

    assert summary["new_alerts"] == 1
    assert set(fake.written[1]) == {"004:CVE-2026-0002"}
    assert state.cursor() == NOW  # never moves backwards


def test_handled_ids_are_forgotten_once_outside_the_overlap(state):
    fake = _RecordingWazuh([hit(alert(cve="CVE-2026-0001"), "old", NOW)])
    poll(fake, state, overlap_seconds=60)
    fake.hits = [hit(alert(cve="CVE-2026-0002"), "new", NOW + 120_000)]

    poll(fake, state, overlap_seconds=60)

    assert state._redis.zset == {"new": NOW + 120_000}


def test_a_failed_write_is_retried_from_the_same_cursor(state):
    fake = _RecordingWazuh([alert()])
    fake.fail_writes = True

    with pytest.raises(ConnectionError):
        poll(fake, state)
    assert state.cursor() is None

    fake.fail_writes = False
    assert poll(fake, state)["indexed"] == 1


def test_the_poll_attaches_only_cached_cvss(state, monkeypatch):
    asked = {}

    def query_cvss(cve_ids, max_lookups):
        asked["max_lookups"] = max_lookups
        return {}

    monkeypatch.setattr(pipeline, "query_cvss", query_cvss)
    poll(_RecordingWazuh([alert()]), state)

    assert asked["max_lookups"] == 0


# ── Score refresh ─────────────────────────────────────────────────────────────

def test_the_refresh_updates_every_document_it_has_scores_for():
    fake = _RecordingWazuh([], results=[
        {"_id": "004:CVE-2026-0001", "cve_id": "CVE-2026-0001"},
        {"_id": "005:CVE-2026-0001", "cve_id": "CVE-2026-0001"},
        {"_id": "004:CVE-2026-0404", "cve_id": "CVE-2026-0404"},
    ])

    summary = pipeline.refresh_scores(wazuh=fake)

    index, updates = fake.updated
    assert index == "iov-results"
    assert set(updates) == {"004:CVE-2026-0001", "005:CVE-2026-0001"}
    assert updates["005:CVE-2026-0001"] == {"epss": EPSS["CVE-2026-0001"], "cvss": CVSS["CVE-2026-0001"]}
    assert summary["documents"] == 3 and summary["cves"] == 2 and summary["failed"] == 0
    assert fake.ensured == 1

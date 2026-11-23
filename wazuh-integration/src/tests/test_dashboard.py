"""Scoring, joining and serving for the prioritisation dashboard.

No indexer, Redis or network required. Run from wazuh-integration/ with:

    PYTHONPATH=src python3 -m pytest src/tests/test_dashboard.py
"""
import pytest

from dashboard import scoring, sources
from dashboard.findings import build_findings, hosts, summarise


def finding(level=None, cvss=7.5, epss=0.01, script_error=None, severity="HIGH"):
    iov = None
    if level is not None:
        iov = {"level": level, "score": {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "ABSENT": 0}.get(level, -1),
               "script_error": script_error, "reason": "r", "evaluated_at": None}
    return {
        "cve_id": "CVE-2026-0001",
        "iov": iov,
        "epss": {"score": epss, "percentile": 0.5} if epss is not None else None,
        "cvss": {"base_score": cvss, "severity": severity, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        if cvss is not None else None,
        "wazuh": {"severity": severity},
    }


def iov_doc(agent="001", cve="CVE-2026-0001", level="HIGH", epss=0.2, cvss=9.8):
    doc = {"agent_id": agent, "agent_name": f"host-{agent}", "cve_id": cve,
           "iov_level": level, "iov_score": {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "ABSENT": 0}.get(level, -1),
           "reason": "r", "packages": [], "evaluated_at": "2026-09-26T10:00:00+00:00"}
    if epss is not None:
        doc["epss"] = {"score": epss, "percentile": 0.9}
    if cvss is not None:
        doc["cvss"] = {"base_score": cvss, "severity": "CRITICAL", "vector": None}
    return doc


def detection(agent="001", cve="CVE-2026-0001", pkg="openssl", base=7.5):
    return {"agent": {"id": agent, "name": f"host-{agent}"}, "host": {"os": {"full": "Ubuntu"}},
            "package": {"name": pkg, "version": "1.0"},
            "vulnerability": {"id": cve, "severity": "High", "score": {"base": base, "version": "3.1"}}}


# ── Scoring ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("epss, threat", [(0.0001, 0), (0.001, 0.25), (0.01, 0.5), (0.1, 0.75), (1.0, 1), (0, 0), (1e-7, 0)])
def test_epss_threat_is_a_quarter_per_decade(epss, threat):
    assert scoring.epss_threat(epss) == pytest.approx(threat)


def test_iov_verdict_orders_the_same_cve():
    scores = {lvl: scoring.score_finding(finding(lvl))["score"] for lvl in ("HIGH", "MEDIUM", "LOW", "ABSENT")}
    assert scores["HIGH"] > scores["MEDIUM"] > scores["LOW"] > scores["ABSENT"] == 0


def test_no_verdict_is_never_safer_than_affected():
    # INCONCLUSIVE, a failed script and a missing IoV must not rank below MEDIUM.
    medium = scoring.score_finding(finding("MEDIUM"))["score"]
    assert scoring.score_finding(finding("INCONCLUSIVE"))["score"] == medium
    assert scoring.score_finding(finding("INCONCLUSIVE", script_error="boom"))["score"] == medium
    assert scoring.score_finding(finding(None))["score"] == medium


def test_absent_is_its_own_band_regardless_of_scores():
    p = scoring.score_finding(finding("ABSENT", cvss=10, epss=0.97))
    assert p["band"]["key"] == "not_affected"
    assert p["what_if"] is None


def test_worked_example():
    # 100 x 0.98 x (0.3 + 0.7 x 0.95...) x 1.0
    p = scoring.score_finding(finding("HIGH", cvss=9.8, epss=0.42))
    assert p["score"] == pytest.approx(100 * 0.98 * scoring.likelihood(0.42), abs=0.05)
    assert p["band"]["key"] == "fix_now"
    assert [f["key"] for f in p["factors"]] == ["impact", "likelihood", "applicability"]


def test_a_likely_exploited_critical_cve_without_iov_is_still_fix_now():
    assert scoring.score_finding(finding(None, cvss=9.8, epss=0.9))["band"]["key"] == "fix_now"


def test_low_verdict_defuses_a_critical_cve():
    assert scoring.score_finding(finding("LOW", cvss=9.8, epss=0.9))["band"]["key"] in ("plan", "fix_soon")


def test_missing_scores_are_assumed_and_said_so():
    p = scoring.score_finding(finding(None, cvss=None, epss=None, severity="CRITICAL"))
    impact, like, _ = p["factors"]
    assert impact["factor"] == pytest.approx(0.95)
    assert like["epss"] == scoring.EPSS_ASSUMED
    assert len(p["assumptions"]) == 2


def test_what_if_brackets_the_neutral_score():
    p = scoring.score_finding(finding(None))
    assert p["what_if"]["LOW"]["score"] < p["score"] < p["what_if"]["HIGH"]["score"]
    assert scoring.score_finding(finding("HIGH"))["what_if"] is None


def test_script_error_is_explained():
    p = scoring.score_finding(finding("INCONCLUSIVE", script_error="parse error"))
    assert p["summary"].startswith("IoV check failed")
    assert any("regenerat" in n for n in p["factors"][2]["notes"])


def test_cvss_vector_is_decoded():
    parts = {p["key"]: p["value"] for p in scoring.parse_cvss_vector("CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N")}
    assert parts["AV"] == "local" and parts["UI"] == "required" and parts["I"] == "none"


def test_parses_iso_and_dashboards_export_times():
    assert scoring.parse_time("2026-09-26T10:00:00Z").hour == 10
    assert scoring.parse_time("Sep 26, 2026 @ 11:54:39.000").minute == 54
    assert scoring.parse_time("garbage") is None


# ── Export CSV ───────────────────────────────────────────────────────────────

def test_reads_the_bundled_export():
    docs = sources.read_export_csv(sources.DEFAULT_DEMO_CSV)
    assert len(docs) == 11
    by_cve = {d["cve_id"]: d for d in docs}
    openssl = by_cve["CVE-2023-0286"]
    assert openssl["iov_score"] == 0 and openssl["script_ran"] is False
    assert openssl["epss"]["score"] == pytest.approx(0.59501)
    assert openssl["cvss"]["base_score"] == 7.4
    assert openssl["packages"][0]["state"] == "UNAFFECTED"
    assert "reason" not in openssl  # the export's " " placeholder is dropped, not kept as text
    assert by_cve["CVE-2026-90003"]["script_error"].startswith("parse error")


# ── Joining ──────────────────────────────────────────────────────────────────

def test_undetected_verdicts_are_findings_and_absent_ones_are_ruled_out():
    docs = [iov_doc("001", level="ABSENT"), iov_doc("002", level="INCONCLUSIVE"), iov_doc("003", level="HIGH")]
    findings, stats = build_findings(docs, detections=[detection("003", cve="CVE-2026-0009")])
    by_agent = {f["agent_id"]: f for f in findings if f["cve_id"] == "CVE-2026-0001"}
    assert set(by_agent) == {"001", "002", "003"}
    assert all(f["source"] == "iov" for f in by_agent.values())
    assert by_agent["001"]["priority"]["band"]["key"] == "not_affected"
    assert by_agent["002"]["priority"]["band"]["key"] != "not_affected"
    assert by_agent["003"]["os"] == "Ubuntu"  # borrowed from the host's other detection
    assert stats == {"iov_only": 3, "wazuh_only": 1, "both": 0}
    assert summarise(findings)["iov"]["ruled_out"] == 1


def test_without_detections_every_verdict_is_a_finding():
    docs = [iov_doc("001", level="ABSENT"), iov_doc("002", level="INCONCLUSIVE")]
    findings, _ = build_findings(docs, detections=None)
    assert len(findings) == 2


def test_detection_packages_collapse_into_one_finding_with_iov_states():
    doc = iov_doc("001", level="LOW") | {"packages": [{"name": "openssl", "version": "1.0", "state": "AFFECTED"}]}
    dets = [detection("001", pkg="openssl"), detection("001", pkg="libssl3")]
    findings, _ = build_findings([doc], dets)
    assert len(findings) == 1
    f = findings[0]
    assert f["source"] == "both"
    assert {p["name"]: p["state"] for p in f["packages"]} == {"openssl": "AFFECTED", "libssl3": None}


def test_scores_are_shared_per_cve_and_detections_fill_cvss():
    docs = [iov_doc("001", level="HIGH", epss=0.3, cvss=9.1)]
    dets = [detection("001"), detection("002"), detection("003", cve="CVE-2026-0002", base=6.1)]
    findings, _ = build_findings(docs, dets, epss_by_cve={"CVE-2026-0002": {"score": 0.002}})
    by_id = {f["id"]: f for f in findings}
    assert by_id["002:CVE-2026-0001"]["epss"]["score"] == 0.3    # borrowed from host 001's IoV document
    assert by_id["002:CVE-2026-0001"]["cvss"]["base_score"] == 9.1
    assert by_id["002:CVE-2026-0001"]["priority"]["iov_level"] == "NOT_ASSESSED"
    assert by_id["003:CVE-2026-0002"]["cvss"]["base_score"] == 6.1  # from the detection
    assert by_id["003:CVE-2026-0002"]["epss"]["score"] == 0.002
    assert [f["rank"] for f in findings] == [1, 2, 3]
    assert findings[0]["id"] == "001:CVE-2026-0001"


def test_summary_and_hosts():
    docs = [iov_doc("001", level="HIGH"), iov_doc("002", level="ABSENT"), iov_doc("001", cve="CVE-2026-0002", level="INCONCLUSIVE") | {"script_error": "x"}]
    findings, _ = build_findings(docs, detections=None)
    s = summarise(findings)
    assert s["urgency"]["key"] == "act_now"
    assert s["urgency"]["driver"]["id"] == "001:CVE-2026-0001"
    assert s["iov"]["ruled_out"] == 1 and s["iov"]["script_error_cves"] == ["CVE-2026-0002"]
    assert s["open"] == 2 and s["bands"]["not_affected"] == 1
    h = {x["agent_id"]: x for x in hosts(findings)}
    assert h["001"]["urgency"]["key"] == "act_now"
    assert h["002"]["urgency"]["key"] == "clear"


def test_empty_estate_is_clear():
    s = summarise([])
    assert s["urgency"]["key"] == "clear" and s["urgency"]["driver"] is None


# ── API ──────────────────────────────────────────────────────────────────────

@pytest.fixture
def client(monkeypatch):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from dashboard import routes

    monkeypatch.setattr(sources, "DASHBOARD_DATA_SOURCE", "demo")
    routes._snapshot.update(built_at=0.0, generation=0, body=None, gzip=None)
    app = fastapi.FastAPI()
    app.include_router(routes.router)
    app.mount("/dashboard/static", routes.static)
    return TestClient(app)


def test_demo_api(client):
    body = client.get("/dashboard/api/findings").json()
    assert body["source"]["kind"] == "demo"
    assert body["summary"]["total"] == len(body["findings"]) > 11
    scores = [f["priority"]["score"] for f in body["findings"]]
    assert scores == sorted(scores, reverse=True)
    # The exported CSV rows are part of the demo.
    assert any(f["cve_id"] == "CVE-2023-0286" and f["priority"]["band"]["key"] == "not_affected" for f in body["findings"])


def test_findings_are_gzipped_when_accepted(client):
    zipped = client.get("/dashboard/api/findings", headers={"Accept-Encoding": "gzip"})
    plain = client.get("/dashboard/api/findings", headers={"Accept-Encoding": "identity"})
    assert zipped.headers["content-encoding"] == "gzip"
    assert "content-encoding" not in plain.headers
    assert zipped.json() == plain.json()


def test_a_stale_snapshot_is_served_and_rebuilt_in_the_background(client, monkeypatch):
    from dashboard import routes

    client.get("/dashboard/api/findings")
    first = routes._snapshot["body"]
    started = []
    monkeypatch.setattr(routes, "_rebuild_in_background", lambda: started.append(True))
    monkeypatch.setattr(routes, "DASHBOARD_CACHE_TTL", -1)
    resp = client.get("/dashboard/api/findings", headers={"Accept-Encoding": "identity"})
    assert resp.content == first      # no waiting for the rebuild
    assert started == [True]


def test_refresh_rebuilds_while_the_viewer_waits(client):
    from dashboard import routes

    client.get("/dashboard/api/findings")
    generation = routes._snapshot["generation"]
    client.get("/dashboard/api/findings?refresh=1")
    assert routes._snapshot["generation"] == generation + 1


def test_page_and_assets_are_served(client):
    assert client.get("/dashboard", follow_redirects=False).status_code == 307
    assert "Vulnerability priorities" in client.get("/dashboard/").text
    assert client.get("/dashboard/static/dashboard.js").status_code == 200


def test_lookups_reject_bad_ids(client):
    assert client.get("/dashboard/api/iov/not-a-cve").status_code == 400
    assert client.get("/dashboard/api/evaluated-iov/001/not-a-cve").status_code == 400
    assert client.get("/dashboard/api/evaluated-iov/..%2F/CVE-2026-0001").status_code in (400, 404)
    assert client.get("/dashboard/api/detection/001/not-a-cve").status_code == 400
    assert client.get("/dashboard/api/detection/..%2F/CVE-2026-0001").status_code in (400, 404)


EVALUATED = {"schema_version": 2, "cve": "CVE-2026-0001", "script": "return HIGH"}


def test_evaluated_iov_is_served_per_finding(client, monkeypatch):
    asked = []

    def lookup(agent_id, cve_id):
        asked.append((agent_id, cve_id))
        return {"iov_document": EVALUATED, "iov_uuid": "u-1", "evaluated_at": "2026-09-26T10:00:00+00:00"}

    monkeypatch.setattr(sources, "evaluated_iov", lookup)
    body = client.get("/dashboard/api/evaluated-iov/004/CVE-2026-0001").json()

    assert asked == [("004", "CVE-2026-0001")]
    assert body == {"uuid": "u-1", "evaluated_at": "2026-09-26T10:00:00+00:00", "document": EVALUATED}


@pytest.mark.parametrize("verdict, says", [
    (None, "No IoV verdict"),
    ({"iov_document": None, "iov_uuid": "u-1"}, "without its IoV"),
])
def test_a_missing_evaluated_iov_is_a_404_that_says_why(client, monkeypatch, verdict, says):
    monkeypatch.setattr(sources, "evaluated_iov", lambda agent_id, cve_id: verdict)
    resp = client.get("/dashboard/api/evaluated-iov/004/CVE-2026-0001")
    assert resp.status_code == 404 and says in resp.json()["detail"]


def test_the_demo_has_no_evaluated_iovs(client):
    assert client.get("/dashboard/api/evaluated-iov/004/CVE-2026-0001").status_code == 404


def _indexer_down(monkeypatch):
    def down():
        raise sources.SourceError("indexer unreachable")

    monkeypatch.setattr(sources, "DASHBOARD_DATA_SOURCE", "indexer")
    monkeypatch.setattr(sources, "load_indexer", down)


def test_indexer_outage_is_a_503_when_there_is_nothing_to_show(client, monkeypatch):
    _indexer_down(monkeypatch)
    resp = client.get("/dashboard/api/findings")
    assert resp.status_code == 503 and "unreachable" in resp.json()["detail"]


def test_indexer_outage_keeps_the_last_snapshot(client, monkeypatch):
    client.get("/dashboard/api/findings")
    _indexer_down(monkeypatch)
    resp = client.get("/dashboard/api/findings?refresh=1")
    assert resp.status_code == 200 and resp.json()["source"]["kind"] == "demo"


# ── Indexer source ───────────────────────────────────────────────────────────

class FakeResponse:
    def __init__(self, status, body=None):
        self.status_code, self._body = status, body

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise sources.requests.HTTPError(str(self.status_code))


def fake_indexer(monkeypatch, iov_docs, detections, page_size=2):
    """A scroll-capable indexer: records every call as (method, path, body)."""
    calls, cursors = [], {}

    def call(path, body, method="post"):
        calls.append((method, path, body))
        if method == "delete":
            return FakeResponse(200, {})
        if path.startswith("_search/scroll"):
            docs, pos = cursors[body["scroll_id"]]
        else:
            index = path.split("/")[0]
            docs = iov_docs if index == sources.IOV_INDEX else detections
            if docs is None:
                return FakeResponse(404)
            pos = 0
        page = docs[pos:pos + page_size]
        sid = f"s{len(calls)}"
        cursors[sid] = (docs, pos + page_size)
        return FakeResponse(200, {"_scroll_id": sid, "hits": {"hits": [{"_source": d} for d in page]}})

    monkeypatch.setattr(sources, "_indexer", call)
    return calls


def test_indexer_scrolls_and_tolerates_a_missing_iov_index(monkeypatch):
    calls = fake_indexer(monkeypatch, None, [detection(str(i).zfill(3)) for i in range(5)])
    monkeypatch.setattr(sources, "_epss_for", lambda ids: {c: {"score": 0.05} for c in ids})
    data = sources.load_indexer()

    assert data["iov_docs"] == [] and len(data["detections"]) == 5
    first = next(c for c in calls if "vulnerabilities" in c[1])
    assert first[2]["_source"] == sources.VULN_FIELDS and first[2]["sort"] == ["_doc"]
    assert "vulnerability.description" not in sources.VULN_FIELDS
    assert [c[0] for c in calls].count("delete") == 1   # the scroll is released
    assert data["epss"] == {"CVE-2026-0001": {"score": 0.05}}  # looked up because no IoV carries it
    findings, _ = build_findings(data["iov_docs"], data["detections"], data["epss"])
    assert len(findings) == 5 and all(f["priority"]["iov_level"] == "NOT_ASSESSED" for f in findings)


def test_the_bulk_read_leaves_the_evaluated_iovs_behind(monkeypatch):
    calls = fake_indexer(monkeypatch, [iov_doc("001")], None)
    sources.load_indexer()

    first = next(c for c in calls if c[1].startswith(sources.IOV_INDEX))
    assert first[2]["_source"] == {"excludes": ["iov_document"]}


def test_one_evaluated_iov_is_read_by_document_id(monkeypatch):
    calls = []

    def call(path, body, method="post"):
        calls.append((method, path))
        if "404" in path:
            return FakeResponse(404)
        return FakeResponse(200, {"_source": {"iov_document": EVALUATED, "evaluated_at": "t"}})

    monkeypatch.setattr(sources, "DASHBOARD_DATA_SOURCE", "indexer")
    monkeypatch.setattr(sources, "_indexer", call)

    assert sources.evaluated_iov("004", "CVE-2026-0001")["iov_document"] == EVALUATED
    method, path = calls[0]
    assert method == "get"
    assert path.startswith("iov-results/_doc/004%3ACVE-2026-0001?")
    assert "_source_includes=iov_document" in path
    assert sources.evaluated_iov("404", "CVE-2026-0001") is None


def test_only_cves_without_epss_in_the_indexer_are_looked_up(monkeypatch):
    fake_indexer(monkeypatch, [iov_doc("001", cve="CVE-2026-0001", epss=0.3)],
                 [detection("002", cve="CVE-2026-0001"), detection("002", cve="CVE-2026-0002")])
    asked = []
    monkeypatch.setattr(sources, "_epss_for", lambda ids: asked.extend(ids) or {})
    sources.load_indexer()
    assert asked == ["CVE-2026-0002"]


def test_unreachable_indexer_is_a_source_error(monkeypatch):
    def call(*args, **kwargs):
        raise sources.requests.ConnectionError("refused")

    monkeypatch.setattr(sources, "_indexer", call)
    with pytest.raises(sources.SourceError, match="unreachable"):
        sources.load_indexer()

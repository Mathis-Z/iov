import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from evaluate_iov import iov_source
from evaluate_iov.iov_source import SyncError, cached_iovs, read_digests, sync


def make_iov(cve: str, note: str = "") -> dict:
    return {"uuid": "2e6b1f0a-9c84-4f3e-bf7a-1d2e5c8a9b3f", "cve": cve,
            "description": f"test {note}", "script": "return LOW"}


class Corpus:
    """The server's view of the world, mutable from inside a test."""

    def __init__(self):
        self.documents: dict[str, dict] = {}
        self.fetched: list[str] = []
        self.fail_for: set[str] = set()

    def digest(self, cve: str) -> str:
        return hashlib.sha256(json.dumps(self.documents[cve]).encode()).hexdigest()


@pytest.fixture
def server():
    corpus = Corpus()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            url = urlparse(self.path)
            query = parse_qs(url.query)
            names = sorted(corpus.documents)

            if url.path == "/api/cves":
                offset = int(query.get("offset", ["0"])[0])
                limit = int(query.get("limit", ["1000"])[0])
                page = names[offset:offset + limit]
                body = {"cves": page, "total": len(names), "offset": offset, "limit": limit}
                if query.get("digests"):
                    body["digests"] = {cve: corpus.digest(cve) for cve in page}
                return self._reply(200, body)

            cve = url.path.removeprefix("/api/")
            corpus.fetched.append(cve)
            if cve in corpus.fail_for:
                return self._reply(500, {"detail": "boom"})
            if cve not in corpus.documents:
                return self._reply(404, {"detail": "Not found"})
            return self._reply(200, corpus.documents[cve])

        def _reply(self, code, body):
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    corpus.url = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield corpus
    httpd.shutdown()
    httpd.server_close()


def test_first_sync_downloads_everything(server, tmp_path):
    server.documents = {f"CVE-2026-000{n}": make_iov(f"CVE-2026-000{n}") for n in (1, 2, 3)}

    report = sync(server.url, tmp_path)

    assert (report.downloaded, report.unchanged, report.removed, report.failed) == (3, 0, 0, 0)
    assert sorted(cve for cve, _ in cached_iovs(tmp_path)) == sorted(server.documents)


def test_unchanged_digests_download_nothing(server, tmp_path):
    server.documents = {"CVE-2026-0001": make_iov("CVE-2026-0001")}
    sync(server.url, tmp_path)
    server.fetched.clear()

    report = sync(server.url, tmp_path)

    assert report.unchanged == 1
    assert report.downloaded == 0
    assert server.fetched == []


def test_changed_digest_is_refetched(server, tmp_path):
    server.documents = {"CVE-2026-0001": make_iov("CVE-2026-0001", "v1")}
    sync(server.url, tmp_path)

    server.documents["CVE-2026-0001"] = make_iov("CVE-2026-0001", "v2")
    report = sync(server.url, tmp_path)

    assert report.downloaded == 1
    assert dict(cached_iovs(tmp_path))["CVE-2026-0001"]["description"] == "test v2"


def test_a_cve_dropped_by_the_server_is_removed_locally(server, tmp_path):
    server.documents = {"CVE-2026-0001": make_iov("CVE-2026-0001"),
                        "CVE-2026-0002": make_iov("CVE-2026-0002")}
    sync(server.url, tmp_path)

    del server.documents["CVE-2026-0002"]
    report = sync(server.url, tmp_path)

    assert report.removed == 1
    assert [cve for cve, _ in cached_iovs(tmp_path)] == ["CVE-2026-0001"]
    assert "CVE-2026-0002" not in read_digests(tmp_path)


def test_one_failing_download_does_not_abort_the_sync(server, tmp_path):
    server.documents = {"CVE-2026-0001": make_iov("CVE-2026-0001"),
                        "CVE-2026-0002": make_iov("CVE-2026-0002")}
    server.fail_for = {"CVE-2026-0001"}

    report = sync(server.url, tmp_path)

    assert report.downloaded == 1
    assert report.failed == 1
    assert [cve for cve, _ in cached_iovs(tmp_path)] == ["CVE-2026-0002"]


def test_a_document_for_the_wrong_cve_is_rejected(server, tmp_path):
    # A document whose own 'cve' disagrees would attribute a verdict to the
    # wrong CVE, so it must never reach the cache.
    server.documents = {"CVE-2026-0001": make_iov("CVE-2026-9999")}

    report = sync(server.url, tmp_path)

    assert report.failed == 1
    assert list(cached_iovs(tmp_path)) == []


def test_pagination_covers_the_whole_corpus(server, tmp_path, monkeypatch):
    monkeypatch.setattr(iov_source, "PAGE_SIZE", 2)
    server.documents = {f"CVE-2026-00{n:02d}": make_iov(f"CVE-2026-00{n:02d}") for n in range(1, 8)}

    report = sync(server.url, tmp_path)

    assert report.downloaded == 7


def test_an_unreachable_server_raises_syncerror(tmp_path):
    with pytest.raises(SyncError):
        sync("http://127.0.0.1:1", tmp_path)


def test_a_failed_sync_leaves_the_cache_usable(server, tmp_path):
    server.documents = {"CVE-2026-0001": make_iov("CVE-2026-0001")}
    sync(server.url, tmp_path)

    with pytest.raises(SyncError):
        sync("http://127.0.0.1:1", tmp_path)

    assert [cve for cve, _ in cached_iovs(tmp_path)] == ["CVE-2026-0001"]


def test_unreadable_cache_entries_are_skipped(tmp_path):
    stored = iov_source.iov_dir(tmp_path)
    stored.mkdir(parents=True)
    (stored / "CVE-2026-0001.iov.json").write_text(json.dumps(make_iov("CVE-2026-0001")))
    (stored / "CVE-2026-0002.iov.json").write_text("{ truncated")

    assert [cve for cve, _ in cached_iovs(tmp_path)] == ["CVE-2026-0001"]


def test_writes_are_atomic(tmp_path, monkeypatch):
    target = tmp_path / "iovs" / "CVE-2026-0001.iov.json"

    def explode(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(iov_source.os, "replace", explode)
    with pytest.raises(OSError):
        iov_source._write_atomic(target, b"partial")

    assert not target.exists()
    assert list(target.parent.iterdir()) == []

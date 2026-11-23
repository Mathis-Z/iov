import base64
import json
import os
import random
import socket
import threading
import zlib

import pytest

from evaluate_iov import daemon, iov_source, wazuh_queue
from evaluate_iov.daemon import Config, build_event, evaluate_pass
from evaluate_iov.evaluation import Result
from evaluate_iov.host import base, kernel
from evaluate_iov.packages import PackageResult
from evaluate_iov.script.interpreter import ScriptOutcome
from evaluate_iov.wazuh_queue import QueueError, frame, send_event


class Listener:
    def __init__(self, sock):
        self._sock = sock

    def received(self) -> list[str]:
        messages = []
        self._sock.settimeout(0.2)
        while True:
            try:
                messages.append(self._sock.recv(65536).decode())
            except TimeoutError:
                return messages


@pytest.fixture
def queue_socket(tmp_path):
    """A real AF_UNIX datagram socket. sun_path is capped at 108 bytes and
    pytest's tmp_path is longer than that, so bind a relative name after
    chdir'ing into it."""
    previous = os.getcwd()
    os.chdir(tmp_path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind("queue.sock")
    try:
        yield Listener(sock)
    finally:
        sock.close()
        os.chdir(previous)


# ── wazuh_queue ───────────────────────────────────────────────────────────────

def test_event_framing():
    assert frame("evaluate-iov", {"a": 1}) == b'1:evaluate-iov:{"a": 1}'


def test_send_event_reaches_the_socket(queue_socket):
    send_event("queue.sock", "evaluate-iov", {"iov": {"cve": "CVE-2026-0001"}})

    assert queue_socket.received() == ['1:evaluate-iov:{"iov": {"cve": "CVE-2026-0001"}}']


def test_a_missing_socket_raises_queueerror(tmp_path):
    with pytest.raises(QueueError):
        send_event(str(tmp_path / "nope.sock"), "evaluate-iov", {"a": 1})


def test_oversized_events_are_refused(queue_socket):
    with pytest.raises(QueueError, match="over the"):
        send_event("queue.sock", "evaluate-iov", {"blob": "x" * wazuh_queue.MAX_EVENT_BYTES})


# ── Event shape ───────────────────────────────────────────────────────────────

def package(name, version, state):
    return PackageResult(name, name, version, "amd64", "debian:12", state, "")


def test_build_event_shape():
    document = {"uuid": "2e6b1f0a-9c84-4f3e-bf7a-1d2e5c8a9b3f", "cve": "CVE-2026-0001",
                "updated": "2026-09-25T10:00:00Z"}
    result = Result(3, "openssh-server is affected; the script returned HIGH.",
                    [package("openssh-server", "1:9.2p1", "AFFECTED")], ScriptOutcome(3), "debian:12")

    event = build_event("CVE-2026-0001", document, result)["iov"]

    assert event["cve"] == "CVE-2026-0001"
    assert event["uuid"] == document["uuid"]
    assert event["iov_updated"] == "2026-09-25T10:00:00Z"
    assert (event["score"], event["level"]) == (3, "HIGH")
    assert event["reason"] == "openssh-server is affected; the script returned HIGH."
    assert (event["script_result"], event["script_ran"], event["script_error"]) == (3, True, None)
    assert event["host_release"] == "debian:12"
    assert event["packages"] == [
        {"key": "openssh-server", "name": "openssh-server", "version": "1:9.2p1", "arch": "amd64",
         "release": "debian:12", "state": "AFFECTED"}
    ]
    assert "packages_truncated" not in event
    assert event["document_encoding"] == "zlib+base64"
    assert "document_omitted" not in event


def decode(encoded):
    return json.loads(zlib.decompress(base64.b64decode(encoded)))


def test_build_event_attaches_the_evaluated_iov():
    document = {"schema_version": 2, "cve": "CVE-2026-0001", "script": "return HIGH",
                "packages": {"openssh": {"names": ["openssh-server"]}}}

    event = build_event("CVE-2026-0001", document, Result(3, "r"))["iov"]

    assert decode(event["document"]) == document


def test_build_event_can_leave_the_iov_out():
    event = build_event("CVE-2026-0001", {"cve": "x"}, Result(3, "r"), include_document=False)["iov"]

    assert "document" not in event
    assert event["document_omitted"] is True


def test_build_event_reports_a_script_error():
    result = Result(2, "r", [], ScriptOutcome(None, "line 3: boom"))
    event = build_event("CVE-2026-0001", {}, result)["iov"]
    assert (event["script_result"], event["script_ran"], event["script_error"]) == (None, True, "line 3: boom")


def test_build_event_reports_inconclusive_as_minus_one():
    event = build_event("CVE-2026-0001", {}, Result(None, "r"))["iov"]

    assert event["score"] == -1
    assert event["level"] == "INCONCLUSIVE"
    assert event["script_ran"] is False


def test_build_event_puts_affected_packages_first_and_truncates(monkeypatch):
    monkeypatch.setattr(daemon, "MAX_EVENT_PACKAGES", 2)
    packages = [package(f"pkg{n}", "1.0", "UNAFFECTED") for n in range(10)]
    packages += [package("zzz", "2.0", "AFFECTED"), package("yyy", "3.0", "UNKNOWN")]

    event = build_event("CVE-2026-0001", {}, Result(2, "r", packages))["iov"]

    assert [p["state"] for p in event["packages"]] == ["AFFECTED", "UNKNOWN"]
    assert event["packages_truncated"] == 10


# ── Evaluation pass ───────────────────────────────────────────────────────────

def write_cached(cache_dir, cve, script="return LOW"):
    stored = iov_source.iov_dir(cache_dir)
    stored.mkdir(parents=True, exist_ok=True)
    (stored / f"{cve}.iov.json").write_text(json.dumps(
        {"schema_version": 2, "uuid": "2e6b1f0a-9c84-4f3e-bf7a-1d2e5c8a9b3f", "cve": cve,
         "description": "test", "script": script}
    ))


def make_config(cache_dir, **overrides):
    defaults = dict(server_url="http://127.0.0.1:1", cache_dir=cache_dir,
                    sync_interval=3600, eval_interval=86400,
                    socket_path="queue.sock", location="evaluate-iov", once=True)
    return Config(**{**defaults, **overrides})


def test_pass_emits_one_event_per_cached_iov(tmp_path, queue_socket):
    for cve in ("CVE-2026-0001", "CVE-2026-0002"):
        write_cached(tmp_path, cve)

    assert evaluate_pass(make_config(tmp_path)) == 2

    events = [json.loads(m.split(":", 2)[2])["iov"] for m in queue_socket.received()]
    assert sorted(e["cve"] for e in events) == ["CVE-2026-0001", "CVE-2026-0002"]
    assert {e["level"] for e in events} == {"LOW"}


def test_the_pass_attaches_each_iov_to_its_verdict(tmp_path, queue_socket):
    write_cached(tmp_path, "CVE-2026-0001", script="return HIGH")

    evaluate_pass(make_config(tmp_path))

    [message] = queue_socket.received()
    event = json.loads(message.split(":", 2)[2])["iov"]
    assert decode(event["document"])["script"] == "return HIGH"


def test_an_iov_too_large_to_attach_still_sends_its_verdict(tmp_path, queue_socket):
    # Incompressible, so it stays over the limit after zlib.
    rng = random.Random(0)
    noise = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(80_000))
    write_cached(tmp_path, "CVE-2026-0001", script=f"// {noise}\nreturn LOW")

    assert evaluate_pass(make_config(tmp_path)) == 1

    [message] = queue_socket.received()
    event = json.loads(message.split(":", 2)[2])["iov"]
    assert event["document_omitted"] is True and "document" not in event
    assert event["level"] in {"LOW", "INCONCLUSIVE"}


def test_one_failing_iov_does_not_abort_the_pass(tmp_path, queue_socket, monkeypatch):
    for cve in ("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"):
        write_cached(tmp_path, cve)

    real_evaluate = daemon.evaluate

    def explode_on_the_second(document):
        if document["cve"] == "CVE-2026-0002":
            raise RuntimeError("boom")
        return real_evaluate(document)

    monkeypatch.setattr(daemon, "evaluate", explode_on_the_second)

    assert evaluate_pass(make_config(tmp_path)) == 2
    assert len(queue_socket.received()) == 2


def test_an_unsendable_event_does_not_abort_the_pass(tmp_path):
    write_cached(tmp_path, "CVE-2026-0001")
    write_cached(tmp_path, "CVE-2026-0002")

    # No socket bound: every publish fails, but every IoV is still evaluated.
    assert evaluate_pass(make_config(tmp_path, socket_path="/nonexistent.sock")) == 2


def test_the_pass_refreshes_the_host_snapshot(tmp_path, queue_socket, monkeypatch):
    calls = []
    monkeypatch.setattr(daemon.base, "reset_caches", lambda: calls.append(1))
    write_cached(tmp_path, "CVE-2026-0001")

    evaluate_pass(make_config(tmp_path))

    # Once per pass, not once per IoV: a single pass must see one consistent
    # snapshot of the host.
    assert calls == [1]


def test_stop_ends_the_pass_early(tmp_path, queue_socket):
    for n in range(5):
        write_cached(tmp_path, f"CVE-2026-000{n + 1}")
    stop = threading.Event()
    stop.set()

    assert evaluate_pass(make_config(tmp_path), stop) == 0


def test_reset_caches_actually_rereads_the_source(monkeypatch):
    calls = []

    def fake_read(path, limit=None):
        calls.append(path)
        return "quiet\n"

    monkeypatch.setattr(kernel, "read_text", fake_read)
    base.reset_caches()

    kernel.kernel_cmdline()
    kernel.kernel_cmdline()
    assert len(calls) == 1

    base.reset_caches()
    kernel.kernel_cmdline()
    assert len(calls) == 2


# ── Configuration ─────────────────────────────────────────────────────────────

def test_server_url_is_required(monkeypatch):
    monkeypatch.delenv("IOV_SERVER_URL", raising=False)
    with pytest.raises(SystemExit):
        daemon.build_config(daemon.parse_args([]))


def test_flags_override_the_environment(monkeypatch):
    monkeypatch.setenv("IOV_SERVER_URL", "http://from-env")
    monkeypatch.setenv("IOV_SYNC_INTERVAL", "120")

    config = daemon.build_config(daemon.parse_args(["--server-url", "http://from-flag"]))

    assert config.server_url == "http://from-flag"
    assert config.sync_interval == 120


def test_a_nonsense_interval_falls_back_to_the_default(monkeypatch):
    monkeypatch.setenv("IOV_SERVER_URL", "http://example")
    monkeypatch.setenv("IOV_EVAL_INTERVAL", "soon")

    config = daemon.build_config(daemon.parse_args([]))

    assert config.eval_interval == daemon.DEFAULT_EVAL_INTERVAL


def test_run_once_syncs_then_evaluates(tmp_path, monkeypatch):
    order = []
    monkeypatch.setattr(daemon, "sync_pass", lambda config: order.append("sync"))
    monkeypatch.setattr(daemon, "evaluate_pass", lambda config, stop: order.append("evaluate"))

    assert daemon.run(make_config(tmp_path), threading.Event()) == 0
    assert order == ["sync", "evaluate"]


def test_a_failed_sync_still_evaluates(tmp_path, queue_socket):
    write_cached(tmp_path, "CVE-2026-0001")

    # server_url points at a closed port, so the sync raises and is swallowed.
    assert daemon.run(make_config(tmp_path), threading.Event()) == 0
    assert len(queue_socket.received()) == 1

"""wazuh-evaluate-iov-daemon — keep this host's IoV verdicts current.

Syncs the IoV corpus from the IoV server into a local cache, evaluates every
cached IoV against the host one at a time, and publishes each verdict through
the local Wazuh agent's queue socket.

It evaluates once on startup, so starting at boot is itself a re-evaluation --
which is the point: a reboot can change the running kernel, the loaded modules
and the installed packages, and every cached verdict is stale until it is
recomputed. After that it loops on two independent intervals, one for syncing
the corpus and one for re-evaluating the host.

An unreachable server is a warning, never a stop: evaluation always runs
against whatever the cache holds.

    wazuh-evaluate-iov-daemon --once --log-level DEBUG

Configuration comes from the environment (see
wazuh-integration/installation/endpoints/daemon.env.example), with command-line
flags overriding it.
"""

import argparse
import base64
import json
import logging
import os
import signal
import threading
import time
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import NamedTuple

from . import AGENT_VERSION, iov_source, wazuh_queue
from .evaluation import evaluate
from .host import base
from .iov_source import SyncError
from .logging_setup import LOGGER_NAME, configure_logging
from .wazuh_queue import QueueError

log = logging.getLogger(LOGGER_NAME)

DEFAULT_CACHE_DIR = "/var/lib/wazuh-evaluate-iov"
DEFAULT_SYNC_INTERVAL = 3600      # 1 hour
DEFAULT_EVAL_INTERVAL = 86400     # 1 day

# Datagrams are size-limited, so a host with hundreds of matching packages
# reports the most telling ones rather than being dropped by analysisd.
MAX_EVENT_PACKAGES = 50
STATE_ORDER = {"AFFECTED": 0, "UNKNOWN": 1, "UNAFFECTED": 2}

# The evaluated IoV travels with its verdict, so the dashboard can show what led
# to it. It goes as one compressed string, not as nested JSON: analysisd would
# split nested JSON into one alert field per key, which grows the
# wazuh-alerts-* mapping with every new IoV, and the alerts template indexes
# strings as keywords, which the indexer rejects above 32 KB. Compressed, IoVs
# are a fraction of that (the largest so far, ~20 KB of JSON, is ~6 KB).
DOCUMENT_ENCODING = "zlib+base64"


class Config(NamedTuple):
    """The daemon's settings, from flags and the environment."""
    server_url: str
    cache_dir: Path
    sync_interval: int
    eval_interval: int
    socket_path: str
    location: str
    once: bool


def _env_int(name: str, default: int) -> int:
    """An interval in seconds from the environment, at least 60."""
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return max(60, int(raw))
    except ValueError:
        log.warning("%s=%r is not a number, using %d", name, raw, default)
        return default


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the command line of wazuh-evaluate-iov-daemon."""
    parser = argparse.ArgumentParser(
        prog="wazuh-evaluate-iov-daemon",
        description="Sync Indicators of Vulnerability and evaluate them against this host.",
    )
    parser.add_argument("--server-url", default=None,
                        help="base URL of the IoV server (env: IOV_SERVER_URL)")
    parser.add_argument("--cache-dir", default=None,
                        help=f"local IoV cache (env: IOV_CACHE_DIR, default {DEFAULT_CACHE_DIR})")
    parser.add_argument("--sync-interval", type=int, default=None, metavar="SECONDS",
                        help="how often to pull new IoVs (env: IOV_SYNC_INTERVAL)")
    parser.add_argument("--eval-interval", type=int, default=None, metavar="SECONDS",
                        help="how often to re-evaluate the host (env: IOV_EVAL_INTERVAL)")
    parser.add_argument("--socket", default=None, dest="socket_path",
                        help="Wazuh agent queue socket (env: WAZUH_QUEUE_SOCKET)")
    parser.add_argument("--location", default=None,
                        help="event location field (env: IOV_EVENT_LOCATION)")
    parser.add_argument("--once", action="store_true",
                        help="run one sync and one evaluation pass, then exit")
    parser.add_argument("--log-level", default=None, metavar="LEVEL",
                        help="DEBUG, INFO (default), WARNING, ERROR")
    return parser.parse_args(argv)


def build_config(args: argparse.Namespace) -> Config:
    """Combine flags and environment into a Config; exits if no server is set."""
    server_url = args.server_url or os.environ.get("IOV_SERVER_URL", "")
    if not server_url:
        raise SystemExit(
            "wazuh-evaluate-iov-daemon: no IoV server configured "
            "(set IOV_SERVER_URL or pass --server-url)"
        )
    return Config(
        server_url=server_url,
        cache_dir=Path(args.cache_dir or os.environ.get("IOV_CACHE_DIR", DEFAULT_CACHE_DIR)),
        sync_interval=args.sync_interval or _env_int("IOV_SYNC_INTERVAL", DEFAULT_SYNC_INTERVAL),
        eval_interval=args.eval_interval or _env_int("IOV_EVAL_INTERVAL", DEFAULT_EVAL_INTERVAL),
        socket_path=(args.socket_path or os.environ.get("WAZUH_QUEUE_SOCKET")
                     or wazuh_queue.default_socket_path()),
        location=args.location or os.environ.get("IOV_EVENT_LOCATION",
                                                 wazuh_queue.DEFAULT_LOCATION),
        once=args.once,
    )


# ── Events ────────────────────────────────────────────────────────────────────

def encode_document(document: dict) -> str:
    """The IoV as DOCUMENT_ENCODING: compact JSON, zlib-compressed, base64."""
    raw = json.dumps(document, separators=(",", ":")).encode()
    return base64.b64encode(zlib.compress(raw, 9)).decode("ascii")


def build_event(cve: str, document: dict, result, include_document: bool = True) -> dict:
    """Turn one evaluation into the event the manager will index."""
    packages = sorted(
        (p.as_dict() for p in result.packages),
        key=lambda entry: (STATE_ORDER.get(entry["state"], 9), entry["name"] or entry["key"]),
    )
    script = result.script

    event = {
        "cve":           cve,
        "uuid":          document.get("uuid"),
        "iov_updated":   document.get("updated"),
        "score":         result.iov_score,
        "level":         result.level,
        "reason":        result.reason,
        "script_result": script.value if script else None,
        "script_ran":    script is not None,
        "script_error":  script.error if script else None,
        "host_release":  result.host_release,
        "agent_version": AGENT_VERSION,
        "evaluated_at":  datetime.now(UTC).isoformat(timespec="seconds"),
        "packages":      packages[:MAX_EVENT_PACKAGES],
    }
    if len(packages) > MAX_EVENT_PACKAGES:
        event["packages_truncated"] = len(packages) - MAX_EVENT_PACKAGES
    if include_document:
        event["document"] = encode_document(document)
        event["document_encoding"] = DOCUMENT_ENCODING
    else:
        event["document_omitted"] = True
    return {"iov": event}


def publish(config: Config, cve: str, document: dict, result) -> None:
    """Send one verdict with its IoV attached, or without the IoV if that
    makes the event too large: the verdict matters more than its explanation.
    Raises QueueError if even that cannot be sent."""
    event = build_event(cve, document, result)
    if len(wazuh_queue.frame(config.location, event)) > wazuh_queue.MAX_EVENT_BYTES:
        log.warning("%s: the IoV is too large to attach, sending the verdict without it", cve)
        event = build_event(cve, document, result, include_document=False)
    wazuh_queue.send_event(config.socket_path, config.location, event)


# ── Passes ────────────────────────────────────────────────────────────────────

def sync_pass(config: Config) -> None:
    """Best-effort corpus refresh. A failure leaves the cache as it was."""
    try:
        iov_source.sync(config.server_url, config.cache_dir)
    except SyncError as exc:
        log.warning("IoV sync failed, continuing with the cached corpus: %s", exc)


def evaluate_pass(config: Config, stop: threading.Event | None = None) -> int:
    """Evaluate every cached IoV, serially, and publish each verdict.

    Returns the number of IoVs evaluated. One IoV failing never aborts the pass.
    """
    # The host has almost certainly changed since the last pass.
    base.reset_caches()

    evaluated = sent = failed = 0
    started = time.monotonic()

    for cve, document in iov_source.cached_iovs(config.cache_dir):
        if stop is not None and stop.is_set():
            log.info("stop requested, ending the evaluation pass early")
            break
        try:
            result = evaluate(document)
        except Exception:
            log.exception("evaluating %s failed", cve)
            failed += 1
            continue
        evaluated += 1
        log.debug("%s -> %s", cve, result.score)

        try:
            publish(config, cve, document, result)
            sent += 1
        except QueueError as exc:
            # The next pass re-sends everything, so there is nothing to spool.
            log.warning("could not publish %s: %s", cve, exc)

    log.info(
        "evaluation pass: %d evaluated, %d published, %d failed, in %.1fs",
        evaluated, sent, failed, time.monotonic() - started,
    )
    return evaluated


# ── Main loop ─────────────────────────────────────────────────────────────────

def run(config: Config, stop: threading.Event) -> int:
    """Sync and evaluate until stopped (or once, with --once). Returns the exit code."""
    log.info(
        "starting: server=%s cache=%s socket=%s sync=%ds eval=%ds",
        config.server_url, config.cache_dir, config.socket_path,
        config.sync_interval, config.eval_interval,
    )

    last_sync = last_eval = None
    while not stop.is_set():
        now = time.monotonic()
        if last_sync is None or now - last_sync >= config.sync_interval:
            sync_pass(config)
            last_sync = now
        if last_eval is None or now - last_eval >= config.eval_interval:
            evaluate_pass(config, stop)
            last_eval = time.monotonic()

        if config.once:
            break

        due = min(last_sync + config.sync_interval, last_eval + config.eval_interval)
        stop.wait(max(1.0, due - time.monotonic()))

    log.info("stopped")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse the configuration, install signal handlers and run the daemon."""
    args = parse_args(argv)
    configure_logging(args.log_level)
    config = build_config(args)

    stop = threading.Event()

    def request_stop(signum, _frame):
        # Set the flag rather than exiting: the IoV in flight finishes first,
        # which is what systemd's stop expects.
        log.info("received signal %d, finishing the current IoV", signum)
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    return run(config, stop)


def run_entrypoint() -> None:
    """Console entrypoint."""
    raise SystemExit(main())

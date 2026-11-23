"""Mirroring the IoV corpus from the IoV server into a local cache.

The cache is what makes the daemon useful at boot: evaluation runs against
whatever is on disk, so an unreachable server delays fresh IoVs but never
stops the host from being evaluated.

The server offers no ETag, Last-Modified or version field, so change detection
runs on the per-IoV content digest that `GET /api/cves?digests=1` returns.
"""

import functools
import json
import logging
import os
import re
import ssl
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple
from urllib import error, parse, request

from .logging_setup import LOGGER_NAME

log = logging.getLogger(LOGGER_NAME)

CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
PAGE_SIZE = 1000
TIMEOUT = 30
MAX_IOV_BYTES = 4 * 1024 * 1024

# Where the common distributions keep their CA bundle. The packaged binary's
# OpenSSL only knows the build host's layout, so it has to be told.
SYSTEM_CA_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",                # Debian, Ubuntu, Alpine, Arch
    "/etc/pki/tls/certs/ca-bundle.crt",                  # RHEL, Fedora
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", # RHEL, Fedora
    "/etc/ssl/ca-bundle.pem",                            # SUSE
)


class SyncError(Exception):
    """The corpus could not be synced; the existing cache stays usable."""


class SyncReport(NamedTuple):
    """Counts of one sync."""
    downloaded: int
    removed: int
    unchanged: int
    failed: int


@functools.cache
def _ssl_context() -> ssl.SSLContext:
    """Trust the host's CA bundle, falling back to certifi's when it has none."""
    if os.environ.get("SSL_CERT_FILE") or os.environ.get("SSL_CERT_DIR"):
        return ssl.create_default_context()
    cafile = next((path for path in SYSTEM_CA_BUNDLES if os.path.isfile(path)), None)
    if cafile is None:
        import certifi
        cafile = certifi.where()
    log.debug("using CA bundle %s", cafile)
    return ssl.create_default_context(cafile=cafile)


def _get(url: str) -> bytes:
    log.debug("GET %s", url)
    try:
        context = _ssl_context() if url.startswith("https:") else None
        with request.urlopen(url, timeout=TIMEOUT, context=context) as response:
            return response.read(MAX_IOV_BYTES)
    except error.HTTPError as exc:
        raise SyncError(f"{url} -> HTTP {exc.code}") from exc
    except Exception as exc:
        raise SyncError(f"{url} -> {exc}") from exc


def list_remote(base_url: str) -> dict[str, str]:
    """Page through /api/cves and return {cve: digest} for the whole corpus."""
    base = base_url.rstrip("/")
    digests: dict[str, str] = {}
    offset = 0

    while True:
        query = parse.urlencode({"offset": offset, "limit": PAGE_SIZE, "digests": 1})
        try:
            body = json.loads(_get(f"{base}/api/cves?{query}"))
        except json.JSONDecodeError as exc:
            raise SyncError(f"{base}/api/cves returned invalid JSON: {exc}") from exc

        page = body.get("cves") or []
        page_digests = body.get("digests") or {}
        for cve in page:
            digests[cve] = page_digests.get(cve, "")

        offset += len(page)
        total = body.get("total", offset)
        if not page or offset >= total:
            break

    log.info("server lists %d IoV(s)", len(digests))
    return digests


def fetch(base_url: str, cve: str) -> bytes:
    """Download one IoV document, verifying it is the one we asked for."""
    raw = _get(f"{base_url.rstrip('/')}/api/{cve}")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SyncError(f"{cve}: server returned invalid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SyncError(f"{cve}: server did not return an IoV object")
    # A document whose own 'cve' disagrees means the corpus is inconsistent;
    # caching it would attribute the verdict to the wrong CVE.
    if document.get("cve") != cve:
        raise SyncError(f"{cve}: server returned a document for {document.get('cve')!r}")
    return raw


# ── Local cache ───────────────────────────────────────────────────────────────

def iov_dir(cache_dir: Path) -> Path:
    """The directory holding the cached IoV documents."""
    return cache_dir / "iovs"


def _digest_file(cache_dir: Path) -> Path:
    return cache_dir / "digests.json"


def read_digests(cache_dir: Path) -> dict[str, str]:
    """The digests of the cached IoVs, {} if there is no readable index."""
    try:
        digests = json.loads(_digest_file(cache_dir).read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return digests if isinstance(digests, dict) else {}


def _write_atomic(path: Path, data: bytes) -> None:
    """Write via a temp file in the same directory, so a crash mid-write can
    never leave a truncated IoV that would later parse as garbage."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(handle, "wb") as temp_file:
            temp_file.write(data)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temp_name, path)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise


def sync(base_url: str, cache_dir: Path) -> SyncReport:
    """Bring the local cache in line with the server.

    Raises SyncError only if the listing itself fails. A single IoV that cannot
    be downloaded is counted and skipped, leaving its cached copy in place.
    """
    remote = list_remote(base_url)
    local = read_digests(cache_dir)
    stored = iov_dir(cache_dir)

    downloaded = unchanged = failed = 0
    digests = dict(local)

    for cve, digest in remote.items():
        if not CVE_RE.match(cve):
            log.warning("server listed a malformed CVE id %r, skipping", cve)
            continue
        path = stored / f"{cve}.iov.json"
        if digest and local.get(cve) == digest and path.exists():
            unchanged += 1
            continue
        try:
            _write_atomic(path, fetch(base_url, cve))
        except (SyncError, OSError) as exc:
            log.warning("could not cache %s: %s", cve, exc)
            failed += 1
            continue
        digests[cve] = digest
        downloaded += 1

    removed = 0
    for cve in set(digests) - set(remote):
        (stored / f"{cve}.iov.json").unlink(missing_ok=True)
        del digests[cve]
        removed += 1

    # Written last: if this fails the worst case is re-downloading next time.
    _write_atomic(_digest_file(cache_dir), json.dumps(digests, indent=2).encode())

    report = SyncReport(downloaded, removed, unchanged, failed)
    log.info(
        "sync: %d downloaded, %d removed, %d unchanged, %d failed",
        *report,
    )
    return report


def cached_iovs(cache_dir: Path) -> Iterator[tuple[str, dict]]:
    """Yield (cve, document) for every usable IoV in the cache, in CVE order."""
    stored = iov_dir(cache_dir)
    try:
        paths = sorted(stored.glob("CVE-*.iov.json"))
    except OSError as exc:
        log.error("cannot read the IoV cache at %s: %s", stored, exc)
        return

    for path in paths:
        try:
            document = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("skipping unreadable cached IoV %s: %s", path.name, exc)
            continue
        if isinstance(document, dict):
            yield path.name.removesuffix(".iov.json"), document

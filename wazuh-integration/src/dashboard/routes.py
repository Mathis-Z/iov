"""/dashboard: the prioritisation page and the JSON it renders.

All URLs the page uses are relative, so it keeps working behind a reverse
proxy that serves ETSO under a path prefix.

Building the findings means reading the whole vulnerability index, which takes
seconds, so it never happens while a viewer waits unless there is nothing to
show yet: the last build is served as prepared JSON, and one older than
DASHBOARD_CACHE_TTL is rebuilt in the background.
"""
import gzip
import json
import logging
import re
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import requests
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from config import DASHBOARD_CACHE_TTL, IOV_PUBLIC_URL, IOV_SOURCE_URL
from dashboard import sources
from dashboard.findings import build_findings, hosts, summarise
from dashboard.scoring import model_description

logger = logging.getLogger("etso.dashboard")

STATIC_DIR = Path(__file__).parent / "static"
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
IOV_CACHE_TTL = 600

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
static = StaticFiles(directory=STATIC_DIR)

_iov_cache: dict[str, tuple[float, dict | None]] = {}

# The last build: its JSON, gzipped once, when it was built, and a counter of
# builds (a clock can tick too coarsely to tell two builds apart).
_snapshot: dict = {"built_at": 0.0, "generation": 0, "body": None, "gzip": None}
_build_lock = threading.Lock()


@router.get("", include_in_schema=False)
def dashboard_redirect():
    # Without the trailing slash the page's relative URLs resolve one level up.
    return RedirectResponse(url="dashboard/")


@router.get("/", include_in_schema=False)
def dashboard_page():
    return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})


def _payload() -> dict:
    data = sources.load()
    findings, stats = build_findings(data["iov_docs"], data["detections"], data["epss"])
    return {
        "source": data["source"] | {"detections": data["detections"] is not None},
        "loaded_at": datetime.fromtimestamp(data["loaded_at"], UTC).isoformat(),
        "model": model_description(),
        "summary": summarise(findings) | {"stats": stats},
        "hosts": hosts(findings),
        "findings": findings,
        "links": {"iov_server": IOV_PUBLIC_URL or None},
    }


def rebuild() -> None:
    """Build and store a new snapshot. A caller that waited for another build
    to finish uses that one instead of starting its own."""
    seen = _snapshot["generation"]
    with _build_lock:
        if _snapshot["generation"] != seen:
            return  # another build finished while this caller waited
        started = time.monotonic()
        # json.dumps directly: FastAPI's generic encoder took seconds on this.
        body = json.dumps(_payload(), separators=(",", ":")).encode()
        _snapshot.update(built_at=time.monotonic(), generation=_snapshot["generation"] + 1,
                         body=body, gzip=gzip.compress(body, compresslevel=5))
        logger.info("Dashboard snapshot built in %.1fs (%.1f MB, %.1f MB gzipped)",
                    time.monotonic() - started, len(body) / 1e6, len(_snapshot["gzip"]) / 1e6)


def _rebuild_in_background() -> None:
    if _build_lock.locked():
        return  # one is running already

    def run():
        try:
            rebuild()
        except Exception:  # keep serving the previous snapshot
            logger.exception("Dashboard background rebuild failed")

    threading.Thread(target=run, name="dashboard-rebuild", daemon=True).start()


@router.get("/api/findings")
def api_findings(request: Request, refresh: bool = Query(default=False)):
    if refresh or _snapshot["body"] is None:
        try:
            rebuild()
        except sources.SourceError as exc:
            logger.error("Dashboard data unavailable: %s", exc)
            if _snapshot["body"] is None:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
    elif time.monotonic() - _snapshot["built_at"] > DASHBOARD_CACHE_TTL:
        _rebuild_in_background()

    headers = {"Cache-Control": "no-store", "Vary": "Accept-Encoding"}
    if "gzip" in request.headers.get("accept-encoding", ""):
        return Response(_snapshot["gzip"], media_type="application/json",
                        headers=headers | {"Content-Encoding": "gzip"})
    return Response(_snapshot["body"], media_type="application/json", headers=headers)


@router.get("/api/detection/{agent_id}/{cve_id}")
def api_detection(agent_id: str, cve_id: str):
    """The scanner's description of one finding, which the bulk read skips."""
    if not CVE_RE.match(cve_id) or not agent_id.isalnum():
        raise HTTPException(status_code=400, detail="Invalid agent or CVE ID")
    try:
        details = sources.detection_details(agent_id, cve_id)
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh indexer unreachable: {exc}") from exc
    if not details:
        raise HTTPException(status_code=404, detail="No detection")
    return {"description": details.get("description"), "reference": details.get("reference")}


@router.get("/api/evaluated-iov/{agent_id}/{cve_id}")
def api_evaluated_iov(agent_id: str, cve_id: str):
    """The IoV this host's verdict was evaluated from, exactly as the agent had
    it. Fetched per finding when the viewer asks: IoVs are several KB each, too
    much to send with every finding."""
    if not CVE_RE.match(cve_id) or not agent_id.isalnum():
        raise HTTPException(status_code=400, detail="Invalid agent or CVE ID")
    try:
        verdict = sources.evaluated_iov(agent_id, cve_id)
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh indexer unreachable: {exc}") from exc
    if verdict is None:
        raise HTTPException(status_code=404, detail="No IoV verdict for this host and CVE.")
    if not verdict.get("iov_document"):
        raise HTTPException(
            status_code=404,
            detail="The agent sent this verdict without its IoV: an older IoV daemon, "
                   "or an IoV too large to attach.",
        )
    return {
        "uuid": verdict.get("iov_uuid"),
        "evaluated_at": verdict.get("evaluated_at"),
        "document": verdict["iov_document"],
    }


@router.get("/api/iov/{cve_id}")
def api_iov(cve_id: str):
    """The IoV document's human-readable parts, fetched server-side: the IoV
    server may only be reachable from ETSO, and this keeps the page free of
    cross-origin requests."""
    if not CVE_RE.match(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE ID")
    if not IOV_SOURCE_URL:
        raise HTTPException(status_code=404, detail="No IoV server configured")

    cached = _iov_cache.get(cve_id)
    if cached and time.monotonic() - cached[0] < IOV_CACHE_TTL:
        doc = cached[1]
    else:
        try:
            resp = requests.get(f"{IOV_SOURCE_URL.rstrip('/')}/api/{cve_id}", timeout=5)
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail=f"IoV server unreachable: {exc}") from exc
        doc = resp.json() if resp.status_code == 200 else None
        _iov_cache[cve_id] = (time.monotonic(), doc)

    if doc is None:
        raise HTTPException(status_code=404, detail="No IoV for this CVE")
    return {
        "cve": doc.get("cve", cve_id),
        "uuid": doc.get("uuid"),
        "description": doc.get("description"),
        "references": doc.get("references") or [],
        "has_script": bool(doc.get("script")),
        "packages": sorted((doc.get("packages") or {}).keys()),
        "created": doc.get("created"),
        "updated": doc.get("updated"),
    }

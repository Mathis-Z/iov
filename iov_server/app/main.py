"""FastAPI app: the IoV API, the admin page and a read-only web front end."""

import hashlib
import json
import logging
import re
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Annotated

import requests
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.config import ADMIN_TOKEN, DATA_DIR, DEBUG
from app.storage import IOV_SUFFIX, iov_path, log_path, status_path, write_atomic
from app.tasks import celery_app, generate_iov

_log_dir = DATA_DIR / "logs"
_log_dir.mkdir(parents=True, exist_ok=True)
_file_handler = logging.FileHandler(_log_dir / "server.log")
_file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
logging.root.addHandler(_file_handler)
logging.root.setLevel(logging.INFO)
for _name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
    logging.getLogger(_name).addHandler(_file_handler)

log = logging.getLogger(__name__)

CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
MAX_LIST_LIMIT = 1000
TASK_TIMEOUT = timedelta(minutes=30)  # a pending generation older than this is requeued
MAX_FAILURES = 3  # attempts before a CVE is marked failed


@asynccontextmanager
async def lifespan(_: FastAPI):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not DEBUG and not ADMIN_TOKEN:
        raise RuntimeError("ADMIN_TOKEN must be set unless DEBUG=1.")
    yield


app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


# ── Auth helpers ──────────────────────────────────────────────────────────────

def _is_admin(authorization: str | None) -> bool:
    """In DEBUG mode an empty ADMIN_TOKEN grants everyone admin access."""
    if not ADMIN_TOKEN.strip():
        return DEBUG
    return authorization == f"Bearer {ADMIN_TOKEN}"


def _require_admin(authorization: Annotated[str | None, Header()] = None) -> None:
    if not _is_admin(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")


# ── Shared helpers ────────────────────────────────────────────────────────────

def _iter_completed_iovs():
    """Yield (cve_id, data, path) for every successfully generated IoV on disk."""
    for path in sorted(DATA_DIR.glob(f"CVE-*{IOV_SUFFIX}")):
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        yield path.name.removesuffix(IOV_SUFFIX), data, path


def _get_completed_cves(limit: int) -> tuple[list[str], int]:
    """Return (cves[:limit], total_count) of completed IoVs on disk."""
    cves = [cve_id for cve_id, _, _ in _iter_completed_iovs()]
    return cves[:limit], len(cves)


@lru_cache(maxsize=8192)
def _digest_cached(path: str, mtime_ns: int, size: int) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _file_digest(path: Path) -> str:
    """SHA-256 of the stored document, memoised on the file's mtime and size.

    Clients polling for changes have nothing else to go on: an IoV carries no
    version field and these responses set no ETag or Last-Modified.
    """
    stat = path.stat()
    return _digest_cached(str(path), stat.st_mtime_ns, stat.st_size)


def _cve_exists(cve_id: str) -> bool:
    """Check MITRE's public CVE API. Fails open on network errors."""
    try:
        resp = requests.get(f"https://cveawg.mitre.org/api/cve/{cve_id}", timeout=10)
        return resp.status_code == 200
    except requests.RequestException as e:
        log.warning("CVE existence check failed for %s: %s", cve_id, e)
        return True


# ── Public HTML routes ────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    cves, total = _get_completed_cves(limit=30)
    return templates.TemplateResponse(request, "list.html", context={
        "cves":      cves,
        "total":     total,
        "truncated": total > 30,
    })


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request):
    return templates.TemplateResponse(request, "admin.html", context={})


# ── API routes ────────────────────────────────────────────────────────────────

@app.get("/api/cves")
def api_list_cves(offset: int = 0, limit: int = MAX_LIST_LIMIT, digests: bool = False):
    """Page through the completed CVE IDs.

    With digests=1 the response also carries a content hash per CVE, so a
    client that mirrors the corpus can tell what actually changed.
    """
    entries = [(cve_id, path) for cve_id, _, path in _iter_completed_iovs()]
    offset  = max(offset, 0)
    limit   = max(1, min(limit, MAX_LIST_LIMIT))
    page    = entries[offset:offset + limit]

    body = {
        "cves":   [cve_id for cve_id, _ in page],
        "total":  len(entries),
        "offset": offset,
        "limit":  limit,
    }
    if digests:
        body["digests"] = {cve_id: _file_digest(path) for cve_id, path in page}
    return body


@app.get("/api/bulk")
def api_bulk_download_iov(_: None = Depends(_require_admin)):
    """Return every successfully generated IoV document, in full.
    Registered before "/api/{cve_id}" so it isn't shadowed by it."""
    return {"items": [data for _, data, _ in _iter_completed_iovs()]}


@app.get("/api/{cve_id}")
def api_get_iov(cve_id: str, authorization: Annotated[str | None, Header()] = None):
    if not CVE_RE.match(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE ID format")

    path = iov_path(cve_id)
    if path.exists():
        return JSONResponse(status_code=200, content=json.loads(path.read_text()))

    if not _is_admin(authorization):
        raise HTTPException(status_code=404, detail="Not found")

    state_path = status_path(cve_id)
    if not state_path.exists():
        if not _cve_exists(cve_id):
            raise HTTPException(status_code=404, detail="CVE ID not found")
        try:
            f = state_path.open("x")
        except FileExistsError:
            pass  # another request queued it in the meantime
        else:
            with f:
                task = generate_iov.delay(cve_id)
                f.write(json.dumps({
                    "status":       "pending",
                    "time_started": datetime.now(UTC).isoformat(),
                    "celery_id":    task.id,
                    "failures":     1,
                }))
            return JSONResponse(status_code=202, content={"status": "queued", "cve": cve_id})

    try:
        content = state_path.read_text().strip()
    except FileNotFoundError:
        # The IoV was stored between the checks above.
        return api_get_iov(cve_id, authorization)
    if not content:
        # Created by a concurrent request that has not written it yet.
        return JSONResponse(status_code=202, content={"status": "in_progress", "cve": cve_id})

    data = json.loads(content)

    if data["status"] == "failed":
        return JSONResponse(status_code=200, content={"status": "FAILED", "cve": cve_id})

    time_started = datetime.fromisoformat(data["time_started"])
    failures     = data.get("failures", 1)

    if datetime.now(UTC) - time_started > TASK_TIMEOUT:
        celery_id = data.get("celery_id")
        if celery_id:
            celery_app.control.revoke(celery_id, terminate=True)

        failures += 1
        if failures > MAX_FAILURES:
            write_atomic(state_path, json.dumps({"status": "failed", "failures": failures}))
            return JSONResponse(status_code=200, content={"status": "FAILED", "cve": cve_id})

        task = generate_iov.delay(cve_id)
        write_atomic(state_path, json.dumps({
            "status":       "pending",
            "time_started": datetime.now(UTC).isoformat(),
            "celery_id":    task.id,
            "failures":     failures,
        }))

    return JSONResponse(status_code=202, content={"status": "in_progress", "cve": cve_id})


@app.delete("/api/{cve_id}")
def api_delete_iov(cve_id: str, _: None = Depends(_require_admin)):
    if not CVE_RE.match(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE ID format")

    removed = []
    for p in [iov_path(cve_id), status_path(cve_id), log_path(cve_id)]:
        if p.exists():
            p.unlink()
            removed.append(p.name)

    if not removed:
        raise HTTPException(status_code=404, detail="No files found for this CVE")

    return {"removed": removed}


@app.put("/api/bulk")
def api_bulk_upsert_iov(items: list[dict], _: None = Depends(_require_admin)):
    """Upsert a batch of pre-generated IoV documents. Each item must be a JSON
    object with a top-level "cve" field; it is written verbatim to
    {cve}.iov.json, overwriting any existing IoV and discarding in-progress or
    failed generation state."""
    upserted: list[str] = []
    errors: dict[str, str] = {}

    for item in items:
        cve_id = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve_id, str) or not CVE_RE.match(cve_id):
            errors[str(cve_id)] = "Missing or invalid 'cve' field"
            continue
        write_atomic(iov_path(cve_id), json.dumps(item))
        status_path(cve_id).unlink(missing_ok=True)
        upserted.append(cve_id)

    return {"upserted": upserted, "errors": errors}


# ── Public CVE detail (HTML) — defined last so it doesn't shadow routes above ─

@app.get("/{cve_id}", response_class=HTMLResponse)
def cve_detail(cve_id: str, request: Request):
    if not CVE_RE.match(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE ID format")

    path = iov_path(cve_id)
    if path.exists():
        return templates.TemplateResponse(request, "detail.html", context={
            "cve_id":   cve_id,
            "state":    "ok",
            "iov_json": json.dumps(json.loads(path.read_text()), indent=2),
        })

    try:
        content = status_path(cve_id).read_text().strip()
    except FileNotFoundError:
        return templates.TemplateResponse(request, "detail.html", context={
            "cve_id": cve_id, "state": "not_found",
        }, status_code=404)

    state = "failed" if content and json.loads(content).get("status") == "failed" else "pending"
    return templates.TemplateResponse(request, "detail.html", context={
        "cve_id": cve_id, "state": state,
    })

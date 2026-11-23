"""Where a CVE's files live in DATA_DIR.

    {cve}.iov.json   a finished IoV, and nothing else
    {cve}.status     generation state while there is no IoV yet:
                     {"status": "pending", "time_started", "celery_id", "failures"}
                     or {"status": "failed", "failures", "reason"?}
    logs/{cve}.log   the last generation attempt's request and response
"""

import json
import os
import tempfile
from pathlib import Path

from app.config import DATA_DIR

IOV_SUFFIX = ".iov.json"
STATUS_SUFFIX = ".status"


def iov_path(cve_id: str) -> Path:
    return DATA_DIR / f"{cve_id}{IOV_SUFFIX}"


def status_path(cve_id: str) -> Path:
    return DATA_DIR / f"{cve_id}{STATUS_SUFFIX}"


def log_path(cve_id: str) -> Path:
    return DATA_DIR / "logs" / f"{cve_id}.log"


def write_atomic(path: Path, text: str) -> None:
    """Write via a temporary file in the same directory, so readers never see
    a partially written document."""
    handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(handle, "w") as temp_file:
            temp_file.write(text)
        # mkstemp creates the file 0600; stored documents are meant to be readable.
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, path)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise


def store_iov(cve_id: str, document_json: str) -> None:
    """Store a finished IoV and drop its generation state."""
    write_atomic(iov_path(cve_id), document_json)
    status_path(cve_id).unlink(missing_ok=True)


def is_current_task(cve_id: str, task_id: str) -> bool:
    """Whether task_id is the generation that {cve}.status is waiting for.

    Celery redelivers unacknowledged tasks, e.g. after a worker restart, so a
    task can run again after its CVE was requeued, deleted or finished.
    """
    try:
        state = json.loads(status_path(cve_id).read_text())
    except (OSError, ValueError):
        return False
    return isinstance(state, dict) and state.get("status") == "pending" \
        and state.get("celery_id") == task_id


def mark_failed(cve_id: str, reason: str) -> None:
    """Give up on a CVE: its generation will not be retried automatically."""
    path = status_path(cve_id)
    try:
        failures = json.loads(path.read_text()).get("failures", 1)
    except (OSError, ValueError, AttributeError):
        failures = 1
    write_atomic(path, json.dumps({"status": "failed", "failures": failures, "reason": reason}))


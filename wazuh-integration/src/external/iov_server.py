"""The IoV server's admin API, for `cli.py queue-iovs`."""
import requests

from config import IOV_SOURCE_URL


class IoVNotAvailable(Exception):
    pass


def check_or_queue_iov(cve_id: str, admin_token: str | None) -> str:
    """Look up the IoV for cve_id on the IoV server and, with an admin token,
    queue its generation if there is none yet.

    Returns "have" (an IoV exists), "queued" (generation was just queued),
    "in_progress" (generation was already running), "failed" (generation has
    failed for good) or, without a token, "missing" (no IoV, nothing queued).
    """
    if IOV_SOURCE_URL is None:
        raise IoVNotAvailable("IOV_SOURCE_URL is not configured")

    headers = {"Authorization": f"Bearer {admin_token}"} if admin_token else {}
    resp = requests.get(f"{IOV_SOURCE_URL.rstrip('/')}/api/{cve_id}", headers=headers, timeout=10)

    if resp.status_code == 200:
        return "failed" if resp.json().get("status") == "FAILED" else "have"
    if resp.status_code == 202:
        return "queued" if resp.json().get("status") == "queued" else "in_progress"
    if resp.status_code == 404 and admin_token is None:
        return "missing"
    resp.raise_for_status()
    raise IoVNotAvailable(f"unexpected status {resp.status_code} from the IoV server")

"""Celery tasks: the periodic poll and score refresh, and the on-demand
rebuild of one agent that `cli.py process` triggers."""
import sys

import redis
from celery import Celery

from config import (
    POLL_INTERVAL,
    REDIS_URL,
    SCORE_REFRESH_INTERVAL,
    TASK_LOCK_TTL,
    TASK_LOG_TTL,
)
from pipeline import poll_new_verdicts, process_iov_results, refresh_scores

celery_app = Celery("tasks", broker=REDIS_URL, backend=REDIS_URL)

# Agents evaluate on their own schedule and publish through the Wazuh agent
# socket, so ETSO polls the alerts index for new verdicts rather than being
# told about them. Requires the beat process (see the Dockerfile CMD) and a
# worker with two slots, so a long score refresh does not hold up the polls.
celery_app.conf.beat_schedule = {
    "poll-iov-verdicts": {
        "task": "poll_iov_verdicts",
        "schedule": POLL_INTERVAL,
        # A poll still queued when the next one is due is redundant.
        "options": {"expires": POLL_INTERVAL},
    },
    "refresh-scores": {
        "task": "refresh_scores",
        "schedule": SCORE_REFRESH_INTERVAL,
        "options": {"expires": SCORE_REFRESH_INTERVAL},
    },
}

# Lock names for the periodic tasks; Wazuh agent IDs are numeric, so they
# cannot collide with a per-agent lock. The TTLs only matter if a worker dies
# mid-run, and are short so that does not stall the schedule for long. A lock
# expiring under a slow run is harmless: every write is idempotent.
POLL_LOCK, POLL_LOCK_TTL = "poll", 120
REFRESH_LOCK, REFRESH_LOCK_TTL = "refresh", 900

_redis = redis.from_url(REDIS_URL, decode_responses=True)


def _lock_key(agent_id: str) -> str:
    return f"task:lock:agent:{agent_id}"


def log_key(task_id: str) -> str:
    return f"task:logs:{task_id}"


def acquire_lock(agent_id: str, ttl: int = TASK_LOCK_TTL) -> bool:
    """Atomically acquire the per-agent lock. Returns False if already held."""
    return _redis.set(_lock_key(agent_id), "1", nx=True, ex=ttl) is not None


def release_lock(agent_id: str) -> None:
    _redis.delete(_lock_key(agent_id))


class _TaskStdout:
    """Line-buffered tee: writes to the real stdout AND appends to a Redis list."""

    def __init__(self, task_id: str):
        self._key = log_key(task_id)
        self._original = sys.stdout
        self._buf = ""

    def write(self, text: str) -> int:
        self._original.write(text)
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line:
                _redis.rpush(self._key, line)
                _redis.expire(self._key, TASK_LOG_TTL)
        return len(text)

    def flush(self) -> None:
        self._original.flush()

    def __getattr__(self, name: str):
        return getattr(self._original, name)


@celery_app.task(bind=True, name="process_agent")
def process_agent(self, agent_id: str):
    """Process one agent's IoV results. The caller acquires the agent's lock."""
    original_stdout = sys.stdout
    sys.stdout = _TaskStdout(self.request.id)
    try:
        return process_iov_results(agent_id=agent_id)
    except Exception as exc:
        print(f"ERROR: {exc}")
        raise
    finally:
        sys.stdout = original_stdout
        release_lock(agent_id)


def _exclusive(lock: str, ttl: int, func):
    """Run func unless the previous run of the same task still holds lock."""
    if not acquire_lock(lock, ttl):
        return None
    try:
        return func()
    finally:
        release_lock(lock)


@celery_app.task(name="poll_iov_verdicts")
def poll_iov_verdicts():
    """Push verdicts from new alerts into iov-results, on the beat schedule."""
    return _exclusive(POLL_LOCK, POLL_LOCK_TTL, poll_new_verdicts)


@celery_app.task(name="refresh_scores")
def refresh_scores_task():
    """Refresh EPSS and backfill CVSS in iov-results, on the beat schedule."""
    return _exclusive(REFRESH_LOCK, REFRESH_LOCK_TTL, refresh_scores)

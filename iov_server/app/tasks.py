"""Celery app and the generation task."""

import logging

from celery import Celery
from celery.signals import after_setup_logger, after_setup_task_logger

from app.config import DATA_DIR, REDIS_URL
from app.storage import is_current_task, mark_failed, store_iov

log = logging.getLogger(__name__)

celery_app = Celery("iov_tasks", broker=REDIS_URL, backend=REDIS_URL)
celery_app.conf.update(
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)


@after_setup_logger.connect
@after_setup_task_logger.connect
def _add_file_handler(logger, **kwargs):
    log_dir = DATA_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_dir / "celery.log")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)


@celery_app.task(bind=True, name="generate_iov", acks_late=True)
def generate_iov(self, cve_id: str):
    """Generate and store the IoV for cve_id, unless the task is outdated."""
    # Deferred: only the worker needs the generator and the evaluate_iov validator.
    from app.generator import IovRejected, run_generator
    if not is_current_task(cve_id, self.request.id):
        log.info("[%s] skipping outdated task %s", cve_id, self.request.id)
        return
    try:
        document = run_generator(cve_id)
        if not is_current_task(cve_id, self.request.id):
            log.info("[%s] discarding the IoV of outdated task %s", cve_id, self.request.id)
            return
        store_iov(cve_id, document)
    except IovRejected as exc:
        # The model had its correction rounds; starting over would only
        # repeat them, so this is final (unlike network or API errors).
        mark_failed(cve_id, str(exc))
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60, max_retries=3) from exc

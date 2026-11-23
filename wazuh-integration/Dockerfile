FROM python:3.12-slim

WORKDIR /app/src

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

# docker-compose.yml mounts src/ over this copy, so code changes need only a
# restart; the copy keeps the image usable without the mount.
COPY src/ /app/src/

# One container runs the Celery worker and beat (the poll and the score
# refresh) next to uvicorn (the dashboard and the CLI's endpoints).
CMD ["/bin/bash", "-c", "celery -A tasks.celery_app worker --loglevel=warning --concurrency=2 -O fair & celery -A tasks.celery_app beat --loglevel=warning --schedule /tmp/celerybeat-schedule & exec uvicorn app:app --host 0.0.0.0 --port ${ETSO_PORT:-8000} --reload"]

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
COPY --from=iov_evaluation requirements.txt agent-requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r agent-requirements.txt

COPY . .
# The agent's evaluate_iov package validates generated IoVs (app/validation.py).
# Only the package's sources: iov-evaluation also holds the build tooling and binaries.
COPY --from=iov_evaluation evaluate_iov/*.py evaluate_iov/iov.schema.json /opt/agent/evaluate_iov/
COPY --from=iov_evaluation evaluate_iov/host/*.py /opt/agent/evaluate_iov/host/
COPY --from=iov_evaluation evaluate_iov/script/*.py /opt/agent/evaluate_iov/script/

ENV PYTHONPATH=/app:/opt/agent

# The Celery worker runs in the background of the same container as the API.
CMD ["sh", "-c", "celery -A app.tasks.celery_app worker --loglevel=info --concurrency=${CELERY_CONCURRENCY:-8} & exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]

"""ETSO's HTTP server: the prioritisation dashboard under /dashboard, and the
endpoints `cli.py process` uses to rebuild an agent's iov-results on demand.
The continuous work (polling for verdicts, refreshing scores) runs in Celery,
see tasks.py."""
import asyncio
import logging

import redis
from celery.result import AsyncResult
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import StreamingResponse

from config import REDIS_URL
from dashboard.routes import router as dashboard_router
from dashboard.routes import static as dashboard_static
from etso_logging import configure_logging
from tasks import acquire_lock, celery_app, log_key, process_agent

configure_logging()

_redis = redis.from_url(REDIS_URL, decode_responses=True)

_TERMINAL = {"SUCCESS", "FAILURE", "REVOKED"}

logger = logging.getLogger("etso.server")


app = FastAPI()
app.include_router(dashboard_router)
app.mount("/dashboard/static", dashboard_static, name="dashboard-static")


@app.post("/process/{agent_id}")
async def process_route(agent_id: str):
    """Queue a rebuild of one agent's iov-results; 409 if one is running."""
    logger.info(f"Received request to process agent {agent_id}")
    if not acquire_lock(agent_id):
        logger.warning(f"Task for agent {agent_id} is already running")
        raise HTTPException(status_code=409, detail=f"Task for agent {agent_id} is already running")
    task = process_agent.delay(agent_id)
    return {"status": "queued", "agent_id": agent_id, "task_id": task.id}


@app.get("/logs/{task_id}")
async def stream_logs(task_id: str, last: int = Query(default=None, ge=1)):
    """
    SSE stream of task log lines.

    Sends existing lines immediately, then polls for new lines every 0.5 s while
    the task is running.  Terminates with an ``event: done`` frame carrying the
    final Celery state (SUCCESS / FAILURE / REVOKED).

    Query param ``last=N`` limits the initial batch to the last N stored lines;
    new lines that arrive while the task is running are always forwarded.
    """
    async def generate():
        existing = _redis.lrange(log_key(task_id), 0, -1)
        result = AsyncResult(task_id, app=celery_app)
        already_done = result.state in _TERMINAL

        start = max(0, len(existing) - last) if last else 0
        for line in existing[start:]:
            yield f"data: {line}\n\n"

        if already_done:
            yield f"event: done\ndata: {result.state}\n\n"
            return

        sent = len(existing)
        while True:
            await asyncio.sleep(0.5)

            new_lines = _redis.lrange(log_key(task_id), sent, -1)
            for line in new_lines:
                yield f"data: {line}\n\n"
            sent += len(new_lines)

            result = AsyncResult(task_id, app=celery_app)
            if result.state in _TERMINAL:
                # Lines written between the last lrange and the state check.
                final_lines = _redis.lrange(log_key(task_id), sent, -1)
                for line in final_lines:
                    yield f"data: {line}\n\n"
                yield f"event: done\ndata: {result.state}\n\n"
                break

    return StreamingResponse(generate(), media_type="text/event-stream")

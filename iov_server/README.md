# IoV server

Generates and serves Indicators of Vulnerability (IoVs), one per CVE. Endpoint daemons mirror the
corpus from here and evaluate it on their host (see [`../iov-evaluation`](../iov-evaluation)).

The server is a FastAPI app with a Celery worker and Redis. IoVs are stored as files in `iov_data/`
(`<CVE>.iov.json`), so the corpus in this repository is also the server's data directory.

## How an IoV is generated

Requesting an IoV that does not exist yet, as an admin, queues its generation. The worker then runs
four steps ([`app/generator.py`](app/generator.py)):

1. **Context.** It fetches the data that needs no search engine directly: the CVE record from
   CIRCL's Vulnerability-Lookup, matching GitHub Security Advisories, and the trackers of the four
   covered distributions: the Ubuntu CVE tracker with its latest USNs, the Debian security tracker
   via OSV, the Red Hat security data API, and Alpine's secdb and tracker
   ([`app/trackers.py`](app/trackers.py)).
2. **Research.** The model (`LLM_MODEL`, default `z-ai/glm-5.3-flash`, via OpenRouter) fills the
   gaps with OpenRouter's web search and web fetch tools (at most 3 searches and 5 fetches), and
   answers with research notes.
3. **Writing.** A separate request with the context, the notes and the full IoV specification
   ([`prompt/prompt6.txt`](prompt/prompt6.txt), format version 2). Structured outputs pin the answer
   to the IoV JSON schema.
4. **Validation.** The answer is checked with the agent's own validator (schema, script parser, CEL
   compilation, known built-ins only, a `return` on every path; [`app/validation.py`](app/validation.py)).
   A rejected answer goes back to the model with the reason, for at most 3 correction rounds.

A generation that still fails validation after the corrections marks the CVE `FAILED` (delete it
to try again). Network and API errors are retried by Celery; a generation that has not finished
after 30 minutes is requeued by the next admin request for it, and after 3 attempts the CVE is
marked `FAILED`. One IoV takes about three minutes and costs about US$0.03.

The validator is the `evaluate_iov` package from [`../iov-evaluation`](../iov-evaluation), which the
Docker build copies into the image. An IoV the server accepts is therefore one the agents can
evaluate.

## Run

Requirements: Docker with Compose, and an [OpenRouter](https://openrouter.ai) API key.

```bash
cd iov_server
cp .env.example .env     # set OPENROUTER_API_KEY and ADMIN_TOKEN
docker compose up -d --build
curl http://localhost:8000/health
```

The build needs the sibling `iov-evaluation/` directory (a Compose `additional_contexts`), so run it
from a full checkout. The container serves the app on port 8000 (host port `IOV_SERVER_PORT`) and
runs the Celery worker next to it. `./iov_data` is mounted as the data directory, so the IoVs in this
repository are served straight away.

For local development, set `DEBUG=1` and leave `ADMIN_TOKEN` empty: every request then counts as
admin. Outside Docker, install `requirements.txt` and `../iov-evaluation/requirements.txt`, then run
`uvicorn app.main:app` and `celery -A app.tasks.celery_app worker` with `PYTHONPATH` including
`../iov-evaluation`, a reachable `REDIS_URL` and a writable `DATA_DIR`.

## Configure

Set in `.env`; [`.env.example`](.env.example) lists all of them with comments.

| Variable | Default | Notes |
|---|---|---|
| `OPENROUTER_API_KEY` | — | **Required** for generation. |
| `ADMIN_TOKEN` | — | **Required** unless `DEBUG` is set; the server refuses to start without it. |
| `DEBUG` | unset | `1` with an empty `ADMIN_TOKEN` makes every request admin. Development only. |
| `LLM_MODEL` | `z-ai/glm-5.3-flash` | Must support tool use and `response_format`. |
| `VULNERABILITY_LOOKUP_API_KEY` | unset | Optional key for CIRCL's Vulnerability-Lookup. |
| `PROMPT_PATH` | `prompt/prompt6.txt` | The IoV specification; its JSON schema block is also the structured-output schema. |
| `REASONING_EFFORT_RESEARCH` / `_WRITE` / `_CORRECTION` | `high` / `high` / `low` | `OPENROUTER_REASONING_EFFORT` overrides all three. |
| `WEB_SEARCH_ENGINE` | `perplexity` | Also `auto`, `native`, `exa`, `firecrawl`, `parallel`. |
| `WEB_SEARCH_MAX_RESULTS` / `WEB_FETCH_MAX_CONTENT_TOKENS` | `10` / `20000` | Per search / per fetched page. |
| `RESEARCH_MAX_SEARCHES` / `RESEARCH_MAX_FETCHES` | `3` / `5` | Research budget per CVE. |
| `RESEARCH_DEADLINE` / `WRITE_DEADLINE` | `600` / `600` | Seconds per request. |
| `OPENROUTER_PROVIDER_SORT` | `throughput` | `price`, `latency`, or empty for OpenRouter's default. |
| `OPENROUTER_IGNORE_PROVIDERS` | `decart,wafer` | Providers never to use. |
| `CELERY_CONCURRENCY` | `8` | Generations in parallel. |
| `IOV_SERVER_PORT` | `8000` | Host port in `docker-compose.yml`. |
| `IOV_SERVER_URL` | `http://localhost:8000` | Server URL for `cli.py`. |
| `DATA_DIR` / `REDIS_URL` | `/data` / `redis://redis:6379/0` | Set by `docker-compose.yml`. |

## API

| Route | Auth | What |
|---|---|---|
| `GET /` , `GET /{cve}` | — | Web front end: the corpus and a single IoV. |
| `GET /admin` | — (token entered in the page) | Admin page for queuing generation. |
| `GET /health` | — | Health check. |
| `GET /api/cves?offset=&limit=&digests=1` | — | Paged list of generated CVEs; with `digests=1`, a content hash per IoV. The daemons mirror the corpus with it. |
| `GET /api/{cve}` | — / admin | The IoV. If it does not exist, an admin request queues generation (`202`) after checking the ID against MITRE's CVE API, a public one gets `404`. Returns `{"status": "FAILED"}` once generation has failed; delete the CVE to try again. |
| `DELETE /api/{cve}` | admin | Deletes the IoV and its generation state and log. |
| `GET /api/bulk` | admin | Every generated IoV. |
| `PUT /api/bulk` | admin | Upserts a list of IoV documents. |

Admin routes take `Authorization: Bearer <ADMIN_TOKEN>`.

## CLI

[`cli.py`](cli.py) wraps the API. It reads `IOV_SERVER_URL` and `ADMIN_TOKEN` from the environment
or from `.env` next to it:

```bash
python cli.py health
python cli.py get CVE-2026-90698            # fetch, or queue generation as admin
python cli.py list
python cli.py bulk-download ./export        # all IoVs as <CVE>.iov.json
python cli.py bulk-upsert ./iov_data        # upload IoV files
python cli.py delete CVE-2026-90698
```

To queue generation for everything Wazuh detected on an agent, use `wazuh-integration`'s
`python3 src/cli.py queue-iovs <agent_id>`.

## Layout

| Path | What |
|---|---|
| `app/main.py` | FastAPI routes. |
| `app/tasks.py` | Celery app and the generation task. |
| `app/generator.py` | Context, research, writing, validation and correction. |
| `app/trackers.py` | Distribution tracker clients (Ubuntu, Debian/OSV, Red Hat, Alpine). |
| `app/validation.py` | Validation with the agent's `evaluate_iov` package. |
| `app/storage.py` | File storage of IoVs, generation state and logs. |
| `app/templates/` | Web front end. |
| `prompt/prompt6.txt` | The IoV specification sent with the writing step, including the IoV JSON schema. |
| `cli.py` | Admin CLI. |
| `iov_data/` | The data directory: the 66 generated IoVs of the evaluation ([`docs/cve_table.pdf`](../docs/cve_table.pdf)) as `<CVE>.iov.json`. At runtime the server also keeps `<CVE>.status` (generation state) and `logs/` (`server.log`, `celery.log`, and per CVE the full request and response log of the last attempt; git-ignored) here. |

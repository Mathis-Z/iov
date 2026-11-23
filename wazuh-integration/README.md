# wazuh-integration (ETSO)

ETSO, the enrichment server. It copies the IoV verdicts that the endpoint daemons send through Wazuh
into the `iov-results` index, adds EPSS and CVSS, and serves the prioritisation dashboard. This
directory also holds everything to install on the Wazuh endpoints and manager.

### Setup

Needs a running Wazuh manager, indexer and dashboard (we use Wazuh 4.8 in the
[wazuh-docker](https://github.com/wazuh/wazuh-docker) single-node deployment) and a running
[`iov_server`](../iov_server).

```bash
cp example.env .env      # Wazuh API/indexer credentials and IOV_SOURCE_URL
docker compose up -d --build
```

This starts Redis (bound to `127.0.0.1:6379`) and the `etso` container: uvicorn on `ETSO_PORT`
(default 8000), a Celery worker and Celery beat. The container uses host networking, so `localhost`
in `.env` is the Docker host, and it mounts `src/`, so code changes need only
`docker compose restart app`. The IoV server also defaults to port 8000; if both run on one host,
change one of them.

Without Docker (Python 3.11 or newer), with a Redis at `REDIS_URL`:

```bash
python3 -m venv .venv && source .venv/bin/activate && python3 -m pip install -r requirements.txt
cd src && uvicorn app:app --port 8000   # plus the two Celery processes, see DEPLOYMENT.md
```

### Layout

| Path | What |
|---|---|
| `src/app.py`, `src/tasks.py` | The FastAPI app and the Celery tasks (poll, score refresh, per-agent rebuild). |
| `src/pipeline.py` | Projects verdict alerts into `iov-results` and adds EPSS and CVSS. |
| `src/external/` | Clients for the Wazuh API and indexer, FIRST and NVD (`cve_info.py`), and the IoV server. |
| `src/dashboard/` | The prioritisation dashboard: data sources, scoring, the page, and demo data. |
| `src/cli.py` | Operator CLI, see below. |
| `src/tests/` | Unit tests. |
| `installation/endpoints/` | Everything to install the IoV evaluation daemon on Wazuh agents. |
| `installation/manager/` | The IoV rules for the Wazuh manager, and the dashboard plugin for the Wazuh dashboard. |

### CLI

`src/cli.py` drives ETSO and inspects agents (`--host`/`--port` select the ETSO server; an omitted
agent ID is asked for interactively):

| Command | What |
|---|---|
| `process [AGENT]` | Rebuild an agent's `iov-results` through the running server, streaming its log. |
| `iov-sync [--agent ID] [--dry-run]` | The same, run directly, for all agents or one. |
| `iov-index` | Create the `iov-results` index now (it is otherwise created on first use). |
| `cves [AGENT]` | Print the CVE IDs Wazuh detected on an agent. |
| `queue-iovs [AGENT] [--min-cvss 8] [--dry-run]` | Queue IoV generation on the IoV server for the agent's detected CVEs that have none yet (needs `ADMIN_TOKEN`; `--dry-run` only counts them). |

The evaluator the daemon runs, and the build of its binaries, are in
[`iov-evaluation/`](../iov-evaluation).

The unit tests need `pytest` and `httpx` on top of `requirements.txt`, and run from
`wazuh-integration/` without Wazuh or Redis:

`PYTHONPATH=src python3 -m pytest src/tests`

### IoV results

Neither the agent nor the manager holds credentials. Verdicts travel:

```
agent daemon -> agent queue socket -> manager rules (group iov_evaluation)
             -> wazuh-alerts-* -> ETSO -> iov-results
```

The manager's only job is the rules in `installation/manager/`. ETSO copies the alerts into the
`iov-results` index. Documents are keyed `<agent_id>:<cve_id>`, so a re-evaluation replaces the
previous verdict instead of adding another one. Each document also carries the CVE's EPSS score
(`epss`, from FIRST) and its CVSS metrics (`cvss`, from NVD). `cvss` holds a headline base score,
version, severity and vector, plus every CVSS version NVD has under `cvss.metrics`, including the
sub-scores. Both are cached in Redis. The index is created automatically, so there is no manual
setup step.

Each verdict also carries the full IoV it was evaluated from (`iov_document`), so a user can see what
led to the result. The daemon sends it compressed (see
[Wazuh events](../iov-evaluation/README.md#wazuh-events)), and ETSO decodes it. `iov_document` is
stored but not indexed, so it can be displayed but not searched. It is null when the event had no IoV
attached: from an older daemon, or when the IoV was too large to attach.

ETSO polls `wazuh-alerts-*` every `POLL_INTERVAL` seconds (default 10) and pushes only the verdicts
of alerts it has not seen yet. A second task refreshes EPSS and backfills CVSS across the whole
index every `SCORE_REFRESH_INTERVAL` seconds (default 300). To rebuild from the last
`IOV_PROJECTION_LOOKBACK` of alerts by hand, `python3 src/cli.py process <agent_id>` goes through
the running server, and `python3 src/cli.py iov-sync [--agent ID] [--dry-run]` runs directly.

**See [DEPLOYMENT.md](DEPLOYMENT.md)** for the order to roll everything out in, ETSO's
configuration, and end-to-end verification. The endpoint and manager steps are in
[`installation/endpoints/`](installation/endpoints/README.md) and
[`installation/manager/`](installation/manager/README.md).

### Prioritisation dashboard

`src/dashboard/` serves a page at `http://<etso>:8000/dashboard/` that ranks every (host, CVE)
finding by what to fix first, and says why. It is part of the ETSO app, so the container already
serves it; it is embedded in Wazuh with the iframe plugin in `installation/manager/`, see
[Embedding in Wazuh](#embedding-in-wazuh).

It reads two indices from the Wazuh indexer (never the Wazuh API): `iov-results` for the IoV
verdicts with EPSS and CVSS, and `wazuh-states-vulnerabilities-*` so CVEs that have no IoV yet are
ranked too, on CVSS and EPSS alone (EPSS for those comes from ETSO's cached FIRST lookup). Every
IoV verdict is included as well, including those for CVEs Wazuh did not detect on that host (marked
"IoV only"); an ABSENT verdict lands under **Not affected** / "Ruled out by IoV", out of the default
open-findings view.

**The score**, per finding, from 0 to 100 (`src/dashboard/scoring.py`):

```
priority = 100 × impact × likelihood × applicability
impact        = CVSS base / 10
likelihood    = 0.3 + 0.7 × threat,  threat = EPSS on a log scale (0.01% → 0 … 100% → 1)
applicability = IoV verdict: HIGH 1.0 · MEDIUM 0.7 · LOW 0.35 · ABSENT 0
                INCONCLUSIVE, a failed IoV script and "no IoV yet" rank as MEDIUM (0.7)
```

Bands: **Fix now** ≥ 50, **Fix soon** ≥ 30, **Plan** ≥ 15, **Low** below, and **Not affected**
when the IoV says ABSENT. The overall urgency is the priority of the most urgent open finding.
Selecting a host (the host filter, a row in the **Hosts** tab, or `?host=`) scopes the whole
overview to it: urgency, band counts, IoV tiles and the risk map. A
missing or broken IoV never makes a finding look safer than it is; a missing score is assumed and
the assumption is shown. Every finding's detail view shows the factor breakdown, the IoV's reason
and script error, what a HIGH or LOW verdict would change, the same CVE on other hosts, and links to
the IoV server, NVD, CVE.org and EPSS.

| Variable | Default | Notes |
|---|---|---|
| `DASHBOARD_DATA_SOURCE` | `indexer` | `demo` serves bundled sample data instead. |
| `DASHBOARD_INCLUDE_DETECTIONS` | `true` | `false` ranks only CVEs with an IoV verdict. |
| `DASHBOARD_CACHE_TTL` | `300` | Age (s) after which the data is rebuilt in the background; viewers get the previous build meanwhile. **Refresh** waits for a new one. |
| `IOV_PUBLIC_URL` | `IOV_SOURCE_URL` | The IoV server as the *browser* reaches it, for the per-CVE links. |

Deep links: `?host=<agent name or id>`, `?band=fix_now|fix_soon|plan|low|not_affected|all`,
`?iov=HIGH|MEDIUM|LOW|ABSENT|INCONCLUSIVE|ERROR|NOT_ASSESSED`, `?q=<text>`, `?tab=hosts|map`,
`?open=<agent id>:<CVE>`, and `?theme=dark|light` (the iframe cannot see Wazuh's own theme; without
it the page follows the OS).

#### Embedding in Wazuh

The plugin in [`installation/manager/`](installation/manager/README.md#dashboard-plugin) adds an
**IoV Dashboard** app to the Wazuh menu that shows this dashboard in an iframe. The plugin has a
server side: the browser loads the page from the Wazuh dashboard itself
(`https://<wazuh>/api/etso/dashboard/`), and the Wazuh dashboard's server fetches it from ETSO
over plain HTTP:

```
browser ──https──▶ Wazuh dashboard /api/etso/dashboard/*   (Wazuh login required)
                        └──http──▶ ETSO :8000 /dashboard/*
```

So the frame shares Wazuh's origin and certificate: no extra port, no certificate to accept, and no
extra SSH forward. The dashboard is only served to users logged in to Wazuh, and only ETSO's
`/dashboard/` is reachable through that route.

Port 8000 must be reachable from the Wazuh dashboard's server, at the address set in
`wazuhIframeWidget.etsoUrl` (see the manager README), and from wherever you run `cli.py`. It does
not need to be reachable from users' browsers. ETSO's port itself still has no authentication, so
keep it off users' networks.

Without a Wazuh, run it standalone on demo data: the real `iov-results` export in
`src/dashboard/demo_data/` plus a generated estate (8 hosts, made-up `CVE-2026-91xxx` IDs):

```
cd src && python3 -m dashboard --demo      # http://127.0.0.1:8050/dashboard/
```

Tests: `PYTHONPATH=src python3 -m pytest src/tests/test_dashboard.py`

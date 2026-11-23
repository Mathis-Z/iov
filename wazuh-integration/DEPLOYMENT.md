# Deploying the IoV evaluation pipeline

How to roll out Indicator-of-Vulnerability evaluation across a Wazuh estate: the daemon on each
endpoint, the detection rules on the manager, and the projection in ETSO.

Assumes you already have a working Wazuh manager, indexer and dashboard, with agents enrolled and
reporting, plus a running `iov_server` that serves IoVs.

## How the pieces fit

```
endpoint                         manager                    ETSO
────────                         ───────                    ────
wazuh-evaluate-iov-daemon
  ├─ pulls IoVs from iov_server
  ├─ evaluates them locally
  └─ writes verdicts to  ───────▶ agent queue socket
                                  analysisd + iov_rules.xml
                                  └─ tags group iov_evaluation
                                     └─ alert ──▶ wazuh-alerts-*
                                                      │
                                                      └──▶ ETSO projects into
                                                           iov-results
```

Credentials live in exactly one place: ETSO. Endpoints hold only the IoV server URL; the manager
holds nothing.

A verdict is a confidence score that the CVE applies to that host:

| Score | Level | Meaning |
|---|---|---|
| `-1` | INCONCLUSIVE | The IoV makes no statement. **Not** evidence of safety. |
| `0` | ABSENT | The host is not affected. |
| `1` | LOW | Affected version present, preconditions absent or mitigated. |
| `2` | MEDIUM | Affected version present, nothing known either way. |
| `3` | HIGH | Affected, and exploitation preconditions are affirmatively present. |

---

## 1. Endpoints

Install `wazuh-evaluate-iov-daemon` on every agent host:
[`installation/endpoints/README.md`](installation/endpoints/README.md). In short, copy
`installation/endpoints/` to the host, run `sudo ./install.sh`, and set `IOV_SERVER_URL` in
`/etc/wazuh-evaluate-iov/daemon.env`.

The daemon binary there is built by [`iov-evaluation/package.sh`](../iov-evaluation/README.md).

---

## 2. Manager

Install the IoV rules on the Wazuh manager, and optionally the dashboard plugin on the Wazuh
dashboard: [`installation/manager/README.md`](installation/manager/README.md). In short, run
`installation/manager/install-iov-manager.sh` on the manager.

---

## 3. ETSO — the projection

The `iov-results` index is created automatically, with the correct mapping, before the first write
and by the first score refresh. There is no manual step and no startup ordering to get right.
`python3 src/cli.py iov-index` exists, but you only need it if you want the index (and its
Dashboards pattern) to exist straight away.

Two Celery beat tasks keep the index current:

- **Poll** (every `POLL_INTERVAL` s). It reads the IoV alerts that are newer than a cursor kept in
  Redis, keeps the newest verdict per agent and CVE, and upserts it into `iov-results`. It then
  moves the cursor to the newest alert it handled. Each poll re-reads `POLL_OVERLAP` seconds before
  the cursor, because Filebeat can deliver an alert after later ones. Alert IDs already handled are
  skipped, so the overlap causes no extra writes. A poll whose write fails does not move the cursor,
  so the next poll retries it. Without a cursor (first start, or Redis emptied), the poll reads
  `IOV_PROJECTION_LOOKBACK` back instead.
- **Score refresh** (every `SCORE_REFRESH_INTERVAL` s). It updates EPSS and CVSS on every document.
  The poll adds the EPSS score and any CVSS that is already cached. An NVD lookup takes up to 6 s,
  which a 10 s poll cannot wait for, so this task does those lookups and backfills CVSS for new
  CVEs. It also refreshes EPSS, which FIRST publishes daily.

A verdict never replaces a newer one: the upsert compares `evaluated_at`, so an older alert
arriving late leaves the stored verdict alone. Documents are keyed `<agent_id>:<cve_id>`.

Rebuild from the alerts by hand with:

```bash
python3 src/cli.py iov-sync --dry-run             # print the documents it would write
python3 src/cli.py iov-sync [--agent 004]         # write them
python3 src/cli.py process 004                    # one agent, through the running server
```

| Variable | Default | Notes |
|---|---|---|
| `WAZUH_ALERTS_INDEX` | `wazuh-alerts-*` | Where to read verdict alerts from. |
| `POLL_INTERVAL` | `10` | Seconds between polls for new verdicts. |
| `POLL_OVERLAP` | `300` | Seconds each poll re-reads before its cursor, for late alerts. |
| `SCORE_REFRESH_INTERVAL` | `300` | Seconds between EPSS/CVSS refreshes. |
| `IOV_PROJECTION_LOOKBACK` | `172800` | How far back the first poll and manual rebuilds read, seconds. |
| `NVD_API_KEY` | unset | Optional. Raises NVD's rate limit from 5 to 50 requests per 30 s. |
| `NVD_MAX_LOOKUPS_PER_RUN` | `40` | Uncached CVEs looked up in NVD per refresh; the rest wait for later ones. |

Keep the lookback wider than the agents' `IOV_EVAL_INTERVAL` (48 h vs 24 h by default), so a first
poll picks up every agent's current verdict.

EPSS scores are cached for 6 h and CVSS metrics for 7 days (1 day for CVEs NVD has no score for).
NVD accepts only one CVE per request, so without an API key the CVSS for a new corpus is filled in
over several refreshes. Until then, a document has no `cvss` field yet. A score is never written as
null, and a failed lookup keeps the value stored before.

The beat process runs in the container alongside the worker and uvicorn. The worker has two slots
(`--concurrency=2`), so a score refresh waiting on NVD does not hold up the polls. Both log at
`warning`, which still shows each task's summary line, so a 10 s schedule does not flood the log.
If you run ETSO outside Docker, start them yourself:

```bash
celery -A tasks.celery_app worker --loglevel=warning --concurrency=2 -O fair
celery -A tasks.celery_app beat --loglevel=warning
```

---

## 4. End-to-end verification

Check the chain in order — each step tells you which hop is broken:

```bash
# 1. endpoint: does the daemon evaluate and publish?
wazuh-evaluate-iov-daemon --once --log-level INFO
#    -> "N evaluated, N published"

# 2. manager: did the rules match?
grep -m5 iov_evaluation /var/ossec/logs/alerts/alerts.json

# 3. indexer: are the alerts searchable?
curl -sk -u USER:PASS "https://INDEXER:9200/wazuh-alerts-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"rule.groups":"iov_evaluation"}}}'

# 4. ETSO: does the run produce documents?
python3 src/cli.py iov-sync --dry-run

# 5. indexer: are they stored?
curl -sk -u USER:PASS \
  "https://INDEXER:9200/iov-results/_search?size=2&pretty"
```

Re-run step 4 without `--dry-run` and confirm the document count in step 5 does not grow — that
confirms the keying is right.

---

## 5. Troubleshooting

Endpoint and manager problems are covered in their READMEs:
[endpoints](installation/endpoints/README.md#troubleshooting),
[manager](installation/manager/README.md#troubleshooting).

**Projection returns 0 documents.** Confirm step 3 above returns hits. If it does, check that
`IOV_PROJECTION_LOOKBACK` covers the age of those alerts for a manual rebuild. For the poll,
delete the Redis key `iov:poll:cursor` to make it re-read the whole lookback.

**Everything works but the index is empty.** `iov-sync` needs indexer credentials from ETSO's
`.env`, so it must run where that file is configured.

**The index exists but `packages` cannot be queried as nested.** It was auto-created by a write
before the mapping was applied: the indexer creates unknown indices on demand with a guessed
dynamic mapping. Delete it and re-run the projection, which applies the real mapping first:
`curl -sk -u USER:PASS -X DELETE "https://INDEXER:9200/iov-results"`.

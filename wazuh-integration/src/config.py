"""ETSO's configuration, read once from the environment (and .env)."""
import os

from dotenv import load_dotenv

load_dotenv()

# Wazuh API
WAZUH_API_HOST=os.getenv("WAZUH_API_HOST", "localhost")
WAZUH_API_PORT=int(os.getenv("WAZUH_API_PORT", "55000"))
WAZUH_API_USER=os.getenv("WAZUH_API_USER")
WAZUH_API_PASSWORD=os.getenv("WAZUH_API_PASSWORD")
# Indexer API (user/password match the dashboard ones)
WAZUH_INDEXER_HOST=os.getenv("WAZUH_INDEXER_HOST", WAZUH_API_HOST)
WAZUH_INDEXER_PORT=int(os.getenv("WAZUH_INDEXER_PORT", "9200"))
WAZUH_INDEXER_USER=os.getenv("WAZUH_INDEXER_USER")
WAZUH_INDEXER_PASSWORD=os.getenv("WAZUH_INDEXER_PASSWORD")
# IOV Server
IOV_SOURCE_URL=os.getenv("IOV_SOURCE_URL")
ADMIN_TOKEN=os.getenv("ADMIN_TOKEN")
# IoV results: agents publish verdicts through the Wazuh agent socket, the
# manager's rules tag them, and ETSO projects the latest verdict per agent+CVE
# out of the alerts index into the iov-results index, together with the CVE's
# EPSS and CVSS scores.
WAZUH_ALERTS_INDEX = os.getenv("WAZUH_ALERTS_INDEX", "wazuh-alerts-*")
# How often to look for new verdict alerts, in seconds.
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "10"))
# Each poll re-reads this many seconds before its cursor, because an alert can
# reach the indexer after later ones (Filebeat batching or backlog). Alerts
# already handled are skipped by ID, so the overlap costs no writes.
POLL_OVERLAP = int(os.getenv("POLL_OVERLAP", "300"))
# How often to refresh EPSS and backfill CVSS across the whole index, in seconds.
SCORE_REFRESH_INTERVAL = int(os.getenv("SCORE_REFRESH_INTERVAL", "300"))
# How far back the first poll (no cursor yet) and manual re-projections read.
# Wider than the daemon's evaluation interval, so every agent's current verdicts
# are covered.
IOV_PROJECTION_LOOKBACK = int(os.getenv("IOV_PROJECTION_LOOKBACK", "172800"))
# NVD serves CVSS one CVE per request, rate limited to 5 requests per 30 s
# without a key and 50 with one. Only the score refresh looks CVEs up in NVD;
# lookups beyond its per-run cap wait for the next refresh.
NVD_API_KEY = os.getenv("NVD_API_KEY") or None
NVD_MAX_LOOKUPS_PER_RUN = int(os.getenv("NVD_MAX_LOOKUPS_PER_RUN", "40"))
# Prioritisation dashboard (/dashboard), embedded in Wazuh through an iframe.
# "indexer" reads the live Wazuh indexer; "demo" serves the bundled sample.
DASHBOARD_DATA_SOURCE = os.getenv("DASHBOARD_DATA_SOURCE", "indexer").lower()
# Rank every CVE Wazuh detected, not only those with an IoV verdict.
DASHBOARD_INCLUDE_DETECTIONS = os.getenv("DASHBOARD_INCLUDE_DETECTIONS", "true").lower() in ("1", "true", "yes")
# Age at which the dashboard rebuilds its data in the background; viewers are
# served the previous build meanwhile. Reading the indexer takes seconds.
DASHBOARD_CACHE_TTL = int(os.getenv("DASHBOARD_CACHE_TTL", "300"))
DASHBOARD_DEMO_CSV = os.getenv("DASHBOARD_DEMO_CSV") or None
# The IoV server as the user's browser reaches it, for the per-CVE links.
# IOV_SOURCE_URL is what ETSO itself uses and may be an internal address.
IOV_PUBLIC_URL = (os.getenv("IOV_PUBLIC_URL") or os.getenv("IOV_SOURCE_URL") or "").rstrip("/")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
TASK_LOCK_TTL = 3600  # tasks.py: expiry in case a worker dies holding the lock
TASK_LOG_TTL = 86400  # tasks.py: 24 h
EPSS_CACHE_TTL = 21600  # cve_info.py: 6 h — FIRST publishes new scores once a day
CVSS_CACHE_TTL = 604800  # cve_info.py: 7 d — NVD rarely rescores
CVSS_MISS_CACHE_TTL = 86400  # cve_info.py: 1 d — CVE not in NVD or not scored yet
LOG_FILE = os.getenv("LOG_FILE", "logs/etso-server.log")
LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG").upper()

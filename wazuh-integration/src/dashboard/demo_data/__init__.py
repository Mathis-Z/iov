"""Generated test data for the dashboard: a small estate on top of the real
iov-results export.

The CVE IDs (CVE-2026-91xxx) are made up, so no generated score can be
mistaken for a real CVE's. The data mimics the real pipeline: the daemon
evaluates every IoV on every host (so most hosts report ABSENT for CVEs they
do not have), Wazuh detects the vulnerable packages, and most detected CVEs
have no IoV yet.
"""
import random
from datetime import UTC, datetime, timedelta

HOSTS = {
    "001": ("vuln-ubuntu",  "Ubuntu 24.04.1 LTS"),
    "002": ("web-prod-01",  "Ubuntu 22.04.5 LTS"),
    "003": ("db-prod-01",   "Debian GNU/Linux 12"),
    "004": ("mail-gw",      "Red Hat Enterprise Linux 9.4"),
    "005": ("vulnlab2",     "Ubuntu 24.04 LTS"),
    "006": ("build-runner", "Fedora Linux 44"),
    "007": ("k8s-node-a",   "Ubuntu 24.04.1 LTS"),
    "008": ("jump-host",    "Debian GNU/Linux 12"),
}

ALL = list(HOSTS)

# (cve, package, version, fixed, cvss vector, base, epss, percentile,
#  precondition, its negation, {host: IoV level} or None when there is no IoV)
CATALOG = [
    ("CVE-2026-91001", "openssh-server", "1:9.6p1-3ubuntu13.4", "1:9.6p1-3ubuntu13.9",
     "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, 0.4213, 0.972,
     "sshd listens on a non-loopback interface with LoginGraceTime > 0",
     "sshd only listens on loopback",
     {"001": "HIGH", "002": "HIGH", "003": "LOW", "004": "MEDIUM", "007": "LOW", "008": "HIGH"}),
    ("CVE-2026-91002", "nginx", "1.24.0-2ubuntu7", "1.24.0-2ubuntu7.3",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, 0.1831, 0.951,
     "an HTTP/3 (QUIC) listener is enabled",
     "no HTTP/3 listener is configured",
     {"002": "LOW", "007": "HIGH"}),
    ("CVE-2026-91003", "sudo", "1.9.15p5-3ubuntu5", "1.9.15p5-3ubuntu5.1",
     "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, 0.0212, 0.834,
     "a sudoers rule uses the chroot option",
     "no sudoers rule uses chroot",
     {"001": "LOW", "002": "LOW", "003": "LOW", "004": "ABSENT", "006": "MEDIUM", "007": "LOW", "008": "HIGH"}),
    ("CVE-2026-91004", "libc6", "2.39-0ubuntu8.3", "2.39-0ubuntu8.4",
     "AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.0, 0.0045, 0.583,
     "the ISO-2022-CN-EXT iconv module is present and PHP is installed",
     "PHP is not installed",
     {"001": "LOW", "002": "HIGH", "005": "LOW", "007": "LOW"}),
    ("CVE-2026-91005", "postgresql-16", "16.4-1.pgdg120+1", "16.6-1.pgdg120+1",
     "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, 0.0121, 0.712,
     "PostgreSQL listens on a non-loopback address",
     "PostgreSQL only listens on loopback",
     {"003": "HIGH"}),
    ("CVE-2026-91006", "linux-image-6.8.0-45-generic", "6.8.0-45.45", "6.8.0-49.49",
     "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, 0.0009, 0.301,
     "nf_tables is loaded and unprivileged user namespaces are enabled",
     "unprivileged user namespaces are disabled",
     {"001": "HIGH", "002": "LOW", "005": "MEDIUM", "007": "HIGH"}),
    ("CVE-2026-91007", "libssl3t64", "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, 0.0031, 0.521,
     "a TLS server with PSK cipher suites is running",
     "no TLS server offers PSK",
     {"001": "LOW", "002": "LOW", "003": "INCONCLUSIVE", "004": "LOW", "006": "ABSENT", "007": "LOW", "008": "LOW"}),
    ("CVE-2026-91008", "postfix", "3.5.25-1.el9", "3.5.25-2.el9",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1, 0.0612, 0.921,
     "smtpd is exposed with SMTPUTF8 enabled",
     "SMTPUTF8 is disabled",
     {"004": "HIGH"}),
    ("CVE-2026-91009", "containerd", "1.7.12-0ubuntu4.1", "1.7.24-0ubuntu1",
     "AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", 8.6, 0.0078, 0.661,
     "containers run with the host PID namespace",
     "no container shares the host PID namespace",
     {"006": "MEDIUM", "007": "HIGH"}),
    ("CVE-2026-91010", "git", "2.47.0-1.fc44", "2.47.1-1.fc44",
     "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8, 0.0341, 0.883,
     "git clones untrusted repositories recursively (CI runner)",
     "git is only used interactively",
     {"006": "HIGH", "008": "LOW"}),
    ("CVE-2026-91011", "python3.12", "3.12.3-1ubuntu0.2", "3.12.3-1ubuntu0.4",
     "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 6.5, 0.0012, 0.382, None, None, None),
    ("CVE-2026-91012", "libcurl4t64", "8.5.0-2ubuntu10.4", "8.5.0-2ubuntu10.6",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, 0.0006, 0.213, None, None, None),
    ("CVE-2026-91013", "libxml2", "2.9.14+dfsg-1.3", "2.9.14+dfsg-1.3+deb12u1",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, 0.0025, 0.463, None, None, None),
    ("CVE-2026-91014", "bind9", "1:9.18.28-1~deb12u2", "1:9.18.33-1~deb12u2",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, 0.0893, 0.942,
     "named runs as an open recursive resolver",
     "recursion is restricted to localnets",
     {"008": "LOW"}),
    ("CVE-2026-91015", "vim", "2:9.1.0016-1ubuntu7.3", "2:9.1.0016-1ubuntu7.6",
     "AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8, 0.0004, 0.121, None, None, None),
    ("CVE-2026-91016", "redis-server", "5:7.0.15-1~deb12u1", "5:7.0.15-1~deb12u3",
     "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, 0.2412, 0.961, None, None, None),
    ("CVE-2026-91017", "linux-image-6.8.0-45-generic", "6.8.0-45.45", "6.8.0-51.52",
     "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5, 0.0002, 0.041, None, None, None),
    ("CVE-2026-91018", "apache2", "2.4.52-1ubuntu4.12", "2.4.52-1ubuntu4.13",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, 0.0052, 0.612,
     "mod_proxy is enabled",
     "mod_proxy is not loaded",
     {"002": "MEDIUM"}),
    ("CVE-2026-91019", "exim4-daemon-light", "4.96-15+deb12u5", "4.96-15+deb12u6",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, 0.3105, 0.971,
     "exim listens on port 25 with chunking enabled",
     "exim only listens on loopback",
     {"008": "ABSENT"}),
    ("CVE-2026-91020", "pkexec", "124-2ubuntu1.24.04.1", "124-2ubuntu1.24.04.2",
     "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, 0.3312, 0.973,
     "pkexec is installed with the setuid bit",
     "pkexec has no setuid bit",
     {"001": "HIGH", "002": "LOW", "003": "ABSENT", "007": "HIGH", "008": "INCONCLUSIVE"}),
    ("CVE-2026-91021", "libwebp7", "1.3.2-0.4build3", "1.3.2-0.4build3.1",
     "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8, 0.0034, 0.541, None, None, None),
    ("CVE-2026-91022", "systemd", "255.4-1ubuntu8.4", "255.4-1ubuntu8.5",
     "AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.9, 0.0007, 0.251, None, None, None),
    ("CVE-2026-91023", "jq", "1.7.1-3.fc44", "1.7.1-4.fc44",
     "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L", 4.3, 0.0003, 0.081, None, None, None),
]

# Wazuh detections of the CVEs that have no IoV yet.
NO_IOV_HOSTS = {
    "CVE-2026-91011": ["001", "005", "006", "007"],
    "CVE-2026-91012": ["001", "002", "003", "005", "007", "008"],
    "CVE-2026-91013": ["002", "003", "004", "006"],
    "CVE-2026-91015": ["001", "002", "003", "005", "007", "008"],
    "CVE-2026-91016": ["003", "007"],
    "CVE-2026-91017": ["001", "005"],
    "CVE-2026-91021": ["001", "006"],
    "CVE-2026-91022": ALL,
    "CVE-2026-91023": ["006"],
}

SCORE = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "ABSENT": 0, "INCONCLUSIVE": -1}
SEVERITY = [(9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW")]


def _severity(base: float) -> str:
    return next(label for lower, label in SEVERITY if base >= lower)


def _cvss(vector: str, base: float) -> dict:
    return {"base_score": base, "version": "3.1", "severity": _severity(base),
            "vector": f"CVSS:3.1/{vector}"}


def _reason(level, pkg, version, fixed, pre, neg) -> tuple[str, str | None, list[dict]]:
    affected = [{"name": pkg, "version": version, "state": "AFFECTED"}]
    if level == "HIGH":
        return f"{pkg} {version} is AFFECTED and {pre}; the script returned HIGH.", None, affected
    if level == "MEDIUM":
        return f"{pkg} {version} is AFFECTED; the script could not tell whether {pre}, so the result is MEDIUM.", None, affected
    if level == "LOW":
        return f"{pkg} {version} is AFFECTED, but {neg}; the script returned LOW.", None, affected
    if level == "ABSENT":
        return (f"{pkg} {fixed} is UNAFFECTED (fixed version installed), so the result is ABSENT.", None,
                [{"name": pkg, "version": fixed, "state": "UNAFFECTED"}])
    error = "line 12: evaluating 'listening_ports(\"tcp\")' failed: no such function"
    return f"The script failed ({error}), so the result is INCONCLUSIVE.", error, affected


def _detection(agent_id, cve, pkg, version, base, description, published) -> dict:
    name, os_full = HOSTS.get(agent_id, (agent_id, None))
    return {
        "agent": {"id": agent_id, "name": name},
        "host": {"os": {"full": os_full}},
        "package": {"name": pkg, "version": version},
        "vulnerability": {
            "id": cve,
            "severity": _severity(base).capitalize() if base else None,
            "score": {"base": base, "version": "3.1"} if base else {},
            "description": description,
            "reference": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "detected_at": published,
            "published_at": published,
        },
    }


def generate(exported: list[dict]) -> tuple[list[dict], list[dict], dict]:
    """Return (iov_docs, detections, epss_by_cve) for the demo estate."""
    rng = random.Random(4242)
    now = datetime.now(UTC).replace(microsecond=0)
    today = now.date().isoformat()

    iov_docs = list(exported)
    detections = []
    epss_by_cve = {}

    # The exported verdicts are real; say Wazuh detected each of them, which
    # is how the ABSENT ones show IoV clearing a scanner hit.
    for doc in exported:
        cvss = doc.get("cvss") or {}
        pkg = next(iter(doc.get("packages") or []), {})
        det = _detection(doc["agent_id"], doc["cve_id"], pkg.get("name"), pkg.get("version"),
                         cvss.get("base_score"), None, (now - timedelta(days=12)).isoformat())
        det["agent"]["name"] = doc.get("agent_name") or det["agent"]["name"]
        detections.append(det)

    for cve, pkg, version, fixed, vector, base, epss, pct, pre, neg, levels in CATALOG:
        epss_entry = {"score": epss, "percentile": pct, "date": today}
        cvss = _cvss(vector, base)
        published = (now - timedelta(days=rng.randint(5, 120))).isoformat()
        description = f"Generated demo vulnerability in {pkg} (fixed in {fixed})."

        if levels is None:
            epss_by_cve[cve] = epss_entry
            for agent_id in NO_IOV_HOSTS[cve]:
                detections.append(_detection(agent_id, cve, pkg, version, base, description, published))
            continue

        uuid = f"{rng.getrandbits(32):08x}-{rng.getrandbits(16):04x}-4{rng.getrandbits(12):03x}-a{rng.getrandbits(12):03x}-{rng.getrandbits(48):012x}"
        for agent_id in ALL:
            # The daemon evaluates every IoV on every host.
            level = levels.get(agent_id, "ABSENT")
            if agent_id in levels:
                detections.append(_detection(agent_id, cve, pkg, version, base, description, published))
            reason, error, packages = _reason(level, pkg, version, fixed, pre, neg)
            if agent_id not in levels:
                reason, packages = "No relevant package is installed, so the result is ABSENT.", []
            # jump-host's daemon has been down for a week: its verdicts are stale.
            age = timedelta(days=6, hours=rng.randint(0, 20)) if agent_id == "008" else timedelta(minutes=rng.randint(5, 600))
            iov_docs.append({
                "agent_id": agent_id,
                "agent_name": HOSTS[agent_id][0],
                "cve_id": cve,
                "iov_uuid": uuid,
                "iov_score": SCORE[level],
                "iov_level": level,
                "reason": reason,
                "script_result": SCORE[level] if level != "INCONCLUSIVE" else None,
                "script_ran": True,
                "script_error": error,
                "packages": packages,
                "evaluated_at": (now - age).isoformat(),
                "rule_id": "100203" if level == "HIGH" else "100202" if level == "MEDIUM" else "100201",
                "epss": epss_entry,
                "cvss": cvss,
            })

    return iov_docs, detections, epss_by_cve

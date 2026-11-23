"""Distribution tracker data, fetched directly before generation.

IoVs cover four distributions: Debian, Ubuntu, Red Hat Enterprise Linux and
Alpine. A web search rarely surfaces the pages that hold their fixed versions,
so their trackers are queried through their APIs and condensed into short text
the model can read:

  Ubuntu   CVE API: per-release status of each source package, and the USNs
           it embeds (binary package names and versions of the most recent ones)
  Debian   OSV's DEBIAN-CVE record (fixed version per Debian release)
  Red Hat  security data API (fix state per product, errata with NEVRAs)
  Alpine   secdb (fixed version per branch) and the security tracker (fixed or
           not per branch)

The trackers are queried in parallel within PREFETCH_BUDGET seconds. Every
source fails soft: one that is down, slow or has no record for the CVE is
reported as such, and generation continues with the rest.
"""

import logging
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, wait

import requests

log = logging.getLogger(__name__)

TIMEOUT = 60
USNS_PER_RELEASE = 2           # most recent notices shown with packages, per release
MAX_BINARIES_PER_RELEASE = 12  # binary package names shown per USN and release
MAX_SECTION_CHARS = 40_000     # cap per tracker section (a kernel CVE's Ubuntu data is ~30k)

UBUNTU_REPORTED = ("released", "needed", "pending", "deferred", "not-affected")
PREFETCH_BUDGET = 75          # seconds for all trackers together
ALPINE_BRANCHES = 6            # newest Alpine branches checked in secdb


def _get_json(url: str, timeout: float = TIMEOUT, **params):
    resp = requests.get(url, params=params or None, timeout=timeout)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def _cap(text: str) -> str:
    if len(text) <= MAX_SECTION_CHARS:
        return text
    return text[:MAX_SECTION_CHARS] + "\n[... truncated ...]"


# ── Ubuntu ────────────────────────────────────────────────────────────────────

def _ubuntu_versions() -> dict[str, str]:
    """Ubuntu codename -> version, e.g. "resolute" -> "26.04"."""
    data = _get_json("https://ubuntu.com/security/releases.json") or {}
    return {r["codename"]: r["version"] for r in data.get("releases", []) if r.get("version")}


def _binary_sample(packages: list[dict]) -> list[str]:
    """A few binary packages of one USN release, kernel images first."""
    binaries = [p for p in packages if not p.get("is_source")
                and not p["name"].endswith(("-dbg", "-dbgsym"))]
    images = [p for p in binaries if p["name"].startswith("linux-image-")]
    chosen = (images or binaries)[:MAX_BINARIES_PER_RELEASE]
    lines = [f"{p['name']} {p['version']}" for p in chosen]
    rest = len(images or binaries) - len(chosen)
    if rest > 0:
        lines.append(f"... and {rest} more")
    return lines


def ubuntu_section(cve_id: str) -> str:
    """Per-release status of each source package, and binaries of recent USNs."""
    cve = _get_json(f"https://ubuntu.com/security/cves/{cve_id}.json")
    if cve is None:
        return f"No Ubuntu CVE record for {cve_id}."
    versions = _ubuntu_versions()

    def release(codename: str) -> str:
        return f"ubuntu:{versions[codename]} ({codename})" if codename in versions else codename

    rows = defaultdict(list)
    for package in cve.get("packages", []):
        for status in package.get("statuses", []):
            if status["status"] in UBUNTU_REPORTED and status["release_codename"] != "upstream":
                detail = f" {status['description']}" if status.get("description") else ""
                rows[status["release_codename"]].append(
                    f"{package['name']}: {status['status']}{detail}")

    order = sorted(rows, key=lambda c: versions.get(c, "0"), reverse=True)
    lines = [
        f"Source: https://ubuntu.com/security/{cve_id}",
        (
            "Per release, source package: status [fixed version when released]."
            " Source packages without an entry here do not exist on that release"
            " or are not tracked."
        ),
    ]
    for codename in order:
        lines.append(f"- {release(codename)}: " + "; ".join(sorted(rows[codename])))

    # The CVE record embeds its notices in full. Only the most recent ones per
    # release are shown with packages: they give the current binary package
    # names and versions; older notices only add superseded versions.
    notices = sorted(cve.get("notices") or [], key=lambda n: n.get("published", ""), reverse=True)
    shown: dict[str, list[str]] = defaultdict(list)
    for notice in notices:
        for codename in notice.get("release_packages") or {}:
            if len(shown[codename]) < USNS_PER_RELEASE:
                shown[codename].append(notice["id"])
    lines.append(f"\nUbuntu Security Notices ({len(notices)}): "
                 + ", ".join(n["id"] for n in notices))
    lines.append(f"Binary packages of the {USNS_PER_RELEASE} most recent notices per release"
                 f" (https://ubuntu.com/security/notices/<ID>):")
    for codename in sorted(shown, key=lambda c: versions.get(c, "0"), reverse=True):
        for notice in (n for n in notices if n["id"] in shown[codename]):
            packages = notice["release_packages"][codename]
            sources = [f"{p['name']} {p['version']}" for p in packages if p.get("is_source")]
            lines.append(f"- {release(codename)}, {notice['id']} ({notice.get('published', '')[:10]},"
                         f" {notice.get('title', '')}): source {', '.join(sources) or '-'};"
                         f" binaries: {', '.join(_binary_sample(packages))}")
    return _cap("\n".join(lines))


# ── Debian ────────────────────────────────────────────────────────────────────

def debian_section(cve_id: str) -> str:
    """Fixed version per Debian release, from OSV's DEBIAN-CVE record."""
    record = _get_json(f"https://api.osv.dev/v1/vulns/DEBIAN-{cve_id}")
    if record is None:
        return f"No Debian record for {cve_id} in OSV."
    lines = [f"Source: https://security-tracker.debian.org/tracker/{cve_id} (via OSV DEBIAN-{cve_id})",
             "Per Debian release, source package: fixed version ('unfixed' if no fix yet)."]
    for affected in record.get("affected", []):
        package = affected.get("package", {})
        fixed = [event["fixed"] for r in affected.get("ranges", [])
                 for event in r.get("events", []) if "fixed" in event]
        lines.append(f"- {package.get('ecosystem', '?')}: {package.get('name', '?')}:"
                     f" {', '.join(fixed) if fixed else 'unfixed'}")
    return _cap("\n".join(lines))


# ── Red Hat ───────────────────────────────────────────────────────────────────

def redhat_section(cve_id: str) -> str:
    """Errata and fix state per product, from the Red Hat security data API."""
    record = _get_json(f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json")
    if record is None:
        return f"No Red Hat record for {cve_id}."
    lines = [f"Source: https://access.redhat.com/security/cve/{cve_id}"]
    released = record.get("affected_release") or []
    if released:
        lines.append("Fixed builds (errata):")
        for item in released:
            lines.append(f"- {item.get('product_name')}: {item.get('package') or '?'}"
                         f" ({item.get('advisory')}, {str(item.get('release_date', ''))[:10]})")
    states = record.get("package_state") or []
    if states:
        lines.append("Package states:")
        for item in states:
            lines.append(f"- {item.get('product_name')}: {item.get('package_name')}: {item.get('fix_state')}")
    if not released and not states:
        lines.append("No package information.")
    return _cap("\n".join(lines))


# ── Alpine ────────────────────────────────────────────────────────────────────

def _alpine_branches() -> list[str]:
    """The newest ALPINE_BRANCHES release branches in secdb, e.g. ["v3.19", ...]."""
    index = requests.get("https://secdb.alpinelinux.org/", timeout=TIMEOUT).text
    branches = sorted(set(re.findall(r'href="(v3\.[0-9]+)/"', index)),
                      key=lambda b: int(b.split(".")[1]))
    return branches[-ALPINE_BRANCHES:]


def _alpine_secfixes(branch: str, repo: str, cve_id: str) -> list[str]:
    """Source packages whose secfixes in one branch and repository name the CVE."""
    data = _get_json(f"https://secdb.alpinelinux.org/{branch}/{repo}.json") or {}
    return [f"{entry['pkg']['name']} {version}"
            for entry in data.get("packages", [])
            for version, cves in (entry["pkg"].get("secfixes") or {}).items()
            if cve_id in (cves or [])]


def alpine_section(cve_id: str) -> str:
    """Fixed versions per branch from secdb, and the security tracker's state."""
    lines = [
        f"Source: https://security.alpinelinux.org/vuln/{cve_id} and https://secdb.alpinelinux.org/",
        (
            "secdb and the tracker name Alpine source packages; their binary subpackages "
            "(e.g. openssh-server of openssh) carry the same version."
        ),
    ]

    branches = _alpine_branches()
    keys = [(b, r) for b in branches for r in ("main", "community")]
    with ThreadPoolExecutor(8) as pool:
        found = dict(zip(keys, pool.map(lambda key: _alpine_secfixes(*key, cve_id), keys), strict=True))
    fixes = [f"- alpine:{b[1:]} ({r}): fixed in {', '.join(v)}" for (b, r), v in found.items() if v]
    lines.append(f"Fixed versions per branch from secdb ({', '.join(branches)} checked):")
    lines += fixes or ["- no secdb entry names this CVE in these branches"]

    resp = requests.get(f"https://security.alpinelinux.org/vuln/{cve_id}",
                        headers={"Accept": "application/json"}, timeout=TIMEOUT)
    if resp.status_code == 404:
        lines.append("The Alpine security tracker has no record of this CVE.")
    else:
        resp.raise_for_status()
        states = resp.json().get("state") or []
        if not states:
            lines.append("The Alpine security tracker lists the CVE without package entries "
                         "(no Alpine package is known to be affected).")
        else:
            lines.append("Security tracker state per repository (source package version: fixed?):")
            for state in sorted(states, key=lambda s: s.get("repo", "")):
                package = state.get("packageVersion", "").rsplit("/srcpkg/", 1)[-1]
                verdict = "fixed" if state.get("fixed") else "NOT fixed (affected)"
                lines.append(f"- {state.get('repo')}: {package.replace('/', ' ')}: {verdict}")
    return _cap("\n".join(lines))


# ── All trackers ──────────────────────────────────────────────────────────────

TRACKERS = (
    ("Ubuntu", ubuntu_section), ("Debian", debian_section), ("Red Hat", redhat_section),
    ("Alpine", alpine_section),
)


def fetch_tracker_data(cve_id: str) -> str:
    """All tracker sections as one Markdown block; sources that fail are noted, not raised."""
    pool = ThreadPoolExecutor(len(TRACKERS))
    futures = {pool.submit(fetch, cve_id): name for name, fetch in TRACKERS}
    done, _ = wait(futures, timeout=PREFETCH_BUDGET)
    bodies = {}
    for future, name in futures.items():
        if future not in done:
            log.warning("[%s] %s tracker data timed out", cve_id, name)
            bodies[name] = f"{name} tracker data could not be fetched in time."
            continue
        try:
            bodies[name] = future.result()
        except Exception as exc:  # noqa: BLE001 -- trackers fail soft
            log.warning("[%s] Failed to fetch %s tracker data: %s", cve_id, name, exc)
            bodies[name] = f"{name} tracker data could not be fetched: {exc}"
    pool.shutdown(wait=False, cancel_futures=True)

    sections = [f"### {name}\n\n{bodies[name]}" for name, _ in TRACKERS]
    return (
        f"## Distribution tracker data for {cve_id} (fetched at generation time)\n\n"
        "This is the distributions' own data, queried directly from "
        + ", ".join(name for name, _ in TRACKERS)
        + ". Treat it as the primary source for affected releases and fixed versions.\n\n"
        + "\n\n".join(sections)
    )

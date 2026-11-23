"""Join Wazuh's detections with the IoV verdicts into scored findings, and
summarise them for the dashboard.

A finding is one (agent, CVE) pair. Its sources:

- Wazuh's vulnerability detector (wazuh-states-vulnerabilities-*): what is
  installed and matches a CVE. One document per package, so several can
  collapse into one finding.
- iov-results: the host's IoV verdict, with the CVE's EPSS and CVSS.

Every pair either source knows of is a finding. The daemon evaluates every IoV
it has on every host, so iov-results also holds verdicts for CVEs Wazuh never
detected on that host: an affected verdict there is something only the IoV
found, and an ABSENT one lands in the "not affected" band like any other.
"""
from collections import defaultdict

from dashboard.scoring import parse_time, score_finding


def _key(agent_id, cve_id) -> str:
    return f"{agent_id}:{cve_id}"


def _iov_part(doc: dict) -> dict:
    return {
        "uuid":          doc.get("iov_uuid"),
        "score":         doc.get("iov_score"),
        "level":         doc.get("iov_level"),
        "reason":        (doc.get("reason") or "").strip() or None,
        "script_ran":    doc.get("script_ran"),
        "script_result": doc.get("script_result"),
        "script_error":  (doc.get("script_error") or "").strip() or None,
        "packages":      doc.get("packages") or [],
        "evaluated_at":  doc.get("evaluated_at"),
    }


def _cvss_from_detection(vuln: dict) -> dict | None:
    score = (vuln.get("score") or {})
    if score.get("base") is None:
        return None
    return {
        "base_score": score["base"],
        "version":    score.get("version"),
        "severity":   (vuln.get("severity") or "").upper() or None,
        "vector":     None,
    }


def build_findings(
    iov_docs: list[dict],
    detections: list[dict] | None,
    epss_by_cve: dict[str, dict] | None = None,
) -> tuple[list[dict], dict]:
    """Return (findings sorted by priority, stats about their sources).

    detections are raw wazuh-states-vulnerabilities _source documents, or None
    when only iov-results is available. epss_by_cve fills in EPSS for CVEs no
    IoV document carries it for.
    """
    iov_by_key = {_key(d["agent_id"], d["cve_id"]): d for d in iov_docs}

    # EPSS and CVSS are properties of the CVE, not the host: any document that
    # has them lends them to every finding for that CVE.
    epss = dict(epss_by_cve or {})
    cvss: dict[str, dict] = {}
    for doc in iov_docs:
        if (doc.get("epss") or {}).get("score") is not None:
            epss.setdefault(doc["cve_id"], doc["epss"])
        if (doc.get("cvss") or {}).get("base_score") is not None:
            cvss.setdefault(doc["cve_id"], doc["cvss"])

    detected: dict[str, dict] = {}
    os_by_agent: dict[str, str] = {}
    for det in detections or []:
        agent = det.get("agent") or {}
        vuln = det.get("vulnerability") or {}
        if not agent.get("id") or not vuln.get("id"):
            continue
        key = _key(agent["id"], vuln["id"])
        entry = detected.setdefault(key, {
            "agent_id":   agent["id"],
            "agent_name": agent.get("name") or agent["id"],
            "cve_id":     vuln["id"],
            "packages":   [],
            "wazuh": {
                "severity":     (vuln.get("severity") or "").upper() or None,
                "description":  vuln.get("description"),
                "reference":    vuln.get("reference"),
                "detected_at":  vuln.get("detected_at"),
                "published_at": vuln.get("published_at"),
            },
            "os": ((det.get("host") or {}).get("os") or {}).get("full"),
            "_cvss": _cvss_from_detection(vuln),
        })
        if entry["os"]:
            os_by_agent.setdefault(agent["id"], entry["os"])
        pkg = det.get("package") or {}
        if pkg.get("name"):
            entry["packages"].append({"name": pkg["name"], "version": pkg.get("version")})

    findings = []
    for key in detected.keys() | iov_by_key.keys():
        det = detected.get(key)
        doc = iov_by_key.get(key)
        base = det or doc
        cve_id = base["cve_id"]
        finding = {
            "id":         key,
            "agent_id":   base["agent_id"],
            "agent_name": base.get("agent_name") or base["agent_id"],
            "cve_id":     cve_id,
            "source":     "both" if det and doc else ("wazuh" if det else "iov"),
            "packages":   _merge_packages(det, doc),
            "os":         (det or {}).get("os") or os_by_agent.get(base["agent_id"]),
            "wazuh":      det["wazuh"] if det else None,
            "iov":        _iov_part(doc) if doc else None,
            "epss":       epss.get(cve_id),
            "cvss":       cvss.get(cve_id) or (det or {}).get("_cvss"),
        }
        finding["priority"] = score_finding(finding)
        findings.append(finding)

    findings.sort(key=lambda f: (-f["priority"]["score"], -(f["cvss"] or {}).get("base_score", 0), f["id"]))
    for rank, finding in enumerate(findings, 1):
        finding["rank"] = rank

    return findings, {
        "iov_only": sum(f["source"] == "iov" for f in findings),
        "wazuh_only": sum(f["source"] == "wazuh" for f in findings),
        "both": sum(f["source"] == "both" for f in findings),
    }


def _merge_packages(det: dict | None, doc: dict | None) -> list[dict]:
    """Detection packages, annotated with the IoV's per-package state."""
    states = {p.get("name"): p for p in ((doc or {}).get("packages") or [])}
    merged = []
    for pkg in (det or {}).get("packages", []):
        iov_pkg = states.pop(pkg["name"], {})
        merged.append(pkg | {"state": iov_pkg.get("state")})
    for name, pkg in states.items():
        merged.append({"name": name, "version": pkg.get("version"), "state": pkg.get("state")})
    return merged


# ── Summaries ────────────────────────────────────────────────────────────────

URGENCY = {
    "fix_now":  ("act_now", "Act now"),
    "fix_soon": ("elevated", "Elevated"),
    "plan":     ("moderate", "Moderate"),
    "low":      ("low", "Low"),
    None:       ("clear", "Clear"),
}

OPEN_BANDS = ("fix_now", "fix_soon", "plan", "low")


def summarise(findings: list[dict]) -> dict:
    bands = {b: 0 for b in (*OPEN_BANDS, "not_affected")}
    levels: dict[str, int] = defaultdict(int)
    for f in findings:
        bands[f["priority"]["band"]["key"]] += 1
        levels[f["priority"]["iov_level"]] += 1

    open_findings = [f for f in findings if f["priority"]["band"]["key"] in OPEN_BANDS]
    worst = open_findings[0] if open_findings else None
    worst_band = worst["priority"]["band"]["key"] if worst else None
    urgency_key, urgency_label = URGENCY[worst_band]

    conclusive = sum(levels[lvl] for lvl in ("HIGH", "MEDIUM", "LOW", "ABSENT"))
    script_errors = sorted({f["cve_id"] for f in findings if (f["iov"] or {}).get("script_error")})
    hosts_at_risk = {f["agent_id"] for f in open_findings if f["priority"]["band"]["key"] in ("fix_now", "fix_soon")}

    return {
        "total": len(findings),
        "open": len(open_findings),
        "bands": bands,
        "iov_levels": dict(levels),
        "urgency": {
            "key": urgency_key,
            "label": urgency_label,
            "score": worst["priority"]["score"] if worst else 0,
            "driver": {
                "id": worst["id"], "cve_id": worst["cve_id"], "agent_name": worst["agent_name"],
                "summary": worst["priority"]["summary"],
            } if worst else None,
            "hosts_at_risk": len(hosts_at_risk),
        },
        "iov": {
            "coverage": round(conclusive / len(findings), 3) if findings else 0,
            "conclusive": conclusive,
            "ruled_out": levels["ABSENT"],
            "deprioritised": levels["LOW"],
            "confirmed": levels["HIGH"],
            "script_error_cves": script_errors,
        },
    }


def hosts(findings: list[dict]) -> list[dict]:
    by_host: dict[str, dict] = {}
    for f in findings:
        h = by_host.setdefault(f["agent_id"], {
            "agent_id": f["agent_id"],
            "agent_name": f["agent_name"],
            "os": f["os"],
            "bands": {b: 0 for b in (*OPEN_BANDS, "not_affected")},
            "top_score": 0.0,
            "top_finding": None,
            "risk_load": 0.0,
            "last_evaluated": None,
        })
        h["os"] = h["os"] or f["os"]
        band = f["priority"]["band"]["key"]
        h["bands"][band] += 1
        h["risk_load"] = round(h["risk_load"] + f["priority"]["score"], 1)
        if f["priority"]["score"] > h["top_score"]:
            h["top_score"] = f["priority"]["score"]
            h["top_finding"] = {"id": f["id"], "cve_id": f["cve_id"]}
        evaluated = parse_time((f["iov"] or {}).get("evaluated_at"))
        if evaluated and (h["last_evaluated"] is None or evaluated > parse_time(h["last_evaluated"])):
            h["last_evaluated"] = evaluated.isoformat()

    for h in by_host.values():
        top_band = next((b for b in OPEN_BANDS if h["bands"][b]), None)
        h["urgency"] = {"key": URGENCY[top_band][0], "label": URGENCY[top_band][1]}
    return sorted(by_host.values(), key=lambda h: (-h["top_score"], -h["risk_load"], h["agent_name"]))

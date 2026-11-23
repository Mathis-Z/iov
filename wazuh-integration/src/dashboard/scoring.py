"""The priority model: one 0-100 score per (agent, CVE) finding, with the
reasons behind it.

    priority = 100 x impact x likelihood x applicability

- impact        CVSS base score / 10. How bad a successful exploit is.
- likelihood    0.3 + 0.7 x threat, where threat is EPSS on a log scale:
                0.01% -> 0, 0.1% -> 0.25, 1% -> 0.5, 10% -> 0.75, 100% -> 1.
                The 0.3 floor keeps a severe CVE nobody exploits yet from
                vanishing: EPSS predicts activity, it does not rule it out.
- applicability What the host's IoV verdict says about the preconditions.
                HIGH confirms them (1.0), LOW finds them absent or mitigated
                (0.35), ABSENT clears the host (0). MEDIUM, INCONCLUSIVE and a
                CVE without an IoV all mean "nothing known either way" and
                share the neutral 0.7, so a missing or broken IoV never makes a
                finding look safer than it is.

Everything a reader might ask "why?" about is returned alongside the score.
"""
import math
from datetime import UTC, datetime

# ── Model constants (the only knobs) ─────────────────────────────────────────

LIKELIHOOD_FLOOR = 0.3

# EPSS assumed when FIRST has no score yet, which is mostly brand-new CVEs.
# 1% is above the median on purpose: new CVEs are the ones being weaponised.
EPSS_ASSUMED = 0.01

# CVSS assumed from the scanner's severity label when there is no base score.
CVSS_FROM_SEVERITY = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}
CVSS_ASSUMED = 5.0

IOV_NOT_ASSESSED = "NOT_ASSESSED"

# level -> (applicability factor, short label, explanation)
IOV_FACTORS = {
    "HIGH": (1.0, "Preconditions present",
             "The IoV confirmed that the exploitation preconditions are present on this host."),
    "MEDIUM": (0.7, "Affected, preconditions unknown",
               "An affected version is installed; nothing is known about the preconditions either way."),
    "LOW": (0.35, "Preconditions absent",
            "An affected version is installed, but the exploitation preconditions are absent or mitigated."),
    "ABSENT": (0.0, "Not affected",
               "The IoV found this host is not affected (fixed or no affected package installed)."),
    "INCONCLUSIVE": (0.7, "Inconclusive",
                     "The IoV made no statement for this host. That is not evidence of safety, so it is ranked neutrally."),
    IOV_NOT_ASSESSED: (0.7, "No IoV yet",
                       "No Indicator of Vulnerability exists for this CVE yet, so it is ranked on CVSS and EPSS alone."),
}

IOV_SCORE_TO_LEVEL = {3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "ABSENT", -1: "INCONCLUSIVE"}

# Priority bands, highest first: (key, lower bound, label, suggested action).
BANDS = [
    ("fix_now", 50, "Fix now", "Patch or mitigate within 48 hours"),
    ("fix_soon", 30, "Fix soon", "Patch within 2 weeks"),
    ("plan", 15, "Plan", "Next maintenance window"),
    ("low", 0.001, "Low", "Backlog; revisit when scores change"),
    ("not_affected", 0, "Not affected", "No action; the IoV cleared this host"),
]

# A verdict older than this is flagged: the host may have changed since.
STALE_AFTER_DAYS = 3

_CVSS_V3_LABELS = {
    "AV": ("Attack vector", {"N": "network", "A": "adjacent network", "L": "local", "P": "physical"}),
    "AC": ("Attack complexity", {"L": "low", "H": "high"}),
    "PR": ("Privileges required", {"N": "none", "L": "low", "H": "high"}),
    "UI": ("User interaction", {"N": "none", "R": "required", "P": "passive", "A": "active"}),
    "S":  ("Scope", {"U": "unchanged", "C": "changed"}),
    "C":  ("Confidentiality", {"N": "none", "L": "low", "H": "high"}),
    "I":  ("Integrity", {"N": "none", "L": "low", "H": "high"}),
    "A":  ("Availability", {"N": "none", "L": "low", "H": "high"}),
    "AT": ("Attack requirements", {"N": "none", "P": "present"}),
}


def model_description() -> dict:
    """The model's constants, for the dashboard's "how is this ranked" panel."""
    return {
        "formula": "priority = 100 × impact × likelihood × applicability",
        "likelihood_floor": LIKELIHOOD_FLOOR,
        "epss_assumed": EPSS_ASSUMED,
        "iov_factors": {level: {"factor": f, "label": label, "text": text}
                        for level, (f, label, text) in IOV_FACTORS.items()},
        "bands": [{"key": k, "min": lo, "label": label, "action": action}
                  for k, lo, label, action in BANDS],
    }


# ── Factors ──────────────────────────────────────────────────────────────────

def epss_threat(epss: float) -> float:
    """EPSS probability on a 0-1 log scale: every 10x adds a quarter."""
    if epss <= 0:
        return 0.0
    return min(1.0, max(0.0, (math.log10(epss) + 4) / 4))


def likelihood(epss: float) -> float:
    return LIKELIHOOD_FLOOR + (1 - LIKELIHOOD_FLOOR) * epss_threat(epss)


def band_for(score: float, iov_level: str) -> dict:
    if iov_level == "ABSENT":
        key, _, label, action = BANDS[-1]
        return {"key": key, "label": label, "action": action}
    for key, lower, label, action in BANDS[:-1]:
        if score >= lower:
            return {"key": key, "label": label, "action": action}
    key, _, label, action = BANDS[-2]
    return {"key": key, "label": label, "action": action}


def parse_cvss_vector(vector: str | None) -> list[dict]:
    """Decode the exploitability and impact parts of a CVSS v3/v4 vector."""
    if not vector:
        return []
    parts = []
    for component in vector.split("/")[1:]:
        key, _, value = component.partition(":")
        if key in _CVSS_V3_LABELS:
            name, values = _CVSS_V3_LABELS[key]
            parts.append({"key": key, "name": name, "value": values.get(value, value)})
    return parts


def _impact(finding: dict) -> tuple[float, dict]:
    cvss = finding.get("cvss") or {}
    base = cvss.get("base_score")
    severity = (cvss.get("severity") or (finding.get("wazuh") or {}).get("severity") or "").upper()
    assumed = None
    if base is None:
        if severity in CVSS_FROM_SEVERITY:
            base = CVSS_FROM_SEVERITY[severity]
            assumed = f"No CVSS base score; assumed {base} from the scanner's {severity} rating."
        else:
            base = CVSS_ASSUMED
            assumed = f"No CVSS score or severity known; assumed a neutral {base}."
    base = float(base)
    vector = parse_cvss_vector(cvss.get("vector"))
    by_key = {p["key"]: p["value"] for p in vector}

    bits = []
    if "AV" in by_key:
        bits.append(f"{by_key['AV']} attack vector")
    if "PR" in by_key:
        bits.append(f"{by_key['PR']} privileges required")
    if by_key.get("UI") not in (None, "none"):
        bits.append("needs user interaction")
    detail = ", ".join(bits).capitalize() if bits else "No vector available."

    return base / 10, {
        "key": "impact",
        "label": "Impact",
        "source": "CVSS",
        "factor": round(base / 10, 3),
        "display": f"{base:.1f}" + (f" {severity}" if severity else ""),
        "detail": detail,
        "vector": vector,
        "vector_string": cvss.get("vector"),
        "version": cvss.get("version"),
        "assumed": assumed,
    }


def _likelihood(finding: dict) -> tuple[float, dict]:
    epss = finding.get("epss") or {}
    score = epss.get("score")
    percentile = epss.get("percentile")
    assumed = None
    if score is None:
        score = EPSS_ASSUMED
        assumed = f"No EPSS score yet (usually a new CVE); assumed {EPSS_ASSUMED:.0%}."
    score = float(score)
    factor = likelihood(score)

    if score >= 0.1:
        detail = "Exploitation activity is likely in the next 30 days."
    elif score >= 0.01:
        detail = "Elevated predicted exploitation activity."
    elif score >= 0.001:
        detail = "Low predicted exploitation activity."
    else:
        detail = "Very low predicted exploitation activity."

    display = f"{score:.2%}" if score >= 0.0001 else "<0.01%"
    if percentile is not None:
        display += f" · {_ordinal(round(float(percentile) * 100))} pct"

    return factor, {
        "key": "likelihood",
        "label": "Likelihood",
        "source": "EPSS",
        "factor": round(factor, 3),
        "display": display,
        "detail": detail,
        "epss": score,
        "percentile": percentile,
        "assumed": assumed,
    }


def _applicability(finding: dict) -> tuple[float, str, dict]:
    iov = finding.get("iov")
    level = iov_level(iov)
    factor, label, text = IOV_FACTORS[level]

    notes = []
    if iov:
        if iov.get("script_error"):
            notes.append("The IoV's check script failed on this host; the IoV likely needs regenerating.")
        elif level == "INCONCLUSIVE" and iov.get("reason"):
            notes.append(iov["reason"])
        age = _age_days(iov.get("evaluated_at"))
        if age is not None and age > STALE_AFTER_DAYS:
            notes.append(f"Verdict is {age:.0f} days old; the host may have changed since.")

    return factor, level, {
        "key": "applicability",
        "label": "Applicability",
        "source": "IoV",
        "factor": factor,
        "display": label,
        "level": level,
        "detail": text,
        "notes": notes,
        "assumed": None,
    }


def iov_level(iov: dict | None) -> str:
    if not iov:
        return IOV_NOT_ASSESSED
    level = (iov.get("level") or "").upper()
    if level in IOV_FACTORS:
        return level
    return IOV_SCORE_TO_LEVEL.get(iov.get("score"), "INCONCLUSIVE")


# ── Scoring ──────────────────────────────────────────────────────────────────

def _compose(impact: float, like: float, applicability: float) -> float:
    return round(100 * impact * like * applicability, 1)


def score_finding(finding: dict) -> dict:
    """Return the finding's priority: score, band, factors and reasons."""
    impact, impact_info = _impact(finding)
    like, like_info = _likelihood(finding)
    applic, level, applic_info = _applicability(finding)

    score = _compose(impact, like, applic)
    band = band_for(score, level)

    # What an IoV verdict could still change, for findings without a firm one.
    what_if = None
    if level in ("MEDIUM", "INCONCLUSIVE", IOV_NOT_ASSESSED):
        what_if = {
            lvl: {"score": s, "band": band_for(s, lvl)["label"]}
            for lvl in ("HIGH", "LOW")
            for s in [_compose(impact, like, IOV_FACTORS[lvl][0])]
        }

    return {
        "score": score,
        "band": band,
        "iov_level": level,
        "summary": _summary(impact_info, like_info, applic_info, finding),
        "factors": [impact_info, like_info, applic_info],
        "what_if": what_if,
        "assumptions": [f["assumed"] for f in (impact_info, like_info, applic_info) if f["assumed"]],
    }


def _summary(impact: dict, like: dict, applic: dict, finding: dict) -> str:
    """One line, in the order a reader weighs it: host fact, threat, impact."""
    level = applic["level"]
    epss = like["epss"]
    iov = finding.get("iov") or {}
    parts = []

    if level == "INCONCLUSIVE" and iov.get("script_error"):
        parts.append("IoV check failed")
    else:
        parts.append({
            "HIGH": "IoV confirmed preconditions",
            "MEDIUM": "Affected version installed",
            "LOW": "IoV: preconditions absent",
            "ABSENT": "IoV: host not affected",
            "INCONCLUSIVE": "IoV inconclusive",
            IOV_NOT_ASSESSED: "No IoV yet",
        }[level])

    if like["assumed"]:
        parts.append("no EPSS yet")
    elif epss >= 0.1:
        parts.append(f"likely exploited (EPSS {epss:.0%})")
    elif epss >= 0.01:
        parts.append(f"elevated exploit activity (EPSS {epss:.1%})")
    else:
        parts.append("low exploit activity")

    severity = impact["display"].split(" ", 1)
    words = severity[1].lower() if len(severity) > 1 else "unknown"
    av = next((p["value"] for p in impact["vector"] if p["key"] == "AV"), None)
    parts.append(f"{words} impact" + (f", {av}" if av else ""))
    return " · ".join(parts)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _ordinal(n: int) -> str:
    if 10 <= n % 100 <= 20:
        return f"{n}th"
    return str(n) + {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")


def parse_time(value) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).strip()
    for fmt in (None, "%b %d, %Y @ %H:%M:%S.%f"):  # ISO, then Dashboards' CSV export
        try:
            parsed = datetime.fromisoformat(text) if fmt is None \
                else datetime.strptime(text, fmt)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def _age_days(value, now: datetime | None = None) -> float | None:
    when = parse_time(value)
    if when is None:
        return None
    return ((now or datetime.now(UTC)) - when).total_seconds() / 86400

"""Evaluating an IoV (format version 2) against the host.

The result is a confidence score that the CVE applies, and a human-readable
reason for it:

    0 ABSENT   1 LOW   2 MEDIUM/DEFAULT   3 HIGH   None INCONCLUSIVE

An uncovered release is INCONCLUSIVE. On a covered release the precedence is
AFFECTED > UNKNOWN > UNAFFECTED, and a covered release on which no relevant
package is installed is ABSENT. When packages are present the script only runs
if an affected version is installed.
"""

import logging
from datetime import UTC, datetime
from typing import NamedTuple

from . import AGENT_VERSION, packages, releases, validation
from .host import kernel, pkgdb
from .logging_setup import LOGGER_NAME
from .packages import AFFECTED, UNAFFECTED, UNKNOWN, PackageResult
from .script.interpreter import ScriptOutcome, run_script, unsupported_functions
from .versions import COMPARATORS

log = logging.getLogger(LOGGER_NAME)

DEFAULT = 2

# INCONCLUSIVE means "the IoV makes no statement about this host". It is
# distinct from ABSENT and must never be read as evidence of safety. Result
# carries it as None; reports carry it as this sentinel so the field stays a
# plain integer.
INCONCLUSIVE = -1

LEVEL_NAMES = {INCONCLUSIVE: "INCONCLUSIVE", 0: "ABSENT", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}

# How many packages a reason names before summarizing the rest.
MAX_REASON_ITEMS = 5


class Result(NamedTuple):
    """The verdict on one IoV: score, reason, and the evidence behind it."""
    score: int | None                      # None = INCONCLUSIVE
    reason: str
    packages: list[PackageResult] = []
    script: ScriptOutcome | None = None    # None = the script did not run
    host_release: str | None = None

    @property
    def iov_score(self) -> int:
        return INCONCLUSIVE if self.score is None else self.score

    @property
    def level(self) -> str:
        return LEVEL_NAMES[self.iov_score]


def _enumerate(details: list[str]) -> str:
    shown = details[:MAX_REASON_ITEMS]
    text = "; ".join(shown)
    if len(details) > len(shown):
        text += f"; and {len(details) - len(shown)} more"
    return text


def _script_reason(outcome: ScriptOutcome, fallback: str) -> str:
    """The part of a reason that describes the script's outcome."""
    if outcome.value is not None:
        return f"the script returned {LEVEL_NAMES[outcome.value]}"
    if outcome.limit:
        return f"the script exceeded a sandbox limit ({outcome.error}), so the result is {fallback}"
    if outcome.error:
        return f"the script failed ({outcome.error}), so the result is {fallback}"
    return f"the script made no statement, so the result is {fallback}"


def _run(script: str, fallback: int | None, prefix: str, host: str | None,
         states: list[PackageResult]) -> Result:
    outcome = run_script(script)
    fallback_name = "DEFAULT" if fallback == DEFAULT else "INCONCLUSIVE"
    reason = _script_reason(outcome, fallback_name)
    reason = f"{prefix}; {reason}." if prefix else reason[0].upper() + reason[1:] + "."
    score = fallback if outcome.value is None else outcome.value
    return Result(score, reason, states, outcome, host)


def evaluate(iov: dict) -> Result:
    """Evaluate an IoV document against this host.

    Never raises for a bad document: a document that is not version 2, violates
    the schema or calls unknown built-ins is INCONCLUSIVE with a reason.
    """
    if not isinstance(iov, dict):
        return Result(None, "The IoV is not a JSON object.")
    problem = validation.unsupported_version(iov)
    if problem:
        return Result(None, problem)
    problem = validation.validation_error(iov)
    if problem:
        return Result(None, f"The IoV violates the schema: {problem}.")

    script = iov.get("script")
    if script:
        unknown = unsupported_functions(script)
        if unknown:
            names = ", ".join(f"{n}()" for n in sorted(unknown))
            return Result(None, f"The script uses built-ins this agent does not provide: {names}.")

    iov_packages = iov.get("packages")
    if not iov_packages:
        return _run(script, None, "", None, [])

    host = releases.host_release()
    if host.dist_id is None:
        return Result(None, "The host's release could not be determined "
                            "(/etc/os-release is missing or has no ID).")
    covered = any(
        releases.best_match(range_set.get("releases", []), host) is not None
        for entry in iov_packages.values() for range_set in entry.get("ranges", [])
    )
    if not covered:
        return Result(None, f"Release {host} is not covered by any range set of this IoV.",
                      host_release=str(host))

    inventory = pkgdb.inventory()
    if inventory is None:
        return Result(None, "The installed packages could not be enumerated "
                            "(no supported package manager was found).", host_release=str(host))
    manager = releases.PACKAGE_MANAGERS.get(host.dist_id, inventory.manager)
    compare = COMPARATORS[manager]

    states: list[PackageResult] = []
    grouped = packages.packages_by_key(list(iov_packages), inventory.packages)
    for key, found in grouped.items():
        relevant, no_running_kernel = packages.relevant_packages(key, found)
        for package in relevant:
            state = packages.classify(key, package, iov_packages[key], host, compare)
            log.info("%s under key %r: %s", package.label(), key, state.state)
            states.append(state)
        if no_running_kernel:
            states.append(PackageResult(
                key, None, None, None, None, UNKNOWN,
                f"kernel images under {key} are installed, but none belongs to the "
                f"running kernel {kernel.kernel_release()}",
            ))

    by_state = {
        s: [r.detail for r in states if r.state == s] for s in (AFFECTED, UNKNOWN, UNAFFECTED)
    }

    if by_state[AFFECTED]:
        affected = _enumerate(by_state[AFFECTED])
        if not script:
            return Result(DEFAULT, f"{affected}; the IoV has no script, so the result is DEFAULT.",
                          states, None, str(host))
        return _run(script, DEFAULT, affected, str(host), states)

    if by_state[UNKNOWN]:
        unknown = _enumerate(by_state[UNKNOWN])
        return Result(None, f"No installed package is affected, but {unknown}, "
                            "so the IoV makes no statement.", states, None, str(host))

    if by_state[UNAFFECTED]:
        reason = f"Every relevant package is unaffected: {_enumerate(by_state[UNAFFECTED])}."
    else:
        reason = f"No package listed by this IoV is installed on the covered release {host}."
    return Result(0, reason, states, None, str(host))


def results_document(iov: dict, result: Result, evaluated_at: datetime | None = None) -> dict:
    """The evaluation results document of the IoV specification."""
    evaluated_at = evaluated_at or datetime.now(UTC)
    script = None
    if result.script is not None:
        script = {"ran": True, "returned": result.script.value, "error": result.script.error}
    return {
        "iov_uuid": iov.get("uuid"),
        "cve": iov.get("cve"),
        "schema_version": iov.get("schema_version"),
        "iov_updated": iov.get("updated"),
        "evaluated_at": evaluated_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "agent_version": AGENT_VERSION,
        "host_release": result.host_release,
        "packages": [p.as_dict() for p in result.packages],
        "script": script or {"ran": False, "returned": None, "error": None},
        "iov_score": result.iov_score,
        "reason": result.reason,
    }

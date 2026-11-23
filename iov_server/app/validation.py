"""Ingestion checks for generated IoVs.

The checks are the agent's own (the evaluate_iov package, which the image
copies from iov-evaluation/evaluate_iov): an IoV the server accepts is one
the agents can evaluate, and the two cannot drift apart.
"""

import json

from evaluate_iov import validation
from evaluate_iov.script.interpreter import check_script

# IoVs cover exactly these distributions (os-release IDs); see the Distributions
# guidelines in the prompt.
COVERED_DISTRIBUTIONS = ("debian", "ubuntu", "rhel", "alpine")


def iov_problem(cve_id: str, iov_json: str) -> str | None:
    """Explain why the generated IoV is unusable, or None if it is fine.

    The explanation goes back to the model verbatim, so it names the offending
    field or script line.
    """
    try:
        document = json.loads(iov_json)
    except json.JSONDecodeError as exc:
        return f"The output is not valid JSON: {exc}."
    if not isinstance(document, dict):
        return "The output is not a JSON object."

    if document.get("cve") != cve_id:
        return f"The IoV is for {document.get('cve')!r}, but it must be for {cve_id}."
    problem = validation.unsupported_version(document)
    if problem:
        return problem
    problem = validation.validation_error(document)
    if problem:
        return f"The IoV violates the schema at {problem}."

    problem = _uncovered_distributions(document)
    if problem:
        return problem

    script = document.get("script")
    if script:
        problem = check_script(script)
        if problem:
            return f"The script is invalid: {problem}."
    return None


def _uncovered_distributions(document: dict) -> str | None:
    """Name release IDs outside COVERED_DISTRIBUTIONS, in range sets or references."""
    specs = [spec for entry in (document.get("packages") or {}).values()
             for range_set in entry.get("ranges", []) for spec in range_set.get("releases", [])]
    specs += [spec for reference in document.get("references") or []
              for spec in reference.get("releases") or []]
    others = sorted({spec.split(":", 1)[0] for spec in specs} - set(COVERED_DISTRIBUTIONS))
    if not others:
        return None
    return (f"The IoV lists releases of {', '.join(others)}, but it must cover only "
            f"{', '.join(COVERED_DISTRIBUTIONS)}. Remove every range set and reference "
            "release of other distributions.")

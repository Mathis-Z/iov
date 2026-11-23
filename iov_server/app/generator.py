"""IoV generation for one CVE: context, research, writing, validation.

Context. Data that needs no search engine is fetched directly and prepended to
every request: the CIRCL Vulnerability-Lookup record, GitHub Security
Advisories and the trackers of the four distributions IoVs cover (Debian,
Ubuntu, Red Hat Enterprise Linux and Alpine; app.trackers).

1. Research. The model gets the context, a short brief of what an IoV needs,
   and OpenRouter's server tools openrouter:web_search and openrouter:web_fetch,
   which OpenRouter executes inside the request. It fills the gaps the trackers
   leave and ends with research notes. The IoV specification is not sent here:
   every tool round re-reads the whole context, and the specification is two
   thirds of it. Structured outputs are not used either: with them, the model
   cannot call tools.
2. Writing. A fresh request with the context, the full IoV specification and
   the research notes; the model writes the IoV with structured outputs pinned
   to the schema, and no tools.
3. Validation. Structured outputs do not guarantee a usable IoV: the script
   language is not expressible in the schema. Every answer is checked with the
   agent's own checks (app.validation); a rejected one goes back to the model
   with the reason, for at most MAX_CORRECTIONS rounds.

Every request is streamed and cut off at a wall-clock deadline, so a provider
that keeps the connection open without finishing cannot stall a worker.
"""

import json
import logging
import re
import socket
import threading
import time

import requests

from app.config import (
    DATA_DIR,
    LLM_MODEL,
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    OPENROUTER_IGNORE_PROVIDERS,
    OPENROUTER_PROVIDER_SORT,
    PROMPT_PATH,
    REASONING_EFFORT_CORRECTION,
    REASONING_EFFORT_RESEARCH,
    REASONING_EFFORT_WRITE,
    RESEARCH_DEADLINE,
    RESEARCH_MAX_FETCHES,
    RESEARCH_MAX_SEARCHES,
    VULNERABILITY_LOOKUP_API_KEY,
    WEB_FETCH_MAX_CONTENT_TOKENS,
    WEB_SEARCH_ENGINE,
    WEB_SEARCH_MAX_RESULTS,
    WRITE_DEADLINE,
)
from app.trackers import fetch_tracker_data
from app.validation import iov_problem

log = logging.getLogger(__name__)

SCHEMA_START = "<<< START OF IOV SCHEMA >>>"
SCHEMA_END = "<<< END OF IOV SCHEMA >>>"

# Connect and between-chunks read timeouts; OpenRouter streams keep-alive
# comments, so the read timeout only catches a connection that went silent.
# The deadlines per request are in app.config.
STREAM_TIMEOUT = (15, 120)
MAX_CORRECTIONS = 3    # rounds in which the model may fix a rejected IoV

RESEARCH_PROMPT = """\
# Task: research {cve_id}

The data above will be used to write an Indicator of Vulnerability (IoV) for \
{cve_id}: a JSON document with which an agent on a Linux host decides whether \
the host is affected. It has two parts:
- packages: per distribution release (ID and VERSION_ID from /etc/os-release, \
e.g. debian:12, ubuntu:24.04, rhel:9, alpine:3.20), the binary package names as \
installed (for kernels usually a name pattern such as linux-image-6.1.0-*-amd64) \
and the affected and fixed versions, exactly as the package manager reports \
them. IoVs cover exactly four distributions: Debian and Ubuntu (dpkg), Red Hat \
Enterprise Linux (RPM) and Alpine Linux (apk). Other distributions, including \
derivatives such as CentOS, AlmaLinux, Rocky Linux or Fedora, are not covered.
- script: checks of the preconditions and mitigations for exploitation on the \
live host, e.g. kernel build options and loaded modules, sysctls, unprivileged \
user namespaces, running services and listening sockets, configuration file \
settings, SELinux/AppArmor, CPU and hardware.

Your job now is only the research; the IoV is written in a later step. You have \
two tools: web_search searches the web, and web_fetch opens a URL and returns \
the page. Use them sparingly, for gaps only:
- The distribution tracker data above was queried directly from the trackers \
of all four distributions. Do not open those trackers again. Open an advisory \
of these distributions only if a fixed version or a binary package name you \
need is missing from the data.
- Do not research any other distribution.
- Look up what the data does not cover: the affected component and the \
vulnerable code path, and the preconditions and mitigations for exploitation.
- Report only facts you read on a page or in the data above, each with its URL.

Answer with research notes in exactly this structure:
## Packages
One line per release of Debian, Ubuntu, Red Hat Enterprise Linux and Alpine: \
release (ID:VERSION), binary package \
name(s) or name pattern, fixed version (or "unfixed", or "not affected"), \
architecture restrictions if any, advisory ID and URL.
## Upstream
Affected component, affected and fixed upstream versions, fix commits, URLs.
## Preconditions and mitigations
What must hold on a host for exploitation, and what prevents it, with URLs.
## Not found
What you looked for but could not establish."""

WRITE_PROMPT = """\
# Research notes for {cve_id}

The research for this CVE is complete; do not search further. These notes were \
made from the distribution tracker data above and the web:

{notes}

Write the IoV for {cve_id} now, from the distribution tracker data and these \
research notes. Follow the schema and all guidelines above, and output only \
the IoV JSON. Cover only Debian, Ubuntu, Red Hat Enterprise Linux and Alpine \
(release IDs debian, ubuntu, rhel and alpine), and list only releases, versions \
and references that appear in the tracker data or the research notes."""

CORRECTION_PROMPT = """\
Your IoV for {cve_id} was rejected: {problem}

Output the complete corrected IoV as a single JSON object that follows the \
schema. Fix this problem, and check the rest of the IoV, in particular every \
script line against the script language rules, for further errors of the same \
kind. Keep everything else unchanged."""


class IovRejected(Exception):
    """The model did not produce a valid IoV within MAX_CORRECTIONS rounds."""


def trim_json(obj, max_chars: int = 10_000):
    """Trim a parsed JSON object bottom-up, replacing any node whose serialized
    form exceeds max_chars with a truncation marker string."""
    MARKER = "...TRUNCATED..."

    if isinstance(obj, str):
        return obj[:max_chars] + MARKER if len(obj) > max_chars else obj

    if isinstance(obj, list):
        trimmed_list_items = [trim_json(item, max_chars) for item in obj]
        if len(json.dumps(trimmed_list_items)) <= max_chars:
            return trimmed_list_items
        else:
            shortened_list = []
            while trimmed_list_items and len(json.dumps(shortened_list + [MARKER])) <= max_chars:
                shortened_list.append(trimmed_list_items.pop(0))
            shortened_list.append(MARKER)
            return shortened_list

    if isinstance(obj, dict):
        trimmed_dictionary = {k: trim_json(v, max_chars) for k, v in obj.items()}
        if len(json.dumps(trimmed_dictionary)) <= max_chars:
            return trimmed_dictionary
        else:
            shortened_dict = {}
            for k, v in trimmed_dictionary.items():
                if len(json.dumps({**shortened_dict, k: v, "MORE_DATA": MARKER})) <= max_chars:
                    shortened_dict[k] = v
                else:
                    shortened_dict["MORE_DATA"] = MARKER
                    break
            return shortened_dict

    return obj


def fetch_initial_cve_info(cve_id: str) -> str:
    """Structured CVE data that does not need a search engine to find."""
    sections = []

    # Vulnerability Lookup API (vulnerability.circl.lu)
    try:
        url = f"https://vulnerability.circl.lu/api/vulnerability/{cve_id.lower()}"
        params = {
            "with_meta": "true",
            # Linked records duplicate the GitHub advisory and can take the API
            # over 30 s (or fail with 503).
            "with_linked": "false",
            "with_comments": "false",
            "with_bundles": "false",
            "with_sightings": "false",
        }
        headers = {"X-API-KEY": VULNERABILITY_LOOKUP_API_KEY} if VULNERABILITY_LOOKUP_API_KEY else {}
        resp = requests.get(url, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        trimmed = trim_json(resp.json())
        sections.append(f"## Vulnerability Lookup data for {cve_id}\n\n{json.dumps(trimmed, indent=2)}")
    except Exception as e:  # noqa: BLE001 -- context sources fail soft
        log.warning("[%s] Failed to fetch from vulnerability.circl.lu: %s", cve_id, e)

    # GitHub Security Advisories
    try:
        resp = requests.get(
            "https://api.github.com/advisories",
            params={"cve_id": cve_id, "per_page": 5},
            headers={"Accept": "application/vnd.github+json"},
            timeout=30,
        )
        resp.raise_for_status()
        # The description and references repeat the CVE record above; keep
        # what is specific to the advisory, notably the affected ecosystem
        # packages (npm, PyPI, ...) with their version ranges.
        keep = ("ghsa_id", "html_url", "type", "severity", "cvss_severities", "cwes",
                "vulnerabilities", "published_at", "updated_at", "withdrawn_at")
        advisories = [{key: a[key] for key in keep if a.get(key) is not None} for a in resp.json()]
        trimmed = trim_json(advisories)
        sections.append(f"## GitHub Security Advisories for {cve_id}\n\n{json.dumps(trimmed, indent=2)}")
    except Exception as e:  # noqa: BLE001 -- context sources fail soft
        log.warning("[%s] Failed to fetch GHSAs: %s", cve_id, e)

    sections.append(fetch_tracker_data(cve_id))

    return "\n\n".join(sections)


def extract_schema(prompt_text: str) -> dict:
    """Pull the IoV JSON Schema out of the prompt.

    The prompt is the single source of truth for the schema: the model is told
    to follow it and structured outputs then hold it to that, so the two cannot
    drift apart.
    """
    start = prompt_text.find(SCHEMA_START)
    end = prompt_text.find(SCHEMA_END)
    if start == -1 or end == -1:
        raise ValueError(
            f"{PROMPT_PATH} has no {SCHEMA_START} / {SCHEMA_END} block to take the schema from"
        )
    return json.loads(prompt_text[start + len(SCHEMA_START):end])


def structured_output_schema(schema):
    """The schema as sent for structured outputs.

    Some OpenRouter providers compile the schema with xgrammar, which rejects
    a string that carries both "format" and "pattern" ("constraints format,
    pattern cannot be enforced together"). Every such field in the IoV schema
    (uuid, timestamps, reference URLs) has a pattern at least as strict as its
    format, so the format is dropped there. xgrammar also rejects uniqueItems
    ("keyword(s) uniqueItems would be ignored"), so it is dropped everywhere.
    The prompt keeps the full schema, and app.validation checks every answer
    against it.
    """
    if isinstance(schema, dict):
        cleaned = {key: structured_output_schema(value) for key, value in schema.items()
                   if key != "uniqueItems"}
        if "pattern" in cleaned and "format" in cleaned:
            del cleaned["format"]
        return cleaned
    if isinstance(schema, list):
        return [structured_output_schema(item) for item in schema]
    return schema


def _base_request(messages: list[dict], effort: str) -> dict:
    return {
        "model": LLM_MODEL,
        "messages": messages,
        "reasoning": {"effort": effort},
        "provider": {
            # Only providers that support every parameter sent: otherwise a request
            # can land on a provider that silently ignores the tools or the schema.
            "require_parameters": True,
            **({"sort": OPENROUTER_PROVIDER_SORT} if OPENROUTER_PROVIDER_SORT else {}),
            **({"ignore": OPENROUTER_IGNORE_PROVIDERS} if OPENROUTER_IGNORE_PROVIDERS else {}),
        },
    }


def research_request(messages: list[dict]) -> dict:
    """Phase 1: research with OpenRouter's server tools, free-form answer."""
    body = _base_request(messages, REASONING_EFFORT_RESEARCH)
    body["tools"] = [
        {
            "type": "openrouter:web_search",
            "parameters": {
                "engine": WEB_SEARCH_ENGINE,
                "max_uses": RESEARCH_MAX_SEARCHES,
                "max_results": WEB_SEARCH_MAX_RESULTS,
            },
        },
        {
            "type": "openrouter:web_fetch",
            "parameters": {
                "max_uses": RESEARCH_MAX_FETCHES,
                "max_content_tokens": WEB_FETCH_MAX_CONTENT_TOKENS,
            },
        },
    ]
    return body


def iov_request(messages: list[dict], schema: dict, effort: str) -> dict:
    """Phase 2: the IoV itself, pinned to the schema, without tools."""
    body = _base_request(messages, effort)
    body["response_format"] = {
        "type": "json_schema",
        "json_schema": {
            "name": "indicator_of_vulnerability",
            # Not strict: the IoV schema uses $defs/$ref, anyOf and
            # propertyNames, which strict mode rejects. The schema still
            # constrains generation, and the result is validated below.
            "strict": False,
            "schema": structured_output_schema(schema),
        },
    }
    return body


def _shutdown(resp: requests.Response) -> None:
    """Shut down a streamed response's socket, ending a read blocked on it.

    While the body streams, the socket belongs to http.client's response,
    not to the urllib3 connection.
    """
    try:
        resp.raw._fp.fp.raw._sock.shutdown(socket.SHUT_RDWR)
    except (AttributeError, OSError):
        resp.close()


def _post(body: dict, deadline_seconds: int) -> dict:
    """Stream one completion and return it shaped like a non-streamed response.

    Raises TimeoutError if the completion is not finished within
    deadline_seconds, and RuntimeError for errors OpenRouter reports, including
    those that arrive mid-stream after the request was accepted.
    """
    deadline = time.monotonic() + deadline_seconds
    resp = requests.post(
        f"{OPENROUTER_BASE_URL}/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
        },
        json={**body, "stream": True},
        stream=True,
        timeout=STREAM_TIMEOUT,
    )
    if resp.status_code >= 400:
        # The body carries the actual reason (unsupported parameter, bad model,
        # rejected schema); the status alone is not enough to act on.
        raise RuntimeError(f"OpenRouter returned HTTP {resp.status_code}: {resp.text[:2000]}")

    content: list[str] = []
    reasoning: list[str] = []
    annotations: list = []
    usage: dict = {}
    provider = finish_reason = None
    # iter_lines() blocks until a whole read chunk has arrived, so a stream that
    # trickles keep-alives never reaches the deadline check in the loop nor
    # trips the read timeout. The watchdog shuts the socket down at the
    # deadline, which ends the blocked read (closing it would not).

    def timeout_message() -> str:
        # How far the provider got tells a slow provider from a stalled one.
        return (f"no complete response within {deadline_seconds} s"
                f" (provider {provider or 'unknown'}, received {sum(map(len, reasoning))}"
                f" reasoning and {sum(map(len, content))} content characters)")

    watchdog = threading.Timer(max(deadline - time.monotonic(), 0), _shutdown, (resp,))
    watchdog.daemon = True
    watchdog.start()
    try:
        # Split the raw bytes: decoded text would also be split at Unicode line
        # separators (U+2028, U+0085, ...), which can occur inside a JSON string.
        for raw in resp.iter_lines():
            line = raw.decode("utf-8", errors="replace")
            if time.monotonic() > deadline:
                raise TimeoutError(timeout_message())
            # Blank lines separate events; lines starting with ':' are keep-alives.
            if not line or not line.startswith("data:"):
                continue
            data = line[len("data:"):].strip()
            if data == "[DONE]":
                break
            chunk = json.loads(data)
            if chunk.get("error"):
                raise RuntimeError(f"OpenRouter returned an error: {json.dumps(chunk['error'])[:2000]}")
            provider = chunk.get("provider") or provider
            usage = chunk.get("usage") or usage
            for choice in chunk.get("choices") or []:
                delta = choice.get("delta") or {}
                content.append(delta.get("content") or "")
                reasoning.append(delta.get("reasoning") or "")
                annotations += delta.get("annotations") or []
                finish_reason = choice.get("finish_reason") or finish_reason
    except Exception as exc:
        if time.monotonic() > deadline:
            raise TimeoutError(timeout_message()) from exc
        raise
    finally:
        watchdog.cancel()
        resp.close()

    if finish_reason is None:
        if time.monotonic() > deadline:
            raise TimeoutError(timeout_message())
        raise RuntimeError("OpenRouter's stream ended without a finished completion")
    if finish_reason == "error":
        raise RuntimeError("OpenRouter reported an error as the finish reason")
    return {
        "provider": provider,
        "usage": usage,
        "choices": [{
            "finish_reason": finish_reason,
            "message": {
                "content": "".join(content),
                "reasoning": "".join(reasoning),
                "annotations": annotations,
            },
        }],
    }


def run_generator(cve_id: str) -> str:
    """Generate the IoV for cve_id and return it as indented JSON.

    Raises IovRejected if no answer passes validation within MAX_CORRECTIONS
    rounds; network and API errors propagate so the task can be retried.
    """
    log.info(
        "[%s] Generating with model=%s search=%s effort=%s/%s/%s max_searches=%d max_fetches=%d",
        cve_id, LLM_MODEL, WEB_SEARCH_ENGINE, REASONING_EFFORT_RESEARCH, REASONING_EFFORT_WRITE,
        REASONING_EFFORT_CORRECTION, RESEARCH_MAX_SEARCHES, RESEARCH_MAX_FETCHES,
    )

    prompt_text = PROMPT_PATH.read_text()
    schema = extract_schema(prompt_text)
    specification = prompt_text.replace("{CVE_ID}", cve_id)
    data = fetch_initial_cve_info(cve_id)

    logs_dir = DATA_DIR / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    with (logs_dir / f"{cve_id}.log").open("w", encoding="utf-8") as log_file:
        def section(title: str, text: str) -> None:
            log_file.write(f"{'=' * 60}\n[{title}]\n{text}\n")
            log_file.flush()

        def log_response(label: str, response: dict) -> str:
            choice = response["choices"][0]
            section(f"USAGE{label}", f"provider: {response.get('provider')}\n"
                                    f"finish reason: {choice.get('finish_reason')}\n"
                                    + json.dumps(response.get("usage", {}), indent=2))
            message = choice["message"]
            # The model's thought process, including what it searched for and
            # opened: OpenRouter does not report the server tool calls themselves.
            reasoning = message.get("reasoning") or "".join(
                detail.get("text") or detail.get("summary") or ""
                for detail in message.get("reasoning_details") or [])
            if reasoning:
                section(f"REASONING{label}", reasoning)
            citations = message.get("annotations") or []
            if citations:
                section(f"CITATIONS{label}", json.dumps(citations, indent=2))
            content = message.get("content") or ""
            section(f"RESPONSE{label}", content)
            return content

        section("REQUEST", f"model: {LLM_MODEL}\nsearch engine: {WEB_SEARCH_ENGINE}"
                           f"\nreasoning effort: research={REASONING_EFFORT_RESEARCH},"
                           f" write={REASONING_EFFORT_WRITE}, correction={REASONING_EFFORT_CORRECTION}"
                           f"\nmax searches: {RESEARCH_MAX_SEARCHES}, max fetches: {RESEARCH_MAX_FETCHES}"
                           f"\ndeadlines: research={RESEARCH_DEADLINE}s, write={WRITE_DEADLINE}s"
                           f"\nspecification: {PROMPT_PATH.name} (sent with the writing phase)")
        section("DATA", data)

        # Phase 1: research, without the specification.
        research = [{"role": "user", "content": data + "\n\n" + RESEARCH_PROMPT.format(cve_id=cve_id)}]
        started = time.monotonic()
        notes = log_response(" (research)", _post(research_request(research), RESEARCH_DEADLINE))
        log.info("[%s] Research took %.0f s", cve_id, time.monotonic() - started)
        if not notes.strip():
            raise RuntimeError(f"The research phase for {cve_id} returned no notes")

        # Phase 2: the IoV, with the specification and the notes, and correction rounds.
        messages = [{"role": "user", "content": data + "\n\n" + specification + "\n\n"
                     + WRITE_PROMPT.format(cve_id=cve_id, notes=notes.strip())}]
        for correction in range(MAX_CORRECTIONS + 1):
            label = f" (correction {correction})" if correction else ""
            effort = REASONING_EFFORT_CORRECTION if correction else REASONING_EFFORT_WRITE
            started = time.monotonic()
            content = log_response(label, _post(iov_request(messages, schema, effort), WRITE_DEADLINE))
            log.info("[%s] Writing%s took %.0f s", cve_id, label, time.monotonic() - started)

            try:
                iov_json = _extract_json(content)
            except ValueError as exc:
                problem = f"{exc}."
            else:
                problem = iov_problem(cve_id, iov_json)
            if problem is None:
                return json.dumps(json.loads(iov_json), indent=2)

            log.warning("[%s] Rejected IoV%s: %s", cve_id, label, problem)
            section(f"REJECTED{label}", problem)
            if correction == MAX_CORRECTIONS:
                break

            messages += [
                {"role": "assistant", "content": content},
                {"role": "user", "content": CORRECTION_PROMPT.format(cve_id=cve_id, problem=problem)},
            ]

    raise IovRejected(
        f"No valid IoV for {cve_id} after {MAX_CORRECTIONS} correction rounds; last problem: {problem}"
    )


def _extract_json(text: str) -> str:
    """Return the JSON object in the response.

    Structured outputs mean the content is normally bare JSON, but a provider
    that ignores response_format can still wrap it in prose or a fence.
    """
    text = text.strip()
    if text.startswith("{"):
        return text

    fence = list(re.finditer(r"```(?:json)?\s*(\{.*?})\s*```", text, re.DOTALL))
    if fence:
        return fence[-1].group(1)

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("No JSON object found in model output")
    return text[start:end + 1]

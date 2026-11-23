"""evaluate-iov — evaluate an Indicator of Vulnerability against this host.

Reads an IoV JSON document (format version 2) from a file and prints the
resulting confidence score and its reason to stdout, or with --json the
evaluation results document of the IoV specification. Logs go to stderr, so
stdout carries only the result.

    evaluate-iov CVE-2024-6387.iov.json
    evaluate-iov --json --log-level DEBUG CVE-2024-6387.iov.json

For the long-running variant that syncs the IoV corpus and publishes verdicts
through the Wazuh agent socket, see daemon.py.
"""

import argparse
import json
import sys

from .evaluation import evaluate, results_document
from .logging_setup import configure_logging


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the command line of evaluate-iov."""
    parser = argparse.ArgumentParser(
        prog="evaluate-iov",
        description="Evaluate an Indicator of Vulnerability (IoV) against this host.",
        epilog="Scores: 0 ABSENT, 1 LOW, 2 MEDIUM/DEFAULT, 3 HIGH, -1 INCONCLUSIVE "
               "(the IoV makes no statement, which is not evidence of safety).",
    )
    parser.add_argument("iov", metavar="IOV_FILE", help="path to the IoV JSON document")
    parser.add_argument(
        "--json", action="store_true", dest="as_json",
        help="print the evaluation results document instead of a human-readable summary",
    )
    parser.add_argument(
        "--log-level", default=None, metavar="LEVEL",
        help="logging verbosity on stderr: DEBUG, INFO, WARNING (default), ERROR",
    )
    return parser.parse_args(argv)


def load_iov(path: str) -> dict:
    """Read an IoV document from a file, exiting with a message if it is unusable."""
    try:
        with open(path, encoding="utf-8") as handle:
            iov = json.load(handle)
    except OSError as exc:
        sys.exit(f"evaluate-iov: cannot read {path}: {exc.strerror}")
    except json.JSONDecodeError as exc:
        sys.exit(f"evaluate-iov: {path} is not valid JSON: {exc}")
    if not isinstance(iov, dict):
        sys.exit(f"evaluate-iov: {path} does not contain an IoV object")
    return iov


def format_summary(cve: str, result) -> str:
    """The human-readable result: level, reason, and one row per package result."""
    lines = [f"{cve}: {result.level} ({result.iov_score})", f"  {result.reason}"]
    rows = [
        (f"{p.name} {p.version} ({p.arch})" if p.name else p.key, p.release or "-", p.state)
        for p in result.packages
    ]
    widths = [max((len(row[i]) for row in rows), default=0) for i in range(2)]
    for label, release, state in rows:
        lines.append(f"  {label:<{widths[0]}}  {release:<{widths[1]}}  {state}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Evaluate one IoV file and print the result; returns the exit code."""
    args = parse_args(argv)
    configure_logging(args.log_level, default="WARNING")

    iov = load_iov(args.iov)
    result = evaluate(iov)

    if args.as_json:
        print(json.dumps(results_document(iov, result), indent=2))
    else:
        print(format_summary(iov.get("cve", "unknown"), result))
    return 0


def run() -> None:
    """Console entrypoint."""
    sys.exit(main())

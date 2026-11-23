#!/usr/bin/env python3
"""
CLI for the vulnerability processing service.

Commands:
  process [agent_id] [--no-wait]
                       Trigger /process/<agent_id> on the running server, then
                       stream the task logs until the task finishes.
                       Omit agent_id to pick interactively from Wazuh agents.
                       Pass --no-wait to return immediately after queuing.
                       Not needed day to day: the server polls for new
                       verdicts every POLL_INTERVAL seconds on its own.
  iov-index            Create the iov-results index and its Dashboards pattern.
  iov-sync [--agent ID] [--lookback SECONDS] [--dry-run]
                       Project IoV verdicts, with EPSS and CVSS, into
                       iov-results directly, without the server.
  cves [agent_id]      Print all CVE IDs for an agent, one per line.
                       Omit agent_id to pick interactively from Wazuh agents.
  queue-iovs [agent_id] [--min-cvss SCORE] [--admin-token TOKEN] [--dry-run]
                       Queue IoV generation on the IoV server for an agent's
                       CVEs that don't have one yet. Only considers CVEs with
                       a CVSS base score greater than --min-cvss (default: 8).

Options for all commands:
  --host HOST          Server host (default: localhost, or SERVER_HOST env var)
  --port PORT          Server port (default: 8000, or SERVER_PORT env var)

Examples:
  python cli.py process 001
  python cli.py process 001 --no-wait
  python cli.py process
  python cli.py iov-sync --dry-run
  python cli.py cves 001
  python cli.py queue-iovs 001 --min-cvss 7
  python cli.py --host etso.example --port 9000 process
"""
import argparse
import json
import os
import sys

import requests

from config import ADMIN_TOKEN, IOV_PROJECTION_LOOKBACK
from external.iov_server import IoVNotAvailable, check_or_queue_iov
from external.wazuh import Wazuh
from pipeline import process_iov_results


def _server_base(host: str, port: int) -> str:
    return f"http://{host}:{port}"


def cmd_process(args: argparse.Namespace) -> None:
    agent_id = args.agent_id

    if not agent_id:
        agent_id = _select_agent_interactively()

    url = f"{_server_base(args.host, args.port)}/process/{agent_id}"
    print(f"POST {url}")
    try:
        resp = requests.post(url, timeout=10)
    except requests.ConnectionError:
        print(f"error: could not connect to server at {args.host}:{args.port}", file=sys.stderr)
        sys.exit(1)

    if resp.status_code == 409:
        print(f"conflict: a task for agent {agent_id} is already running")
        sys.exit(2)

    if not resp.ok:
        print(f"error: server returned {resp.status_code}: {resp.text}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    task_id = data.get("task_id")
    print(f"queued — agent_id={data.get('agent_id')}  task_id={task_id}")

    if args.no_wait or not task_id:
        return

    _follow_task(args.host, args.port, task_id)


def _follow_task(host: str, port: int, task_id: str) -> None:
    """Stream log lines from /logs/<task_id> until the task finishes."""
    url = f"{_server_base(host, port)}/logs/{task_id}"
    print(f"\n--- task logs ({task_id}) ---")
    try:
        with requests.get(url, stream=True, timeout=(5, None)) as resp:
            resp.raise_for_status()
            awaiting_status = False
            for raw in resp.iter_lines(decode_unicode=True):
                if raw == "event: done":
                    awaiting_status = True
                elif raw.startswith("data: "):
                    content = raw[6:]
                    if awaiting_status:
                        status_label = {"SUCCESS": "done", "FAILURE": "failed", "REVOKED": "revoked"}.get(content, content.lower())
                        print(f"\n--- {status_label} ---")
                        return
                    print(content)
    except KeyboardInterrupt:
        print("\n(interrupted)")
    except requests.ConnectionError as exc:
        print(f"error: connection lost while streaming logs: {exc}", file=sys.stderr)
        sys.exit(1)


def _select_agent_interactively() -> str:
    """List active Wazuh agents and prompt the user to pick one."""
    print("Fetching agent list from Wazuh…")
    try:
        agents = Wazuh().list_agents()
    except (requests.RequestException, OSError, RuntimeError) as exc:
        print(f"error: could not list agents: {exc}", file=sys.stderr)
        sys.exit(1)

    if not agents:
        print("No active agents found.", file=sys.stderr)
        sys.exit(1)

    print()
    print(f"  {'#':>3}  {'ID':<6}  {'Name':<30}  {'OS'}")
    print(f"  {'-'*3}  {'-'*6}  {'-'*30}  {'-'*20}")
    for i, agent in enumerate(agents, start=1):
        os_info = agent.get("os", {})
        os_name = os_info.get("name", "") if isinstance(os_info, dict) else ""
        os_version = os_info.get("version", "") if isinstance(os_info, dict) else ""
        os_str = f"{os_name} {os_version}".strip()
        print(f"  {i:>3}  {agent['id']:<6}  {agent['name']:<30}  {os_str}")
    print()

    while True:
        try:
            raw = input(f"Select agent [1-{len(agents)}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(agents):
                return agents[idx]["id"]

        print(f"  Please enter a number between 1 and {len(agents)}.")


def cmd_iov_index(args: argparse.Namespace) -> None:
    Wazuh().ensure_iov_index()
    print(f"Done — the {Wazuh.IOV_INDEX_NAME} index is ready.")


def cmd_iov_sync(args: argparse.Namespace) -> None:
    summary = process_iov_results(
        agent_id=args.agent, lookback_seconds=args.lookback, dry_run=args.dry_run
    )
    documents = summary.pop("documents", None)
    if documents is not None:
        for doc_id, doc in sorted(documents.items()):
            print(f"{doc_id}: {json.dumps(doc)}")
    print(
        f"Scanned {summary['scanned']} alert(s); "
        f"{'would index' if args.dry_run else 'indexed'} {summary['indexed']} verdict(s) "
        f"across {summary['agents']} agent(s)."
    )


def cmd_cves(args: argparse.Namespace) -> None:
    agent_id = args.agent_id or _select_agent_interactively()
    for cve_id in Wazuh().detected_cves(agent_id):
        print(cve_id)


def cmd_queue_iovs(args: argparse.Namespace) -> None:
    # A dry run asks without the token, so the IoV server only reports.
    admin_token = None if args.dry_run else (args.admin_token or ADMIN_TOKEN)
    if not args.dry_run and not admin_token:
        print("error: an admin token is required (--admin-token or ADMIN_TOKEN env var)", file=sys.stderr)
        sys.exit(1)

    agent_id = args.agent_id or _select_agent_interactively()

    cve_ids = [
        cve_id for cve_id, base in Wazuh().detected_cves(agent_id).items()
        if base is not None and base > args.min_cvss
    ]

    counts = dict.fromkeys(("queued", "have", "in_progress", "failed", "missing"), 0)
    for cve_id in cve_ids:
        try:
            counts[check_or_queue_iov(cve_id, admin_token)] += 1
        except (requests.RequestException, IoVNotAvailable) as exc:
            print(f"error: could not check/queue IoV for {cve_id}: {exc}", file=sys.stderr)

    print(f"CVEs considered (CVSS > {args.min_cvss}): {len(cve_ids)}")
    if args.dry_run:
        print(f"IoVs that would be queued: {counts['missing']}")
    else:
        print(f"IoVs queued:        {counts['queued']}")
    print(f"IoVs already had:   {counts['have']}")
    if counts["in_progress"]:
        print(f"IoVs in progress:   {counts['in_progress']}")
    if counts["failed"]:
        print(f"IoVs failed:        {counts['failed']}")


def build_parser() -> argparse.ArgumentParser:
    default_host = os.getenv("SERVER_HOST", "localhost")
    default_port = int(os.getenv("SERVER_PORT", "8000"))

    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="CLI for the vulnerability processing service.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", default=default_host, help=f"server host (default: {default_host})")
    parser.add_argument("--port", default=default_port, type=int, help=f"server port (default: {default_port})")

    sub = parser.add_subparsers(dest="command", required=True)

    # process
    p_process = sub.add_parser("process", help="trigger processing for an agent")
    p_process.add_argument(
        "agent_id",
        nargs="?",
        default=None,
        help="Wazuh agent ID; omit to select interactively",
    )
    p_process.add_argument(
        "--no-wait",
        action="store_true",
        dest="no_wait",
        help="return immediately after queuing (do not stream logs)",
    )
    p_process.set_defaults(func=cmd_process)

    # iov-index
    p_iov_index = sub.add_parser(
        "iov-index",
        help="create the iov-results index that IoV verdicts are written into",
    )
    p_iov_index.set_defaults(func=cmd_iov_index)

    # iov-sync
    p_iov_sync = sub.add_parser(
        "iov-sync",
        help="project IoV verdicts, with EPSS and CVSS, from the alerts index into iov-results",
    )
    p_iov_sync.add_argument(
        "--agent",
        default=None,
        metavar="ID",
        help="only this Wazuh agent (default: all agents)",
    )
    p_iov_sync.add_argument(
        "--lookback",
        type=int,
        default=IOV_PROJECTION_LOOKBACK,
        metavar="SECONDS",
        help=f"how far back to read alerts (default {IOV_PROJECTION_LOOKBACK})",
    )
    p_iov_sync.add_argument(
        "--dry-run",
        action="store_true",
        help="print the documents that would be written instead of writing them",
    )
    p_iov_sync.set_defaults(func=cmd_iov_sync)

    # cves
    p_cves = sub.add_parser("cves", help="print all CVE IDs for an agent, newline-separated")
    p_cves.add_argument(
        "agent_id",
        nargs="?",
        default=None,
        help="Wazuh agent ID; omit to select interactively",
    )
    p_cves.set_defaults(func=cmd_cves)

    # queue-iovs
    p_queue_iovs = sub.add_parser("queue-iovs", help="queue IoV generation for an agent's CVEs that don't have one yet")
    p_queue_iovs.add_argument(
        "agent_id",
        nargs="?",
        default=None,
        help="Wazuh agent ID; omit to select interactively",
    )
    p_queue_iovs.add_argument(
        "--min-cvss",
        type=float,
        default=8.0,
        help="only consider CVEs with a CVSS base score greater than this (default: 8)",
    )
    p_queue_iovs.add_argument(
        "--admin-token",
        default=None,
        help="admin token for the IoV server (default: ADMIN_TOKEN env var)",
    )
    p_queue_iovs.add_argument(
        "--dry-run",
        action="store_true",
        help="only report which CVEs have an IoV; queue nothing (needs no token)",
    )
    p_queue_iovs.set_defaults(func=cmd_queue_iovs)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

"""
CLI for administering an iov_server instance.

Usage:
    python cli.py [--env-file PATH] <command> [OPTIONS]

Commands:
    bulk-upsert PATH [PATH ...]   Recursively upload all *.iov.json files under
                                   the given paths to the admin "/api/bulk" route.
    bulk-download DIR              Download every successfully generated IoV
                                   from the admin "/api/bulk" route as
                                   "{cve}.iov.json" files into DIR.
    list                           List all completed CVE IDs ("/api/cves", paged).
    get CVE_ID                     Fetch a single IoV; as admin, queues generation
                                   if it doesn't exist yet ("/api/{cve_id}").
    delete CVE_ID                  Delete a single IoV and its log (admin only).
    health                         Check server health ("/health").

Shared options:
    --env-file PATH      .env-style file to read defaults from
                         (default: ".env" next to this script; silently
                         skipped if missing). Real environment variables
                         always take precedence over the file.
    --server-url URL     Base URL of the iov_server instance
                         (default: $IOV_SERVER_URL or http://localhost:8000)
    --token TOKEN        Admin token, required for admin-only commands
                         (default: $ADMIN_TOKEN)
    -v, --verbose        Debug logging

bulk-upsert also accepts --batch-size N (default: 50).
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

DEFAULT_ENV_FILE = Path(__file__).resolve().parent / ".env"


def _parse_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            env[key] = value
    return env


def _load_env_file(path: Path) -> None:
    """Populate os.environ from a .env-style file without overriding variables
    that are already set in the real environment."""
    if not path.is_file():
        return
    for key, value in _parse_env_file(path).items():
        os.environ.setdefault(key, value)


def _collect_iov_files(paths: list[str]) -> list[Path]:
    """Resolve the given paths to a deduplicated, sorted list of *.iov.json files.
    Files are taken as-is (regardless of name); directories are searched recursively."""
    files: set[Path] = set()
    for raw in paths:
        p = Path(raw).expanduser()
        if p.is_dir():
            files.update(p.rglob("*.iov.json"))
        elif p.is_file():
            files.add(p)
        else:
            logger.warning("Path does not exist, skipping: %s", p)
    return sorted(files)


def _load_documents(files: list[Path]) -> list[dict]:
    docs = []
    for f in files:
        try:
            docs.append(json.loads(f.read_text()))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to read %s: %s", f, e)
    return docs


def _batched(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _require_token(token: str) -> bool:
    if not token:
        logger.error("An admin token is required (--token or $ADMIN_TOKEN).")
        return False
    return True


def bulk_upsert(paths: list[str], server_url: str, token: str, batch_size: int) -> int:
    if not _require_token(token):
        return 1

    files = _collect_iov_files(paths)
    logger.info("Found %d .iov.json file(s).", len(files))
    if not files:
        return 0

    docs = _load_documents(files)
    if not docs:
        logger.error("No valid documents to upload.")
        return 1

    headers = {"Authorization": f"Bearer {token}"}
    upserted_total = 0
    error_total = 0

    for batch in _batched(docs, batch_size):
        resp = requests.put(f"{server_url.rstrip('/')}/api/bulk", json=batch, headers=headers, timeout=60)
        resp.raise_for_status()
        result = resp.json()
        upserted_total += len(result.get("upserted", []))
        for cve, reason in result.get("errors", {}).items():
            logger.warning("%s: %s", cve, reason)
            error_total += 1

    logger.info("Upserted %d document(s), %d error(s).", upserted_total, error_total)
    return 1 if error_total else 0


def bulk_download(directory: str, server_url: str, token: str) -> int:
    if not _require_token(token):
        return 1

    out_dir = Path(directory).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)

    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{server_url.rstrip('/')}/api/bulk", headers=headers, timeout=60)
    resp.raise_for_status()
    items = resp.json().get("items", [])

    written = 0
    for item in items:
        cve_id = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve_id, str):
            logger.warning("Skipping item without a 'cve' field: %r", item)
            continue
        (out_dir / f"{cve_id}.iov.json").write_text(json.dumps(item, indent=2))
        written += 1

    logger.info("Downloaded %d document(s) to %s.", written, out_dir)
    return 0


def list_cves(server_url: str) -> int:
    listed = 0
    offset = 0
    while True:
        resp = requests.get(
            f"{server_url.rstrip('/')}/api/cves",
            params={"offset": offset, "limit": 1000},
            timeout=30,
        )
        resp.raise_for_status()
        body = resp.json()
        cves = body.get("cves", [])
        for cve in cves:
            print(cve)
        listed += len(cves)
        offset += len(cves)
        if not cves or listed >= body.get("total", listed):
            break
    logger.info("%d CVE(s) listed.", listed)
    return 0


def get_iov(cve_id: str, server_url: str, token: str) -> int:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    resp = requests.get(f"{server_url.rstrip('/')}/api/{cve_id}", headers=headers, timeout=30)
    try:
        print(json.dumps(resp.json(), indent=2))
    except ValueError:
        print(resp.text)
    if resp.status_code >= 400:
        logger.error("Request failed with status %d.", resp.status_code)
        return 1
    return 0


def delete_iov(cve_id: str, server_url: str, token: str) -> int:
    if not _require_token(token):
        return 1

    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.delete(f"{server_url.rstrip('/')}/api/{cve_id}", headers=headers, timeout=30)
    try:
        print(json.dumps(resp.json(), indent=2))
    except ValueError:
        print(resp.text)
    if resp.status_code >= 400:
        logger.error("Request failed with status %d.", resp.status_code)
        return 1
    return 0


def health(server_url: str) -> int:
    resp = requests.get(f"{server_url.rstrip('/')}/health", timeout=10)
    print(json.dumps(resp.json(), indent=2))
    return 0 if resp.ok else 1


def _add_common_arguments(subparser: argparse.ArgumentParser, *, needs_token: bool = True) -> None:
    subparser.add_argument(
        "--server-url", default=os.getenv("IOV_SERVER_URL", "http://localhost:8000"), metavar="URL",
        help="Base URL of the iov_server instance (default: $IOV_SERVER_URL or http://localhost:8000)",
    )
    if needs_token:
        subparser.add_argument(
            "--token", default=os.getenv("ADMIN_TOKEN", ""), metavar="TOKEN",
            help="Admin token (default: $ADMIN_TOKEN)",
        )
    subparser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Administer an iov_server instance.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--env-file", default=str(DEFAULT_ENV_FILE), metavar="PATH",
        help=f".env-style file to read defaults from (default: {DEFAULT_ENV_FILE})",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    bulk_parser = subparsers.add_parser(
        "bulk-upsert",
        help="Recursively upload all *.iov.json files under the given paths.",
    )
    bulk_parser.add_argument(
        "paths", nargs="+", metavar="PATH",
        help="Files or directories to upload (directories are searched recursively).",
    )
    bulk_parser.add_argument(
        "--batch-size", type=int, default=50, metavar="N",
        help="Number of documents per request (default: 50)",
    )
    _add_common_arguments(bulk_parser)

    download_parser = subparsers.add_parser(
        "bulk-download",
        help="Download all successfully generated IoVs to a local directory.",
    )
    download_parser.add_argument(
        "directory", metavar="DIR",
        help="Local directory to write {cve}.iov.json files into (created if missing).",
    )
    _add_common_arguments(download_parser)

    list_parser = subparsers.add_parser(
        "list",
        help="List all completed CVE IDs.",
    )
    _add_common_arguments(list_parser, needs_token=False)

    get_parser = subparsers.add_parser(
        "get",
        help="Fetch a single IoV; as admin, queues generation if missing.",
    )
    get_parser.add_argument("cve_id", metavar="CVE_ID")
    _add_common_arguments(get_parser)

    delete_parser = subparsers.add_parser(
        "delete",
        help="Delete a single IoV and its log file (admin only).",
    )
    delete_parser.add_argument("cve_id", metavar="CVE_ID")
    _add_common_arguments(delete_parser)

    health_parser = subparsers.add_parser(
        "health",
        help="Check server health.",
    )
    _add_common_arguments(health_parser, needs_token=False)

    return parser


def main() -> None:
    # First pass: find --env-file (if any) before other defaults (which read
    # from os.environ) are computed, without erroring on the rest of argv.
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--env-file", default=str(DEFAULT_ENV_FILE))
    pre_args, _ = pre_parser.parse_known_args()
    _load_env_file(Path(pre_args.env_file).expanduser())

    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if args.command == "bulk-upsert":
        sys.exit(bulk_upsert(args.paths, args.server_url, args.token, args.batch_size))
    elif args.command == "bulk-download":
        sys.exit(bulk_download(args.directory, args.server_url, args.token))
    elif args.command == "list":
        sys.exit(list_cves(args.server_url))
    elif args.command == "get":
        sys.exit(get_iov(args.cve_id, args.server_url, args.token))
    elif args.command == "delete":
        sys.exit(delete_iov(args.cve_id, args.server_url, args.token))
    elif args.command == "health":
        sys.exit(health(args.server_url))


if __name__ == "__main__":
    main()

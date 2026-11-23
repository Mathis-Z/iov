# IoV evaluation

`evaluate_iov/` evaluates an Indicator of Vulnerability (IoV, format version 2, as specified in
[`iov_server/prompt/prompt6.txt`](../iov_server/prompt/prompt6.txt)) against the host it runs on.
It reports a confidence level that the CVE applies to this host, together with a human-readable
reason:

| Score | Level | Meaning |
|---|---|---|
| `0` | ABSENT | Not affected: patched, not installed, or the vulnerable code is not present. |
| `1` | LOW | Affected version present, exploitation preconditions absent or mitigated. |
| `2` | MEDIUM | Affected version present, no evidence either way (`DEFAULT`). |
| `3` | HIGH | Affected, and the exploitation preconditions are affirmatively present. |
| `-1` | INCONCLUSIVE | The IoV makes no statement about this host. **Not** evidence of safety. |

The same codebase builds two binaries: the standalone `evaluate-iov` CLI and the
`wazuh-evaluate-iov-daemon` for Wazuh agents. The IoV server imports the package too (see
`iov_server/app/validation.py`), so an IoV the server accepts is one the agents can evaluate.

## How an IoV is evaluated

1. **Validation** (`validation.py`). The document must have `"schema_version": 2` and conform to
   `evaluate_iov/iov.schema.json`, a copy of the schema in `prompt6.txt`
   (`tests/test_validation.py` fails if the two drift apart, so edit both together). Scripts that
   call functions which are neither built-ins nor part of CEL are rejected. Any of these makes the
   result INCONCLUSIVE. Format version 1 documents are not evaluated.
2. **Release** (`releases.py`). The host's release is `ID:VERSION_ID` from `/etc/os-release`. If no
   range set lists it, the result is INCONCLUSIVE.
3. **Packages** (`packages.py`, `host/pkgdb.py`, `host/origin.py`, `versions.py`). Every installed
   binary package whose name equals a `packages` key, or matches an anchored regex key (`^...$`),
   is classified against the most specific matching range set:
   - versions are compared with the ordering of the release's package manager (dpkg, rpm, apk or
     pacman, reimplemented in `versions.py`, so no host tool is needed);
   - `arches` restricts a range set to architectures;
   - `"origin": "distribution"` only applies to verified distribution builds: by signing key on
     rpm hosts, by comparison with the configured APT/apk/pacman repositories otherwise;
   - kernel image packages count only if they own `/boot/vmlinuz-$(uname -r)` or
     `/lib/modules/$(uname -r)/`. If kernel images are installed under a key but none belongs to
     the running kernel, the key is UNKNOWN.

   Each package is AFFECTED, UNAFFECTED or UNKNOWN. AFFECTED takes precedence over UNKNOWN
   (INCONCLUSIVE), which takes precedence over UNAFFECTED (ABSENT). If no listed package is
   installed, the result is ABSENT.
4. **Script** (`script/`). If an affected package was found, or the IoV has no `packages`, the
   script decides the level. A script that returns `null` or fails falls back to DEFAULT if an
   affected package was found and to INCONCLUSIVE otherwise, never to ABSENT. An IoV without a
   script reports DEFAULT for an affected package.

### Script language

A script is a thin statement layer over [CEL](https://github.com/google/cel-spec), one statement
per line: `let NAME := EXPR`, `return EXPR`, and `if EXPR` / `elif EXPR` / `else` / `end` blocks.
Lines starting with `//` are comments. There are no loops or user-defined functions; iteration uses
CEL's macros (`exists`, `all`, `filter`, `map`). A script returns `ABSENT`, `LOW`, `MEDIUM`
(`DEFAULT`), `HIGH` or `null`. The parser and executor are in `script/interpreter.py`; expressions
are evaluated by `cel-python`, with two small patches in `script/environment.py` (CEL's
heterogeneous equality with `null`, and compact error messages for `||`/`&&`).

Scripts see three constants, `uname`, `os_release` and `kernel_cmdline`, and 39 read-only built-ins
(registered in `script/environment.py`, implemented in `host/`):

| Category | Built-ins |
|---|---|
| Kernel | `kernel_config`, `kernel_modules`, `kernel_feature`, `sysctl`, `userns_unprivileged_allowed` |
| Hardware | `cpu`, `pci_devices`, `mounts` |
| Processes, network | `get_processes`, `process_environ`, `listening_sockets`, `service_exposed`, `interfaces`, `routes` |
| systemd | `systemd_unit`, `systemd_units`, `systemd_unit_property` |
| Security, accounts | `selinux`, `apparmor`, `users`, `groups`, `shadow` (never password hashes) |
| Files | `file_info`, `list_dir`, `find_files`, `glob`, `file_hash`, `read_file`, `file_matches`, `find_all` |
| Configuration | `directive_values`, `ini_values`, `xml_query`, `json_query`, `yaml_query` |
| Packages | `installed_packages`, `package_owner`, `package_verify`, `version_compare` |

Every built-in returns `null` when its data source is unavailable (no systemd, an unreadable file,
no kernel configuration). List-returning built-ins return `[]` when the source is available but
nothing matches, so `[]` is evidence of absence and `null` is not. The full signatures and return
shapes are in the specification.

**Sandbox limits.** Any parse error, CEL error, invalid return value or exceeded limit makes the
script produce no output:

| Limit | Value | Where |
|---|---|---|
| Wall-clock time per script | 30 s (the specification requires at least 10 s) | `script/interpreter.py` `TIME_LIMIT` |
| Executed statements | 10,000 | `script/interpreter.py` `MAX_STATEMENTS` |
| Entries per returned list | 10,000 | `host/base.py` `MAX_ENTRIES` |
| Bytes read per file | 1 MiB | `host/base.py` `MAX_FILE_BYTES` |

Built-ins never write, load modules or use the network. Host commands (`rpm`, `dpkg-query`,
`systemctl`, `ip`, ...) are fixed programs with a 15 s timeout each.

## Layout

| Path | What |
|---|---|
| `evaluate_iov/evaluation.py` | Top-level evaluation and the results document. |
| `evaluate_iov/validation.py`, `iov.schema.json` | Schema validation. |
| `evaluate_iov/releases.py`, `packages.py`, `versions.py` | Release matching, package classification, version comparison. |
| `evaluate_iov/script/` | Script parser, executor and CEL environment. |
| `evaluate_iov/host/` | Read-only host data sources behind the built-ins. |
| `evaluate_iov/cli.py` | The `evaluate-iov` CLI. |
| `evaluate_iov/daemon.py`, `iov_source.py`, `wazuh_queue.py` | The Wazuh daemon: corpus mirror and event publishing. |
| `evaluate_iov/tests/` | Unit tests. |
| `entrypoint_*.py` | PyInstaller entrypoints, one per binary. |
| `package.sh` | Builds both binaries. |
| `dist/evaluate-iov` | The standalone CLI, built. |

## Running from source

Python 3.11 or newer:

```bash
cd iov-evaluation
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m evaluate_iov ../iov_server/iov_data/CVE-2024-6345.iov.json
```

## `evaluate-iov` (CLI)

```
evaluate-iov [--json] [--log-level LEVEL] IOV_FILE
```

It prints the level, the reason and one row per classified package to stdout. With `--json` it
prints the evaluation results document of the specification instead (IoV UUID, host release,
package results, script outcome, `iov_score`, `reason`). Logs go to stderr; the level comes from
`--log-level` or `EVALUATE_IOV_LOG_LEVEL` (default `WARNING`). Scripts read host files, so run it
as root to see what the daemon sees.

```bash
sudo iov-evaluation/dist/evaluate-iov iov_server/iov_data/CVE-2024-6345.iov.json
sudo iov-evaluation/dist/evaluate-iov --json --log-level DEBUG iov_server/iov_data/CVE-2024-6345.iov.json
```

## `wazuh-evaluate-iov-daemon`

The daemon mirrors the IoV corpus from the IoV server into a local cache, using the per-IoV content
digests from `GET /api/cves?digests=1`, and downloads changed IoVs from `GET /api/<CVE>`. It
evaluates every cached IoV at startup (a reboot can change the running kernel) and then daily, one
at a time, and publishes each verdict through the local Wazuh agent's queue socket, so it needs no
credentials of its own. An unreachable server is logged and the cached corpus is evaluated anyway.
SIGTERM finishes the IoV in flight and exits.

Configuration comes from the environment, with command-line flags taking precedence:

| Variable | Flag | Default |
|---|---|---|
| `IOV_SERVER_URL` | `--server-url` | required |
| `IOV_CACHE_DIR` | `--cache-dir` | `/var/lib/wazuh-evaluate-iov` |
| `IOV_SYNC_INTERVAL` | `--sync-interval` | `3600` s (environment values are floored at 60) |
| `IOV_EVAL_INTERVAL` | `--eval-interval` | `86400` s (environment values are floored at 60) |
| `WAZUH_QUEUE_SOCKET` | `--socket` | `/var/ossec/queue/sockets/queue`, or the pre-4.x path if only that exists |
| `IOV_EVENT_LOCATION` | `--location` | `evaluate-iov` |
| `EVALUATE_IOV_LOG_LEVEL` | `--log-level` | `INFO` |

`--once` runs one sync and one evaluation pass and exits. The binary is written to
[`wazuh-integration/installation/endpoints/`](../wazuh-integration/installation/endpoints), next
to its installer, systemd unit and example environment file; installing it is described there.

### Events

Each verdict is one JSON event, `{"iov": {...}}`, with the CVE, IoV UUID, score and level, reason,
script outcome, host release, and up to 50 package results with the affected ones first. It also
carries the evaluated IoV in `document`, as compact JSON that is zlib-compressed and
base64-encoded (`"document_encoding": "zlib+base64"`). Nested JSON would make analysisd create one
alert field per key, and the alerts template indexes strings as keywords, which the indexer rejects
above 32 KB. If attaching the IoV would push the event over the 60 KB queue limit, the verdict is
sent without it and with `"document_omitted": true`.

## Tests and linting

```bash
cd iov-evaluation
.venv/bin/pip install pytest ruff
.venv/bin/python -m pytest evaluate_iov/tests
.venv/bin/ruff check --isolated --line-length 100 --select E,F,W,B,UP,SIM,I --exclude evaluate_iov/tests .
```

The tests run against fixtures and monkeypatched host sources, so they pass on any Linux host
without root.

## Packaging

`package.sh` builds both binaries as fully static x86_64 executables. It creates a temporary
virtualenv, runs PyInstaller, which bundles the interpreter, the dependencies and the schema, and
then staticx, which bundles glibc and the dynamic loader, so the binaries run on any x86_64 Linux
regardless of its libraries:

```bash
cd iov-evaluation
./package.sh                          # with python3 from PATH
PYTHON=/usr/bin/python3 ./package.sh  # or a specific interpreter (needs bz2, lzma, ssl, ...)
```

It writes `dist/evaluate-iov` and
`../wazuh-integration/installation/endpoints/wazuh-evaluate-iov-daemon`. Binaries run host tools
(`rpm`, `dpkg-query`, ...) with the host's own `LD_LIBRARY_PATH`, not the bundled one.

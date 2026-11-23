# Endpoints: `wazuh-evaluate-iov-daemon`

Installs the IoV evaluation daemon on a Wazuh agent host. The daemon pulls IoVs from the IoV server
and evaluates them on the host. It publishes each verdict through the local Wazuh agent, and the
manager's rules (see [`../manager`](../manager)) pick the verdicts up.

This directory is everything an endpoint needs:

| File | Installed to |
|---|---|
| `wazuh-evaluate-iov-daemon` | `/usr/local/bin/wazuh-evaluate-iov-daemon` |
| `wazuh-evaluate-iov-daemon.service` | `/etc/systemd/system/` |
| `daemon.env.example` | `/etc/wazuh-evaluate-iov/daemon.env` (mode 600), only if absent |
| `install.sh` | Does the above and starts the service. |

The binary is built by [`iov-evaluation/package.sh`](../../../iov-evaluation), which writes it
here. It is fully static, so one build runs on any x86_64 Linux.

## Install

Copy this directory to the endpoint (or use a checkout), then:

```bash
sudo ./install.sh
```

The script:

1. Installs the files as listed above.
2. Enables and restarts the service. `restart` rather than `start`, so an upgrade picks up the new
   binary.
3. Checks that the service stayed up.
4. Prints where the config file is.

Re-running it upgrades the binary and unit but keeps an existing `daemon.env`. The example config
points `IOV_SERVER_URL` at the placeholder `http://iov-server.example:8000`; set it to your IoV
server and restart:

```bash
$EDITOR /etc/wazuh-evaluate-iov/daemon.env
systemctl restart wazuh-evaluate-iov-daemon
```

The unit runs as root: it reads `/proc` and `/boot/config-*`, runs `lsmod`, `dpkg-query` and `rpm`,
and writes to the ossec queue socket. `ProtectSystem=strict` is deliberately *not* set; it would cut
off `/var/ossec`.

## Configure

Environment variables, with flags overriding them. Precedence is **flag → env var → default**.

| Variable | Flag | Default | Notes |
|---|---|---|---|
| `IOV_SERVER_URL` | `--server-url` | — | **Required.** Missing → exits 1. |
| `IOV_CACHE_DIR` | `--cache-dir` | `/var/lib/wazuh-evaluate-iov` | The mirrored IoV corpus. |
| `IOV_SYNC_INTERVAL` | `--sync-interval` | `3600` | Seconds; floored at 60. |
| `IOV_EVAL_INTERVAL` | `--eval-interval` | `86400` | Seconds; floored at 60. |
| `WAZUH_QUEUE_SOCKET` | `--socket` | probed | `/var/ossec/queue/sockets/queue`, else the pre-4.x path. |
| `IOV_EVENT_LOCATION` | `--location` | `evaluate-iov` | Nothing in the manager's rules depends on it. |
| `EVALUATE_IOV_LOG_LEVEL` | `--log-level` | `INFO` | Goes to the journal. |

A non-numeric interval is logged as a warning and falls back to the default rather than crashing
the service.

If you move `IOV_CACHE_DIR` off `/var/lib`, add a matching `ReadWritePaths=` to the unit.
`ProtectHome=yes` and `PrivateTmp=yes` are on, so a cache under `/home` or `/tmp` will not work as
shipped.

Prefer not to use the env file? `systemctl edit wazuh-evaluate-iov-daemon`:

```ini
[Service]
Environment=IOV_SERVER_URL=http://iov-server.example:8000
Environment=IOV_EVAL_INTERVAL=21600
```

## What it does at runtime

It syncs the corpus and evaluates **once on startup**, so a reboot is itself a re-evaluation. That
matters, because a reboot can change the running kernel, the loaded modules and the installed
packages. After that it loops on the two intervals independently.

An unreachable IoV server is a warning, never a stop: evaluation always runs against the local
cache, so a host is still evaluated at boot when the server is down. Evaluation is serial, one IoV
at a time. On `SIGTERM` it finishes the IoV in flight and exits 0.

## Verify

```bash
wazuh-evaluate-iov-daemon --once --log-level INFO
```

Expect `sync: N downloaded …` then `evaluation pass: N evaluated, N published`. `--once` runs a
single sync and evaluation pass and exits, which is the quickest check of a deployment. Then:

```bash
systemctl status wazuh-evaluate-iov-daemon
journalctl -u wazuh-evaluate-iov-daemon -n 50
```

## Troubleshooting

**`status=203/EXEC` from systemd.** `execve()` failed; the daemon never ran, so no configuration is
involved. Run the binary by hand: the shell prints the real reason where systemd only gives the
errno. Usually the file is missing, not executable, or built for the wrong architecture.

**No systemd on the host.** `which systemd` finding nothing proves nothing: `systemd` is PID 1 at
`/usr/lib/systemd/systemd`, not a command on `$PATH`. Check with `ps -p 1 -o comm=`, which is what
`install.sh` checks.

**Daemon evaluates but publishes 0.** The queue socket path is wrong or unwritable. Check
`ls -l /var/ossec/queue/sockets/queue` and set `WAZUH_QUEUE_SOCKET` if your agent uses the pre-4.x
`/var/ossec/queue/ossec/queue`.

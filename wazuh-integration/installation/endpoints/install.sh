#!/usr/bin/env bash
# Install (or upgrade) wazuh-evaluate-iov-daemon on a Wazuh agent host.
#
# Copies the daemon binary and the systemd unit into place, installs the
# config file if there is none yet, and (re)starts the service. Re-running it
# upgrades the binary and unit but never overwrites an existing config.
#
# Usage, from a checkout or a copy of this directory (the daemon binary in it
# is built by iov-evaluation/package.sh):
#   sudo ./install.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

SERVICE=wazuh-evaluate-iov-daemon
BINARY_SRC="$SCRIPT_DIR/$SERVICE"
UNIT_SRC="$SCRIPT_DIR/$SERVICE.service"
CONFIG_SRC="$SCRIPT_DIR/daemon.env.example"

# Must match ExecStart= and EnvironmentFile= in the unit.
BINARY_DST=/usr/local/bin/$SERVICE
UNIT_DST=/etc/systemd/system/$SERVICE.service
CONFIG_DST=/etc/wazuh-evaluate-iov/daemon.env

die() { echo "install: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (sudo $0)"
# 'which systemd' proves nothing: systemd is PID 1, not a command on PATH.
[ "$(ps -p 1 -o comm= 2>/dev/null)" = systemd ] || die "systemd is not running on this host"
for f in "$BINARY_SRC" "$UNIT_SRC" "$CONFIG_SRC"; do
    [ -f "$f" ] || die "missing $f (run iov-evaluation/package.sh first?)"
done

echo "Installing $BINARY_DST"
install -D -m 755 "$BINARY_SRC" "$BINARY_DST"

echo "Installing $UNIT_DST"
install -D -m 644 "$UNIT_SRC" "$UNIT_DST"

if [ -e "$CONFIG_DST" ]; then
    echo "Keeping existing $CONFIG_DST"
else
    echo "Installing $CONFIG_DST"
    install -D -m 600 "$CONFIG_SRC" "$CONFIG_DST"
fi

systemctl daemon-reload
systemctl enable --quiet "$SERVICE"
# restart rather than start, so an upgrade picks up the new binary.
systemctl restart "$SERVICE"

# Type=simple counts as active at once; give a crash on startup time to show.
sleep 3
if systemctl is-active --quiet "$SERVICE"; then
    echo "$SERVICE is running."
else
    echo "WARNING: $SERVICE did not stay up; see: journalctl -u $SERVICE" >&2
fi

echo
echo "Config file: $CONFIG_DST"
echo "After editing it: systemctl restart $SERVICE"

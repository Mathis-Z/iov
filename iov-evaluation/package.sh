#!/usr/bin/env bash
# Build every single-file executable from the shared evaluate_iov codebase.
#
#   dist/evaluate-iov
#       standalone CLI: takes an IoV file, prints the result
#   ../wazuh-integration/installation/endpoints/wazuh-evaluate-iov-daemon
#       systemd service: syncs IoVs from the server and publishes verdicts
#       through the Wazuh agent socket. Built straight into the endpoint
#       installation directory, which is all an endpoint needs.
#
# Both binaries are fully static: PyInstaller bundles the interpreter and every
# Python dependency, then staticx bundles the remaining shared libraries (glibc,
# libz, ...) and the dynamic loader itself, so they run on any x86_64 Linux
# regardless of its glibc version or installed libraries.
#
# Usage:
#   cd iov-evaluation
#   ./package.sh                          # builds with python3 from PATH
#   PYTHON=/usr/bin/python3 ./package.sh  # or with a specific interpreter
#
# Deployed to agents with wazuh-integration/installation/endpoints/install.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$SCRIPT_DIR/.venv-build"
DIST_DIR="$SCRIPT_DIR/dist"
ENDPOINTS_DIR="$SCRIPT_DIR/../wazuh-integration/installation/endpoints"
BUILD_DIR="$SCRIPT_DIR/.pyinstaller-build"
PYTHON="${PYTHON:-python3}"

# PyInstaller silently leaves out extension modules that fail to import, and
# the binary then only breaks on the host that needs them.
echo "[package.sh] Checking $PYTHON's standard library extensions ..."
"$PYTHON" -c "import bz2, ctypes, grp, gzip, lzma, pwd, ssl, zlib"

echo "[package.sh] Creating build virtualenv at $VENV ..."
"$PYTHON" -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt" pyinstaller staticx patchelf

build() {
    local name="$1" entrypoint="$2" out_dir="$3"
    echo "[package.sh] Running PyInstaller for $name ..."
    "$VENV/bin/pyinstaller" \
        --onefile \
        --name "$name" \
        --collect-all celpy \
        --collect-data jsonschema_specifications \
        --collect-data tzdata \
        --add-data "$SCRIPT_DIR/evaluate_iov/iov.schema.json:evaluate_iov" \
        --distpath "$BUILD_DIR/dist" \
        --workpath "$BUILD_DIR" \
        --specpath "$BUILD_DIR" \
        --paths "$SCRIPT_DIR" \
        "$SCRIPT_DIR/$entrypoint"

    echo "[package.sh] Running staticx for $name ..."
    mkdir -p "$out_dir"
    # staticx calls patchelf, which pip installs into the venv's bin.
    PATH="$VENV/bin:$PATH" "$VENV/bin/staticx" --strip \
        "$BUILD_DIR/dist/$name" "$out_dir/$name"
    chmod 755 "$out_dir/$name"
    echo "[package.sh] Built $(cd "$out_dir" && pwd)/$name"
}

build evaluate-iov              entrypoint_evaluate_iov.py              "$DIST_DIR"
build wazuh-evaluate-iov-daemon entrypoint_wazuh_evaluate_iov_daemon.py "$ENDPOINTS_DIR"

echo "[package.sh] Done."
rm -rf "$VENV" "$BUILD_DIR"

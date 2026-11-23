#!/usr/bin/env bash
# Build the plugin for one OpenSearch Dashboards version, in Docker.
#
#   ./build.sh 2.10.0          -> build/wazuhIframeWidget-2.10.0.zip
#
# The version must be exactly the one the Wazuh dashboard runs; find it with
#   grep '"version"' /usr/share/wazuh-dashboard/package.json
#
# Needs git and Docker. The OpenSearch Dashboards checkout (~2 GB after
# bootstrap) is kept in .osd-build/ so a rebuild skips the slow part.
set -euo pipefail

VERSION="${1:?usage: $0 <opensearch-dashboards-version, e.g. 2.10.0>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${OSD_BUILD_DIR:-$HERE/.osd-build}"
OSD="$WORK/OpenSearch-Dashboards-$VERSION"
PLUGIN="wazuh_iframe_widget"

if [ ! -d "$OSD" ]; then
  mkdir -p "$WORK"
  git clone --depth 1 --branch "$VERSION" \
    https://github.com/opensearch-project/OpenSearch-Dashboards.git "$OSD"
fi
NODE_VERSION="$(tr -d '[:space:]v' < "$OSD/.nvmrc")"

# Fresh copy of the plugin sources, with the target version in the manifest:
# the dashboard refuses a plugin built for any other version.
rm -rf "$OSD/plugins/$PLUGIN"
mkdir -p "$OSD/plugins/$PLUGIN"
cp -R "$HERE/public" "$HERE/server" "$HERE/package.json" "$HERE/opensearch_dashboards.json" "$OSD/plugins/$PLUGIN/"
sed -i "s/\"opensearchDashboardsVersion\": *\"[^\"]*\"/\"opensearchDashboardsVersion\": \"$VERSION\"/" \
  "$OSD/plugins/$PLUGIN/opensearch_dashboards.json"

docker run --rm \
  -v "$OSD:/osd:z" -w /osd \
  -e HOME=/tmp \
  --user "$(id -u):$(id -g)" \
  "node:$NODE_VERSION" \
  bash -c "
    set -e
    [ -d node_modules ] || yarn osd bootstrap
    cd plugins/$PLUGIN
    yarn build --opensearch-dashboards-version '$VERSION'
  "

mkdir -p "$HERE/build"
cp "$OSD/plugins/$PLUGIN/build/"*.zip "$HERE/build/"
ls -l "$HERE/build/"*"$VERSION"*.zip

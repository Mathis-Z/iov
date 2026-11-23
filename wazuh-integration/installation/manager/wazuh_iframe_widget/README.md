# Wazuh iframe widget

Adds an **IoV Dashboard** app to the Wazuh dashboard that embeds ETSO's prioritisation dashboard,
served by this plugin's own server side at `/api/etso/dashboard/`, which fetches it from ETSO
(`server/routes/etso_proxy.ts`).

Build it for the exact OpenSearch Dashboards version your Wazuh dashboard runs, in Docker:

```bash
grep '"version"' /usr/share/wazuh-dashboard/package.json   # e.g. 2.10.0 (Wazuh 4.8)
./build.sh 2.10.0                                           # -> build/wazuhIframeWidget-2.10.0.zip
```

Configuring, installing and troubleshooting are in the
[manager README](../README.md#dashboard-plugin).

`build.sh` clones OpenSearch Dashboards at that tag into `.osd-build/`, bootstraps it in a
`node` container matching its `.nvmrc`, and builds the plugin there.

Or inside an existing, bootstrapped OpenSearch Dashboards checkout of that version (works on
Windows too, with that checkout's Node version from `.nvmrc` on the PATH):

```bash
cp -R public server package.json opensearch_dashboards.json <osd>/plugins/wazuh_iframe_widget/
cd <osd>/plugins/wazuh_iframe_widget
node ../../scripts/plugin_helpers build --opensearch-dashboards-version 2.10.0
# -> build/wazuhIframeWidget-2.10.0.zip
```

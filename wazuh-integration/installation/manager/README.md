# Manager: detection rules and dashboard plugin

Two things are installed on the Wazuh side:

- **The IoV rules** (`iov_rules.xml`) on the **manager**. They turn the verdicts the endpoint
  daemons send (see [`../endpoints`](../endpoints)) into alerts that ETSO reads back. This part is
  required.
- **The dashboard plugin** (`wazuh_iframe_widget/`) on the **Wazuh dashboard**. It adds an
  **IoV Dashboard** app that embeds ETSO's prioritisation dashboard. This part is optional.

| File | What |
|---|---|
| `iov_rules.xml` | The rules. |
| `assemble_install_script.sh` | Packages the rules into `install-iov-manager.sh`. Re-run after editing the rules. |
| `install-iov-manager.sh` | Generated, self-contained installer for the rules. |
| `wazuh_iframe_widget/` | The dashboard plugin's source and `build.sh`. |

## Rules

### What the rules do

The daemon writes pure JSON to the agent socket, so analysisd's built-in JSON decoding splits it
into `iov.*` fields; no custom decoder is needed. `iov_rules.xml` then defines:

| Rule | Level | Matches |
|---|---|---|
| `100200` | 0 | Any event with an `iov.cve` field. Parent only, generates no alert. |
| `100201` | 3 | `iov.level` of INCONCLUSIVE, ABSENT or LOW |
| `100202` | 7 | MEDIUM: an affected package is installed |
| `100203` | 10 | HIGH: affected, and the preconditions are present |

Two things here are load-bearing:

- **The `iov_evaluation` group is the contract with ETSO.** ETSO's query filters on
  `rule.groups: iov_evaluation`. Rename it and ETSO silently finds nothing.
- **The levels must stay above the manager's `log_alert_level`** (3 by default). A level-0 rule
  generates no alert, so it never reaches `wazuh-alerts-*` and ETSO never sees it. That is why
  `100200` is only a parent and the verdict rules carry real levels, even though an IoV verdict is
  an assessment rather than an incident.

### Install

```bash
./assemble_install_script.sh          # only needed after editing iov_rules.xml
scp install-iov-manager.sh manager:
ssh manager 'sudo ./install-iov-manager.sh'
```

The installer takes `--no-restart`, `--ossec-dir DIR` and `--dry-run`. It validates the rule set
with `wazuh-analysisd -t` before restarting, and restarts via `systemctl` or
`/var/ossec/bin/wazuh-control`, depending on what the host has. Re-running it is safe.

**It is also safe to paste into a bash prompt**, for manager containers with no editor. The script
is one function definition plus a call:

- a failure exits that function's subshell rather than your shell;
- `set -euo pipefail` does not leak into your session;
- a truncated paste runs nothing.

There is nowhere to put flags when pasting, so set the environment first:

```bash
IOV_NO_RESTART=1 IOV_OSSEC_DIR=/var/ossec
<paste the script>
```

By hand instead:

```bash
cp iov_rules.xml /var/ossec/etc/rules/
chown root:wazuh /var/ossec/etc/rules/iov_rules.xml
chmod 660 /var/ossec/etc/rules/iov_rules.xml
/var/ossec/bin/wazuh-analysisd -t          # must pass before restarting
systemctl restart wazuh-manager            # or /var/ossec/bin/wazuh-control restart
```

No `ossec.conf` change is needed: `etc/rules` is already in the default `<rule_dir>`.

### Customising

- **Rule IDs** `100200`–`100203` are in the user range. If they collide with your own rules,
  `wazuh-analysisd -t` reports a duplicate ID; renumber consistently, keeping the `<if_sid>`
  references in step.
- **Levels** can be tuned to control dashboard noise, but do not set them to 0 (see above). If
  MEDIUM/HIGH verdicts trip notification rules, filter on the `iov` group in those rules rather
  than lowering these.
- **Event location**: if you change `IOV_EVENT_LOCATION` on the agents, nothing in the rules
  depends on it. `100200` selects on the `iov.cve` field, not the location.

### Verify

```bash
/var/ossec/bin/wazuh-analysisd -t                                 # rules parse
grep -m5 iov_evaluation /var/ossec/logs/alerts/alerts.json        # alerts are firing
```

To test the rules against a captured event, feed the JSON (without the `1:evaluate-iov:` framing)
to `/var/ossec/bin/wazuh-logtest`. That is the most useful tool for this chain.

### Troubleshooting

**"The rule set does not parse."** Get the real error with `/var/ossec/bin/wazuh-analysisd -t`. Do
**not** use `wazuh-logtest -t` for this: it connects to a running analysisd's logtest socket, so on
a stopped manager it fails for reasons unrelated to your rules. The commonest genuine cause is a
duplicate rule ID: `grep -rn '10020' /var/ossec/etc/rules/`.

**No systemd in the manager container.** Restart with `/var/ossec/bin/wazuh-control restart`; the
installer does this on its own.

**Alerts in `alerts.json` but nothing in `wazuh-alerts-*`.** Filebeat is not shipping to the
indexer. That is a base Wazuh problem, not an IoV one; check `filebeat test output` on the manager.

## Dashboard plugin

The plugin adds an **IoV Dashboard** app to the Wazuh menu that shows ETSO's dashboard in an
iframe, and passes Wazuh's dark-mode setting along. Its server side serves the page at
`/api/etso/dashboard/` on the Wazuh dashboard itself, fetching it from ETSO over plain HTTP. So the
frame needs no certificate or port of its own, and only logged-in Wazuh users can load it. See
[Embedding in Wazuh](../../README.md#embedding-in-wazuh) for the whole picture.

### Configure

The Wazuh dashboard's server must reach ETSO. Set where, in `opensearch_dashboards.yml`
(`/etc/wazuh-dashboard/opensearch_dashboards.yml`, or `config/wazuh_dashboard/opensearch_dashboards.yml`
in wazuh-docker):

```yaml
wazuhIframeWidget.etsoUrl: http://127.0.0.1:8000     # the default
```

The default fits a Wazuh dashboard installed as a package on the same host as ETSO. **In Docker,
`127.0.0.1` is the dashboard container itself**, so point it at the host instead. For wazuh-docker
on the ETSO host, add to the `wazuh.dashboard` service in `docker-compose.yml`:

```yaml
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

and set `wazuhIframeWidget.etsoUrl: http://host.docker.internal:8000`. A host firewall must let the
Docker network reach port 8000.

### Build and install

On the host that runs the Wazuh dashboard, from this directory:

```bash
# 1. Build for the exact dashboard version (first build: ~15-30 min, ~2 GB).
grep '"version"' /usr/share/wazuh-dashboard/package.json        # e.g. 2.10.0 for Wazuh 4.8
wazuh_iframe_widget/build.sh 2.10.0

# 2. Install it and restart the dashboard.
sudo cp wazuh_iframe_widget/build/wazuhIframeWidget-2.10.0.zip /tmp/
sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin \
  install file:///tmp/wazuhIframeWidget-2.10.0.zip
sudo systemctl restart wazuh-dashboard
```

To update the plugin later, `opensearch-dashboards-plugin remove wazuhIframeWidget` first, then
install again. A Wazuh upgrade changes the dashboard version, so rebuild the plugin for it.
[`wazuh_iframe_widget/README.md`](wazuh_iframe_widget/README.md) describes building without Docker.
The build needs only Docker and git on the build host; the Wazuh host needs neither.

**Wazuh in Docker** (wazuh-docker): a plugin installed into the container is lost when the
container is recreated, so unpack it on the host and mount it instead. For `single-node`:

```bash
cd wazuh-docker/single-node
mkdir -p config/wazuh_dashboard/plugins/wazuhIframeWidget
unzip -o wazuhIframeWidget-2.10.0.zip 'opensearch-dashboards/wazuhIframeWidget/*' -d /tmp/iframe
cp -R /tmp/iframe/opensearch-dashboards/wazuhIframeWidget/. config/wazuh_dashboard/plugins/wazuhIframeWidget/
# docker-compose.yml, under wazuh.dashboard -> volumes:
#   - ./config/wazuh_dashboard/plugins/wazuhIframeWidget:/usr/share/wazuh-dashboard/plugins/wazuhIframeWidget:ro
docker-compose up -d --no-deps wazuh.dashboard
```

To update it, replace the files in that directory and `docker restart single-node-wazuh.dashboard-1`.

Browsers keep seeing the old plugin after an update. The dashboard serves plugin bundles with a
one-year `max-age`, under a URL that only changes with the Wazuh version. So each user has to empty
the browser cache once ("Empty cache and hard reload" in the devtools). Changes to ETSO's dashboard
page itself need no plugin update and no cache clearing; the plugin only points the iframe at it.

The dashboard refuses to start on an invalid plugin manifest (it logs `invalid-manifest` and
exits), so check `docker logs` after a change. Keep `opensearch_dashboards.json` free of keys
OpenSearch Dashboards 2.10 does not know, such as `type`.

### Verify

Check the route from the Wazuh host, first without a session:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost/api/etso/dashboard/    # 401: login required
```

Then log in to Wazuh and open **IoV Dashboard**; the page should render with no certificate prompt.

### Troubleshooting

The frame shows the route's error, or the browser's network tab shows it for `/api/etso/dashboard/`:

- **401** means the request had no Wazuh session. Log in to Wazuh again.
- **502** means the Wazuh dashboard cannot reach ETSO: `wazuhIframeWidget.etsoUrl` is wrong, ETSO
  is down, or (in Docker) the container cannot reach the host. The Wazuh dashboard's log names the
  address it tried. Test it from where the dashboard runs, e.g.
  `docker exec single-node-wazuh.dashboard-1 curl -s http://host.docker.internal:8000/dashboard/`.
- **504** means ETSO did not answer within 5 minutes. The first build after an ETSO restart reads
  the whole indexer; reload once it has finished.
- **404 for `/api/etso/dashboard/`** means the plugin's server side is not loaded. Check that the
  installed build is this version (it has a `server/` directory), and restart the dashboard.

#!/usr/bin/env bash
# Install the IoV detection rules on a Wazuh MANAGER.
#
# GENERATED FILE -- do not edit. Produced by installation/manager/assemble_install_script.sh
# from iov_rules.xml.
#
# The rules match the verdicts wazuh-evaluate-iov-daemon publishes through the
# agent socket and tag them with the iov_evaluation group. Nothing else is
# installed here: ETSO projects those alerts into the iov-results
# index itself (creating it on first use), so the manager needs no
# integration script and no indexer credentials.
#
# SAFE TO PASTE into a plain bash prompt -- no editor needed on the target.
# Everything below defines one function and then calls it, so:
#   * a failure exits that function's subshell, never your shell;
#   * 'set -euo pipefail' stays inside it and does not leak into your session;
#   * a truncated paste leaves an unterminated function and runs nothing.
# When pasting there is nowhere to put flags, so configure it with environment
# variables set on the lines before, or exported beforehand:
#
#   IOV_NO_RESTART=1 IOV_DRY_RUN=1 IOV_OSSEC_DIR=/var/ossec
#   <paste this script>
#
# Run as a file instead and the equivalent flags work:
#
#   sudo ./install-iov-manager.sh [OPTIONS]
#
#   --no-restart         install the rules but leave the manager running
#   --ossec-dir DIR      Wazuh root (default: /var/ossec), for testing
#   --dry-run            print what would change, touch nothing
#   -h, --help           this text
#
# Re-running is safe.

# The body is a ( ) subshell, which is what makes this paste-safe.
iov_install() (
    set -euo pipefail

    OSSEC_DIR="${IOV_OSSEC_DIR:-/var/ossec}"
    RESTART=1
    DRY_RUN=0
    # Written as 'if', not '&& VAR=0': under set -e a failing test as the last
    # command of an && list would abort the install.
    if [ -n "${IOV_NO_RESTART:-}" ]; then RESTART=0; fi
    if [ -n "${IOV_DRY_RUN:-}" ];   then DRY_RUN=1; fi

    usage() {
        cat <<'USAGE'
install-iov-manager.sh -- install the IoV detection rules on a Wazuh manager.

  --no-restart         install the rules but leave the manager running
  --ossec-dir DIR      Wazuh root (default: /var/ossec)
  --dry-run            print what would change, touch nothing

Pasting into a shell? Use the environment instead: IOV_NO_RESTART,
IOV_DRY_RUN, IOV_OSSEC_DIR.
USAGE
    }

    while [ $# -gt 0 ]; do
        case "$1" in
            --ossec-dir)  OSSEC_DIR="$2"; shift 2 ;;
            --no-restart) RESTART=0; shift ;;
            --dry-run)    DRY_RUN=1; shift ;;
            -h|--help)    usage; exit 0 ;;
            *)            printf 'install-iov-manager: unknown option %s\n' "$1" >&2; exit 2 ;;
        esac
    done

    say()  { printf '[iov-install] %s\n' "$*"; }
    warn() { printf '[iov-install] WARNING: %s\n' "$*" >&2; }
    # exit leaves this function's subshell only, so an interactive shell that
    # the script was pasted into survives.
    die()  { printf '[iov-install] ERROR: %s\n' "$*" >&2; exit 1; }

    run() {
        if [ "$DRY_RUN" -eq 1 ]; then
            printf '[iov-install] would run: %s\n' "$*"
        else
            "$@"
        fi
    }

    # Write stdin to a file with the given owner and mode.
    install_file() {
        local path="$1" owner="$2" mode="$3" content
        content="$(cat)"
        if [ "$DRY_RUN" -eq 1 ]; then
            printf '[iov-install] would write %s (%s, %s, %d bytes)\n' \
                "$path" "$owner" "$mode" "${#content}"
            return
        fi
        mkdir -p "$(dirname "$path")"
        printf '%s\n' "$content" > "$path"
        chown "$owner" "$path" 2>/dev/null || warn "could not chown $path to $owner"
        chmod "$mode" "$path"
        say "installed $path"
    }

read -r -d '' RULES <<'__IOV_RULES_EOF__' || true
<!--
  Copy to the MANAGER's /var/ossec/etc/rules/iov_rules.xml, then restart it:

      sudo systemctl restart wazuh-manager
      # or, in a container without systemd:
      sudo /var/ossec/bin/wazuh-control restart

  These match the events wazuh-evaluate-iov-daemon writes to the agent's queue
  socket. The daemon sends pure JSON, so analysisd's built-in JSON decoding
  splits it into iov.* fields and no custom decoder is needed.

  Rule levels are deliberately low: an IoV verdict is an assessment, not an
  alert. The levels exist so the events reach wazuh-alerts-*, where ETSO reads
  them back and projects them into iov-results.
-->
<group name="iov,">

  <rule id="100200" level="0">
    <decoded_as>json</decoded_as>
    <field name="iov.cve">\.+</field>
    <description>IoV evaluation reported by the agent</description>
    <group>iov_evaluation,</group>
  </rule>

  <rule id="100201" level="3">
    <if_sid>100200</if_sid>
    <field name="iov.level">INCONCLUSIVE|ABSENT|LOW</field>
    <description>IoV $(iov.cve): $(iov.level) — no action indicated</description>
    <group>iov_evaluation,</group>
  </rule>

  <rule id="100202" level="7">
    <if_sid>100200</if_sid>
    <field name="iov.level">MEDIUM</field>
    <description>IoV $(iov.cve): an affected package is installed</description>
    <group>iov_evaluation,</group>
  </rule>

  <rule id="100203" level="10">
    <if_sid>100200</if_sid>
    <field name="iov.level">HIGH</field>
    <description>IoV $(iov.cve): affected and the exploitation preconditions are present</description>
    <group>iov_evaluation,</group>
  </rule>

</group>
__IOV_RULES_EOF__

# ── Preflight ─────────────────────────────────────────────────────────────────

    # Root is needed for a real install; --ossec-dir points at a scratch tree
    # for testing, where it is not.
    if [ "$DRY_RUN" -eq 0 ] && [ "$OSSEC_DIR" = "/var/ossec" ] && [ "$(id -u)" -ne 0 ]; then
        die "must run as root to install into /var/ossec"
    fi
    [ -d "$OSSEC_DIR" ] || die "$OSSEC_DIR does not exist -- is Wazuh installed here?"

    # An agent has no analysisd, and installing rules there does nothing.
    if [ ! -x "$OSSEC_DIR/bin/wazuh-analysisd" ] && [ "$OSSEC_DIR" = "/var/ossec" ]; then
        die "this host looks like a Wazuh agent, not a manager (no bin/wazuh-analysisd)"
    fi

    OSSEC_GROUP="wazuh"
    getent group "$OSSEC_GROUP" >/dev/null 2>&1 || OSSEC_GROUP="ossec"

# ── Rules ─────────────────────────────────────────────────────────────────────

    # etc/rules is in the default <rule_dir>, so no ossec.conf change is needed.
    say "installing rules"
    printf '%s' "$RULES" | install_file "$OSSEC_DIR/etc/rules/iov_rules.xml" "root:$OSSEC_GROUP" 660

# ── Validate and restart ──────────────────────────────────────────────────────

    # wazuh-analysisd -t is the configuration test. Do NOT use wazuh-logtest
    # here: it connects to a running analysisd's logtest socket, so it fails on
    # a stopped manager and reports a parse error that isn't one.
    if [ "$DRY_RUN" -eq 0 ]; then
        if [ -x "$OSSEC_DIR/bin/wazuh-analysisd" ]; then
            say "checking the rule set parses"
            if ! VALIDATION="$("$OSSEC_DIR/bin/wazuh-analysisd" -t 2>&1)"; then
                printf '%s\n' "$VALIDATION" >&2
                die "the rule set does not parse (output above); nothing was restarted"
            fi
        else
            warn "no wazuh-analysisd here, skipping the rule-set check"
        fi
    fi

    # Containers usually have no systemd; wazuh-control is Wazuh's own
    # init-agnostic wrapper and works either way.
    restart_manager() {
        if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            run systemctl restart wazuh-manager
        elif [ -x "$OSSEC_DIR/bin/wazuh-control" ]; then
            run "$OSSEC_DIR/bin/wazuh-control" restart
        else
            warn "no systemd and no $OSSEC_DIR/bin/wazuh-control -- restart the manager yourself"
        fi
    }

    if [ "$RESTART" -eq 1 ]; then
        say "restarting the manager"
        restart_manager
    elif command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        say "not restarting; run 'systemctl restart wazuh-manager' to apply"
    else
        say "not restarting; run '$OSSEC_DIR/bin/wazuh-control restart' to apply"
    fi

    cat <<'NEXT'

[iov-install] Done. To verify the chain end to end:

  1. On an agent:  wazuh-evaluate-iov-daemon --once --log-level INFO
                   -> "N evaluated, N published"
  2. On this host: grep -m5 iov_evaluation /var/ossec/logs/alerts/alerts.json
  3. On the indexer, confirm the alerts are searchable:
                   curl -sk -u USER:PASS "https://INDEXER:9200/wazuh-alerts-*/_search?pretty" \
                     -H 'Content-Type: application/json' \
                     -d '{"query":{"term":{"rule.groups":"iov_evaluation"}}}'
  4. On the ETSO host: python3 src/cli.py iov-sync --dry-run
                   then without --dry-run to write iov-results.

NEXT
)

iov_install "$@"

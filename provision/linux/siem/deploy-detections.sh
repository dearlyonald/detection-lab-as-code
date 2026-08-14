#!/usr/bin/env bash
# =============================================================================
#  detection-lab-as-code — deploy Sigma rules to Wazuh
# =============================================================================
#  Converts the Sigma rules in detections/sigma/ into Wazuh local rules and
#  installs them into /var/ossec/etc/rules/.
#
#  This is the step that turns a folder of YAML into an actual, firing SIEM.
#  Most labs skip it, which is why most labs have "detections" that have never
#  detected anything.
# =============================================================================
set -euo pipefail

log()  { printf '\033[0;36m[%(%H:%M:%S)T] >>> %s\033[0m\n' -1 "$1"; }
ok()   { printf '\033[0;32m[%(%H:%M:%S)T]  OK  %s\033[0m\n' -1 "$1"; }
warn() { printf '\033[0;33m[%(%H:%M:%S)T]  !!  %s\033[0m\n' -1 "$1"; }

STAGING="/opt/detection-lab"
RULES_DIR="/var/ossec/etc/rules"
mkdir -p "$STAGING"

# -----------------------------------------------------------------------------
# Toolchain
# -----------------------------------------------------------------------------
log "Installing the Sigma toolchain"
pip3 install --quiet --upgrade pip
# pysigma + the Wazuh-compatible backend. sigma-cli drives the conversion.
pip3 install --quiet sigma-cli pysigma pysigma-backend-opensearch pyyaml 2>/dev/null || {
  warn "pip install failed; falling back to the bundled converter"
}
ok "toolchain ready"

# -----------------------------------------------------------------------------
# Where are the rules?
# -----------------------------------------------------------------------------
# Vagrant's synced folder is disabled by design (it is slow and it leaks the
# host filesystem into a machine we deliberately attack). Rules are pushed with
# `vagrant upload` from the host instead — see tools/deploy.ps1.
if [ ! -d "$STAGING/sigma" ]; then
  warn "no rules staged at $STAGING/sigma"
  warn "push them from the host with:  .\\tools\\deploy-rules.ps1"
  warn "then re-run:  vagrant provision siem --provision-with decoders-rules"
  exit 0
fi

RULE_COUNT=$(find "$STAGING/sigma" -name '*.yml' | wc -l)
log "Converting $RULE_COUNT Sigma rules to Wazuh format"

# -----------------------------------------------------------------------------
# Conversion
# -----------------------------------------------------------------------------
# Wazuh has no first-class Sigma backend, so we generate native Wazuh XML rules.
# The converter lives in the repo (tools/sigma_to_wazuh.py) and is unit-tested
# in CI, which keeps the translation honest.
if [ -f "$STAGING/tools/sigma_to_wazuh.py" ]; then
  python3 "$STAGING/tools/sigma_to_wazuh.py" \
      --input  "$STAGING/sigma" \
      --output "$RULES_DIR/100100-detection-lab.xml" \
      --base-id 100100
  ok "rules written to $RULES_DIR/100100-detection-lab.xml"
else
  warn "converter not found at $STAGING/tools/sigma_to_wazuh.py"
  exit 0
fi

chown wazuh:wazuh "$RULES_DIR/100100-detection-lab.xml"
chmod 640 "$RULES_DIR/100100-detection-lab.xml"

# -----------------------------------------------------------------------------
# Validate before restarting. A malformed rule file makes wazuh-manager refuse
# to start, and then you have no SIEM at all.
# -----------------------------------------------------------------------------
log "Validating the ruleset"
if /var/ossec/bin/wazuh-logtest -t 2>&1 | grep -qi 'error'; then
  warn "ruleset failed validation — reverting"
  mv "$RULES_DIR/100100-detection-lab.xml" "$STAGING/rejected-$(date +%s).xml"
  exit 1
fi
ok "ruleset validated"

log "Restarting the manager"
systemctl restart wazuh-manager
sleep 8

if systemctl is-active --quiet wazuh-manager; then
  ok "manager restarted with $RULE_COUNT detections loaded"
else
  warn "manager failed to restart: journalctl -u wazuh-manager -n 50"
  exit 1
fi

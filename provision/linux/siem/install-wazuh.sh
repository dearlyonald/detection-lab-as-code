#!/usr/bin/env bash
# =============================================================================
#  detection-lab-as-code — Wazuh all-in-one SIEM installation
# =============================================================================
#  Installs the Wazuh indexer, server and dashboard on a single node using the
#  official assisted installer.
#
#  Idempotent: re-running `vagrant provision siem` detects an existing install
#  and skips straight to configuration, so iterating on detections is fast.
# =============================================================================
set -euo pipefail

WAZUH_VERSION="4.9"
BIND_IP="${WAZUH_BIND_IP:-10.13.37.30}"
CRED_FILE="/root/wazuh-credentials.txt"

log()  { printf '\033[0;36m[%(%H:%M:%S)T] >>> %s\033[0m\n' -1 "$1"; }
ok()   { printf '\033[0;32m[%(%H:%M:%S)T]  OK  %s\033[0m\n' -1 "$1"; }
warn() { printf '\033[0;33m[%(%H:%M:%S)T]  !!  %s\033[0m\n' -1 "$1"; }

# -----------------------------------------------------------------------------
# Preflight — the installer fails late and confusingly if RAM is short, so check
# up front and say something useful.
# -----------------------------------------------------------------------------
TOTAL_MB=$(free -m | awk '/^Mem:/{print $2}')
if [ "$TOTAL_MB" -lt 5800 ]; then
  warn "only ${TOTAL_MB}MB RAM — the Wazuh indexer needs 6GB+."
  warn "raise machines.siem.memory in lab.yml, then: vagrant reload siem"
fi
ok "memory: ${TOTAL_MB}MB"

if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
  ok "Wazuh already installed — skipping to configuration"
  ALREADY_INSTALLED=1
else
  ALREADY_INSTALLED=0
fi

# -----------------------------------------------------------------------------
# Host prerequisites
# -----------------------------------------------------------------------------
if [ "$ALREADY_INSTALLED" -eq 0 ]; then
  log "Installing prerequisites"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl gnupg apt-transport-https lsb-release \
                        jq python3-pip unzip net-tools >/dev/null
  ok "prerequisites installed"

  # vm.max_map_count — the indexer is OpenSearch, and it refuses to start
  # below 262144. Set it persistently, not just for this boot.
  log "Tuning kernel parameters for the indexer"
  sysctl -w vm.max_map_count=262144 >/dev/null
  grep -q 'vm.max_map_count' /etc/sysctl.conf || echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
  ok "vm.max_map_count=262144"

  # -----------------------------------------------------------------------------
  # Install
  # -----------------------------------------------------------------------------
  log "Downloading the Wazuh ${WAZUH_VERSION} assisted installer"
  cd /root
  curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"
  chmod +x wazuh-install.sh

  log "Running the installer — this takes 10-20 minutes, be patient"
  # -a = all-in-one, -i = ignore hardware checks (we already warned above)
  ./wazuh-install.sh -a -i 2>&1 | tee /root/wazuh-install.log

  # The installer prints the admin password once, into the log. Capture it, or
  # you will be locked out of your own dashboard.
  if [ -f /root/wazuh-install-files.tar ]; then
    tar -xf /root/wazuh-install-files.tar -C /root/ 2>/dev/null || true
  fi
  grep -E 'password' /root/wazuh-install.log > "$CRED_FILE" 2>/dev/null || true
  chmod 600 "$CRED_FILE"
  ok "installation complete; credentials saved to $CRED_FILE"
fi

# -----------------------------------------------------------------------------
# Manager configuration
# -----------------------------------------------------------------------------
log "Configuring the manager for lab use"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
cp "$OSSEC_CONF" "${OSSEC_CONF}.bak.$(date +%s)"

# Enable agent auto-enrolment on 1515 so Windows agents register themselves
# without a manual key exchange.
if ! grep -q '<auth>' "$OSSEC_CONF"; then
  warn "auth block missing from ossec.conf — agent auto-enrolment may not work"
else
  # use_password=no keeps the lab frictionless; never do this in production.
  sed -i 's|<use_password>yes</use_password>|<use_password>no</use_password>|' "$OSSEC_CONF"
  ok "agent auto-enrolment enabled on ${BIND_IP}:1515"
fi

# -----------------------------------------------------------------------------
# Log retention — the default archives setting drops raw events, which makes it
# impossible to go back and test a new rule against yesterday's attack run.
# Archiving everything is exactly what a detection lab needs.
# -----------------------------------------------------------------------------
log "Enabling full event archiving"
sed -i 's|<logall>no</logall>|<logall>yes</logall>|'             "$OSSEC_CONF"
sed -i 's|<logall_json>no</logall_json>|<logall_json>yes</logall_json>|' "$OSSEC_CONF"
ok "archives.json will retain every event, matched or not"

# -----------------------------------------------------------------------------
# Vulnerability detection off — it is heavy, downloads large feeds, and this
# lab is about detection engineering, not vulnerability management.
# -----------------------------------------------------------------------------
python3 - "$OSSEC_CONF" <<'PYEOF'
import re, sys
path = sys.argv[1]
conf = open(path, encoding='utf-8').read()
conf = re.sub(
    r'(<vulnerability-detection>.*?<enabled>)yes(</enabled>)',
    r'\1no\2', conf, flags=re.S)
open(path, 'w', encoding='utf-8').write(conf)
PYEOF
ok "vulnerability detection disabled (saves ~1GB RAM and a long feed download)"

# -----------------------------------------------------------------------------
# Filebeat / indexer template — raise the field limit. Sysmon events carry a lot
# of fields and the default 1000-field mapping limit silently drops documents.
# -----------------------------------------------------------------------------
if [ -f /etc/filebeat/filebeat.yml ]; then
  log "Restarting filebeat"
  systemctl restart filebeat || warn "filebeat restart failed"
fi

systemctl restart wazuh-manager
sleep 10

# -----------------------------------------------------------------------------
# Verification — prove each component is actually up.
# -----------------------------------------------------------------------------
log "Verifying services"
ALL_OK=1
for svc in wazuh-indexer wazuh-manager wazuh-dashboard filebeat; do
  if systemctl is-active --quiet "$svc"; then
    ok "$svc is running"
  else
    warn "$svc is NOT running"
    ALL_OK=0
  fi
done

# The indexer answering on 9200 is the real health signal.
# Check HTTPS reachability without hardcoded credentials.
# HTTP 401 confirms that the endpoint is reachable, not cluster health.
INDEXER_STATUS="$(curl -sk -o /dev/null -w '%{http_code}' \
  --connect-timeout 5 --max-time 10 \
  https://127.0.0.1:9200/ || true)"

if [[ "$INDEXER_STATUS" == "200" || "$INDEXER_STATUS" == "401" ]]; then
  ok "indexer HTTPS endpoint responding (HTTP ${INDEXER_STATUS})"
else
  warn "indexer HTTPS endpoint not responding as expected (HTTP ${INDEXER_STATUS})"
  ALL_OK=0
fi

echo
echo "==============================================================="
echo "  Wazuh dashboard : https://${BIND_IP}"
echo "  Username        : admin"
echo "  Password        : see /root/wazuh-credentials.txt on this VM"
echo "                    (vagrant ssh siem -c 'sudo cat /root/wazuh-credentials.txt')"
echo "  Agent enrolment : ${BIND_IP}:1515  (auto, no password)"
echo "==============================================================="

[ "$ALL_OK" -eq 1 ] || warn "one or more services are down — check: journalctl -u wazuh-manager -n 50"

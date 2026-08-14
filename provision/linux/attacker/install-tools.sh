#!/usr/bin/env bash
# =============================================================================
#  detection-lab-as-code — attacker workstation
# =============================================================================
#  Tooling for adversary emulation against the lab, and only against the lab.
#  Everything installed here is standard, publicly documented offensive-security
#  software used the way a red team or a purple-team exercise uses it: to
#  generate telemetry that the detections in this repo are then measured against.
#
#  This box has no route off the host-only network by design.
# =============================================================================
set -euo pipefail

log()  { printf '\033[0;36m[%(%H:%M:%S)T] >>> %s\033[0m\n' -1 "$1"; }
ok()   { printf '\033[0;32m[%(%H:%M:%S)T]  OK  %s\033[0m\n' -1 "$1"; }
warn() { printf '\033[0;33m[%(%H:%M:%S)T]  !!  %s\033[0m\n' -1 "$1"; }

export DEBIAN_FRONTEND=noninteractive

log "Updating package lists"
apt-get update -qq

# -----------------------------------------------------------------------------
# Core tooling
# -----------------------------------------------------------------------------
log "Installing core tooling"
apt-get install -y -qq \
    python3-pip python3-venv git curl jq \
    ldap-utils dnsutils netcat-openbsd nmap \
    krb5-user smbclient >/dev/null
ok "core tooling installed"

# -----------------------------------------------------------------------------
# Impacket — the reference implementation for the AD techniques this lab
# emulates (Kerberoasting, AS-REP roasting, DCSync, PsExec-style execution).
# Each one maps to a detection in detections/sigma/windows/.
# -----------------------------------------------------------------------------
log "Installing Impacket"
pip3 install --quiet --break-system-packages impacket 2>/dev/null \
  || pip3 install --quiet impacket
ok "Impacket installed"

# -----------------------------------------------------------------------------
# CrackMapExec / NetExec — lateral movement and credential validation at scale.
# -----------------------------------------------------------------------------
log "Installing NetExec"
pip3 install --quiet --break-system-packages netexec 2>/dev/null \
  || warn "NetExec install failed — not fatal, Impacket covers the same ground"

# -----------------------------------------------------------------------------
# MITRE Caldera — automated adversary emulation with an ATT&CK-mapped planner.
# Optional: heavy, and the Atomic Red Team runner on ws01 covers most scenarios.
# Enable by setting INSTALL_CALDERA=1.
# -----------------------------------------------------------------------------
if [ "${INSTALL_CALDERA:-0}" = "1" ]; then
  log "Installing MITRE Caldera"
  cd /opt
  git clone --depth 1 --recursive https://github.com/mitre/caldera.git 2>/dev/null || true
  cd caldera && pip3 install --quiet -r requirements.txt --break-system-packages 2>/dev/null || true
  ok "Caldera at /opt/caldera — start with: python3 server.py --insecure"
fi

# -----------------------------------------------------------------------------
# Lab context — so the scenario scripts do not hard-code addresses.
# -----------------------------------------------------------------------------
cat > /etc/lab-env <<EOF
LAB_DOMAIN=${LAB_DOMAIN:-nexus.lab}
LAB_NETBIOS=${LAB_NETBIOS:-NEXUS}
LAB_DC_IP=${LAB_DC_IP:-10.13.37.10}
LAB_SIEM_IP=${LAB_SIEM_IP:-10.13.37.30}
LAB_WS_IP=10.13.37.20
EOF
ok "lab context written to /etc/lab-env"

# Kerberos client config, so ticket-based techniques work without flags.
cat > /etc/krb5.conf <<EOF
[libdefaults]
    default_realm = $(echo "${LAB_DOMAIN:-nexus.lab}" | tr '[:lower:]' '[:upper:]')
    dns_lookup_realm = false
    dns_lookup_kdc = true

[realms]
    $(echo "${LAB_DOMAIN:-nexus.lab}" | tr '[:lower:]' '[:upper:]') = {
        kdc = ${LAB_DC_IP:-10.13.37.10}
        admin_server = ${LAB_DC_IP:-10.13.37.10}
    }

[domain_realm]
    .${LAB_DOMAIN:-nexus.lab} = $(echo "${LAB_DOMAIN:-nexus.lab}" | tr '[:lower:]' '[:upper:]')
    ${LAB_DOMAIN:-nexus.lab} = $(echo "${LAB_DOMAIN:-nexus.lab}" | tr '[:lower:]' '[:upper:]')
EOF
ok "krb5.conf configured for the lab realm"

# Point DNS at the DC so SRV lookups resolve.
echo "nameserver ${LAB_DC_IP:-10.13.37.10}" > /etc/resolv.conf 2>/dev/null || true

echo
echo "==============================================================="
echo "  Attacker box ready."
echo "  Lab context : /etc/lab-env"
echo "  Scenarios   : attack/scenarios/  (run from the host)"
echo "  Scope       : 10.13.37.0/24 only. This network is not routable."
echo "==============================================================="

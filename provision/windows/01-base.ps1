<#
.SYNOPSIS
    Stage 1 — baseline configuration for every Windows machine in the lab.
.DESCRIPTION
    Sets hostname, points DNS at the domain controller, opens the host-only
    subnet on the firewall, and enlarges the event logs so a full attack
    scenario does not roll off the Security log before you can query it.

    Everything here is idempotent: re-running `vagrant provision` is safe.
#>

. "$PSScriptRoot\_lib.ps1"

$Domain   = $env:LAB_DOMAIN
$Hostname = $env:LAB_HOSTNAME
$DcIp     = $env:LAB_DC_IP
$Role     = $env:LAB_ROLE

Write-Step "Baseline configuration — host=$Hostname role=$Role domain=$Domain"
Initialize-LabDirs

# -----------------------------------------------------------------------------
# Hostname
# -----------------------------------------------------------------------------
if ($env:COMPUTERNAME -ne $Hostname.ToUpper()) {
    Write-Step "Renaming $($env:COMPUTERNAME) -> $Hostname"
    Rename-Computer -NewName $Hostname -Force -ErrorAction Stop
    Write-Ok "rename queued (applies on next reboot)"
} else {
    Write-Ok "hostname already $Hostname"
}

# -----------------------------------------------------------------------------
# DNS — the workstation must resolve the domain via the DC, or the domain join
# in stage 20 fails with a misleading "domain not found".
# The host-only adapter is the one carrying our 10.13.37.0/24 address.
# -----------------------------------------------------------------------------
if ($Role -ne 'domain_controller') {
    $labNic = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
              Where-Object { $_.IPAddress -like '10.13.37.*' } |
              Select-Object -First 1

    if ($labNic) {
        Set-DnsClientServerAddress -InterfaceIndex $labNic.InterfaceIndex -ServerAddresses $DcIp
        Write-Ok "DNS on ifIndex $($labNic.InterfaceIndex) -> $DcIp"
    } else {
        Write-Warn "no 10.13.37.x adapter found yet — DNS will be set during domain join"
    }
}

# -----------------------------------------------------------------------------
# Firewall
# -----------------------------------------------------------------------------
# The lab subnet is fully open between machines. This is deliberate: we are
# studying *detection*, not prevention, and a blocked lateral-movement attempt
# generates no interesting telemetry. The host-only network is not routable, so
# this never touches the real LAN.
# -----------------------------------------------------------------------------
Write-Step "Opening host-only subnet on the firewall"
$ruleName = 'LAB-Allow-HostOnly-Subnet'
Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $ruleName `
    -Direction Inbound -Action Allow -Profile Any `
    -RemoteAddress '10.13.37.0/24' | Out-Null
Write-Ok "firewall: 10.13.37.0/24 allowed inbound"

# ICMP, so the scenario scripts can wait for a host to come back after reboot.
Remove-NetFirewallRule -DisplayName 'LAB-Allow-ICMP' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'LAB-Allow-ICMP' `
    -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Action Allow -Profile Any | Out-Null

# -----------------------------------------------------------------------------
# Event log capacity
# -----------------------------------------------------------------------------
# Default Security log is 20 MB. A single Atomic Red Team run with command-line
# auditing on can generate that in minutes, silently discarding the evidence you
# came for. This is the most common reason a home lab "has no logs".
# -----------------------------------------------------------------------------
Write-Step "Enlarging event logs"
Set-EventLogSize -LogName 'Security'                                   -MaxSizeMB 1024
Set-EventLogSize -LogName 'System'                                     -MaxSizeMB 256
Set-EventLogSize -LogName 'Application'                                -MaxSizeMB 256
Set-EventLogSize -LogName 'Microsoft-Windows-PowerShell/Operational'   -MaxSizeMB 512
Set-EventLogSize -LogName 'Microsoft-Windows-TaskScheduler/Operational' -MaxSizeMB 128

# TaskScheduler operational log is disabled by default on client SKUs.
& wevtutil.exe sl 'Microsoft-Windows-TaskScheduler/Operational' /e:true 2>&1 | Out-Null

# -----------------------------------------------------------------------------
# Time sync — skewed clocks make correlation across machines impossible and
# will quietly break Kerberos (5-minute tolerance).
# -----------------------------------------------------------------------------
Write-Step "Configuring time synchronisation"
if ($Role -eq 'domain_controller') {
    & w32tm.exe /config /manualpeerlist:'pool.ntp.org' /syncfromflags:manual /reliable:yes /update 2>&1 | Out-Null
} else {
    & w32tm.exe /config /syncfromflags:domhier /update 2>&1 | Out-Null
}
Restart-Service w32time -ErrorAction SilentlyContinue

Write-Ok "Stage 1 complete on $Hostname"

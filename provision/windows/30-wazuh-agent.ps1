<#
.SYNOPSIS
    Stage 30 — install the Wazuh agent and ship the channels the rules need.
.DESCRIPTION
    Installs the agent, enrols it against the SIEM, and rewrites ossec.conf so
    that the Windows event channels this repo's detections depend on are
    actually forwarded. The default agent config ships Security/System/Application
    only — Sysmon and PowerShell Operational are NOT included, which is why so
    many labs collect Sysmon locally and then wonder why nothing reaches the SIEM.
#>

. "$PSScriptRoot\_lib.ps1"

$SiemIp   = $env:LAB_SIEM_IP
$Hostname = $env:LAB_HOSTNAME
$WazuhVersion = '4.9.0'
$agentMsi = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion-1.msi"

Initialize-LabDirs
$msiPath = "C:\LabTools\wazuh-agent.msi"

$installed = Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
if (-not $installed) {
    Write-Step "Downloading Wazuh agent $WazuhVersion"
    Get-RemoteFile -Uri $agentMsi -OutFile $msiPath | Out-Null

    Write-Step "Installing and enrolling against $SiemIp"
    # WAZUH_REGISTRATION_SERVER triggers automatic enrolment over port 1515,
    # so no manual agent key exchange is needed.
    $args = @(
        '/i', "`"$msiPath`"", '/q',
        "WAZUH_MANAGER=$SiemIp",
        "WAZUH_REGISTRATION_SERVER=$SiemIp",
        "WAZUH_AGENT_NAME=$Hostname",
        "WAZUH_AGENT_GROUP=windows"
    )
    $p = Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru -NoNewWindow
    if ($p.ExitCode -ne 0) { throw "Wazuh agent install failed with exit code $($p.ExitCode)" }
    Write-Ok "agent installed"
} else {
    Write-Ok "Wazuh agent already present"
}

# -----------------------------------------------------------------------------
# Configure the log channels.
# -----------------------------------------------------------------------------
$ossecConf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
if (-not (Test-Path $ossecConf)) { throw "ossec.conf not found at $ossecConf" }

Write-Step "Configuring forwarded event channels"

# eventchannel format (not eventlog) is required for the modern XML-based
# channels — Sysmon and PowerShell/Operational will not work with 'eventlog'.
$localfileBlocks = @'
  <!-- ===== detection-lab-as-code: channels required by detections/sigma ===== -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <!-- Drops the highest-volume, lowest-value events at the agent so the
         indexer is not overwhelmed. 5145 is kept: it is how lateral movement
         over admin shares is detected. -->
    <query>Event/System[EventID != 5156 and EventID != 5157 and EventID != 4658 and EventID != 4690]</query>
  </localfile>

  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- The single most important channel in this lab. -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- 4104 script block logging — feeds the obfuscation detections. -->
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Windows PowerShell</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-TaskScheduler/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <!-- ===== end detection-lab-as-code block ===== -->
'@

$conf = Get-Content $ossecConf -Raw

# Idempotent: strip any previous block we wrote before inserting the current one.
$conf = [regex]::Replace(
    $conf,
    '(?s)\s*<!-- =+ detection-lab-as-code.*?end detection-lab-as-code block =+ -->',
    ''
)

# Remove the stock localfile entries so channels are not forwarded twice.
$conf = [regex]::Replace($conf, '(?s)<localfile>.*?</localfile>\s*', '')

# Insert before the closing </ossec_config>.
$conf = $conf -replace '</ossec_config>', "$localfileBlocks`r`n</ossec_config>"

Set-Content -Path $ossecConf -Value $conf -Encoding UTF8
Write-Ok "ossec.conf updated with 8 event channels"

# -----------------------------------------------------------------------------
# Restart and verify connectivity to the manager.
# -----------------------------------------------------------------------------
Write-Step "Restarting the agent"
Restart-Service -Name 'WazuhSvc' -Force
Start-Sleep -Seconds 20

$svc = Get-Service -Name 'WazuhSvc'
if ($svc.Status -ne 'Running') { throw "WazuhSvc is $($svc.Status) after restart" }

# ossec.log records the enrolment result; surface it rather than assuming success.
$log = 'C:\Program Files (x86)\ossec-agent\ossec.log'
if (Test-Path $log) {
    $tail = Get-Content $log -Tail 25
    if ($tail -match 'Connected to the server') {
        Write-Ok "agent connected to manager at $SiemIp"
    } else {
        Write-Warn "no 'Connected to the server' line yet. Last log lines:"
        $tail | ForEach-Object { Write-Host "    $_" }
        Write-Warn "if this persists, check that siem is up: vagrant status siem"
    }
}

Write-Ok "Stage 30 complete"

<#
.SYNOPSIS
    Stage 3 — install Sysmon with a curated configuration.
.DESCRIPTION
    Native Windows auditing tells you a process started. Sysmon tells you which
    process started it, hashed, with its command line, its parent, the network
    connections it opened and the DLLs it loaded. Most rules in this repo are
    written against Sysmon because the native equivalents either do not exist
    (image load, named pipes) or cannot be correlated (no ProcessGuid).

    Sysmon event IDs this lab relies on:
      1  Process creation      — richer 4688, includes hashes and ParentImage
      3  Network connection    — C2 beacon detection
      7  Image loaded          — unsigned DLL / DLL side-loading
      8  CreateRemoteThread    — process injection
      10 ProcessAccess         — LSASS access, i.e. credential dumping
      11 FileCreate            — dropper artefacts
      12/13/14 Registry        — persistence in Run keys
      15 FileCreateStreamHash  — mark-of-the-web / ADS abuse
      22 DnsQuery              — DNS-based C2 and exfil
      25 ProcessTampering      — process hollowing
#>

. "$PSScriptRoot\_lib.ps1"

Initialize-LabDirs
$binDir = Join-Path $PSScriptRoot 'bin'
if (-not (Test-Path $binDir)) { New-Item -ItemType Directory -Path $binDir -Force | Out-Null }

$zipPath    = Join-Path $binDir 'Sysmon.zip'
$extractDir = Join-Path $binDir 'Sysmon'
$configPath = Join-Path $binDir 'sysmonconfig.xml'

# -----------------------------------------------------------------------------
# Already installed? Then just refresh the config — much faster on re-provision.
# -----------------------------------------------------------------------------
$existing = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq 'Running' } | Select-Object -First 1

# -----------------------------------------------------------------------------
# Fetch Sysmon
# -----------------------------------------------------------------------------
Write-Step "Fetching Sysmon from Microsoft"
Get-RemoteFile -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zipPath | Out-Null

if (-not (Test-Path (Join-Path $extractDir 'Sysmon64.exe'))) {
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
}
$sysmonExe = Join-Path $extractDir 'Sysmon64.exe'
if (-not (Test-Path $sysmonExe)) { $sysmonExe = Join-Path $extractDir 'Sysmon.exe' }
if (-not (Test-Path $sysmonExe)) { throw "Sysmon binary not found after extraction" }

# -----------------------------------------------------------------------------
# Fetch the configuration
# -----------------------------------------------------------------------------
# SwiftOnSecurity's config is the community baseline: aggressive filtering, low
# volume, high signal. It is intentionally conservative — it excludes a lot of
# normal activity. When a rule in this repo needs an event that the baseline
# filters out, the override is added to sysmon-overrides.xml with a comment
# explaining which rule needs it.
# -----------------------------------------------------------------------------
Write-Step "Fetching Sysmon configuration"
$configUrl = if ($env:SYSMON_CONFIG_URL) { $env:SYSMON_CONFIG_URL } else {
    'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml'
}

try {
    Get-RemoteFile -Uri $configUrl -OutFile $configPath | Out-Null
} catch {
    Write-Warn "could not fetch remote config, falling back to the bundled minimal config"
    Copy-Item -Path (Join-Path $PSScriptRoot 'sysmon-fallback.xml') -Destination $configPath -Force
}

# Sanity-check the XML before handing it to Sysmon — a truncated download
# produces a service that installs but silently logs nothing.
try {
    [xml]$null = Get-Content $configPath -Raw
    Write-Ok "Sysmon config parsed cleanly"
} catch {
    Write-Warn "config XML is invalid, using bundled fallback"
    Copy-Item -Path (Join-Path $PSScriptRoot 'sysmon-fallback.xml') -Destination $configPath -Force
}

# -----------------------------------------------------------------------------
# Install or reconfigure
# -----------------------------------------------------------------------------
if ($existing) {
    Write-Step "Sysmon already running — applying updated configuration"
    & $sysmonExe -c $configPath 2>&1 | Out-String | Write-Host
} else {
    Write-Step "Installing Sysmon"
    # -accepteula is required for unattended install; -i installs with config.
    & $sysmonExe -accepteula -i $configPath 2>&1 | Out-String | Write-Host
}

Start-Sleep -Seconds 5

# -----------------------------------------------------------------------------
# Verify — and make the failure loud. A lab that silently has no Sysmon data is
# worse than no lab, because you will write rules that can never fire.
# -----------------------------------------------------------------------------
$svc = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue |
       Where-Object { $_.Status -eq 'Running' } | Select-Object -First 1

if (-not $svc) { throw "Sysmon service is not running after installation" }
Write-Ok "Sysmon service running: $($svc.Name)"

Set-EventLogSize -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxSizeMB 1024

# Generate one known-good event and read it back, proving the pipeline end to end.
Write-Step "Smoke-testing the Sysmon event pipeline"
Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', 'echo sysmon-smoke-test' -WindowStyle Hidden -Wait
Start-Sleep -Seconds 3

$evt = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1
} -MaxEvents 5 -ErrorAction SilentlyContinue

if ($evt) {
    Write-Ok "Sysmon Event ID 1 confirmed — $($evt.Count) recent process-creation events"
} else {
    Write-Warn "no Sysmon Event ID 1 found; check the configuration filters"
}

Write-Ok "Stage 3 complete"

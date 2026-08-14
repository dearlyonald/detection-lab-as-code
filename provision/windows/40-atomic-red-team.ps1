<#
.SYNOPSIS
    Stage 40 — install Invoke-AtomicRedTeam and the atomics library.
.DESCRIPTION
    Atomic Red Team is the execution engine for this lab's adversary emulation.
    Each "atomic" is a small, documented, reversible test mapped to exactly one
    MITRE ATT&CK technique, which is what makes detection coverage measurable
    rather than anecdotal.

    Installed but NOT executed here. Execution is driven from attack/run-atomic.ps1
    so that every run is recorded with a timestamp and can be correlated against
    the SIEM afterwards.
#>

. "$PSScriptRoot\_lib.ps1"

Initialize-LabDirs

if (Get-Module -ListAvailable -Name 'invoke-atomicredteam') {
    Write-Ok "Invoke-AtomicRedTeam already installed"
} else {
    Write-Step "Installing Invoke-AtomicRedTeam and the atomics library"

    # NuGet provider + PSGallery trust, both of which prompt interactively by
    # default and would otherwise hang the provisioner forever.
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted

    try {
        # -getAtomics downloads the atomics/ folder (the actual test definitions).
        Install-Module -Name invoke-atomicredteam -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
        Write-Ok "module installed"
    } catch {
        Write-Warn "PSGallery install failed, falling back to the git-based installer"
        IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
        Install-AtomicRedTeam -getAtomics -Force
    }
}

# -----------------------------------------------------------------------------
# Fetch the atomics library if the module install did not bring it.
# -----------------------------------------------------------------------------
$atomicsPath = 'C:\AtomicRedTeam\atomics'
if (-not (Test-Path $atomicsPath)) {
    Write-Step "Downloading the atomics library"
    New-Item -ItemType Directory -Path 'C:\AtomicRedTeam' -Force | Out-Null
    $zip = 'C:\LabTools\atomics.zip'
    Get-RemoteFile -Uri 'https://github.com/redcanaryco/atomic-red-team/archive/refs/heads/master.zip' -OutFile $zip | Out-Null
    Expand-Archive -Path $zip -DestinationPath 'C:\LabTools\atomics-extract' -Force
    Move-Item -Path 'C:\LabTools\atomics-extract\atomic-red-team-master\atomics' -Destination $atomicsPath -Force
    Remove-Item 'C:\LabTools\atomics-extract' -Recurse -Force -ErrorAction SilentlyContinue
}

if (Test-Path $atomicsPath) {
    $count = (Get-ChildItem $atomicsPath -Directory -Filter 'T*').Count
    Write-Ok "atomics library ready: $count techniques available at $atomicsPath"
} else {
    Write-Warn "atomics library not present — attack/run-atomic.ps1 will not work"
}

# -----------------------------------------------------------------------------
# Copy the lab's own attack tooling onto the box.
# -----------------------------------------------------------------------------
# Vagrant's shell provisioner uploads only the script itself, so the runner and
# the scenario definitions are fetched from the synced copy staged by Vagrant
# under C:\vagrant when available, or left to be pushed manually.
Write-Ok "Stage 40 complete — run attacks with:  attack\run-atomic.ps1 -Scenario 01-initial-access"

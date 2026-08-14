<#
.SYNOPSIS
    Checks and installs everything the host needs before `vagrant up`.
.DESCRIPTION
    Verifies hardware, virtualisation support and conflicting hypervisors, then
    installs Vagrant, the vagrant-reload plugin and the Python dependencies.

    Run it before the first build. It is safe to re-run.

.PARAMETER CheckOnly
    Report status without installing anything.
#>

[CmdletBinding()]
param([switch]$CheckOnly)

$ErrorActionPreference = 'Stop'
$issues = @()
$repoRoot = Split-Path $PSScriptRoot -Parent

function Test-Item {
    param([string]$Name, [scriptblock]$Check, [string]$Expected, [switch]$Fatal)
    try { $value = & $Check } catch { $value = $null }
    $ok = [bool]$value
    $mark = if ($ok) { 'OK  ' } else { if ($Fatal) { 'FAIL' } else { 'WARN' } }
    $colour = if ($ok) { 'Green' } elseif ($Fatal) { 'Red' } else { 'Yellow' }
    Write-Host ("  [{0}] {1,-34} {2}" -f $mark, $Name, $value) -ForegroundColor $colour
    if (-not $ok) { $script:issues += "$Name — expected $Expected" }
    return $ok
}

Write-Host "`n=== detection-lab-as-code — host prerequisites ===`n" -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# Hardware
# -----------------------------------------------------------------------------
Write-Host "Hardware" -ForegroundColor Cyan
$cs = Get-CimInstance Win32_ComputerSystem
$ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)

Test-Item -Name 'RAM (>= 16 GB)' -Expected 'at least 16 GB' -Fatal -Check {
    if ($ramGB -ge 16) { "$ramGB GB" }
} | Out-Null

Test-Item -Name 'Logical processors (>= 4)' -Expected '4 or more' -Check {
    if ($cs.NumberOfLogicalProcessors -ge 4) { "$($cs.NumberOfLogicalProcessors)" }
} | Out-Null

# VMs are large; put them on the roomiest drive.
$freeGB = (Get-PSDrive -PSProvider FileSystem |
           Where-Object { $_.Free } |
           Sort-Object Free -Descending |
           Select-Object -First 1)
Test-Item -Name 'Free disk (>= 60 GB)' -Expected '60 GB free somewhere' -Fatal -Check {
    if ($freeGB.Free / 1GB -ge 60) { "$([math]::Round($freeGB.Free/1GB,1)) GB on $($freeGB.Name):" }
} | Out-Null

Test-Item -Name 'Virtualisation in firmware' -Expected 'enabled in BIOS/UEFI' -Fatal -Check {
    if ((Get-CimInstance Win32_Processor).VirtualizationFirmwareEnabled) { 'enabled' }
} | Out-Null

# -----------------------------------------------------------------------------
# Hypervisor conflicts
# -----------------------------------------------------------------------------
# VirtualBox and Hyper-V both want exclusive access to VT-x. With Hyper-V active
# VirtualBox falls back to a slow emulation layer and nested paging breaks, which
# shows up much later as VMs that boot but crawl.
# -----------------------------------------------------------------------------
Write-Host "`nHypervisor" -ForegroundColor Cyan
$hyperV = $cs.HypervisorPresent
if ($hyperV) {
    Write-Host "  [WARN] Hyper-V is active — VirtualBox will run degraded" -ForegroundColor Yellow
    Write-Host "         Disable it and reboot:" -ForegroundColor DarkGray
    Write-Host "           bcdedit /set hypervisorlaunchtype off" -ForegroundColor DarkGray
    Write-Host "           Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All" -ForegroundColor DarkGray
    $issues += "Hyper-V active — disable for full VirtualBox performance"
} else {
    Write-Host "  [OK  ] Hyper-V not active" -ForegroundColor Green
}

$vboxManage = "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe"
Test-Item -Name 'VirtualBox' -Expected 'VirtualBox 7.x installed' -Fatal -Check {
    if (Test-Path $vboxManage) { & $vboxManage --version }
} | Out-Null

# -----------------------------------------------------------------------------
# Tooling
# -----------------------------------------------------------------------------
Write-Host "`nTooling" -ForegroundColor Cyan
$hasVagrant = Test-Item -Name 'Vagrant' -Expected 'Vagrant 2.4+' -Check {
    (Get-Command vagrant -ErrorAction SilentlyContinue) -and ((vagrant --version) -replace 'Vagrant ', '')
}
$hasPython = Test-Item -Name 'Python' -Expected 'Python 3.10+' -Fatal -Check {
    (Get-Command python -ErrorAction SilentlyContinue) -and (python --version)
}
Test-Item -Name 'Git' -Expected 'git in PATH' -Check {
    (Get-Command git -ErrorAction SilentlyContinue) -and (git --version)
} | Out-Null

if ($CheckOnly) {
    Write-Host "`n--- check only, nothing installed ---`n" -ForegroundColor DarkGray
    if ($issues) { $issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow } }
    return
}

# -----------------------------------------------------------------------------
# Install what is missing
# -----------------------------------------------------------------------------
if (-not $hasVagrant) {
    Write-Host "`nInstalling Vagrant" -ForegroundColor Cyan
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id Hashicorp.Vagrant -e --accept-source-agreements --accept-package-agreements
        # winget updates PATH for new shells only.
        $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                    [Environment]::GetEnvironmentVariable('Path', 'User')
    } else {
        Write-Host "  winget unavailable — download Vagrant manually:" -ForegroundColor Yellow
        Write-Host "    https://developer.hashicorp.com/vagrant/install" -ForegroundColor Yellow
    }
}

if (Get-Command vagrant -ErrorAction SilentlyContinue) {
    # vagrant-reload is required: promoting a DC and joining a domain each need
    # a reboot in the middle of provisioning.
    $plugins = vagrant plugin list 2>&1 | Out-String
    if ($plugins -notmatch 'vagrant-reload') {
        Write-Host "`nInstalling the vagrant-reload plugin" -ForegroundColor Cyan
        vagrant plugin install vagrant-reload
    } else {
        Write-Host "`n  [OK  ] vagrant-reload plugin present" -ForegroundColor Green
    }
}

if ($hasPython) {
    Write-Host "`nInstalling Python dependencies" -ForegroundColor Cyan
    python -m pip install --quiet --upgrade pip
    python -m pip install --quiet -r (Join-Path $repoRoot 'requirements.txt')
    Write-Host "  [OK  ] requirements.txt installed" -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# Move VirtualBox VM storage to the roomiest drive.
# -----------------------------------------------------------------------------
if (Test-Path $vboxManage) {
    $target = "$($freeGB.Name):\SecurityProjects\.vms"
    $current = (& $vboxManage list systemproperties | Select-String 'Default machine folder') -replace '.*:\s+', ''
    if ($current -notlike "*$($freeGB.Name):*") {
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        & $vboxManage setproperty machinefolder $target
        Write-Host "`n  [OK  ] VirtualBox VM storage -> $target" -ForegroundColor Green
    }
}

Write-Host "`n=================================================================" -ForegroundColor Cyan
if ($issues) {
    Write-Host "  Outstanding items:" -ForegroundColor Yellow
    $issues | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
} else {
    Write-Host "  All prerequisites satisfied." -ForegroundColor Green
}
Write-Host "`n  Next:  python tools\validate_sigma.py" -ForegroundColor Cyan
Write-Host "         `$env:LAB_PROFILE = 'standard'; vagrant up siem" -ForegroundColor Cyan
Write-Host "=================================================================`n" -ForegroundColor Cyan

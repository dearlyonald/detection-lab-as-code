<#
.SYNOPSIS
    Shared helpers for every Windows provisioning script.
.DESCRIPTION
    Dot-sourced by the numbered scripts. Keeps logging, retry and idempotency
    logic in one place so the provisioners stay readable.
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # download progress bars are 10x slower over WinRM

# TLS 1.2 — Server 2019/2022 images still default to SSL3/TLS1.0 for
# Invoke-WebRequest, which makes every GitHub download fail.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:LabToolsDir = 'C:\LabTools'
$script:LabLogDir   = 'C:\LabTools\logs'

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ("[{0:HH:mm:ss}] >>> {1}" -f (Get-Date), $Message) -ForegroundColor Cyan
}

function Write-Ok {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ("[{0:HH:mm:ss}]  OK  {1}" -f (Get-Date), $Message) -ForegroundColor Green
}

function Write-Warn {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ("[{0:HH:mm:ss}]  !!  {1}" -f (Get-Date), $Message) -ForegroundColor Yellow
}

function Initialize-LabDirs {
    foreach ($d in @($script:LabToolsDir, $script:LabLogDir)) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
}

<#
    Downloads survive flaky NAT + GitHub rate limits far better with a retry.
    Returns the local path.
#>
function Get-RemoteFile {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$OutFile,
        [int]$Retries = 4
    )
    if (Test-Path $OutFile) {
        Write-Ok "cached: $(Split-Path $OutFile -Leaf)"
        return $OutFile
    }
    for ($i = 1; $i -le $Retries; $i++) {
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -TimeoutSec 300
            Write-Ok "downloaded: $(Split-Path $OutFile -Leaf)"
            return $OutFile
        } catch {
            Write-Warn "download attempt $i/$Retries failed: $($_.Exception.Message)"
            if ($i -eq $Retries) { throw }
            Start-Sleep -Seconds ($i * 10)
        }
    }
}

<#
    Idempotent registry write. Creates the key path when missing, which the
    PowerShell-logging keys always are on a fresh image.
#>
function Set-RegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('DWord','String','ExpandString','MultiString','QWord')]
        [string]$Type = 'DWord'
    )
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

<#
    auditpol by subcategory GUID rather than by display name.
    Display names are localised — on an Arabic or German Windows image the
    name-based call silently fails and you end up with a lab that produces no
    4688 events at all. GUIDs are stable across every locale.
#>
function Enable-AuditSubcategory {
    param(
        [Parameter(Mandatory)][string]$Guid,
        [Parameter(Mandatory)][string]$FriendlyName,
        [ValidateSet('enable','disable')][string]$Success = 'enable',
        [ValidateSet('enable','disable')][string]$Failure = 'enable'
    )
    $out = & auditpol.exe /set /subcategory:"$Guid" /success:$Success /failure:$Failure 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "auditpol failed for $FriendlyName ($Guid): $out"
    } else {
        Write-Ok "audit: $FriendlyName (success=$Success failure=$Failure)"
    }
}

function Test-IsDomainController {
    (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -in @(4, 5)
}

function Set-EventLogSize {
    param(
        [Parameter(Mandatory)][string]$LogName,
        [int]$MaxSizeMB = 512
    )
    try {
        & wevtutil.exe sl "$LogName" /ms:($MaxSizeMB * 1MB) 2>&1 | Out-Null
        Write-Ok "log size: $LogName -> ${MaxSizeMB}MB"
    } catch {
        Write-Warn "could not resize $LogName : $($_.Exception.Message)"
    }
}

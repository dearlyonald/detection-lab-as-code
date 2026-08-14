<#
.SYNOPSIS
    Push the validated rule set to the SIEM and reload it.
.DESCRIPTION
    The Vagrant synced folder is disabled on purpose — it is slow, and mounting
    the host filesystem inside a VM the lab deliberately attacks is a bad idea.
    Rules are therefore uploaded explicitly, which also means nothing reaches the
    SIEM without passing validation first.

    Refuses to deploy if `validate_sigma.py` fails. Shipping an untested rule to
    a SIEM is how alert fatigue starts.
#>

[CmdletBinding()]
param(
    [switch]$SkipValidation,
    [string]$Machine = 'siem'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
Push-Location $repoRoot

try {
    # -------------------------------------------------------------------------
    # Gate: no deployment without a green rule set.
    # -------------------------------------------------------------------------
    if (-not $SkipValidation) {
        Write-Host "`n>>> Validating rules before deployment" -ForegroundColor Cyan
        python tools\validate_sigma.py
        if ($LASTEXITCODE -ne 0) {
            throw "Rule validation failed — refusing to deploy. Fix the failures above, or re-run with -SkipValidation if you genuinely intend to ship a failing rule."
        }
    }

    # -------------------------------------------------------------------------
    # Is the SIEM actually running?
    # -------------------------------------------------------------------------
    $status = vagrant status $Machine 2>&1 | Out-String
    if ($status -notmatch 'running') {
        throw "$Machine is not running. Start it with:  vagrant up $Machine"
    }

    Write-Host "`n>>> Uploading rules and tooling to $Machine" -ForegroundColor Cyan
    vagrant upload detections\sigma /opt/detection-lab/sigma $Machine
    vagrant upload tools            /opt/detection-lab/tools $Machine
    Write-Host "    uploaded" -ForegroundColor Green

    Write-Host "`n>>> Converting and reloading" -ForegroundColor Cyan
    vagrant provision $Machine --provision-with decoders-rules

    Write-Host "`n-----------------------------------------------------------------"
    Write-Host "  Deployed. Verify a rule end to end with the Wazuh log tester:"
    Write-Host "    vagrant ssh $Machine -c 'sudo /var/ossec/bin/wazuh-logtest'"
    Write-Host "-----------------------------------------------------------------`n"
}
finally {
    Pop-Location
}

<#
.SYNOPSIS
    Runs an adversary emulation scenario against the lab and records exactly
    what was executed, so the results can be correlated against the SIEM.

.DESCRIPTION
    Wraps Invoke-AtomicRedTeam with the bookkeeping that turns "I ran some
    attacks" into "these 14 techniques executed at these timestamps, and 11 of
    them produced an alert".

    For every technique it records the start and end time, the exit status and
    the ATT&CK ID. tools/attack_coverage.py then joins that record against the
    Sigma rule set to produce a coverage report and an ATT&CK Navigator layer.

    SCOPE: this only ever runs against the host-only lab network defined in
    lab.yml. It refuses to run on a machine that is not part of the lab.

.PARAMETER Scenario
    Scenario file under attack/scenarios/ (without the .yml extension).

.PARAMETER CheckPrereqs
    Resolve prerequisites without executing anything.

.PARAMETER Cleanup
    Run the cleanup commands for the scenario instead of the attacks.

.EXAMPLE
    .\run-atomic.ps1 -Scenario 01-domain-compromise -WhatIf
    .\run-atomic.ps1 -Scenario 01-domain-compromise
    .\run-atomic.ps1 -Scenario 01-domain-compromise -Cleanup
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Scenario,
    [switch]$CheckPrereqs,
    [switch]$Cleanup,
    [int]$DelaySeconds = 20
)

$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# Safety interlock
# -----------------------------------------------------------------------------
# These tests intentionally create persistence, touch credential stores and drop
# files. Running them on a workstation that is not the disposable lab VM would
# be a genuine problem, so refuse unless the host is on the lab network.
# -----------------------------------------------------------------------------
$onLabNetwork = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -like '10.13.37.*' }

if (-not $onLabNetwork) {
    throw @"
REFUSING TO RUN.

This host has no 10.13.37.0/24 address, so it is not one of the lab VMs.
These atomics create persistence and touch credential material - they belong on
a disposable VM only.

Run this inside ws01:   vagrant ssh ws01     (or via the VirtualBox console)
"@
}

$resultsDir = Join-Path $PSScriptRoot 'results'
New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null

$scenarioPath = Join-Path $PSScriptRoot "scenarios\$Scenario.yml"
if (-not (Test-Path $scenarioPath)) {
    $available = (Get-ChildItem (Join-Path $PSScriptRoot 'scenarios') -Filter '*.yml' |
                  ForEach-Object { $_.BaseName }) -join ', '
    throw "Scenario '$Scenario' not found. Available: $available"
}

# -----------------------------------------------------------------------------
# Minimal YAML reader.
# -----------------------------------------------------------------------------
# powershell-yaml is not present on a fresh Windows image and installing it adds
# a network dependency to the attack path. The scenario schema is deliberately
# flat, so a purpose-built parser is more reliable here than a general one.
# -----------------------------------------------------------------------------
function Read-Scenario {
    param([string]$Path)

    $scenario = [ordered]@{ name = ''; description = ''; techniques = @() }
    $current = $null

    foreach ($line in Get-Content $Path) {
        if ($line -match '^\s*#' -or $line.Trim() -eq '') { continue }

        if ($line -match '^name:\s*(.+)$')        { $scenario.name = $Matches[1].Trim('"''') ; continue }
        if ($line -match '^description:\s*(.+)$') { $scenario.description = $Matches[1].Trim('"''') ; continue }

        if ($line -match '^\s*-\s+technique:\s*(\S+)') {
            if ($current) { $scenario.techniques += [pscustomobject]$current }
            $current = [ordered]@{ technique = $Matches[1]; test_numbers = @(); name = ''; stage = '' }
            continue
        }
        if ($current -and $line -match '^\s+test_numbers:\s*\[(.+)\]') {
            $current.test_numbers = $Matches[1] -split ',' | ForEach-Object { [int]$_.Trim() }
            continue
        }
        if ($current -and $line -match '^\s+name:\s*(.+)$')  { $current.name  = $Matches[1].Trim('"''') ; continue }
        if ($current -and $line -match '^\s+stage:\s*(.+)$') { $current.stage = $Matches[1].Trim('"''') ; continue }
    }
    if ($current) { $scenario.techniques += [pscustomobject]$current }
    return [pscustomobject]$scenario
}

$s = Read-Scenario -Path $scenarioPath

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  $($s.name)" -ForegroundColor Cyan
Write-Host "  $($s.description)" -ForegroundColor DarkGray
Write-Host "  $($s.techniques.Count) techniques  |  host $env:COMPUTERNAME" -ForegroundColor DarkGray
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

Import-Module invoke-atomicredteam -Force -ErrorAction Stop

$runId  = "{0}-{1}" -f $Scenario, (Get-Date -Format 'yyyyMMdd-HHmmss')
$record = [ordered]@{
    run_id      = $runId
    scenario    = $Scenario
    host        = $env:COMPUTERNAME
    started_utc = (Get-Date).ToUniversalTime().ToString('o')
    mode        = if ($Cleanup) { 'cleanup' } elseif ($CheckPrereqs) { 'prereq' } else { 'execute' }
    executions  = @()
}

foreach ($t in $s.techniques) {
    $label = if ($t.name) { $t.name } else { $t.technique }
    $tests = if ($t.test_numbers.Count) { $t.test_numbers } else { $null }

    Write-Host ("[{0}] {1}  {2}" -f $t.stage.PadRight(18), $t.technique.PadRight(12), $label) -ForegroundColor Yellow

    $exec = [ordered]@{
        technique    = $t.technique
        name         = $label
        stage        = $t.stage
        test_numbers = $t.test_numbers
        started_utc  = (Get-Date).ToUniversalTime().ToString('o')
        status       = 'skipped'
        error        = $null
    }

    if (-not $PSCmdlet.ShouldProcess($t.technique, $record.mode)) {
        $exec.status = 'whatif'
        $record.executions += [pscustomobject]$exec
        continue
    }

    try {
        $splat = @{ AtomicTechnique = $t.technique; TimeoutSeconds = 120 }
        if ($tests) { $splat.TestNumbers = $tests }

        if ($CheckPrereqs) {
            Invoke-AtomicTest @splat -CheckPrereqs
        } elseif ($Cleanup) {
            Invoke-AtomicTest @splat -Cleanup
        } else {
            # GetPrereqs first, so a test does not fail merely because a
            # supporting file was missing - that would understate coverage.
            Invoke-AtomicTest @splat -GetPrereqs -ErrorAction SilentlyContinue
            Invoke-AtomicTest @splat
        }
        $exec.status = 'completed'
        Write-Host "         done" -ForegroundColor Green
    } catch {
        $exec.status = 'error'
        $exec.error  = $_.Exception.Message
        # An individual technique failing must not abort the run - partial
        # coverage data is still useful, and hiding the failure would not be.
        Write-Host "         ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }

    $exec.ended_utc = (Get-Date).ToUniversalTime().ToString('o')
    $record.executions += [pscustomobject]$exec

    if (-not $Cleanup -and -not $CheckPrereqs) {
        # Spacing the techniques apart keeps them distinguishable in the SIEM
        # timeline instead of arriving as one indivisible burst.
        Start-Sleep -Seconds $DelaySeconds
    }
}

$record.ended_utc = (Get-Date).ToUniversalTime().ToString('o')

$outFile = Join-Path $resultsDir "$runId.json"
$record | ConvertTo-Json -Depth 6 | Set-Content -Path $outFile -Encoding UTF8

$completed = ($record.executions | Where-Object status -eq 'completed').Count
$errored   = ($record.executions | Where-Object status -eq 'error').Count

Write-Host ""
Write-Host "-----------------------------------------------------------------"
Write-Host ("  completed {0}   errored {1}   of {2} techniques" -f $completed, $errored, $s.techniques.Count)
Write-Host "  run record : $outFile"
Write-Host ""
Write-Host "  Next:"
Write-Host "    1. Give the SIEM 2-3 minutes to ingest."
Write-Host "    2. Copy the run record to the host and generate the report:"
Write-Host "         python tools/attack_coverage.py --run $runId"
Write-Host "-----------------------------------------------------------------"
Write-Host ""

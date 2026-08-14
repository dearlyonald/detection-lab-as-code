<#
.SYNOPSIS
    Stage 21 — make ws01 look like a real employee's machine.
.DESCRIPTION
    Detection rules tuned against a pristine VM are worthless: on a clean image
    literally any process creation looks anomalous. This script creates the
    ordinary background activity that a rule has to survive — user documents,
    browser-like traffic, scheduled tasks, mapped drives, installed software
    paths — plus the specific conditions the attack scenarios depend on.

    Everything created here stays inside the VM.
#>

. "$PSScriptRoot\_lib.ps1"

$Domain  = $env:LAB_DOMAIN
$NetBios = $env:LAB_NETBIOS

Initialize-LabDirs

# -----------------------------------------------------------------------------
# Local admin for the helpdesk group (documented weakness #4 from 11-dc-populate)
# -----------------------------------------------------------------------------
Write-Step "Granting $NetBios\NEXUS-IT local Administrators membership"
try {
    Add-LocalGroupMember -Group 'Administrators' -Member "$NetBios\NEXUS-IT" -ErrorAction Stop
    Write-Ok "NEXUS-IT is now local admin on $env:COMPUTERNAME"
} catch {
    Write-Warn "could not add NEXUS-IT to Administrators: $($_.Exception.Message)"
}

# -----------------------------------------------------------------------------
# Realistic user data — gives exfiltration and discovery techniques something
# to actually find, and gives file-access rules realistic paths to match on.
# -----------------------------------------------------------------------------
Write-Step "Seeding user documents"
$docRoot = 'C:\Users\Public\Documents\NEXUS'
$folders = @('Finance', 'HR', 'Engineering', 'Legal', 'Shared')
foreach ($f in $folders) { New-Item -ItemType Directory -Path (Join-Path $docRoot $f) -Force | Out-Null }

$docs = @(
    @{ Path="$docRoot\Finance\Q3-2026-Budget-Forecast.xlsx.txt";   Body="NEXUS Corp - Q3 2026 budget forecast. CONFIDENTIAL - Finance only." }
    @{ Path="$docRoot\Finance\Vendor-Payment-Schedule.csv";        Body="vendor,iban,amount`nAlpha Supplies,SA0380000000608010167519,142500`nBeta Logistics,SA4420000001234567891234,89300" }
    @{ Path="$docRoot\HR\Employee-Salary-Bands-2026.xlsx.txt";     Body="Grade,Min,Max`nG7,18000,24000`nG8,25000,33000" }
    @{ Path="$docRoot\Engineering\infra-credentials-OLD.txt";      Body="# deprecated - migrated to vault 2025`njenkins_admin / Bu1ldSrv#2024`ngitlab_runner / R#nn3r2024!" }
    @{ Path="$docRoot\Legal\Merger-Discussion-NDA.docx.txt";       Body="Draft NDA - Project Falcon. Do not distribute." }
    @{ Path="$docRoot\Shared\IT-Onboarding-Checklist.txt";         Body="1. Create AD account`n2. Map S: drive`n3. Install VPN client" }
)
foreach ($d in $docs) { Set-Content -Path $d.Path -Value $d.Body -Encoding UTF8 }
Write-Ok "$($docs.Count) decoy documents created under $docRoot"

# The credentials in these files are fictional strings for a disconnected lab.
# They exist so that credential-harvesting techniques (T1552.001 Credentials In
# Files) have something to hit and so the rule that watches for bulk reads of
# these paths has a realistic target.

# -----------------------------------------------------------------------------
# Benign scheduled tasks — the false-positive pressure that persistence rules
# have to survive. Without these, "a scheduled task was created" is a perfect
# detection, which is exactly the illusion a clean lab creates.
# -----------------------------------------------------------------------------
Write-Step "Creating benign scheduled tasks (false-positive pressure)"
$benignTasks = @(
    @{ Name='NEXUS-DiskCleanup';   Cmd='cleanmgr.exe';  Args='/sagerun:1';                 Time='03:00' }
    @{ Name='NEXUS-InventorySync'; Cmd='powershell.exe';Args='-NoProfile -Command Get-ComputerInfo | Out-Null'; Time='04:30' }
    @{ Name='NEXUS-LogRotate';     Cmd='cmd.exe';       Args='/c forfiles /p C:\LabTools\logs /d -7 /c "cmd /c del @file"'; Time='02:15' }
)
foreach ($t in $benignTasks) {
    if (Get-ScheduledTask -TaskName $t.Name -ErrorAction SilentlyContinue) { continue }
    $action  = New-ScheduledTaskAction -Execute $t.Cmd -Argument $t.Args
    $trigger = New-ScheduledTaskTrigger -Daily -At $t.Time
    Register-ScheduledTask -TaskName $t.Name -Action $action -Trigger $trigger `
        -User 'SYSTEM' -RunLevel Highest -Description 'NEXUS IT maintenance' | Out-Null
    Write-Ok "benign task: $($t.Name)"
}

# -----------------------------------------------------------------------------
# Benign Run-key entries — same reasoning, for the persistence rules.
# -----------------------------------------------------------------------------
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' `
                  -Name 'NexusVpnAgent' -Value 'C:\Program Files\NexusVPN\agent.exe --tray' -Type String
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' `
                  -Name 'NexusBackupTray' -Value 'C:\Program Files\NexusBackup\tray.exe' -Type String

# -----------------------------------------------------------------------------
# Baseline noise generator — a scheduled task that periodically runs ordinary
# admin commands. Rules are validated against 24h of this before being marked
# stable, which is how the false-positive counts in the README were measured.
# -----------------------------------------------------------------------------
Write-Step "Installing the background noise generator"
$noiseScript = @'
# Generates ordinary IT activity so detections are tested against realistic
# background traffic rather than a silent machine.
$ErrorActionPreference = 'SilentlyContinue'
$commands = @(
    { Get-Process | Select-Object -First 5 | Out-Null },
    { Get-Service | Where-Object Status -eq 'Running' | Out-Null },
    { ipconfig /all | Out-Null },
    { net share | Out-Null },
    { Get-ChildItem C:\Users -Recurse -Depth 2 | Out-Null },
    { Test-NetConnection -ComputerName dc01 -Port 445 -InformationLevel Quiet | Out-Null },
    { klist | Out-Null },
    { whoami /groups | Out-Null },
    { Get-WmiObject Win32_OperatingSystem | Out-Null },
    { tasklist /svc | Out-Null }
)
1..8 | ForEach-Object {
    & ($commands | Get-Random)
    Start-Sleep -Seconds (Get-Random -Minimum 20 -Maximum 90)
}
'@
$noisePath = 'C:\LabTools\generate-noise.ps1'
Set-Content -Path $noisePath -Value $noiseScript -Encoding UTF8

if (-not (Get-ScheduledTask -TaskName 'NEXUS-BaselineNoise' -ErrorAction SilentlyContinue)) {
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
               -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $noisePath"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
               -RepetitionInterval (New-TimeSpan -Minutes 20)
    Register-ScheduledTask -TaskName 'NEXUS-BaselineNoise' -Action $action -Trigger $trigger `
        -User 'SYSTEM' -RunLevel Highest -Description 'Detection lab baseline activity' | Out-Null
    Write-Ok "noise generator scheduled every 20 minutes"
}

Write-Ok "Stage 21 complete — ws01 now looks lived-in"

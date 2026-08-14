<#
.SYNOPSIS
    Stage 2 — Windows advanced audit policy and PowerShell logging.
.DESCRIPTION
    This is the single most important script in the lab.

    A default Windows install logs almost nothing an analyst can use: no process
    command lines, no PowerShell script blocks, no Kerberos service ticket
    requests. Half the "undetectable" attacks people write about are simply
    attacks against a host that was never configured to log.

    Every setting below is switched on because a specific detection in
    detections/sigma/ depends on it. The mapping is in the comment above each
    block — if you remove a setting, you break the named rules.

.NOTES
    Subcategories are set by GUID, not by display name. Display names are
    localised; GUIDs are not. See _lib.ps1 for the rationale.
#>

. "$PSScriptRoot\_lib.ps1"

Write-Step "Configuring advanced audit policy on $env:COMPUTERNAME"

# -----------------------------------------------------------------------------
# Force subcategory policy to override the legacy 9 top-level categories.
# Without this, a legacy GPO can silently reset everything we set below.
# -----------------------------------------------------------------------------
Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                  -Name 'SCENoApplyLegacyAuditPolicy' -Value 1

# -----------------------------------------------------------------------------
# DETAILED TRACKING
#   4688 Process Creation  — the backbone of nearly every rule in this repo.
#   Feeds: win_susp_lolbin_*, win_encoded_powershell, win_regsvr32_scriptlet
# -----------------------------------------------------------------------------
Enable-AuditSubcategory -Guid '{0CCE922B-69AE-11D9-BED3-505054503030}' -FriendlyName 'Process Creation'
Enable-AuditSubcategory -Guid '{0CCE922C-69AE-11D9-BED3-505054503030}' -FriendlyName 'Process Termination' -Failure disable

# -- Command line in 4688 --------------------------------------------------
# Without this one registry value, 4688 tells you "powershell.exe ran" and
# nothing else. With it, you get the full command line. This single setting is
# the difference between a useful SOC and a decorative one.
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
                  -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1
Write-Ok "4688 will include the full command line"

# -----------------------------------------------------------------------------
# LOGON / LOGOFF
#   4624 success, 4625 failure, 4648 explicit credentials, 4672 special privs
#   Feeds: win_bruteforce_then_success, win_runas_explicit_creds
# -----------------------------------------------------------------------------
Enable-AuditSubcategory -Guid '{0CCE9215-69AE-11D9-BED3-505054503030}' -FriendlyName 'Logon'
Enable-AuditSubcategory -Guid '{0CCE9216-69AE-11D9-BED3-505054503030}' -FriendlyName 'Logoff' -Failure disable
Enable-AuditSubcategory -Guid '{0CCE9217-69AE-11D9-BED3-505054503030}' -FriendlyName 'Account Lockout'
Enable-AuditSubcategory -Guid '{0CCE921B-69AE-11D9-BED3-505054503030}' -FriendlyName 'Special Logon'
Enable-AuditSubcategory -Guid '{0CCE921C-69AE-11D9-BED3-505054503030}' -FriendlyName 'Other Logon/Logoff Events'

# -----------------------------------------------------------------------------
# ACCOUNT LOGON  (evaluated on the DC)
#   4768 TGT request, 4769 service ticket, 4771 pre-auth failed
#   Feeds: win_kerberoasting_rc4_ticket  — 4769 with encryption type 0x17
#          win_asrep_roasting            — 4768 with pre-auth not required
# -----------------------------------------------------------------------------
Enable-AuditSubcategory -Guid '{0CCE9242-69AE-11D9-BED3-505054503030}' -FriendlyName 'Kerberos Authentication Service'
Enable-AuditSubcategory -Guid '{0CCE9240-69AE-11D9-BED3-505054503030}' -FriendlyName 'Kerberos Service Ticket Operations'
Enable-AuditSubcategory -Guid '{0CCE923F-69AE-11D9-BED3-505054503030}' -FriendlyName 'Credential Validation'

# -----------------------------------------------------------------------------
# ACCOUNT / GROUP MANAGEMENT
#   4720 user created, 4728/4732 added to privileged group, 4738 user changed
#   Feeds: win_new_admin_account_off_hours
# -----------------------------------------------------------------------------
Enable-AuditSubcategory -Guid '{0CCE9235-69AE-11D9-BED3-505054503030}' -FriendlyName 'User Account Management'
Enable-AuditSubcategory -Guid '{0CCE9236-69AE-11D9-BED3-505054503030}' -FriendlyName 'Computer Account Management'
Enable-AuditSubcategory -Guid '{0CCE9237-69AE-11D9-BED3-505054503030}' -FriendlyName 'Security Group Management'
Enable-AuditSubcategory -Guid '{0CCE923A-69AE-11D9-BED3-505054503030}' -FriendlyName 'Other Account Management Events'

# -----------------------------------------------------------------------------
# OBJECT ACCESS
#   4657 registry value modified — feeds win_persistence_run_key
#   5145 detailed file share    — feeds win_admin_share_access (lateral movement)
# -----------------------------------------------------------------------------
Enable-AuditSubcategory -Guid '{0CCE921E-69AE-11D9-BED3-505054503030}' -FriendlyName 'Registry'
Enable-AuditSubcategory -Guid '{0CCE9244-69AE-11D9-BED3-505054503030}' -FriendlyName 'Detailed File Share' -Failure disable
Enable-AuditSubcategory -Guid '{0CCE9224-69AE-11D9-BED3-505054503030}' -FriendlyName 'File Share'
Enable-AuditSubcategory -Guid '{0CCE9220-69AE-11D9-BED3-505054503030}' -FriendlyName 'SAM'

# -----------------------------------------------------------------------------
# PRIVILEGE USE
#   4673/4674 — noisy, but SeDebugPrivilege use is a strong credential-dumping
#   signal. Success only; failures here are pure noise.
# -----------------------------------------------------------------------------
Enable-AuditSubcategory -Guid '{0CCE9228-69AE-11D9-BED3-505054503030}' -FriendlyName 'Sensitive Privilege Use' -Failure disable

# -----------------------------------------------------------------------------
# POLICY CHANGE — catches an attacker turning the lights off (1102, 4719)
# -----------------------------------------------------------------------------
Enable-AuditSubcategory -Guid '{0CCE922F-69AE-11D9-BED3-505054503030}' -FriendlyName 'Audit Policy Change'
Enable-AuditSubcategory -Guid '{0CCE9230-69AE-11D9-BED3-505054503030}' -FriendlyName 'Authentication Policy Change'

# -----------------------------------------------------------------------------
# SYSTEM
#   7045 service installed (System log) is a classic lateral-movement artefact.
# -----------------------------------------------------------------------------
Enable-AuditSubcategory -Guid '{0CCE9211-69AE-11D9-BED3-505054503030}' -FriendlyName 'Security System Extension'
Enable-AuditSubcategory -Guid '{0CCE9212-69AE-11D9-BED3-505054503030}' -FriendlyName 'System Integrity'

# -----------------------------------------------------------------------------
# DS ACCESS — domain controller only. 4662 is how DCSync is caught.
#   Feeds: win_dcsync_replication_rights
# -----------------------------------------------------------------------------
if (Test-IsDomainController) {
    Write-Step "Domain controller detected — enabling Directory Service auditing"
    Enable-AuditSubcategory -Guid '{0CCE923B-69AE-11D9-BED3-505054503030}' -FriendlyName 'Directory Service Access'
    Enable-AuditSubcategory -Guid '{0CCE923C-69AE-11D9-BED3-505054503030}' -FriendlyName 'Directory Service Changes'
}

# =============================================================================
#  POWERSHELL LOGGING
# =============================================================================
# Script Block Logging (4104) records the *deobfuscated* script body after the
# engine has decoded it. An attacker can base64 and string-concatenate all they
# like — 4104 sees the final text. This is why the obfuscation rules in this
# repo key off 4104 and not off the 4688 command line alone.
# =============================================================================
Write-Step "Enabling PowerShell script block, module and transcription logging"

$psBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'

# -- Script block logging (Event ID 4104)
Set-RegistryValue -Path "$psBase\ScriptBlockLogging" -Name 'EnableScriptBlockLogging' -Value 1
# Invocation logging (4105/4106) is extremely noisy — deliberately left off.
Set-RegistryValue -Path "$psBase\ScriptBlockLogging" -Name 'EnableScriptBlockInvocationLogging' -Value 0

# -- Module logging (Event ID 4103)
Set-RegistryValue -Path "$psBase\ModuleLogging" -Name 'EnableModuleLogging' -Value 1
Set-RegistryValue -Path "$psBase\ModuleLogging\ModuleNames" -Name '*' -Value '*' -Type String

# -- Transcription — full session transcripts on disk, useful for the writeups
Set-RegistryValue -Path "$psBase\Transcription" -Name 'EnableTranscripting'    -Value 1
Set-RegistryValue -Path "$psBase\Transcription" -Name 'EnableInvocationHeader' -Value 1
Set-RegistryValue -Path "$psBase\Transcription" -Name 'OutputDirectory' -Value 'C:\LabTools\logs\pstranscripts' -Type String
New-Item -ItemType Directory -Path 'C:\LabTools\logs\pstranscripts' -Force | Out-Null

Write-Ok "PowerShell logging enabled (4103 / 4104 / transcripts)"

# -----------------------------------------------------------------------------
# Windows Defender: keep it ON, but in audit-friendly mode.
# -----------------------------------------------------------------------------
# Deliberate choice: Defender stays enabled. A lab where AV is disabled teaches
# you to detect attacks that would never have survived first contact in a real
# environment. Instead we exclude only the Atomic Red Team staging folder so the
# test payloads can execute, and we keep Defender's own detections as an extra
# telemetry source (Microsoft-Windows-Windows Defender/Operational, event 1116).
# -----------------------------------------------------------------------------
try {
    Add-MpPreference -ExclusionPath 'C:\AtomicRedTeam' -ErrorAction Stop
    Add-MpPreference -ExclusionPath 'C:\LabTools'      -ErrorAction Stop
    Write-Ok "Defender left ENABLED; excluded only C:\AtomicRedTeam and C:\LabTools"
} catch {
    Write-Warn "could not set Defender exclusions: $($_.Exception.Message)"
}

# -----------------------------------------------------------------------------
# Verification — prove the policy actually applied instead of assuming it did.
# -----------------------------------------------------------------------------
Write-Step "Verifying applied policy"
$applied = & auditpol.exe /get /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' 2>&1 | Out-String
if ($applied -match 'Success') {
    Write-Ok "Process Creation auditing confirmed active"
} else {
    Write-Warn "Process Creation auditing did NOT apply — detections will be blind:`n$applied"
}

$cmdLine = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
            -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction SilentlyContinue)
if ($cmdLine.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
    Write-Ok "4688 command-line capture confirmed"
} else {
    Write-Warn "4688 command-line capture NOT set"
}

& gpupdate.exe /force 2>&1 | Out-Null
Write-Ok "Stage 2 complete — telemetry baseline established"

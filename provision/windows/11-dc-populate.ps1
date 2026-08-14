<#
.SYNOPSIS
    Stage 11 — build a realistic Active Directory for NEXUS Corp.
.DESCRIPTION
    An empty domain produces boring, unrealistic telemetry: every event is
    Administrator, every logon is interactive, and detections tuned against it
    fall apart the moment they see real data.

    This script creates an org with departments, service accounts, nested group
    membership, and a small number of *deliberate, documented* misconfigurations
    that make specific attack paths reachable. Each weakness is annotated with
    the attack it enables and the detection that should catch it.

    THE WEAKNESSES ARE INTENTIONAL AND CONFINED TO A HOST-ONLY LAB VM.
#>

. "$PSScriptRoot\_lib.ps1"

Import-Module ActiveDirectory -ErrorAction Stop

$Domain  = $env:LAB_DOMAIN
$DN      = ($Domain -split '\.' | ForEach-Object { "DC=$_" }) -join ','
$DefaultPassword = ConvertTo-SecureString 'NexusLab#2026' -AsPlainText -Force

Write-Step "Populating Active Directory for $Domain ($DN)"

# -----------------------------------------------------------------------------
# Organisational units
# -----------------------------------------------------------------------------
$ous = @('Corp', 'Corp\Users', 'Corp\Workstations', 'Corp\Servers', 'Corp\ServiceAccounts', 'Corp\Admins')
foreach ($ou in $ous) {
    $parts  = $ou -split '\\'
    $name   = $parts[-1]
    $parent = if ($parts.Count -eq 1) { $DN } else {
        (($parts[0..($parts.Count - 2)] | ForEach-Object { "OU=$_" })[-1..0] -join ',') + ",$DN"
    }
    $path = "OU=$name,$parent"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$path'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $name -Path $parent -ProtectedFromAccidentalDeletion $false
        Write-Ok "OU created: $path"
    }
}

$usersOU  = "OU=Users,OU=Corp,$DN"
$svcOU    = "OU=ServiceAccounts,OU=Corp,$DN"
$adminsOU = "OU=Admins,OU=Corp,$DN"

function New-LabUser {
    param(
        [Parameter(Mandatory)][string]$Sam,
        [Parameter(Mandatory)][string]$Display,
        [Parameter(Mandatory)][string]$Path,
        [string]$Title = '',
        [string]$Department = '',
        [SecureString]$Password = $DefaultPassword
    )
    if (Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue) {
        Write-Ok "user exists: $Sam"; return
    }
    New-ADUser -Name $Display -SamAccountName $Sam `
        -UserPrincipalName "$Sam@$Domain" -DisplayName $Display `
        -Path $Path -Title $Title -Department $Department `
        -AccountPassword $Password -Enabled $true `
        -PasswordNeverExpires $true -ChangePasswordAtLogon $false
    Write-Ok "user created: $Sam ($Title)"
}

# -----------------------------------------------------------------------------
# Ordinary staff — the background noise that makes detections realistic
# -----------------------------------------------------------------------------
Write-Step "Creating standard users"
$staff = @(
    @{ Sam='a.alharbi';  Name='Abdullah Alharbi';  Title='Financial Analyst';  Dept='Finance' }
    @{ Sam='n.alotaibi'; Name='Noura Alotaibi';    Title='HR Specialist';      Dept='HR' }
    @{ Sam='m.aldosari'; Name='Mohammed Aldosari'; Title='Sales Manager';      Dept='Sales' }
    @{ Sam='s.alqahtani';Name='Sara Alqahtani';    Title='Software Engineer';  Dept='Engineering' }
    @{ Sam='f.alzahrani';Name='Faisal Alzahrani';  Title='Helpdesk Technician';Dept='IT' }
    @{ Sam='r.alshehri'; Name='Reem Alshehri';     Title='Legal Counsel';      Dept='Legal' }
)
foreach ($u in $staff) {
    New-LabUser -Sam $u.Sam -Display $u.Name -Path $usersOU -Title $u.Title -Department $u.Dept
}

# -----------------------------------------------------------------------------
# Tier-0 / admin accounts
# -----------------------------------------------------------------------------
Write-Step "Creating administrative accounts"
New-LabUser -Sam 'adm.k.almutairi' -Display 'Khalid Almutairi (Admin)' -Path $adminsOU -Title 'Domain Administrator' -Department 'IT'
Add-ADGroupMember -Identity 'Domain Admins' -Members 'adm.k.almutairi' -ErrorAction SilentlyContinue

New-LabUser -Sam 'adm.helpdesk' -Display 'Helpdesk Admin' -Path $adminsOU -Title 'Workstation Admin' -Department 'IT'

# -----------------------------------------------------------------------------
# ⚠ INTENTIONAL WEAKNESS #1 — Kerberoastable service account
# -----------------------------------------------------------------------------
#  What: a user account with a registered SPN and an RC4-crackable password.
#  Attack: T1558.003 Kerberoasting. Any domain user can request a service ticket
#          for this SPN and crack it offline.
#  Detects: detections/sigma/windows/win_kerberoasting_rc4_ticket.yml (4769)
#  Real-world analogue: SQL/IIS service accounts created a decade ago and never
#          migrated to gMSA. This is still one of the most common findings in a
#          real AD assessment.
# -----------------------------------------------------------------------------
Write-Step "Creating deliberately Kerberoastable service account (documented weakness #1)"
$weakSvcPassword = ConvertTo-SecureString 'Summer2019' -AsPlainText -Force
New-LabUser -Sam 'svc_mssql' -Display 'SQL Service Account' -Path $svcOU `
            -Title 'Service Account' -Department 'IT' -Password $weakSvcPassword
Set-ADUser -Identity 'svc_mssql' -ServicePrincipalNames @{ Add = "MSSQLSvc/sql01.$Domain`:1433" } -ErrorAction SilentlyContinue
Write-Ok "svc_mssql has SPN MSSQLSvc/sql01.$Domain:1433 with a weak password"

New-LabUser -Sam 'svc_backup' -Display 'Backup Service Account' -Path $svcOU -Title 'Service Account' -Department 'IT'
Set-ADUser -Identity 'svc_backup' -ServicePrincipalNames @{ Add = "BACKUP/backup01.$Domain" } -ErrorAction SilentlyContinue

# -----------------------------------------------------------------------------
# ⚠ INTENTIONAL WEAKNESS #2 — AS-REP roastable account
# -----------------------------------------------------------------------------
#  What: Kerberos pre-authentication disabled on a normal user.
#  Attack: T1558.004 AS-REP Roasting — crackable hash without any credentials.
#  Detects: detections/sigma/windows/win_asrep_roasting.yml (4768, preauth type 0)
# -----------------------------------------------------------------------------
Write-Step "Disabling Kerberos pre-auth on one account (documented weakness #2)"
Set-ADAccountControl -Identity 'f.alzahrani' -DoesNotRequirePreAuth $true
Write-Ok "f.alzahrani is now AS-REP roastable"

# -----------------------------------------------------------------------------
# ⚠ INTENTIONAL WEAKNESS #3 — password in the description field
# -----------------------------------------------------------------------------
#  What: a credential stored in a user's AD description, readable by any user.
#  Attack: T1087.002 Account Discovery — trivially harvested during recon.
#  Detects: detections/sigma/windows/win_ldap_recon_bulk_enumeration.yml
# -----------------------------------------------------------------------------
Set-ADUser -Identity 'svc_backup' -Description 'Backup svc - pwd: B@ckupNexus2021 - do not change, breaks the job'
Write-Ok "credential planted in svc_backup description (weakness #3)"

# -----------------------------------------------------------------------------
# Groups and nested membership
# -----------------------------------------------------------------------------
Write-Step "Creating groups"
$groups = @(
    @{ Name='NEXUS-Finance';     Scope='Global'; Members=@('a.alharbi') }
    @{ Name='NEXUS-IT';          Scope='Global'; Members=@('f.alzahrani','adm.helpdesk') }
    @{ Name='NEXUS-Engineering'; Scope='Global'; Members=@('s.alqahtani') }
    @{ Name='NEXUS-FileShare-RW';Scope='Global'; Members=@('NEXUS-Finance','NEXUS-IT') }
)
foreach ($g in $groups) {
    if (-not (Get-ADGroup -Filter "Name -eq '$($g.Name)'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $g.Name -GroupScope $g.Scope -Path "OU=Corp,$DN"
        Write-Ok "group created: $($g.Name)"
    }
    foreach ($mbr in $g.Members) {
        Add-ADGroupMember -Identity $g.Name -Members $mbr -ErrorAction SilentlyContinue
    }
}

# -----------------------------------------------------------------------------
# ⚠ INTENTIONAL WEAKNESS #4 — helpdesk group with local admin on workstations
# -----------------------------------------------------------------------------
#  Enables the lateral-movement leg of the end-to-end scenario.
#  Detects: win_admin_share_access.yml, win_service_install_lateral.yml
# -----------------------------------------------------------------------------
Write-Step "Granting NEXUS-IT local admin on workstations via Restricted Groups GPO"
# Applied as a GPP/Restricted-Groups style assignment during ws01 provisioning
# (see 20-ws-join.ps1) — recorded here so the weakness lives with the others.

# -----------------------------------------------------------------------------
# Password policy — weak on purpose so the brute-force scenario terminates in a
# reasonable time. Documented, not accidental.
# -----------------------------------------------------------------------------
Write-Step "Setting a deliberately permissive password policy (weakness #5)"
Set-ADDefaultDomainPasswordPolicy -Identity $Domain `
    -MinPasswordLength 7 -ComplexityEnabled $true `
    -LockoutThreshold 0 `
    -MaxPasswordAge '365.00:00:00'
# LockoutThreshold 0 = no lockout, so password spraying can run to completion
# and the detection has something to find. In production this would be a finding.

# -----------------------------------------------------------------------------
# Summary — written to disk so the attack scenarios can read the inventory
# -----------------------------------------------------------------------------
$inventory = [ordered]@{
    domain          = $Domain
    generated       = (Get-Date).ToString('o')
    standard_users  = $staff.Sam
    admin_users     = @('adm.k.almutairi', 'adm.helpdesk')
    service_accounts= @('svc_mssql', 'svc_backup')
    weaknesses      = @(
        @{ id=1; type='kerberoastable';  target='svc_mssql';    technique='T1558.003' }
        @{ id=2; type='asrep_roastable'; target='f.alzahrani';  technique='T1558.004' }
        @{ id=3; type='password_in_desc';target='svc_backup';   technique='T1087.002' }
        @{ id=4; type='helpdesk_localadmin'; target='NEXUS-IT'; technique='T1078.002' }
        @{ id=5; type='no_lockout_policy';target='domain';      technique='T1110.003' }
    )
}
Initialize-LabDirs
$inventory | ConvertTo-Json -Depth 5 | Set-Content 'C:\LabTools\ad-inventory.json' -Encoding UTF8

Write-Ok "Active Directory populated: $($staff.Count) staff, 2 admins, 2 service accounts, 5 documented weaknesses"
Write-Ok "Inventory written to C:\LabTools\ad-inventory.json"

<#
.SYNOPSIS
    Stage 10 — promote dc01 to a domain controller for a new forest.
.DESCRIPTION
    Installs AD DS + DNS and creates the forest defined in lab.yml. Reboots at
    the end (Vagrant's :reload provisioner handles the wait), after which
    11-dc-populate.ps1 builds a realistic directory.

    Idempotent: if the machine is already a DC for the right domain, it exits
    immediately so `vagrant provision` stays cheap.
#>

. "$PSScriptRoot\_lib.ps1"

$Domain   = $env:LAB_DOMAIN
$NetBios  = $env:LAB_NETBIOS

# Lab-only credential. This is a throwaway VM on a non-routable host-only
# network that is rebuilt from scratch with `vagrant destroy`. Never reuse this
# pattern anywhere real — and note it is not a secret worth protecting here,
# which is exactly why it is safe to have it in the repo.
$SafeModePassword = ConvertTo-SecureString 'LabDSRM!2026#nexus' -AsPlainText -Force

if (Test-IsDomainController) {
    $current = (Get-CimInstance Win32_ComputerSystem).Domain
    Write-Ok "already a domain controller for '$current' — skipping promotion"
    return
}

Write-Step "Installing AD DS and DNS roles"
Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools | Out-Null
Write-Ok "roles installed"

Write-Step "Promoting to first DC of new forest '$Domain' (NetBIOS: $NetBios)"
# -Force suppresses the interactive confirmation; -NoRebootOnCompletion lets
# Vagrant own the reboot so it can reconnect over WinRM cleanly.
Install-ADDSForest `
    -DomainName                    $Domain `
    -DomainNetbiosName             $NetBios `
    -SafeModeAdministratorPassword $SafeModePassword `
    -InstallDns                    $true `
    -DomainMode                    'WinThreshold' `
    -ForestMode                    'WinThreshold' `
    -DatabasePath                  'C:\Windows\NTDS' `
    -LogPath                       'C:\Windows\NTDS' `
    -SysvolPath                    'C:\Windows\SYSVOL' `
    -NoRebootOnCompletion:$true `
    -Force:$true

Write-Ok "forest created — reboot required (Vagrant will handle it)"

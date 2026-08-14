<#
.SYNOPSIS
    Stage 20 — join ws01 to the domain and grant the helpdesk group local admin.
.DESCRIPTION
    Waits for the DC to answer DNS before attempting the join, because on a cold
    `vagrant up` the workstation is frequently ready before AD DS has finished
    starting. Retrying here is the difference between a reliable lab and one
    that fails one boot in three.
#>

. "$PSScriptRoot\_lib.ps1"

$Domain  = $env:LAB_DOMAIN
$NetBios = $env:LAB_NETBIOS
$DcIp    = $env:LAB_DC_IP

$joinUser = "$NetBios\Administrator"
$joinPass = ConvertTo-SecureString 'vagrant' -AsPlainText -Force   # box default
$cred     = New-Object System.Management.Automation.PSCredential($joinUser, $joinPass)

# Already joined? Nothing to do.
$cs = Get-CimInstance Win32_ComputerSystem
if ($cs.PartOfDomain -and $cs.Domain -eq $Domain) {
    Write-Ok "already joined to $Domain"
    return
}

# -----------------------------------------------------------------------------
# Point DNS at the DC first — a domain join with the wrong resolver fails with
# "the specified domain either does not exist", which sends people hunting for
# credential problems that are not there.
# -----------------------------------------------------------------------------
Write-Step "Pointing DNS at the domain controller ($DcIp)"
Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -like '10.13.37.*' } |
    ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses $DcIp }
Clear-DnsClientCache

# -----------------------------------------------------------------------------
# Wait for the domain to actually be resolvable and answering.
# -----------------------------------------------------------------------------
Write-Step "Waiting for $Domain to become available (up to 10 minutes)"
$deadline = (Get-Date).AddMinutes(10)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        # An SRV record for the LDAP service is the definitive "AD is up" signal.
        $srv = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$Domain" -Type SRV -Server $DcIp -ErrorAction Stop
        if ($srv) { $ready = $true; break }
    } catch {
        Start-Sleep -Seconds 15
    }
}
if (-not $ready) { throw "Domain $Domain never became resolvable — is dc01 up? (vagrant status)" }
Write-Ok "domain is answering"

# -----------------------------------------------------------------------------
# Join, with retries for the race where AD DS is up but NETLOGON is not.
# -----------------------------------------------------------------------------
Write-Step "Joining $env:COMPUTERNAME to $Domain"
for ($i = 1; $i -le 5; $i++) {
    try {
        Add-Computer -DomainName $Domain -Credential $cred `
                     -OUPath "OU=Workstations,OU=Corp,$(($Domain -split '\.' | ForEach-Object { "DC=$_" }) -join ',')" `
                     -Force -ErrorAction Stop
        Write-Ok "joined on attempt $i — reboot required"
        break
    } catch {
        Write-Warn "join attempt $i/5 failed: $($_.Exception.Message)"
        if ($i -eq 5) { throw }
        Start-Sleep -Seconds 30
    }
}

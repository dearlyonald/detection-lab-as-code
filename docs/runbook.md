# Runbook

Operating the lab, and what actually goes wrong.

---

## Build order matters

Bring the SIEM up **first**. The Windows agents enrol themselves against
`10.13.37.30:1515` during provisioning; if nothing is listening, they install
successfully and then sit disconnected, which is a confusing state to debug
later.

```powershell
$env:LAB_PROFILE = "standard"
vagrant up siem      # ~20 min — the Wazuh installer is the slow part
vagrant up dc01      # ~15 min — includes a reboot for the DC promotion
vagrant up ws01      # ~20 min — includes a reboot for the domain join
```

First run also downloads ~8 GB of base boxes. Subsequent rebuilds are much faster.

---

## Everyday commands

| Goal | Command |
|---|---|
| Status of everything | `vagrant status` |
| Re-run provisioning without rebuilding | `vagrant provision ws01` |
| Re-run one provisioning step | `vagrant provision ws01 --provision-with sysmon` |
| Shell on Linux | `vagrant ssh siem` |
| Shell on Windows | `vagrant powershell ws01` |
| Suspend the lab (keeps state) | `vagrant suspend` |
| Rebuild one machine from scratch | `vagrant destroy -f ws01; vagrant up ws01` |
| Burn it all down | `vagrant destroy -f` |

**Snapshot before every attack run.** It turns a broken VM from an hour of
rebuilding into thirty seconds:

```powershell
vagrant snapshot save ws01 clean
# ... run attacks, break things ...
vagrant snapshot restore ws01 clean
```

---

## Verifying the telemetry pipeline

Work outwards from the endpoint. Most "my detection does not fire" problems are
a missing log, not a broken rule.

**1 — is Sysmon logging?**
```powershell
vagrant powershell ws01
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5
```

**2 — do 4688 events carry the command line?**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 1 |
    Format-List -Property Message
```
If `Process Command Line` is absent, `02-audit-policy.ps1` did not apply. Re-run
`vagrant provision ws01 --provision-with audit`, then `gpupdate /force`.

**3 — is the agent connected?**
```powershell
Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 20
```
Look for `Connected to the server`.

**4 — is the manager receiving?**
```bash
vagrant ssh siem
sudo /var/ossec/bin/agent_control -l          # list agents and their state
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

**5 — does a rule match a specific event?**
```bash
sudo /var/ossec/bin/wazuh-logtest
# paste a raw event, see which rule id fires
```

---

## Things that break, and why

**`vagrant up` hangs at "Waiting for machine to boot"**
Windows boxes negotiate WinRM slowly on first boot. `config.vm.boot_timeout` is
already 900 s. If it still times out, open the VirtualBox GUI and watch the
console — it is usually sitting on a "Windows needs to restart" prompt.

**Domain join fails with "the specified domain either does not exist"**
Almost never a credential problem. `ws01` resolved DNS through NAT instead of
through `dc01`. `20-ws-join.ps1` waits on the `_ldap._tcp.dc._msdcs` SRV record
for this reason — if it still fails, confirm `dc01` is fully up first.

**Wazuh indexer will not start**
Two usual causes: less than 6 GB RAM on the SIEM, or `vm.max_map_count` below
262144. Both are handled by `install-wazuh.sh`, but a `vagrant reload siem`
without re-provisioning can lose the sysctl. Check with:
```bash
sudo systemctl status wazuh-indexer
cat /proc/sys/vm/max_map_count
```

**No Sysmon events reaching the SIEM, but they exist locally**
The agent is shipping the default channels only. `30-wazuh-agent.ps1` rewrites
`ossec.conf` to add the Sysmon channel using `eventchannel` format — the older
`eventlog` format silently cannot read modern XML channels. Re-run:
`vagrant provision ws01 --provision-with wazuh-agent`.

**Atomic tests fail with "prerequisites not met"**
Run `.\attack\run-atomic.ps1 -Scenario 01-domain-compromise -CheckPrereqs` first.
Some atomics need files fetched from the internet, which the lab has via NAT but
which can be blocked by Defender before the exclusion applies.

**Everything is slow**
Check Hyper-V: `(Get-CimInstance Win32_ComputerSystem).HypervisorPresent`. If
true, VirtualBox is running in a degraded emulation mode.
`bcdedit /set hypervisorlaunchtype off`, then reboot.

---

## Resetting between scenarios

Attack runs leave persistence, dropped files and modified registry keys. Running
a second scenario on top of the first produces telemetry that no longer maps
cleanly to either.

```powershell
.\attack\run-atomic.ps1 -Scenario 01-domain-compromise -Cleanup   # best effort
vagrant snapshot restore ws01 clean                               # authoritative
```

Prefer the snapshot. Atomic cleanup commands are provided by the technique
authors and are not guaranteed to be complete.

---

## Licensing note

The Windows boxes are Microsoft evaluation images — 180 days, and the clock
resets when the VM is rebuilt. That is fine for a lab that is destroyed and
recreated routinely, but it is not a licence for any other use.

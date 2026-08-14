# Architecture

How the pieces fit, and why each one is there.

---

## The three layers

```
┌─ TELEMETRY ──────────────────────────────────────────────────────────┐
│  What the endpoints are configured to record.                        │
│  provision/windows/02-audit-policy.ps1 · 03-sysmon.ps1               │
│                                                                      │
│  This layer decides which detections are POSSIBLE. Everything above  │
│  it is downstream of what was logged, and no rule can recover an     │
│  event that was never written.                                       │
└──────────────────────────────────────────────────────────────────────┘
                                  ↓
┌─ TRANSPORT ──────────────────────────────────────────────────────────┐
│  Getting the events off the host and into the SIEM.                  │
│  provision/windows/30-wazuh-agent.ps1 · provision/linux/siem/        │
│                                                                      │
│  Eight event channels, in eventchannel format. The default agent     │
│  config ships three and none of them are Sysmon.                     │
└──────────────────────────────────────────────────────────────────────┘
                                  ↓
┌─ DETECTION ──────────────────────────────────────────────────────────┐
│  detections/sigma/ · tools/                                          │
│                                                                      │
│  Rules, their tests, the evaluator that proves they work, and the    │
│  converter that puts them into the SIEM.                             │
└──────────────────────────────────────────────────────────────────────┘
```

Most home labs build the middle layer well, the bottom layer by accident, and
the top layer not at all. The value is concentrated in the layer that is usually
skipped.

---

## Why each machine exists

**`dc01` — domain controller.** Kerberos events (4768, 4769) and directory
access events (4662) are only ever logged on a DC. Kerberoasting, AS-REP
roasting and DCSync are undetectable without one, and those are three of the
four highest-value techniques against an AD estate.

**`ws01` — the victim workstation.** Where process, registry and file telemetry
comes from, and where Atomic Red Team executes. Deliberately made to look
lived-in by `21-ws-victimise.ps1`, because rules tuned against a silent machine
do not survive contact with a real one.

**`siem` — Wazuh all-in-one.** Indexer, manager and dashboard on one node.
Configured with `logall_json` so every raw event is archived, not just the ones
that matched a rule — otherwise a new rule can never be tested against
yesterday's attack.

**`attacker` — Kali.** Impacket and NetExec, for the techniques that are cleaner
to launch from outside the Windows estate. Optional; the atomics on `ws01` cover
most of the same ground.

---

## The intentional weaknesses

`11-dc-populate.ps1` plants five documented misconfigurations. Each exists to
make a specific attack path *reachable*, so the end-to-end scenario actually
completes rather than stalling halfway.

| # | Weakness | Enables | Detected by |
|---|---|---|---|
| 1 | `svc_mssql` has an SPN and a weak password | T1558.003 Kerberoasting | `win_kerberoasting_rc4_ticket` |
| 2 | `f.alzahrani` has pre-auth disabled | T1558.004 AS-REP roasting | `win_asrep_roasting` |
| 3 | Password in `svc_backup` description | T1552.001 credentials in files | *(gap)* |
| 4 | `NEXUS-IT` is local admin on workstations | T1078.002 valid accounts | `win_admin_share_lateral_movement` |
| 5 | No account lockout threshold | T1110.003 password spraying | *(gap — needs correlation)* |

Two of the five have no detection. That is stated here rather than left for a
reader to discover, and both are on the backlog.

---

## Why the evaluator is written rather than imported

`tools/sigma_eval.py` implements Sigma's condition grammar directly instead of
converting rules through `sigma-cli` and a backend.

The reason is testability. Converting a rule to a query language tells you the
conversion succeeded; it tells you nothing about whether the rule *matches the
event you care about*. To learn that from a backend you need the whole SIEM
running, which is not available in CI and is far too slow for the edit-test loop
that rule writing actually requires.

Evaluating in-process makes the loop about two seconds, which is what makes it
practical to insist that every rule ship with tests.

The cost is a documented subset rather than full Sigma. Unsupported constructs —
aggregations, correlation, field references — raise an explicit error. A rule
using them is skipped *loudly* and counted as skipped in the summary, never
silently reported as passing.

---

## Data flow of one detection

Taking Kerberoasting end to end:

```
1.  attacker runs GetUserSPNs.py against dc01
        ↓
2.  dc01 issues an RC4 service ticket for svc_mssql
        ↓
3.  Kerberos Service Ticket Operations auditing writes Security 4769
        ↑ enabled by 02-audit-policy.ps1, subcategory GUID 0CCE9240
        ↓
4.  Wazuh agent ships the Security channel
        ↑ configured by 30-wazuh-agent.ps1
        ↓
5.  wazuh-manager evaluates rule 100xxx
        ↑ generated from win_kerberoasting_rc4_ticket.yml by sigma_to_wazuh.py
        ↓
6.  alert at level 10 with mitre id T1558.003
```

Break any link and the detection silently stops working. This is why the
provisioning scripts verify their own work — `02-audit-policy.ps1` reads the
policy back after setting it, and `03-sysmon.ps1` generates a test event and
confirms it appears.

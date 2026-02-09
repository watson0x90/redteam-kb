# LDAP Enumeration

> **MITRE ATT&CK**: Discovery > T1087.002 - Account Discovery: Domain Account
> **Platforms**: Windows (Active Directory), Linux (OpenLDAP)
> **Required Privileges**: None (anonymous bind) / Domain User (authenticated)
> **OPSEC Risk**: Low-Medium (LDAP queries are routine in AD environments)

## Strategic Overview

Lightweight Directory Access Protocol is the query interface to Active Directory and the
single most important enumeration target in enterprise Windows environments. A successful
LDAP enumeration provides a complete map of the domain: every user account, group membership,
computer object, organizational unit, Group Policy Object, trust relationship, and password
policy. For the Red Team Lead, LDAP enumeration is where passive recon transforms into
actionable intelligence. Anonymous LDAP binds (no credentials required) are still possible
on misconfigured domain controllers and older Windows Server versions. With even a single
low-privilege domain account, authenticated LDAP queries unlock the full directory -- this
is by design in Active Directory, not a misconfiguration. Understanding LDAP query syntax,
search filters, and the AD schema is essential for extracting high-value targets: service
accounts with SPNs (Kerberoastable), accounts with unconstrained delegation, users with
AdminCount=1, and accounts with password not required flags.

## Technical Deep-Dive

### Discovery and Anonymous Binding

```bash
# Discover LDAP services via DNS SRV records
dig SRV _ldap._tcp.domain.local +short
dig SRV _gc._tcp.domain.local +short       # Global Catalog

# Discover naming contexts (base DN) without authentication
ldapsearch -x -H ldap://10.10.10.50 -s base namingContexts
# Returns: DC=domain,DC=local (the base DN for all queries)

# Test anonymous LDAP bind
ldapsearch -x -H ldap://10.10.10.50 -b "DC=domain,DC=local" "(objectClass=*)" \
  -s base 2>&1 | head -20
# Success = anonymous bind allowed

# Nmap LDAP discovery
nmap -sV -p 389,636,3268,3269 --script ldap-rootdse 10.10.10.50
```

### User Enumeration

```bash
# Enumerate all domain users
ldapsearch -x -H ldap://10.10.10.50 -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName displayName \
  description memberOf userAccountControl

# Find enabled accounts only (LDAP filter for userAccountControl)
ldapsearch -x -H ldap://10.10.10.50 -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" \
  "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" \
  sAMAccountName

# Find accounts with "password never expires" flag
ldapsearch -x -H ldap://10.10.10.50 -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" \
  "(userAccountControl:1.2.840.113556.1.4.803:=65536)" sAMAccountName

# Find accounts with "password not required" flag
ldapsearch -x -H ldap://10.10.10.50 -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" \
  "(userAccountControl:1.2.840.113556.1.4.803:=32)" sAMAccountName

# Find accounts with AdminCount=1 (high-privilege accounts)
ldapsearch -x -H ldap://10.10.10.50 -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" "(&(objectClass=user)(adminCount=1))" \
  sAMAccountName memberOf
```

### Group and Membership Enumeration

```bash
# Enumerate all domain groups
ldapsearch -x -H ldap://10.10.10.50 -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" "(objectClass=group)" cn member description

# Find members of Domain Admins
ldapsearch -x -H ldap://10.10.10.50 -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" "(&(objectClass=group)(cn=Domain Admins))" member

# Find nested group memberships (recursive)
ldapsearch -x -H ldap://10.10.10.50 -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" \
  "(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=domain,DC=local)" \
  sAMAccountName
```

### Service Account and SPN Discovery

```bash
# Find accounts with ServicePrincipalNames (Kerberoastable)
ldapsearch -x -H ldap://10.10.10.50 -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName

# Find computer accounts
ldapsearch -x -H ldap://10.10.10.50 -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" "(objectClass=computer)" cn dNSHostName \
  operatingSystem operatingSystemVersion
```

### Password Policy Extraction

```bash
# Extract domain password policy
ldapsearch -x -H ldap://10.10.10.50 -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" "(objectClass=domainDNS)" \
  minPwdLength maxPwdAge minPwdAge pwdHistoryLength lockoutThreshold \
  lockoutDuration lockoutObservationWindow pwdProperties

# Fine-grained password policies (PSOs)
ldapsearch -x -H ldap://10.10.10.50 -D "user@domain.local" -w 'password' \
  -b "CN=Password Settings Container,CN=System,DC=domain,DC=local" \
  "(objectClass=msDS-PasswordSettings)" cn msDS-MinimumPasswordLength \
  msDS-LockoutThreshold msDS-PSOAppliesTo
```

### Dedicated LDAP Enumeration Tools

```bash
# windapsearch - purpose-built AD LDAP tool
windapsearch -d domain.local --dc 10.10.10.50 -u user@domain.local -p password \
  --da               # Domain admins
windapsearch -d domain.local --dc 10.10.10.50 -u user@domain.local -p password \
  --privileged-users  # All privileged users
windapsearch -d domain.local --dc 10.10.10.50 -u user@domain.local -p password \
  --unconstrained     # Unconstrained delegation

# ldapdomaindump - dump entire domain to HTML/JSON/grep-friendly formats
ldapdomaindump -u 'domain\user' -p 'password' 10.10.10.50 -o ldap-dump/
# Produces: domain_users.html, domain_groups.html, domain_computers.html,
#           domain_policy.html, domain_trusts.html
```

### Python ldap3 Scripting

```python
# Custom LDAP enumeration with Python ldap3
from ldap3 import Server, Connection, ALL, SUBTREE

server = Server('10.10.10.50', get_info=ALL)
conn = Connection(server, user='domain\\user', password='password', auto_bind=True)

# Search for all users with SPNs
conn.search(
    search_base='DC=domain,DC=local',
    search_filter='(&(objectClass=user)(servicePrincipalName=*))',
    search_scope=SUBTREE,
    attributes=['sAMAccountName', 'servicePrincipalName', 'memberOf']
)

for entry in conn.entries:
    print(f"User: {entry.sAMAccountName}, SPNs: {entry.servicePrincipalName}")

# Search for accounts with delegation
conn.search(
    search_base='DC=domain,DC=local',
    search_filter='(userAccountControl:1.2.840.113556.1.4.803:=524288)',
    attributes=['sAMAccountName', 'dNSHostName']
)
```

## Detection & Evasion

### What Defenders See
- LDAP queries are standard AD operations and generate minimal alerts by default
- High-volume LDAP enumeration may trigger advanced threat analytics (e.g., Microsoft ATA/ATP)
- Queries for sensitive attributes (AdminCount, servicePrincipalName) can be monitored
- Anonymous bind attempts on modern DCs generate Event ID 2889 (unsigned LDAP bind)
- Tools like ldapdomaindump create distinctive query patterns

### Evasion Techniques
- LDAP queries from domain-joined workstations blend with normal AD traffic
- Query specific OUs rather than the entire domain to reduce volume
- Spread queries over time rather than dumping everything at once
- Use standard LDAP ports (389/636) through normal domain communication paths
- Avoid anonymous binds on modern environments -- use compromised credentials instead

### LDAP Channel Binding and Signing
- Microsoft has been enforcing LDAP signing and channel binding requirements
- LDAP signing prevents tampering with LDAP traffic
- Channel binding ties LDAP sessions to TLS channels (prevents relay attacks)
- Red teams must be aware of these restrictions when using cleartext LDAP (port 389)
- Use LDAPS (port 636) when LDAP signing is enforced

## Cross-References

- **DNS Enumeration** (01-reconnaissance/dns-enumeration.md) -- SRV records reveal DCs
- **SMB Enumeration** (01-reconnaissance/smb-enumeration.md) -- SMB provides complementary user/share data
- **Password Attacks** (02-initial-access/password-attacks.md) -- password policy extraction informs spraying
- **Active Scanning** (01-reconnaissance/active-scanning.md) -- port 389/636/3268 discovery

## References

- MITRE ATT&CK T1087.002: https://attack.mitre.org/techniques/T1087/002/
- windapsearch: https://github.com/ropnop/windapsearch
- ldapdomaindump: https://github.com/dirkjanm/ldapdomaindump
- ldap3 Python library: https://github.com/cannatag/ldap3
- LDAP Wiki: https://ldapwiki.com/
- Microsoft LDAP Signing: https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows

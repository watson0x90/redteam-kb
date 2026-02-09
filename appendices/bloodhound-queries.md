# BloodHound Custom Cypher Queries

> Ready-to-use Cypher queries for BloodHound CE and Legacy.
> Organized by attack category for rapid engagement use.
> Paste directly into the BloodHound Raw Query bar or Neo4j browser.

---

## High-Value Target Identification

```cypher
// All Domain Admins (recursive group membership)
MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.name =~ '(?i).*domain admins.*'
RETURN u.name AS User, g.name AS Group
ORDER BY u.name

// Enterprise Admins
MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.name =~ '(?i).*enterprise admins.*'
RETURN u.name AS User

// Kerberoastable users with path to Domain Admins
MATCH (u:User {hasspn:true})
MATCH p=shortestPath((u)-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}))
RETURN u.name AS KerberoastableUser, length(p) AS PathLength
ORDER BY PathLength ASC

// Kerberoastable users with admin count (high-value targets)
MATCH (u:User {hasspn:true, admincount:true})
RETURN u.name, u.serviceprincipalnames, u.description

// AS-REP Roastable users
MATCH (u:User {dontreqpreauth:true})
RETURN u.name AS User, u.displayname AS DisplayName, u.description AS Description, u.enabled AS Enabled

// Users with DCSync rights (GetChanges + GetChangesAll)
MATCH p=(u)-[:GetChanges|GetChangesAll*1..]->(d:Domain)
RETURN u.name AS Principal, d.name AS Domain

// Users with DCSync rights (explicit check for both permissions)
MATCH (d:Domain)
MATCH p1=(u1)-[:GetChanges]->(d)
MATCH p2=(u2)-[:GetChangesAll]->(d)
WHERE u1.name = u2.name
RETURN u1.name AS DCSync_Principal

// Unconstrained delegation computers (excluding DCs)
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name CONTAINS 'DC'
RETURN c.name AS Computer, c.operatingsystem AS OS

// Constrained delegation principals
MATCH (p) WHERE p.allowedtodelegate IS NOT NULL
RETURN p.name AS Principal, p.allowedtodelegate AS DelegationTarget

// Users with passwords that never expire
MATCH (u:User {pwdneverexpires:true, enabled:true})
RETURN u.name, u.lastlogontimestamp
ORDER BY u.lastlogontimestamp ASC

// Users with password not required
MATCH (u:User {passwordnotreqd:true, enabled:true})
RETURN u.name, u.displayname
```

---

## Attack Path Queries

```cypher
// Shortest path from any owned principal to Domain Admins
MATCH p=shortestPath((u {owned:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}))
RETURN p

// All shortest paths to Domain Admins (top 20)
MATCH p=allShortestPaths((u:User)-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}))
WHERE NOT u.name =~ '(?i).*admin.*'
RETURN p LIMIT 20

// Shortest path from specific user to DA
MATCH p=shortestPath((u:User {name:'JSMITH@DOMAIN.LOCAL'})-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}))
RETURN p

// Shortest path from Domain Users to DA
MATCH p=shortestPath((g1:Group {name:'DOMAIN USERS@DOMAIN.LOCAL'})-[*1..]->(g2:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}))
RETURN p

// Find all computers where Domain Admins have active sessions
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})
RETURN c.name AS Computer, u.name AS DomainAdmin

// Paths through specific edge types (e.g., GenericAll abuse chain)
MATCH p=(u:User)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(t)
WHERE t:User OR t:Group OR t:Computer
RETURN p LIMIT 50

// Find principals that can add members to privileged groups
MATCH (u)-[:AddMember]->(g:Group)
WHERE g.name =~ '(?i).*(admin|operator|manager).*'
RETURN u.name AS Principal, g.name AS TargetGroup

// Machines where we can RDP as current owned users
MATCH (u {owned:true})-[:CanRDP]->(c:Computer)
RETURN u.name AS User, c.name AS Computer, c.operatingsystem AS OS
```

---

## ACL Abuse Queries

```cypher
// All GenericAll permissions on users (password reset / targeted kerberoast)
MATCH (a)-[:GenericAll]->(b:User)
WHERE NOT a.name =~ '(?i).*admin.*'
RETURN a.name AS Attacker, b.name AS Target, labels(a) AS AttackerType

// WriteDACL permissions (can grant themselves more access)
MATCH (a)-[:WriteDacl]->(b)
WHERE NOT a.name =~ '(?i).*admin.*'
RETURN a.name AS Principal, b.name AS Target, labels(b) AS TargetType
LIMIT 100

// WriteOwner permissions (can take ownership then modify DACL)
MATCH (a)-[:WriteOwner]->(b)
WHERE NOT a.name =~ '(?i).*admin.*'
RETURN a.name, b.name

// GenericWrite on computers (RBCD setup)
MATCH (a)-[:GenericWrite]->(c:Computer)
RETURN a.name AS Principal, c.name AS TargetComputer

// AllExtendedRights on users (force password change)
MATCH (a)-[:AllExtendedRights]->(u:User)
RETURN a.name AS Attacker, u.name AS Target

// ForceChangePassword
MATCH (a)-[:ForceChangePassword]->(u:User)
WHERE a <> u
RETURN a.name, u.name

// Dangerous ACLs on the domain object
MATCH (d:Domain)<-[r:GenericAll|WriteDacl|WriteOwner|AllExtendedRights]-(p)
RETURN p.name AS Principal, type(r) AS Right, d.name AS Domain
```

---

## GPO Abuse Queries

```cypher
// GPOs that apply to computers with Domain Admin sessions
MATCH (g:GPO)-[:GpLink]->(ou:OU)-[:Contains*1..]->(c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(da:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})
RETURN g.name AS GPO, c.name AS Computer, u.name AS Admin

// Who can modify GPOs?
MATCH (u)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl]->(g:GPO)
RETURN u.name AS Principal, g.name AS GPO

// GPOs linked to Domain Controllers OU (Tier 0)
MATCH (g:GPO)-[:GpLink]->(ou:OU)
WHERE ou.name =~ '(?i).*domain controllers.*'
RETURN g.name AS GPO, ou.name AS OU

// Users affected by specific GPO
MATCH (g:GPO {name:'VULNERABLE_GPO@DOMAIN.LOCAL'})-[:GpLink]->(ou:OU)-[:Contains*1..]->(target)
WHERE target:User OR target:Computer
RETURN target.name AS AffectedObject, labels(target) AS Type

// GPOs with wide scope (linked to root domain)
MATCH (g:GPO)-[:GpLink]->(d:Domain)
RETURN g.name AS GPO, d.name AS Domain
```

---

## Trust Relationship Queries

```cypher
// All domain trusts
MATCH (d1:Domain)-[r:TrustedBy]->(d2:Domain)
RETURN d1.name AS TrustingDomain, d2.name AS TrustedDomain,
       r.trusttype AS TrustType, r.transitive AS Transitive, r.sidfiltering AS SIDFiltering

// Domains with SID filtering disabled (SID history abuse possible)
MATCH (d1:Domain)-[r:TrustedBy]->(d2:Domain)
WHERE r.sidfiltering = false
RETURN d1.name, d2.name

// Foreign group membership (users in groups across trust boundaries)
MATCH (u:User)-[:MemberOf]->(g:Group)
WHERE NOT u.domain = g.domain
RETURN u.name AS ForeignUser, g.name AS Group, u.domain AS UserDomain, g.domain AS GroupDomain

// Cross-domain attack paths
MATCH p=shortestPath((u:User {domain:'CHILD.DOMAIN.LOCAL'})-[*1..]->(g:Group {name:'ENTERPRISE ADMINS@DOMAIN.LOCAL'}))
RETURN p
```

---

## Azure / Entra ID Queries (BloodHound CE)

```cypher
// Azure Global Admins
MATCH (u)-[:AZGlobalAdmin]->(t:AZTenant)
RETURN u.name AS GlobalAdmin, t.name AS Tenant

// Users who can reset passwords of Global Admins
MATCH (a)-[:AZResetPassword]->(ga)-[:AZGlobalAdmin]->(t:AZTenant)
RETURN a.name AS Attacker, ga.name AS TargetGlobalAdmin

// Service Principals with dangerous permissions
MATCH (sp:AZServicePrincipal)-[r:AZOwns|AZCloudAppAdmin|AZAppAdmin]->(target)
RETURN sp.name AS ServicePrincipal, type(r) AS Permission, target.name AS Target

// Path from on-prem to Azure
MATCH p=shortestPath((u:User)-[*1..]->(az:AZTenant))
WHERE NOT u.name =~ '(?i).*admin.*'
RETURN p LIMIT 10

// Users who can abuse App Registrations
MATCH (u)-[:AZOwns|AZCloudAppAdmin]->(app:AZApp)-[:AZRunsAs]->(sp:AZServicePrincipal)-[r]->(target)
RETURN u.name, app.name, sp.name, type(r), target.name
LIMIT 25
```

---

## Operational Hygiene Queries

```cypher
// Users not logged in for 90+ days but still enabled (stale accounts)
MATCH (u:User {enabled:true})
WHERE u.lastlogontimestamp < (datetime().epochSeconds - (90 * 86400))
RETURN u.name, u.lastlogontimestamp
ORDER BY u.lastlogontimestamp ASC

// Computers with old OS (unsupported)
MATCH (c:Computer)
WHERE c.operatingsystem =~ '.*(2008|2003|XP|Vista|7 ).*'
RETURN c.name, c.operatingsystem

// Service accounts with admin privileges
MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE u.name =~ '(?i).*svc.*' AND g.admincount = true
RETURN u.name, g.name

// High-value targets list (custom marking)
MATCH (n {highvalue:true})
RETURN n.name, labels(n)

// Count of principals per attack technique
MATCH (u:User {hasspn:true}) RETURN 'Kerberoastable' AS Technique, count(u) AS Count
UNION ALL
MATCH (u:User {dontreqpreauth:true}) RETURN 'AS-REP Roastable', count(u)
UNION ALL
MATCH (c:Computer {unconstraineddelegation:true}) RETURN 'Unconstrained Delegation', count(c)
UNION ALL
MATCH (u {owned:true}) RETURN 'Owned Principals', count(u)
```

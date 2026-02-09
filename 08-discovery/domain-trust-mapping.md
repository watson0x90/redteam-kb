# Domain Trust Mapping

> **MITRE ATT&CK**: Discovery > T1482 - Domain Trust Discovery
> **Platforms**: Windows (Active Directory environments)
> **Required Privileges**: User (domain-authenticated)
> **OPSEC Risk**: Low (LDAP queries against domain controllers are normal traffic)

## Strategic Overview

Domain trust mapping is one of the highest-value, lowest-risk discovery activities in an engagement. A single LDAP query can reveal the entire trust architecture of a multi-domain forest, exposing attack paths that span organizational boundaries. Many organizations have legacy trust relationships they have forgotten about -- child domains from acquisitions, external trusts to partners, or forest trusts with weak SID filtering. Understanding trusts before attempting lateral movement is essential because trust direction determines which direction authentication (and therefore attacks) can flow.

**Critical insight**: A trust from Domain A to Domain B means Domain A trusts Domain B. Users in Domain B can access resources in Domain A. The trust direction is the opposite of the access direction -- this confuses many operators.

## Technical Deep-Dive

### Trust Enumeration (Built-in Tools)

```cmd
:: List all trusts for current domain
nltest /domain_trusts /all_trusts

:: Detailed trust information
nltest /domain_trusts /v

:: Trust relationship for specific domain
nltest /sc_query:CHILD.CORP.LOCAL

:: .NET method (PowerShell, no modules needed)
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).GetAllTrustRelationships()
```

### PowerView Trust Enumeration

```powershell
# Current domain trusts
Get-DomainTrust
Get-DomainTrust -Domain child.corp.local   # Specific domain's trusts

# Forest-level enumeration
Get-ForestDomain                           # All domains in current forest
Get-ForestGlobalCatalog                    # All Global Catalog servers
Get-ForestTrust                            # Forest-level trusts

# Map all trusts (recursive)
Get-DomainTrustMapping                     # Maps trusts across all reachable domains
```

### ADModule Trust Enumeration

```powershell
# Microsoft signed module -- less likely to trigger alerts
Get-ADTrust -Filter *
Get-ADTrust -Filter * | Select Name,Direction,TrustType,ForestTransitive,SIDFilteringQuarantined

Get-ADForest | Select Domains,ForestMode,Name
Get-ADDomain | Select DistinguishedName,DNSRoot,ParentDomain,ChildDomains
```

### Trust Types Explained

| Trust Type | Description | Attack Relevance |
|-----------|-------------|-----------------|
| **Parent-Child** | Automatic, bidirectional, transitive within a forest | Golden ticket from child can escalate to forest root (SID history) |
| **Tree-Root** | Connects tree roots in same forest, bidirectional, transitive | Same as parent-child -- intra-forest trusts share a key |
| **External** | Between domains in different forests, non-transitive | Limited by SID filtering, but credential attacks work |
| **Forest** | Between forest root domains, can be transitive | SID filtering enabled by default -- blocks SID history attacks |
| **Shortcut** | Optimization within a forest, reduces auth hops | Same privileges as underlying transitive trust |
| **Realm** | Trust with non-Windows Kerberos realm (MIT, etc.) | Rare but can be exploited if misconfigured |

### Trust Direction and Attack Implications

```
Trust Direction    | Access Direction  | Attack Path
-------------------+-------------------+--------------------
A --> B (Outbound) | B --> A           | Compromise B to access A
A <-- B (Inbound)  | A --> B           | Compromise A to access B
A <-> B (Bidir)    | Both directions   | Compromise either to access both
```

```powershell
# Check trust direction and transitivity
Get-DomainTrust | Select SourceName,TargetName,TrustDirection,TrustType,TrustAttributes

# TrustDirection values:
# Bidirectional = 0x03, Inbound = 0x01, Outbound = 0x02
```

### SID Filtering Status

```powershell
# Check if SID Filtering (quarantine) is enabled
Get-ADTrust -Filter * | Select Name,SIDFilteringQuarantined,SIDFilteringForestAware

# PowerView -- check for SID filtering
Get-DomainTrust | Select TargetName,TrustAttributes
# FILTER_SIDS (0x00000004) in TrustAttributes = SID Filtering enabled
# TREAT_AS_EXTERNAL (0x00000040) = forest trust treated as external

# Netdom (built-in)
netdom trust CHILD.CORP.LOCAL /domain:CORP.LOCAL /quarantine
```

**SID Filtering Impact**:
- **Enabled** (default on forest/external trusts): Blocks SID history attacks across trust boundary. ExtraSIDs in tickets are filtered out.
- **Disabled** (default on intra-forest trusts): SID history is honored. A golden ticket with Enterprise Admin SID from a child domain grants forest-root access.

### Foreign Group Membership

```powershell
# Find users from other domains who are members of groups in current domain
Get-DomainForeignGroupMember
Get-DomainForeignGroupMember | Select GroupName,MemberName,MemberDomain

# Find users from current domain who are members of groups in other domains
Get-DomainForeignUser
Get-DomainForeignUser | Select UserName,UserDomain,GroupName,GroupDomain
```

### BloodHound Trust Visualization

```cypher
// All trust relationships
MATCH (d1:Domain)-[r:TrustedBy]->(d2:Domain) RETURN d1,r,d2

// Cross-domain attack paths from owned users
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group))
WHERE u.domain <> g.domain
RETURN p

// Foreign group memberships
MATCH (u:User)-[:MemberOf]->(g:Group)
WHERE u.domain <> g.domain
RETURN u.name, u.domain, g.name, g.domain

// Users with cross-domain admin access
MATCH (u:User)-[:AdminTo]->(c:Computer)
WHERE u.domain <> c.domain
RETURN u.name, u.domain, c.name, c.domain
```

### Attack Paths per Trust Type

| Trust Scenario | Attack Technique | Prerequisite |
|---------------|------------------|--------------|
| Child -> Parent (intra-forest) | Golden ticket with ExtraSIDs (Enterprise Admin SID) | Krbtgt hash of child domain |
| Parent -> Child | Standard lateral movement, ticket forging | Valid credentials or hash |
| External trust (no SID filtering) | SID history injection across trust | Domain admin in source domain |
| External trust (SID filtering ON) | Kerberoast across trust, credential theft | Valid user in trusted domain |
| Forest trust | Limited to explicit permissions, Kerberoast | Valid user, SID filtering blocks escalation |

## Detection & Evasion

| Activity | Detection Vector | Risk Level |
|----------|-----------------|------------|
| nltest /domain_trusts | Process creation logging (4688) | Very Low |
| Get-ADTrust | LDAP query -- normal admin activity | Very Low |
| Get-DomainTrustMapping | Multiple LDAP queries across domains | Low |
| BloodHound cross-domain collection | LDAP queries to multiple DCs | Low-Medium |
| Cross-domain authentication | Kerberos referral tickets (event 4769) | Low |

Trust enumeration is one of the safest activities in a red team engagement. The queries are indistinguishable from normal administrative activity and generate minimal log volume.

## Cross-References

- [AD Enumeration](./ad-enumeration.md)
- [BloodHound Guide](./bloodhound-guide.md)
- [Forest and Trust Attacks](../12-active-directory-deep-dive/forest-and-trust-attacks.md)
- [Golden/Silver Tickets](../06-credential-access/)

## References

- MITRE ATT&CK T1482: https://attack.mitre.org/techniques/T1482/
- Microsoft Trust Documentation: https://learn.microsoft.com/en-us/entra/identity/domain-services/concepts-forest-trust
- SID Filtering: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/sid-filtering
- Harmj0y - A Guide to Attacking Domain Trusts: https://harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/

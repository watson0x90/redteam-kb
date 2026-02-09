# Discovery

This section covers the techniques used to gain situational awareness within a compromised environment. Discovery is the internal reconnaissance phase that maps the network, identifies high-value targets, and informs the lateral movement strategy.

---

**Navigation:**
| Previous | Current | Next |
|----------|---------|------|
| [07 - Credential Access](../07-credential-access/README.md) | **08 - Discovery** | [09 - Lateral Movement](../09-lateral-movement/README.md) |

**MITRE ATT&CK Tactic:** [TA0007 - Discovery](https://attack.mitre.org/tactics/TA0007/)

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| AD Enumeration | [ad-enumeration.md](ad-enumeration.md) | T1087.002 | Medium | Enumerating users, groups, computers, OUs, GPOs, and trust relationships via LDAP and native tools |
| BloodHound Guide | [bloodhound-guide.md](bloodhound-guide.md) | T1087.002 | Medium-High | Running SharpHound collectors, ingesting data, and analyzing attack paths in BloodHound |
| Network Discovery | [network-discovery.md](network-discovery.md) | T1046 | Medium-High | Internal port scanning, ARP discovery, service enumeration, and network segmentation mapping |
| Domain Trust Mapping | [domain-trust-mapping.md](domain-trust-mapping.md) | T1482 | Medium | Enumerating forest and domain trusts, trust direction, and cross-trust attack paths |
| Cloud Discovery | [cloud-discovery.md](cloud-discovery.md) | T1580 | Medium | Enumerating cloud resources, IAM policies, storage, compute instances, and service configurations |

---

## Section Overview

Discovery is the intelligence-gathering phase that takes place inside the network perimeter. The quality of discovery directly determines the efficiency of lateral movement and the speed at which operators reach their objectives. Active Directory enumeration is typically the highest-priority discovery activity in Windows environments, as AD contains the complete map of users, groups, computers, permissions, and trust relationships. BloodHound has become the standard tool for visualizing AD attack paths, but operators must understand the OPSEC implications of running large-scale LDAP queries and SharpHound collection methods. Network discovery through internal scanning complements AD enumeration by identifying systems and services that may not be domain-joined. Domain trust mapping reveals cross-domain and cross-forest attack opportunities that significantly expand the engagement scope. Each technique in this section balances thoroughness against detection risk, with guidance on throttling queries and using targeted collection to minimize noise.

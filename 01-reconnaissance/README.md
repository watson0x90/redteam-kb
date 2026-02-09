# Reconnaissance

This section covers the techniques used to gather information about a target organization before any active exploitation begins. Reconnaissance is the first technical phase of the kill chain and directly shapes the attack surface analysis, target selection, and initial access strategy.

---

**Navigation:**
| Previous | Current | Next |
|----------|---------|------|
| [00 - Methodology](../00-methodology/README.md) | **01 - Reconnaissance** | [02 - Initial Access](../02-initial-access/README.md) |

**MITRE ATT&CK Tactic:** [TA0043 - Reconnaissance](https://attack.mitre.org/tactics/TA0043/)

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| Passive Recon | [passive-recon.md](passive-recon.md) | T1593, T1596 | Low | OSINT, certificate transparency, social media, breach data, and metadata harvesting |
| Active Scanning | [active-scanning.md](active-scanning.md) | T1595 | High | Port scanning, service fingerprinting, and vulnerability scanning against live targets |
| DNS Enumeration | [dns-enumeration.md](dns-enumeration.md) | T1590.002 | Medium | Zone transfers, subdomain brute-forcing, DNS record analysis, and passive DNS |
| SMB Enumeration | [smb-enumeration.md](smb-enumeration.md) | T1135 | High | Share enumeration, null sessions, user listing, and SMB signing analysis |
| SNMP Enumeration | [snmp-enumeration.md](snmp-enumeration.md) | T1046 | Medium | Community string guessing, MIB walking, and extracting network configuration |
| LDAP Enumeration | [ldap-enumeration.md](ldap-enumeration.md) | T1087.002 | Medium | Anonymous binds, user and group enumeration, and LDAP query crafting |
| Web Recon | [web-recon.md](web-recon.md) | T1595.002 | Medium | Directory brute-forcing, virtual host discovery, technology fingerprinting, and API enumeration |
| Cloud Recon | [cloud-recon.md](cloud-recon.md) | T1580 | Low-Medium | Cloud storage bucket discovery, tenant enumeration, and exposed cloud service identification |

---

## Section Overview

Reconnaissance is the intelligence-gathering phase that determines the quality of every subsequent attack step. The section is divided between passive techniques (which leave no trace on the target) and active techniques (which interact directly with target systems and carry detection risk). Effective operators layer multiple reconnaissance methods to build a comprehensive target profile including network topology, technology stack, organizational structure, and credential exposure. The transition from passive to active recon should be deliberate, with each escalation in interaction justified by operational need and controlled by OPSEC discipline.

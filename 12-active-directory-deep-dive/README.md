# Active Directory Deep Dive

This section provides a comprehensive, in-depth treatment of Active Directory attack and defense techniques. While AD concepts appear throughout other kill chain phases, this section consolidates advanced AD tradecraft into a single dedicated reference covering fundamentals through advanced forest-level attacks.

---

**Navigation:**
| Previous | Current | Next |
|----------|---------|------|
| [11 - Command & Control](../11-command-and-control/README.md) | **12 - Active Directory Deep Dive** | [13 - Cloud Security](../13-cloud-security/README.md) |

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| AD Fundamentals | [ad-fundamentals.md](ad-fundamentals.md) | N/A | N/A | Core AD architecture, LDAP, Kerberos, NTLM, replication, and security principals |
| AD Attack Path Methodology | [ad-attack-path-methodology.md](ad-attack-path-methodology.md) | T1087.002 | Medium | Systematic approach to identifying and chaining AD attack paths from initial foothold to DA |
| Kerberos Attacks Deep Dive | [kerberos-attacks-deep-dive.md](kerberos-attacks-deep-dive.md) | T1558 | Medium-High | Comprehensive Kerberos exploitation: AS-REP, Kerberoasting, delegation, S4U, PAC abuse |
| ADCS Attacks | [adcs-attacks.md](adcs-attacks.md) | T1649 | Medium-High | Active Directory Certificate Services exploitation: ESC1 through ESC8 and beyond |
| AD Persistence Deep Dive | [ad-persistence-deep-dive.md](ad-persistence-deep-dive.md) | T1098 | High | Golden/Silver/Diamond tickets, AdminSDHolder, SID History, DCShadow, and DSRM abuse |
| Forest & Trust Attacks | [forest-and-trust-attacks.md](forest-and-trust-attacks.md) | T1482 | High | Cross-forest attacks, SID filtering bypass, trust key extraction, and PAM trust abuse |
| Azure AD Integration | [azure-ad-integration.md](azure-ad-integration.md) | T1078.004 | Medium-High | Hybrid identity attacks: Azure AD Connect, PHS/PTA abuse, seamless SSO, and cloud-to-on-prem pivoting |
| gMSA & MSA Abuse | [gmsa-and-msa-abuse.md](gmsa-and-msa-abuse.md) | T1078 | Medium | Group Managed Service Account password extraction and managed service account abuse |
| AD Defense & Hardening | [ad-defense-and-hardening.md](ad-defense-and-hardening.md) | N/A | N/A | Tiered administration, PAW deployment, credential hygiene, and AD security monitoring |

---

## Section Overview

Active Directory remains the central identity and access management system in the vast majority of enterprise environments, making it the primary target for red team operations. This section goes beyond the individual technique references found elsewhere in the knowledge base and provides a holistic treatment of AD security. It begins with fundamentals -- understanding how LDAP, Kerberos, and NTLM authentication actually work at the protocol level -- because effective attack and defense both require this foundation. The attack path methodology file provides a systematic framework for chaining individual techniques into complete domain compromise paths. Dedicated deep dives into Kerberos attacks and ADCS exploitation cover the most impactful modern attack surfaces, while the persistence and forest trust sections address maintaining access and expanding scope. The Azure AD integration section addresses the increasingly common hybrid identity architecture where on-premises AD connects to cloud identity providers, creating unique cross-boundary attack opportunities. The section concludes with defense and hardening guidance, enabling operators to provide actionable remediation recommendations alongside their findings.

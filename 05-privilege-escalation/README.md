# Privilege Escalation

This section covers the techniques used to gain higher-level permissions on a system or within a domain. Privilege escalation transforms a low-privilege foothold into administrative or SYSTEM-level access, unlocking the full range of post-exploitation capabilities.

---

**Navigation:**
| Previous | Current | Next |
|----------|---------|------|
| [04 - Persistence](../04-persistence/README.md) | **05 - Privilege Escalation** | [06 - Defense Evasion](../06-defense-evasion/README.md) |

**MITRE ATT&CK Tactic:** [TA0004 - Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| Windows Local Privesc | [windows-local-privesc.md](windows-local-privesc.md) | T1068 | Medium | Service misconfigurations, unquoted paths, DLL hijacking, token manipulation, and kernel exploits |
| UAC Bypass | [uac-bypass.md](uac-bypass.md) | T1548.002 | Medium | Techniques to bypass User Account Control and elevate from medium to high integrity |
| AD Privilege Escalation | [ad-privilege-escalation.md](ad-privilege-escalation.md) | T1078.002 | Medium-High | Domain escalation paths including Group Policy, AdminSDHolder, and domain trust abuse |
| Kerberos Attacks | [kerberos-attacks.md](kerberos-attacks.md) | T1558 | Medium | Kerberoasting, AS-REP Roasting, and Kerberos delegation abuse for privilege escalation |
| Delegation Abuse | [delegation-abuse.md](delegation-abuse.md) | T1134 | Medium-High | Unconstrained, constrained, and resource-based constrained delegation exploitation |
| ACL Abuse | [acl-abuse.md](acl-abuse.md) | T1222 | Medium | Exploiting misconfigured Active Directory ACLs for privilege escalation paths |
| Certificate Abuse | [certificate-abuse.md](certificate-abuse.md) | T1649 | Medium-High | AD Certificate Services (ADCS) attacks including ESC1-ESC8 escalation vectors |
| LAPS Abuse | [laps-abuse.md](laps-abuse.md) | T1555 | Medium | Reading LAPS passwords, abusing LAPS delegation, and LAPS persistence techniques |
| GPO Abuse | [gpo-abuse.md](gpo-abuse.md) | T1484.001 | High | Abusing Group Policy Object edit rights for code execution across OUs |
| Linux Privesc | [linux-privesc.md](linux-privesc.md) | T1068 | Medium | SUID/SGID binaries, capabilities, cron jobs, sudo misconfigurations, kernel exploits, and 2025 CVEs |
| macOS Privesc | [macos-privesc.md](macos-privesc.md) | T1548.004, T1068 | Medium | TCC bypass, SIP bypass, dylib hijacking, authorization database, installer package abuse, XPC flaws |
| Cloud Privesc | [cloud-privesc.md](cloud-privesc.md) | T1078 | Medium | IAM policy escalation, role assumption chains, and cloud metadata service abuse |

---

## Section Overview

Privilege escalation is often the critical pivot point that determines engagement success. This section spans three domains: local Windows escalation, Active Directory domain escalation, and Linux/cloud escalation. Local techniques exploit misconfigurations in services, file permissions, and Windows integrity levels. Domain-level techniques leverage the complexity of Active Directory's permission model, Kerberos protocol, and certificate infrastructure to reach Domain Admin or equivalent access. The ADCS attack surface (ESC1 through ESC8) has become one of the most impactful escalation vectors in modern environments. Operators should use BloodHound and manual enumeration to identify the shortest viable escalation path and weigh each technique's noise level against the target's monitoring maturity.

# Command & Control

This section covers the infrastructure, protocols, and frameworks used to maintain communication between the operator and compromised systems. Command and control (C2) is the backbone that enables all post-exploitation activity.

---

**Navigation:**
| Previous | Current | Next |
|----------|---------|------|
| [10 - Collection & Exfiltration](../10-collection-and-exfiltration/README.md) | **11 - Command & Control** | [12 - Active Directory Deep Dive](../12-active-directory-deep-dive/README.md) |

**MITRE ATT&CK Tactic:** [TA0011 - Command and Control](https://attack.mitre.org/tactics/TA0011/)

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| C2 Frameworks | [c2-frameworks.md](c2-frameworks.md) | T1219 | Varies | Comparison of Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel, and other C2 platforms |
| C2 Infrastructure | [c2-infrastructure.md](c2-infrastructure.md) | T1583 | Medium | Redirectors, domain fronting, CDN abuse, cloud-hosted infrastructure, and OPSEC hardening |
| DNS C2 | [dns-c2.md](dns-c2.md) | T1071.004 | Low-Medium | DNS-based command and control channels for restrictive network environments |
| Covert Channels | [covert-channels.md](covert-channels.md) | T1071 | Low-Medium | Steganography, social media C2, legitimate service abuse, and protocol tunneling |

---

## Section Overview

Command and control infrastructure is the lifeline between the operator and the target environment. A well-architected C2 setup provides reliable, stealthy communication that survives network disruptions and resists defender attribution. This section covers both the strategic architecture of C2 infrastructure (redirectors, domain categorization, certificate management, traffic profiles) and the tactical selection of C2 frameworks for specific engagement requirements. Modern C2 must contend with TLS inspection, DNS monitoring, JA3/JA3S fingerprinting, and behavioral analysis of network traffic patterns. Operators should deploy layered C2 channels -- a primary channel for regular operations, a secondary channel for resilience, and a tertiary low-and-slow channel for long-term persistence -- each using different protocols and infrastructure to prevent single-point-of-failure compromise. The section also addresses DNS tunneling and covert channels as options for environments with restrictive egress policies where traditional HTTP/S C2 is not viable.

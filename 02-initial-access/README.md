# Initial Access

This section covers the techniques used to gain a first foothold inside the target environment. Initial access is the transition from external reconnaissance to internal operations and represents one of the highest-risk phases for detection.

---

**Navigation:**
| Previous | Current | Next |
|----------|---------|------|
| [01 - Reconnaissance](../01-reconnaissance/README.md) | **02 - Initial Access** | [03 - Execution](../03-execution/README.md) |

**MITRE ATT&CK Tactic:** [TA0001 - Initial Access](https://attack.mitre.org/tactics/TA0001/)

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| Phishing Payloads | [phishing-payloads.md](phishing-payloads.md) | T1566 | High | Spear-phishing attachments, links, and service-based phishing with payload delivery |
| Password Attacks | [password-attacks.md](password-attacks.md) | T1110 | Medium-High | Password spraying, credential stuffing, brute-force, and default credential exploitation |
| Exploit Public-Facing Apps | [exploit-public-apps.md](exploit-public-apps.md) | T1190 | High | Exploiting web applications, VPNs, mail gateways, and other internet-facing services |
| Supply Chain | [supply-chain.md](supply-chain.md) | T1195 | Low-Medium | Compromising software supply chains, package managers, and update mechanisms |
| Trusted Relationships | [trusted-relationships.md](trusted-relationships.md) | T1199 | Medium | Leveraging partner, vendor, or contractor access to pivot into the target environment |
| External Remote Services | [external-remote-services.md](external-remote-services.md) | T1133 | Medium | Abusing VPNs, RDP gateways, Citrix, and other remote access services with valid credentials |
| M365 Initial Access | [office365-initial-access.md](office365-initial-access.md) | T1566.002, T1528 | Medium-High | Teams phishing, SharePoint payload delivery, QR code phishing, BitB, AiTM frameworks, calendar attacks |
| Web Application Attacks | [web-application-attacks.md](web-application-attacks.md) | T1190 | High | SQL injection, SSRF, deserialization, SSTI, XXE, authentication bypass, and file upload attacks |
| CI/CD Pipeline Attacks | [cicd-pipeline-attacks.md](cicd-pipeline-attacks.md) | T1195.002 | Medium-High | GitHub Actions, GitLab CI, Jenkins, Azure DevOps exploitation and supply chain compromise |
| Exchange Exploitation | [exchange-exploitation.md](exchange-exploitation.md) | T1190, T1114 | High | Exchange Server CVE chains (ProxyShell/ProxyLogon), email authentication bypass, SMTP exploitation |
| Wireless & Physical Attacks | [wireless-physical-attacks.md](wireless-physical-attacks.md) | T1200 | Medium | WiFi attacks, Bluetooth exploitation, HID payloads, network implants, RFID/NFC cloning |

---

## Section Overview

Initial access is where the engagement transitions from planning and reconnaissance into active compromise. This phase demands careful balancing of payload effectiveness against detection risk. Phishing remains the most common vector for red teams, but mature targets increasingly require operators to exploit public-facing applications or leverage trusted relationships. Each technique in this section includes considerations for payload construction, delivery mechanism, and the immediate post-exploitation steps required to stabilize access before the foothold is lost. Operators should coordinate initial access timing with their C2 infrastructure readiness and have contingency vectors prepared in case the primary approach is burned.

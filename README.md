# Red Team Operations - Technical Knowledge Base

> A comprehensive technical reference for red team operations, organized along the **MITRE ATT&CK framework**. Built as a structured knowledge base for demonstrating depth and breadth across offensive security domains -- from initial access through exfiltration, with emphasis on Active Directory, cloud environments, and operational tradecraft.

---

## Quick Navigation

| #  | Section | Directory | Description |
|----|---------|-----------|-------------|
| 00 | **Methodology & Leadership** | [`00-methodology/`](./00-methodology/README.md) | Engagement lifecycle, rules of engagement, threat modeling, purple team, reporting, team management, lab infrastructure. |
| 01 | **Reconnaissance** | [`01-reconnaissance/`](./01-reconnaissance/README.md) | OSINT, active scanning, DNS/SMB/SNMP/LDAP enumeration, web recon, cloud asset discovery. |
| 02 | **Initial Access** | [`02-initial-access/`](./02-initial-access/README.md) | Phishing payloads, password attacks, public app exploitation, supply chain, trusted relationships. |
| 03 | **Execution** | [`03-execution/`](./03-execution/README.md) | PowerShell, .NET, WMI, LOLBAS, process injection, scripting engines. |
| 04 | **Persistence** | [`04-persistence/`](./04-persistence/README.md) | Registry, scheduled tasks, services, COM hijacking, WMI subscriptions, Golden Tickets, Skeleton Key, cloud persistence. |
| 05 | **Privilege Escalation** | [`05-privilege-escalation/`](./05-privilege-escalation/README.md) | Windows local privesc, UAC bypass, Kerberos attacks, delegation, ACL abuse, ADCS, LAPS, GPO, Linux, cloud IAM. |
| 06 | **Defense Evasion** | [`06-defense-evasion/`](./06-defense-evasion/README.md) | AMSI bypass, ETW evasion, AV/EDR evasion, AppLocker bypass, logging evasion, network evasion, CLM bypass. |
| 07 | **Credential Access** | [`07-credential-access/`](./07-credential-access/README.md) | LSASS dumping, SAM/LSA secrets, DCSync, DPAPI, Kerberos creds, NTLM theft, password cracking, cloud credentials. |
| 08 | **Discovery** | [`08-discovery/`](./08-discovery/README.md) | AD enumeration, BloodHound, network discovery, domain trust mapping, cloud resource enumeration. |
| 09 | **Lateral Movement** | [`09-lateral-movement/`](./09-lateral-movement/README.md) | PtH, PtT, Overpass-the-Hash, WMI, WinRM, PsExec, DCOM, RDP, NTLM relay, SSH, MSSQL, cloud lateral. |
| 10 | **Collection & Exfiltration** | [`10-collection-and-exfiltration/`](./10-collection-and-exfiltration/README.md) | Data staging, exfiltration channels (DNS, HTTPS, stego), cloud exfiltration. |
| 11 | **Command & Control** | [`11-command-and-control/`](./11-command-and-control/README.md) | C2 framework comparison, infrastructure design, DNS C2, covert channels. |
| 12 | **AD Deep Dive** | [`12-active-directory-deep-dive/`](./12-active-directory-deep-dive/README.md) | AD fundamentals, attack path methodology, Kerberos deep dive, ADCS, persistence, trust attacks, Azure AD, gMSA, defense. |
| 13 | **Cloud Security** | [`13-cloud-security/`](./13-cloud-security/README.md) | Cloud methodology, AWS/Azure/GCP attack techniques, cloud tools reference. |
| 14 | **Impact** | [`14-impact/`](./14-impact/README.md) | Ransomware simulation, data destruction assessment, business impact framing. |
| 15 | **Code Examples** | [`15-code-examples/`](./15-code-examples/README.md) | Process injection, syscalls (Hell's/Halo's Gate), COFF loaders, C2 channels, shellcode, evasion implementations. |
| A  | **Appendices** | [`appendices/`](./appendices/README.md) | PowerShell, Impacket, Cobalt Strike cheatsheets, BloodHound queries, Windows internals, detection notes. |

---

## Key References

These cross-cutting reference documents tie the knowledge base together and provide quick-lookup capability during review.

| Document | Purpose |
|----------|---------|
| [**MITRE ATT&CK Index**](./MITRE_ATTACK_INDEX.md) | Complete mapping of every technique to its ATT&CK ID, tactic, and file location. |
| [**Tools Arsenal**](./TOOLS_ARSENAL.md) | Consolidated inventory of all offensive tools with usage context and OPSEC notes. |
| [**Glossary**](./GLOSSARY.md) | Definitions for acronyms, jargon, and domain-specific terminology. |

---

## Knowledge Base Structure

Every topic file follows a **standard template** for consistency:

```
1. MITRE ATT&CK Mapping     - Technique ID(s), tactic(s), sub-technique references
2. Strategic Overview        - Why it matters, when to use, risk/reward tradeoff
3. Technical Deep-Dive       - Step-by-step with commands, tools, and variations
4. Detection & Evasion       - Defender visibility, OPSEC considerations
5. Cross-References          - Links to related techniques in this knowledge base
```

---

## Reading Paths

### Active Directory Security

| Order | Section | Focus Areas |
|:-----:|---------|-------------|
| 1 | [12 - AD Deep Dive](./12-active-directory-deep-dive/README.md) | Fundamentals, attack paths, Kerberos, ADCS |
| 2 | [08 - Discovery](./08-discovery/README.md) | AD enumeration, BloodHound, trust mapping |
| 3 | [07 - Credential Access](./07-credential-access/README.md) | DCSync, LSASS, Kerberoasting, DPAPI |
| 4 | [05 - Privilege Escalation](./05-privilege-escalation/README.md) | ACL abuse, delegation, ADCS, GPO |
| 5 | [09 - Lateral Movement](./09-lateral-movement/README.md) | PtH, PtT, NTLM relay, DCOM |
| 6 | [04 - Persistence](./04-persistence/README.md) | Golden/Diamond Tickets, DCShadow, AdminSDHolder |

### Cloud Security

| Order | Section | Focus Areas |
|:-----:|---------|-------------|
| 1 | [13 - Cloud Security](./13-cloud-security/README.md) | Methodology, AWS/Azure/GCP attack techniques |
| 2 | [01 - Reconnaissance](./01-reconnaissance/README.md) | Cloud OSINT, S3/blob discovery |
| 3 | [02 - Initial Access](./02-initial-access/README.md) | OAuth abuse, credential stuffing |
| 4 | [05 - Privilege Escalation](./05-privilege-escalation/README.md) | IAM escalation, role chaining |
| 5 | [12 - AD Deep Dive](./12-active-directory-deep-dive/README.md) | Azure AD integration, hybrid pivoting |
| 6 | [10 - Collection & Exfiltration](./10-collection-and-exfiltration/README.md) | Cloud exfiltration channels |

### Methodology & Leadership

| Order | Section | Focus Areas |
|:-----:|---------|-------------|
| 1 | [00 - Methodology](./00-methodology/README.md) | Engagement lifecycle, ROE, threat modeling |
| 2 | [14 - Impact](./14-impact/README.md) | Business impact framing, executive reporting |
| 3 | [11 - Command & Control](./11-command-and-control/README.md) | C2 architecture, infrastructure design |
| 4 | [06 - Defense Evasion](./06-defense-evasion/README.md) | OPSEC philosophy, detection awareness |
| 5 | [Appendices](./appendices/README.md) | Detection engineering notes, cheatsheets |

### Technical Deep-Dive (Code & Implementation)

| Order | Section | Focus Areas |
|:-----:|---------|-------------|
| 1 | [15 - Code Examples](./15-code-examples/README.md) | Process injection, syscalls, COFF loaders |
| 2 | [06 - Defense Evasion](./06-defense-evasion/README.md) | AV/EDR evasion theory |
| 3 | [03 - Execution](./03-execution/README.md) | Code injection, .NET execution |
| 4 | [07 - Credential Access](./07-credential-access/README.md) | LSASS dumping implementations |
| 5 | [11 - Command & Control](./11-command-and-control/README.md) | C2 protocol design |

### Full Kill Chain (End-to-End)

| Order | Section | Focus Areas |
|:-----:|---------|-------------|
| 1 | [00 - Methodology](./00-methodology/README.md) | Planning and scoping |
| 2 | [01 - Reconnaissance](./01-reconnaissance/README.md) | Target profiling |
| 3 | [02 - Initial Access](./02-initial-access/README.md) | Gaining first foothold |
| 4 | [03 - Execution](./03-execution/README.md) | Running payloads |
| 5 | [04 - Persistence](./04-persistence/README.md) | Maintaining access |
| 6 | [05 - Privilege Escalation](./05-privilege-escalation/README.md) | Elevating privileges |
| 7 | [06 - Defense Evasion](./06-defense-evasion/README.md) | Avoiding detection |
| 8 | [07 - Credential Access](./07-credential-access/README.md) | Harvesting credentials |
| 9 | [08 - Discovery](./08-discovery/README.md) | Mapping the environment |
| 10 | [09 - Lateral Movement](./09-lateral-movement/README.md) | Pivoting toward objectives |
| 11 | [10 - Collection & Exfiltration](./10-collection-and-exfiltration/README.md) | Achieving objectives |
| 12 | [11 - Command & Control](./11-command-and-control/README.md) | Maintaining communications |
| 13 | [14 - Impact](./14-impact/README.md) | Delivering findings |

---

## Usage Notes

- **Quick reference**: Use the Key References documents for rapid lookup of technique IDs, tool syntax, or terminology.
- **Cross-referencing**: Every topic file includes cross-references linking to related techniques.
- **Code examples**: Section 15 provides working implementations in C, C++, and Python for hands-on understanding.

---

*This knowledge base is maintained as a living document. Content reflects real-world operational experience and is aligned with the MITRE ATT&CK framework v14+.*

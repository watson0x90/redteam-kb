# Appendices & Quick References

This section contains cheat sheets, quick-reference guides, and supplementary material that supports the main knowledge base. These resources are designed for rapid lookup during engagements.

---

**Navigation:**
| Previous | Current | Next |
|----------|---------|------|
| [14 - Impact](../14-impact/README.md) | **Appendices** | -- |

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| PowerShell Cheatsheet | [powershell-cheatsheet.md](powershell-cheatsheet.md) | N/A | N/A | Essential PowerShell one-liners, cmdlets, and snippets for offensive operations |
| Impacket Cheatsheet | [impacket-cheatsheet.md](impacket-cheatsheet.md) | N/A | N/A | Quick reference for all Impacket tools: secretsdump, psexec, ntlmrelayx, getST, and more |
| Cobalt Strike Cheatsheet | [cobalt-strike-cheatsheet.md](cobalt-strike-cheatsheet.md) | N/A | N/A | Cobalt Strike Beacon commands, Aggressor scripts, and malleable C2 profile reference |
| BloodHound Queries | [bloodhound-queries.md](bloodhound-queries.md) | N/A | N/A | Custom Cypher queries for BloodHound: attack paths, ACL abuse, delegation, and AD hygiene |
| Windows Internals Reference | [windows-internals-reference.md](windows-internals-reference.md) | N/A | N/A | Key Windows internals concepts: tokens, integrity levels, sessions, security descriptors, and ETW |
| Detection Engineering Notes | [detection-engineering-notes.md](detection-engineering-notes.md) | N/A | N/A | Detection logic for common attack techniques to support purple team exercises and reporting |

---

## Section Overview

The appendices serve as a toolbox of ready-to-use reference material that complements the in-depth technique guides in the main knowledge base. Cheat sheets for PowerShell, Impacket, and Cobalt Strike provide the exact command syntax needed during live operations without requiring operators to search through documentation. The BloodHound queries collection includes both standard attack path queries and custom Cypher queries for identifying non-obvious escalation routes and AD hygiene issues. The Windows internals reference provides the foundational operating system knowledge that underpins many attack and evasion techniques -- understanding tokens, integrity levels, and security descriptors is essential for advanced exploitation. Detection engineering notes bridge the gap between offense and defense by documenting the telemetry and detection logic for each major attack technique, enabling operators to provide specific, actionable detection recommendations in their reports.

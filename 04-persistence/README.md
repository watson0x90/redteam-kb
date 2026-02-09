# Persistence

This section covers the techniques used to maintain access to compromised systems across reboots, credential changes, and remediation attempts. Persistence ensures that operator access survives beyond the initial foothold.

---

**Navigation:**
| Previous | Current | Next |
|----------|---------|------|
| [03 - Execution](../03-execution/README.md) | **04 - Persistence** | [05 - Privilege Escalation](../05-privilege-escalation/README.md) |

**MITRE ATT&CK Tactic:** [TA0003 - Persistence](https://attack.mitre.org/tactics/TA0003/)

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| Registry Persistence | [registry-persistence.md](registry-persistence.md) | T1547.001 | Medium | Run keys, RunOnce, Winlogon, and other registry-based autostart mechanisms |
| Scheduled Tasks | [scheduled-tasks.md](scheduled-tasks.md) | T1053.005 | Medium | Task Scheduler abuse for recurring execution with configurable triggers |
| Services Persistence | [services-persistence.md](services-persistence.md) | T1543.003 | Medium-High | Creating or modifying Windows services for persistent code execution |
| Startup Folder | [startup-folder.md](startup-folder.md) | T1547.001 | Low-Medium | Dropping payloads into user or common startup directories |
| COM Hijacking | [com-hijacking.md](com-hijacking.md) | T1546.015 | Low | Hijacking COM object registry entries to achieve persistence through legitimate application loading |
| WMI Event Subscriptions | [wmi-event-subscriptions.md](wmi-event-subscriptions.md) | T1546.003 | Medium | Permanent WMI event consumers for fileless persistence tied to system events |
| DCShadow Persistence | [dcshadow-persistence.md](dcshadow-persistence.md) | T1207 | Very High | Registering a rogue domain controller to inject changes directly into AD replication |
| Golden Ticket Persistence | [golden-ticket-persistence.md](golden-ticket-persistence.md) | T1558.001 | High | Forging TGTs with the KRBTGT hash for domain-wide persistent access |
| Skeleton Key | [skeleton-key.md](skeleton-key.md) | T1556.001 | Very High | Patching LSASS on domain controllers to add a master password for any account |
| SSH Backdoors | [ssh-backdoors.md](ssh-backdoors.md) | T1098.004 | Medium | Authorized key injection, SSH config manipulation, and PAM backdoors on Linux targets |
| Cloud Persistence | [cloud-persistence.md](cloud-persistence.md) | T1098 | Medium | Service principals, OAuth app registrations, IAM key creation, and federated identity abuse |
| Outlook Persistence | [outlook-persistence.md](outlook-persistence.md) | T1137.003, T1137.004, T1137.005 | Medium | Malicious Outlook rules, custom forms with VBScript, and folder home page abuse via Ruler |
| Linux Persistence | [linux-persistence.md](linux-persistence.md) | T1053.003, T1543.002, T1547.006 | Medium | Cron, systemd, PAM backdoors, LD_PRELOAD, shell config, kernel modules, eBPF persistence |
| macOS Persistence | [macos-persistence.md](macos-persistence.md) | T1543.004, T1547.011, T1547.015 | Medium | LaunchAgents/Daemons, login items, dylib hijacking, Folder Actions, authorization plugins |

---

## Section Overview

Persistence is a critical investment decision during an engagement. Every persistence mechanism carries a trade-off between reliability, stealth, and the blast radius if discovered. Lightweight mechanisms like registry run keys and startup folders are easy to deploy but also easy to detect and remediate. Domain-level persistence such as Golden Tickets and DCShadow provide powerful, long-lived access but generate significant forensic evidence and carry high OPSEC risk during deployment. Operators should layer persistence at multiple levels (user-level, admin-level, domain-level) and across different mechanism types to ensure that remediation of one vector does not eliminate all access. Each file in this section covers the deployment procedure, detection signatures, cleanup requirements, and situational guidance for when to use each technique.

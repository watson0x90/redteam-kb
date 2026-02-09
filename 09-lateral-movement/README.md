# Lateral Movement

This section covers the techniques used to move between systems within a compromised environment. Lateral movement transforms a single-host compromise into network-wide access and is the primary mechanism for reaching high-value targets.

---

**Navigation:**
| Previous | Current | Next |
|----------|---------|------|
| [08 - Discovery](../08-discovery/README.md) | **09 - Lateral Movement** | [10 - Collection & Exfiltration](../10-collection-and-exfiltration/README.md) |

**MITRE ATT&CK Tactic:** [TA0008 - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| Pass-the-Hash | [pass-the-hash.md](pass-the-hash.md) | T1550.002 | High | Authenticating with NTLM hashes without knowing the plaintext password |
| Pass-the-Ticket | [pass-the-ticket.md](pass-the-ticket.md) | T1550.003 | Medium-High | Injecting stolen Kerberos tickets to authenticate as another user |
| Overpass-the-Hash | [overpass-the-hash.md](overpass-the-hash.md) | T1550.002 | Medium | Converting an NTLM hash into a Kerberos TGT for stealthier lateral movement |
| WMI Lateral | [wmi-lateral.md](wmi-lateral.md) | T1047 | Medium | Remote process execution via WMI with no service installation or binary drop |
| WinRM Lateral | [winrm-lateral.md](winrm-lateral.md) | T1021.006 | Medium | PowerShell Remoting and WinRM-based lateral movement using legitimate management protocols |
| PsExec / SMBExec | [psexec-smbexec.md](psexec-smbexec.md) | T1021.002 | High | Remote service creation over SMB for command execution on target systems |
| DCOM Lateral | [dcom-lateral.md](dcom-lateral.md) | T1021.003 | Low-Medium | Abusing Distributed COM objects (MMC20, ShellWindows, ShellBrowserWindow) for remote execution |
| RDP Lateral | [rdp-lateral.md](rdp-lateral.md) | T1021.001 | Medium | Remote Desktop Protocol access, session hijacking, and restricted admin mode abuse |
| NTLM Relay Lateral | [ntlm-relay-lateral.md](ntlm-relay-lateral.md) | T1557.001 | High | Relaying captured NTLM authentication to other services for unauthorized access |
| SSH Lateral | [ssh-lateral.md](ssh-lateral.md) | T1021.004 | Low-Medium | SSH-based lateral movement in Linux/Unix environments and hybrid networks |
| MSSQL Lateral | [mssql-lateral.md](mssql-lateral.md) | T1021 | Medium | SQL Server linked servers, xp_cmdshell, and database trust chain abuse |
| Cloud Lateral | [cloud-lateral.md](cloud-lateral.md) | T1021 | Medium | Cross-account role assumption, shared service exploitation, and hybrid AD-cloud pivoting |
| Network Pivoting | [network-pivoting.md](network-pivoting.md) | T1572, T1090 | Medium | SSH tunneling, Chisel, Ligolo-ng, SOCKS proxying, DNS/ICMP tunneling, double pivoting |
| Database Exploitation | [database-exploitation.md](database-exploitation.md) | T1210 | Medium-High | MSSQL, Oracle, PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch exploitation for lateral movement |

---

## Section Overview

Lateral movement is the phase where operational tradecraft is most visible to defenders. Every lateral movement technique generates network traffic, authentication events, and often new process creation on the target host. This section covers the full spectrum from well-known techniques like Pass-the-Hash and PsExec to more nuanced approaches like DCOM abuse and MSSQL linked server chains. The choice of lateral movement technique should be driven by the credentials available (NTLM hash vs. Kerberos ticket vs. plaintext), the target's monitoring posture (what authentication events are being collected), and the target's network architecture (what protocols are permitted between segments). Operators should prefer techniques that blend with legitimate administrative traffic in the environment and avoid techniques that create persistent artifacts like services or scheduled tasks unless persistence is the explicit goal.

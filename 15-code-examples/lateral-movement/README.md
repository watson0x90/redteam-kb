# Lateral Movement Techniques - Code Reference

> **AUTHORIZED USE ONLY**: All examples in this reference are intended exclusively for
> authorized security testing (penetration tests, red team engagements) performed under
> explicit written client authorization as defined in the Rules of Engagement (ROE).
> Unauthorized use of these techniques is illegal and unethical.

## Overview

Lateral movement (MITRE ATT&CK TA0008) encompasses techniques that adversaries use to
pivot through a network after gaining initial access. These techniques leverage legitimate
authentication protocols and remote management infrastructure -- NTLM, Kerberos, DCOM,
WMI -- turning trusted Windows subsystems into pivot mechanisms.

For red team operators, understanding these at the code level is critical for two reasons:

1. **Tool Development**: Commercial C2 frameworks abstract these techniques, but when
   tooling fails or is detected, operators must understand the underlying APIs and
   protocols to improvise. Building custom lateral movement tooling that avoids known
   signatures requires deep knowledge of the authentication and execution primitives.
2. **Detection Engineering**: Defenders who understand the exact API call chains,
   network artifacts, and log entries produced by each technique can build far more
   robust detection rules than those relying solely on vendor signatures.

Understanding *why* Pass-the-Hash works at the NTLM protocol level, or *how* a Golden
Ticket forges a PAC structure, is foundational knowledge that distinguishes senior
practitioners from tool operators.

## Technique Comparison

| Technique | MITRE ID | Stealth | Complexity | Detection Risk | Primary Detection Source |
|---|---|---|---|---|---|
| Pass the Hash | T1550.002 | Medium | Low | **Medium-High** | Event 4624 Type 9, Sysmon 10 (LSASS) |
| Golden Ticket | T1558.001 | High | High | **Medium** | Event 4769 RC4 downgrade, TGT anomalies |
| Silver Ticket | T1558.002 | Very High | High | **Low-Medium** | PAC validation failure, service anomalies |
| DCOM Execution | T1021.003 | High | Medium | **Low-Medium** | Event 4688 unusual parent (mmc.exe) |
| WMI Remote Exec | T1047 | Medium-High | Low-Medium | **Medium** | Event 4688 WmiPrvSE parent, Sysmon 20/21 |

### Detection Risk Explained

- **Medium-High**: Monitored by default in most enterprise EDR deployments.
- **Medium**: Requires tuned detection rules and correlation across data sources.
- **Low-Medium**: Fewer out-of-box detections; requires protocol-level analysis.

## File Index

| Topic | File | Languages | Detection Risk | Description |
|-------|------|-----------|----------------|-------------|
| Pass the Hash | [pth-implementation.md](pth-implementation.md) | C, Python | Medium-High | NTLM protocol internals, NTLMv2 response computation, LSASS credential patching |
| Kerberos Ticket Forging | [kerberos-ticket-forging.md](kerberos-ticket-forging.md) | C, Python | Medium | Golden/Silver/Diamond Ticket construction, PAC structure, ASN.1 encoding |
| DCOM Execution | [dcom-execution.md](dcom-execution.md) | C, Python | Low-Medium | COM/DCOM architecture, MMC20.Application, ShellWindows, ShellBrowserWindow |
| WMI Remote Execution | [wmi-remote-exec.md](wmi-remote-exec.md) | C, Python | Medium | Win32_Process.Create, WMI event subscriptions, IWbemServices COM interface |

## Key Defensive Data Sources

These are the primary telemetry sources for detecting lateral movement techniques:

- **Windows Security Event 4624** - Logon events (Type 3 network, Type 9 NewCredentials, Type 10 RDP)
- **Windows Security Event 4648** - Explicit credential logon (RunAs-style operations)
- **Windows Security Event 4769** - Kerberos Service Ticket operations
- **Windows Security Event 4688** - Process creation with parent-child tracking
- **Sysmon Event ID 1** - Process creation with full command line and hash
- **Sysmon Event ID 3** - Network connections (DCOM/WMI RPC traffic)
- **Sysmon Event ID 10** - Process access (LSASS handle acquisition)
- **Sysmon Event ID 20/21** - WMI event consumer/binding creation
- **ETW (Event Tracing for Windows)** - Microsoft-Windows-WMI-Activity, NTLM operational logs
- **Network Traffic Analysis** - NTLM over SMB, Kerberos TGT/TGS patterns, RPC endpoint mapper

## References

- MITRE ATT&CK TA0008: https://attack.mitre.org/tactics/TA0008/
- MITRE ATT&CK T1550.002: https://attack.mitre.org/techniques/T1550/002/
- MITRE ATT&CK T1558: https://attack.mitre.org/techniques/T1558/
- "Windows Internals" by Russinovich, Solomon, and Ionescu
- Microsoft NTLM Documentation: MS-NLMP specification
- Microsoft Kerberos Documentation: MS-KILE specification
- Lateral Movement Narrative: [09-lateral-movement](../../09-lateral-movement/README.md)

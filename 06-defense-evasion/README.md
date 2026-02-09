# Defense Evasion

This section covers the techniques used to avoid detection by security controls throughout an engagement. Defense evasion is not a single phase but a continuous discipline applied across every stage of the kill chain.

---

**Navigation:**
| Previous | Current | Next |
|----------|---------|------|
| [05 - Privilege Escalation](../05-privilege-escalation/README.md) | **06 - Defense Evasion** | [07 - Credential Access](../07-credential-access/README.md) |

**MITRE ATT&CK Tactic:** [TA0005 - Defense Evasion](https://attack.mitre.org/tactics/TA0005/)

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| AMSI Bypass | [amsi-bypass.md](amsi-bypass.md) | T1562.001 | High | Patching or unhooking the Antimalware Scan Interface to execute unscanned payloads |
| ETW Evasion | [etw-evasion.md](etw-evasion.md) | T1562.006 | High | Disabling or blinding Event Tracing for Windows to suppress telemetry |
| AV/EDR Evasion | [av-edr-evasion.md](av-edr-evasion.md) | T1562.001 | Very High | Unhooking userland APIs, direct syscalls, callback removal, and driver-level evasion |
| AppLocker Bypass | [applocker-bypass.md](applocker-bypass.md) | T1218 | Medium | Bypassing application whitelisting policies using trusted binaries and alternate execution paths |
| Logging Evasion | [logging-evasion.md](logging-evasion.md) | T1562.002 | High | Disabling or tampering with Windows Event Logs, Sysmon, and audit policies |
| Network Evasion | [network-evasion.md](network-evasion.md) | T1090 | Medium | Traffic encryption, domain fronting, protocol tunneling, and IDS/IPS evasion |
| Signature Evasion | [signature-evasion.md](signature-evasion.md) | T1027 | Medium | Obfuscation, encryption, packing, and payload transformation to defeat static signatures |
| CLM Bypass | [clm-bypass.md](clm-bypass.md) | T1059.001 | Medium | Escaping PowerShell Constrained Language Mode to regain full language capabilities |
| Anti-Forensics | [anti-forensics.md](anti-forensics.md) | T1070 | High | Timestomping, event log manipulation, artifact cleanup, memory forensics evasion, disk forensics evasion |
| EDR Internals | [edr-internals.md](edr-internals.md) | T1562.001 | N/A (Reference) | Kernel callbacks, minifilter drivers, ETW providers, user-mode hooks, PPL, EDR architecture reference |

---

## Section Overview

Defense evasion is the thread that runs through every other tactic in this knowledge base. Modern enterprise environments deploy layered defenses including AMSI for script scanning, ETW for telemetry collection, EDR agents for behavioral detection, AppLocker or WDAC for application control, and centralized logging infrastructure. Each layer must be understood and addressed by the operator. This section covers both the theoretical basis for each defensive control (how it works, what telemetry it generates) and the practical techniques for bypassing or blinding it. Critically, evasion techniques themselves generate artifacts -- patching AMSI triggers ETW events, disabling ETW may be detected by EDR, and unhooking EDR may be detected by kernel callbacks. Operators must understand these circular dependencies and sequence their evasion operations to minimize the detection window.

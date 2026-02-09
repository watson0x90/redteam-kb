# Process Injection Techniques - Code Reference

> **AUTHORIZED USE ONLY**: All examples in this reference are intended exclusively for
> authorized security testing (penetration tests, red team engagements) performed under
> explicit written client authorization as defined in the Rules of Engagement (ROE).
> Unauthorized use of these techniques is illegal and unethical.

## Overview

Process injection (MITRE ATT&CK T1055) is a category of techniques where code is
executed in the address space of a separate, typically legitimate, process. Adversaries
use these techniques to evade process-based defenses, elevate privileges, and access
other processes' data. Security professionals must understand them for two reasons:

1. **Red Team / Pentesting**: To simulate real adversary tradecraft during authorized
   engagements and validate that defensive controls detect or prevent these behaviors.
2. **Blue Team / Detection Engineering**: To build robust detection rules, understand
   indicator-of-attack (IoA) patterns, and tune EDR/SIEM tooling against these methods.

Understanding the API call chains, memory artifacts, and OS internals behind each
technique is foundational knowledge for any offensive or defensive security role.

## Technique Comparison

| Technique | MITRE Sub-ID | Stealth | Complexity | Detection Risk | Primary Detection Source |
|---|---|---|---|---|---|
| Classic Injection (CreateRemoteThread) | T1055.002 | Low | Low | **High** | Sysmon 8, ETW, EDR hooks |
| APC Queue Injection | T1055.004 | Medium | Medium | **Medium-High** | Sysmon 8, API monitoring |
| Thread Hijacking | T1055 | Medium | Medium | **Medium** | Thread suspension events |
| Process Hollowing (RunPE) | T1055.012 | Medium | High | **Medium-High** | Memory scanning, PEB analysis |
| DLL Injection | T1055.001 | Low-Med | Low-Med | **High** | Module load events (Sysmon 7) |
| Module Stomping | T1055 | High | High | **Low-Medium** | .text hash comparison |
| NT API Section Mapping | T1055 | High | High | **Low-Medium** | Section mapping ETW events |

### Detection Risk Explained

- **High**: Well-known pattern; most commercial EDRs detect by default.
- **Medium-High**: Detected by tuned environments; some default rules exist.
- **Medium**: Requires specific telemetry and custom rules.
- **Low-Medium**: Fewer out-of-box detections; requires advanced analysis.

## File Index

| File | Technique | Key APIs |
|---|---|---|
| [classic-injection.md](classic-injection.md) | CreateRemoteThread Injection | OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread |
| [apc-injection.md](apc-injection.md) | APC Queue Injection | QueueUserAPC, CreateToolhelp32Snapshot, OpenThread |
| [thread-hijacking.md](thread-hijacking.md) | Thread Context Hijacking | SuspendThread, GetThreadContext, SetThreadContext, ResumeThread |
| [process-hollowing.md](process-hollowing.md) | Process Hollowing (RunPE) | CreateProcess (SUSPENDED), NtUnmapViewOfSection, WriteProcessMemory |
| [dll-injection.md](dll-injection.md) | DLL Injection Variants | LoadLibraryA, CreateRemoteThread, Reflective Loading |
| [module-stomping.md](module-stomping.md) | Module Stomping | LoadLibraryExA, VirtualProtect, PE section parsing |
| [ntapi-injection.md](ntapi-injection.md) | NT API Section Mapping | NtCreateSection, NtMapViewOfSection |

## Key Defensive Data Sources

These are the primary telemetry sources used to detect process injection across all variants:

- **Sysmon Event ID 1** - Process creation (parent-child relationships)
- **Sysmon Event ID 7** - Image loaded (DLL load events)
- **Sysmon Event ID 8** - CreateRemoteThread detected
- **Sysmon Event ID 10** - Process access (OpenProcess with specific rights)
- **Sysmon Event ID 25** - Process tampering
- **ETW (Event Tracing for Windows)** - Microsoft-Windows-Threat-Intelligence provider
- **EDR Userland Hooks** - ntdll.dll / kernel32.dll API inline hooks
- **Memory Forensics** - Volatility / WinDbg analysis of VAD trees, PEB, loaded modules

## References

- MITRE ATT&CK T1055: https://attack.mitre.org/techniques/T1055/
- Elastic Security: Process Injection Detection
- Red Canary Threat Detection Report
- "Windows Internals" by Russinovich, Solomon, and Ionescu

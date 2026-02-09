# Persistence Mechanisms - Code Examples

MITRE ATT&CK Tactic: TA0003 - Persistence

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

This directory contains annotated code implementations for common Windows persistence mechanisms. Each file pairs working code with detection artifacts, OPSEC notes, and cross-references to the narrative knowledge base in `../../04-persistence/`.

The goal is not novelty but **clarity**: every code path is annotated with what forensic evidence it produces, which defensive tools detect it, and how operators can make informed risk decisions during authorized engagements.

## Table of Contents

| Topic | File | Languages | Detection Risk | Description |
|---|---|---|---|---|
| Registry Run Keys & Autostart | [registry-persistence-code.md](registry-persistence-code.md) | C, PowerShell | Medium-High | Registry autostart locations (Run, RunOnce, IFEO, AppInit_DLLs, Winlogon), transacted registry writes, and OPSEC comparison of key visibility |
| Scheduled Task Creation | [scheduled-task-creation.md](scheduled-task-creation.md) | C (COM), PowerShell, XML | High | Task Scheduler COM API usage, XML task definitions, hidden task techniques via SD manipulation, and detection in Event 4698 / Sysmon |
| WMI Event Subscriptions | [wmi-event-subscription.md](wmi-event-subscription.md) | C (COM), Python, MOF | Medium | Permanent WMI event subscriptions using EventFilter/Consumer/Binding triad, MOF compilation, namespace OPSEC tradeoffs |
| DLL Hijack Discovery | [dll-hijack-discovery.md](dll-hijack-discovery.md) | C, DEF files | Low-Medium | DLL search order exploitation, phantom DLL identification, proxy DLL construction with export forwarding, Process Monitor methodology |
| Windows Service Persistence | [service-persistence.md](service-persistence.md) | C | High | Service creation via SCM API, service DLL skeleton, modifying existing services as stealthier alternative, detection via Event 7045 |

## Usage Notes

- **Detection Risk** is a subjective rating based on default Windows auditing plus common EDR baselines (Sysmon, Defender for Endpoint).
- All C code compiles with MSVC (`cl.exe`) or MinGW (`x86_64-w64-mingw32-gcc`). Compilation instructions are included per file.
- PowerShell examples assume PowerShell 5.1+ unless noted.
- Cross-references to `../../04-persistence/` link to the narrative explanations; cross-references within this directory link to sibling code files.

## Compilation Quick Reference

```
# MSVC (Developer Command Prompt)
cl.exe /W4 /Fe:output.exe source.c advapi32.lib ole32.lib oleaut32.lib

# MinGW cross-compile from Linux
x86_64-w64-mingw32-gcc -o output.exe source.c -ladvapi32 -lole32 -loleaut32
```

## Related Knowledge Base Sections

- [Registry Persistence (Narrative)](../../04-persistence/registry-persistence.md)
- [Scheduled Tasks (Narrative)](../../04-persistence/scheduled-tasks.md)
- [WMI Persistence (Narrative)](../../04-persistence/wmi-persistence.md)
- [DLL Hijacking (Narrative)](../../04-persistence/dll-hijacking.md)
- [Service Persistence (Narrative)](../../04-persistence/service-persistence.md)
- [Detection Engineering](../../12-detection-engineering/)

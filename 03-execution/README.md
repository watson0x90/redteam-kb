# Execution

This section covers the techniques used to run adversary-controlled code on target systems. Execution is the mechanism through which all other tactical objectives are achieved, from deploying persistence to dumping credentials.

---

**Navigation:**
| Previous | Current | Next |
|----------|---------|------|
| [02 - Initial Access](../02-initial-access/README.md) | **03 - Execution** | [04 - Persistence](../04-persistence/README.md) |

**MITRE ATT&CK Tactic:** [TA0002 - Execution](https://attack.mitre.org/tactics/TA0002/)

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| PowerShell Execution | [powershell-execution.md](powershell-execution.md) | T1059.001 | High | PowerShell cradles, download strings, constrained language mode bypass, and AMSI considerations |
| .NET Execution | [dotnet-execution.md](dotnet-execution.md) | T1059 | Medium-High | In-memory .NET assembly loading, Reflection, and execute-assembly tradecraft |
| WMI Execution | [wmi-execution.md](wmi-execution.md) | T1047 | Medium | WMI process creation, event subscriptions, and remote execution via DCOM |
| LOLBins | [lolbins.md](lolbins.md) | T1218 | Low-Medium | Living-off-the-land binaries for proxy execution, download, and code signing bypass |
| Code Injection | [code-injection.md](code-injection.md) | T1055 | High | Process injection techniques including DLL injection, process hollowing, and thread hijacking |
| Scripting Engines | [scripting-engines.md](scripting-engines.md) | T1059 | Medium | VBScript, JScript, WSH, MSHTA, and alternative scripting runtime abuse |
| ClickFix Execution | [clickfix-execution.md](clickfix-execution.md) | T1204.004 | Medium | FakeCAPTCHA/ClickFix social engineering via clipboard injection; bypasses email gateways, browser sandboxing, and EDR |
| VDI/Citrix Breakout | [vdi-breakout.md](vdi-breakout.md) | T1059, T1218 | Medium | Citrix/VMware Horizon escape, kiosk breakout, application whitelisting bypass in restricted desktops |

---

## Section Overview

Execution is the enabler for every other phase of the kill chain. The choice of execution method directly impacts detection exposure, forensic artifacts, and operational flexibility. Modern red teams must navigate a layered defense stack including AMSI, Script Block Logging, ETW telemetry, and EDR behavioral detection. This section emphasizes the trade-offs between execution methods: PowerShell offers flexibility but heavy monitoring; .NET in-memory execution reduces disk artifacts but triggers CLR loading events; LOLBins blend into legitimate activity but have limited capability. Operators should select execution methods based on the target's defensive maturity and rotate techniques when indicators suggest detection.

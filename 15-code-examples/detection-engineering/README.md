# Detection Engineering Code Examples

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

Detection engineering is the discipline of building, testing, and refining the sensors and rules that
identify adversary activity. For red teamers, deep familiarity with detection engineering is not
optional -- it is a core professional requirement. You cannot credibly test an organization's
defenses without understanding what those defenses actually look for, how they parse telemetry,
and where their blind spots live.

This section contains working code examples for two foundational detection technologies:

1. **YARA rules** -- the pattern-matching language used by malware analysts and automated
   scanning pipelines to identify malicious files and memory regions.
2. **ETW (Event Tracing for Windows) consumers** -- the real-time telemetry framework that
   underpins nearly every modern EDR product on Windows.

Each file provides complete, commented code that a red teamer can deploy in a lab environment
to validate whether their tooling triggers known detection signatures. This is the essence of
purple teaming: build the detector, run your tool against it, observe whether it fires, then
iterate on both sides.

## Contents

| Topic | File | Languages | Purple Team Value | Description |
|---|---|---|---|---|
| YARA Rule Development | [yara-rule-development.md](yara-rule-development.md) | YARA, Python | Write detection rules for your own implants, then test evasion | Covers YARA syntax, five practical rules (process injection, shellcode, Cobalt Strike, PE anomalies, AMSI bypass), pe/math modules, and yara-python automation |
| ETW Consumer Code | [etw-consumer-code.md](etw-consumer-code.md) | C, Python | Build real-time monitors to validate your evasion techniques | Covers ETW architecture, five key security providers, C consumer with EVENT_RECORD parsing, Python consumer, and practical monitoring for CLR loading, image loads, and LSASS access |

## How to Use These Examples

1. **Lab first.** Deploy all code in an isolated test environment. Never run detection tooling
   against production systems without explicit coordination with the defending team.
2. **Build the detector.** Compile/run the detection code from these examples.
3. **Run your implant.** Execute your red team tooling in the monitored environment.
4. **Observe.** Did the rule fire? Did the ETW consumer log the event?
5. **Iterate.** If detected, modify your tooling. If not detected, improve the rule.
   This feedback loop is the core value of purple teaming.

## Prerequisites

- **YARA examples**: YARA >= 4.x installed, Python 3.8+ with `yara-python` package
- **ETW examples**: Windows 10/11 or Server 2016+, Visual Studio build tools (C examples),
  Python 3.8+ with `pywintrace` or `pyetw` (Python examples), Administrator privileges

## Cross-References

- [ETW Evasion Techniques](../../06-defense-evasion/etw-evasion.md) -- understand what
  ETW consumers see so you know what patching actually disables
- [AV/EDR Evasion](../../06-defense-evasion/av-edr-evasion.md) -- YARA is one layer in
  the AV/EDR detection stack; these rules illustrate the static-analysis component
- [AMSI Bypass Techniques](../../06-defense-evasion/amsi-bypass.md) -- the AMSI YARA rule
  here detects the exact byte patches described in that narrative

## License and Ethics

All code in this directory is provided for authorized security testing and educational purposes.
Red team professionals are expected to operate under explicit written authorization (Rules of
Engagement) that defines scope, timing, and permitted techniques. Detection engineering skills
make you a better operator and a better contributor to organizational security.

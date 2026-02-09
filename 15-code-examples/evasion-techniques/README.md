# Evasion Technique Implementations - Educational Reference

> **Category**: Code Examples - Defense Evasion
> **Purpose**: Understanding evasion mechanisms for detection engineering
> **Languages**: C, Python
> **MITRE ATT&CK**: T1562 (Impair Defenses), T1620 (Reflective Code Loading), T1027.013

## Section Overview

This section provides educational analysis of defense evasion techniques at the code level. Understanding how these mechanisms work is essential for:

- **Detection Engineering**: Building monitoring for evasion attempts
- **Incident Response**: Recognizing artifacts of evasion techniques
- **Security Architecture**: Designing defenses that resist tampering

## Contents

| Topic | File | Target | Description |
|-------|------|--------|-------------|
| AMSI Patching | [amsi-patching.md](amsi-patching.md) | AMSI | AmsiScanBuffer neutralization analysis |
| ETW Patching | [etw-patching.md](etw-patching.md) | ETW | Event tracing tampering analysis |
| PE Loader | [pe-loader.md](pe-loader.md) | PE Format | Reflective PE loading analysis |
| Sleep Obfuscation | [sleep-obfuscation.md](sleep-obfuscation.md) | Memory | Sleep-time memory encryption analysis |
| Callback Injection | [callback-injection.md](callback-injection.md) | Callbacks | Callback-based shellcode execution analysis |
| Stack Spoofing | [stack-spoofing.md](stack-spoofing.md) | Call Stack | Call stack evasion and frame spoofing analysis |
| Unhooking Variants | [unhooking-variants.md](unhooking-variants.md) | ntdll | EDR hook removal and ntdll restoration analysis |

## Cross-References

- [AMSI Bypass Theory](../../06-defense-evasion/amsi-bypass.md)
- [ETW Evasion Theory](../../06-defense-evasion/etw-evasion.md)
- [AV/EDR Evasion Theory](../../06-defense-evasion/av-edr-evasion.md)
- [Syscalls & EDR Evasion Code](../syscalls-and-evasion/README.md)

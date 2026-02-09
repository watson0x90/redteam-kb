# Shellcode Development - Educational Reference

> **Category**: Code Examples - Position-Independent Code
> **Purpose**: Understanding PIC fundamentals for security analysis
> **Languages**: C, x64 Assembly, Python
> **MITRE ATT&CK**: T1059, T1027, T1106

## Section Overview

This section provides educational analysis of position-independent code (PIC) concepts, encoding techniques, and execution methods. Understanding these fundamentals is essential for:

- **Malware Analysis**: Recognizing shellcode patterns in memory dumps
- **Detection Engineering**: Building signatures for shellcode behavior
- **Threat Intelligence**: Understanding adversary tradecraft at the code level

## Contents

| Topic | File | Focus | Description |
|-------|------|-------|-------------|
| PIC Fundamentals | [shellcode-basics.md](shellcode-basics.md) | Architecture | PEB walking, API resolution, compilation |
| Encoding & Encryption | [shellcode-encryption.md](shellcode-encryption.md) | Obfuscation | XOR, AES, UUID encoding, entropy analysis |
| Execution Methods | [shellcode-runners.md](shellcode-runners.md) | Execution | Callbacks, fibers, NT API, detection profiles |

## Key Concepts

- **Position Independence**: Code that runs correctly regardless of memory address
- **PEB Walking**: Resolving API addresses at runtime without import tables
- **Encoding**: Transforming shellcode to evade static signatures
- **Execution Primitives**: Windows API patterns for executing arbitrary code in memory

## Cross-References

- [Process Injection Techniques](../process-injection/README.md)
- [Syscalls & EDR Evasion](../syscalls-and-evasion/README.md)
- [AV/EDR Evasion Theory](../../06-defense-evasion/av-edr-evasion.md)
- [Code Injection Theory](../../03-execution/code-injection.md)

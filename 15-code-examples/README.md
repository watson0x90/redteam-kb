# Code Examples & Implementations

> **Category**: Technical Deep-Dive
> **Audience**: Red Team Operators & Tool Developers
> **Languages**: C, C++, Python, x64 Assembly

| Previous | Current | Next |
|----------|---------|------|
| [Appendices](../appendices/README.md) | **Code Examples** | - |

## Section Overview

This section contains working code implementations of core red team techniques. Unlike the technique reference files which describe *what* to do, these files show *how* it works at the code level. Each implementation includes detailed comments explaining the underlying Windows internals, detection considerations, and OPSEC implications.

Understanding these implementations at the code level is what separates a Red Team Lead from someone who only runs tools.

## Contents

### Process Injection Techniques

| Topic | File | Languages | Detection Risk | Description |
|-------|------|-----------|----------------|-------------|
| Classic Injection | [classic-injection.md](process-injection/classic-injection.md) | C, Python | High | OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread |
| APC Injection | [apc-injection.md](process-injection/apc-injection.md) | C | Medium | QueueUserAPC, Early Bird variant |
| Thread Hijacking | [thread-hijacking.md](process-injection/thread-hijacking.md) | C | Medium | SuspendThread, SetThreadContext, trampoline technique |
| Process Hollowing | [process-hollowing.md](process-injection/process-hollowing.md) | C, Python | Medium-High | CREATE_SUSPENDED, NtUnmapViewOfSection, PE remapping |
| DLL Injection | [dll-injection.md](process-injection/dll-injection.md) | C, Python | Medium-High | LoadLibrary, Reflective DLL, Manual Mapping |
| Module Stomping | [module-stomping.md](process-injection/module-stomping.md) | C | Low-Medium | Overwrite legitimate DLL .text section |
| NT API Injection | [ntapi-injection.md](process-injection/ntapi-injection.md) | C | Low-Medium | NtCreateSection, NtMapViewOfSection (no WriteProcessMemory) |

### Syscalls & EDR Evasion

| Topic | File | Languages | Description |
|-------|------|-----------|-------------|
| Direct Syscalls | [direct-syscalls.md](syscalls-and-evasion/direct-syscalls.md) | C, ASM | Bypass ntdll hooks via direct syscall instruction |
| Hell's Gate | [hells-gate.md](syscalls-and-evasion/hells-gate.md) | C, ASM | Runtime SSN resolution from in-memory ntdll |
| Halo's Gate | [halos-gate.md](syscalls-and-evasion/halos-gate.md) | C, ASM | SSN resolution when target function is hooked |
| Indirect Syscalls | [indirect-syscalls.md](syscalls-and-evasion/indirect-syscalls.md) | C, ASM | Execute syscall from within ntdll (stack trace evasion) |
| NTDLL Unhooking | [ntdll-unhooking.md](syscalls-and-evasion/ntdll-unhooking.md) | C | Replace hooked ntdll with clean copy |
| API Hashing | [api-hashing.md](syscalls-and-evasion/api-hashing.md) | C, Python | Dynamic API resolution to avoid string detection |

### COFF Loaders & BOF Development

| Topic | File | Languages | Description |
|-------|------|-----------|-------------|
| COFF Format | [coff-format-deep-dive.md](coff-loaders/coff-format-deep-dive.md) | C (structs) | Complete COFF structure reference |
| Basic COFF Loader | [basic-coff-loader.md](coff-loaders/basic-coff-loader.md) | C | Minimal working COFF object loader |
| BOF Development | [bof-development.md](coff-loaders/bof-development.md) | C | Writing Beacon Object Files with examples |
| Advanced Loader | [coff-loader-advanced.md](coff-loaders/coff-loader-advanced.md) | C | Production loader with full Beacon API |

### C2 Communication Channels

| Topic | File | Languages | Stealth | Description |
|-------|------|-----------|---------|-------------|
| DNS C2 | [dns-c2-implementation.md](c2-channels/dns-c2-implementation.md) | Python, C | High | DNS tunneling server and client |
| ICMP C2 | [icmp-c2-implementation.md](c2-channels/icmp-c2-implementation.md) | Python, C | Medium | Covert channel via ICMP payloads |
| DoH C2 | [doh-c2-implementation.md](c2-channels/doh-c2-implementation.md) | Python | Very High | DNS-over-HTTPS encrypted C2 |
| HTTP/S C2 | [http-c2-implementation.md](c2-channels/http-c2-implementation.md) | Python, C | Medium | HTTP C2 with malleable traffic |
| Named Pipes | [named-pipe-c2.md](c2-channels/named-pipe-c2.md) | C, Python | Low-Med | SMB-based internal peer-to-peer C2 |

### Shellcode Development

| Topic | File | Languages | Description |
|-------|------|-----------|-------------|
| Shellcode Basics | [shellcode-basics.md](shellcode/shellcode-basics.md) | C, ASM | PIC fundamentals, PEB walking, compilation |
| Encryption | [shellcode-encryption.md](shellcode/shellcode-encryption.md) | C, Python | XOR, AES-256, UUID obfuscation |
| Execution Methods | [shellcode-runners.md](shellcode/shellcode-runners.md) | C, Python | Callbacks, fibers, NT API, mapping injection |

### Credential Access Code

| Topic | File | Languages | Description |
|-------|------|-----------|-------------|
| Token Manipulation | [token-manipulation.md](credential-access-code/token-manipulation.md) | C | Token enumeration, duplication, impersonation |
| Custom MiniDump | [minidump-implementation.md](credential-access-code/minidump-implementation.md) | C, Python | LSASS dumping without MiniDumpWriteDump |
| DPAPI Decryption | [dpapi-decryption.md](credential-access-code/dpapi-decryption.md) | C, Python | Master key derivation, Chrome/Edge credential decryption chain |
| SAM Registry Dump | [sam-registry-dump.md](credential-access-code/sam-registry-dump.md) | C, Python | BOOTKEY derivation, SAM hive parsing, NTLMv1 hash extraction |
| Kerberos Ticket Extraction | [kerberos-ticket-extraction.md](credential-access-code/kerberos-ticket-extraction.md) | C, Python | In-memory ticket enumeration, kirbi/ccache formats, Pass-the-Ticket |

### Lateral Movement Techniques

| Topic | File | Languages | Detection Risk | Description |
|-------|------|-----------|----------------|-------------|
| Pass the Hash | [pth-implementation.md](lateral-movement/pth-implementation.md) | C, Python | Medium-High | NTLM protocol internals, NTLMv2 response computation, LSASS credential patching |
| Kerberos Ticket Forging | [kerberos-ticket-forging.md](lateral-movement/kerberos-ticket-forging.md) | C, Python | Medium | Golden/Silver/Diamond Ticket construction, PAC structure, ASN.1 encoding |
| DCOM Execution | [dcom-execution.md](lateral-movement/dcom-execution.md) | C, Python | Low-Medium | MMC20.Application, ShellWindows, ShellBrowserWindow COM objects |
| WMI Remote Execution | [wmi-remote-exec.md](lateral-movement/wmi-remote-exec.md) | C, Python | Medium | Win32_Process.Create, WMI event subscriptions, IWbemServices COM interface |

### Evasion Technique Implementations

| Topic | File | Languages | Description |
|-------|------|-----------|-------------|
| AMSI Patching | [amsi-patching.md](evasion-techniques/amsi-patching.md) | C, Python | AmsiScanBuffer patch, hardware breakpoint bypass |
| ETW Patching | [etw-patching.md](evasion-techniques/etw-patching.md) | C | EtwEventWrite/NtTraceEvent neutralization |
| Reflective PE Loader | [pe-loader.md](evasion-techniques/pe-loader.md) | C | Load PE from memory without LoadLibrary |
| Sleep Obfuscation | [sleep-obfuscation.md](evasion-techniques/sleep-obfuscation.md) | C | Ekko-style memory encryption during sleep |
| Callback Injection | [callback-injection.md](evasion-techniques/callback-injection.md) | C | EnumWindows, timer queues, thread pool callbacks, fiber execution |
| Stack Spoofing | [stack-spoofing.md](evasion-techniques/stack-spoofing.md) | C | Synthetic stack frames, return address spoofing, call stack desync |
| Unhooking Variants | [unhooking-variants.md](evasion-techniques/unhooking-variants.md) | C | Disk copy, KnownDlls mapping, suspended process, per-function restore |

### Persistence Mechanisms

| Topic | File | Languages | Detection Risk | Description |
|-------|------|-----------|----------------|-------------|
| Registry Persistence | [registry-persistence-code.md](persistence-mechanisms/registry-persistence-code.md) | C | High | Run keys, IFEO, AppInit_DLLs, Winlogon, transacted writes |
| Scheduled Task Creation | [scheduled-task-creation.md](persistence-mechanisms/scheduled-task-creation.md) | C, PowerShell | High | COM-based ITaskService, XML definitions, task hiding via SD |
| WMI Event Subscription | [wmi-event-subscription.md](persistence-mechanisms/wmi-event-subscription.md) | C, Python | Medium-High | EventFilter + EventConsumer + FilterToConsumerBinding |
| DLL Hijack Discovery | [dll-hijack-discovery.md](persistence-mechanisms/dll-hijack-discovery.md) | C | Low-Medium | Search order exploitation, phantom DLLs, export proxying |
| Service Persistence | [service-persistence.md](persistence-mechanisms/service-persistence.md) | C | High | CreateServiceW, service DLL skeleton, existing service modification |

### Active Directory Attack Code

| Topic | File | Languages | Detection Risk | Description |
|-------|------|-----------|----------------|-------------|
| Kerberoasting | [kerberoasting-implementation.md](active-directory/kerberoasting-implementation.md) | C, Python | Medium | SPN enumeration, TGS-REQ construction, ticket extraction for offline cracking |
| AS-REP Roasting | [asrep-roasting.md](active-directory/asrep-roasting.md) | C, Python | Medium | Pre-auth bypass, AS-REP encrypted part extraction, hashcat format |
| DCSync Internals | [dcsync-internals.md](active-directory/dcsync-internals.md) | C, Python | Very High | DRS replication protocol, IDL_DRSGetNCChanges, NTLM hash extraction |
| ADCS Abuse | [adcs-abuse-code.md](active-directory/adcs-abuse-code.md) | C, Python | Medium-High | ESC1-ESC8, CSR construction, PKINIT authentication with forged certs |

### Cloud Attack Code

| Topic | File | Languages | Detection Risk | Description |
|-------|------|-----------|----------------|-------------|
| IMDS Token Theft | [imds-token-theft.md](cloud-attack-code/imds-token-theft.md) | Python, Bash | Medium | AWS/Azure/GCP metadata service exploitation, SSRF-to-IMDS chains |
| Cloud C2 Channels | [cloud-c2-channels.md](cloud-attack-code/cloud-c2-channels.md) | Python | Low-Medium | S3 dead drops, Lambda URL C2, Azure Queue C2, X-Ray trace C2 |
| OAuth Token Abuse | [oauth-token-abuse.md](cloud-attack-code/oauth-token-abuse.md) | Python | Medium | Device code phishing, Graph API abuse, token refresh, Pass-the-PRT |

### Network Evasion

| Topic | File | Languages | Detection Risk | Description |
|-------|------|-----------|----------------|-------------|
| Domain Fronting | [domain-fronting.md](network-evasion/domain-fronting.md) | Python, Go | Low | CDN-based SNI/Host mismatch, Cloudflare Workers, Azure CDN, CloudFront |
| JA3 Randomization | [ja3-randomization.md](network-evasion/ja3-randomization.md) | Python, Go | Low | TLS fingerprint evasion, cipher suite shuffling, browser mimicry |

### Detection Engineering (Purple Team)

| Topic | File | Languages | Purple Team Value | Description |
|-------|------|-----------|-------------------|-------------|
| YARA Rule Development | [yara-rule-development.md](detection-engineering/yara-rule-development.md) | YARA, Python | Critical | Injection artifacts, shellcode signatures, PE anomalies, evasion testing |
| ETW Consumer Code | [etw-consumer-code.md](detection-engineering/etw-consumer-code.md) | C, Python | Critical | Real-time telemetry consumers, CLR loading, LSASS access monitoring |

## Compilation Notes

### Windows (MSVC)
```bash
cl.exe /nologo /W3 /GS- source.c /link /OUT:output.exe
```

### Windows (MinGW Cross-Compile from Linux)
```bash
x86_64-w64-mingw32-gcc -o output.exe source.c -lws2_32 -lntdll
```

### BOF Compilation
```bash
x86_64-w64-mingw32-gcc -c -o bof.o bof.c    # Object file only
```

### Python
```bash
pip install pycryptodome requests pywin32    # Common dependencies
```

## Cross-References

- [Process Injection Theory](../03-execution/code-injection.md)
- [AV/EDR Evasion Concepts](../06-defense-evasion/av-edr-evasion.md)
- [AMSI Bypass Theory](../06-defense-evasion/amsi-bypass.md)
- [LSASS Dumping Theory](../07-credential-access/lsass-dumping.md)
- [C2 Frameworks](../11-command-and-control/c2-frameworks.md)
- [Cobalt Strike Cheatsheet](../appendices/cobalt-strike-cheatsheet.md)
- [Lateral Movement Theory](../09-lateral-movement/README.md)
- [Persistence Techniques](../04-persistence/README.md)
- [Active Directory Deep Dive](../12-active-directory-deep-dive/README.md)
- [Cloud Security](../13-cloud-security/README.md)
- [DPAPI Abuse Theory](../07-credential-access/dpapi-abuse.md)
- [Kerberos Attacks Theory](../07-credential-access/kerberos-credential-attacks.md)
- [Network Evasion Theory](../06-defense-evasion/network-evasion.md)

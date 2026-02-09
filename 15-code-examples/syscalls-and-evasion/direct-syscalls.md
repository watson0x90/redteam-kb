# Direct Syscalls

> **Context**: This document explains how Windows system calls work and why direct
> invocation is significant for both offensive security testing and defensive engineering.
> For authorized engagements only.

## Normal API Call Flow

When a Windows application calls a function like `VirtualAllocEx`, the call passes
through multiple layers before reaching the kernel:

```
Application Code
    |
    v
kernel32.dll!VirtualAllocEx        <-- High-level wrapper
    |
    v
ntdll.dll!NtAllocateVirtualMemory  <-- Native API (thin syscall stub)
    |
    v
syscall instruction                <-- Transition to kernel mode
    |
    v
ntoskrnl.exe                       <-- Kernel handler
```

EDR products hook at the ntdll.dll layer, replacing the first bytes of the native
function with a JMP to their inspection code. This lets them see every argument before
the call reaches the kernel.

## Direct Syscall Flow

A direct syscall skips ntdll entirely:

```
Application Code
    |
    v
In-process syscall stub            <-- Executes syscall instruction directly
    |
    v
ntoskrnl.exe                       <-- Kernel handler (no hook is hit)
```

## The x64 Syscall Stub Structure

Every native function in ntdll.dll follows a nearly identical pattern. This is the
**syscall stub** -- a small sequence that transitions to kernel mode:

```asm
; Typical ntdll syscall stub for NtAllocateVirtualMemory (Windows 10 21H2)
;
; Offset | Bytes          | Instruction
; -------+----------------+----------------------------------------------
; +0x00  | 4C 8B D1       | mov r10, rcx     ; save 1st arg (rcx is
;        |                |                  ; clobbered by syscall)
; +0x03  | B8 18 00 00 00 | mov eax, 0x18    ; SSN (System Service Number)
;        |                |                  ; 0x18 = NtAllocateVirtualMemory
; +0x08  | F6 04 25 08 03 | test byte ptr [7FFE0308h], 1
;        | FE 7F 01       |                  ; check if should use int 2Eh
; +0x10  | 75 03          | jne +3           ; if set, use legacy interrupt
; +0x12  | 0F 05          | syscall          ; fast syscall to kernel
; +0x14  | C3             | ret              ; return to caller
; +0x15  | CD 2E          | int 2Eh          ; legacy syscall path
; +0x17  | C3             | ret
```

Key observations:
- `mov r10, rcx` -- The Windows x64 calling convention uses rcx for the first
  argument, but the `syscall` instruction overwrites rcx with the return address.
  So rcx is saved to r10 first.
- `mov eax, SSN` -- The **System Service Number** identifies which kernel function
  to call. This is the critical value.
- `syscall` -- The actual ring 3 to ring 0 transition.

## System Service Numbers (SSNs)

SSNs are **not stable across Windows versions**. They change with each release:

```
Function                    | Win10 1803 | Win10 21H2 | Win11 22H2
----------------------------+------------+------------+-----------
NtAllocateVirtualMemory     | 0x18       | 0x18       | 0x18
NtWriteVirtualMemory        | 0x3A       | 0x3A       | 0x3A
NtCreateThreadEx            | 0xC1       | 0xC7       | 0xCF
NtProtectVirtualMemory      | 0x50       | 0x50       | 0x50
```

*Note: Some SSNs remain stable; others shift as new syscalls are inserted.*

This versioning is why hardcoding SSNs is fragile. Tools must resolve them dynamically
or maintain version-specific tables.

## Conceptual Code: Syscall Stub Definition

The following illustrates how a direct syscall stub is conceptually defined. This is
a simplified educational representation:

```c
// Educational illustration of syscall invocation concepts.
// This shows the data structures and typedef patterns involved.

#include <windows.h>

// Native API function signature for NtAllocateVirtualMemory
// Matches the kernel's expected parameter layout
typedef NTSTATUS(NTAPI* pfnNtAllocateVirtualMemory)(
    HANDLE    ProcessHandle,      // Target process
    PVOID*    BaseAddress,        // In/out: allocation base
    ULONG_PTR ZeroBits,          // Address constraint
    PSIZE_T   RegionSize,        // In/out: size
    ULONG     AllocationType,    // MEM_COMMIT | MEM_RESERVE
    ULONG     Protect            // PAGE_EXECUTE_READWRITE etc.
);

// The concept: a small assembly stub that performs the syscall directly.
// In practice, this would be defined via inline assembly or a separate
// ASM file that is linked into the project.
//
// Pseudocode for what the stub does:
//   mov r10, rcx          ; preserve first argument
//   mov eax, <SSN>        ; load the system service number
//   syscall                ; transition to kernel
//   ret                    ; return to caller
```

## SysWhispers Tool Family

**SysWhispers** (by @jthuraisamy) automates the generation of direct syscall stubs:

- **SysWhispers1**: Generated version-specific ASM stubs with hardcoded SSNs.
- **SysWhispers2**: Introduced sorted-by-address SSN resolution (avoids hardcoding).
- **SysWhispers3**: Added indirect syscall support and egg-hunting techniques.

These tools generate `.asm` and `.h` files that can be compiled into a project,
replacing ntdll calls with in-process stubs.

---

## Detection & Defense

Direct syscalls are well-understood by defenders. Multiple detection layers exist:

### 1. Stack Trace Analysis (Primary Detection)

When a legitimate call goes through ntdll, the return address on the stack points
into ntdll.dll's memory range. With direct syscalls, the return address points into
the application's own memory -- a strong anomaly signal.

```
Legitimate stack trace:
  ntoskrnl.exe!NtAllocateVirtualMemory
  ntdll.dll!NtAllocateVirtualMemory + 0x14    <-- return addr in ntdll
  kernel32.dll!VirtualAllocEx + 0x56
  application.exe!main + 0x42

Direct syscall stack trace (suspicious):
  ntoskrnl.exe!NtAllocateVirtualMemory
  application.exe!some_function + 0x28         <-- return addr NOT in ntdll
```

EDR kernel drivers inspect the return address in the trap frame. If it falls outside
ntdll's address range, the call is flagged as suspicious.

### 2. ETW Threat Intelligence Provider

The **Microsoft-Windows-Threat-Intelligence** ETW provider generates events from
the kernel for sensitive operations. These events are generated **after** the
syscall is processed, so bypassing ntdll hooks does not evade them:

- Memory allocation in remote processes
- Memory protection changes (RW -> RX)
- Thread creation in remote processes

This is a kernel-level telemetry source that cannot be tampered with from userland.

### 3. Kernel Callbacks

Drivers can register callbacks via:
- `PsSetCreateProcessNotifyRoutineEx` -- process creation
- `PsSetCreateThreadNotifyRoutineEx` -- thread creation
- `PsSetLoadImageNotifyRoutine` -- image (DLL/EXE) loads
- `ObRegisterCallbacks` -- handle operations

These fire regardless of how the syscall was invoked.

### 4. Static Signatures

Direct syscall stubs have recognizable byte patterns:
- `4C 8B D1` (`mov r10, rcx`) followed by `B8 XX XX 00 00` (`mov eax, SSN`)
- These patterns in non-ntdll modules are a strong indicator.

YARA rules can detect these patterns in PE files:

```
rule Direct_Syscall_Stub {
    meta:
        description = "Detects direct syscall stub patterns in non-system binaries"
    strings:
        $stub = { 4C 8B D1 B8 ?? ?? 00 00 }
    condition:
        $stub and not pe.imports("ntdll.dll")
}
```

### Summary

Direct syscalls were effective historically but are now well-detected. The return
address anomaly is a reliable indicator. This drove the evolution toward indirect
syscalls and other techniques documented in subsequent files.

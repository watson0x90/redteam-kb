# Shellcode Basics - Position-Independent Code Fundamentals

> **MITRE ATT&CK**: T1059 (Command and Scripting Interpreter)
> **Purpose**: Understanding PIC architecture for malware analysis and detection
> **Languages**: C, x64 Assembly
> **Detection Focus**: PEB walking patterns, API resolution heuristics

## Strategic Overview

Shellcode is position-independent code (PIC) designed to run from any memory address without relying on the OS loader. Understanding how shellcode resolves APIs and executes is fundamental to:

- Analyzing malware samples that use shellcode stages
- Building detection rules for PEB walking and API resolution
- Understanding process injection payloads
- Reverse engineering C2 implant loaders

### Why This Matters for Red Team Leads
- Shellcode is the payload delivered by virtually every injection technique
- Understanding PIC constraints informs tool development decisions
- API resolution techniques determine the OPSEC profile of payloads

## Technical Deep-Dive

### Position-Independent Code Requirements

```
Normal EXE/DLL:
┌─────────────────────────────────────┐
│ PE Header (tells loader about IAT)  │
│ Import Address Table (IAT)          │ ← Loader fills in API addresses
│ Code: call [IAT+offset]            │ ← Uses fixed addresses
│ Data: strings at fixed offsets      │
└─────────────────────────────────────┘
  ▲ Depends on loader, fixed base address, IAT resolution

Position-Independent Code (Shellcode):
┌─────────────────────────────────────┐
│ No headers, no imports              │
│ Code: find APIs at runtime          │ ← Must self-resolve everything
│ Data: inline with code              │ ← No fixed data section
│ No absolute addresses               │ ← RIP-relative only
└─────────────────────────────────────┘
  ▲ Self-contained, runs from any address
```

### PEB (Process Environment Block) Walking

```c
/*
 * Educational: How shellcode locates loaded DLLs via the PEB.
 *
 * The PEB is a user-mode structure that contains process metadata,
 * including a linked list of all loaded DLLs (the LDR data).
 *
 * This is the FUNDAMENTAL technique for API resolution in shellcode.
 * Every shellcode developer and malware analyst must understand this.
 *
 * Detection:
 * - Memory scanners look for PEB access patterns (GS:[0x60] on x64)
 * - YARA rules can match PEB walking instruction sequences
 * - EDR hooks on LdrLoadDll catch dynamic loading
 */

#include <windows.h>
#include <winternl.h>  /* PEB, LDR structures */
#include <stdio.h>

/*
 * Key PEB Structures (from winternl.h / ntddk.h):
 *
 * TEB (Thread Environment Block):
 *   Offset 0x60 (x64): Pointer to PEB
 *   Accessed via: GS:[0x60] on x64, FS:[0x30] on x86
 *
 * PEB (Process Environment Block):
 *   Offset 0x18 (x64): PEB_LDR_DATA pointer
 *
 * PEB_LDR_DATA:
 *   Offset 0x20 (x64): InMemoryOrderModuleList (LIST_ENTRY)
 *
 * LDR_DATA_TABLE_ENTRY:
 *   Offset 0x30: DllBase (base address of the module)
 *   Offset 0x40: FullDllName (UNICODE_STRING)
 *   Offset 0x48: BaseDllName (UNICODE_STRING)
 */

/* Walk PEB to enumerate loaded modules (educational demonstration) */
void enumerate_loaded_modules(void) {
    /*
     * Accessing the PEB via NtCurrentTeb()
     * In assembly, this would be: mov rax, gs:[0x60]
     *
     * Detection Signature:
     * x64: 65 48 8B 04 25 60 00 00 00  (mov rax, gs:[0x60])
     * x86: 64 A1 30 00 00 00           (mov eax, fs:[0x30])
     *
     * YARA Rule Example:
     * rule PEB_Access {
     *     strings:
     *         $peb_x64 = { 65 48 8B (04 25 | 0C 25) 60 00 00 00 }
     *         $peb_x86 = { 64 (A1 | 8B (0D | 15 | 1D | 35 | 3D)) 30 00 00 00 }
     *     condition:
     *         any of them
     * }
     */

#ifdef _WIN64
    /* x64: PEB is at GS:[0x60] */
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    /* x86: PEB is at FS:[0x30] */
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    if (!pPeb || !pPeb->Ldr) {
        printf("Failed to access PEB\n");
        return;
    }

    /* Navigate to InMemoryOrderModuleList */
    PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    printf("=== PEB Module Enumeration ===\n");
    printf("%-20s %-18s %s\n", "Base Address", "Size", "Module Name");
    printf("%-20s %-18s %s\n", "------------", "----", "-----------");

    while (current != head) {
        /* LDR_DATA_TABLE_ENTRY is at offset -0x10 from InMemoryOrderLinks */
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
            current,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );

        if (entry->DllBase) {
            printf("0x%p    0x%08lx    %ls\n",
                   entry->DllBase,
                   entry->SizeOfImage,
                   entry->FullDllName.Buffer ? entry->FullDllName.Buffer : L"(null)");
        }

        current = current->Flink;
    }

    /*
     * Module Load Order (important for shellcode):
     * 1. ntdll.dll      (always first - NT layer)
     * 2. kernel32.dll   (always second - Win32 API)
     * 3. kernelbase.dll  (Win7+ - actual implementations)
     *
     * Shellcode typically needs kernel32.dll to call:
     * - LoadLibraryA (load additional DLLs)
     * - GetProcAddress (resolve any API by name)
     * - VirtualAlloc, VirtualProtect (memory management)
     */
}

/*
 * Finding kernel32.dll base address from PEB
 * This is the critical first step in most shellcode.
 */
HMODULE find_kernel32_via_peb(void) {
    /*
     * Strategy: Walk InMemoryOrderModuleList
     * Entry 1 = exe itself
     * Entry 2 = ntdll.dll
     * Entry 3 = kernel32.dll (usually)
     *
     * More robust: Compare module name hash against
     * known hash of "kernel32.dll" or "KERNEL32.DLL"
     */
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;  /* Skip exe */
    current = current->Flink;           /* Skip ntdll */
    current = current->Flink;           /* kernel32 */

    PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
        current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks
    );

    return (HMODULE)entry->DllBase;
}
```

### Export Table Parsing (Custom GetProcAddress)

```c
/*
 * Educational: How shellcode resolves API functions by parsing
 * the PE export table of a loaded DLL.
 *
 * This is equivalent to GetProcAddress but without calling
 * any API - pure memory parsing.
 *
 * Detection:
 * - Export table parsing patterns in memory
 * - Accessing PE headers of loaded DLLs from unexpected code
 * - YARA rules for PE header parsing sequences
 */

/* Parse PE export directory to find function by name */
FARPROC find_export_by_name(HMODULE hModule, const char *funcName) {
    /*
     * PE Structure Navigation:
     * DOS Header -> e_lfanew -> NT Headers -> Optional Header ->
     * DataDirectory[0] -> Export Directory
     */
    BYTE *base = (BYTE *)hModule;

    /* DOS Header: first 2 bytes should be "MZ" (0x5A4D) */
    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)base;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    /* NT Headers: at offset e_lfanew from base */
    IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS *)(base + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    /* Export Directory: DataDirectory[0] */
    DWORD exportRVA = ntHeaders->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRVA == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY *exportDir = (IMAGE_EXPORT_DIRECTORY *)(base + exportRVA);

    /* Export table arrays */
    DWORD *nameRVAs = (DWORD *)(base + exportDir->AddressOfNames);
    WORD  *ordinals = (WORD *)(base + exportDir->AddressOfNameOrdinals);
    DWORD *funcRVAs = (DWORD *)(base + exportDir->AddressOfFunctions);

    /* Linear search through exported names */
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char *name = (const char *)(base + nameRVAs[i]);

        /* Compare function name (case-sensitive) */
        if (strcmp(name, funcName) == 0) {
            WORD ordinal = ordinals[i];
            DWORD funcRVA = funcRVAs[ordinal];
            return (FARPROC)(base + funcRVA);
        }
    }

    return NULL;  /* Function not found */
}

/*
 * Usage in shellcode context:
 *
 * HMODULE k32 = find_kernel32_via_peb();
 * typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
 * typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
 *
 * pLoadLibraryA fnLoadLibrary = (pLoadLibraryA)find_export_by_name(k32, "LoadLibraryA");
 * pGetProcAddress fnGetProcAddr = (pGetProcAddress)find_export_by_name(k32, "GetProcAddress");
 *
 * // Now can load any DLL and resolve any function
 * HMODULE user32 = fnLoadLibrary("user32.dll");
 * // ... resolve MessageBoxA, etc.
 */
```

### x64 Assembly - PEB Walking

```asm
; Educational: x64 assembly for PEB walking
; This is what the C code above compiles to at the CPU level
;
; Detection: These byte sequences are used in YARA rules
; to identify shellcode in memory dumps

section .text
global find_kernel32

find_kernel32:
    ; Access PEB via TEB (GS segment on x64)
    ; Bytes: 65 48 8B 04 25 60 00 00 00
    mov rax, [gs:0x60]          ; RAX = PEB pointer

    ; PEB.Ldr (offset 0x18)
    mov rax, [rax + 0x18]       ; RAX = PEB_LDR_DATA

    ; InMemoryOrderModuleList (offset 0x20)
    mov rsi, [rax + 0x20]       ; RSI = first LIST_ENTRY

    ; Walk the list: exe -> ntdll -> kernel32
    lodsq                        ; Skip exe (RAX = Flink)
    xchg rax, rsi
    lodsq                        ; Skip ntdll
    xchg rax, rsi
    lodsq                        ; kernel32 entry
    xchg rax, rsi

    ; DllBase is at offset 0x30 from InMemoryOrderLinks
    mov rax, [rsi + 0x20]       ; RAX = kernel32 base address
    ret

; YARA Detection Pattern:
; { 65 48 8B 04 25 60 00 00 00 48 8B 40 18 48 8B 70 20 }
```

### Shellcode Extraction (Python)

```python
"""
Educational: Extracting shellcode bytes from compiled binaries.
This is how raw shellcode is prepared from compiled C/ASM code.

Used by malware analysts to:
1. Extract and analyze shellcode from malware samples
2. Understand the compilation -> shellcode pipeline
3. Generate test payloads for detection rule validation
"""
import struct
import sys

def extract_text_section(pe_path: str) -> bytes:
    """
    Extract .text section from a PE file.

    In real shellcode development:
    1. Compile C code with specific flags (no CRT, custom entry)
    2. Extract the .text section containing the PIC code
    3. This raw bytes IS the shellcode

    Detection: .text section extraction tools are not inherently
    malicious - they're used in legitimate software development too.
    """
    with open(pe_path, 'rb') as f:
        data = f.read()

    # Parse DOS header
    if data[:2] != b'MZ':
        raise ValueError("Not a valid PE file")

    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]

    # Parse COFF header
    num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    opt_header_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]

    # Section headers start after optional header
    section_offset = e_lfanew + 24 + opt_header_size

    for i in range(num_sections):
        offset = section_offset + (i * 40)
        name = data[offset:offset+8].rstrip(b'\x00').decode()
        raw_size = struct.unpack_from('<I', data, offset + 16)[0]
        raw_ptr = struct.unpack_from('<I', data, offset + 20)[0]

        if name == '.text':
            return data[raw_ptr:raw_ptr + raw_size]

    raise ValueError(".text section not found")


def format_shellcode(raw_bytes: bytes, lang: str = 'c') -> str:
    """
    Format raw bytes as a code-embeddable array.

    Supports: C, Python, C# output formats.
    """
    if lang == 'c':
        lines = []
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i+16]
            hex_str = ', '.join(f'0x{b:02x}' for b in chunk)
            lines.append(f'    {hex_str},')
        return f'unsigned char shellcode[{len(raw_bytes)}] = {{\n' + \
               '\n'.join(lines) + '\n};'

    elif lang == 'python':
        lines = []
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i+16]
            hex_str = ''.join(f'\\x{b:02x}' for b in chunk)
            lines.append(f'    b"{hex_str}"')
        return 'shellcode = (\n' + '\n'.join(lines) + '\n)'

    elif lang == 'csharp':
        hex_str = ', '.join(f'0x{b:02x}' for b in raw_bytes)
        return f'byte[] shellcode = new byte[{len(raw_bytes)}] {{ {hex_str} }};'


def analyze_shellcode(raw_bytes: bytes) -> dict:
    """
    Basic static analysis of shellcode bytes.

    Detection Use: These heuristics are used by AV/EDR
    to identify shellcode in memory.
    """
    analysis = {
        'size': len(raw_bytes),
        'entropy': calculate_entropy(raw_bytes),
        'null_bytes': raw_bytes.count(0x00),
        'null_free': raw_bytes.count(0x00) == 0,
    }

    # Check for common PEB walking patterns
    peb_x64 = b'\x65\x48\x8b\x04\x25\x60\x00\x00\x00'
    peb_x86 = b'\x64\xa1\x30\x00\x00\x00'
    analysis['peb_walk_x64'] = peb_x64 in raw_bytes
    analysis['peb_walk_x86'] = peb_x86 in raw_bytes

    # Check for syscall instructions
    analysis['has_syscall'] = b'\x0f\x05' in raw_bytes
    analysis['has_int2e'] = b'\xcd\x2e' in raw_bytes

    return analysis


def calculate_entropy(data: bytes) -> float:
    """Shannon entropy - high entropy suggests encryption/compression."""
    import math
    from collections import Counter
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return round(-sum((c/length) * math.log2(c/length) for c in freq.values()), 3)
```

## Detection & Evasion

### Detection Signatures

| Pattern | Detection Method | YARA / Signature |
|---------|-----------------|------------------|
| PEB access (x64) | Byte sequence scan | `65 48 8B 04 25 60 00 00 00` |
| PEB access (x86) | Byte sequence scan | `64 A1 30 00 00 00` |
| Export table parsing | PE header access from non-loader | API call monitoring |
| RWX memory regions | Memory protection scan | VirtualAlloc with PAGE_EXECUTE_READWRITE |
| Small code with API hashes | Entropy + size heuristic | High entropy < 10KB |

### Defensive Recommendations

1. **Memory scanning**: Periodic scans for PEB walking patterns in process memory
2. **RWX detection**: Alert on memory regions with execute + write permissions
3. **API monitoring**: Hook NtAllocateVirtualMemory, NtProtectVirtualMemory
4. **YARA rules**: Deploy rules matching known shellcode stub patterns
5. **ETW tracing**: Monitor for unusual PE header access patterns

## Cross-References

- [Process Injection Techniques](../process-injection/README.md)
- [API Hashing](../syscalls-and-evasion/api-hashing.md)
- [Direct Syscalls](../syscalls-and-evasion/direct-syscalls.md)
- [Windows Internals Reference](../../appendices/windows-internals-reference.md)
- [AV/EDR Evasion](../../06-defense-evasion/av-edr-evasion.md)

## References

- Microsoft: PEB Structure Documentation
- MSDN: PE Format Specification
- Offensive Security: Shellcoding for Pentesters (OSCE)
- SANS SEC760: Advanced Exploit Development
- Corelan: Exploit Writing Tutorial Series

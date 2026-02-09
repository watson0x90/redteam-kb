# Reflective PE Loader - Educational Analysis

> **MITRE ATT&CK**: T1620 - Reflective Code Loading
> **Purpose**: Understanding PE loading for malware analysis and detection
> **Languages**: C
> **Detection Focus**: Unbacked executable memory, PE header signatures

## Strategic Overview

A reflective PE loader maps a Portable Executable (PE) file into memory and executes it without using the Windows loader (LoadLibrary). This allows DLLs and EXEs to be loaded from memory buffers rather than disk, avoiding file-based detection. Understanding the PE loading process is essential for:

- Analyzing fileless malware that loads PEs from memory
- Building detection for reflective loading patterns
- Understanding how Cobalt Strike's execute-assembly and reflective DLL injection work
- Reverse engineering custom loaders found in malware

### Why This Matters for Red Team Leads
- Reflective loading is the foundation of in-memory execution
- Cobalt Strike, Metasploit, and most C2s use reflective DLL injection
- Understanding PE internals differentiates senior operators

## Technical Deep-Dive

### PE Format Structure

```c
/*
 * Educational: PE Format structures for loader analysis.
 *
 * Every Windows executable (EXE/DLL) follows the PE format.
 * Understanding these structures is required for:
 * 1. Writing PE parsers for malware analysis
 * 2. Understanding how reflective loaders work
 * 3. Building detection rules for PE-in-memory
 *
 * PE Layout:
 * ┌──────────────────────────┐ Offset 0
 * │ DOS Header (64 bytes)    │ "MZ" signature
 * │   e_lfanew → NT Headers  │
 * ├──────────────────────────┤ e_lfanew
 * │ NT Headers               │ "PE\0\0" signature
 * │   FileHeader (20 bytes)  │ Machine, sections, timestamp
 * │   OptionalHeader         │ Entry point, image base, etc.
 * │     DataDirectory[16]    │ Import/Export/Reloc tables
 * ├──────────────────────────┤
 * │ Section Headers[]        │ .text, .data, .rdata, .reloc
 * ├──────────────────────────┤
 * │ .text section            │ Executable code
 * ├──────────────────────────┤
 * │ .rdata section           │ Read-only data, imports
 * ├──────────────────────────┤
 * │ .data section            │ Initialized data
 * ├──────────────────────────┤
 * │ .reloc section           │ Base relocation table
 * └──────────────────────────┘
 */

#include <windows.h>
#include <stdio.h>

/*
 * PE Header Structures (from winnt.h)
 * These are built into Windows but shown here for reference.
 */

/*
 * IMAGE_DOS_HEADER (64 bytes)
 * First structure in any PE file.
 * Key field: e_lfanew - offset to NT headers
 *
 * Detection: "MZ" (0x4D5A) at the start of a memory region
 * that isn't file-backed = potential reflective loading
 */
/* typedef struct _IMAGE_DOS_HEADER {
 *     WORD  e_magic;    // "MZ" = 0x5A4D
 *     ...               // DOS stub fields (legacy)
 *     LONG  e_lfanew;   // Offset to NT headers
 * } IMAGE_DOS_HEADER; */

/*
 * IMAGE_NT_HEADERS (x64: 264 bytes)
 * Contains PE signature, file header, and optional header.
 *
 * Detection: "PE\0\0" signature (0x00004550) in non-file memory
 */
/* typedef struct _IMAGE_NT_HEADERS64 {
 *     DWORD                   Signature;      // "PE\0\0"
 *     IMAGE_FILE_HEADER       FileHeader;
 *     IMAGE_OPTIONAL_HEADER64 OptionalHeader;
 * } IMAGE_NT_HEADERS64; */

/*
 * Key OptionalHeader Fields for Loading:
 * - AddressOfEntryPoint: RVA of entry point (DllMain or main)
 * - ImageBase: Preferred base address
 * - SectionAlignment: Alignment in memory (usually 0x1000)
 * - SizeOfImage: Total size when mapped
 * - DataDirectory[]: Array of important table locations
 *   [0] = Export Table
 *   [1] = Import Table
 *   [5] = Base Relocation Table
 *   [9] = TLS Table
 */
```

### PE Parser Implementation

```c
/*
 * Educational: PE metadata parser for analysis.
 * This reads and displays PE structure information,
 * which is the foundation for understanding loaders.
 *
 * BUILD: cl.exe /nologo /W3 pe_parser.c
 */

typedef struct {
    BOOL valid;
    WORD machine;
    DWORD entryPointRVA;
    ULONGLONG imageBase;
    DWORD sizeOfImage;
    WORD numberOfSections;
    WORD dllCharacteristics;
    BOOL isExecutable;
    BOOL isDLL;
    BOOL hasRelocations;
    BOOL hasImports;
    BOOL hasExports;
    BOOL hasTLS;
} PE_INFO;

PE_INFO parse_pe_headers(const BYTE *data, size_t dataSize) {
    PE_INFO info = {0};

    /* Validate DOS header */
    if (dataSize < sizeof(IMAGE_DOS_HEADER)) return info;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return info;  /* "MZ" */

    /* Validate NT headers */
    if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > dataSize) return info;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return info;  /* "PE\0\0" */

    info.valid = TRUE;
    info.machine = nt->FileHeader.Machine;
    info.numberOfSections = nt->FileHeader.NumberOfSections;
    info.entryPointRVA = nt->OptionalHeader.AddressOfEntryPoint;
    info.imageBase = nt->OptionalHeader.ImageBase;
    info.sizeOfImage = nt->OptionalHeader.SizeOfImage;
    info.dllCharacteristics = nt->OptionalHeader.DllCharacteristics;

    info.isExecutable = !(nt->FileHeader.Characteristics & IMAGE_FILE_DLL);
    info.isDLL = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

    /* Check data directories */
    info.hasExports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0;
    info.hasImports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0;
    info.hasRelocations = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0;
    info.hasTLS = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0;

    return info;
}

void display_pe_info(PE_INFO *info) {
    printf("=== PE Analysis ===\n");
    printf("Machine:         0x%04X (%s)\n", info->machine,
           info->machine == 0x8664 ? "x64" :
           info->machine == 0x14C  ? "x86" : "Other");
    printf("Type:            %s\n", info->isDLL ? "DLL" : "EXE");
    printf("Entry Point RVA: 0x%08X\n", info->entryPointRVA);
    printf("Image Base:      0x%016llX\n", info->imageBase);
    printf("Size of Image:   0x%08X (%u KB)\n", info->sizeOfImage,
           info->sizeOfImage / 1024);
    printf("Sections:        %d\n", info->numberOfSections);
    printf("Has Exports:     %s\n", info->hasExports ? "Yes" : "No");
    printf("Has Imports:     %s\n", info->hasImports ? "Yes" : "No");
    printf("Has Relocations: %s\n", info->hasRelocations ? "Yes" : "No");
    printf("Has TLS:         %s\n", info->hasTLS ? "Yes" : "No");
    printf("ASLR Enabled:    %s\n",
           (info->dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) ? "Yes" : "No");
}
```

### Reflective Loading Process (Educational)

```c
/*
 * Educational: The conceptual steps of reflective PE loading.
 *
 * This documents the PROCESS, not a complete implementation.
 * Understanding these steps is essential for:
 * 1. Analyzing reflective loaders found in malware
 * 2. Building detection for each step
 * 3. Understanding Cobalt Strike's reflective DLL injection
 *
 * Step-by-step Loading Process:
 *
 * STEP 1: Parse PE Headers
 * ─────────────────────────
 * Read DOS header -> find NT headers -> extract:
 * - SizeOfImage (how much memory to allocate)
 * - AddressOfEntryPoint (where to start execution)
 * - SectionAlignment (how to align sections in memory)
 * - Data directories (imports, relocations, TLS)
 *
 * Detection: PE header parsing from non-loader process
 *
 *
 * STEP 2: Allocate Memory
 * ───────────────────────
 * VirtualAlloc(SizeOfImage) with appropriate protections.
 * Try preferred ImageBase first; if unavailable, any address.
 *
 * Detection: Large RWX/RW allocation matching PE SizeOfImage
 *
 *
 * STEP 3: Map Sections
 * ────────────────────
 * Copy each section to its correct virtual address offset:
 *   for each section:
 *     memcpy(base + section.VirtualAddress,
 *            pe_data + section.PointerToRawData,
 *            section.SizeOfRawData)
 *
 * Detection: Sequential memory writes to aligned boundaries
 *
 *
 * STEP 4: Process Relocations
 * ───────────────────────────
 * If loaded at non-preferred base, fix all absolute addresses:
 *   delta = actual_base - preferred_base
 *   for each relocation entry:
 *     *(DWORD_PTR*)(base + reloc.offset) += delta
 *
 * Detection: Many pointer-sized writes to recently allocated memory
 *
 *
 * STEP 5: Resolve Imports
 * ───────────────────────
 * Walk the import directory and resolve each imported function:
 *   for each imported DLL:
 *     hDll = LoadLibrary(dll_name)  ← Detectable API call
 *     for each imported function:
 *       addr = GetProcAddress(hDll, func_name)
 *       *(IAT_entry) = addr
 *
 * Detection: LoadLibrary + GetProcAddress calls from non-standard location
 *
 *
 * STEP 6: Execute TLS Callbacks (if present)
 * ──────────────────────────────────────────
 * TLS (Thread Local Storage) callbacks run before the entry point.
 * Some malware hides initialization code in TLS callbacks.
 *
 * Detection: TLS directory in non-file-backed memory
 *
 *
 * STEP 7: Set Section Protections
 * ───────────────────────────────
 * Apply correct protections to each section:
 *   .text  → PAGE_EXECUTE_READ
 *   .rdata → PAGE_READONLY
 *   .data  → PAGE_READWRITE
 *
 * Detection: VirtualProtect calls setting EXECUTE on heap memory
 *
 *
 * STEP 8: Call Entry Point
 * ────────────────────────
 * For DLLs: call DllMain(base, DLL_PROCESS_ATTACH, NULL)
 * For EXEs: call main() or entry point
 *
 * Detection: Execution flow entering non-module memory
 */

/*
 * Relocation Processing (Educational)
 *
 * Base relocations fix absolute addresses when a PE is loaded
 * at a different base than its preferred ImageBase.
 */
void process_relocations_educational(
    BYTE *imageBase,
    ULONGLONG preferredBase,
    IMAGE_NT_HEADERS64 *ntHeaders
) {
    LONGLONG delta = (LONGLONG)((ULONGLONG)imageBase - preferredBase);
    if (delta == 0) return;  /* Loaded at preferred base */

    DWORD relocRVA = ntHeaders->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD relocSize = ntHeaders->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (relocRVA == 0 || relocSize == 0) return;

    IMAGE_BASE_RELOCATION *reloc = (IMAGE_BASE_RELOCATION *)(imageBase + relocRVA);

    while (reloc->VirtualAddress && reloc->SizeOfBlock) {
        DWORD entryCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *entries = (WORD *)(reloc + 1);

        for (DWORD i = 0; i < entryCount; i++) {
            WORD type = entries[i] >> 12;
            WORD offset = entries[i] & 0x0FFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                /* 64-bit relocation: add delta to 8-byte value */
                ULONGLONG *addr = (ULONGLONG *)(imageBase + reloc->VirtualAddress + offset);
                *addr += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                /* 32-bit relocation: add delta to 4-byte value */
                DWORD *addr = (DWORD *)(imageBase + reloc->VirtualAddress + offset);
                *addr += (DWORD)delta;
            }
            /* type == 0 (IMAGE_REL_BASED_ABSOLUTE) = padding, skip */
        }

        reloc = (IMAGE_BASE_RELOCATION *)((BYTE *)reloc + reloc->SizeOfBlock);
    }
}
```

## Detection & Evasion

### Detection Indicators

| Loading Step | Detection Method | Indicator |
|-------------|-----------------|-----------|
| PE in memory | Memory scanning | "MZ" + "PE\0\0" in non-file-backed regions |
| Allocation | API monitoring | VirtualAlloc with size matching PE SizeOfImage |
| Relocations | Write pattern | Many aligned pointer writes to new allocation |
| Import resolution | API monitoring | LoadLibrary + GetProcAddress from heap/stack |
| Section protection | API monitoring | VirtualProtect setting EXECUTE on non-module memory |
| Entry point | Call stack | Execution originating from unbacked memory |

### Memory Scanning Rules

```
YARA Rule for In-Memory PE Detection:

rule Reflective_PE_In_Memory {
    meta:
        description = "Detects PE file loaded reflectively in memory"
        severity = "high"
    strings:
        $mz = "MZ"
        $pe = "PE\x00\x00"
        $section_text = ".text"
        $section_rdata = ".rdata"
    condition:
        $mz at 0 and
        $pe in (0x40..0x400) and
        ($section_text or $section_rdata) and
        // Not a file on disk - memory scan only
        not uint16(0) == 0x5A4D  // redundant but explicit
}

Detection Tools:
- pe-sieve: Scans process memory for unbacked PE images
- Moneta: Detects anomalous memory regions
- Hollows Hunter: Finds hollowed/injected PEs
- Volatility: Memory forensics PE carving
```

### Defensive Recommendations

1. **pe-sieve**: Run periodically to scan for in-memory PEs
2. **CIG (Code Integrity Guard)**: Prevent unsigned code execution
3. **Memory scanning**: YARA rules for PE headers in non-file regions
4. **Call stack validation**: Flag execution from unbacked memory
5. **ETW monitoring**: Track VirtualAlloc + VirtualProtect sequences

## Cross-References

- [Process Hollowing](../process-injection/process-hollowing.md)
- [DLL Injection](../process-injection/dll-injection.md)
- [Module Stomping](../process-injection/module-stomping.md)
- [COFF Format Deep Dive](../coff-loaders/coff-format-deep-dive.md)
- [AV/EDR Evasion](../../06-defense-evasion/av-edr-evasion.md)

## References

- Microsoft: PE Format Specification
- MITRE ATT&CK T1620
- Stephen Fewer: Reflective DLL Injection (original research)
- monoxgas: sRDI - Shellcode Reflective DLL Injection (https://github.com/monoxgas/sRDI) - converts any DLL to PIC shellcode with reflective loader
- TheWover: donut (https://github.com/TheWover/donut) - PE/DLL/.NET to shellcode converter
- hasherezade: pe-sieve, libpeconv
- Cobalt Strike: Reflective Loading Documentation

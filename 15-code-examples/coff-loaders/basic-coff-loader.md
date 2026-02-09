# Basic COFF Loader Implementation

> **Languages**: C
> **Purpose**: Minimal but functional COFF object file loader that can parse, relocate, and execute a BOF

## Overview

This is a simplified but **working** COFF loader. It performs the five essential steps:

1. Parse the COFF file header and validate it
2. Allocate memory for each section and copy raw data
3. Build a symbol map and resolve external symbols via `GetProcAddress`
4. Process relocations to patch in actual addresses
5. Find the entry point (`go` function) and call it

This handles the most common x64 relocation types and the `MODULE$Function` dynamic function
resolution convention used by BOFs.

## Full C Implementation

```c
/*
 * basic_coff_loader.c
 *
 * A minimal COFF/BOF loader for x64 Windows.
 * Compile: cl.exe /nologo basic_coff_loader.c /link /out:loader.exe
 *
 * Usage: loader.exe <path_to_bof.o>
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ========================================================================
 * COFF Structure Definitions
 * ======================================================================== */

#pragma pack(push, 1)

typedef struct {
    UINT16 Machine;
    UINT16 NumberOfSections;
    UINT32 TimeDateStamp;
    UINT32 PointerToSymbolTable;
    UINT32 NumberOfSymbols;
    UINT16 SizeOfOptionalHeader;
    UINT16 Characteristics;
} COFF_FILE_HEADER;

typedef struct {
    char    Name[8];
    UINT32  VirtualSize;
    UINT32  VirtualAddress;
    UINT32  SizeOfRawData;
    UINT32  PointerToRawData;
    UINT32  PointerToRelocations;
    UINT32  PointerToLinenumbers;
    UINT16  NumberOfRelocations;
    UINT16  NumberOfLinenumbers;
    UINT32  Characteristics;
} COFF_SECTION;

typedef struct {
    union {
        char ShortName[8];
        struct {
            UINT32 Zeroes;
            UINT32 Offset;
        } LongName;
    } Name;
    UINT32 Value;
    INT16  SectionNumber;
    UINT16 Type;
    UINT8  StorageClass;
    UINT8  NumberOfAuxSymbols;
} COFF_SYMBOL;

typedef struct {
    UINT32 VirtualAddress;
    UINT32 SymbolTableIndex;
    UINT16 Type;
} COFF_RELOCATION;

#pragma pack(pop)

/* Relocation types for AMD64 */
#define IMAGE_REL_AMD64_ABSOLUTE  0x0000
#define IMAGE_REL_AMD64_ADDR64    0x0001
#define IMAGE_REL_AMD64_ADDR32NB  0x0003
#define IMAGE_REL_AMD64_REL32     0x0004
#define IMAGE_REL_AMD64_REL32_1   0x0005
#define IMAGE_REL_AMD64_REL32_2   0x0006
#define IMAGE_REL_AMD64_REL32_3   0x0007
#define IMAGE_REL_AMD64_REL32_4   0x0008
#define IMAGE_REL_AMD64_REL32_5   0x0009
#define IMAGE_REL_AMD64_SECREL    0x000B

/* Section characteristics */
#define SCN_MEM_EXECUTE  0x20000000
#define SCN_MEM_READ     0x40000000
#define SCN_MEM_WRITE    0x80000000
#define SCN_CNT_UNINIT   0x00000080

/* Symbol storage classes */
#define SYM_CLASS_EXTERNAL  0x02
#define SYM_CLASS_STATIC    0x03

/* ========================================================================
 * Loaded Section Tracking
 * ======================================================================== */

typedef struct {
    char*         data;      /* Pointer to allocated memory for this section     */
    COFF_SECTION* header;    /* Pointer to section header in the raw COFF data   */
    DWORD         allocSize; /* How many bytes were allocated                     */
} LoadedSection;

/* ========================================================================
 * Beacon API Stubs
 *
 * A real loader implements these fully. Here we provide minimal versions
 * that print to stdout so we can see BOF output.
 * ======================================================================== */

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1E
#define CALLBACK_ERROR       0x0D

void BeaconPrintf(int type, char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (type == CALLBACK_ERROR)
        fprintf(stderr, "[BOF ERROR] ");
    else
        printf("[BOF] ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

void BeaconOutput(int type, char* data, int len) {
    (void)type;
    printf("[BOF OUTPUT] %.*s\n", len, data);
}

/* ========================================================================
 * Helper: Get Symbol Name
 * ======================================================================== */

const char* GetSymbolName(COFF_SYMBOL* sym, char* stringTable) {
    static char nameBuf[256];
    if (sym->Name.LongName.Zeroes != 0) {
        /* Short name (up to 8 chars, may not be null-terminated) */
        memcpy(nameBuf, sym->Name.ShortName, 8);
        nameBuf[8] = '\0';
        return nameBuf;
    } else {
        /* Long name from string table */
        return stringTable + sym->Name.LongName.Offset;
    }
}

/* ========================================================================
 * Helper: Resolve External Symbol
 *
 * BOFs use the convention MODULE$Function for DFR (Dynamic Function
 * Resolution). For example, "KERNEL32$CreateFileA" means:
 *   LoadLibrary("KERNEL32.dll") -> GetProcAddress(h, "CreateFileA")
 *
 * Symbols starting with "__imp_" are indirect imports generated by MSVC.
 * We strip the prefix and resolve the underlying function.
 *
 * Beacon API functions (BeaconPrintf, BeaconOutput, etc.) are resolved
 * to our local stub implementations.
 * ======================================================================== */

void* ResolveExternalSymbol(const char* name) {
    /* Check for Beacon API functions first */
    if (strcmp(name, "BeaconPrintf") == 0  ||
        strcmp(name, "_BeaconPrintf") == 0 ||
        strcmp(name, "__imp_BeaconPrintf") == 0)
        return (void*)BeaconPrintf;

    if (strcmp(name, "BeaconOutput") == 0  ||
        strcmp(name, "_BeaconOutput") == 0 ||
        strcmp(name, "__imp_BeaconOutput") == 0)
        return (void*)BeaconOutput;

    /* Strip __imp_ prefix if present */
    const char* resolved = name;
    if (strncmp(name, "__imp_", 6) == 0)
        resolved = name + 6;

    /* Look for MODULE$Function pattern */
    const char* dollar = strchr(resolved, '$');
    if (dollar != NULL) {
        /* Extract module name and function name */
        char moduleName[128];
        size_t moduleLen = (size_t)(dollar - resolved);
        if (moduleLen >= sizeof(moduleName) - 5)
            return NULL;

        memcpy(moduleName, resolved, moduleLen);
        moduleName[moduleLen] = '\0';

        /* Append .dll if not already present */
        if (strstr(moduleName, ".") == NULL)
            strcat(moduleName, ".dll");

        const char* funcName = dollar + 1;

        /* Load the DLL and resolve the function */
        HMODULE hMod = LoadLibraryA(moduleName);
        if (hMod == NULL) {
            fprintf(stderr, "[-] Failed to load module: %s\n", moduleName);
            return NULL;
        }

        void* addr = (void*)GetProcAddress(hMod, funcName);
        if (addr == NULL) {
            fprintf(stderr, "[-] Failed to resolve: %s!%s\n", moduleName, funcName);
            return NULL;
        }

        printf("[+] Resolved: %s -> %p\n", resolved, addr);
        return addr;
    }

    /* Try resolving from already-loaded modules as a fallback */
    HMODULE modules[] = {
        GetModuleHandleA("kernel32.dll"),
        GetModuleHandleA("ntdll.dll"),
        GetModuleHandleA("advapi32.dll"),
        GetModuleHandleA("msvcrt.dll"),
        NULL
    };

    for (int i = 0; modules[i] != NULL; i++) {
        void* addr = (void*)GetProcAddress(modules[i], resolved);
        if (addr != NULL) {
            printf("[+] Resolved (fallback): %s -> %p\n", resolved, addr);
            return addr;
        }
    }

    fprintf(stderr, "[-] Unresolved external symbol: %s\n", name);
    return NULL;
}

/* ========================================================================
 * Section Permission Helper
 * ======================================================================== */

DWORD GetSectionProtection(UINT32 characteristics) {
    BOOL exec  = (characteristics & SCN_MEM_EXECUTE) != 0;
    BOOL read  = (characteristics & SCN_MEM_READ)    != 0;
    BOOL write = (characteristics & SCN_MEM_WRITE)   != 0;

    if (exec && write) return PAGE_EXECUTE_READWRITE;
    if (exec && read)  return PAGE_EXECUTE_READ;
    if (exec)          return PAGE_EXECUTE;
    if (write)         return PAGE_READWRITE;
    if (read)          return PAGE_READONLY;
    return PAGE_READWRITE; /* Default: readable/writable */
}

/* ========================================================================
 * Main Loader Function
 * ======================================================================== */

int LoadAndExecuteCOFF(BYTE* coffData, DWORD coffSize) {
    int result = -1;

    /* ----------------------------------------------------------------
     * Step 1: Parse and validate the COFF file header
     * ---------------------------------------------------------------- */
    if (coffSize < sizeof(COFF_FILE_HEADER)) {
        fprintf(stderr, "[-] File too small for COFF header\n");
        return -1;
    }

    COFF_FILE_HEADER* fileHeader = (COFF_FILE_HEADER*)coffData;

    if (fileHeader->Machine != 0x8664) {
        fprintf(stderr, "[-] Not an x64 COFF object (Machine: 0x%04X)\n",
                fileHeader->Machine);
        return -1;
    }

    if (fileHeader->SizeOfOptionalHeader != 0) {
        fprintf(stderr, "[-] Has optional header - this is a PE, not a COFF object\n");
        return -1;
    }

    printf("[+] COFF: %d sections, %d symbols\n",
           fileHeader->NumberOfSections, fileHeader->NumberOfSymbols);

    /* ----------------------------------------------------------------
     * Step 2: Allocate and populate sections
     * ---------------------------------------------------------------- */
    int numSections = fileHeader->NumberOfSections;
    LoadedSection* sections = (LoadedSection*)calloc(numSections, sizeof(LoadedSection));
    if (!sections) return -1;

    COFF_SECTION* sectionHeaders = (COFF_SECTION*)(coffData + sizeof(COFF_FILE_HEADER));

    for (int i = 0; i < numSections; i++) {
        COFF_SECTION* sh = &sectionHeaders[i];
        sections[i].header = sh;

        /* Determine allocation size: max of VirtualSize and SizeOfRawData */
        DWORD allocSize = sh->SizeOfRawData;
        if (sh->VirtualSize > allocSize)
            allocSize = sh->VirtualSize;
        if (allocSize == 0)
            allocSize = 1024; /* Minimum allocation for empty sections */

        sections[i].allocSize = allocSize;

        /* Allocate with RWX initially; we tighten permissions after relocation */
        sections[i].data = (char*)VirtualAlloc(
            NULL, allocSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (sections[i].data == NULL) {
            fprintf(stderr, "[-] VirtualAlloc failed for section %d\n", i);
            goto cleanup;
        }

        /* Zero the allocation, then copy raw data if present */
        memset(sections[i].data, 0, allocSize);
        if (sh->SizeOfRawData > 0 && sh->PointerToRawData > 0) {
            memcpy(sections[i].data,
                   coffData + sh->PointerToRawData,
                   sh->SizeOfRawData);
        }

        char secName[9] = {0};
        memcpy(secName, sh->Name, 8);
        printf("[+] Section %-8s: %d bytes at %p\n",
               secName, allocSize, sections[i].data);
    }

    /* ----------------------------------------------------------------
     * Step 3: Parse symbol table and build address map
     * ---------------------------------------------------------------- */
    COFF_SYMBOL* symbolTable = (COFF_SYMBOL*)(
        coffData + fileHeader->PointerToSymbolTable
    );
    char* stringTable = (char*)(
        coffData + fileHeader->PointerToSymbolTable
        + (fileHeader->NumberOfSymbols * sizeof(COFF_SYMBOL))
    );

    /* Allocate an array to hold the resolved address for each symbol */
    void** symbolAddresses = (void**)calloc(fileHeader->NumberOfSymbols, sizeof(void*));
    if (!symbolAddresses) goto cleanup;

    /* Track the entry point (symbol named "go") */
    void* entryPoint = NULL;

    for (UINT32 i = 0; i < fileHeader->NumberOfSymbols; i++) {
        COFF_SYMBOL* sym = &symbolTable[i];
        const char* name = GetSymbolName(sym, stringTable);

        if (sym->SectionNumber > 0) {
            /* Internal symbol: address is section base + value offset */
            int secIdx = sym->SectionNumber - 1;
            if (secIdx < numSections) {
                symbolAddresses[i] = sections[secIdx].data + sym->Value;
            }

            /* Check if this is our entry point */
            if (strcmp(name, "go") == 0 || strcmp(name, "_go") == 0) {
                entryPoint = symbolAddresses[i];
                printf("[+] Found entry point '%s' at %p\n", name, entryPoint);
            }
        }
        else if (sym->SectionNumber == 0 &&
                 sym->StorageClass == SYM_CLASS_EXTERNAL) {
            /* External symbol: resolve via DFR / GetProcAddress */
            symbolAddresses[i] = ResolveExternalSymbol(name);
            if (symbolAddresses[i] == NULL) {
                fprintf(stderr, "[!] Warning: unresolved symbol '%s'\n", name);
                /* Continue anyway; the BOF may not use this symbol */
            }
        }

        /* Skip auxiliary symbol entries */
        i += sym->NumberOfAuxSymbols;
    }

    if (entryPoint == NULL) {
        fprintf(stderr, "[-] Entry point 'go' not found in symbol table\n");
        goto cleanup;
    }

    /* ----------------------------------------------------------------
     * Step 4: Process relocations for each section
     * ---------------------------------------------------------------- */
    for (int i = 0; i < numSections; i++) {
        COFF_SECTION* sh = sections[i].header;
        if (sh->NumberOfRelocations == 0)
            continue;

        COFF_RELOCATION* relocs = (COFF_RELOCATION*)(
            coffData + sh->PointerToRelocations
        );

        for (int r = 0; r < sh->NumberOfRelocations; r++) {
            COFF_RELOCATION* rel = &relocs[r];

            /* Where in the loaded section to apply the patch */
            char* patchAddr = sections[i].data + rel->VirtualAddress;

            /* The target symbol's resolved address */
            void* symAddr = symbolAddresses[rel->SymbolTableIndex];
            if (symAddr == NULL) {
                fprintf(stderr, "[!] Relocation references NULL symbol (idx %d)\n",
                        rel->SymbolTableIndex);
                continue;
            }

            /* Apply the relocation based on type */
            switch (rel->Type) {
                case IMAGE_REL_AMD64_REL32: {
                    /* 32-bit PC-relative: target - (patch + 4) */
                    INT64 delta = (INT64)symAddr - ((INT64)patchAddr + 4);
                    *(INT32*)patchAddr = (INT32)delta;
                    break;
                }
                case IMAGE_REL_AMD64_REL32_1: {
                    INT64 delta = (INT64)symAddr - ((INT64)patchAddr + 5);
                    *(INT32*)patchAddr = (INT32)delta;
                    break;
                }
                case IMAGE_REL_AMD64_REL32_2: {
                    INT64 delta = (INT64)symAddr - ((INT64)patchAddr + 6);
                    *(INT32*)patchAddr = (INT32)delta;
                    break;
                }
                case IMAGE_REL_AMD64_REL32_3: {
                    INT64 delta = (INT64)symAddr - ((INT64)patchAddr + 7);
                    *(INT32*)patchAddr = (INT32)delta;
                    break;
                }
                case IMAGE_REL_AMD64_REL32_4: {
                    INT64 delta = (INT64)symAddr - ((INT64)patchAddr + 8);
                    *(INT32*)patchAddr = (INT32)delta;
                    break;
                }
                case IMAGE_REL_AMD64_REL32_5: {
                    INT64 delta = (INT64)symAddr - ((INT64)patchAddr + 9);
                    *(INT32*)patchAddr = (INT32)delta;
                    break;
                }
                case IMAGE_REL_AMD64_ADDR64: {
                    /* 64-bit absolute address */
                    *(UINT64*)patchAddr = (UINT64)symAddr;
                    break;
                }
                case IMAGE_REL_AMD64_ADDR32NB: {
                    /* 32-bit relative to image base (use first section as base) */
                    INT64 delta = (INT64)symAddr - (INT64)sections[0].data;
                    *(UINT32*)patchAddr = (UINT32)delta;
                    break;
                }
                case IMAGE_REL_AMD64_SECREL: {
                    /* 32-bit offset within the target symbol's section */
                    COFF_SYMBOL* targetSym = &symbolTable[rel->SymbolTableIndex];
                    *(UINT32*)patchAddr = targetSym->Value;
                    break;
                }
                case IMAGE_REL_AMD64_ABSOLUTE:
                    /* No-op */
                    break;
                default:
                    fprintf(stderr, "[!] Unknown relocation type 0x%04X\n", rel->Type);
                    break;
            }
        }
    }

    printf("[+] Relocations applied. Executing entry point...\n\n");

    /* ----------------------------------------------------------------
     * Step 5: Execute the entry point
     * ---------------------------------------------------------------- */
    typedef void (*BofEntry)(char* args, int len);
    BofEntry entry = (BofEntry)entryPoint;

    /* Call the BOF with no arguments (NULL, 0) */
    entry(NULL, 0);

    printf("\n[+] BOF execution complete.\n");
    result = 0;

    /* ----------------------------------------------------------------
     * Cleanup: Free all section memory
     * ---------------------------------------------------------------- */
cleanup:
    if (sections) {
        for (int i = 0; i < numSections; i++) {
            if (sections[i].data) {
                /* Zero memory before freeing to prevent forensic recovery */
                memset(sections[i].data, 0, sections[i].allocSize);
                VirtualFree(sections[i].data, 0, MEM_RELEASE);
            }
        }
        free(sections);
    }
    if (symbolAddresses)
        free(symbolAddresses);

    return result;
}

/* ========================================================================
 * Entry Point: Read BOF from disk and load it
 * ======================================================================== */

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <bof_file.o>\n", argv[0]);
        return 1;
    }

    /* Read the BOF file into memory */
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Cannot open file: %s\n", argv[1]);
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* fileData = (BYTE*)malloc(fileSize);
    DWORD bytesRead = 0;
    ReadFile(hFile, fileData, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    if (bytesRead != fileSize) {
        fprintf(stderr, "[-] Failed to read entire file\n");
        free(fileData);
        return 1;
    }

    printf("[+] Loaded %s (%d bytes)\n\n", argv[1], fileSize);

    /* Load and execute the COFF object */
    int result = LoadAndExecuteCOFF(fileData, fileSize);

    free(fileData);
    return result;
}
```

## Compilation

```bash
# With MSVC (recommended):
cl.exe /nologo /W4 basic_coff_loader.c /link /out:loader.exe

# With MinGW (cross-compile from Linux):
x86_64-w64-mingw32-gcc -o loader.exe basic_coff_loader.c -lkernel32

# Test with a simple BOF:
loader.exe my_bof.o
```

## How It Works Step by Step

1. **File header parsing**: The loader reads the 20-byte COFF header, checks that the machine
   type is x64 (0x8664) and that there is no optional header (confirming this is a raw COFF
   object, not a PE executable).

2. **Section loading**: For each section, the loader allocates memory with `VirtualAlloc` and
   copies the raw section data. Initially all memory is RWX so relocations can be applied to
   all sections. A production loader would tighten permissions after relocation.

3. **Symbol resolution**: The loader walks the symbol table. Internal symbols (defined in a
   section) get their address calculated as `section_base + value`. External symbols (section
   number 0) are resolved using the `MODULE$Function` naming convention -- split on `$`, call
   `LoadLibraryA` for the module, and `GetProcAddress` for the function. Beacon API symbols
   (`BeaconPrintf`, `BeaconOutput`) are mapped to local stub functions.

4. **Relocation processing**: For each section, the loader reads the relocation table and
   patches the loaded code. The most common type (`IMAGE_REL_AMD64_REL32`) computes a 32-bit
   relative offset: `target_addr - (patch_addr + 4)`. This is what x64 `CALL` and
   RIP-relative `LEA`/`MOV` instructions use.

5. **Execution**: The loader finds the symbol named `go` (the BOF entry point convention),
   casts it to a function pointer `void(*)(char*, int)`, and calls it.

6. **Cleanup**: After the BOF returns, all section memory is zeroed and freed. This prevents
   memory forensics tools from recovering the BOF code or data.

## Limitations of This Basic Loader

- No argument packing/parsing (the `datap` API) -- see the advanced loader
- No structured output (`formatp` API) -- only `BeaconPrintf` and `BeaconOutput` stubs
- No SEH wrapping around the BOF call -- a crash kills the process
- No timeout mechanism for hung BOFs
- Allocates all sections as RWX (should tighten after relocation)
- Single-threaded, synchronous execution only

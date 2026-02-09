# COFF File Format Deep Dive

> **Languages**: C (structure definitions)
> **Purpose**: Understanding the binary format you need to parse to build a COFF loader

## Overview

A COFF object file is the raw output of compilation before linking. It contains machine code,
data, and metadata that tells a linker (or our loader) how to fix up addresses so the code
can actually run. Understanding this format at the byte level is essential for building a
loader that can take a compiled BOF and execute it in-process.

The file is laid out sequentially: file header, section headers, raw data for each section,
relocation entries for each section, symbol table, and string table.

## COFF File Header (20 bytes)

```c
/*
 * The COFF file header sits at offset 0 of the file. It tells us the target
 * architecture, how many sections exist, and where to find the symbol table.
 *
 * IMPORTANT: COFF objects have NO optional header (SizeOfOptionalHeader == 0).
 * PE executables (which wrap COFF) DO have an optional header. If
 * SizeOfOptionalHeader != 0, you are looking at a PE, not a raw COFF object.
 */
typedef struct _COFF_FILE_HEADER {
    UINT16 Machine;
    /*
     * Target architecture. Common values:
     *   0x8664 = IMAGE_FILE_MACHINE_AMD64  (x86-64)
     *   0x014C = IMAGE_FILE_MACHINE_I386   (x86-32)
     *   0xAA64 = IMAGE_FILE_MACHINE_ARM64  (AArch64)
     *
     * Your loader MUST check this field. Loading an x86 BOF into an x64
     * process will crash or produce garbage results because relocations
     * and calling conventions differ.
     */

    UINT16 NumberOfSections;
    /*
     * How many section headers follow immediately after this file header.
     * Typical BOFs have 2-6 sections: .text, .data, .rdata, .bss, and
     * sometimes .pdata (exception unwind info) or debug sections.
     */

    UINT32 TimeDateStamp;
    /*
     * Unix timestamp of when the file was compiled. Useful for forensics,
     * often zeroed out intentionally by red team tooling to reduce indicators.
     */

    UINT32 PointerToSymbolTable;
    /*
     * Absolute file offset to the symbol table. The symbol table is an
     * array of 18-byte COFF_SYMBOL entries. This is the most important
     * pointer in the header for a loader -- without symbols, you cannot
     * resolve external API calls or find the entry point.
     */

    UINT32 NumberOfSymbols;
    /*
     * Total number of symbol table entries (including auxiliary symbols).
     * The string table begins immediately after:
     *   string_table_offset = PointerToSymbolTable + (NumberOfSymbols * 18)
     */

    UINT16 SizeOfOptionalHeader;
    /*
     * For COFF objects, this MUST be 0. If nonzero, you are parsing a PE
     * executable (which has a COFF header followed by an optional header
     * followed by section headers). A loader should reject files where
     * this field is nonzero.
     */

    UINT16 Characteristics;
    /*
     * Bitfield of file attributes. For COFF objects, typically 0 or a
     * combination of:
     *   0x0001 = IMAGE_FILE_RELOCS_STRIPPED      (no relocations)
     *   0x0004 = IMAGE_FILE_LINE_NUMS_STRIPPED    (no line numbers)
     *   0x0008 = IMAGE_FILE_LOCAL_SYMS_STRIPPED   (no local symbols)
     *   0x0020 = IMAGE_FILE_LARGE_ADDRESS_AWARE   (can handle >2GB)
     *   0x0100 = IMAGE_FILE_32BIT_MACHINE         (32-bit target)
     */
} COFF_FILE_HEADER;
/* sizeof(COFF_FILE_HEADER) == 20 bytes */
```

## Section Header (40 bytes each)

```c
/*
 * Section headers immediately follow the file header. There are exactly
 * NumberOfSections of them. Each describes a contiguous block of data
 * (code, initialized data, read-only data, etc.) and where to find
 * its relocations.
 *
 * Memory layout of section headers in the file:
 *   offset = sizeof(COFF_FILE_HEADER) + SizeOfOptionalHeader
 *   section[i] is at offset + (i * 40)
 */
typedef struct _COFF_SECTION {
    char Name[8];
    /*
     * Section name, null-padded (NOT necessarily null-terminated if exactly
     * 8 chars). Common names in BOFs:
     *   ".text"   - Executable code (the compiled functions)
     *   ".data"   - Initialized writable data (global variables with values)
     *   ".rdata"  - Read-only initialized data (string literals, vtables)
     *   ".bss"    - Uninitialized data (zero-filled at load time)
     *   ".reloc"  - Base relocations (rare in COFF objects)
     *   ".pdata"  - Exception handler unwind data (x64)
     *   ".xdata"  - Exception handler unwind data (x64, extended)
     *
     * If Name[0] == '/', the remaining 7 bytes are an ASCII decimal number
     * that is an offset into the string table. This handles section names
     * longer than 8 characters (rare but possible).
     */

    UINT32 VirtualSize;
    /*
     * Size of the section when loaded into memory. In COFF objects (as
     * opposed to PE files), this is typically 0. The loader should use
     * max(VirtualSize, SizeOfRawData) when allocating memory.
     */

    UINT32 VirtualAddress;
    /*
     * In COFF objects, this is always 0. In PE files, it is the RVA
     * (relative virtual address) where the section will be mapped.
     * Your loader ignores this and allocates sections wherever VirtualAlloc
     * places them.
     */

    UINT32 SizeOfRawData;
    /*
     * Size of the section data on disk, in bytes. This is how many bytes
     * to copy from PointerToRawData. For .bss sections, this is 0 (the
     * section is all zeros, allocated but not stored on disk).
     */

    UINT32 PointerToRawData;
    /*
     * Absolute file offset to the raw data for this section. Read
     * SizeOfRawData bytes starting here. For .bss, this is 0.
     */

    UINT32 PointerToRelocations;
    /*
     * Absolute file offset to this section's relocation table. Each
     * relocation entry is 10 bytes (COFF_RELOCATION). There are
     * NumberOfRelocations entries. This is the critical data: it tells
     * the loader which bytes in this section need to be patched with
     * actual addresses.
     */

    UINT32 PointerToLinenumbers;
    /* File offset to line number entries. Usually 0. Ignored by loaders. */

    UINT16 NumberOfRelocations;
    /*
     * How many relocation entries exist for this section. If this is 0xFFFF,
     * the actual count is stored in the first relocation entry's VirtualAddress
     * field (extended relocations). Most BOFs have far fewer.
     */

    UINT16 NumberOfLinenumbers;
    /* Number of line number entries. Usually 0. Ignored by loaders. */

    UINT32 Characteristics;
    /*
     * Bitfield describing the section's properties. The loader uses these
     * to set memory permissions. Key flags:
     *
     *   0x00000020 = IMAGE_SCN_CNT_CODE              Contains code
     *   0x00000040 = IMAGE_SCN_CNT_INITIALIZED_DATA  Contains initialized data
     *   0x00000080 = IMAGE_SCN_CNT_UNINITIALIZED_DATA Contains uninitialized data (.bss)
     *   0x01000000 = IMAGE_SCN_LNK_NRELOC_OVFL       Extended relocations
     *   0x02000000 = IMAGE_SCN_MEM_DISCARDABLE        Can be discarded after loading
     *   0x04000000 = IMAGE_SCN_MEM_NOT_CACHED         Should not be cached
     *   0x08000000 = IMAGE_SCN_MEM_NOT_PAGED          Should not be paged out
     *   0x10000000 = IMAGE_SCN_MEM_SHARED             Shared across processes
     *   0x20000000 = IMAGE_SCN_MEM_EXECUTE            Executable memory
     *   0x40000000 = IMAGE_SCN_MEM_READ               Readable memory
     *   0x80000000 = IMAGE_SCN_MEM_WRITE              Writable memory
     *
     * For a loader, the important combination is:
     *   .text  -> EXECUTE | READ         -> PAGE_EXECUTE_READ
     *   .data  -> READ | WRITE           -> PAGE_READWRITE
     *   .rdata -> READ                   -> PAGE_READONLY
     *   .bss   -> READ | WRITE           -> PAGE_READWRITE
     */
} COFF_SECTION;
/* sizeof(COFF_SECTION) == 40 bytes */
```

## Symbol Table Entry (18 bytes each)

```c
/*
 * The symbol table is the registry of every named entity in the object
 * file: functions, global variables, section names, and external references.
 * It sits at file offset PointerToSymbolTable and contains NumberOfSymbols
 * entries, each exactly 18 bytes.
 *
 * For a COFF loader, symbols serve two purposes:
 * 1. Finding the entry point (symbol named "go" or "_main")
 * 2. Finding external references that need to be resolved (Win32 API
 *    functions like "KERNEL32$CreateFileA")
 */
typedef struct _COFF_SYMBOL {
    union {
        char ShortName[8];
        /*
         * If the first 4 bytes are nonzero, this is the symbol name,
         * null-padded to 8 bytes. Most API function names are longer
         * than 8 characters, so they use the string table instead.
         */
        struct {
            UINT32 Zeroes;
            /*
             * If this is 0, the name is stored in the string table
             * at the offset specified by the Offset field below.
             */
            UINT32 Offset;
            /*
             * Offset into the string table. The string table starts
             * immediately after the symbol table. The first 4 bytes
             * of the string table are its total size (including those
             * 4 bytes). So string_table[Offset] gives you the name.
             *
             * string_table_start = file_base + PointerToSymbolTable
             *                      + (NumberOfSymbols * 18)
             * name = string_table_start + Offset
             */
        } LongName;
    } Name;

    UINT32 Value;
    /*
     * Meaning depends on StorageClass and SectionNumber:
     * - For defined symbols (SectionNumber > 0): byte offset within the
     *   section where this symbol lives. E.g., a function at offset 0x40
     *   in .text has Value = 0x40.
     * - For external symbols (SectionNumber == 0): typically 0
     * - For absolute symbols (SectionNumber == -1): the value itself
     */

    INT16 SectionNumber;
    /*
     * Which section this symbol is defined in (1-based index):
     *   > 0  : Symbol is defined in section N (1 = first section)
     *   0    : IMAGE_SYM_UNDEFINED - external symbol, needs resolution
     *   -1   : IMAGE_SYM_ABSOLUTE  - absolute value, not relocated
     *   -2   : IMAGE_SYM_DEBUG     - debug information
     *
     * For the loader:
     *   SectionNumber > 0  -> internal symbol, address = sections[N-1].data + Value
     *   SectionNumber == 0 -> external symbol, resolve via GetProcAddress
     */

    UINT16 Type;
    /*
     * Symbol type. The low byte is the base type, high byte is the derived
     * type. In practice, the only value that matters:
     *   0x0020 = function type (IMAGE_SYM_DTYPE_FUNCTION << 4)
     *   0x0000 = not a function
     */

    UINT8 StorageClass;
    /*
     * How this symbol is stored. Important values:
     *   0x02 = IMAGE_SYM_CLASS_EXTERNAL    Visible outside this file
     *   0x03 = IMAGE_SYM_CLASS_STATIC      File-scope (static keyword)
     *   0x06 = IMAGE_SYM_CLASS_LABEL       Code label
     *   0x68 = IMAGE_SYM_CLASS_SECTION     Section symbol
     *
     * For a loader, IMAGE_SYM_CLASS_EXTERNAL + SectionNumber==0 means
     * "this is an imported function that I need to resolve."
     */

    UINT8 NumberOfAuxSymbols;
    /*
     * Number of auxiliary symbol records following this entry. Auxiliary
     * symbols provide extra info (section definitions, file names, etc.)
     * and are also 18 bytes each. When iterating the symbol table, skip
     * these: next_index = current_index + 1 + NumberOfAuxSymbols.
     */
} COFF_SYMBOL;
/* sizeof(COFF_SYMBOL) == 18 bytes */
```

## Relocation Entry (10 bytes each)

```c
/*
 * Relocations tell the loader exactly which bytes in a section need to be
 * patched to contain actual runtime addresses. Each section has its own
 * relocation table (pointed to by PointerToRelocations in the section header).
 *
 * Without relocations, the code would reference address 0 for every function
 * call and global variable access. The relocation table says: "at offset X
 * in this section, patch in the address of symbol Y using method Z."
 */
typedef struct _COFF_RELOCATION {
    UINT32 VirtualAddress;
    /*
     * Byte offset within the section where the relocation should be applied.
     * For example, if .text contains a CALL instruction at offset 0x15 that
     * references an external function, VirtualAddress = 0x15 (pointing to
     * the displacement bytes of the CALL, not the opcode byte).
     */

    UINT32 SymbolTableIndex;
    /*
     * Zero-based index into the symbol table. This identifies WHICH symbol
     * the relocation references. The loader looks up this symbol to get
     * the target address (either from a loaded section or from GetProcAddress).
     */

    UINT16 Type;
    /*
     * How to apply the relocation. This is architecture-specific.
     * See the tables below for x64 and x86 relocation types.
     */
} COFF_RELOCATION;
/* sizeof(COFF_RELOCATION) == 10 bytes */
```

## x64 (AMD64) Relocation Types

```c
/*
 * These are the relocation types you will encounter in x64 BOFs.
 * Your loader MUST handle at least the first four to work correctly.
 *
 * Notation:
 *   S = symbol address (resolved address of the target)
 *   P = patch location (address of the bytes being patched)
 *   The loader writes the computed value at address P.
 */

#define IMAGE_REL_AMD64_ABSOLUTE  0x0000
/*
 * No relocation. Padding entry. Skip it.
 */

#define IMAGE_REL_AMD64_ADDR64    0x0001
/*
 * 64-bit absolute address. Write the full 8-byte address of the symbol.
 *   *(UINT64*)P = S
 *
 * Used for: 64-bit data pointers, jump tables, vtable entries.
 * Example: A global pointer variable initialized to the address of a function.
 */

#define IMAGE_REL_AMD64_ADDR32NB  0x0003
/*
 * 32-bit address relative to image base (no base, hence "NB").
 *   *(UINT32*)P = S - ImageBase
 *
 * Used for: exception unwind data in .pdata/.xdata sections.
 * The loader needs to track a conceptual "image base" for this.
 * In practice, use the base address of the first section.
 */

#define IMAGE_REL_AMD64_REL32     0x0004
/*
 * 32-bit relative displacement. THE MOST COMMON RELOCATION in x64 code.
 *   *(INT32*)P = S - (P + 4)
 *
 * Used for: CALL and JMP instructions, RIP-relative data access (LEA, MOV).
 * On x64, most instructions use RIP-relative addressing, so this is by far
 * the most frequent relocation type. The "+4" accounts for the fact that
 * RIP-relative offsets are computed from the end of the instruction's
 * displacement field (which is 4 bytes).
 */

#define IMAGE_REL_AMD64_REL32_1   0x0005
/*
 *   *(INT32*)P = S - (P + 5)
 * Same as REL32 but the instruction has 1 extra byte after the displacement.
 */

#define IMAGE_REL_AMD64_REL32_2   0x0006
/*
 *   *(INT32*)P = S - (P + 6)
 * Same as REL32 but with 2 extra bytes after displacement.
 */

#define IMAGE_REL_AMD64_REL32_3   0x0007
/*
 *   *(INT32*)P = S - (P + 7)
 * Same as REL32 but with 3 extra bytes after displacement.
 */

#define IMAGE_REL_AMD64_REL32_4   0x0008
/*
 *   *(INT32*)P = S - (P + 8)
 * Same as REL32 but with 4 extra bytes after displacement.
 */

#define IMAGE_REL_AMD64_REL32_5   0x0009
/*
 *   *(INT32*)P = S - (P + 9)
 * Same as REL32 but with 5 extra bytes after displacement.
 */

#define IMAGE_REL_AMD64_SECTION   0x000A
/*
 * 16-bit section index. Used in debug info.
 *   *(UINT16*)P = section_index_of(S)
 */

#define IMAGE_REL_AMD64_SECREL    0x000B
/*
 * 32-bit offset within the section containing the symbol.
 *   *(UINT32*)P = S - section_base_of(S)
 * Used in debug info and .pdata.
 */
```

## x86 (i386) Relocation Types

```c
/*
 * If you support 32-bit BOFs, you need these as well.
 */

#define IMAGE_REL_I386_ABSOLUTE   0x0000
/* No relocation. Skip. */

#define IMAGE_REL_I386_DIR32      0x0006
/*
 * 32-bit absolute address.
 *   *(UINT32*)P = S
 * This is the primary relocation for x86 code. Unlike x64, 32-bit code
 * uses absolute addresses for most references.
 */

#define IMAGE_REL_I386_DIR32NB    0x0007
/*
 * 32-bit address without base.
 *   *(UINT32*)P = S - ImageBase
 */

#define IMAGE_REL_I386_REL32      0x0014
/*
 * 32-bit PC-relative displacement.
 *   *(INT32*)P = S - (P + 4)
 * Used for CALL and JMP instructions on x86.
 */
```

## How the Pieces Connect

```
File Parse Flow:
================

1. Read COFF_FILE_HEADER at offset 0
   |
   +-> Validate: Machine == 0x8664, SizeOfOptionalHeader == 0
   +-> Note: NumberOfSections, PointerToSymbolTable, NumberOfSymbols

2. Read Section Headers at offset 20
   |
   +-> For each section (i = 0 .. NumberOfSections-1):
       |
       +-> section[i] at offset 20 + (i * 40)
       +-> Allocate memory: VirtualAlloc(max(VirtualSize, SizeOfRawData))
       +-> Copy raw data: memcpy(alloc, file + PointerToRawData, SizeOfRawData)

3. Read Symbol Table at offset PointerToSymbolTable
   |
   +-> For each symbol (j = 0 .. NumberOfSymbols-1):
       |
       +-> Get name (ShortName or string table lookup)
       +-> If SectionNumber > 0: internal, address = section[N-1].alloc + Value
       +-> If SectionNumber == 0: external, resolve via GetProcAddress
       |   +-> Parse "MODULE$Function" convention
       |   +-> LoadLibraryA("MODULE.dll") then GetProcAddress(h, "Function")
       +-> Skip NumberOfAuxSymbols auxiliary entries

4. Process Relocations for each section
   |
   +-> For each section with NumberOfRelocations > 0:
       |
       +-> Read relocation entries at PointerToRelocations
       +-> For each relocation:
           |
           +-> target = section.alloc + relocation.VirtualAddress
           +-> symbol = symbol_table[relocation.SymbolTableIndex]
           +-> symbol_addr = resolved address of that symbol
           +-> Apply based on Type:
               REL32:    *(INT32*)target  = symbol_addr - (target + 4)
               ADDR64:   *(UINT64*)target = symbol_addr
               ADDR32NB: *(UINT32*)target = symbol_addr - image_base

5. Find entry point: symbol named "go" with SectionNumber > 0
   |
   +-> entry_addr = section[sym.SectionNumber - 1].alloc + sym.Value
   +-> Cast to void(*)(char*, int) and call with arguments

6. Cleanup: VirtualFree all section allocations
```

## String Table

```c
/*
 * The string table immediately follows the symbol table in the file.
 *   string_table_offset = PointerToSymbolTable + (NumberOfSymbols * 18)
 *
 * Layout:
 *   Bytes 0-3:  UINT32 total size of string table (including these 4 bytes)
 *   Bytes 4+:   Null-terminated strings, packed sequentially
 *
 * When a symbol has Name.Zeroes == 0, its name is at:
 *   string_table_base + Name.Offset
 *
 * Example: If Name.Offset == 4, the name starts at the first string
 * (right after the size field).
 */

/* Helper to get a symbol's name */
const char* GetSymbolName(COFF_SYMBOL* sym, char* stringTable) {
    if (sym->Name.LongName.Zeroes != 0) {
        /* Short name: up to 8 chars, may not be null-terminated */
        static char buf[9];
        memcpy(buf, sym->Name.ShortName, 8);
        buf[8] = '\0';
        return buf;
    } else {
        /* Long name: look up in string table */
        return stringTable + sym->Name.LongName.Offset;
    }
}
```

## Practical Notes for Loader Authors

1. **Always check Machine type** before loading. An x86 BOF loaded into an x64 process will
   have wrong relocation types and calling conventions.

2. **The `__imp_` prefix**: When MSVC compiles a call to an imported function, it may generate
   a symbol named `__imp_FunctionName` (an indirect call through the IAT). BOFs compiled with
   the DFR convention use `MODULE$Function` instead, which is simpler for loaders to parse.

3. **Section alignment**: COFF objects typically have no alignment requirements beyond natural
   alignment. However, `VirtualAlloc` returns page-aligned memory (4096-byte aligned), which
   satisfies any alignment need.

4. **Auxiliary symbols**: When iterating the symbol table, remember to skip auxiliary entries.
   A symbol with `NumberOfAuxSymbols = 2` means the next 2 entries (36 bytes) are auxiliary
   data, not real symbols. Failure to skip these will desync your symbol table parsing.

5. **The `.bss` section**: Has `SizeOfRawData == 0` and `PointerToRawData == 0`. Allocate
   `VirtualSize` bytes and zero-fill. `VirtualAlloc` with `MEM_COMMIT` already zeros memory.

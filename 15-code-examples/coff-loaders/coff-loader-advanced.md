# Advanced COFF Loader Features

> **Languages**: C
> **Purpose**: Production-quality COFF loader with full Beacon API, argument packing, SEH, memory cleanup, and output capture

## Overview

This advanced loader builds on the basic loader with the features needed for real-world use:
a complete Beacon API implementation (format buffers, data parsers, output capture), argument
packing for passing operator input to BOFs, structured exception handling to prevent BOF
crashes from killing the host process, and thorough memory cleanup to frustrate forensics.

## Full C Implementation

```c
/*
 * advanced_coff_loader.c
 *
 * Production-quality COFF/BOF loader with full Beacon API support.
 *
 * Features:
 *   - Complete Beacon output/format/data APIs
 *   - Argument packing and parsing
 *   - SEH wrapping to survive BOF crashes
 *   - Tracked allocations with zeroing cleanup
 *   - Output capture into a caller-accessible buffer
 *   - Dynamic function resolution for MODULE$Function convention
 *
 * Compile (MSVC):
 *   cl.exe /nologo /W4 /EHa advanced_coff_loader.c /link /out:adv_loader.exe
 *
 * Compile (MinGW):
 *   x86_64-w64-mingw32-gcc -o adv_loader.exe advanced_coff_loader.c \
 *       -lkernel32 -luser32 -ladvapi32
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ========================================================================
 * COFF Structures (same as basic loader, included for completeness)
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
        struct { UINT32 Zeroes; UINT32 Offset; } LongName;
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

#define CALLBACK_OUTPUT      0x00
#define CALLBACK_OUTPUT_OEM  0x1E
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0D

/* ========================================================================
 * Global Output Capture Buffer
 *
 * All BeaconPrintf and BeaconOutput calls append to this buffer. After
 * the BOF returns, the caller can read the captured output. This is how
 * a C2 framework would collect BOF output to send back to the operator.
 * ======================================================================== */

typedef struct {
    char*  data;
    int    length;
    int    capacity;
} OutputBuffer;

static OutputBuffer g_output = { NULL, 0, 0 };

void OutputBuffer_Init(OutputBuffer* ob, int initialCapacity) {
    ob->data = (char*)malloc(initialCapacity);
    ob->length = 0;
    ob->capacity = initialCapacity;
    if (ob->data) ob->data[0] = '\0';
}

void OutputBuffer_Append(OutputBuffer* ob, const char* text, int len) {
    if (len <= 0) return;
    /* Grow if needed */
    while (ob->length + len + 1 > ob->capacity) {
        ob->capacity *= 2;
        ob->data = (char*)realloc(ob->data, ob->capacity);
    }
    memcpy(ob->data + ob->length, text, len);
    ob->length += len;
    ob->data[ob->length] = '\0';
}

void OutputBuffer_Free(OutputBuffer* ob) {
    if (ob->data) { free(ob->data); ob->data = NULL; }
    ob->length = 0;
    ob->capacity = 0;
}

/* ========================================================================
 * Beacon API Implementation: Output Functions
 * ======================================================================== */

void Impl_BeaconPrintf(int type, char* fmt, ...) {
    char temp[4096];
    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(temp, sizeof(temp), fmt, args);
    va_end(args);

    if (written > 0) {
        if (type == CALLBACK_ERROR) {
            OutputBuffer_Append(&g_output, "[ERROR] ", 8);
        }
        OutputBuffer_Append(&g_output, temp, written);
        OutputBuffer_Append(&g_output, "\n", 1);
    }
}

void Impl_BeaconOutput(int type, char* data, int len) {
    (void)type;
    if (data && len > 0) {
        OutputBuffer_Append(&g_output, data, len);
    }
}

/* ========================================================================
 * Beacon API Implementation: Format Buffer (formatp)
 *
 * The format API gives BOFs a growable string buffer. This is more
 * efficient than many individual BeaconPrintf calls because the BOF
 * builds its output locally and sends it in a single BeaconOutput call.
 * ======================================================================== */

typedef struct {
    char*  original;
    char*  buffer;
    int    length;
    int    size;
} formatp;

void Impl_BeaconFormatAlloc(formatp* fmt, int maxsz) {
    if (!fmt) return;
    fmt->original = (char*)calloc(1, maxsz);
    fmt->buffer   = fmt->original;
    fmt->length   = 0;
    fmt->size     = maxsz;
}

void Impl_BeaconFormatReset(formatp* fmt) {
    if (!fmt) return;
    fmt->buffer = fmt->original;
    fmt->length = 0;
    if (fmt->original) memset(fmt->original, 0, fmt->size);
}

void Impl_BeaconFormatFree(formatp* fmt) {
    if (!fmt) return;
    if (fmt->original) {
        memset(fmt->original, 0, fmt->size); /* Zero before free */
        free(fmt->original);
    }
    fmt->original = NULL;
    fmt->buffer = NULL;
    fmt->length = 0;
    fmt->size = 0;
}

void Impl_BeaconFormatAppend(formatp* fmt, char* text, int len) {
    if (!fmt || !text || len <= 0) return;
    if (fmt->length + len > fmt->size) return; /* Truncate silently */
    memcpy(fmt->buffer, text, len);
    fmt->buffer += len;
    fmt->length += len;
}

void Impl_BeaconFormatPrintf(formatp* fmt, char* fmtStr, ...) {
    if (!fmt || !fmtStr) return;
    int remaining = fmt->size - fmt->length;
    if (remaining <= 0) return;

    va_list args;
    va_start(args, fmtStr);
    int written = vsnprintf(fmt->buffer, remaining, fmtStr, args);
    va_end(args);

    if (written > 0 && written < remaining) {
        fmt->buffer += written;
        fmt->length += written;
    }
}

char* Impl_BeaconFormatToString(formatp* fmt, int* size) {
    if (!fmt) return NULL;
    if (size) *size = fmt->length;
    return fmt->original;
}

int Impl_BeaconFormatLength(formatp* fmt) {
    return fmt ? fmt->length : 0;
}

char* Impl_BeaconFormatOriginal(formatp* fmt) {
    return fmt ? fmt->original : NULL;
}

/* ========================================================================
 * Beacon API Implementation: Data Parser (datap / Argument Parsing)
 *
 * Arguments from the operator are packed into a binary buffer using a
 * simple type-length-value format. The data parser extracts values
 * sequentially. The packing format:
 *
 *   int:   4 bytes, big-endian
 *   short: 2 bytes, big-endian
 *   str:   4-byte length (big-endian) + string bytes + null terminator
 *   bin:   4-byte length (big-endian) + raw bytes
 * ======================================================================== */

typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} datap;

void Impl_BeaconDataParse(datap* parser, char* buffer, int size) {
    if (!parser) return;
    parser->original = buffer;
    parser->buffer   = buffer;
    parser->length   = size;
    parser->size     = size;
}

int Impl_BeaconDataInt(datap* parser) {
    if (!parser || parser->length < 4) return 0;
    /* Read 4 bytes big-endian */
    BYTE* p = (BYTE*)parser->buffer;
    int val = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
    parser->buffer += 4;
    parser->length -= 4;
    return val;
}

short Impl_BeaconDataShort(datap* parser) {
    if (!parser || parser->length < 2) return 0;
    BYTE* p = (BYTE*)parser->buffer;
    short val = (short)((p[0] << 8) | p[1]);
    parser->buffer += 2;
    parser->length -= 2;
    return val;
}

int Impl_BeaconDataLength(datap* parser) {
    return parser ? parser->length : 0;
}

char* Impl_BeaconDataExtract(datap* parser, int* outLen) {
    if (!parser || parser->length < 4) return NULL;

    /* Read the 4-byte length prefix (big-endian) */
    BYTE* p = (BYTE*)parser->buffer;
    int dataLen = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
    parser->buffer += 4;
    parser->length -= 4;

    if (dataLen <= 0 || dataLen > parser->length) return NULL;

    char* result = parser->buffer;
    parser->buffer += dataLen;
    parser->length -= dataLen;

    if (outLen) *outLen = dataLen;
    return result;
}

/* ========================================================================
 * Argument Packing (Operator -> BOF)
 *
 * This function builds the binary buffer that the BOF's go() receives.
 * The format string uses single characters to describe each argument:
 *   'i' = 4-byte integer
 *   's' = 2-byte short
 *   'z' = null-terminated string (packed as length + data)
 *   'b' = binary blob (packed as length + data)
 *
 * Example: PackArguments("zi", "hostname", 443)
 *   -> 4-byte len + "hostname\0" + 4-byte int 443
 * ======================================================================== */

typedef struct {
    char*  data;
    int    length;
    int    capacity;
} ArgBuffer;

void ArgBuffer_Init(ArgBuffer* ab) {
    ab->capacity = 1024;
    ab->data = (char*)malloc(ab->capacity);
    ab->length = 0;
}

void ArgBuffer_Grow(ArgBuffer* ab, int needed) {
    while (ab->length + needed > ab->capacity) {
        ab->capacity *= 2;
        ab->data = (char*)realloc(ab->data, ab->capacity);
    }
}

void ArgBuffer_AddInt(ArgBuffer* ab, int value) {
    ArgBuffer_Grow(ab, 4);
    BYTE* p = (BYTE*)(ab->data + ab->length);
    p[0] = (value >> 24) & 0xFF;
    p[1] = (value >> 16) & 0xFF;
    p[2] = (value >> 8)  & 0xFF;
    p[3] =  value        & 0xFF;
    ab->length += 4;
}

void ArgBuffer_AddShort(ArgBuffer* ab, short value) {
    ArgBuffer_Grow(ab, 2);
    BYTE* p = (BYTE*)(ab->data + ab->length);
    p[0] = (value >> 8) & 0xFF;
    p[1] =  value       & 0xFF;
    ab->length += 2;
}

void ArgBuffer_AddString(ArgBuffer* ab, const char* str) {
    int slen = (int)strlen(str) + 1; /* Include null terminator */
    ArgBuffer_AddInt(ab, slen);
    ArgBuffer_Grow(ab, slen);
    memcpy(ab->data + ab->length, str, slen);
    ab->length += slen;
}

void ArgBuffer_AddBinary(ArgBuffer* ab, const void* data, int len) {
    ArgBuffer_AddInt(ab, len);
    ArgBuffer_Grow(ab, len);
    memcpy(ab->data + ab->length, data, len);
    ab->length += len;
}

void ArgBuffer_Free(ArgBuffer* ab) {
    if (ab->data) {
        memset(ab->data, 0, ab->capacity);
        free(ab->data);
    }
    ab->data = NULL;
    ab->length = 0;
    ab->capacity = 0;
}

/* ========================================================================
 * Beacon API Symbol Resolution Table
 *
 * Maps symbol names from the BOF to our implementation functions. When
 * the loader encounters an external symbol matching one of these names,
 * it returns a pointer to our implementation rather than trying
 * LoadLibrary/GetProcAddress.
 * ======================================================================== */

typedef struct {
    const char* name;
    void*       address;
} BeaconApiEntry;

BeaconApiEntry g_beaconApi[] = {
    { "BeaconPrintf",          (void*)Impl_BeaconPrintf          },
    { "BeaconOutput",          (void*)Impl_BeaconOutput          },
    { "BeaconFormatAlloc",     (void*)Impl_BeaconFormatAlloc     },
    { "BeaconFormatReset",     (void*)Impl_BeaconFormatReset     },
    { "BeaconFormatFree",      (void*)Impl_BeaconFormatFree      },
    { "BeaconFormatAppend",    (void*)Impl_BeaconFormatAppend    },
    { "BeaconFormatPrintf",    (void*)Impl_BeaconFormatPrintf    },
    { "BeaconFormatToString",  (void*)Impl_BeaconFormatToString  },
    { "BeaconFormatLength",    (void*)Impl_BeaconFormatLength    },
    { "BeaconFormatOriginal",  (void*)Impl_BeaconFormatOriginal  },
    { "BeaconDataParse",       (void*)Impl_BeaconDataParse       },
    { "BeaconDataInt",         (void*)Impl_BeaconDataInt         },
    { "BeaconDataShort",       (void*)Impl_BeaconDataShort       },
    { "BeaconDataLength",      (void*)Impl_BeaconDataLength      },
    { "BeaconDataExtract",     (void*)Impl_BeaconDataExtract     },
    { NULL, NULL }
};

/* ========================================================================
 * Enhanced Symbol Resolution
 *
 * Checks Beacon API table first, then falls back to MODULE$Function
 * parsing and GetProcAddress resolution.
 * ======================================================================== */

void* ResolveSymbol(const char* name) {
    /* Strip common prefixes added by compilers */
    const char* cleanName = name;
    if (strncmp(name, "__imp_", 6) == 0)
        cleanName = name + 6;
    else if (name[0] == '_')
        cleanName = name + 1;

    /* Check Beacon API table */
    for (int i = 0; g_beaconApi[i].name != NULL; i++) {
        if (strcmp(cleanName, g_beaconApi[i].name) == 0)
            return g_beaconApi[i].address;
    }
    /* Also check with original name (in case prefix stripping was wrong) */
    for (int i = 0; g_beaconApi[i].name != NULL; i++) {
        if (strcmp(name, g_beaconApi[i].name) == 0)
            return g_beaconApi[i].address;
    }

    /* Try MODULE$Function convention */
    const char* dollar = strchr(cleanName, '$');
    if (dollar != NULL) {
        char moduleName[128];
        size_t modLen = (size_t)(dollar - cleanName);
        if (modLen < sizeof(moduleName) - 5) {
            memcpy(moduleName, cleanName, modLen);
            moduleName[modLen] = '\0';
            /* Append .dll extension if absent */
            if (!strchr(moduleName, '.'))
                strcat(moduleName, ".dll");

            HMODULE hMod = LoadLibraryA(moduleName);
            if (hMod) {
                void* addr = (void*)GetProcAddress(hMod, dollar + 1);
                if (addr) return addr;
            }
        }
    }

    /* Fallback: scan common system DLLs */
    const char* fallbackDlls[] = {
        "kernel32.dll", "ntdll.dll", "advapi32.dll",
        "user32.dll", "msvcrt.dll", "ws2_32.dll", NULL
    };
    for (int i = 0; fallbackDlls[i]; i++) {
        HMODULE hMod = GetModuleHandleA(fallbackDlls[i]);
        if (hMod) {
            void* addr = (void*)GetProcAddress(hMod, cleanName);
            if (addr) return addr;
        }
    }

    return NULL; /* Unresolved */
}

/* ========================================================================
 * Memory Tracking for Cleanup
 *
 * We track every VirtualAlloc call so we can zero and free everything
 * after the BOF executes, even if it crashed. This prevents memory
 * forensics from recovering BOF code or data from the process.
 * ======================================================================== */

#define MAX_TRACKED_ALLOCS 64

typedef struct {
    void*  address;
    DWORD  size;
} TrackedAlloc;

typedef struct {
    TrackedAlloc allocs[MAX_TRACKED_ALLOCS];
    int          count;
} AllocTracker;

void AllocTracker_Init(AllocTracker* tracker) {
    memset(tracker, 0, sizeof(AllocTracker));
}

void* AllocTracker_Alloc(AllocTracker* tracker, DWORD size, DWORD protect) {
    if (tracker->count >= MAX_TRACKED_ALLOCS) return NULL;

    void* mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, protect);
    if (mem) {
        tracker->allocs[tracker->count].address = mem;
        tracker->allocs[tracker->count].size    = size;
        tracker->count++;
    }
    return mem;
}

void AllocTracker_FreeAll(AllocTracker* tracker) {
    for (int i = 0; i < tracker->count; i++) {
        if (tracker->allocs[i].address) {
            /* Zero memory before freeing: defense against forensics */
            memset(tracker->allocs[i].address, 0, tracker->allocs[i].size);
            VirtualFree(tracker->allocs[i].address, 0, MEM_RELEASE);
            tracker->allocs[i].address = NULL;
        }
    }
    tracker->count = 0;
}

/* ========================================================================
 * Section and Symbol Helpers (same as basic loader)
 * ======================================================================== */

typedef struct {
    char*         data;
    COFF_SECTION* header;
    DWORD         allocSize;
} LoadedSection;

const char* GetSymbolName(COFF_SYMBOL* sym, char* stringTable) {
    static char buf[256];
    if (sym->Name.LongName.Zeroes != 0) {
        memcpy(buf, sym->Name.ShortName, 8);
        buf[8] = '\0';
        return buf;
    }
    return stringTable + sym->Name.LongName.Offset;
}

/* ========================================================================
 * Core Loader with SEH and Output Capture
 * ======================================================================== */

typedef struct {
    char*   outputData;    /* Captured BOF output (caller must free)          */
    int     outputLength;  /* Length of captured output                       */
    int     exitCode;      /* 0 = success, -1 = load error, -2 = SEH crash   */
    DWORD   exceptionCode; /* Windows exception code if BOF crashed           */
} LoadResult;

LoadResult LoadAndExecuteBOF(
    BYTE*       coffData,
    DWORD       coffSize,
    char*       args,
    int         argsLen
) {
    LoadResult result = { NULL, 0, -1, 0 };
    AllocTracker tracker;
    AllocTracker_Init(&tracker);
    void** symbolAddresses = NULL;

    /* Initialize the global output capture buffer */
    OutputBuffer_Init(&g_output, 4096);

    /* ---- Parse COFF header ---- */
    if (coffSize < sizeof(COFF_FILE_HEADER)) goto cleanup;
    COFF_FILE_HEADER* fh = (COFF_FILE_HEADER*)coffData;
    if (fh->Machine != 0x8664 || fh->SizeOfOptionalHeader != 0) goto cleanup;

    int numSections = fh->NumberOfSections;
    LoadedSection* sections = (LoadedSection*)calloc(numSections, sizeof(LoadedSection));
    if (!sections) goto cleanup;

    COFF_SECTION* secHeaders = (COFF_SECTION*)(coffData + sizeof(COFF_FILE_HEADER));

    /* ---- Allocate and populate sections ---- */
    for (int i = 0; i < numSections; i++) {
        COFF_SECTION* sh = &secHeaders[i];
        sections[i].header = sh;
        DWORD allocSize = sh->SizeOfRawData > sh->VirtualSize
                        ? sh->SizeOfRawData : sh->VirtualSize;
        if (allocSize == 0) allocSize = 1024;
        sections[i].allocSize = allocSize;

        /* Allocate as RWX; we tighten permissions after relocation */
        sections[i].data = (char*)AllocTracker_Alloc(
            &tracker, allocSize, PAGE_EXECUTE_READWRITE);
        if (!sections[i].data) goto cleanup;

        memset(sections[i].data, 0, allocSize);
        if (sh->SizeOfRawData > 0 && sh->PointerToRawData > 0) {
            memcpy(sections[i].data,
                   coffData + sh->PointerToRawData,
                   sh->SizeOfRawData);
        }
    }

    /* ---- Resolve symbols ---- */
    COFF_SYMBOL* symTable = (COFF_SYMBOL*)(coffData + fh->PointerToSymbolTable);
    char* strTable = (char*)(coffData + fh->PointerToSymbolTable
                             + (fh->NumberOfSymbols * sizeof(COFF_SYMBOL)));

    symbolAddresses = (void**)calloc(fh->NumberOfSymbols, sizeof(void*));
    if (!symbolAddresses) goto cleanup;

    void* entryPoint = NULL;

    for (UINT32 i = 0; i < fh->NumberOfSymbols; i++) {
        COFF_SYMBOL* sym = &symTable[i];
        const char* name = GetSymbolName(sym, strTable);

        if (sym->SectionNumber > 0 && sym->SectionNumber <= numSections) {
            symbolAddresses[i] = sections[sym->SectionNumber - 1].data + sym->Value;
            if (strcmp(name, "go") == 0 || strcmp(name, "_go") == 0)
                entryPoint = symbolAddresses[i];
        }
        else if (sym->SectionNumber == 0 && sym->StorageClass == 0x02) {
            symbolAddresses[i] = ResolveSymbol(name);
        }
        i += sym->NumberOfAuxSymbols;
    }

    if (!entryPoint) goto cleanup;

    /* ---- Process relocations ---- */
    for (int i = 0; i < numSections; i++) {
        COFF_SECTION* sh = sections[i].header;
        if (sh->NumberOfRelocations == 0) continue;

        COFF_RELOCATION* relocs = (COFF_RELOCATION*)(
            coffData + sh->PointerToRelocations);

        for (int r = 0; r < sh->NumberOfRelocations; r++) {
            COFF_RELOCATION* rel = &relocs[r];
            char* patch = sections[i].data + rel->VirtualAddress;
            void* symAddr = symbolAddresses[rel->SymbolTableIndex];
            if (!symAddr) continue;

            switch (rel->Type) {
                case IMAGE_REL_AMD64_REL32:
                    *(INT32*)patch = (INT32)((INT64)symAddr - ((INT64)patch + 4));
                    break;
                case IMAGE_REL_AMD64_REL32_1:
                    *(INT32*)patch = (INT32)((INT64)symAddr - ((INT64)patch + 5));
                    break;
                case IMAGE_REL_AMD64_REL32_2:
                    *(INT32*)patch = (INT32)((INT64)symAddr - ((INT64)patch + 6));
                    break;
                case IMAGE_REL_AMD64_REL32_3:
                    *(INT32*)patch = (INT32)((INT64)symAddr - ((INT64)patch + 7));
                    break;
                case IMAGE_REL_AMD64_REL32_4:
                    *(INT32*)patch = (INT32)((INT64)symAddr - ((INT64)patch + 8));
                    break;
                case IMAGE_REL_AMD64_REL32_5:
                    *(INT32*)patch = (INT32)((INT64)symAddr - ((INT64)patch + 9));
                    break;
                case IMAGE_REL_AMD64_ADDR64:
                    *(UINT64*)patch = (UINT64)symAddr;
                    break;
                case IMAGE_REL_AMD64_ADDR32NB:
                    *(UINT32*)patch = (UINT32)((INT64)symAddr - (INT64)sections[0].data);
                    break;
                case IMAGE_REL_AMD64_SECREL: {
                    COFF_SYMBOL* tSym = &symTable[rel->SymbolTableIndex];
                    *(UINT32*)patch = tSym->Value;
                    break;
                }
                case IMAGE_REL_AMD64_ABSOLUTE:
                    break; /* No-op */
            }
        }
    }

    /* ---- Tighten section permissions (defense in depth) ---- */
    for (int i = 0; i < numSections; i++) {
        DWORD oldProt;
        DWORD newProt = PAGE_READONLY; /* Default to read-only */
        UINT32 ch = sections[i].header->Characteristics;
        if (ch & 0x20000000) /* EXECUTE */
            newProt = (ch & 0x80000000) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if (ch & 0x80000000) /* WRITE */
            newProt = PAGE_READWRITE;
        VirtualProtect(sections[i].data, sections[i].allocSize, newProt, &oldProt);
    }

    /* ---- Execute with SEH wrapping ---- */
    typedef void (*BofEntry)(char*, int);
    BofEntry entry = (BofEntry)entryPoint;

    __try {
        entry(args, argsLen);
        result.exitCode = 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result.exitCode = -2;
        result.exceptionCode = GetExceptionCode();
        Impl_BeaconPrintf(CALLBACK_ERROR,
            "BOF crashed with exception 0x%08X", result.exceptionCode);
    }

    /* ---- Capture output ---- */
    if (g_output.length > 0) {
        result.outputData = (char*)malloc(g_output.length + 1);
        memcpy(result.outputData, g_output.data, g_output.length);
        result.outputData[g_output.length] = '\0';
        result.outputLength = g_output.length;
    }

cleanup:
    AllocTracker_FreeAll(&tracker);
    OutputBuffer_Free(&g_output);
    if (symbolAddresses) free(symbolAddresses);
    if (sections) free(sections);
    return result;
}

/* ========================================================================
 * Main: Demonstrate loading a BOF with arguments
 * ======================================================================== */

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <bof.o> [string_arg] [int_arg]\n", argv[0]);
        printf("\nExample:\n");
        printf("  %s regquery.o \"SOFTWARE\\\\Microsoft\\\\Windows\" \"ProgramFilesDir\"\n",
               argv[0]);
        return 1;
    }

    /* Read BOF file */
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Cannot open: %s\n", argv[1]);
        return 1;
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* fileData = (BYTE*)malloc(fileSize);
    DWORD bytesRead = 0;
    ReadFile(hFile, fileData, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    printf("[*] Loaded BOF: %s (%d bytes)\n", argv[1], fileSize);

    /* Pack arguments if provided */
    ArgBuffer argBuf;
    ArgBuffer_Init(&argBuf);

    for (int i = 2; i < argc; i++) {
        /* Heuristic: if it parses as a number, pack as int; otherwise string */
        char* endp;
        long val = strtol(argv[i], &endp, 0);
        if (*endp == '\0' && endp != argv[i]) {
            ArgBuffer_AddInt(&argBuf, (int)val);
            printf("[*] Arg %d: int(%d)\n", i - 1, (int)val);
        } else {
            ArgBuffer_AddString(&argBuf, argv[i]);
            printf("[*] Arg %d: str(\"%s\")\n", i - 1, argv[i]);
        }
    }

    /* Execute */
    printf("[*] Executing BOF...\n\n");
    LoadResult res = LoadAndExecuteBOF(
        fileData, fileSize,
        argBuf.data, argBuf.length
    );

    /* Display results */
    if (res.exitCode == 0) {
        printf("\n[+] BOF executed successfully.\n");
    } else if (res.exitCode == -2) {
        printf("\n[-] BOF crashed with exception 0x%08X\n", res.exceptionCode);
    } else {
        printf("\n[-] BOF failed to load.\n");
    }

    if (res.outputData) {
        printf("\n--- BOF Output ---\n%s\n--- End Output ---\n", res.outputData);
        free(res.outputData);
    }

    /* Cleanup */
    ArgBuffer_Free(&argBuf);
    memset(fileData, 0, fileSize); /* Zero the raw BOF data */
    free(fileData);

    return (res.exitCode == 0) ? 0 : 1;
}
```

## Compilation

```bash
# MSVC (requires /EHa for SEH __try/__except support):
cl.exe /nologo /W4 /EHa advanced_coff_loader.c /link /out:adv_loader.exe

# MinGW (SEH works differently; use -fseh-exceptions on x64):
x86_64-w64-mingw32-gcc -o adv_loader.exe advanced_coff_loader.c \
    -lkernel32 -ladvapi32 -fseh-exceptions

# Test with arguments:
adv_loader.exe bof_regquery.o "SOFTWARE\Microsoft\Windows\CurrentVersion" "ProgramFilesDir"
adv_loader.exe bof_processlist.o
adv_loader.exe bof_whoami.o
```

## Key Improvements Over the Basic Loader

| Feature | Basic Loader | Advanced Loader |
|---|---|---|
| Beacon API | Printf/Output stubs only | Full format + data parser APIs |
| Arguments | None | Binary packing with int/short/string/blob |
| Crash safety | BOF crash kills process | SEH wrapping catches exceptions |
| Output | Printed to stdout | Captured into buffer for C2 forwarding |
| Memory | VirtualFree only | Tracked allocations, zeroed before free |
| Permissions | RWX everywhere | Tightened per-section after relocation |
| Symbol resolution | Basic MODULE$Func | Beacon API table + MODULE$Func + fallback DLL scan |

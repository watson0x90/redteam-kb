# API Hashing & Dynamic Resolution

> **Context**: API hashing is a foundational tradecraft technique used to avoid
> embedding plaintext Windows API names in binaries. It is relevant to both
> malware analysis (reverse engineering hashed imports) and detection engineering.

## Why Avoid Plaintext API Names?

Static analysis tools scan binaries for strings like `VirtualAllocEx`,
`CreateRemoteThread`, or `NtProtectVirtualMemory`. The presence of these strings
in an import table or as embedded strings is a strong indicator of suspicious
functionality.

API hashing replaces these readable strings with precomputed numeric constants.
At runtime, the code walks loaded modules and their exports, hashing each name
until a match is found.

```
Traditional:
  GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAllocEx");
  // String "VirtualAllocEx" is visible in the binary

Hashed:
  resolve_by_hash(0x91AFCA54);  // No readable API name in binary
  // 0x91AFCA54 is the hash of "VirtualAllocEx"
```

## Common Hash Algorithms

### djb2 (Daniel J. Bernstein)

The most widely used hash in this context due to its simplicity:

```c
// djb2 hash -- compact and fast, widely seen in offensive tooling.
// Produces a 32-bit hash from a null-terminated string.
//
// The magic constant 5381 and the multiplier 33 were chosen empirically
// by Bernstein for good distribution properties.

// unsigned long djb2(const char* str) {
//     unsigned long hash = 5381;
//     int c;
//     while ((c = *str++))
//         hash = ((hash << 5) + hash) + c;   // hash * 33 + c
//     return hash;
// }
```

### CRC32

Some tools use CRC32, which is a well-known checksum algorithm. It has better
collision resistance than djb2 but is slightly more code:

```c
// CRC32 hash for API resolution.
// Uses a precomputed lookup table (256 entries).
//
// unsigned int crc32_hash(const char* str) {
//     unsigned int crc = 0xFFFFFFFF;
//     while (*str) {
//         crc = (crc >> 8) ^ crc32_table[(crc ^ *str++) & 0xFF];
//     }
//     return crc ^ 0xFFFFFFFF;
// }
//
// The crc32_table is a standard 256-entry table derived from
// the CRC32 polynomial 0xEDB88320.
```

### ROR13 (Rotate Right 13)

Another classic from early shellcode:

```c
// ROR13 hash -- used in Metasploit's block_api and similar.
// Rotates the hash right by 13 bits before adding each character.
//
// unsigned int ror13(const char* str) {
//     unsigned int hash = 0;
//     while (*str) {
//         hash = ((hash >> 13) | (hash << 19));  // rotate right 13
//         hash += *str++;
//     }
//     return hash;
// }
```

## PEB Walking for Module Enumeration

To hash-resolve an API, the code must first enumerate all loaded modules. This is
done by walking the PEB's loader data structures, avoiding calls to `GetModuleHandle`
(which could be hooked or leave traces).

```c
// PEB walking on x64 Windows -- conceptual walkthrough.
//
// The PEB (Process Environment Block) is accessed via the TEB
// (Thread Environment Block), which is at GS:[0x00] on x64.
//
// TEB->ProcessEnvironmentBlock (offset 0x60) -> PEB
// PEB->Ldr (offset 0x18) -> PEB_LDR_DATA
// PEB_LDR_DATA->InMemoryOrderModuleList -> doubly-linked list of modules

// Conceptual module enumeration:
//
// void WalkModules() {
//     // Read PEB from TEB
//     PPEB peb = (PPEB)__readgsqword(0x60);   // x64: GS:[0x60]
//
//     // Access the loader data
//     PPEB_LDR_DATA ldr = peb->Ldr;
//
//     // Get the first entry in InMemoryOrderModuleList
//     PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
//     PLIST_ENTRY current = head->Flink;
//
//     while (current != head) {
//         // Each entry is embedded in a LDR_DATA_TABLE_ENTRY structure.
//         // The offset to the containing structure depends on which list
//         // we are walking (InMemoryOrder offset differs from InLoadOrder).
//
//         PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
//             current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks
//         );
//
//         // entry->DllBase      = base address of the module
//         // entry->BaseDllName  = UNICODE_STRING with the DLL name
//         // entry->FullDllName  = UNICODE_STRING with full path
//
//         // Hash the module name and compare to target module hash
//         // If match, proceed to EAT walking for this module
//
//         current = current->Flink;
//     }
// }
```

## Export Address Table (EAT) Walking

Once a module is found, parse its PE headers to walk the exports:

```c
// EAT walking -- resolving an export by hash.
//
// Given a module base address and a target hash, enumerate all exports
// and hash each name until a match is found.

// PVOID ResolveByHash(PVOID moduleBase, unsigned long targetHash) {
//     PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
//     PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + dos->e_lfanew);
//
//     // Export directory is in the DataDirectory array at index 0
//     DWORD exportRVA = nt->OptionalHeader
//         .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
//
//     if (exportRVA == 0) return NULL;  // No exports
//
//     PIMAGE_EXPORT_DIRECTORY exports =
//         (PIMAGE_EXPORT_DIRECTORY)((PBYTE)moduleBase + exportRVA);
//
//     PDWORD addrFunctions = (PDWORD)((PBYTE)moduleBase + exports->AddressOfFunctions);
//     PDWORD addrNames     = (PDWORD)((PBYTE)moduleBase + exports->AddressOfNames);
//     PWORD  addrOrdinals  = (PWORD)((PBYTE)moduleBase + exports->AddressOfNameOrdinals);
//
//     for (DWORD i = 0; i < exports->NumberOfNames; i++) {
//         char* funcName = (char*)((PBYTE)moduleBase + addrNames[i]);
//
//         if (djb2(funcName) == targetHash) {
//             WORD ordinal = addrOrdinals[i];
//             DWORD funcRVA = addrFunctions[ordinal];
//             return (PVOID)((PBYTE)moduleBase + funcRVA);
//         }
//     }
//     return NULL;  // Not found
// }
```

## Python Hash Generator Utility

For precomputing hash constants during development (used by security researchers
to build lookup tables and by analysts to identify known hashes):

```python
# hash_generator.py
# Utility for precomputing API name hashes.
# Useful for BOTH red team (generating constants) and blue team
# (building lookup tables for malware analysis).

def djb2(name: str) -> int:
    """Compute djb2 hash of an API name (32-bit)."""
    hash_val = 5381
    for c in name:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def ror13(name: str) -> int:
    """Compute ROR13 hash of an API name (32-bit)."""
    hash_val = 0
    for c in name:
        hash_val = (((hash_val >> 13) | (hash_val << 19)) + ord(c)) & 0xFFFFFFFF
    return hash_val

# Common APIs of interest for analysis
apis = [
    "VirtualAllocEx",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateThreadEx",
    "NtWriteVirtualMemory",
    "LoadLibraryA",
    "GetProcAddress",
]

if __name__ == "__main__":
    print(f"{'API Name':<35} {'djb2':>12} {'ROR13':>12}")
    print("-" * 62)
    for api in apis:
        print(f"{api:<35} 0x{djb2(api):08X}   0x{ror13(api):08X}")
```

This utility produces a reference table that analysts can use to identify hashes
found during reverse engineering.

---

## Detection & Defense

API hashing has been used for decades, and defenders have developed robust detection
approaches.

### 1. Hash Constant Databases

Security researchers maintain databases mapping known hash values back to API names
for common algorithms (djb2, CRC32, ROR13, and many custom variants).

Tools like **HashDB** (OALabs) and **shellcode_hashes** (Mandiant/FLARE) provide
IDA/Ghidra plugins that automatically annotate hash constants in disassembly:

```
Before annotation:
  mov ecx, 0x91AFCA54    ; unknown constant
  call resolve_function

After annotation:
  mov ecx, 0x91AFCA54    ; djb2("VirtualAllocEx")
  call resolve_function
```

### 2. Absence of Imports as an Indicator

A PE file that performs complex operations (memory allocation, thread creation) but
has a minimal or empty import table is suspicious. Legitimate applications import
functions normally; the absence of expected imports suggests dynamic resolution.

Static analysis rules can flag binaries where:
- The import table is abnormally small
- Common utility DLLs (kernel32, ntdll) are not in the import table
- The binary's functionality (from behavioral analysis) does not match its imports

### 3. PEB Access Pattern Detection

Accessing the PEB via `__readgsqword(0x60)` and then traversing the loader
structures is a distinctive pattern. While legitimate code occasionally accesses
the PEB, the pattern of PEB -> Ldr -> module list -> PE headers -> EAT -> hash
comparison is characteristic of manual resolution.

ETW providers and instrumentation can detect this access pattern.

### 4. Behavioral Detection

Regardless of how APIs are resolved, the **behavior** is the same. Security
products that monitor behavior -- sequences of memory allocation, protection
changes, and thread creation -- detect the outcome rather than the mechanism.

This makes behavioral detection algorithm-agnostic: it does not matter whether
the attacker used djb2, CRC32, or a custom hash.

### 5. Memory Scanning for Hash Functions

The hash function itself (especially djb2 with its distinctive constant 5381 or
0x1505 and shift-by-5 pattern) can be detected in binary code:

```
rule API_Hashing_djb2 {
    meta:
        description = "Detects djb2 hash function constants in binary"
    strings:
        $magic = { 05 15 00 00 }            // 5381 in little-endian
        $shift = { C1 E? 05 }              // shl reg, 5
    condition:
        $magic and $shift
}
```

### 6. Dynamic Analysis / Sandboxing

When executed in a sandbox, all API resolution (hashed or not) results in actual
function calls that can be traced. API monitoring at the sandbox level captures
the resolved functions regardless of the resolution method.

### Summary

API hashing removes static indicators (plaintext strings) but introduces its own
detectable patterns: hash constants, minimal import tables, PEB walking behavior,
and hash function code signatures. The most robust defense is behavioral detection
that focuses on what the code does rather than how it resolves its dependencies.
Blue team analysts should maintain hash lookup databases and use tools like HashDB
to accelerate reverse engineering of samples using these techniques.

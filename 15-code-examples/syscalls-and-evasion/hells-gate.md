# Hell's Gate

> **Original Research**: am0nsec (Paul Lainet) & smelly__vx (2020).
> Paper: "Hell's Gate" -- first published technique for runtime SSN resolution
> by parsing ntdll's export table in memory.

## The Problem Hell's Gate Solves

Direct syscalls require knowing the **System Service Number (SSN)** for each native
function. Hardcoding SSNs is fragile because they change across Windows versions.

Hell's Gate resolves SSNs **at runtime** by:
1. Locating ntdll.dll in memory via the PEB (Process Environment Block).
2. Parsing ntdll's Export Address Table (EAT) to find function addresses.
3. Reading the bytes at each function address to extract the SSN from the stub.

## Conceptual Architecture

```
 PEB -> PEB_LDR_DATA -> InMemoryOrderModuleList
    |
    v
 Find ntdll.dll base address
    |
    v
 Parse PE headers -> Export Directory -> AddressOfFunctions
    |
    v
 Locate target function (by hash, not by name string)
    |
    v
 Read bytes at function address: 4C 8B D1 B8 [SSN] 00 00
    |
    v
 Extract SSN -> use in syscall stub
```

## Core Data Structure: VX_TABLE_ENTRY

The original Hell's Gate implementation uses a structure to track each resolved
syscall:

```c
// Structure representing a single resolved syscall entry.
// Each entry maps a hashed function name to its resolved SSN
// and the function's address in ntdll.
typedef struct _VX_TABLE_ENTRY {
    PVOID   pAddress;        // Address of the function in ntdll.dll
    DWORD64 dwHash;          // djb2 hash of the function name
    WORD    wSystemCall;     // Extracted System Service Number (SSN)
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

// Table holding all syscalls needed by the tool
typedef struct _VX_TABLE {
    VX_TABLE_ENTRY NtAllocateVirtualMemory;
    VX_TABLE_ENTRY NtProtectVirtualMemory;
    VX_TABLE_ENTRY NtCreateThreadEx;
    VX_TABLE_ENTRY NtWaitForSingleObject;
    // Additional entries as needed...
} VX_TABLE, *PVX_TABLE;
```

## Step 1: PEB Walking to Find ntdll

The PEB is accessible without any API calls -- it is always at a fixed offset from
the Thread Environment Block (TEB). This avoids calling `GetModuleHandle` which
itself could be hooked.

```c
// PEB walking: locating ntdll.dll base address without API calls.
//
// On x64 Windows, the TEB is accessible via the GS segment register.
// GS:[0x60] points to the PEB.
// PEB->Ldr->InMemoryOrderModuleList contains loaded modules.
//
// The load order is deterministic:
//   [0] = the executable itself
//   [1] = ntdll.dll           <-- always second
//   [2] = kernel32.dll

typedef struct _PEB_LDR_DATA_PARTIAL {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;   // We walk this list
} PEB_LDR_DATA_PARTIAL;

typedef struct _LDR_DATA_TABLE_ENTRY_PARTIAL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;                        // Base address of the module
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_PARTIAL;

// Conceptual function to retrieve ntdll base:
// 1. Read PEB from TEB (GS:[0x60] on x64)
// 2. Access PEB->Ldr->InMemoryOrderModuleList
// 3. Walk to the second entry (ntdll.dll)
// 4. Return DllBase
```

## Step 2: EAT Parsing

Once the ntdll base address is known, parse its PE headers to reach the Export
Address Table:

```c
// Export Address Table parsing -- conceptual walkthrough.
//
// PE structure navigation:
//   Base + 0x3C                    -> e_lfanew (offset to PE header)
//   PE header + 0x88               -> Export Directory RVA (x64)
//   Export Directory contains:
//     - NumberOfFunctions          : total exported functions
//     - NumberOfNames              : number of named exports
//     - AddressOfFunctions         : RVA array of function addresses
//     - AddressOfNames             : RVA array of function name strings
//     - AddressOfNameOrdinals      : RVA array mapping name index -> function index

// Pseudocode for resolving a function by hash:
//
// for i in 0..NumberOfNames:
//     name = base + AddressOfNames[i]
//     if djb2_hash(name) == target_hash:
//         ordinal = AddressOfNameOrdinals[i]
//         function_addr = base + AddressOfFunctions[ordinal]
//         return function_addr
```

## Step 3: Byte Pattern Matching for SSN Extraction

This is the core of Hell's Gate. Once a function address is found, the code reads
the stub bytes to extract the SSN:

```c
// Byte pattern expected at the start of an unhooked ntdll syscall stub:
//
// Offset  Bytes          Meaning
// 0x00    4C 8B D1       mov r10, rcx
// 0x03    B8 XX XX 00 00 mov eax, <SSN>     <-- SSN is at offset +4 and +5
// 0x08    ...            (rest of stub)
//
// If bytes at +0 match 4C 8B D1 and byte at +3 is B8, the function is
// NOT hooked and we can extract the SSN from bytes +4 and +5.

// Conceptual SSN extraction logic:
//
// BOOL ExtractSSN(PVOID pFunctionAddress, PWORD pSSN) {
//     PBYTE stub = (PBYTE)pFunctionAddress;
//
//     // Check for unhooked stub pattern
//     if (stub[0] == 0x4C &&     // 4C 8B D1 = mov r10, rcx
//         stub[1] == 0x8B &&
//         stub[2] == 0xD1 &&
//         stub[3] == 0xB8) {     // B8 = mov eax, imm32
//
//         // Extract SSN (little-endian WORD at offset +4)
//         *pSSN = (WORD)((stub[5] << 8) | stub[4]);
//         return TRUE;           // Successfully extracted
//     }
//
//     // If the bytes don't match, the function is likely HOOKED.
//     // The first bytes have been overwritten with a JMP to the EDR's
//     // inspection routine. Hell's Gate CANNOT resolve this function.
//     return FALSE;
// }
```

## djb2 API Hashing

Hell's Gate identifies functions by hash rather than plaintext name strings. This
avoids string-based signatures. The djb2 algorithm is commonly used:

```c
// djb2 hash function -- originally by Daniel J. Bernstein.
// Produces a 64-bit hash of a null-terminated ASCII string.
// Used to identify API functions without embedding their names.
//
// DWORD64 djb2(PBYTE str) {
//     DWORD64 hash = 5381;           // magic starting value
//     INT c;
//     while ((c = *str++))
//         hash = ((hash << 5) + hash) + c;  // hash * 33 + c
//     return hash;
// }
//
// Example:
//   djb2("NtAllocateVirtualMemory") -> 0x... (precomputed constant)
//
// The precomputed hash is stored in the binary; the name string is not.
```

## Limitation: Hooked Functions

**Hell's Gate fails when the target function is hooked.** EDR hooks overwrite the
first bytes of the stub (typically with `E9 XX XX XX XX` -- a relative JMP), so
the expected `4C 8B D1 B8` pattern is no longer present. This limitation motivated
the development of Halo's Gate.

---

## Detection & Defense

### 1. Hook Integrity as Defense

Ironically, EDR hooks serve as both a detection mechanism AND a defense against
Hell's Gate. If a function is hooked, Hell's Gate cannot extract its SSN. Broad
hook coverage on sensitive functions is therefore a mitigation.

### 2. Memory Scanning for Gate Structures

The `VX_TABLE_ENTRY` and `VX_TABLE` structures in process memory are indicators.
Memory scanning for:
- Arrays of (address, hash, SSN) tuples
- Known djb2 hash constants for sensitive functions

### 3. PEB Access Pattern Detection

Walking the PEB to find module bases is legitimate behavior, but the specific pattern
of PEB -> Ldr -> module list -> PE header parsing -> EAT walking is characteristic
of manual resolution techniques. This access pattern, combined with subsequent
suspicious syscalls, is a behavioral indicator.

### 4. ETW and Kernel Telemetry

As with direct syscalls, Hell's Gate still results in syscall instructions executing
from non-ntdll memory (unless combined with indirect syscalls). Stack trace analysis
at the kernel level remains effective.

### 5. Static Analysis

The byte-pattern matching constants (`0x4C`, `0x8B`, `0xD1`, `0xB8`) appearing
together in a binary -- especially outside of ntdll -- are a signature:

```
rule Hells_Gate_Pattern_Match {
    meta:
        description = "Detects Hell's Gate SSN extraction byte checks"
    strings:
        $check1 = { 80 3? 4C }   // cmp byte ptr [reg], 0x4C
        $check2 = { 80 3? 8B }   // cmp byte ptr [reg], 0x8B
        $check3 = { 80 3? D1 }   // cmp byte ptr [reg], 0xD1
        $check4 = { 80 3? B8 }   // cmp byte ptr [reg], 0xB8
    condition:
        all of them
}
```

### Summary

Hell's Gate was a significant advancement in runtime SSN resolution, but its reliance
on reading unmodified stub bytes means it is defeated by the very hooks it tries to
bypass. This led directly to the Halo's Gate technique.

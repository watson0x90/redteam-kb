# Halo's Gate & Tartarus Gate

> **Halo's Gate**: Researched by Sektor7 (reenz0h), building on Hell's Gate.
> **Tartarus Gate**: Extended by trickster0 to handle additional hook patterns.

## The Problem: Hell's Gate Fails on Hooked Functions

Hell's Gate reads the first bytes of an ntdll syscall stub and expects a clean,
unhooked pattern (`4C 8B D1 B8 XX XX 00 00`). When an EDR hooks a function, those
bytes are replaced with a JMP instruction, and Hell's Gate cannot extract the SSN.

Halo's Gate solves this by exploiting a fundamental property of the System Service
Dispatch Table (SSDT):

**SSNs are assigned sequentially based on the alphabetical address order of functions
in ntdll's export table.**

## Core Insight: Neighbor Stub Scanning

If `NtAllocateVirtualMemory` (SSN = 0x18) is hooked, its neighbor functions are
likely NOT all hooked. Each syscall stub in ntdll is exactly **32 bytes** apart
(the stub size is consistent).

So the strategy is:
1. Find the target function's address.
2. If it is hooked, look at the **neighboring** stubs (address +/- 32 bytes).
3. Find an unhooked neighbor and read its SSN.
4. Calculate the target's SSN: `target_SSN = neighbor_SSN +/- offset`.

```
Memory layout of ntdll syscall stubs (conceptual):

Address         Function                    SSN    Hooked?
0x7FFE1000      NtAccessCheck               0x00   No
0x7FFE1020      NtAccessCheckAndAudit...    0x01   No
...             ...                         ...    ...
0x7FFE1300      NtAllocateVirtualMemory     0x18   YES (EDR hook)
0x7FFE1320      NtAllocateVirtualMemoryEx   0x19   No     <- neighbor +1
...             ...                         ...    ...
0x7FFE12E0      NtAllocateLocallyUniqueId   0x17   No     <- neighbor -1
```

If the target (SSN 0x18) is hooked but neighbor +1 (SSN 0x19) is clean:
`target_SSN = 0x19 - 1 = 0x18`

## Resolution Logic

The scanning algorithm checks increasing distances from the target:

```c
// Halo's Gate resolution logic -- conceptual pseudocode.
//
// Given a function address that is HOOKED (Hell's Gate failed),
// scan neighboring stubs to find an unhooked one and calculate
// the target SSN by offset.

// BOOL HalosGateResolve(PVOID pFunction, PWORD pSSN) {
//     PBYTE stub = (PBYTE)pFunction;
//
//     // First: try Hell's Gate (unhooked check)
//     if (stub[0] == 0x4C && stub[1] == 0x8B &&
//         stub[2] == 0xD1 && stub[3] == 0xB8) {
//         *pSSN = *(WORD*)(stub + 4);
//         return TRUE;
//     }
//
//     // Hell's Gate failed -- function is hooked.
//     // Scan neighbors in both directions.
//
//     // STUB_SIZE = 32 bytes (0x20) -- distance between consecutive stubs
//     #define STUB_SIZE 0x20
//     #define MAX_SEARCH 500   // limit search range
//
//     for (WORD i = 1; i < MAX_SEARCH; i++) {
//
//         // --- Check DOWNWARD neighbor (address + i * STUB_SIZE) ---
//         PBYTE down = stub + (i * STUB_SIZE);
//         if (down[0] == 0x4C && down[1] == 0x8B &&
//             down[2] == 0xD1 && down[3] == 0xB8) {
//             // Unhooked neighbor found at offset +i
//             // Its SSN is at bytes +4 and +5
//             WORD neighborSSN = *(WORD*)(down + 4);
//             // Target SSN = neighbor SSN - i (because SSNs are sequential)
//             *pSSN = neighborSSN - i;
//             return TRUE;
//         }
//
//         // --- Check UPWARD neighbor (address - i * STUB_SIZE) ---
//         PBYTE up = stub - (i * STUB_SIZE);
//         if (up[0] == 0x4C && up[1] == 0x8B &&
//             up[2] == 0xD1 && up[3] == 0xB8) {
//             // Unhooked neighbor found at offset -i
//             WORD neighborSSN = *(WORD*)(up + 4);
//             // Target SSN = neighbor SSN + i
//             *pSSN = neighborSSN + i;
//             return TRUE;
//         }
//     }
//
//     // All neighbors within range are hooked -- resolution failed
//     return FALSE;
// }
```

## Why 32 Bytes?

Each ntdll syscall stub occupies exactly 32 bytes on modern x64 Windows:

```
Bytes 0x00-0x02:  mov r10, rcx       (3 bytes)
Bytes 0x03-0x07:  mov eax, SSN       (5 bytes)
Bytes 0x08-0x0F:  test + jne          (8 bytes)
Bytes 0x10-0x11:  (padding/alignment)
Bytes 0x12-0x13:  syscall             (2 bytes)
Bytes 0x14:       ret                 (1 byte)
Bytes 0x15-0x16:  int 2Eh             (2 bytes)
Bytes 0x17:       ret                 (1 byte)
Bytes 0x18-0x1F:  padding to 32-byte boundary
```

This consistent sizing is what makes stride-based neighbor scanning reliable.

## Tartarus Gate: Handling Partial Hooks

Some EDRs use a **partial hook** strategy where they do not overwrite the `mov r10, rcx`
instruction but redirect execution after the SSN is loaded. In this case:

- Bytes `4C 8B D1` are still present (first 3 bytes intact).
- Byte at offset +3 might be `B8` (mov eax) -- SSN appears readable.
- But bytes at offset +8 or later contain a JMP (execution is redirected).

**Tartarus Gate** adds additional byte checks beyond just the first 4 bytes:

```c
// Tartarus Gate -- extended stub validation.
//
// Check not just the first 4 bytes, but also validate that the
// bytes following the SSN are consistent with an unhooked stub.
//
// BOOL TartarusGateCheck(PBYTE stub) {
//     // Standard Hell's Gate checks
//     if (stub[0] != 0x4C || stub[1] != 0x8B || stub[2] != 0xD1)
//         return FALSE;
//
//     if (stub[3] != 0xB8)
//         return FALSE;
//
//     // Additional Tartarus Gate checks:
//     // Verify the test instruction after the mov eax
//     // Byte at +8 should be part of "test byte ptr [...]" (0xF6)
//     if (stub[8] != 0xF6)
//         return FALSE;
//
//     // Verify syscall instruction at expected offset
//     if (stub[0x12] != 0x0F || stub[0x13] != 0x05)
//         return FALSE;
//
//     return TRUE;   // Stub appears fully intact
// }
```

This catches partial hooks where the SSN bytes look correct but execution would
be diverted.

## SSN Ordering: Why Sequential Math Works

The SSDT in the kernel is a table indexed by SSN. Functions are assigned SSNs in
the order they appear in ntdll's sorted export list. When Microsoft adds new
syscalls in a Windows update, existing SSNs may shift -- but within any single
version, they are always sequential with no gaps.

This means if you can confirm any one function's SSN, you can calculate any
other function's SSN by knowing the relative distance in the export table.

---

## Detection & Defense

### 1. Behavioral Analysis

Halo's Gate produces the same end result as direct syscalls -- a syscall instruction
executing from non-ntdll memory. All detection methods for direct syscalls apply:
- Stack trace analysis (return address outside ntdll)
- ETW Threat Intelligence provider events
- Kernel callbacks

### 2. Hook Integrity Monitoring

EDR drivers can periodically verify that their hooks are intact. If hooks are
still in place, Halo's Gate does not remove them -- it works around them. The
hooks still serve as detection points for non-Gate callers.

Advanced EDRs monitor for **hook coverage gaps**. If only a subset of sensitive
functions is hooked, Halo's Gate has more unhooked neighbors to work with.
Broader hook coverage reduces the effectiveness of neighbor scanning.

### 3. Dense Hooking Strategy

One defensive countermeasure is to hook ALL or nearly all ntdll syscall stubs, not
just the sensitive ones. If every neighbor is hooked, Halo's Gate's scanning will
fail to find a clean reference SSN. However, this has performance implications.

### 4. Trap Stubs

An advanced defensive technique: place intentional "canary" hooks on functions that
are rarely called legitimately. If a Halo's Gate scan reads these stubs' neighbors,
the canary triggers an alert -- indicating an active scanning attempt.

### 5. Memory Access Telemetry

Reading sequential memory at 32-byte intervals across ntdll's .text section is a
distinctive access pattern. Hardware breakpoints or page-level access monitoring
could detect this scanning behavior, though this is not commonly deployed due to
performance overhead.

### Summary

Halo's Gate overcomes Hell's Gate's limitation with hooked functions, and Tartarus
Gate adds resilience against partial hooks. However, both techniques still result
in direct syscall execution from non-ntdll memory, leaving the core stack-trace
detection vector intact. This limitation motivated the development of indirect
syscalls.

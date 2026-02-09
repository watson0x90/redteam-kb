# AMSI Patching - Educational Analysis

> **MITRE ATT&CK**: T1562.001 - Impair Defenses: Disable or Modify Tools
> **Purpose**: Understanding AMSI architecture for detection engineering
> **Languages**: C, Python
> **Detection Focus**: Integrity monitoring, ETW events, memory scanning

## Strategic Overview

The Antimalware Scan Interface (AMSI) is a Windows security feature that allows applications to send content to antimalware providers for scanning before execution. PowerShell, VBScript, JScript, and .NET all integrate with AMSI. Understanding how AMSI works - and how it can be tampered with - is critical for both red team operators and defenders.

### Why This Matters for Red Team Leads
- AMSI is the first line of defense against script-based attacks
- Understanding bypass methods informs payload development decisions
- Detection of AMSI tampering is a high-fidelity alert for defenders

### Detection Opportunity
AMSI tampering is **highly detectable** through ETW events, integrity monitoring, and behavioral analysis.

## Technical Deep-Dive

### AMSI Architecture

```
┌────────────┐     ┌──────────┐     ┌─────────────┐     ┌──────────────┐
│ PowerShell │────>│ amsi.dll │────>│ AMSI Provider│────>│  AV Engine   │
│ Script Host│     │          │     │ (MpOav.dll)  │     │ (WdFilter)   │
│            │     │AmsiScan  │     │              │     │              │
│            │     │Buffer()  │     │ Returns:     │     │ Signature    │
│            │     │          │     │ CLEAN/MALWARE│     │ Matching     │
└────────────┘     └──────────┘     └─────────────┘     └──────────────┘

AMSI Flow:
1. Application (e.g., PowerShell) calls AmsiScanBuffer/AmsiScanString
2. amsi.dll forwards content to registered AMSI provider
3. Provider (typically Windows Defender) scans content
4. Result returned: AMSI_RESULT_CLEAN or AMSI_RESULT_DETECTED
5. Application decides whether to execute based on result
```

### AmsiScanBuffer Function Analysis

```c
/*
 * Educational: AmsiScanBuffer function signature and internals.
 *
 * This is the primary AMSI scanning function. Understanding its
 * behavior is essential for both bypass analysis and detection.
 *
 * Function Prototype (from amsi.h):
 *
 * HRESULT AmsiScanBuffer(
 *     HAMSICONTEXT amsiContext,   // Context from AmsiInitialize
 *     PVOID        buffer,        // Content to scan
 *     ULONG        length,        // Buffer length
 *     LPCWSTR      contentName,   // Identifier for logging
 *     HAMSISESSION amsiSession,   // Session handle
 *     AMSI_RESULT  *result        // OUT: scan result
 * );
 *
 * Return Values:
 * - S_OK (0): Scan completed successfully
 * - E_INVALIDARG: Invalid parameter
 * - E_NOT_VALID_STATE: AMSI not initialized
 *
 * AMSI_RESULT values:
 * - AMSI_RESULT_CLEAN          (0)
 * - AMSI_RESULT_NOT_DETECTED   (1)
 * - AMSI_RESULT_BLOCKED_BY_ADMIN_START (16384)
 * - AMSI_RESULT_BLOCKED_BY_ADMIN_END   (20479)
 * - AMSI_RESULT_DETECTED       (32768)
 */

#include <windows.h>
#include <stdio.h>

/*
 * AMSI Patch Concepts (Educational - How It Works)
 *
 * Concept 1: Return-based patch
 * The first instructions of AmsiScanBuffer are overwritten with:
 * - x64: mov eax, 0x80070057 (E_INVALIDARG); ret
 *   Bytes: B8 57 00 07 80 C3
 * - This makes AmsiScanBuffer always return "invalid argument"
 * - PowerShell interprets the error as "scan passed"
 *
 * Detection of this approach:
 * 1. Memory integrity: Compare amsi.dll .text section against
 *    the on-disk version. Any differences = tampering.
 * 2. ETW: Microsoft-Windows-AMSI provider logs scan failures
 * 3. Periodic scanning: Scan AmsiScanBuffer prologue for patches
 * 4. Kernel callbacks: Register for image load notifications
 *
 * Concept 2: AmsiOpenSession patch
 * Patching AmsiOpenSession to fail prevents scanning sessions
 * from being created, so AmsiScanBuffer is never called.
 *
 * Concept 3: AMSI context corruption
 * Corrupting the AMSI context handle makes all scans fail.
 * Less targeted but harder to detect via function patching checks.
 */

/* Structure definitions for analysis */
typedef enum {
    AMSI_RESULT_CLEAN           = 0,
    AMSI_RESULT_NOT_DETECTED    = 1,
    AMSI_RESULT_DETECTED        = 32768
} AMSI_RESULT_ENUM;

/*
 * Detection: Verify AmsiScanBuffer integrity
 *
 * Compare the first N bytes of AmsiScanBuffer against known-good
 * prologue. If they differ, patching has occurred.
 *
 * Known-good x64 prologue (Windows 10/11):
 * 4C 8B DC           mov r11, rsp
 * 49 89 5B 08        mov [r11+08], rbx
 * 49 89 6B 10        mov [r11+10], rbp
 * 49 89 73 18        mov [r11+18], rsi
 * 57                 push rdi
 * 41 56              push r14
 * 41 57              push r15
 *
 * If first bytes are: B8 57 00 07 80 C3 = PATCHED
 */
void check_amsi_integrity(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        printf("amsi.dll not loaded\n");
        return;
    }

    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) {
        printf("AmsiScanBuffer not found\n");
        return;
    }

    /* Read first 16 bytes of the function */
    unsigned char prologue[16];
    memcpy(prologue, (void *)pAmsiScanBuffer, sizeof(prologue));

    printf("AmsiScanBuffer @ 0x%p\n", pAmsiScanBuffer);
    printf("Prologue bytes: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", prologue[i]);
    }
    printf("\n");

    /* Check for known patch patterns */
    if (prologue[0] == 0xB8 && prologue[5] == 0xC3) {
        printf("ALERT: AmsiScanBuffer appears PATCHED!\n");
        printf("  Pattern: mov eax, 0x%08X; ret\n",
               *(DWORD *)&prologue[1]);
    } else if (prologue[0] == 0xC3) {
        printf("ALERT: AmsiScanBuffer starts with RET!\n");
    } else if (prologue[0] == 0x4C && prologue[1] == 0x8B) {
        printf("OK: AmsiScanBuffer appears intact.\n");
    } else {
        printf("WARNING: Unknown prologue - investigate further.\n");
    }

    FreeLibrary(hAmsi);
}
```

### Hardware Breakpoint Approach Analysis

```c
/*
 * Educational: Hardware breakpoint-based AMSI bypass concept.
 *
 * Instead of modifying memory (which is detectable by integrity
 * checks), this approach uses hardware debug registers to intercept
 * execution at the AmsiScanBuffer entry point.
 *
 * How it works:
 * 1. Set a hardware breakpoint (DR0) on AmsiScanBuffer address
 * 2. Register a Vectored Exception Handler (VEH)
 * 3. When AmsiScanBuffer is called, the breakpoint fires
 * 4. VEH catches the SINGLE_STEP exception
 * 5. VEH modifies the return value and skips the function
 *
 * Advantages:
 * - No memory modification (passes integrity checks)
 * - No suspicious VirtualProtect calls
 *
 * Detection:
 * - VEH registration: AddVectoredExceptionHandler is monitorable
 * - Debug register access: GetThreadContext/SetThreadContext
 * - Hardware breakpoints can be detected by checking DR registers
 * - ETW: Exception dispatch events
 */

#include <windows.h>
#include <stdio.h>

/*
 * Vectored Exception Handler concept
 *
 * Detection Points:
 * 1. AddVectoredExceptionHandler API call
 * 2. EXCEPTION_SINGLE_STEP (0x80000004) exceptions
 * 3. Debug register (DR0-DR3) modifications
 * 4. SetThreadContext API calls
 *
 * Monitoring:
 * - ETW Provider: Microsoft-Windows-Kernel-Process
 * - EDR hook on NtSetContextThread
 * - Periodic DR register inspection
 */

/* Check if hardware breakpoints are set (defensive tool) */
void check_hardware_breakpoints(void) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        printf("=== Hardware Breakpoint Check ===\n");
        printf("DR0: 0x%016llX", (unsigned long long)ctx.Dr0);
        if (ctx.Dr0) printf(" [BREAKPOINT SET]");
        printf("\n");

        printf("DR1: 0x%016llX", (unsigned long long)ctx.Dr1);
        if (ctx.Dr1) printf(" [BREAKPOINT SET]");
        printf("\n");

        printf("DR2: 0x%016llX", (unsigned long long)ctx.Dr2);
        if (ctx.Dr2) printf(" [BREAKPOINT SET]");
        printf("\n");

        printf("DR3: 0x%016llX", (unsigned long long)ctx.Dr3);
        if (ctx.Dr3) printf(" [BREAKPOINT SET]");
        printf("\n");

        printf("DR7: 0x%016llX (control register)\n",
               (unsigned long long)ctx.Dr7);

        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            printf("\nALERT: Hardware breakpoints detected!\n");
            printf("This may indicate AMSI/ETW bypass attempts.\n");
        } else {
            printf("\nOK: No hardware breakpoints set.\n");
        }
    }
}
```

### Detection Script (Python)

```python
"""
Educational: AMSI integrity monitoring script.
Demonstrates how defenders can detect AMSI tampering.
"""
import ctypes
import ctypes.wintypes
import struct

def check_amsi_status():
    """
    Verify AMSI integrity by checking AmsiScanBuffer prologue.

    Deploy as:
    - Scheduled task running every 5 minutes
    - EDR custom detection rule
    - Sysmon configuration trigger
    """
    try:
        amsi = ctypes.windll.LoadLibrary("amsi.dll")
        addr = ctypes.windll.kernel32.GetProcAddress(
            amsi._handle,
            b"AmsiScanBuffer"
        )

        if not addr:
            return {"status": "ERROR", "message": "AmsiScanBuffer not found"}

        # Read first 8 bytes
        buf = (ctypes.c_ubyte * 8)()
        ctypes.memmove(buf, addr, 8)
        prologue = bytes(buf)

        # Check for known patch patterns
        patches = {
            b'\xB8\x57\x00\x07\x80\xC3': 'E_INVALIDARG return patch',
            b'\xB8\x00\x00\x00\x00\xC3': 'Zero return patch',
            b'\xC3':                       'Immediate RET',
            b'\x31\xC0\xC3':              'xor eax,eax; ret',
            b'\x48\x31\xC0\xC3':          'xor rax,rax; ret (x64)',
        }

        for pattern, description in patches.items():
            if prologue[:len(pattern)] == pattern:
                return {
                    "status": "PATCHED",
                    "description": description,
                    "bytes": prologue.hex(),
                    "severity": "CRITICAL",
                    "action": "AMSI has been tampered with - investigate immediately"
                }

        return {
            "status": "INTACT",
            "bytes": prologue.hex(),
            "message": "AmsiScanBuffer appears unmodified"
        }

    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

# Run check
result = check_amsi_status()
print(f"AMSI Status: {result['status']}")
for k, v in result.items():
    if k != 'status':
        print(f"  {k}: {v}")
```

## Detection & Evasion

### Detection Matrix

| Bypass Method | Detection Mechanism | Event Source | Reliability |
|--------------|-------------------|-------------|-------------|
| Memory patching | Integrity check on amsi.dll .text | Memory scan | High |
| Hardware breakpoints | DR register inspection | GetThreadContext | Medium |
| AMSI context corruption | AMSI scan failure events | ETW AMSI provider | High |
| AmsiInitialize hook | DLL load monitoring | Sysmon Event 7 | Medium |
| CLR hooking | .NET assembly load events | ETW CLR provider | Medium |

### ETW-Based Detection

```
ETW Provider: Microsoft-Windows-AMSI (ID: 2A576B87-09A7-520E-C21A-4942F0271D67)

Key Events:
- Event ID 1101: AmsiScanBuffer called (content, result)
- Event ID 1102: AmsiScanString called
- Event ID 1103: AmsiNotifyOperation called

Detection Logic:
1. If AMSI events suddenly STOP after being active = patching likely
2. If all scan results are CLEAN during suspicious activity = investigate
3. If AMSI initialization fails repeatedly = context corruption
```

### Defensive Hardening

1. **Credential Guard**: Protects AMSI from in-process tampering
2. **WDAC/AppLocker**: Prevent loading of unsigned DLLs that may patch AMSI
3. **ETW monitoring**: Alert on AMSI provider event gaps
4. **Memory integrity**: Periodic comparison of amsi.dll in-memory vs on-disk
5. **Script Block Logging**: GPO: "Turn on PowerShell Script Block Logging"

## Cross-References

- [AMSI Bypass Theory](../../06-defense-evasion/amsi-bypass.md)
- [ETW Patching](etw-patching.md)
- [PowerShell Execution](../../03-execution/powershell-execution.md)
- [CLM Bypass](../../06-defense-evasion/clm-bypass.md)

## References

- Microsoft: AMSI Architecture Documentation
- MITRE ATT&CK T1562.001
- MDSec: AMSI Bypass Research
- Rasta Mouse: AMSI Bypass Methods Analysis
- Elastic Security: Detecting AMSI Bypass Techniques

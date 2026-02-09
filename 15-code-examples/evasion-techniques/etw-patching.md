# ETW Patching - Educational Analysis

> **MITRE ATT&CK**: T1562.006 - Impair Defenses: Indicator Blocking
> **Purpose**: Understanding ETW architecture for detection engineering
> **Languages**: C
> **Detection Focus**: ETW provider integrity, kernel callback monitoring

## Strategic Overview

Event Tracing for Windows (ETW) is the primary telemetry framework in Windows. It provides real-time event data to security tools, EDR agents, and the Windows Event Log. Understanding ETW architecture - and how adversaries attempt to blind it - is critical for building resilient detection pipelines.

### Why This Matters for Red Team Leads
- ETW is the backbone of most EDR detection capabilities
- Tampering with ETW can blind multiple security tools simultaneously
- Understanding ETW helps evaluate which detections can be bypassed

### Detection Opportunity
ETW tampering is **detectable** through kernel-level monitoring, integrity checks, and canary events that validate ETW pipeline health.

## Technical Deep-Dive

### ETW Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    ETW Architecture                          │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │Provider 1│  │Provider 2│  │Provider 3│  Providers        │
│  │(.NET CLR)│  │(Kernel)  │  │(Security)│  (Event Sources)  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘                  │
│       │              │              │                        │
│       ▼              ▼              ▼                        │
│  ┌──────────────────────────────────────────────┐           │
│  │           ETW Session (Kernel)                │           │
│  │  Manages buffers, routing, delivery           │  Session  │
│  └──────────────────────┬───────────────────────┘  Layer    │
│                         │                                    │
│       ┌─────────────────┼─────────────────┐                 │
│       ▼                 ▼                 ▼                  │
│  ┌─────────┐    ┌──────────┐    ┌──────────┐               │
│  │Event Log│    │EDR Agent │    │Real-time │  Consumers     │
│  │Service  │    │(ETW sub) │    │Analyzer  │  (Listeners)   │
│  └─────────┘    └──────────┘    └──────────┘               │
│                                                              │
└──────────────────────────────────────────────────────────────┘

Key ETW Providers for Security:
─────────────────────────────────────────────────────────────
Microsoft-Windows-Kernel-Process     Process creation/termination
Microsoft-Windows-Kernel-File        File operations
Microsoft-Windows-Kernel-Network     Network connections
Microsoft-Windows-Kernel-Registry    Registry modifications
Microsoft-Windows-DotNETRuntime      .NET assembly loads
Microsoft-Windows-AMSI               AMSI scan events
Microsoft-Windows-PowerShell         PowerShell script execution
Microsoft-Windows-Threat-Intelligence Memory/code integrity
Microsoft-Windows-Security-Auditing  Security event log
─────────────────────────────────────────────────────────────
```

### EtwEventWrite Function Analysis

```c
/*
 * Educational: EtwEventWrite function internals.
 *
 * EtwEventWrite is the user-mode function that providers call
 * to emit events. It's exported by ntdll.dll and transitions
 * to kernel mode via NtTraceEvent.
 *
 * Call Chain:
 * Provider -> EtwEventWrite (ntdll) -> NtTraceEvent (syscall) -> Kernel ETW
 *
 * Patching Concepts:
 *
 * 1. EtwEventWrite patch: Overwrite the function prologue to
 *    immediately return 0 (STATUS_SUCCESS). The provider thinks
 *    the event was written, but it never reaches the kernel.
 *
 * 2. NtTraceEvent patch: Similar but at the syscall transition
 *    point. Harder to detect but same effect.
 *
 * 3. Provider disable: Use EtwEventRegister to disable specific
 *    providers rather than patching functions.
 *
 * Detection:
 * - Memory integrity: Compare ntdll .text section against disk
 * - Canary events: Send test events and verify they arrive
 * - Kernel callbacks: Kernel-level ETW monitoring can't be
 *   patched from user mode (requires driver/BYOVD)
 */

#include <windows.h>
#include <evntprov.h>  /* ETW provider APIs */
#include <stdio.h>

/*
 * ETW Provider Registration (how providers work)
 *
 * This shows the normal flow of ETW provider usage.
 * Understanding this helps analysts know what to monitor.
 */
void demonstrate_etw_provider(void) {
    REGHANDLE hProvider = 0;

    /* Define a test provider GUID */
    /* In real use, each provider has a unique GUID */
    GUID testGuid = {0x12345678, 0xAAAA, 0xBBBB,
                     {0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33}};

    /*
     * EventRegister: Register as an ETW provider
     *
     * Detection: Unexpected EventRegister calls from suspicious
     * processes may indicate custom ETW manipulation.
     */
    ULONG status = EventRegister(
        &testGuid,
        NULL,        /* No enable callback */
        NULL,        /* No callback context */
        &hProvider
    );

    if (status != ERROR_SUCCESS) {
        printf("EventRegister failed: %lu\n", status);
        return;
    }

    /*
     * EventWrite: Emit an event
     *
     * This is what gets patched in ETW bypass scenarios.
     * The call goes through:
     * EventWrite -> EtwEventWrite (ntdll) -> NtTraceEvent (kernel)
     *
     * If EtwEventWrite is patched, this call returns success
     * but the event never reaches the ETW session.
     */
    EVENT_DESCRIPTOR eventDesc = {0};
    eventDesc.Id = 1;
    eventDesc.Level = 4;  /* Informational */

    EventWrite(hProvider, &eventDesc, 0, NULL);
    printf("Event written (if ETW is intact, this was delivered)\n");

    EventUnregister(hProvider);
}

/*
 * EtwEventWrite Integrity Check (Defensive Tool)
 *
 * Compare the in-memory version of EtwEventWrite against
 * the expected prologue to detect patching.
 *
 * Expected x64 prologue (Windows 10/11):
 * 4C 8B DC           mov r11, rsp
 * 48 83 EC 58        sub rsp, 0x58
 * ...or similar function setup
 *
 * Patched prologue:
 * C3                 ret (immediately return)
 * or
 * 33 C0 C3           xor eax, eax; ret (return 0)
 * or
 * B8 00 00 00 00 C3  mov eax, 0; ret
 */
void check_etw_integrity(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("ERROR: ntdll.dll not found\n");
        return;
    }

    /* Check EtwEventWrite */
    FARPROC pEtwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
    if (pEtwEventWrite) {
        unsigned char prologue[8];
        memcpy(prologue, (void *)pEtwEventWrite, sizeof(prologue));

        printf("EtwEventWrite @ 0x%p\n", pEtwEventWrite);
        printf("  Prologue: ");
        for (int i = 0; i < 8; i++) printf("%02X ", prologue[i]);
        printf("\n");

        /* Check for patch indicators */
        if (prologue[0] == 0xC3) {
            printf("  ALERT: Starts with RET - PATCHED!\n");
        } else if (prologue[0] == 0x33 && prologue[1] == 0xC0 && prologue[2] == 0xC3) {
            printf("  ALERT: xor eax,eax; ret - PATCHED!\n");
        } else if (prologue[0] == 0xB8 && prologue[5] == 0xC3) {
            printf("  ALERT: mov eax,imm; ret - PATCHED!\n");
        } else {
            printf("  OK: Prologue appears intact\n");
        }
    }

    /* Check NtTraceEvent */
    FARPROC pNtTraceEvent = GetProcAddress(ntdll, "NtTraceEvent");
    if (pNtTraceEvent) {
        unsigned char prologue[8];
        memcpy(prologue, (void *)pNtTraceEvent, sizeof(prologue));

        printf("\nNtTraceEvent @ 0x%p\n", pNtTraceEvent);
        printf("  Prologue: ");
        for (int i = 0; i < 8; i++) printf("%02X ", prologue[i]);
        printf("\n");

        /* NtTraceEvent should start with: mov r10, rcx; mov eax, SSN */
        if (prologue[0] == 0x4C && prologue[1] == 0x8B && prologue[2] == 0xD1) {
            printf("  OK: Standard syscall stub\n");
        } else if (prologue[0] == 0xC3) {
            printf("  ALERT: Starts with RET - PATCHED!\n");
        } else if (prologue[0] == 0xE9 || prologue[0] == 0xFF) {
            printf("  WARNING: Starts with JMP - possibly HOOKED by EDR\n");
        } else {
            printf("  WARNING: Unexpected prologue - investigate\n");
        }
    }
}

/*
 * ETW Provider Enumeration (Defensive)
 *
 * List active ETW sessions and providers to detect:
 * 1. Missing expected providers (disabled by attacker)
 * 2. Unexpected new providers (attacker instrumentation)
 * 3. Modified provider configurations
 *
 * Command-line equivalent:
 * logman query -ets         (list active trace sessions)
 * logman query "EventLog-Security" -ets  (query specific session)
 */
```

### ETW Canary Events (Detection)

```c
/*
 * ETW Canary: A defensive technique to detect ETW tampering.
 *
 * Concept:
 * 1. Register a custom ETW provider
 * 2. Periodically write "canary" events
 * 3. A separate consumer verifies canary events arrive
 * 4. If canary events stop arriving -> ETW has been tampered with
 *
 * This is similar to a network heartbeat but for ETW integrity.
 * If the pipeline is broken, the canary consumer raises an alert.
 */

/*
 * Implementation approach:
 *
 * Thread 1 (Producer):
 *   while (running) {
 *       EventWrite(hProvider, &canaryEvent, ...);
 *       Sleep(5000);  // Every 5 seconds
 *   }
 *
 * Thread 2 (Consumer):
 *   Subscribe to canary provider
 *   while (running) {
 *       WaitForEvent(timeout=10000);
 *       if (no event received within 10 seconds) {
 *           ALERT: ETW pipeline may be compromised!
 *           // Trigger: email, SIEM alert, process dump
 *       }
 *   }
 *
 * Detection Value:
 * - Catches ALL forms of ETW patching (function patch, provider
 *   disable, session destruction)
 * - Works regardless of which function is patched
 * - Minimal performance impact
 * - Cannot be bypassed without also tampering with the canary
 */
```

## Detection & Evasion

### Detection Summary

| Tampering Method | Detection | Reliability |
|-----------------|-----------|-------------|
| EtwEventWrite patch | ntdll integrity check | High |
| NtTraceEvent patch | ntdll integrity check | High |
| Provider disable | Provider enumeration | Medium |
| Session destruction | Session monitoring | Medium |
| Kernel ETW patch | Requires PatchGuard/KPP bypass | Very Hard to bypass |
| Canary events | Event flow monitoring | Very High |

### Defensive Recommendations

1. **ETW Canary**: Deploy canary event producer/consumer pairs
2. **ntdll Integrity**: Periodically verify ntdll function prologues
3. **Kernel telemetry**: Use Microsoft-Windows-Threat-Intelligence (requires PPL)
4. **Session monitoring**: Alert when security-critical ETW sessions are modified
5. **Provider auditing**: Baseline and monitor active ETW providers

### Event Log References

```
Relevant Event IDs:
─────────────────────────────────────────────────────
Security Event Log:
  4688: Process creation (with command line logging enabled)
  4689: Process termination

Sysmon:
  Event 1:  Process creation
  Event 7:  Image loaded (DLL loading)
  Event 10: Process access (handle operations)

ETW Sessions (logman query -ets):
  Monitor for session deletions or modifications
  Alert on "EventLog-*" session changes
─────────────────────────────────────────────────────
```

## Cross-References

- [ETW Evasion Theory](../../06-defense-evasion/etw-evasion.md)
- [AMSI Patching](amsi-patching.md)
- [NTDLL Unhooking](../syscalls-and-evasion/ntdll-unhooking.md)
- [Direct Syscalls](../syscalls-and-evasion/direct-syscalls.md)
- [Detection Engineering Notes](../../appendices/detection-engineering-notes.md)

## References

- Microsoft: ETW Architecture Documentation
- MITRE ATT&CK T1562.006
- Matt Graeber: Subverting Sysmon
- Palantir: ETW Tampering Detection
- Elastic Security: Detecting ETW Patching

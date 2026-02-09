# Sleep Obfuscation - Educational Analysis

> **MITRE ATT&CK**: T1027.013 - Obfuscated Files or Information: Encrypted/Encoded Information
> **Purpose**: Understanding sleep-time evasion for detection engineering
> **Languages**: C
> **Detection Focus**: Memory permission changes, timer queue abuse, call stack analysis

## Strategic Overview

Sleep obfuscation (also called sleep encryption or Ekko-style obfuscation) encrypts a beacon's memory while it sleeps between check-ins. This defeats memory scanners that look for known implant signatures during the sleep period (which is typically 90%+ of the beacon's lifetime). Understanding this technique is essential for building detection capabilities.

### Why This Matters for Red Team Leads
- Memory scanning is a primary EDR detection mechanism
- Beacons spend most of their time sleeping (60-300+ second intervals)
- Encrypting memory during sleep reduces the window for detection

### Detection Opportunity
Sleep obfuscation requires periodic memory permission changes and timer manipulation, both of which are **detectable** through proper monitoring.

## Technical Deep-Dive

### The Problem Sleep Obfuscation Solves

```
Without Sleep Obfuscation:
─────────────────────────────────────────────
  ┌──────┐  ┌──────────────────────────────────────┐  ┌──────┐
  │Active│  │          SLEEPING (60 sec)            │  │Active│
  │ 1sec │  │  Memory contains: implant code,       │  │ 1sec │
  │      │  │  strings, config, C2 addresses...     │  │      │
  │      │  │  ▲ SCANNABLE by EDR memory scanning   │  │      │
  └──────┘  └──────────────────────────────────────┘  └──────┘

  Memory is readable and scannable for ~98% of the time!

With Sleep Obfuscation:
─────────────────────────────────────────────
  ┌──────┐  ┌──────────────────────────────────────┐  ┌──────┐
  │Active│  │          SLEEPING (60 sec)            │  │Active│
  │ 1sec │  │  Memory is ENCRYPTED (random bytes)   │  │ 1sec │
  │      │  │  Protection: PAGE_READWRITE (no exec) │  │      │
  │      │  │  ▲ Scanners find nothing recognizable │  │      │
  └──────┘  └──────────────────────────────────────┘  └──────┘

  Only ~2% of time has scannable implant signatures!
```

### Timer Queue Mechanism

```c
/*
 * Educational: How timer-based sleep obfuscation works.
 *
 * The technique uses Windows Timer Queues to schedule a chain
 * of operations that execute automatically:
 *
 * Timer Chain:
 * T1 (0ms):   Encrypt implant memory (XOR/RC4/AES)
 * T2 (0ms):   Change memory protection to RW (non-executable)
 * T3 (Nms):   Change memory protection back to RX
 * T4 (Nms):   Decrypt implant memory
 * T5 (Nms):   Signal completion event (resume execution)
 *
 * The timers fire in sequence, creating an automated
 * encrypt-sleep-decrypt cycle.
 *
 * Detection:
 * - CreateTimerQueueTimer API calls with short, chained timers
 * - VirtualProtect calls changing RX -> RW -> RX periodically
 * - Memory regions that alternate between encrypted and decrypted
 * - Timer callbacks pointing to VirtualProtect/encryption functions
 *
 * Named Variants:
 * - Ekko:    Uses CreateTimerQueueTimer + ROP chain
 * - Foliage: Uses NtApcQueueTimer for timer callbacks
 * - Cronos:  Uses SetTimer with window message queue
 * - Zilean:  Uses NtDelayExecution with encrypted sections
 */

#include <windows.h>
#include <stdio.h>

/*
 * CreateTimerQueueTimer API (used in Ekko-style obfuscation)
 *
 * BOOL CreateTimerQueueTimer(
 *     PHANDLE             phNewTimer,
 *     HANDLE              TimerQueue,
 *     WAITORTIMERCALLBACK  Callback,    ← This is the key parameter
 *     PVOID               Parameter,
 *     DWORD               DueTime,     ← When to fire
 *     DWORD               Period,      ← 0 = one-shot
 *     ULONG               Flags
 * );
 *
 * Detection Points:
 * 1. Multiple CreateTimerQueueTimer calls in rapid succession
 * 2. Timer callbacks pointing to system APIs (ROP-like behavior)
 * 3. Callbacks targeting VirtualProtect, SystemFunction032 (RC4)
 * 4. Timer due times that create a sequential chain
 */

/*
 * Conceptual Timer Chain (Educational)
 *
 * NOTE: This shows the CONCEPT, not a complete implementation.
 * The actual implementation uses function pointers to system
 * APIs as timer callbacks, creating a ROP-like chain.
 */
void explain_timer_chain(void) {
    printf("=== Ekko Sleep Obfuscation Timer Chain ===\n\n");

    printf("Step 1: Setup\n");
    printf("  - Calculate implant memory region (base, size)\n");
    printf("  - Generate random encryption key\n");
    printf("  - Create timer queue\n\n");

    printf("Step 2: Create Timer Chain\n");
    printf("  Timer 1 (DueTime=0ms):   Encrypt memory (SystemFunction032/XOR)\n");
    printf("  Timer 2 (DueTime=0ms):   VirtualProtect(RW) - remove execute\n");
    printf("  Timer 3 (DueTime=Nms):   VirtualProtect(RX) - restore execute\n");
    printf("  Timer 4 (DueTime=Nms):   Decrypt memory (SystemFunction032/XOR)\n");
    printf("  Timer 5 (DueTime=Nms):   SetEvent(resumeEvent)\n\n");

    printf("Step 3: Wait\n");
    printf("  WaitForSingleObject(resumeEvent, INFINITE)\n");
    printf("  → Thread blocks while timer chain executes\n\n");

    printf("Step 4: Resume\n");
    printf("  Timer 5 fires SetEvent, thread wakes up\n");
    printf("  Memory is decrypted and executable again\n");
    printf("  Implant continues normal operation\n");
}

/*
 * SystemFunction032 - The Encryption Primitive
 *
 * SystemFunction032 is an undocumented function in advapi32.dll
 * that performs RC4 encryption/decryption in-place.
 *
 * Why it's used:
 * - Already present in the process (advapi32 is usually loaded)
 * - Can be called as a timer callback (correct calling convention)
 * - RC4 is symmetric: same function encrypts and decrypts
 * - Fast enough for large memory regions
 *
 * Function Signature:
 * NTSTATUS SystemFunction032(
 *     PUNICODE_STRING Data,  // Buffer to encrypt/decrypt
 *     PUNICODE_STRING Key    // Encryption key
 * );
 *
 * Detection:
 * - GetProcAddress("SystemFunction032") is a strong indicator
 * - This function is rarely used by legitimate software
 * - Combined with timer queue usage = high confidence alert
 */

/* Structure used with SystemFunction032 */
typedef struct {
    DWORD Length;       /* Length of the buffer */
    DWORD MaximumLength;
    PVOID Buffer;       /* Pointer to data */
} USTRING;

/*
 * Detection: Monitoring Memory Permission Changes
 *
 * Sleep obfuscation REQUIRES changing memory permissions:
 * RX (normal) → RW (for encryption) → RX (after decryption)
 *
 * This creates a detectable pattern:
 * 1. Same memory region changes protection multiple times
 * 2. Changes follow a regular interval (sleep time)
 * 3. Permission alternates between RX and RW
 *
 * Detection Approach: Monitor VirtualProtect calls and flag
 * regions that exhibit periodic permission changes.
 */
void demonstrate_detection_logic(void) {
    printf("=== Detection: Memory Permission Monitoring ===\n\n");

    printf("Monitor for this pattern:\n");
    printf("  t=0:     VirtualProtect(region, RW)    [encrypt phase]\n");
    printf("  t=0:     Memory content changes         [encryption]\n");
    printf("  t=60s:   VirtualProtect(region, RX)    [decrypt phase]\n");
    printf("  t=60s:   Memory content changes         [decryption]\n");
    printf("  t=60s:   Code executes from region      [beacon active]\n");
    printf("  t=61s:   VirtualProtect(region, RW)    [next cycle]\n");
    printf("  ...\n\n");

    printf("Detection Rule:\n");
    printf("  IF same memory region has VirtualProtect called\n");
    printf("     alternating between RW and RX\n");
    printf("     more than 3 times in 10 minutes\n");
    printf("  THEN alert: possible sleep obfuscation\n");
}
```

### Call Stack Analysis (Detection)

```c
/*
 * Call Stack Analysis - Detecting Sleep Obfuscation
 *
 * When a beacon is sleeping, its thread's call stack reveals
 * the sleep mechanism. Different methods have different stacks:
 *
 * Normal Sleep (no obfuscation):
 * ─────────────────────────────────
 * ntdll!NtDelayExecution
 * KERNELBASE!SleepEx
 * beacon.dll+0x1234        ← Implant code visible in stack
 *
 * Ekko-style Sleep Obfuscation:
 * ─────────────────────────────────
 * ntdll!NtWaitForSingleObject
 * KERNELBASE!WaitForSingleObjectEx
 * beacon.dll+0x5678        ← Still visible, but memory is encrypted
 *
 * Advanced Obfuscation (stack spoofing):
 * ─────────────────────────────────
 * ntdll!NtWaitForSingleObject
 * KERNELBASE!WaitForSingleObjectEx
 * kernel32!BaseThreadInitThunk  ← Spoofed to look like thread start
 *
 * Detection:
 * 1. Thread waiting on event with call stack containing
 *    non-module (unbacked) memory addresses
 * 2. Return addresses in the stack that point to private memory
 * 3. Stack frames that don't properly chain back to thread start
 */

/*
 * Practical Detection: Use NtQueryInformationThread or
 * StackWalk64 to examine thread call stacks.
 *
 * For each thread:
 *   1. Capture thread context (GetThreadContext)
 *   2. Walk the call stack (StackWalk64)
 *   3. For each return address, check if it maps to a loaded module
 *   4. If any return address is in unbacked memory → SUSPICIOUS
 *
 * Tools that implement this:
 * - Hunt-Sleeping-Beacons (Joe Desimone)
 * - BeaconEye
 * - ThreadStackSpoofer detection
 * - Moneta (forrest-orr)
 */
```

## Detection & Evasion

### Detection Matrix

| Technique | Detection Method | Confidence |
|-----------|-----------------|------------|
| Timer queue creation | API monitoring (CreateTimerQueueTimer) | Medium |
| SystemFunction032 use | API resolution monitoring | High |
| RX ↔ RW transitions | VirtualProtect monitoring | High |
| Periodic permission changes | Time-series analysis of VirtualProtect | Very High |
| Encrypted memory during sleep | Entropy analysis + call stack check | Medium |
| Call stack with unbacked frames | Thread stack walking | High |

### Hunting Queries

```
# Elastic Security / Sysmon
# Detect periodic VirtualProtect calls on same region
process where event.action == "memory_protection_changed"
  and process.name != expected_processes
  | stats count by process.pid, memory.region_base
  | where count > 3

# CrowdStrike / Carbon Black
# Detect SystemFunction032 resolution
api_call:"GetProcAddress" AND api_parameter:"SystemFunction032"

# Thread stack analysis
# Run Hunt-Sleeping-Beacons to find threads with:
# - Wait state + unbacked return addresses
Hunt-Sleeping-Beacons.exe --scan-all
```

### Defensive Recommendations

1. **Thread stack inspection**: Periodically scan sleeping threads for unbacked return addresses
2. **VirtualProtect monitoring**: Track memory regions with periodic permission changes
3. **API monitoring**: Alert on SystemFunction032 resolution by non-crypto applications
4. **Timer queue auditing**: Monitor CreateTimerQueueTimer with callbacks to system APIs
5. **Hunt-Sleeping-Beacons**: Deploy tooling specifically designed for this detection

## Cross-References

- [AV/EDR Evasion Theory](../../06-defense-evasion/av-edr-evasion.md)
- [Process Injection](../process-injection/README.md)
- [ETW Patching](etw-patching.md)
- [Direct Syscalls](../syscalls-and-evasion/direct-syscalls.md)
- [C2 Frameworks](../../11-command-and-control/c2-frameworks.md)

## References

- MITRE ATT&CK T1027.013
- C5pทider: Ekko - Sleep Obfuscation (original research)
- Elastic Security: Detecting Sleep Obfuscation
- Joe Desimone: Hunt-Sleeping-Beacons
- forrest-orr: Moneta Memory Scanner
- Austin Hudson: Foliage Sleep Obfuscation

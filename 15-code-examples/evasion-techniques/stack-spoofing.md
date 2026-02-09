# Stack Spoofing - Educational Analysis

> **MITRE ATT&CK**: T1055 - Process Injection (general evasion technique)
> **Purpose**: Understanding call stack evasion for detection engineering
> **Languages**: C
> **Detection Focus**: Stack frame validation, ROP gadget detection, timing anomalies

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

Modern EDR products analyze thread call stacks to detect shellcode execution. Legitimate
function calls produce clean stack frames with return addresses pointing into known modules
(kernel32, ntdll, user32, etc.). Shellcode and implant code produce anomalous stacks with
return addresses in unbacked (private) memory. Stack spoofing techniques construct fake
stack frames or manipulate return addresses to make malicious call stacks appear legitimate.

### Why This Matters for Red Team Leads
- Call stack analysis is a primary EDR detection mechanism for in-memory threats
- Tools like Hunt-Sleeping-Beacons specifically target anomalous stack frames
- Understanding stack internals is essential for advanced implant development

### Detection Opportunity
Stack spoofing introduces structural anomalies that are **detectable** through deep frame
validation, ROP gadget scanning, and timing analysis.

## Technical Deep-Dive

### Stack Frame Anatomy (x64)

```
x64 Stack Frame Layout (Windows calling convention):
────────────────────────────────────────────────────

Higher addresses
  ┌──────────────────────────────┐
  │ Return Address (8 bytes)     │ ← Points to instruction after CALL
  ├──────────────────────────────┤
  │ Saved RBP (8 bytes)          │ ← Previous frame's base pointer
  ├──────────────────────────────┤
  │ Local Variables              │
  │ ...                          │
  ├──────────────────────────────┤
  │ Shadow Space (32 bytes)      │ ← Required by x64 Windows ABI
  ├──────────────────────────────┤
  │ Parameters (if >4 args)      │
  ├──────────────────────────────┤
  │ Return Address (next frame)  │ ← Next CALL instruction
  └──────────────────────────────┘
Lower addresses (RSP points here)

Key points:
- RBP chain: each frame's saved RBP points to the previous frame
- Return addresses: each should point into a legitimate loaded module
- Walking the RBP chain reconstructs the full call history
- If ANY return address points to unbacked memory → SUSPICIOUS

EDR call stack analysis:
1. Capture thread context (RIP, RSP, RBP)
2. Walk the RBP chain from current frame to thread start
3. For each return address, verify it falls within a loaded module
4. Flag frames with return addresses in private/unbacked memory
```

### The Problem: Anomalous Call Stacks

```c
/*
 * Educational: Why shellcode produces detectable call stacks.
 *
 * When shellcode calls a Windows API (e.g., NtCreateFile), the
 * call stack contains the shellcode's address as a return address.
 *
 * Clean call stack (legitimate program):
 * ─────────────────────────────────────
 * ntdll!NtCreateFile
 * kernelbase!CreateFileW      ← Return addr in kernelbase.dll (signed)
 * myapp.exe!OpenLogFile       ← Return addr in main executable (signed)
 * myapp.exe!main              ← Return addr in main executable (signed)
 * kernel32!BaseThreadInitThunk← Thread start (normal)
 *
 * Anomalous call stack (shellcode):
 * ─────────────────────────────────────
 * ntdll!NtCreateFile
 * kernelbase!CreateFileW      ← Return addr in kernelbase.dll (OK)
 * 0x000001A2B3C40000          ← UNBACKED MEMORY (shellcode!) ← DETECTED
 *
 * The unbacked return address is the primary detection signal.
 * Stack spoofing aims to replace these addresses with ones that
 * point into legitimate modules.
 */
```

### Approach 1: Synthetic Stack Frames

```c
/*
 * Educational: Building fake stack frames before calling Windows APIs.
 *
 * Concept:
 * Before the shellcode calls a Windows API, it constructs a series
 * of fake stack frames on the stack. Each fake frame has:
 * - A saved RBP pointing to the previous fake frame
 * - A return address pointing into a legitimate module
 *
 * The result is a call stack that appears to originate from
 * normal code, even though the actual caller is shellcode.
 *
 * Implementation Steps:
 * 1. Find addresses of RET instructions in legitimate modules
 *    (these serve as "return addresses" in fake frames)
 * 2. Build a chain of fake frames on the stack
 * 3. Set RSP/RBP to point into the fake frame chain
 * 4. Call the target API
 *
 * Detection:
 * - Stack frames that reference RET gadgets (not actual function bodies)
 * - Return addresses that point to single RET instructions rather than
 *   the instruction after a CALL (no corresponding CALL before the RET)
 * - Frame alignment anomalies (16-byte alignment violations)
 * - Stack depth that does not match expected call depth
 *
 * OPSEC:
 * - Must maintain correct 16-byte RSP alignment (Windows ABI requirement)
 * - Fake return addresses should be plausible (inside function bodies)
 * - Using RET-only gadgets is detectable; better to use addresses after
 *   real CALL instructions in known functions
 */

#include <windows.h>
#include <stdio.h>

/*
 * Finding RET gadgets in legitimate modules.
 *
 * A "gadget" is a short instruction sequence ending in RET (0xC3).
 * For stack spoofing, we need addresses of RET instructions in
 * modules like kernel32.dll or ntdll.dll.
 *
 * Detection: If return addresses in a call stack all point to
 * simple RET or JMP;RET sequences rather than real function code,
 * this indicates synthetic frames.
 */
LPVOID find_ret_gadget(HMODULE hModule) {
    /*
     * Walk the .text section of the module looking for 0xC3 (RET).
     *
     * OPSEC note: A single RET gadget is suspicious. Better spoofing
     * uses addresses AFTER legitimate CALL instructions, so the
     * return address looks like a normal function return.
     */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".text") == 0) {
            BYTE *text = (BYTE*)hModule + section[i].VirtualAddress;
            DWORD size = section[i].Misc.VirtualSize;

            /* Scan for RET instruction (0xC3) */
            for (DWORD j = 0; j < size; j++) {
                if (text[j] == 0xC3) {
                    return &text[j];
                }
            }
        }
    }
    return NULL;
}

/*
 * Conceptual: Building synthetic stack frames.
 *
 * WARNING: This is pseudo-code illustrating the concept.
 * Actual implementation requires careful assembly to manipulate
 * RSP/RBP without corrupting the real stack.
 *
 * The fake stack layout:
 *
 * [RSP]     → Shadow space (32 bytes, zeroed)
 * [RSP+32]  → Fake return addr 1 (points to RET in kernel32)
 * [RSP+40]  → Fake saved RBP 1 (points to next fake frame)
 * [RSP+48]  → Fake return addr 2 (points to RET in ntdll)
 * [RSP+56]  → Fake saved RBP 2 (points to next fake frame)
 * [RSP+64]  → Fake return addr 3 (BaseThreadInitThunk+N)
 * [RSP+72]  → NULL (end of chain)
 *
 * Detection:
 * - Validate that each return address has a CALL instruction
 *   at [return_addr - 5] (E8 xx xx xx xx for near CALL)
 * - Check that the CALL target matches the next frame's function
 * - Verify stack frame sizes are consistent with function prologues
 */
void explain_synthetic_frames(void) {
    printf("=== Synthetic Stack Frame Construction ===\n\n");

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    LPVOID ret_k32 = find_ret_gadget(k32);
    LPVOID ret_ntdll = find_ret_gadget(ntdll);

    printf("kernel32 RET gadget: %p\n", ret_k32);
    printf("ntdll    RET gadget: %p\n", ret_ntdll);
    printf("\nThese addresses would be placed as return addresses\n");
    printf("in fake stack frames to create a legitimate-looking\n");
    printf("call stack during API calls from shellcode.\n");
}
```

### Approach 2: Return Address Spoofing (JMP Gadget)

```c
/*
 * Educational: Return address spoofing using JMP RBX gadgets.
 *
 * Instead of building entire fake frames, this approach replaces
 * just the immediate return address with a gadget address in a
 * legitimate DLL.
 *
 * Concept:
 * 1. Find a "JMP RBX" gadget (0xFF 0x23 or 0x48 0xFF 0xE3) in ntdll
 * 2. Set RBX = address of the actual target function (API to call)
 * 3. Push the JMP RBX gadget address as the return address
 * 4. When the API returns, it jumps to the gadget (in ntdll)
 * 5. The gadget executes JMP RBX, which jumps to our next instruction
 *
 * Result: The API sees a return address inside ntdll (legitimate),
 * not in shellcode memory.
 *
 * Detection:
 * - Return addresses pointing to JMP/CALL register gadgets
 * - Stack contains addresses of known gadgets used by spoofing tools
 * - The instruction at the return address is a single JMP, not normal code
 * - Behavioral: the call stack "skips" a frame (gadget does not create one)
 *
 * OPSEC:
 * - JMP RBX gadgets are limited; specific addresses may be signatured
 * - Better to use JMP [RBX+offset] or CALL [RAX] for variety
 * - The gadget address itself becomes an IOC if widely used
 */

/*
 * Find a JMP RBX gadget in a module's .text section.
 *
 * JMP RBX = 0xFF 0xE3 (2 bytes)
 *
 * Detection: If a return address points to exactly these bytes,
 * it indicates return address spoofing. Build detection rules
 * that check if the instruction at each return address is a
 * JMP/CALL register instruction.
 */
LPVOID find_jmp_rbx_gadget(HMODULE hModule) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".text") == 0) {
            BYTE *text = (BYTE*)hModule + section[i].VirtualAddress;
            DWORD size = section[i].Misc.VirtualSize;

            /* Scan for JMP RBX (0xFF 0xE3) */
            for (DWORD j = 0; j < size - 1; j++) {
                if (text[j] == 0xFF && text[j + 1] == 0xE3) {
                    /*
                     * Found JMP RBX gadget.
                     *
                     * Detection: Catalog all JMP register gadgets in system DLLs.
                     * If any return address on any thread's stack points to one
                     * of these gadgets, investigate the thread.
                     */
                    return &text[j];
                }
            }
        }
    }
    return NULL;
}

void explain_return_address_spoofing(void) {
    printf("=== Return Address Spoofing (JMP RBX) ===\n\n");

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    LPVOID gadget = find_jmp_rbx_gadget(ntdll);

    printf("JMP RBX gadget in ntdll: %p\n", gadget);
    printf("\nUsage concept:\n");
    printf("  1. Set RBX = address of next shellcode instruction\n");
    printf("  2. Push gadget address as fake return address\n");
    printf("  3. JMP to target API\n");
    printf("  4. API executes and RETs to gadget (in ntdll - looks clean)\n");
    printf("  5. Gadget executes JMP RBX -> back to shellcode\n");
    printf("\nThe API only sees the ntdll gadget address on the stack,\n");
    printf("not the shellcode address.\n");
}
```

### Approach 3: Call Stack Desynchronization (NtContinue / RtlRestoreContext)

```c
/*
 * Educational: Using NtContinue or RtlRestoreContext for full
 * register context control, including RSP (stack pointer).
 *
 * Concept:
 * NtContinue and RtlRestoreContext accept a CONTEXT structure that
 * specifies ALL register values, including RIP and RSP. By crafting
 * a CONTEXT with:
 * - RIP = address of target API function
 * - RSP = address of a pre-built fake stack
 *
 * ...the target function executes with an entirely controlled stack.
 * The call stack appears to originate from whatever the fake stack says.
 *
 * NtContinue Prototype (undocumented):
 * NTSTATUS NtContinue(
 *     PCONTEXT ThreadContext,  ← Full register context to restore
 *     BOOLEAN  RaiseAlert      ← Usually FALSE
 * );
 *
 * RtlRestoreContext Prototype:
 * VOID RtlRestoreContext(
 *     PCONTEXT ContextRecord,
 *     PEXCEPTION_RECORD ExceptionRecord ← NULL for normal use
 * );
 *
 * OPSEC Rating: HIGH
 * - Full control over the entire call stack appearance
 * - No gadgets needed (the context swap is atomic)
 * - Used by Ekko/Foliage sleep obfuscation for sleeping with clean stacks
 *
 * Detection:
 * - NtContinue / RtlRestoreContext calls with suspicious CONTEXT values
 * - RSP in CONTEXT pointing to non-stack memory
 * - RIP in CONTEXT pointing to a Windows API (direct call via context swap)
 * - Timer callbacks that invoke NtContinue (Ekko/Foliage pattern)
 */

/*
 * Timer-Based Stack Spoofing (Ekko/Foliage Pattern)
 *
 * This approach combines CreateTimerQueueTimer with NtContinue:
 *
 * 1. Build a CONTEXT structure:
 *    - RIP = NtContinue
 *    - RSP = fake stack with clean return addresses
 *    - RCX = pointer to another CONTEXT that runs the actual target
 *
 * 2. Create a timer with the CONTEXT as the callback parameter:
 *    CreateTimerQueueTimer(timer, queue, NtContinue, &ctx, 0, 0, ...)
 *
 * 3. When the timer fires, NtContinue executes with the crafted context
 *    The resulting call stack shows only legitimate module addresses
 *
 * Detection:
 * - CreateTimerQueueTimer with callback = NtContinue or RtlRestoreContext
 * - Timer parameter pointing to a CONTEXT structure
 * - CONTEXT.Rip set to a Windows API function
 * - CONTEXT.Rsp pointing to non-standard stack memory
 *
 * Cross-reference: See sleep-obfuscation.md for how Ekko/Foliage use
 * this pattern for sleeping with encrypted memory AND spoofed stacks.
 */

typedef NTSTATUS (NTAPI *pNtContinue)(PCONTEXT, BOOLEAN);

void explain_context_based_spoofing(void) {
    printf("=== NtContinue-Based Call Stack Desynchronization ===\n\n");

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC pNC = GetProcAddress(ntdll, "NtContinue");
    FARPROC pRRC = GetProcAddress(ntdll, "RtlRestoreContext");

    printf("NtContinue:        %p\n", pNC);
    printf("RtlRestoreContext: %p\n", pRRC);

    printf("\nContext-based spoofing flow:\n");
    printf("  1. Capture current CONTEXT (RtlCaptureContext)\n");
    printf("  2. Modify CONTEXT.Rip = target API address\n");
    printf("  3. Modify CONTEXT.Rsp = fake stack with clean frames\n");
    printf("  4. Set API parameters in CONTEXT.Rcx/Rdx/R8/R9\n");
    printf("  5. Call NtContinue(&modified_context, FALSE)\n");
    printf("  6. Execution transfers to API with spoofed stack\n\n");

    printf("Ekko/Foliage integration:\n");
    printf("  - Timer fires → NtContinue with CONTEXT\n");
    printf("  - CONTEXT.Rip = VirtualProtect (to change permissions)\n");
    printf("  - CONTEXT.Rsp = fake stack (clean call chain)\n");
    printf("  - Result: sleep encryption with clean call stack\n");

    /*
     * Detection Strategy:
     * Monitor for NtContinue/RtlRestoreContext calls where:
     * 1. CONTEXT.Rsp does not point to the thread's actual stack
     *    (compare against TEB.StackBase/StackLimit)
     * 2. CONTEXT.Rip points to a known API function (not normal for
     *    exception handling use of NtContinue)
     * 3. Called from a timer callback context
     */
}
```

### Relationship to Sleep Obfuscation

```c
/*
 * Educational: How Ekko/Foliage combine stack spoofing with sleep encryption.
 *
 * The Ekko technique (detailed in sleep-obfuscation.md) uses a timer
 * chain to encrypt beacon memory during sleep. Advanced variants add
 * stack spoofing to make the sleeping thread's call stack appear clean.
 *
 * Without stack spoofing:
 *   Thread sleeps → WaitForSingleObject → call stack shows beacon.dll
 *   → Hunt-Sleeping-Beacons detects unbacked return address
 *
 * With stack spoofing (Foliage):
 *   Thread sleeps → WaitForSingleObject → call stack shows only
 *   ntdll + kernel32 frames → appears to be a normal thread pool wait
 *
 * Timer chain with stack spoofing:
 * Timer 1: NtContinue(ctx1) where ctx1.Rip = SystemFunction032 (encrypt)
 * Timer 2: NtContinue(ctx2) where ctx2.Rip = VirtualProtect (RW)
 * Timer 3: NtContinue(ctx3) where ctx3.Rip = WaitForSingleObject (sleep)
 *          ctx3.Rsp = fake stack with clean frames
 * Timer 4: NtContinue(ctx4) where ctx4.Rip = VirtualProtect (RX)
 * Timer 5: NtContinue(ctx5) where ctx5.Rip = SystemFunction032 (decrypt)
 * Timer 6: SetEvent(resumeEvent)
 *
 * Each NtContinue call uses a CONTEXT with a controlled RSP,
 * so ALL stack frames at every stage appear legitimate.
 *
 * See: sleep-obfuscation.md for the full timer chain analysis.
 */
```

## Detection Indicators

### Stack Frame Validation

Detect stack spoofing by validating stack frame integrity:

1. **Return address verification**: For each return address, check that the instruction
   at `[return_addr - 5]` is a CALL instruction (E8 xx xx xx xx) whose target matches
   the function in the next frame. Spoofed return addresses often fail this check.

2. **ROP gadget detection**: Scan return addresses for known gadget patterns (JMP reg,
   CALL reg, RET). Legitimate return addresses point into function bodies, not gadgets.

3. **Stack bounds validation**: Compare RSP against the thread's stack limits
   (TEB.StackBase / TEB.StackLimit). If RSP is outside these bounds, the stack
   has been swapped.

4. **Frame size consistency**: Each function's stack frame size should match its
   prologue (SUB RSP, N). Spoofed frames may have inconsistent sizes.

### Detection Matrix

| Spoofing Method | Detection Technique | Confidence |
|----------------|-------------------|------------|
| Synthetic frames | CALL instruction verification at return_addr-5 | High |
| JMP RBX gadgets | Gadget scanning at return addresses | Very High |
| NtContinue context swap | RSP outside TEB stack bounds | High |
| Timer + NtContinue | Timer callback = NtContinue address | Very High |
| Foliage sleep spoofing | Periodic NtContinue from timer context | High |

### Timing Anomalies

Stack construction takes measurable time. If a function call is preceded by
unusual stack manipulation (many writes to sequential stack addresses), this
timing signature can be detected through performance counters or ETW events.

### Tools for Detection

```
Hunt-Sleeping-Beacons: Scans sleeping threads for unbacked return addresses
Moneta:               Detects anomalous memory regions and call stacks
BeaconEye:            Pattern-matches Cobalt Strike beacon structures
pe-sieve:             Scans for injected/hollowed code
Volatility:           Memory forensics call stack reconstruction

Custom Detection:
- Walk all thread stacks using StackWalk64 API
- For each return address, query VirtualQuery to check if it is
  IMAGE_MEM (backed by a loaded module) or PRIVATE (suspicious)
- Flag threads with PRIVATE return addresses in their call stacks
```

## Cross-References

- [Sleep Obfuscation](sleep-obfuscation.md) - Ekko/Foliage use stack spoofing during sleep
- [Callback Injection](callback-injection.md) - callbacks produce anomalous stacks that spoofing addresses
- [ETW Patching](etw-patching.md) - ETW provides telemetry for NtContinue monitoring
- [PE Loader](pe-loader.md) - reflective loaded code produces unbacked stack frames
- [AV/EDR Evasion Theory](../../06-defense-evasion/av-edr-evasion.md)
- [Direct Syscalls](../syscalls-and-evasion/direct-syscalls.md)

## References

- MITRE ATT&CK T1055
- Mariusz Banach: ThreadStackSpoofer (original research)
- Kyle Avery: SpoofStack / ReturnAddressSpoofer
- C5pider: Ekko Sleep Obfuscation (timer + context chain)
- Austin Hudson: Foliage (NtContinue-based sleep with stack spoofing)
- Joe Desimone: Hunt-Sleeping-Beacons (detection tooling)
- Elastic Security: Detecting Stack Spoofing Techniques

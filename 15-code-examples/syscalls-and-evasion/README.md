# Syscalls & EDR Evasion: Security Knowledge Base

> **AUTHORIZED USE ONLY**: The techniques documented here are for educational purposes
> and authorized security engagements only. Unauthorized use of these techniques against
> systems you do not own or have written permission to test is illegal and unethical.
> This material is intended for red team professionals conducting sanctioned assessments
> and blue team engineers building detection capabilities.

## Why Syscalls Matter in Security

Windows applications interact with the kernel through **system calls** (syscalls). The
standard flow routes every API call through a well-defined chain:

```
Application -> kernel32.dll -> ntdll.dll -> kernel (via syscall instruction)
```

Security products (EDRs, AVs) insert **hooks** into this chain -- typically at the
ntdll.dll layer -- to inspect every call before it reaches the kernel. This is the
foundation of userland monitoring.

The offensive-defensive dynamic around syscalls represents one of the most active areas
of security research:

- **Attackers** seek to bypass these hooks to avoid detection.
- **Defenders** develop layered telemetry to detect bypass attempts themselves.

Understanding both sides is essential for any security professional.

## Evolution of Syscall Techniques

The progression of techniques follows a clear cat-and-mouse pattern, where each
offensive advance is met with a corresponding defensive improvement.

### Timeline

| Era       | Technique             | Concept                                  | Key Research              |
|-----------|-----------------------|------------------------------------------|---------------------------|
| Early     | Direct Syscalls       | Hardcode SSN, execute `syscall` in-process | SysWhispers (2019)       |
| 2020      | Hell's Gate           | Parse ntdll at runtime to extract SSN    | am0nsec & smelly__vx     |
| 2021      | Halo's Gate           | Neighbor-stub scanning to bypass hooks   | Sektor7                  |
| 2021      | Tartarus Gate         | Handle partial hooks / trampolines       | trickster0               |
| 2022+     | Indirect Syscalls     | Execute `syscall` instruction from ntdll | SysWhispers3, KlezVirus  |
| Ongoing   | NTDLL Unhooking       | Replace hooked ntdll .text with clean copy | Various researchers     |
| Ongoing   | API Hashing           | Resolve APIs by hash to avoid string signatures | Classic tradecraft  |

### Comparison: Technique vs. Detection Approach

| Technique           | How It Works                          | Primary Detection Method                        |
|---------------------|---------------------------------------|-------------------------------------------------|
| Direct Syscalls     | App executes `syscall` instruction    | Stack trace: return addr outside ntdll          |
| Hell's Gate         | Parse ntdll EAT for SSNs at runtime  | Fails if target stub is hooked; memory scanning |
| Halo's Gate         | Scan neighbor stubs for SSNs          | Behavioral analysis; hook integrity monitoring   |
| Tartarus Gate       | Handle partial hooks via deeper scan  | Same as Halo's Gate plus trampoline detection    |
| Indirect Syscalls   | JMP to `syscall;ret` inside ntdll     | Advanced stack analysis; ETW kernel telemetry    |
| NTDLL Unhooking     | Overwrite .text section with clean copy| .text integrity monitoring; unhooking detection |
| API Hashing         | Resolve APIs by hash, no strings      | Hash constant signatures; PEB access patterns    |

## Defense-in-Depth: The Blue Team Perspective

No single detection covers all techniques. Effective defense requires layered telemetry:

1. **Userland Hooks** -- First line of defense; catches unsophisticated threats.
2. **ETW Threat Intelligence Provider** -- Kernel-level telemetry that cannot be
   bypassed from userland; reports suspicious memory operations.
3. **Kernel Callbacks** -- Process/thread/image-load notifications from kernel drivers.
4. **Stack Trace Analysis** -- Validating that syscall return addresses originate from
   expected modules (ntdll.dll).
5. **Memory Integrity Monitoring** -- Detecting modifications to .text sections of
   loaded DLLs.
6. **Behavioral Analytics** -- Correlating sequences of actions (e.g., allocate +
   write + protect + create thread) regardless of how syscalls are invoked.

## File Index

| File                      | Topic                                        |
|---------------------------|----------------------------------------------|
| `direct-syscalls.md`      | Direct syscall invocation and SSN structure   |
| `hells-gate.md`           | Runtime SSN resolution via EAT parsing        |
| `halos-gate.md`           | Neighbor-stub scanning for hooked functions   |
| `indirect-syscalls.md`    | Executing syscall from within ntdll memory    |
| `ntdll-unhooking.md`      | Restoring clean ntdll .text section           |
| `api-hashing.md`          | Hash-based API resolution and PEB walking     |

## How EDR Hooks Work (Brief Overview)

When an EDR product loads into a process, it typically:

1. **Injects a DLL** via various mechanisms (AppInit_DLLs, process creation callbacks, etc.).
2. **Patches ntdll function prologues** by replacing the first bytes of target functions
   with a JMP instruction to the EDR's inspection routine.
3. **Inspects arguments** -- the EDR examines the function parameters (which process,
   what memory protections, etc.) and makes an allow/block decision.
4. **Restores flow** -- if allowed, the EDR executes the original instructions (saved
   in a trampoline) and the call proceeds normally.

```
Before hooking (clean ntdll stub):
  4C 8B D1           mov r10, rcx
  B8 18 00 00 00     mov eax, 0x18
  ...

After hooking (EDR-patched stub):
  E9 XX XX XX XX     jmp EDR_inspection_routine    <-- hook
  00 00 00           (remaining original bytes overwritten)
  ...
```

This is why all the techniques in this knowledge base focus on either:
- **Avoiding the hook** (direct/indirect syscalls) -- never call the hooked function.
- **Removing the hook** (unhooking) -- restore the original bytes.
- **Working around the hook** (Gate techniques) -- read SSN from unhooked neighbors.

## MITRE ATT&CK Mapping

These techniques map to the following ATT&CK categories:

| Technique          | MITRE ID    | Tactic            |
|--------------------|-------------|-------------------|
| Direct Syscalls    | T1106       | Defense Evasion   |
| API Hashing        | T1027.007   | Defense Evasion   |
| NTDLL Unhooking    | T1562.001   | Defense Evasion   |
| Process Injection  | T1055       | Defense Evasion   |

Understanding these mappings helps blue teams build detection coverage aligned to
the ATT&CK framework.

## Recommended Reading

- Windows Internals, Part 1 & 2 (Yosifovich, Russinovich, Solomon, Ionescu)
- "A Syscall Journey in the Windows Kernel" -- mdsec.co.uk
- "EDR Internals" series -- various security researchers
- MITRE ATT&CK: Defense Evasion (TA0005)
- "Blinding EDR On Windows" -- @_batsec_
- "Silencing the EDR" -- various conference presentations

## Ethical Framework

Red team professionals operate under strict rules of engagement. Every technique
documented here should only be used:

- With explicit written authorization (scope document / ROE)
- Within the defined scope of an engagement
- With proper safeguards to avoid impacting production systems
- With full documentation for the client's defensive improvement

The ultimate goal of red teaming is to **improve the organization's security posture**,
not to demonstrate that attacks are possible.

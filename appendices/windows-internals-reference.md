# Windows Internals Reference for Red Team Operators

> Understanding Windows internals is essential for developing reliable exploits,
> evading security controls, and operating at a level beyond tool-running.
> This reference covers the structures and mechanisms most relevant to offensive operations.

---

## Access Tokens

An access token is the kernel object that defines the security context of a process or thread.
Every process has a **primary token**; threads can have **impersonation tokens**.

### Token Structure (Key Fields)

```
TOKEN
  +0x000 TokenId                 # Unique identifier
  +0x008 AuthenticationId (LUID) # Logon session this token belongs to
  +0x010 ParentTokenId           # Token this was derived from
  +0x040 User (SID)              # Primary SID of the token owner
  +0x048 Groups                  # Array of SID_AND_ATTRIBUTES (group memberships)
  +0x050 Privileges              # Array of LUID_AND_ATTRIBUTES (assigned privileges)
  +0x080 IntegrityLevel          # Mandatory integrity level SID
  +0x0A0 TokenType               # TokenPrimary (1) or TokenImpersonation (2)
  +0x0A8 ImpersonationLevel      # SecurityAnonymous/Identification/Impersonation/Delegation
```

### Token Types and Impersonation Levels

| Type | Level | Can Enumerate Local? | Can Access Network? | Can Create Processes? |
|---|---|---|---|---|
| Primary | N/A | Yes | Yes | Yes |
| Impersonation | SecurityAnonymous | No | No | No |
| Impersonation | SecurityIdentification | Yes (query only) | No | No |
| Impersonation | SecurityImpersonation | Yes | No | No |
| Impersonation | SecurityDelegation | Yes | Yes | Yes |

### Token Manipulation APIs

```c
// Duplicate a token (elevation or impersonation attacks)
DuplicateTokenEx(hExistingToken, MAXIMUM_ALLOWED, NULL,
                 SecurityDelegation, TokenPrimary, &hNewToken);

// Impersonate a logged-on user
ImpersonateLoggedOnUser(hToken);

// Create a process with a stolen token
CreateProcessWithTokenW(hToken, LOGON_WITH_PROFILE, NULL,
                        L"cmd.exe", CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

// Create process as a user (requires password)
CreateProcessWithLogonW(L"admin", L"DOMAIN", L"password",
                        LOGON_WITH_PROFILE, NULL, L"cmd.exe", 0, NULL, NULL, &si, &pi);
```

### Key Privileges for Offensive Operations

| Privilege | Abuse Potential |
|---|---|
| SeImpersonatePrivilege | Potato attacks (SYSTEM via token impersonation) |
| SeAssignPrimaryTokenPrivilege | Create processes with arbitrary tokens |
| SeDebugPrivilege | Open any process (LSASS access) |
| SeBackupPrivilege | Read any file (bypass ACLs) |
| SeRestorePrivilege | Write any file, modify registry |
| SeTakeOwnershipPrivilege | Take ownership of any securable object |
| SeLoadDriverPrivilege | Load kernel drivers (kernel-mode code execution) |
| SeTcbPrivilege | Act as part of the OS (most powerful privilege) |
| SeCreateTokenPrivilege | Create arbitrary tokens |
| SeMachineAccountPrivilege | Add computer accounts to domain |

---

## Security Identifiers (SIDs)

### SID Structure

```
S-1-5-21-3623811015-3361044348-30300820-1013
| | |  |          |            |         |
| | |  |          |            |         +-- RID (Relative Identifier)
| | |  +----------+------------+----------- Sub-Authority values (Domain ID)
| | +-- Identifier Authority (5 = NT Authority)
| +-- Revision (always 1)
+-- SID prefix
```

### Well-Known SIDs

| SID | Name | Red Team Relevance |
|---|---|---|
| S-1-0-0 | Nobody | Null session identity |
| S-1-1-0 | Everyone | Universal group |
| S-1-5-7 | Anonymous | Anonymous logon |
| S-1-5-11 | Authenticated Users | Any domain-authenticated user |
| S-1-5-18 | SYSTEM (LocalSystem) | Highest local privilege |
| S-1-5-19 | Local Service | Limited service account |
| S-1-5-20 | Network Service | Limited, has network identity |
| S-1-5-21-...-500 | Administrator | Built-in admin (RID 500) |
| S-1-5-21-...-502 | krbtgt | Key Distribution Center service |
| S-1-5-21-...-512 | Domain Admins | DA group |
| S-1-5-21-...-513 | Domain Users | Default user group |
| S-1-5-21-...-515 | Domain Computers | Default computer group |
| S-1-5-21-...-516 | Domain Controllers | DC computer group |
| S-1-5-21-...-519 | Enterprise Admins | Forest-level admin |
| S-1-5-21-...-520 | Group Policy Creator Owners | Can create GPOs |
| S-1-5-21-...-526 | Key Admins | PKINIT key trust |
| S-1-5-21-...-527 | Enterprise Key Admins | Forest PKINIT |
| S-1-5-32-544 | BUILTIN\Administrators | Local admin group |
| S-1-5-32-555 | BUILTIN\Remote Desktop Users | RDP access |

### SID History Abuse

SID History is a legitimate migration feature that attackers exploit for cross-trust
privilege escalation. If SID filtering is disabled on a trust, a user with SID History
containing a DA SID from the parent domain gains DA access to the parent.

```powershell
# Check for SID History on users
Get-ADUser -Filter {SIDHistory -like "*"} -Properties SIDHistory | Select-Object Name, SIDHistory

# Inject SID History (requires DA on child domain)
# Mimikatz: misc::addsid <user> <target_SID>
```

---

## Process Integrity Levels

Windows implements Mandatory Integrity Control (MIC) with four primary levels:

| Level | SID | Value | Typical Process |
|---|---|---|---|
| Untrusted | S-1-16-0 | 0x0000 | Sandboxed/restricted |
| Low | S-1-16-4096 | 0x1000 | Browser tabs, Protected Mode IE |
| Medium | S-1-16-8192 | 0x2000 | Standard user processes |
| High | S-1-16-12288 | 0x3000 | Elevated (Run as Administrator) |
| System | S-1-16-16384 | 0x4000 | SYSTEM services |

**Key rule**: A process cannot write to objects with a higher integrity level (no write up).
This is why UAC exists -- standard user processes run at Medium, admin operations need High.

---

## Authentication Architecture

### LSASS (Local Security Authority Subsystem Service)

```
lsass.exe -- the central authentication broker
  |
  +-- Security Support Providers (SSPs) -- loaded as DLLs
  |     +-- msv1_0.dll    (NTLM authentication)
  |     +-- kerberos.dll  (Kerberos authentication)
  |     +-- wdigest.dll   (WDigest -- cleartext in memory if enabled)
  |     +-- tspkg.dll     (Terminal Services SSP)
  |     +-- credman.dll   (Credential Manager)
  |     +-- cloudAP.dll   (Azure AD / cloud authentication)
  |     +-- pku2u.dll     (PKU2U -- peer-to-peer authentication)
  |
  +-- Credential storage in memory
        +-- NTLM hashes (always present)
        +-- Kerberos tickets (TGT, service tickets)
        +-- WDigest passwords (plaintext if UseLogonCredential=1)
        +-- DPAPI master keys
        +-- Cached domain credentials (mscashv2)
```

### Credential Guard

Credential Guard uses Virtual Secure Mode (VSM) to isolate credentials in a separate
virtual trust level (VTL 1) that even the NT kernel (VTL 0) cannot access.

```
VTL 1 (Secure World)          VTL 0 (Normal World)
+------------------+          +------------------+
| LSAIso.exe       |          | lsass.exe        |
| (Isolated LSA)   |          | (Standard LSA)   |
| - NTLM hashes    |          | - Proxy calls    |
| - Kerberos keys  |          |   to LSAIso      |
| - DPAPI keys     |          |                  |
+------------------+          +------------------+
        ^                              |
        |  Secure RPC calls            |
        +------------------------------+
```

**Impact on Red Team**: With Credential Guard, Mimikatz cannot extract NTLM hashes or
Kerberos tickets from LSASS memory. Workarounds include DCSync (network-based, not
memory-based) and extracting cached credentials that are NOT protected by CG.

---

## Processes and Threads

### Process Creation Flow

```
1. User calls CreateProcess()
2. Kernel: NtCreateUserProcess()
3. Image file mapped into new address space
4. PEB (Process Environment Block) created
5. Initial thread created with TEB (Thread Environment Block)
6. DLL load notifications sent (ntdll!LdrInitializeThunk)
7. DLLs loaded: ntdll.dll -> kernel32.dll -> user DLLs
8. Entry point called (main/WinMain)
```

### PEB (Process Environment Block) -- Key Fields

```
PEB (user-mode, accessible to the process)
  +0x002 BeingDebugged         # IsDebuggerPresent() reads this
  +0x00C Ldr                   # PEB_LDR_DATA -- loaded module list
  +0x020 ProcessParameters     # Command line, environment, working directory
  +0x068 NtGlobalFlag          # Debugging flags
  +0x0BC SessionId             # Terminal Services session
```

**Red Team Use**: Overwrite PEB->ProcessParameters to spoof command line arguments
(visible in Process Explorer, Event ID 4688). Access PEB->Ldr to walk loaded modules
for manual syscall resolution.

### Protected Processes (PP/PPL)

| Protection Level | Signer | Example |
|---|---|---|
| PsProtectedSignerNone | None | Standard process |
| PsProtectedSignerAuthenticode | Authenticode | Third-party AV |
| PsProtectedSignerWindows | Microsoft | csrss.exe, services.exe |
| PsProtectedSignerWinTcb | Windows TCB | smss.exe, lsass.exe (when PPL enabled) |
| PsProtectedSignerAntimalware | ELAM | Windows Defender, EDR |

**Red Team Impact**: PPL-protected LSASS prevents direct OpenProcess() with
PROCESS_VM_READ. Bypass methods: load a vulnerable signed driver to strip PPL flag,
or use alternative credential extraction methods (DCSync, SAM/SECURITY registry hives).

---

## Services and Drivers

### Service Control Manager (SCM)

Services are managed by services.exe via the SCM database in the registry:
`HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`

| Registry Value | Meaning | Red Team Relevance |
|---|---|---|
| ImagePath | Binary path | Point to payload |
| Start | 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled | 2=persistence |
| Type | 0x10=Own process, 0x20=Share process, 0x1=Kernel driver | Driver loading |
| ObjectName | Account to run as | LocalSystem for max privilege |

### Kernel Driver Signing

Windows enforces driver signature requirements (DSE - Driver Signature Enforcement):

- **Test Signing**: `bcdedit /set testsigning on` (requires reboot, leaves watermark)
- **Vulnerable Driver**: Load a legitimately signed but vulnerable driver (BYOVD)
  - Examples: RTCore64.sys, dbutil_2_3.sys, gdrv.sys, ene.sys
- **Cert Theft**: Steal a code-signing certificate to sign a custom driver
- **Boot-time**: Load before DSE is enforced (bootkit territory)

### EDR Architecture (Minifilter Drivers)

```
User Mode:    EDR Agent Process
                    |
                    | DeviceIoControl / FilterConnectCommunicationPort
                    |
Kernel Mode:  Minifilter Driver (.sys)
                    |
              Filter Manager (fltmgr.sys)
                    |
              File System Driver (ntfs.sys)
                    |
              Storage Driver Stack
```

EDR minifilters register callbacks for:
- Process creation/termination (PsSetCreateProcessNotifyRoutineEx)
- Thread creation (PsSetCreateThreadNotifyRoutine)
- Image load (PsSetLoadImageNotifyRoutine)
- Registry operations (CmRegisterCallbackEx)
- Object access (ObRegisterCallbacks -- protects LSASS handles)
- Minifilter file I/O callbacks (pre/post operation)

**Red Team Relevance**: Understanding these callbacks helps operators know which actions
trigger EDR detection and design evasion strategies (direct syscalls bypass user-mode
hooks but not kernel callbacks; BYOVD can remove kernel callbacks).

---

## Handle and Object System

### Common Object Types and Access Rights

| Object Type | Key Access Rights | Red Team Use |
|---|---|---|
| Process | PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD | LSASS dump, injection |
| Thread | THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME | APC injection |
| Token | TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_ASSIGN_PRIMARY | Token theft |
| File | FILE_READ_DATA, FILE_WRITE_DATA, DELETE | Data access |
| Registry Key | KEY_SET_VALUE, KEY_CREATE_SUB_KEY | Persistence |
| Service | SERVICE_CHANGE_CONFIG, SERVICE_START | Privilege escalation |
| Section | SECTION_MAP_WRITE, SECTION_MAP_EXECUTE | Shared memory injection |

### Access Check Flow

```
Thread requests access to object
  -> SeAccessCheck()
    -> Read Security Descriptor of target object
    -> Check owner SID (owner always has READ_CONTROL + WRITE_DAC)
    -> Walk DACL entries in order:
       1. Explicit Deny ACEs evaluated first
       2. Explicit Allow ACEs evaluated next
       3. Inherited Deny ACEs
       4. Inherited Allow ACEs
    -> Check mandatory integrity label (no write up, no read up if set)
    -> Grant or deny requested access mask
```

---

## Quick Reference: Registry Locations for Red Team

```
Persistence:
  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon (Userinit, Shell)
  HKLM\SYSTEM\CurrentControlSet\Services\<name>

Credentials:
  HKLM\SAM\SAM\Domains\Account\Users  (local password hashes)
  HKLM\SECURITY\Cache                  (cached domain credentials)
  HKLM\SECURITY\Policy\Secrets         (LSA secrets -- service account passwords)

Security Configuration:
  HKLM\SYSTEM\CurrentControlSet\Control\Lsa  (RunAsPPL, LmCompatibilityLevel)
  HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest (UseLogonCredential)
  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System (UAC settings)
```

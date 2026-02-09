# Token Manipulation - Educational Analysis

> **MITRE ATT&CK**: T1134 - Access Token Manipulation
> **Purpose**: Understanding Windows token architecture for security analysis
> **Languages**: C, Python
> **Detection Focus**: Event ID 4672, handle operations, privilege escalation patterns

## Strategic Overview

Windows access tokens are kernel objects that define a security context - who you are, what groups you belong to, and what privileges you have. Understanding token architecture is fundamental to:

- Detecting privilege escalation via token impersonation
- Analyzing lateral movement that uses token theft
- Understanding potato-style attacks (SeImpersonate abuse)
- Building detection rules for token manipulation events

### Why This Matters for Red Team Leads
- Token manipulation is the basis for most Windows privilege escalation
- Understanding tokens informs decisions about post-exploitation tradecraft
- SeImpersonatePrivilege → SYSTEM is a critical attack path

## Technical Deep-Dive

### Windows Token Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Windows Token Types                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Primary Token:                                             │
│  ├─ One per process                                         │
│  ├─ Defines process security context                        │
│  ├─ Created at logon, inherited by child processes          │
│  └─ Contains: SID, Groups, Privileges, Integrity Level     │
│                                                             │
│  Impersonation Token:                                       │
│  ├─ Per-thread (temporarily assumes another identity)       │
│  ├─ Created via: LogonUser, DuplicateToken, SSPI            │
│  ├─ Impersonation Levels:                                   │
│  │   ├─ Anonymous:       No identification info             │
│  │   ├─ Identification:  Identify but not impersonate       │
│  │   ├─ Impersonation:   Local impersonation               │
│  │   └─ Delegation:      Network impersonation (Kerberos)   │
│  └─ Used by services to act on behalf of clients           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Token Enumeration

```c
/*
 * Educational: Enumerating access token information.
 *
 * Understanding token contents is essential for:
 * 1. Analyzing what privileges a compromised account has
 * 2. Identifying token impersonation opportunities
 * 3. Building detection for privilege abuse
 *
 * BUILD: cl.exe /nologo /W3 token_enum.c /link advapi32.lib
 */
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

/*
 * Display current token privileges.
 *
 * Key Privileges for Attackers:
 * ────────────────────────────────────────────────────
 * SeDebugPrivilege         → Access any process (LSASS dumping)
 * SeImpersonatePrivilege   → Impersonate tokens (potato attacks)
 * SeAssignPrimaryToken     → Assign process tokens
 * SeBackupPrivilege        → Read any file (bypass ACLs)
 * SeRestorePrivilege       → Write any file (bypass ACLs)
 * SeTakeOwnershipPrivilege → Take ownership of objects
 * SeLoadDriverPrivilege    → Load kernel drivers (BYOVD)
 * SeTcbPrivilege           → Act as part of the OS
 * SeCreateTokenPrivilege   → Create new tokens
 * ────────────────────────────────────────────────────
 *
 * Detection:
 * Event ID 4672: "Special privileges assigned to new logon"
 * This fires when a user logs in with any of these privileges.
 */
void enumerate_token_privileges(HANDLE hToken) {
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);

    TOKEN_PRIVILEGES *pPrivs = (TOKEN_PRIVILEGES *)malloc(dwSize);
    if (!pPrivs) return;

    if (GetTokenInformation(hToken, TokenPrivileges, pPrivs, dwSize, &dwSize)) {
        printf("=== Token Privileges (%lu total) ===\n", pPrivs->PrivilegeCount);

        for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) {
            char privName[256];
            DWORD nameLen = sizeof(privName);

            LookupPrivilegeNameA(NULL, &pPrivs->Privileges[i].Luid,
                                privName, &nameLen);

            DWORD attrs = pPrivs->Privileges[i].Attributes;
            const char *state;
            if (attrs & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
                state = "Enabled (Default)";
            else if (attrs & SE_PRIVILEGE_ENABLED)
                state = "Enabled";
            else if (attrs & SE_PRIVILEGE_REMOVED)
                state = "Removed";
            else
                state = "Disabled";

            /* Flag security-critical privileges */
            BOOL critical = (
                strcmp(privName, "SeDebugPrivilege") == 0 ||
                strcmp(privName, "SeImpersonatePrivilege") == 0 ||
                strcmp(privName, "SeBackupPrivilege") == 0 ||
                strcmp(privName, "SeRestorePrivilege") == 0 ||
                strcmp(privName, "SeTakeOwnershipPrivilege") == 0 ||
                strcmp(privName, "SeLoadDriverPrivilege") == 0 ||
                strcmp(privName, "SeTcbPrivilege") == 0
            );

            printf("  %-40s %s%s\n", privName, state,
                   critical ? " [!CRITICAL]" : "");
        }
    }

    free(pPrivs);
}

/*
 * Display token user and groups.
 *
 * Detection Use: Understanding group memberships helps
 * identify escalation paths:
 * - BUILTIN\Administrators → already privileged
 * - Domain Admins → domain compromise
 * - Backup Operators → SeBackupPrivilege
 * - Server Operators → service control
 */
void enumerate_token_groups(HANDLE hToken) {
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize);

    TOKEN_GROUPS *pGroups = (TOKEN_GROUPS *)malloc(dwSize);
    if (!pGroups) return;

    if (GetTokenInformation(hToken, TokenGroups, pGroups, dwSize, &dwSize)) {
        printf("\n=== Token Groups (%lu total) ===\n", pGroups->GroupCount);

        for (DWORD i = 0; i < pGroups->GroupCount; i++) {
            char name[256], domain[256];
            DWORD nameLen = sizeof(name), domainLen = sizeof(domain);
            SID_NAME_USE sidType;

            if (LookupAccountSidA(NULL, pGroups->Groups[i].Sid,
                                  name, &nameLen, domain, &domainLen, &sidType)) {
                DWORD attrs = pGroups->Groups[i].Attributes;
                printf("  %s\\%s", domain, name);

                if (attrs & SE_GROUP_ENABLED) printf(" [Enabled]");
                if (attrs & SE_GROUP_OWNER) printf(" [Owner]");
                if (attrs & SE_GROUP_USE_FOR_DENY_ONLY) printf(" [DenyOnly]");
                if (attrs & SE_GROUP_INTEGRITY) printf(" [Integrity]");
                printf("\n");
            }
        }
    }

    free(pGroups);
}

/*
 * Display token integrity level.
 *
 * Integrity Levels:
 * - Untrusted (0x0000)
 * - Low       (0x1000) - Internet Explorer protected mode
 * - Medium    (0x2000) - Standard user
 * - High      (0x3000) - Elevated administrator
 * - System    (0x4000) - SYSTEM services
 *
 * UAC creates two tokens for admins:
 * - Medium integrity (filtered, no admin privs)
 * - High integrity (full, used after UAC prompt)
 */
void display_integrity_level(HANDLE hToken) {
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);

    TOKEN_MANDATORY_LABEL *pLabel = (TOKEN_MANDATORY_LABEL *)malloc(dwSize);
    if (!pLabel) return;

    if (GetTokenInformation(hToken, TokenIntegrityLevel, pLabel, dwSize, &dwSize)) {
        DWORD intLevel = *GetSidSubAuthority(pLabel->Label.Sid,
                          *GetSidSubAuthorityCount(pLabel->Label.Sid) - 1);

        printf("\n=== Token Integrity Level ===\n");
        printf("  Level: 0x%04lX - ", intLevel);
        if (intLevel >= SECURITY_MANDATORY_SYSTEM_RID)
            printf("SYSTEM\n");
        else if (intLevel >= SECURITY_MANDATORY_HIGH_RID)
            printf("HIGH (Elevated)\n");
        else if (intLevel >= SECURITY_MANDATORY_MEDIUM_RID)
            printf("MEDIUM (Standard User)\n");
        else if (intLevel >= SECURITY_MANDATORY_LOW_RID)
            printf("LOW\n");
        else
            printf("UNTRUSTED\n");
    }

    free(pLabel);
}

/* Main: Enumerate current process token */
int main(void) {
    HANDLE hToken;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken failed: %lu\n", GetLastError());
        return 1;
    }

    enumerate_token_privileges(hToken);
    enumerate_token_groups(hToken);
    display_integrity_level(hToken);

    CloseHandle(hToken);
    return 0;
}
```

### Token Privilege Adjustment

```c
/*
 * Educational: Enabling token privileges.
 *
 * Some privileges exist in the token but are disabled by default.
 * AdjustTokenPrivileges enables them.
 *
 * Example: SeDebugPrivilege is present for Administrators
 * but disabled. Enabling it allows OpenProcess on any process.
 *
 * Detection:
 * - AdjustTokenPrivileges API call
 * - Event ID 4703: "A user right was adjusted"
 * - Enabling SeDebugPrivilege is a high-fidelity alert
 */
BOOL enable_privilege(HANDLE hToken, LPCSTR privilegeName) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueA(NULL, privilegeName, &luid)) {
        printf("LookupPrivilegeValue failed: %lu\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    /*
     * AdjustTokenPrivileges
     *
     * Detection Events:
     * - Security Event 4703: Token privilege adjusted
     * - ETW: Microsoft-Windows-Security-Auditing
     * - EDR: API hook on NtAdjustPrivilegesToken
     */
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        printf("AdjustTokenPrivileges failed: %lu\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("Privilege '%s' not available in token\n", privilegeName);
        return FALSE;
    }

    printf("Privilege '%s' enabled successfully\n", privilegeName);
    return TRUE;
}
```

### Token Impersonation Concepts

```c
/*
 * Educational: Token impersonation flow.
 *
 * Token impersonation allows a thread to temporarily operate
 * under a different security context. This is the basis for:
 * - Potato attacks (SeImpersonate abuse)
 * - Token theft from other processes
 * - Service account impersonation
 *
 * FLOW:
 * 1. OpenProcess(target_pid) - get handle to target process
 * 2. OpenProcessToken(handle) - get target's token
 * 3. DuplicateTokenEx() - create impersonation token
 * 4. ImpersonateLoggedOnUser() or SetThreadToken() - impersonate
 * 5. Perform actions as the impersonated user
 * 6. RevertToSelf() - revert to original identity
 *
 * REQUIREMENTS:
 * - SeImpersonatePrivilege (for impersonation)
 * - SeDebugPrivilege (for opening other processes' tokens)
 * - Or: PROCESS_QUERY_INFORMATION access to target
 *
 * Detection:
 * - Event 4672: Special privileges at logon
 * - Event 4624: Logon event (Type 9 = NewCredentials)
 * - Sysmon Event 10: Process access (to get token)
 * - Handle operations on process tokens
 */

/*
 * Token Duplication (Educational)
 *
 * DuplicateTokenEx creates a new token that can be used
 * for impersonation or to create a process.
 */
void explain_token_duplication(void) {
    printf("=== Token Duplication Flow ===\n\n");

    printf("1. Get handle to target process:\n");
    printf("   HANDLE hProc = OpenProcess(\n");
    printf("       PROCESS_QUERY_INFORMATION,\n");
    printf("       FALSE, target_pid);\n\n");

    printf("2. Get target's token:\n");
    printf("   HANDLE hToken;\n");
    printf("   OpenProcessToken(hProc,\n");
    printf("       TOKEN_DUPLICATE | TOKEN_QUERY,\n");
    printf("       &hToken);\n\n");

    printf("3. Duplicate as impersonation token:\n");
    printf("   HANDLE hDupToken;\n");
    printf("   DuplicateTokenEx(hToken,\n");
    printf("       TOKEN_ALL_ACCESS,\n");
    printf("       NULL,\n");
    printf("       SecurityImpersonation,  // Level\n");
    printf("       TokenImpersonation,     // Type\n");
    printf("       &hDupToken);\n\n");

    printf("4. Impersonate:\n");
    printf("   ImpersonateLoggedOnUser(hDupToken);\n");
    printf("   // Thread now runs as target user\n\n");

    printf("5. Perform actions as impersonated user\n\n");

    printf("6. Revert:\n");
    printf("   RevertToSelf();\n");
}

/*
 * Potato Attacks Overview
 *
 * "Potato" attacks exploit SeImpersonatePrivilege to escalate
 * from service accounts to SYSTEM. They work by:
 *
 * 1. Coercing a SYSTEM-level service to authenticate
 * 2. Capturing the SYSTEM token from the authentication
 * 3. Using SeImpersonatePrivilege to impersonate SYSTEM
 *
 * Variants:
 * - Hot Potato:    NBNS + WPAD poisoning → SYSTEM
 * - Rotten Potato: DCOM + NTLM local relay → SYSTEM
 * - Juicy Potato:  DCOM CLSID abuse → SYSTEM
 * - Sweet Potato:  Combined techniques → SYSTEM
 * - Print Spoofer: Print service coercion → SYSTEM
 * - God Potato:    Latest variant, works on Server 2022
 *
 * Detection:
 * - Token impersonation from service accounts
 * - SeImpersonatePrivilege usage by non-standard services
 * - Named pipe creation for token capture
 * - DCOM activation from service accounts
 */
```

### Python Token Enumeration

```python
"""
Educational: Token enumeration via Python ctypes.
Demonstrates how token information can be queried for
security analysis and incident response.
"""
import ctypes
import ctypes.wintypes
from ctypes import windll

# Constants
TOKEN_QUERY = 0x0008
TokenUser = 1
TokenGroups = 2
TokenPrivileges = 3
TokenIntegrityLevel = 25

def get_current_token_info():
    """
    Enumerate current process token for security analysis.

    Use this for:
    - Incident response: What privileges does this process have?
    - Forensics: What user is this process running as?
    - Hardening: Are unnecessary privileges present?
    """
    hToken = ctypes.wintypes.HANDLE()
    hProcess = windll.kernel32.GetCurrentProcess()

    if not windll.advapi32.OpenProcessToken(
        hProcess, TOKEN_QUERY, ctypes.byref(hToken)):
        print(f"OpenProcessToken failed: {windll.kernel32.GetLastError()}")
        return

    # Get token user (SID)
    dwSize = ctypes.wintypes.DWORD()
    windll.advapi32.GetTokenInformation(
        hToken, TokenUser, None, 0, ctypes.byref(dwSize))

    buffer = ctypes.create_string_buffer(dwSize.value)
    if windll.advapi32.GetTokenInformation(
        hToken, TokenUser, buffer, dwSize, ctypes.byref(dwSize)):

        # Extract SID and lookup account name
        sid_ptr = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))
        name = ctypes.create_string_buffer(256)
        domain = ctypes.create_string_buffer(256)
        name_len = ctypes.wintypes.DWORD(256)
        domain_len = ctypes.wintypes.DWORD(256)
        sid_type = ctypes.wintypes.DWORD()

        # Note: In production, properly parse TOKEN_USER structure
        print("Token enumeration complete")

    windll.kernel32.CloseHandle(hToken)

get_current_token_info()
```

## Detection & Evasion

### Detection Events

| Event Source | Event ID | Description |
|-------------|----------|-------------|
| Security | 4672 | Special privileges assigned to new logon |
| Security | 4624 | Logon (Type 9 = NewCredentials/impersonation) |
| Security | 4648 | Explicit credentials (runas, token theft) |
| Security | 4703 | Token privilege adjusted |
| Sysmon | 10 | Process access (token handle access) |
| Sysmon | 1 | Process create (token in new process) |

### Detection Rules

```
# Sigma: Detect SeDebugPrivilege usage
title: SeDebugPrivilege Enabled
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4703
        EnabledPrivilegeList|contains: 'SeDebugPrivilege'
    condition: selection
level: high

# Sigma: Token impersonation from unexpected process
title: Token Impersonation Detected
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10  # ProcessAccess
        GrantedAccess|contains:
            - '0x0040'  # PROCESS_DUP_HANDLE
            - '0x0400'  # PROCESS_QUERY_INFORMATION
    condition: selection
```

### Defensive Recommendations

1. **Least privilege**: Remove SeDebugPrivilege and SeImpersonatePrivilege from unnecessary accounts
2. **Protected Users**: Add privileged accounts to Protected Users group
3. **Credential Guard**: Prevents credential theft from LSASS
4. **Audit policies**: Enable token right adjustment auditing
5. **Sysmon**: Configure process access monitoring (Event 10)

## Cross-References

- [Windows Local Privilege Escalation](../../05-privilege-escalation/windows-local-privesc.md)
- [LSASS Dumping](../../07-credential-access/lsass-dumping.md)
- [Windows Internals Reference](../../appendices/windows-internals-reference.md)
- [MiniDump Implementation](minidump-implementation.md)

## References

- Microsoft: Access Token Documentation
- MITRE ATT&CK T1134 Documentation
- ired.team: Token Manipulation
- itm4n: PrintSpoofer Research
- GhostPack: Token Manipulation in Rubeus

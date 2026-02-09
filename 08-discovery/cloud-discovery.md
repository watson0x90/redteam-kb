# Cloud Resource Discovery

> **MITRE ATT&CK**: Discovery > T1580 - Cloud Infrastructure Discovery
> **Platforms**: AWS, Azure, GCP
> **Required Privileges**: Authenticated cloud user (any level)
> **OPSEC Risk**: Low-Medium (API calls are logged but often not monitored in real-time)

## Strategic Overview

Cloud discovery follows a different paradigm than on-premises enumeration. Every API call is logged (CloudTrail, Azure Activity Log, GCP Audit Log), but the sheer volume of legitimate API calls in most environments means that enumeration activity rarely triggers alerts unless specific detections are configured. The key advantage is that a single set of credentials or an assumed role often provides read access to far more resources than intended. Cloud misconfigurations -- overly permissive IAM policies, public storage buckets, exposed secrets in metadata -- are among the most reliable findings in modern red team engagements.

**Discovery priority**: Identity and access (who am I, what can I do) -> Compute (VMs, containers, serverless) -> Storage (S3, Blob, GCS) -> Databases -> Networking -> Secrets management.

## Technical Deep-Dive

### AWS Discovery

```bash
# Identity -- always start here
aws sts get-caller-identity                    # Who am I?
aws iam get-user                               # Current user details
aws iam list-attached-user-policies --user-name USERNAME
aws iam list-user-policies --user-name USERNAME

# IAM enumeration
aws iam list-users                             # All IAM users
aws iam list-roles                             # All IAM roles
aws iam list-groups                            # All IAM groups
aws iam list-policies --scope Local            # Custom policies (most interesting)
aws iam get-policy-version --policy-arn ARN --version-id v1   # Read policy details
aws iam get-account-authorization-details      # Full IAM dump (if permitted)

# Compute
aws ec2 describe-instances --query 'Reservations[].Instances[].{ID:InstanceId,IP:PrivateIpAddress,PubIP:PublicIpAddress,State:State.Name,Name:Tags[?Key==`Name`].Value|[0]}' --output table
aws ec2 describe-security-groups               # Firewall rules
aws lambda list-functions                      # Serverless functions
aws ecs list-clusters                          # Container clusters
aws eks list-clusters                          # Kubernetes clusters

# Storage
aws s3 ls                                      # List all buckets
aws s3 ls s3://bucket-name --recursive         # List bucket contents
aws s3api get-bucket-policy --bucket NAME      # Bucket policy
aws s3api get-bucket-acl --bucket NAME         # Bucket ACL

# Databases
aws rds describe-db-instances                  # RDS databases
aws dynamodb list-tables                       # DynamoDB tables
aws redshift describe-clusters                 # Redshift clusters

# Secrets and parameters
aws secretsmanager list-secrets                # Secrets Manager
aws ssm describe-parameters                    # SSM Parameter Store
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption  # Dump all parameters

# Network
aws ec2 describe-vpcs                          # VPCs
aws ec2 describe-subnets                       # Subnets
```

```bash
# Pacu -- AWS exploitation framework (modules: iam__enum_permissions, ec2__enum, s3__enum, lambda__enum)
pacu > import_keys PROFILE_NAME && run iam__enum_permissions

# enumerate-iam.py -- brute-force every API action (very noisy -- thousands of AccessDenied events)
python enumerate-iam.py --access-key AKIA... --secret-key SECRET
```

### Azure Discovery

```bash
# Azure CLI enumeration
az account list                                # Subscriptions
az account show                                # Current context
az ad user list --output table                 # AAD users
az ad group list --output table                # AAD groups
az ad app list --output table                  # App registrations
az ad sp list --all --output table             # Service principals

# Compute
az vm list --output table                      # Virtual machines
az webapp list --output table                  # App Services
az functionapp list --output table             # Function Apps
az aks list --output table                     # AKS clusters

# Storage
az storage account list --output table         # Storage accounts
az storage container list --account-name NAME  # Blob containers

# Databases
az sql server list --output table              # SQL servers
az cosmosdb list --output table                # CosmosDB

# Networking
az network vnet list --output table            # Virtual networks
az network nsg list --output table             # Network Security Groups
```

```bash
# ROADtools -- Azure AD enumeration (roadrecon auth -> gather -> gui for web UI analysis)
roadrecon auth -u user@corp.onmicrosoft.com -p 'Password1' && roadrecon gather

# AzureHound -- BloodHound for Azure
azurehound list -u user@corp.onmicrosoft.com -p 'Password1' --tenant TENANT_ID -o azurehound.json
```

### GCP Discovery

```bash
# Identity and project
gcloud auth list                               # Authenticated accounts
gcloud config list                             # Current configuration
gcloud projects list                           # All accessible projects
gcloud organizations list                      # Organization info

# IAM
gcloud iam service-accounts list               # Service accounts
gcloud projects get-iam-policy PROJECT_ID      # Project IAM bindings

# Compute
gcloud compute instances list                  # VMs
gcloud functions list                          # Cloud Functions
gcloud run services list                       # Cloud Run services
gcloud container clusters list                 # GKE clusters

# Storage
gsutil ls                                      # Cloud Storage buckets
gsutil ls gs://bucket-name                     # Bucket contents
gsutil iam get gs://bucket-name               # Bucket IAM

# Databases
gcloud sql instances list                      # Cloud SQL
gcloud firestore databases list                # Firestore

# Secrets
gcloud secrets list                            # Secret Manager
gcloud secrets versions access latest --secret=SECRET_NAME
```

### Multi-Cloud Automated Enumeration

```bash
# ScoutSuite -- multi-cloud security auditing
scout aws --profile default                    # AWS assessment
scout azure --cli                              # Azure assessment
scout gcp --project-id PROJECT                 # GCP assessment

# Prowler -- AWS/Azure/GCP security assessment
prowler aws                                    # AWS security checks
prowler azure                                  # Azure security checks

# CloudFox -- find exploitable attack paths
cloudfox aws all-checks --profile default      # AWS attack surface
cloudfox azure all-checks                      # Azure attack surface
```

## Detection & Evasion

| Activity | Log Source | Detection Approach |
|----------|-----------|-------------------|
| AWS API enumeration | CloudTrail | Unusual API call volume, AccessDenied spikes |
| Azure AD enumeration | Azure AD Sign-in/Audit Logs | Bulk directory reads, Graph API abuse |
| GCP API enumeration | Cloud Audit Logs | Admin Activity audit logs |
| IAM policy enumeration | CloudTrail/Activity Logs | GetPolicy, ListPolicies call patterns |
| enumerate-iam.py | CloudTrail | Massive AccessDenied event volume (very noisy) |

**Evasion strategies**: Space API calls over time, use read-only actions first (Describe/List/Get), avoid enumerate-iam.py in production (extremely noisy), leverage assumed roles, use cloud console GUI for browsing (blends with admin activity), and check for GuardDuty/Defender/SCC before aggressive enumeration.

## Cross-References

- [Cloud Exfiltration](../10-collection-and-exfiltration/cloud-exfiltration.md)
- [Initial Access - Cloud](../03-initial-access/)
- [Privilege Escalation - Cloud](../05-privilege-escalation/)
- [AD Enumeration](./ad-enumeration.md)

## References

- MITRE ATT&CK T1580: https://attack.mitre.org/techniques/T1580/
- Pacu: https://github.com/RhinoSecurityLabs/pacu
- ScoutSuite: https://github.com/nccgroup/ScoutSuite
- ROADtools: https://github.com/dirkjanm/ROADtools
- CloudFox: https://github.com/BishopFox/cloudfox
- Prowler: https://github.com/prowler-cloud/prowler

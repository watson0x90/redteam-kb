# GCP Attack Techniques

This subsection covers offensive techniques specific to Google Cloud Platform environments. GCP's IAM model, organization hierarchy, and service account architecture present unique attack patterns distinct from AWS and Azure.

---

**Navigation:**
| Parent | Section |
|--------|---------|
| [Cloud Security](../README.md) | **GCP Attack Techniques** |

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| GCP Initial Access | [gcp-initial-access.md](gcp-initial-access.md) | T1078.004 | Medium | Exposed service account keys, metadata server abuse, misconfigured Cloud Storage, and OAuth token theft |
| GCP Privilege Escalation | [gcp-privilege-escalation.md](gcp-privilege-escalation.md) | T1078.004 | Medium | IAM policy escalation, service account impersonation chains, and organization-level role abuse |
| GCP Persistence | [gcp-persistence.md](gcp-persistence.md) | T1098 | Medium-High | Service account key creation, Cloud Functions backdoors, and organization policy manipulation |

---

## Section Overview

GCP attack techniques center on the platform's service account model and organizational hierarchy. Unlike AWS where IAM users and roles are the primary identity types, GCP relies heavily on service accounts for both human and machine identities, making service account key exposure and impersonation the most common attack vectors. The GCP metadata server (accessible at 169.254.169.254) provides access tokens for attached service accounts and is a primary target for SSRF attacks. GCP's organization, folder, and project hierarchy creates inheritance-based IAM policy resolution that can be exploited when permissions are granted at higher levels than intended. Privilege escalation in GCP frequently involves chaining service account impersonation permissions (iam.serviceAccounts.getAccessToken, iam.serviceAccounts.actAs) to reach highly privileged service accounts. Persistence leverages the creation of new service account keys, Cloud Function triggers, and Pub/Sub subscriptions. Operators should use tools like GCPBucketBrute for storage enumeration and the gcloud CLI with custom scripts for systematic IAM analysis.

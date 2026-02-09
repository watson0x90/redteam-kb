# Cloud Security

This section covers cloud-specific attack methodology, techniques, and tools across the three major cloud service providers. As organizations migrate workloads to the cloud, red teams must operate across hybrid environments that span on-premises infrastructure and multi-cloud deployments.

---

**Navigation:**
| Previous | Current | Next |
|----------|---------|------|
| [12 - Active Directory Deep Dive](../12-active-directory-deep-dive/README.md) | **13 - Cloud Security** | [14 - Impact](../14-impact/README.md) |

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| Cloud Methodology | [cloud-methodology.md](cloud-methodology.md) | N/A | N/A | Overall approach to cloud red teaming, shared responsibility models, and engagement scoping |
| AWS Attack Techniques | [aws/README.md](aws/README.md) | Multiple | Varies | Amazon Web Services initial access, IAM escalation, persistence, and service abuse |
| Azure Attack Techniques | [azure/README.md](azure/README.md) | Multiple | Varies | Microsoft Azure initial access, Azure AD attacks, privilege escalation, and persistence |
| GCP Attack Techniques | [gcp/README.md](gcp/README.md) | Multiple | Varies | Google Cloud Platform initial access, privilege escalation, and persistence |
| Cloud Tools | [cloud-tools.md](cloud-tools.md) | N/A | N/A | Reference guide for cloud-specific offensive tools: ScoutSuite, Pacu, ROADtools, CloudFox, etc. |
| Container & Kubernetes | [containers/README.md](containers/README.md) | T1611, T1609, T1610 | Varies | Container escapes, Kubernetes RBAC abuse, service account exploitation, cloud-specific K8s attacks |

---

## Section Overview

Cloud security represents a rapidly evolving attack surface that requires distinct tradecraft from traditional on-premises engagements. The shared responsibility model means that cloud providers secure the infrastructure layer while customers are responsible for identity, access, configuration, and data security -- and these customer-managed layers are where the majority of cloud vulnerabilities exist. This section begins with a cloud methodology overview that adapts the traditional kill chain to cloud-native concepts like IAM policies, service principals, metadata services, and API-driven infrastructure. Each major cloud provider (AWS, Azure, GCP) has a dedicated subsection covering provider-specific attack techniques organized by kill chain phase. Common cross-cloud themes include overly permissive IAM policies, exposed storage buckets, metadata service credential theft, and serverless function abuse. The container escape techniques and Kubernetes attack techniques pages cover the full spectrum of container breakout methods and Kubernetes-specific attack vectors, including 2025-2026 CVEs (runc triple breakout, IngressNightmare, NVIDIA container toolkit escapes), RBAC abuse, cloud provider-specific K8s attacks (EKS IRSA/Pod Identity, GKE Workload Identity, AKS WireServer), and service mesh exploitation. The cloud tools reference provides operational guidance on the offensive tooling ecosystem for cloud assessments. Operators working in hybrid environments should cross-reference this section with the Azure AD Integration content in the Active Directory Deep Dive section.

# Cloud Attack Code - Reference Index

**MITRE ATT&CK Coverage**: T1552.005, T1102, T1071.001, T1528, T1550.001

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

This directory contains annotated code examples for cloud-focused attack techniques.
Each file pairs working implementation patterns with detection guidance and OPSEC
notes so that both red and blue teams can use them as a shared reference.

Every example maps to one or more MITRE ATT&CK techniques and cross-references
the narrative knowledge base files under `../../13-cloud-security/`.

## Contents

| Topic | File | Languages | Detection Risk | Description |
|---|---|---|---|---|
| IMDS Token Theft | [imds-token-theft.md](imds-token-theft.md) | Python, Bash, cURL | **Medium-High** | Querying cloud Instance Metadata Services (AWS, Azure, GCP) to steal temporary credentials, SSRF-to-IMDS attack chains, IMDSv2 bypass scenarios, and post-exploitation pivot techniques. |
| Cloud C2 Channels | [cloud-c2-channels.md](cloud-c2-channels.md) | Python, Bash | **Low-Medium** | Four "living off the cloud" command-and-control implementations: S3 dead drop, Azure Storage Queue, Lambda Function URL (HazyBeacon-style), and AWS X-Ray trace-based C2. |
| OAuth Token Abuse | [oauth-token-abuse.md](oauth-token-abuse.md) | Python, Bash, PowerShell | **Medium** | Device code phishing, Graph API abuse with stolen tokens, refresh token persistence, Pass-the-PRT extraction and replay, and ConsentFix social engineering technique. |

## How to Use This Reference

1. **Red team operators** -- review the OPSEC comments embedded in every code block
   before adapting patterns for an engagement. Detection indicators at the bottom of
   each file describe exactly what defenders will see.
2. **Blue team analysts** -- jump to the `## Detection Indicators` section in each
   file for log queries, signatures, and behavioral patterns.
3. **Security architects** -- the mitigation notes inline and the cross-references
   to the `13-cloud-security` KB provide hardening guidance.

## Prerequisites

Common Python libraries referenced across these files:

```text
boto3          >= 1.28    # AWS SDK
requests       >= 2.31    # HTTP client
azure-identity >= 1.15    # Azure auth
azure-storage-queue >= 12.8
msal           >= 1.24    # Microsoft Authentication Library
google-auth    >= 2.23    # GCP auth
```

Install for a lab environment only -- never on production workstations:

```bash
pip install boto3 requests azure-identity azure-storage-queue msal google-auth
```

## Cross-References

- [AWS Initial Access Narrative](../../13-cloud-security/aws/aws-initial-access.md)
- [Azure AD Attack Narrative](../../13-cloud-security/azure/azure-ad-attacks.md)
- [GCP Privilege Escalation Narrative](../../13-cloud-security/gcp/gcp-privesc.md)
- [Cloud Persistence Techniques](../../13-cloud-security/cloud-persistence.md)

## Revision History

| Date | Change |
|---|---|
| 2025-06-01 | Initial creation -- IMDS, C2 channels, OAuth token abuse |
| 2025-08-15 | Added React2Shell (CVE-2025-55182) notes to IMDS file |
| 2025-11-01 | Updated Azure Managed Identity MSP mitigation notes |

---
*Maintained as part of the red team knowledge base. All code is for authorized testing only.*

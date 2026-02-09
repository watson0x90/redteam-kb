# AWS Attack Techniques

This subsection covers offensive techniques specific to Amazon Web Services environments. AWS is the most widely adopted cloud platform, and its extensive service catalog creates a large and complex attack surface.

---

**Navigation:**
| Parent | Section |
|--------|---------|
| [Cloud Security](../README.md) | **AWS Attack Techniques** |

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| AWS Initial Access | [aws-initial-access.md](aws-initial-access.md) | T1078.004 | Medium | Exploiting exposed IAM keys, misconfigured S3 buckets, SSRF to metadata service, and Cognito abuse |
| AWS IAM Escalation | [aws-iam-escalation.md](aws-iam-escalation.md) | T1078.004 | Medium | IAM policy abuse, role chaining, AssumeRole pivoting, and privilege escalation through service permissions |
| AWS Persistence | [aws-persistence.md](aws-persistence.md) | T1098 | Medium-High | Backdoor IAM users, access key rotation, Lambda functions, EC2 instance profiles, and cross-account roles |
| AWS Services Abuse | [aws-services-abuse.md](aws-services-abuse.md) | T1530 | Medium | Exploiting S3, Lambda, EC2, SSM, STS, CodeBuild, and other AWS services for attack objectives |

---

## Section Overview

AWS attack techniques revolve around the Identity and Access Management (IAM) system, which governs all authorization decisions across the platform. The most common initial access vectors involve exposed access keys in source code repositories, SSRF attacks against the EC2 metadata service (IMDSv1), and misconfigured S3 bucket policies. IAM escalation is the AWS equivalent of Active Directory privilege escalation, where operators chain together overly permissive IAM policies to reach administrative access. AWS persistence techniques leverage the platform's own features -- IAM users, access keys, Lambda functions, and cross-account trust relationships -- to maintain access that survives credential rotation. The services abuse section covers the exploitation of individual AWS services including S3 data access, Lambda code execution, SSM command execution on EC2 instances, and STS token manipulation. Operators should use tools like Pacu and CloudFox for automated enumeration and privilege escalation path discovery.

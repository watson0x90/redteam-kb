# Passive Reconnaissance & OSINT

> **MITRE ATT&CK**: Reconnaissance > T1593 - Search Open Websites/Domains & T1596 - Search Open Technical Databases
> **Platforms**: All (external, pre-engagement)
> **Required Privileges**: None
> **OPSEC Risk**: Very Low (no direct target interaction)

## Strategic Overview

Passive reconnaissance is the foundation of every red team engagement. Because there is
zero direct interaction with the target's infrastructure, this phase is typically unlimited
by Rules of Engagement. The goal is to build a comprehensive target profile -- domains,
subdomains, email formats, technology stacks, employees, leaked credentials, and exposed
services -- before a single packet touches the target network. A thorough passive recon
phase can identify attack paths that bypass perimeter defenses entirely. Red Team Leads
should allocate 20-40% of engagement time to this phase; shortcuts here cascade into
operational failures later.

## Technical Deep-Dive

### Google Dorking

```bash
# Find exposed login portals
site:target.com intitle:"login" OR intitle:"sign in"

# Discover documents with metadata
site:target.com filetype:pdf OR filetype:docx OR filetype:xlsx

# Find configuration files and backups
site:target.com filetype:conf OR filetype:bak OR filetype:sql

# Identify directory listings
intitle:"index of" site:target.com

# Locate exposed admin panels
site:target.com inurl:admin OR inurl:panel OR inurl:dashboard

# Find subdomains indexed by Google
site:*.target.com -www
```

### Certificate Transparency Logs

```bash
# Query crt.sh for subdomains via certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Use certsh tool for structured output
python3 certsh.py -d target.com

# Amass passive mode leveraging CT logs, APIs, and archives
amass enum -passive -d target.com -o amass-passive.txt
```

### Shodan & Censys Queries

```bash
# Shodan CLI - find exposed services for an organization
shodan search "ssl.cert.subject.CN:target.com" --fields ip_str,port,org,hostnames
shodan search "org:\"Target Corp\"" --fields ip_str,port,product,version

# Censys search for certificates and hosts
censys search "parsed.names: target.com" --index-type certificates
censys search "autonomous_system.name: Target Corp" --index-type hosts

# Shodan facet analysis for technology profiling
shodan stats --facets port,product,os "org:\"Target Corp\""
```

### GitHub & Source Code Reconnaissance

```bash
# TruffleHog - scan repos for secrets (including git history)
trufflehog github --org target-org --only-verified
trufflehog git https://github.com/target-org/repo.git

# Gitrob - identify sensitive files in repos
gitrob -org target-org

# Manual GitHub dorking
# "target.com" password OR secret OR token OR api_key
# org:target-org filename:.env
# org:target-org filename:id_rsa
```

### Metadata Extraction

```bash
# ExifTool - extract metadata from downloaded documents
exiftool -a -u -g1 downloaded_file.pdf
# Reveals: author names, software versions, internal paths, email addresses

# FOCA - automated metadata extraction and analysis (Windows)
# Bulk download and analyze documents from a domain
# Extracts users, paths, OS versions, printer names, email addresses

# Metagoofil - download and extract metadata in bulk
metagoofil -d target.com -t pdf,docx,xlsx -l 100 -o metadata_output/
```

### Comprehensive OSINT Frameworks

```bash
# theHarvester - multi-source email, subdomain, IP enumeration
theHarvester -d target.com -b all -f harvester-results

# SpiderFoot - automated OSINT collection
spiderfoot -s target.com -m all -o spiderfoot-results.json

# Recon-ng - modular reconnaissance framework
recon-ng
> marketplace install all
> modules load recon/domains-hosts/hackertarget
> options set SOURCE target.com
> run
```

### Breach Data & Credential Intelligence

```bash
# Have I Been Pwned API - check if corporate emails appear in breaches
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/user@target.com" \
  -H "hibp-api-key: YOUR_KEY"

# DeHashed, IntelX, LeakCheck for credential lookups
# CRITICAL: Only use breach data within legal boundaries of engagement scope

# LinkedIn enumeration for email format discovery
# Identify naming convention: first.last, flast, firstl, etc.
# Cross-reference with breach data for credential stuffing candidates
```

### DNS History & WHOIS

```bash
# WHOIS for registration details
whois target.com
# Note: registrant info, name servers, registration dates, registrar

# DNS history via SecurityTrails API
curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a" \
  -H "APIKEY: YOUR_KEY"

# Wayback Machine for historical site content
waybackurls target.com | sort -u > wayback-urls.txt
# Find removed pages, old login portals, deprecated APIs
```

## Detection & Evasion

### Why Passive Recon Is Nearly Undetectable
- No packets sent to target infrastructure -- all data sourced from third parties
- Certificate Transparency logs, Shodan, and search engines are public resources
- The target has no visibility into who queries these services
- Only risk: if target monitors for their domain in CT log subscriptions or Google Alerts

### OPSEC Considerations
- Use VPNs or Tor when querying OSINT platforms to avoid attribution
- Avoid authenticated API queries that could be logged and traced
- Do not access target websites directly during passive recon phase
- Rate-limit API queries to avoid bans on OSINT platforms
- Store collected data securely; breach data has legal sensitivity
- Sanitize operational notes of client-identifying information

### Defensive Perspective
- Organizations should monitor CT logs for unauthorized certificate issuance
- Implement Google Alerts for sensitive document exposure
- Conduct regular GitHub secret scanning on organizational repositories
- Monitor for employee credential exposure via breach notification services
- Remove unnecessary metadata from published documents before upload

## Cross-References

- **Active Scanning** (01-reconnaissance/active-scanning.md) -- follow-up with direct scanning
- **DNS Enumeration** (01-reconnaissance/dns-enumeration.md) -- passive DNS feeds into active DNS enum
- **Web Recon** (01-reconnaissance/web-recon.md) -- technology fingerprinting from passive data
- **Cloud Recon** (01-reconnaissance/cloud-recon.md) -- cloud asset discovery via OSINT
- **Phishing** (02-initial-access/phishing-payloads.md) -- OSINT informs phishing pretexts

## References

- MITRE ATT&CK T1593: https://attack.mitre.org/techniques/T1593/
- MITRE ATT&CK T1596: https://attack.mitre.org/techniques/T1596/
- OSINT Framework: https://osintframework.com/
- Google Hacking Database: https://www.exploit-db.com/google-hacking-database
- theHarvester: https://github.com/laramies/theHarvester
- Amass: https://github.com/owasp-amass/amass
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- Recon-ng: https://github.com/lanmaster53/recon-ng

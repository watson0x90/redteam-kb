# Web Application Reconnaissance

> **MITRE ATT&CK**: Reconnaissance > T1595.002 - Active Scanning: Vulnerability Scanning
> **Platforms**: All (HTTP/HTTPS services)
> **Required Privileges**: None
> **OPSEC Risk**: Medium (web requests are logged; brute-force generates volume)

## Strategic Overview

Web applications are the most common initial access vector in modern engagements. Nearly
every organization exposes web services -- corporate sites, email portals, VPN gateways,
API endpoints, and internal applications accidentally exposed to the internet. Web
reconnaissance bridges network-level scanning with application-level exploitation. The
Red Team Lead must approach web recon systematically: identify all web services across
discovered hosts, fingerprint their technology stacks, enumerate directories and virtual
hosts, analyze JavaScript for API endpoints and secrets, and identify WAF protections that
will shape the exploitation approach. A thorough web recon phase often reveals forgotten
applications, development endpoints with debug enabled, and administrative interfaces
protected only by obscurity. Every discovered endpoint is a potential entry point.

## Technical Deep-Dive

### Directory and File Brute-Force

```bash
# Gobuster directory mode - fast, reliable
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -t 50 -o gobuster-dirs.txt -x php,asp,aspx,jsp,html,txt,bak
# -x = file extensions to append, -t = threads

# ffuf - flexible fuzzer with advanced filtering
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -mc 200,301,302,403 -fc 404 -t 50 -o ffuf-results.json -of json

# ffuf with extension fuzzing
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -e .php,.asp,.aspx,.jsp,.bak,.old,.conf,.txt,.xml,.json -mc all -fc 404

# Feroxbuster - recursive directory brute-force
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -t 50 -d 3 -x php,asp,aspx --smart -o ferox-results.txt

# Dirsearch - feature-rich directory scanner
dirsearch -u https://target.com -e php,asp,aspx,jsp -t 50 --random-agent \
  -o dirsearch-results.txt

# Recursive scanning with depth control
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -t 30 --no-error -r    # -r follows redirects
```

### Virtual Host (VHost) Enumeration

```bash
# Gobuster vhost mode - discover virtual hosts on the same IP
gobuster vhost -u https://10.10.10.50 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --domain target.com --append-domain -t 50

# ffuf vhost fuzzing with response size filtering
ffuf -u https://10.10.10.50 -H "Host: FUZZ.target.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs 0 -mc 200,301,302,403 -t 50

# Manual vhost testing with curl
curl -s -H "Host: dev.target.com" https://10.10.10.50 | head -20
curl -s -H "Host: staging.target.com" https://10.10.10.50 | head -20
curl -s -H "Host: admin.target.com" https://10.10.10.50 | head -20
```

### Technology Fingerprinting

```bash
# WhatWeb - identify technologies from HTTP responses
whatweb https://target.com -a 3 -v
# Detects: CMS, frameworks, server software, JavaScript libraries, analytics

# httpx - fast HTTP probing with technology detection
httpx -l subdomains.txt -sc -td -title -server -ip -cdn -o httpx-results.txt
# -sc=status code, -td=tech detect, -title=page title, -server=server header

# Wappalyzer CLI (webanalyze)
webanalyze -host https://target.com -crawl 2

# Nmap HTTP scripts for fingerprinting
nmap -sV --script http-headers,http-server-header,http-generator -p 80,443,8080 10.10.10.50

# Curl for manual header analysis
curl -sI https://target.com
# Look for: Server, X-Powered-By, X-AspNet-Version, X-Generator, Set-Cookie prefixes
```

### Robots.txt, Sitemap, and Configuration Files

```bash
# Check robots.txt for hidden paths
curl -s https://target.com/robots.txt
# Disallowed paths often contain admin panels and sensitive directories

# Check sitemap for URL structure
curl -s https://target.com/sitemap.xml
curl -s https://target.com/sitemap_index.xml

# Common configuration and information disclosure files
for path in robots.txt sitemap.xml .well-known/security.txt crossdomain.xml \
  clientaccesspolicy.xml .git/HEAD .env .htaccess web.config package.json \
  composer.json wp-config.php.bak info.php phpinfo.php; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path")
    [ "$code" != "404" ] && echo "[${code}] https://target.com/$path"
done
```

### JavaScript Analysis and API Discovery

```bash
# Extract JavaScript files from a page
curl -s https://target.com | grep -oP 'src="[^"]*\.js[^"]*"' | cut -d'"' -f2

# LinkFinder - discover endpoints in JavaScript files
linkfinder -i https://target.com -o cli
linkfinder -i https://target.com/static/app.js -o results.html

# SecretFinder - find secrets in JavaScript
python3 SecretFinder.py -i https://target.com/static/app.js -o cli
# Finds: API keys, tokens, passwords, AWS keys, private URLs

# GAP (Get All Parameters) - extract parameters from JS/HTML
python3 gap.py -u https://target.com -o gap-results.txt

# Katana - web crawling for endpoint discovery
katana -u https://target.com -d 3 -jc -kf -o katana-results.txt
# -jc=JavaScript crawl, -kf=known files, -d=depth
```

### WAF Detection and Identification

```bash
# wafw00f - WAF fingerprinting
wafw00f https://target.com
wafw00f https://target.com -a    # Test all WAF signatures

# Manual WAF detection via response headers and behavior
curl -s -H "User-Agent: <script>alert(1)</script>" https://target.com -I
# 403 or custom error page = WAF present

# Nmap WAF detection
nmap --script http-waf-detect,http-waf-fingerprint -p 443 target.com

# Common WAF indicators in headers:
# Cloudflare: cf-ray header, __cfduid cookie
# AWS WAF: x-amzn-requestid
# Akamai: AkamaiGHost server header
# Imperva: incap_ses cookie
```

### CMS Identification and Scanning

```bash
# WPScan - WordPress vulnerability scanner
wpscan --url https://target.com --enumerate u,vp,vt,cb,dbe \
  --api-token YOUR_TOKEN --random-user-agent
# u=users, vp=vulnerable plugins, vt=vulnerable themes
# cb=config backups, dbe=database exports

# CMSeek - multi-CMS detection and scanning
python3 cmseek.py -u https://target.com

# Droopescan - Drupal/Joomla/WordPress/SilverStripe scanner
droopescan scan drupal -u https://target.com

# Joomscan - Joomla scanner
joomscan -u https://target.com
```

### Parameter and Endpoint Discovery

```bash
# Arjun - HTTP parameter discovery
arjun -u https://target.com/endpoint -m GET -t 50
arjun -u https://target.com/api/v1/users -m POST -t 50

# ParamSpider - mining parameters from web archives
paramspider -d target.com -o params.txt

# ffuf for parameter brute-force
ffuf -u "https://target.com/page?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 -fs 4242    # Filter by response size to detect valid parameters
```

## Detection & Evasion

### What Defenders See
- High-volume 404 responses from directory brute-force in web server access logs
- Rapid sequential requests from a single IP with automated User-Agent strings
- WAF logs showing blocked payloads and known scanning tool signatures
- Anomalous request patterns: sequential wordlist-based paths

### Evasion Techniques
- Rotate User-Agent strings: `--random-user-agent` in most tools
- Rate-limit requests: `-t 10` (lower thread count) and `--delay` flags
- Use legitimate-looking User-Agent strings (Chrome, Firefox current versions)
- Route through multiple IP addresses (proxy chains, cloud functions)
- Avoid default tool signatures (customize wordlists, headers)
- Target specific directories based on technology stack rather than generic wordlists

### OPSEC Considerations
- Directory brute-force is one of the noisiest recon activities
- WAFs may auto-block source IPs after threshold violations
- Some applications have real-time alerting on 403/404 spikes
- Always check scope: scanning a CDN IP may scan shared infrastructure

## Cross-References

- **DNS Enumeration** (01-reconnaissance/dns-enumeration.md) -- discovered subdomains need web recon
- **Cloud Recon** (01-reconnaissance/cloud-recon.md) -- cloud-hosted web apps have specific patterns
- **Passive Recon** (01-reconnaissance/passive-recon.md) -- Wayback Machine reveals historical endpoints
- **Exploit Public Apps** (02-initial-access/exploit-public-apps.md) -- web recon findings lead to exploitation
- **Phishing** (02-initial-access/phishing-payloads.md) -- identified login portals inform phishing

## References

- MITRE ATT&CK T1595.002: https://attack.mitre.org/techniques/T1595/002/
- Gobuster: https://github.com/OJ/gobuster
- ffuf: https://github.com/ffuf/ffuf
- Feroxbuster: https://github.com/epi052/feroxbuster
- WPScan: https://github.com/wpscanteam/wpscan
- Katana: https://github.com/projectdiscovery/katana
- httpx: https://github.com/projectdiscovery/httpx
- SecLists: https://github.com/danielmiessler/SecLists

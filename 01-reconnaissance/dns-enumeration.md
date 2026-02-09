# DNS Enumeration

> **MITRE ATT&CK**: Reconnaissance > T1590.002 - Gather Victim Network Information: DNS
> **Platforms**: All (network-level)
> **Required Privileges**: None
> **OPSEC Risk**: Low-Medium (DNS queries are common but bulk enumeration is detectable)

## Strategic Overview

DNS is the backbone of network infrastructure and one of the most information-rich protocols
for reconnaissance. A single misconfigured DNS server can expose the entire internal network
topology through a zone transfer. Even without zone transfers, subdomain enumeration reveals
attack surface that organizations often forget about -- development servers, staging
environments, legacy applications, and shadow IT. The Red Team Lead should treat DNS
enumeration as a mandatory step: it bridges passive OSINT with active network scanning by
translating domain intelligence into actionable IP addresses. DNS enumeration also uncovers
mail servers (MX records), name servers (NS records), SPF/DKIM/DMARC policies (TXT records),
and service locations (SRV records) that inform later attack phases.

## Technical Deep-Dive

### Zone Transfers (AXFR)

```bash
# Attempt zone transfer with dig (the gold standard if it works)
dig axfr @ns1.target.com target.com

# Alternative with host command
host -t axfr target.com ns1.target.com

# Automated zone transfer attempt across all name servers
for ns in $(dig NS target.com +short); do
    echo "=== Trying zone transfer from $ns ==="
    dig axfr @$ns target.com
done

# Zone transfer via nmap NSE script
nmap --script dns-zone-transfer -p 53 ns1.target.com
```

### DNS Record Enumeration

```bash
# Enumerate all common record types for a domain
for type in A AAAA CNAME MX NS TXT SRV SOA PTR; do
    echo "=== $type Records ==="
    dig $type target.com +short
done

# MX records reveal mail infrastructure
dig MX target.com +short
# Result: 10 mail.target.com -> Exchange, O365, Google Workspace

# TXT records expose SPF, DKIM, DMARC, domain verification tokens
dig TXT target.com +short
# SPF reveals authorized mail senders (IP ranges, third-party services)

# SRV records for service discovery (LDAP, Kerberos, SIP, XMPP)
dig SRV _ldap._tcp.target.com +short
dig SRV _kerberos._tcp.target.com +short
dig SRV _sip._tls.target.com +short

# SOA record for primary nameserver and admin email
dig SOA target.com +short

# Reverse DNS lookups for IP ranges
dig -x 10.10.10.50 +short
# Bulk reverse DNS for a subnet
for i in $(seq 1 254); do
    result=$(dig -x 10.10.10.$i +short 2>/dev/null)
    [ -n "$result" ] && echo "10.10.10.$i -> $result"
done
```

### Subdomain Brute-Force

```bash
# Subfinder - passive subdomain enumeration from multiple sources
subfinder -d target.com -all -o subfinder-results.txt

# Amass - comprehensive enumeration (passive + active)
amass enum -d target.com -active -brute -w /usr/share/wordlists/dns-subdomains.txt \
  -o amass-results.txt
amass enum -d target.com -passive -o amass-passive.txt

# Gobuster DNS mode - pure brute-force
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -t 50 -o gobuster-dns.txt

# ffuf for DNS brute-force with wildcard filtering
ffuf -u "http://FUZZ.target.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc 200,301,302,403 -o ffuf-dns.json

# MassDNS - extremely fast bulk resolution
massdns -r resolvers.txt -t A -o S -w massdns-results.txt subdomains-wordlist.txt

# Puredns - accurate brute-force with wildcard filtering
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  target.com -r resolvers.txt -w puredns-results.txt
```

### Wildcard Detection and Handling

```bash
# Test for wildcard DNS records
dig A nonexistent-random-subdomain-12345.target.com +short
# If this returns an IP, a wildcard record exists

# Amass handles wildcards automatically
# For manual tools, filter out the wildcard IP from results
WILDCARD_IP=$(dig A nonexistent-random-xyz.target.com +short)
cat subdomain-results.txt | while read sub; do
    ip=$(dig A "$sub" +short)
    [ "$ip" != "$WILDCARD_IP" ] && echo "$sub -> $ip"
done
```

### Dedicated DNS Enumeration Tools

```bash
# dnsrecon - comprehensive DNS enumeration
dnsrecon -d target.com -t std,brt,axfr -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
dnsrecon -d target.com -t rvl -r 10.10.10.0/24   # Reverse lookup range

# dnsenum - automated enumeration with Google scraping
dnsenum --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --update a -r target.com

# fierce - domain scanner finding non-contiguous IP space
fierce --domain target.com --subdomains /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Knock - subdomain scanner
knockpy target.com
```

### Passive DNS Sources

```bash
# SecurityTrails API for historical DNS data
curl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains" \
  -H "APIKEY: YOUR_KEY" | jq -r '.subdomains[]' | sed "s/$/.target.com/"

# VirusTotal passive DNS
curl -s "https://www.virustotal.com/api/v3/domains/target.com/subdomains" \
  -H "x-apikey: YOUR_KEY" | jq -r '.data[].id'

# DNSDumpster (web-based, no API) - useful for quick visual mapping
# https://dnsdumpster.com/

# RapidDNS - bulk passive DNS
curl -s "https://rapiddns.io/subdomain/target.com" | grep -oP '[\w.-]+\.target\.com' | sort -u
```

## Detection & Evasion

### What Defenders See
- Zone transfer attempts generate distinctive AXFR query logs on authoritative DNS servers
- High-volume subdomain queries from a single source IP trigger DNS monitoring alerts
- Brute-force subdomain resolution creates anomalous query volume in DNS logs
- Passive DNS lookups through third-party APIs are invisible to the target

### Evasion Techniques
- Use multiple DNS resolvers to distribute query load (avoid target's DNS servers)
- Limit query rate: `--delay` flags or custom throttling to 5-10 queries/second
- Prefer passive DNS sources (SecurityTrails, VirusTotal) over active brute-force
- Use public resolvers (8.8.8.8, 1.1.1.1) instead of the target's authoritative servers
- Spread enumeration across time windows to avoid volume-based detection

### Defensive Recommendations
- Disable zone transfers to unauthorized IPs (allow-transfer in BIND, zone transfer restrictions)
- Monitor DNS query logs for AXFR requests and high-volume subdomain lookups
- Implement DNS query rate limiting on authoritative servers
- Use split-horizon DNS to prevent internal record exposure
- Regularly audit public DNS records for unnecessary exposure

## Cross-References

- **Passive Recon** (01-reconnaissance/passive-recon.md) -- CT logs and OSINT feed subdomain lists
- **Active Scanning** (01-reconnaissance/active-scanning.md) -- resolved IPs become scan targets
- **Web Recon** (01-reconnaissance/web-recon.md) -- discovered subdomains need web enumeration
- **Cloud Recon** (01-reconnaissance/cloud-recon.md) -- cloud-specific DNS patterns (CNAME to cloud providers)
- **LDAP Enumeration** (01-reconnaissance/ldap-enumeration.md) -- SRV records reveal domain controllers

## References

- MITRE ATT&CK T1590.002: https://attack.mitre.org/techniques/T1590/002/
- Subfinder: https://github.com/projectdiscovery/subfinder
- Amass: https://github.com/owasp-amass/amass
- MassDNS: https://github.com/blechschmidt/massdns
- Puredns: https://github.com/d3mondev/puredns
- dnsrecon: https://github.com/darkoperator/dnsrecon
- SecLists DNS Wordlists: https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS

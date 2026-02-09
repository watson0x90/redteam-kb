# Active Scanning & Network Reconnaissance

> **MITRE ATT&CK**: Reconnaissance > T1046 - Network Service Scanning
> **Platforms**: All (network-level)
> **Required Privileges**: None (root/admin for SYN scans)
> **OPSEC Risk**: Medium-High (generates network traffic, triggers IDS/IPS)

## Strategic Overview

Active scanning transitions from passive intelligence gathering to direct target interaction.
Every packet sent to the target is potentially observable by defenders, making scan strategy
a critical OPSEC decision. The Red Team Lead must balance thoroughness against detection risk.
A full-port SYN scan of a /16 will find everything but will also light up every SOC dashboard.
Conversely, a slow targeted scan of known high-value ports may slip through but miss shadow IT.
Successful active scanning requires understanding the defensive posture first -- what IDS/IPS
exists, what logging is in place, and what thresholds trigger alerts. The recon phase should
answer: "What is running, what version, and what is vulnerable?" while generating the minimum
detectable footprint.

## Technical Deep-Dive

### Nmap Fundamentals

```bash
# TCP SYN scan (half-open, requires root) - the standard scan
sudo nmap -sS -p- -T3 --open -oA full-syn-scan 10.10.10.0/24

# Version detection with default scripts
sudo nmap -sS -sV -sC -p 21,22,25,53,80,88,110,135,139,143,389,443,445,\
636,993,995,1433,3306,3389,5985,8080,8443 -oA targeted-scan 10.10.10.0/24

# OS detection (requires at least one open and one closed port)
sudo nmap -sS -O --osscan-guess -oA os-scan 10.10.10.50

# UDP scan for common services (slow -- target specific ports)
sudo nmap -sU -p 53,67,68,69,123,161,162,500,514,1900 --open -oA udp-scan 10.10.10.0/24

# Aggressive comprehensive scan on specific host
sudo nmap -sS -sV -sC -O -p- -T4 --script=vuln -oA aggressive-scan 10.10.10.50
```

### Nmap Scripting Engine (NSE)

```bash
# SMB vulnerability checks
nmap --script smb-vuln-ms17-010,smb-vuln-ms08-067 -p 445 10.10.10.0/24

# HTTP enumeration
nmap --script http-enum,http-headers,http-methods,http-title -p 80,443,8080 10.10.10.50

# SSL/TLS analysis
nmap --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed -p 443 10.10.10.50

# Default credential checks
nmap --script ftp-anon,mysql-empty-password,ms-sql-empty-password -p 21,3306,1433 10.10.10.0/24

# Enumerate all available scripts for a service
ls /usr/share/nmap/scripts/ | grep smb
nmap --script-help "smb-*"
```

### Masscan for Speed

```bash
# Full port scan at controlled rate (adjust rate to environment)
sudo masscan 10.10.10.0/24 -p 0-65535 --rate 1000 -oL masscan-full.txt

# Rate-limited scan to avoid detection
sudo masscan 10.10.10.0/24 -p 0-65535 --rate 100 --wait 5 -oL masscan-slow.txt

# Feed Masscan results into Nmap for service enumeration
# Parse masscan output, extract open ports, scan with nmap
masscan_to_nmap() {
    grep "^open" masscan-full.txt | awk '{print $3,$4}' | sort -t. -k1,1n -k2,2n | \
    awk '{ports[$2]=ports[$2]","$1} END {for(ip in ports) print ip, substr(ports[ip],2)}' | \
    while read ip ports; do
        nmap -sV -sC -p "$ports" "$ip" -oA "nmap-$ip"
    done
}
```

### Rustscan for Fast Port Discovery

```bash
# Rustscan with Nmap integration (finds ports fast, then enumerates)
rustscan -a 10.10.10.50 --ulimit 5000 -- -sV -sC -oA rustscan-results

# Scan subnet with batch size control
rustscan -a 10.10.10.0/24 -b 500 --ulimit 5000 -- -sV
```

### Service Fingerprinting & Banner Grabbing

```bash
# Manual banner grabbing with netcat
nc -nv 10.10.10.50 22    # SSH banner
nc -nv 10.10.10.50 21    # FTP banner
nc -nv 10.10.10.50 25    # SMTP banner

# HTTP header fingerprinting with curl
curl -sI https://target.com | head -20
curl -sv https://target.com 2>&1 | grep "< "

# Automated banner grabbing across a range
for port in 21 22 25 80 443 8080; do
    echo "--- Port $port ---"
    echo "" | timeout 3 nc -nv 10.10.10.50 $port 2>&1
done
```

### Vulnerability Scanning

```bash
# Nessus (commercial) - CLI scan initiation
nessuscli scan --hosts 10.10.10.0/24 --policy "Advanced Scan" --name "RedTeam-Scan"

# OpenVAS (open-source) - via GVM CLI
gvm-cli socket --xml '<create_target><name>RedTeam</name>\
<hosts>10.10.10.0/24</hosts></create_target>'

# Nuclei - fast template-based vulnerability scanner
nuclei -l targets.txt -t cves/ -t exposures/ -t misconfiguration/ -o nuclei-results.txt
nuclei -u https://target.com -t http/cves/ -severity critical,high -o critical-vulns.txt
```

### Practical Engagement Scan Patterns

```bash
# Phase 1: Quick discovery (top 100 ports, fast timing)
sudo nmap -sS --top-ports 100 -T4 --open -oA phase1-quick 10.10.10.0/24

# Phase 2: Targeted service enumeration on discovered hosts
sudo nmap -sS -sV -sC -p- -T3 --open -oA phase2-full 10.10.10.50,51,52

# Phase 3: Deep vulnerability assessment on high-value targets
sudo nmap -sS -sV --script=vuln -p- -T3 -oA phase3-vuln 10.10.10.50
```

## Detection & Evasion

### Evasion Techniques

```bash
# Fragmentation to bypass packet inspection
sudo nmap -f -sS -p 80,443 10.10.10.50

# Decoy scan (mix real scan with decoy source IPs)
sudo nmap -sS -D 10.10.10.100,10.10.10.101,ME,10.10.10.102 -p 80 10.10.10.50

# Source port manipulation (some firewalls allow DNS/HTTP source ports)
sudo nmap -sS --source-port 53 -p 445 10.10.10.50
sudo nmap -sS --source-port 80 -p 1-1024 10.10.10.50

# Slow timing to avoid rate-based detection
sudo nmap -sS -T1 --max-rate 5 --max-parallelism 1 -p 80,443 10.10.10.50

# Randomize host and port order
sudo nmap -sS --randomize-hosts -p- --scan-delay 500ms 10.10.10.0/24

# Idle/Zombie scan (uses third-party host for stealth)
sudo nmap -sI zombie-host:80 -p 80,443 10.10.10.50
```

### What Defenders See
- SYN scans generate RST packets from closed ports -- anomalous traffic patterns
- Sequential port scanning is a strong IDS signature (Snort, Suricata rules)
- Version detection (-sV) completes TCP handshakes and sends probes -- fully logged
- NSE scripts generate application-layer traffic specific to each protocol
- High packet rates from Masscan trigger rate-based IDS alerts

### OPSEC Best Practices
- Scan from an IP address expected to generate traffic (e.g., a compromised web server)
- Use timing controls (-T2 or -T3, never -T5 in production engagements)
- Split scans across multiple source IPs and time windows
- Start with targeted port lists based on passive recon, not full port scans
- Log all scan activity for deconfliction with the client SOC

## Cross-References

- **Passive Recon** (01-reconnaissance/passive-recon.md) -- passive data informs scan targets
- **DNS Enumeration** (01-reconnaissance/dns-enumeration.md) -- DNS data reveals additional hosts
- **SMB Enumeration** (01-reconnaissance/smb-enumeration.md) -- follow-up for port 445 discoveries
- **SNMP Enumeration** (01-reconnaissance/snmp-enumeration.md) -- follow-up for port 161 discoveries
- **Exploit Public Apps** (02-initial-access/exploit-public-apps.md) -- vulnerabilities found lead to exploitation

## References

- MITRE ATT&CK T1046: https://attack.mitre.org/techniques/T1046/
- Nmap Reference Guide: https://nmap.org/book/man.html
- Masscan: https://github.com/robertdavidgraham/masscan
- Rustscan: https://github.com/RustScan/RustScan
- Nuclei: https://github.com/projectdiscovery/nuclei
- NSE Script Documentation: https://nmap.org/nsedoc/

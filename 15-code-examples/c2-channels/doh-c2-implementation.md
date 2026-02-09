# DNS-over-HTTPS (DoH) C2 - Educational Protocol Analysis

> **MITRE ATT&CK**: T1071.004 (DNS) + T1573.002 (Encrypted Channel: Asymmetric Cryptography)
> **Purpose**: Understanding DoH abuse patterns for detection engineering
> **Detection Priority**: Critical - Encrypted DNS is a significant blind spot

## Strategic Overview

DNS-over-HTTPS (DoH) wraps DNS queries inside HTTPS connections to legitimate resolvers (Google, Cloudflare, etc.). This creates a significant detection challenge because:

1. DNS queries are encrypted within TLS, invisible to traditional DNS monitoring
2. Traffic goes to legitimate, high-reputation domains (dns.google, cloudflare-dns.com)
3. Standard DNS logging infrastructure sees nothing
4. The traffic pattern looks identical to normal HTTPS browsing

### Why This Matters for Red Team Leads
- Combines DNS tunneling stealth with TLS encryption
- Bypasses all traditional DNS inspection and logging
- Traffic destinations are legitimate infrastructure (difficult to block)
- Represents the evolution of DNS-based C2

### Detection Opportunity
While encrypted, DoH traffic has detectable characteristics at the network flow level.

## Technical Deep-Dive

### DoH Protocol Overview

```
Traditional DNS Tunneling:
┌────────┐  DNS/UDP:53  ┌───────────┐  DNS/UDP:53  ┌──────────────┐
│ Client │─────────────>│ Recursive │─────────────>│ Attacker's   │
│        │<─────────────│ Resolver  │<─────────────│ Auth DNS     │
└────────┘              └───────────┘              └──────────────┘
  ▲ VISIBLE to DNS monitoring at every hop

DoH-based Tunneling:
┌────────┐  HTTPS:443   ┌──────────────┐  DNS/UDP:53  ┌──────────────┐
│ Client │─────────────>│ DoH Resolver │─────────────>│ Attacker's   │
│        │  (encrypted) │ (Google/CF)  │              │ Auth DNS     │
│        │<─────────────│              │<─────────────│              │
└────────┘              └──────────────┘              └──────────────┘
  ▲ INVISIBLE to local DNS monitoring
  ▲ Encrypted in TLS, looks like HTTPS to google.com
```

### DoH Request Format

```python
"""
Educational: How DoH encapsulates DNS queries in HTTPS.
Understanding the wire format helps defenders identify
DoH traffic patterns even when content is encrypted.

DoH is defined in RFC 8484. Queries use either:
- GET with base64url-encoded DNS wire format in ?dns= parameter
- POST with application/dns-message content type
"""
import base64
import struct
import json

# === DOH WIRE FORMAT ANALYSIS ===

def build_dns_wire_query(domain: str, record_type: int = 1) -> bytes:
    """
    Build DNS wire format query (RFC 1035) for DoH encapsulation.

    This is the same format used in UDP DNS, but sent over HTTPS.
    Understanding this format helps analysts:
    1. Decode DoH queries from TLS-inspected traffic
    2. Build detection rules for DNS wire format in HTTP bodies
    3. Analyze DoH traffic in proxy logs with TLS inspection
    """
    # DNS Header
    header = struct.pack('!HHHHHH',
        0x1234,  # Transaction ID
        0x0100,  # Flags: standard query, recursion desired
        1,       # Questions: 1
        0,       # Answers: 0
        0,       # Authority: 0
        0,       # Additional: 0
    )

    # Encode domain name in DNS wire format
    question = b''
    for label in domain.split('.'):
        question += bytes([len(label)]) + label.encode()
    question += b'\x00'  # Root label

    # Query type and class
    question += struct.pack('!HH', record_type, 1)  # Type, Class IN

    return header + question


def format_doh_get_url(dns_query: bytes, resolver: str) -> str:
    """
    Format a DoH GET request URL (RFC 8484 Section 4.1).

    Detection Note: DoH GET requests contain base64url-encoded
    DNS wire format in the ?dns= query parameter. If TLS
    inspection is available, this parameter is detectable.
    """
    encoded = base64.urlsafe_b64encode(dns_query).rstrip(b'=').decode()
    return f"https://{resolver}/dns-query?dns={encoded}"


def format_doh_post_headers() -> dict:
    """
    Required headers for DoH POST requests (RFC 8484 Section 4.1).

    Detection Note: The content-type 'application/dns-message'
    is a strong indicator of DoH traffic in TLS-inspected logs.
    """
    return {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message',
    }


# === DEMONSTRATE DOH FORMAT ===

# Common DoH resolvers (legitimate infrastructure)
DOH_RESOLVERS = {
    'Google':       'dns.google',
    'Cloudflare':   'cloudflare-dns.com',
    'Quad9':        'dns.quad9.net',
    'NextDNS':      'dns.nextdns.io',
    'AdGuard':      'dns.adguard.com',
}

# Show how a tunneling query would be formatted
demo_domain = "encoded-data-here.tunnel.attacker.com"
wire_query = build_dns_wire_query(demo_domain, record_type=16)  # TXT

print("=== DoH Wire Format Analysis ===")
print(f"Domain: {demo_domain}")
print(f"Wire format ({len(wire_query)} bytes): {wire_query.hex()}")
print()

for name, resolver in DOH_RESOLVERS.items():
    url = format_doh_get_url(wire_query, resolver)
    print(f"{name}: {url}")

print("\n=== Detection Implications ===")
print("1. DNS query is base64url-encoded in URL parameter")
print("2. Without TLS inspection, only the resolver IP is visible")
print("3. All traffic appears as HTTPS to legitimate services")
print("4. Volume analysis and endpoint identification are primary detections")
```

### DoH Query Execution (Python - Educational)

```python
"""
Educational: How DoH queries are executed using standard HTTP libraries.
This demonstrates the simplicity of DoH from an attacker's perspective,
highlighting why detection at the network level is critical.

This example queries legitimate DNS records to show the protocol flow.
"""
import requests
import struct

def doh_query_example(domain: str, resolver_url: str = "https://dns.google/resolve") -> dict:
    """
    Perform a DoH query using Google's JSON API.

    Note: Google also offers a JSON API (not RFC 8484) that is
    even simpler to use and harder to distinguish from normal
    API traffic.

    Detection: Monitor for repeated HTTPS connections to known
    DoH resolver IPs, especially from processes that don't
    normally perform DNS resolution.
    """
    params = {
        'name': domain,
        'type': 'TXT',  # TXT records carry the most data
    }
    headers = {
        'Accept': 'application/dns-json',
    }

    # This looks like a normal HTTPS GET to dns.google
    response = requests.get(resolver_url, params=params, headers=headers)
    return response.json()

# === Detection: Identifying DoH resolver endpoints ===

DOH_RESOLVER_IPS = {
    # Google DNS
    '8.8.8.8', '8.8.4.4',
    '2001:4860:4860::8888', '2001:4860:4860::8844',
    # Cloudflare DNS
    '1.1.1.1', '1.0.0.1',
    '2606:4700:4700::1111', '2606:4700:4700::1001',
    # Quad9
    '9.9.9.9', '149.112.112.112',
    # NextDNS
    '45.90.28.0', '45.90.30.0',
}

def check_doh_connection(dst_ip: str, dst_port: int) -> str:
    """
    Detection function: Check if an outbound HTTPS connection
    is targeting a known DoH resolver.

    Integration: Add to firewall/proxy log analysis pipeline.
    """
    if dst_port == 443 and dst_ip in DOH_RESOLVER_IPS:
        return f"ALERT: HTTPS connection to known DoH resolver {dst_ip}"
    return "OK"
```

### Detection Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    DoH Detection Strategy                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Layer 1: Endpoint-Level                                        │
│  ├─ Monitor processes making HTTPS connections to DoH IPs       │
│  ├─ Detect DoH client libraries loaded by suspicious processes  │
│  └─ Sysmon Event ID 3: Network connections to resolver IPs      │
│                                                                 │
│  Layer 2: Network-Level                                         │
│  ├─ Block/alert on connections to known DoH resolver IPs        │
│  ├─ TLS fingerprinting (JA3) for DoH client libraries           │
│  ├─ Traffic volume analysis to resolver endpoints               │
│  └─ SNI inspection for DoH resolver hostnames                   │
│                                                                 │
│  Layer 3: TLS Inspection (if available)                         │
│  ├─ Inspect for application/dns-message content type            │
│  ├─ Detect ?dns= query parameters in GET requests               │
│  ├─ Apply standard DNS tunneling detection to decrypted content │
│  └─ Entropy analysis on decoded DNS queries                     │
│                                                                 │
│  Layer 4: Policy-Based                                          │
│  ├─ Force all DNS through corporate resolvers (block external)  │
│  ├─ Block known DoH resolver IPs at the firewall                │
│  ├─ Deploy internal DoH resolver and whitelist only that        │
│  └─ GPO: Disable DoH in browsers and OS                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Detection & Evasion

### Detection Challenges

| Challenge | Why It's Hard | Mitigation |
|-----------|--------------|------------|
| Encrypted content | TLS prevents payload inspection | TLS inspection / endpoint monitoring |
| Legitimate destinations | Traffic goes to Google/Cloudflare | IP-based blocking of DoH resolvers |
| Standard HTTPS | Port 443, valid TLS, valid certs | JA3 fingerprinting, volume analysis |
| Browser support | Firefox/Chrome support DoH natively | GPO to disable browser DoH |
| Low volume | C2 needs minimal DNS queries | Baseline and anomaly detection |

### Detection Indicators

| Indicator | Detection Method |
|-----------|-----------------|
| Connections to DoH resolver IPs on port 443 | Firewall/proxy logs |
| SNI containing DoH resolver domains | TLS metadata inspection |
| Non-browser processes connecting to DoH IPs | Endpoint process monitoring |
| Elevated HTTPS traffic to resolver infrastructure | NetFlow analysis |
| JA3 fingerprint mismatch (non-browser TLS client) | JA3/JA3S analysis |
| DNS resolution not using corporate resolvers | DNS server logs (absence of queries) |

### Enterprise Mitigations

1. **Block DoH at the firewall**: Maintain list of DoH resolver IPs and block/alert
2. **Disable browser DoH**: GPO to disable DNS over HTTPS in Chrome/Firefox/Edge
3. **TLS inspection**: Decrypt and inspect HTTPS to known DoH endpoints
4. **Force corporate DNS**: All DNS must go through monitored corporate resolvers
5. **Canary domains**: Generate DNS queries for canary domains; if they don't appear in DNS logs, something is bypassing corporate DNS

## Cross-References

- [DNS C2 Implementation](dns-c2-implementation.md)
- [DNS C2 Theory](../../11-command-and-control/dns-c2.md)
- [Network Evasion](../../06-defense-evasion/network-evasion.md)
- [C2 Infrastructure Design](../../11-command-and-control/c2-infrastructure.md)

## References

- RFC 8484: DNS Queries over HTTPS (DoH)
- MITRE ATT&CK T1071.004 + T1573.002
- SANS: Detecting and Preventing DNS over HTTPS Abuse
- US-CERT: DNS over HTTPS Enterprise Considerations

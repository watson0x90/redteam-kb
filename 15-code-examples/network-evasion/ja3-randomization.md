# JA3 Randomization

MITRE ATT&CK: **T1071.001 -- Application Layer Protocol: Web Protocols** (evasion technique)

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

JA3 is a method for fingerprinting TLS clients by hashing specific fields from the TLS
ClientHello message. Because the ClientHello is sent **before** encryption is established,
it is visible to any network monitor on the path. Security tools use JA3 hashes to
identify known-malicious clients (e.g., Cobalt Strike, Sliver, Metasploit) without
decrypting traffic.

JA3 randomization defeats this detection by manipulating the ClientHello so that the
resulting hash either (a) changes on every connection, making static signatures useless,
or (b) exactly matches a legitimate browser, allowing the implant to blend in.

## How JA3 Hashing Works

```
 TLS ClientHello
 ┌─────────────────────────────────────────────────────┐
 │  TLS Version .................. e.g., 0x0303 (1.2)  │──┐
 │  Cipher Suites ............... ordered list          │  │
 │  Extensions .................. ordered list          │  ├── MD5 hash
 │  Elliptic Curves ............. (supported_groups)    │  │   = JA3
 │  EC Point Formats ............ (ec_point_formats)    │  │
 └─────────────────────────────────────────────────────┘──┘

 JA3 string format:
   TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats

 Example (Cobalt Strike default):
   769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
   MD5 -> 72a589da586844d7f0818ce684948eea
```

**Key insight**: The *order* of cipher suites and extensions matters for the hash, but
most TLS implementations accept them in any order. Shuffling the order changes the hash
without affecting the TLS negotiation outcome.

## Why Static JA3 Matters

| Tool | Default JA3 Hash | Risk |
|---|---|---|
| Cobalt Strike 4.x | `72a589da586844d7f0818ce684948eea` | Signatured by most NDR/IDS |
| Sliver (Go default) | `e35b83e61b22fc708966e2b86e2bac5c` | Increasingly signatured |
| Metasploit (Ruby) | `3e886a6867e8fb2d23ede1cc3d3e98c3` | Well-known |
| Python requests 2.x | `b386946a5a44d1ddcc843bc75336dfce` | Not malicious per se, but unusual for enterprise desktops |

A defender who sees any of these hashes on the wire can raise a high-confidence alert
before inspecting a single byte of decrypted traffic.

## Approach 1 -- Cipher Suite Shuffling

Randomize the order of offered cipher suites on every connection. The negotiated cipher
remains the same (the server picks the highest-priority match), but the JA3 hash changes.

```python
"""
Cipher suite shuffling via a custom SSLContext.
OPSEC: Shuffling alone produces hashes that may not match *any* known browser.
       Some NDR products flag "unknown JA3" just as aggressively as known-bad.
DETECTION: A client producing a different JA3 on every connection is itself
           an anomaly -- legitimate browsers have a stable JA3 per version.
"""
import ssl, random, socket

# Chrome 124 cipher suites.  OPSEC: Pull current values from a live packet
# capture rather than hard-coding an outdated list.
CHROME_CIPHERS = [
    "TLS_AES_128_GCM_SHA256",        "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",   "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",           "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",              "AES128-SHA",
    "AES256-SHA",
]

def make_shuffled_context() -> ssl.SSLContext:
    """Build SSLContext with randomized cipher order -- new JA3 each call."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # OPSEC: TLS 1.3 suites first -- browsers always do this.
    shuffled = CHROME_CIPHERS.copy()
    random.shuffle(shuffled)
    ctx.set_ciphers(":".join(shuffled))
    # DETECTION: Zeek/Suricata extract cipher order from ClientHello.
    return ctx

ctx = make_shuffled_context()
with socket.create_connection(("target.example.com", 443)) as sock:
    with ctx.wrap_socket(sock, server_hostname="target.example.com") as tls:
        tls.sendall(b"GET / HTTP/1.1\r\nHost: target.example.com\r\n\r\n")
        print(tls.recv(4096))
```

## Approach 2 -- Extension Ordering

Randomize the order of TLS extensions in the ClientHello. This requires lower-level
access to the handshake than Python's `ssl` module provides, so we use `scapy`.

```python
"""
TLS extension reordering using scapy.
OPSEC: scapy's TLS stack is partial; use it for ClientHello crafting only.
       In practice most operators use Go's uTLS (see below).  Extension
       reordering is valid per RFC 8446 Section 4.2.
DETECTION: Extensions in unusual positions (e.g., SNI not first) may
           trigger heuristic rules expecting browser-like ordering.
"""
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import (
    TLS_Ext_ServerName, TLS_Ext_SupportedVersions, TLS_Ext_SupportedGroups,
    TLS_Ext_SignatureAlgorithms, TLS_Ext_PSKKeyExchangeModes,
    TLS_Ext_ExtendedMasterSecret, TLS_Ext_SessionTicket,
)
import random

def build_randomized_client_hello(server_name: str) -> TLSClientHello:
    """Construct a ClientHello with randomized extension order."""
    extensions = [
        TLS_Ext_ServerName(servernames=[{"servername": server_name.encode()}]),
        TLS_Ext_SupportedVersions(versions=[0x0304, 0x0303]),
        TLS_Ext_SupportedGroups(groups=[0x001D, 0x0017, 0x0018]),
        TLS_Ext_SignatureAlgorithms(sig_algs=[
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601,
        ]),
        TLS_Ext_ExtendedMasterSecret(),
        TLS_Ext_SessionTicket(),
        TLS_Ext_PSKKeyExchangeModes(kxmodes=[0x01]),
    ]
    # OPSEC: Pin SNI at index 0 (middleboxes may require it first),
    # shuffle the rest.  Full randomization only if no middleboxes.
    sni_ext = extensions[0]
    rest = extensions[1:]
    random.shuffle(rest)
    extensions = [sni_ext] + rest

    return TLSClientHello(
        ciphers=[0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F,
                 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014],
        ext=extensions,
    )
    # DETECTION: Missing GREASE values signal a non-browser -- see Approach 3.
```

## Approach 3 -- GREASE Values

GREASE (Generate Random Extensions And Sustain Extensibility, RFC 8701) values are
reserved TLS code points that modern browsers insert into cipher suite lists, extension
lists, and other fields. Their purpose is to ensure servers and middleboxes tolerate
unknown values. Absence of GREASE in a ClientHello immediately identifies the client as
**not** a modern browser.

```python
"""
GREASE value injection (RFC 8701).
OPSEC: Chrome inserts 1 GREASE cipher + 1 GREASE extension; Firefox inserts 2
       of each.  Match target browser precisely.  Values outside the RFC set
       (0x0A0A..0xFAFA) are a detection signal.
DETECTION: Absence of GREASE = strong non-browser indicator.  GREASE in the
           wrong position is also flagged.
"""
import random

GREASE_VALUES = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
]

def inject_grease(cipher_list: list[int], extension_ids: list[int]):
    """Insert random GREASE values matching Chrome placement behavior."""
    # OPSEC: Browsers randomize the GREASE value per session.
    cipher_list.insert(0, random.choice(GREASE_VALUES))      # position 0
    extension_ids.insert(1, random.choice(GREASE_VALUES))    # after SNI
    return cipher_list, extension_ids
```

## Go Implementation -- uTLS Browser Mimicry

The `refraction-networking/utls` library provides the most mature implementation of TLS
fingerprint mimicry. It ships with presets that exactly reproduce the ClientHello of
specific browser versions.

```go
// uTLS-based JA3 mimicry in Go.
// OPSEC: uTLS presets are version-locked.  Mimic Chrome 120 but send
//   Chrome 124 User-Agent = mismatch detection.  Always align preset
//   with User-Agent and sec-ch-ua headers.
// DETECTION: JA3 matches Chrome but HTTP/2 SETTINGS frame differs,
//   or JA3 matches Chrome but no HTTP/2 ALPN negotiation occurs.
package main

import (
    "fmt"
    "io"
    "net"
    "net/http"
    tls "github.com/refraction-networking/utls"
)

func dialWithFingerprint(addr, sni string) (net.Conn, error) {
    tcpConn, err := net.Dial("tcp", addr)
    if err != nil { return nil, err }

    // OPSEC: HelloChrome_Auto tracks latest stable release.
    // Pin to HelloChrome_120 for a reproducible JA3.
    tlsConn := tls.UClient(tcpConn, &tls.Config{ServerName: sni},
        tls.HelloChrome_120)
    if err := tlsConn.Handshake(); err != nil {
        tcpConn.Close()
        return nil, fmt.Errorf("TLS handshake failed: %w", err)
    }
    return tlsConn, nil
}

func main() {
    conn, _ := dialWithFingerprint("target.example.com:443", "target.example.com")
    defer conn.Close()
    // OPSEC: This bypasses Go's default HTTP transport (own TLS stack).
    // You must manually handle HTTP/2 framing if ALPN negotiates h2.
    req, _ := http.NewRequest("GET", "https://target.example.com/", nil)
    req.Header.Set("User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "+
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    // DETECTION: HTTP/2 ALPN negotiated but HTTP/1.1 frames sent = signal.
    _ = req.Write(conn)
    buf := make([]byte, 4096)
    n, _ := io.ReadFull(conn, buf)
    fmt.Println(string(buf[:n]))
}
```

## JA3S -- Server-Side Fingerprinting

JA3S hashes the **ServerHello** the same way JA3 hashes the ClientHello. If your C2
server always responds with an identical ServerHello (same TLS version, cipher, and
extensions), its JA3S hash becomes a stable fingerprint that defenders can track.

```
 ServerHello fields hashed for JA3S:
   TLSVersion, CipherSuite, Extensions

 Mitigation:
 - Rotate the selected cipher suite by configuring the server to prefer
   different suites on a schedule.
 - Use a standard web server (nginx, Caddy) as a TLS terminator in front
   of the C2.  Its JA3S will match millions of other websites.
```

OPSEC: Placing nginx in front of your C2 and serving a generic default page on `/`
makes the JA3S -- and the server's broader fingerprint -- indistinguishable from a
legitimate website. See [C2 Infrastructure](../../11-command-and-control/c2-infrastructure.md).

## HTTP/2 Fingerprinting (Akamai Fingerprint)

TLS fingerprinting is only one layer. HTTP/2 introduces a second fingerprinting surface:

```
 HTTP/2 SETTINGS frame fields:
   HEADER_TABLE_SIZE       (default 4096)
   ENABLE_PUSH             (0 or 1)
   MAX_CONCURRENT_STREAMS  (browser-specific)
   INITIAL_WINDOW_SIZE     (browser-specific)
   MAX_FRAME_SIZE          (default 16384)
   MAX_HEADER_LIST_SIZE    (browser-specific)

 + WINDOW_UPDATE frame value
 + Pseudo-header order (:method, :authority, :scheme, :path)
 + Priority frames (Chrome uses PRIORITY; Firefox does not)
```

A mismatch between the JA3 (which says "this is Chrome") and the HTTP/2 settings frame
(which says "this is a Go net/http client") is a high-confidence detection signal.

```python
# OPSEC: If using Python httpx or Go net/http for HTTP/2, their default
# SETTINGS frame values differ from browsers.  You must override:
#
#   HEADER_TABLE_SIZE      = 65536   (Chrome default)
#   MAX_CONCURRENT_STREAMS = 1000    (Chrome default)
#   INITIAL_WINDOW_SIZE    = 6291456 (Chrome default)
#   MAX_HEADER_LIST_SIZE   = 262144  (Chrome default)
#
# Then send a WINDOW_UPDATE of 15663105 on stream 0 (Chrome behavior).
#
# DETECTION: Akamai's HTTP/2 fingerprint database catalogs known browser
# settings.  Any deviation from the expected profile for the claimed
# User-Agent is flagged.
```

## Detection Indicators

| Indicator | Data Source | Detection Logic |
|---|---|---|
| Known-bad JA3 hash | Zeek `ssl.log`, Suricata `tls` event | Lookup JA3 hash against threat intel feeds (ja3er.com, abuse.ch) |
| JA3 / User-Agent mismatch | Zeek `ssl.log` + `http.log` correlation | JA3 indicates Chrome but User-Agent says Python-requests or curl |
| JA3 / HTTP/2 fingerprint mismatch | Custom Zeek script or Akamai logs | JA3 matches Chrome 120, but HTTP/2 SETTINGS frame matches Go stdlib |
| Absent GREASE values | Zeek `ssl.log` with extended fields | ClientHello cipher suite list and extension list contain no GREASE values; all modern browsers include GREASE |
| JA3 entropy anomaly | SIEM correlation | Same source IP produces N distinct JA3 hashes in T minutes; legitimate clients have stable JA3 per application version |
| TLS negotiation timing anomaly | Network TAP with packet timestamps | Custom TLS stacks (scapy, uTLS with random delays) may exhibit microsecond-level timing patterns that differ from browser TLS implementations |
| JA3S consistency for C2 server | Zeek `ssl.log` on outbound connections | All connections to a specific IP produce the same JA3S hash, which maps to a known C2 framework |
| ClientHello size anomaly | Packet capture analysis | Unusually small or large ClientHello (missing extensions or excessive padding) compared to expected browser baseline |

## Cross-References

- [Network Evasion Techniques](../../06-defense-evasion/network-evasion.md) -- broader
  context for network-layer evasion including protocol tunneling, traffic shaping, and
  encrypted channel abuse.
- [C2 Infrastructure](../../11-command-and-control/c2-infrastructure.md) -- how JA3
  mimicry integrates with redirector chains, domain fronting, and malleable C2 profiles.
- [Domain Fronting](domain-fronting.md) -- complementary technique; domain fronting hides
  the destination while JA3 randomization hides the client identity. Best used together.

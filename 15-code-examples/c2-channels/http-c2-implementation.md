# HTTP/S C2 Beaconing - Educational Protocol Analysis

> **MITRE ATT&CK**: T1071.001 - Application Layer Protocol: Web Protocols
> **Purpose**: Understanding HTTP C2 patterns for detection engineering
> **Detection Priority**: High - Most common C2 channel in real-world attacks

## Strategic Overview

HTTP/HTTPS is the most common C2 protocol because web traffic is universally allowed, blends with legitimate browsing, and provides high bandwidth. Understanding the structural patterns of HTTP C2 communication is essential for detection engineering.

### Why This Matters for Red Team Leads
- HTTP/S is the default C2 channel for most frameworks (Cobalt Strike, Sliver, Mythic)
- Malleable C2 profiles allow traffic to mimic legitimate applications
- TLS encryption protects payload content from inspection
- JA3/JA3S fingerprinting provides a detection vector even with encryption

### Detection Opportunity
HTTP C2 creates **behavioral patterns** (beaconing, check-in structure, response patterns) that are detectable through traffic analysis even when content is encrypted.

## Technical Deep-Dive

### HTTP C2 Communication Model

```
┌──────────┐                          ┌──────────┐
│  Implant │                          │ C2 Server│
│ (Beacon) │                          │(Teamsvr) │
│          │ ──── GET /status ───────> │          │  1. Check-in (beacon)
│          │ <─── 200 OK (no task) ──  │          │
│          │                          │          │
│          │     [sleep interval]     │          │  2. Sleep (jitter)
│          │                          │          │
│          │ ──── GET /status ───────> │          │  3. Check-in again
│          │ <─── 200 OK (task) ─────  │          │  4. Receive task
│          │                          │          │
│          │ ──── POST /results ────>  │          │  5. Return results
│          │ <─── 200 OK ────────────  │          │
└──────────┘                          └──────────┘

Key Behavioral Patterns (Detectable):
- Regular check-in intervals (beaconing)
- Consistent URI patterns
- Small requests, potentially large responses (asymmetric)
- Cookie/header-based session tracking
- User-Agent consistency across sessions
```

### Beaconing Detection Analysis (Python)

```python
"""
Educational: HTTP C2 beaconing detection through traffic analysis.
This demonstrates how defenders identify C2 traffic by analyzing
timing patterns, even when content is encrypted.

These detection techniques are used by tools like:
- RITA (Real Intelligence Threat Analytics)
- Zeek + custom scripts
- Elastic Security beacon detection
"""
import math
import statistics
from collections import defaultdict
from typing import List, Tuple

# === BEACON DETECTION ALGORITHMS ===

def detect_beaconing(connections: List[dict], threshold: float = 0.15) -> dict:
    """
    Detect beaconing behavior from connection metadata.

    Algorithm: Calculate coefficient of variation (CV) for inter-arrival
    times between connections from same src to same dst.

    Detection Logic:
    - Regular beaconing: CV < 0.1 (very consistent intervals)
    - Jittered beaconing: CV 0.1 - 0.3 (still detectable pattern)
    - Normal browsing: CV > 0.5 (irregular, human-driven)

    Parameters:
        connections: List of {'timestamp': float, 'src': str, 'dst': str, ...}
        threshold: CV threshold below which traffic is flagged as beaconing
    """
    # Group connections by src-dst pair
    pairs = defaultdict(list)
    for conn in sorted(connections, key=lambda x: x['timestamp']):
        key = (conn['src'], conn['dst'])
        pairs[key].append(conn['timestamp'])

    results = []
    for (src, dst), timestamps in pairs.items():
        if len(timestamps) < 10:  # Need sufficient samples
            continue

        # Calculate inter-arrival times
        intervals = [timestamps[i+1] - timestamps[i]
                     for i in range(len(timestamps)-1)]

        avg = statistics.mean(intervals)
        if avg == 0:
            continue

        std = statistics.stdev(intervals)
        cv = std / avg  # Coefficient of variation

        result = {
            'src': src,
            'dst': dst,
            'connection_count': len(timestamps),
            'avg_interval_sec': round(avg, 2),
            'std_dev': round(std, 2),
            'coeff_variation': round(cv, 4),
            'duration_hours': round((timestamps[-1] - timestamps[0]) / 3600, 2),
            'is_beaconing': cv < threshold,
        }

        # Classify beacon type
        if cv < 0.05:
            result['beacon_type'] = 'FIXED_INTERVAL (very suspicious)'
        elif cv < 0.15:
            result['beacon_type'] = 'LOW_JITTER (likely C2)'
        elif cv < 0.30:
            result['beacon_type'] = 'MODERATE_JITTER (investigate)'
        else:
            result['beacon_type'] = 'IRREGULAR (likely normal)'

        results.append(result)

    return sorted(results, key=lambda x: x['coeff_variation'])


def analyze_uri_patterns(requests: List[dict]) -> dict:
    """
    Detect consistent URI patterns indicative of C2 check-ins.

    C2 frameworks often use:
    - Fixed URIs: /api/v1/status, /updates/check
    - Rotating URIs from a small set: /page1, /page2, /page3
    - Parameterized URIs: /content?id={session_id}

    Normal browsing has high URI diversity with low repetition.
    """
    uri_counts = defaultdict(int)
    for req in requests:
        uri_counts[req.get('uri', '/')] += 1

    total = len(requests)
    unique_uris = len(uri_counts)
    top_uri_pct = max(uri_counts.values()) / total * 100 if total > 0 else 0

    return {
        'total_requests': total,
        'unique_uris': unique_uris,
        'uri_diversity': round(unique_uris / max(total, 1), 4),
        'top_uri': max(uri_counts, key=uri_counts.get),
        'top_uri_percentage': round(top_uri_pct, 1),
        'suspicious': top_uri_pct > 50,  # Same URI > 50% of time
        'verdict': 'SUSPICIOUS: Low URI diversity' if unique_uris < 5 and total > 20
                   else 'NORMAL: High URI diversity',
    }


# === JA3 FINGERPRINT ANALYSIS ===

def explain_ja3():
    """
    JA3/JA3S fingerprinting explanation for detection.

    JA3 creates a fingerprint from the TLS ClientHello:
    - TLS version
    - Cipher suites offered
    - Extensions
    - Elliptic curves
    - Elliptic curve point formats

    Detection Value:
    - Each TLS client library has a unique JA3 hash
    - C2 implants often use non-browser TLS libraries
    - A process claiming to be Chrome but with a non-Chrome JA3 = suspicious
    - JA3S fingerprints the server's ServerHello
    """
    known_ja3 = {
        'Chrome (Windows)':  'cd08e31494816f6d2f3f5d7a24dc80d2',
        'Firefox (Windows)': '47eca3b31d15e5bdf2e1daeab5e04c76',
        'Cobalt Strike':     '72a589da586844d7f0818ce684948eea',
        'Metasploit':        'a0e9f5d64349fb13191bc781f81f42e1',
        'Sliver (default)':  '19e29534fd49dd27d09234e639c4057e',
        'Python requests':   'eb1d94daa7e0344597e756a1fb6e7054',
        'curl':              '456523fc94726331a4d5a2e1d40b2cd7',
    }

    print("=== JA3 Fingerprint Database (Examples) ===")
    for client, ja3_hash in known_ja3.items():
        print(f"  {client:25s} -> {ja3_hash}")

    print("\nDetection Rule: Alert when JA3 hash doesn't match")
    print("the claimed User-Agent. E.g., User-Agent says Chrome")
    print("but JA3 hash matches Python requests library.")

explain_ja3()
```

### HTTP C2 Traffic Patterns (C - WinHTTP Client)

```c
/*
 * Educational: HTTP client communication patterns using WinHTTP.
 * This demonstrates the Windows API calls that C2 implants use
 * for HTTP communication, helping defenders understand:
 * 1. Which API calls to monitor (API hooking / ETW)
 * 2. What handle patterns indicate C2 activity
 * 3. How malleable profiles change traffic appearance
 *
 * BUILD: cl.exe /nologo /W3 http_demo.c /link winhttp.lib
 */
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

/*
 * WinHTTP vs WinINet API Selection
 *
 * WinHTTP: Designed for server-side/service HTTP.
 *   - Used by: Cobalt Strike (default), custom implants
 *   - Detection: winhttp.dll loaded by non-browser process
 *   - ETW Provider: Microsoft-Windows-WinHttp
 *
 * WinINet: Designed for client-side HTTP (IE/browser APIs).
 *   - Used by: Some implants for proxy-aware connections
 *   - Shares IE proxy settings automatically
 *   - Detection: wininet.dll usage patterns
 *   - ETW Provider: Microsoft-Windows-WinINet
 *
 * Detection Strategy: Monitor for winhttp.dll/wininet.dll
 * loaded by processes that aren't browsers or known HTTP clients.
 */

/* Demonstrate WinHTTP connection lifecycle */
void demonstrate_winhttp_flow(void) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    /*
     * Step 1: WinHttpOpen - Create session handle
     * The User-Agent string is a detection point.
     * C2 frameworks set this to mimic browsers.
     *
     * Detection: Non-standard or outdated User-Agents,
     * User-Agent that doesn't match the JA3 fingerprint
     */
    hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",  /* User-Agent */
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,               /* Use system proxy */
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0                                                /* Synchronous */
    );

    /*
     * Step 2: WinHttpConnect - Specify target server
     * Detection: Connections to unusual domains or IPs,
     * especially from processes that shouldn't make HTTP calls
     */
    if (hSession) {
        hConnect = WinHttpConnect(
            hSession,
            L"www.example.com",  /* Target host */
            INTERNET_DEFAULT_HTTPS_PORT,
            0
        );
    }

    /*
     * Step 3: WinHttpOpenRequest - Create request
     * URI path is where malleable C2 profiles operate
     *
     * Malleable C2 Example:
     * - Default: GET /beacon/check
     * - Malleable: GET /api/v2/updates/check (mimics legitimate API)
     */
    if (hConnect) {
        hRequest = WinHttpOpenRequest(
            hConnect,
            L"GET",                   /* HTTP method */
            L"/api/v2/status",        /* URI path */
            NULL,                      /* HTTP/1.1 */
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE        /* Use HTTPS */
        );
    }

    /*
     * Step 4: WinHttpSendRequest + WinHttpReceiveResponse
     * The request/response pattern creates the beacon timing
     * that detection algorithms analyze
     */
    if (hRequest) {
        /* Additional headers can be added for profile matching */
        WinHttpAddRequestHeaders(
            hRequest,
            L"Accept: application/json\r\n",
            -1,
            WINHTTP_ADDREQ_FLAG_ADD
        );

        BOOL bResult = WinHttpSendRequest(
            hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            0, 0
        );

        if (bResult) {
            WinHttpReceiveResponse(hRequest, NULL);

            /* Read response data */
            DWORD dwSize = 0, dwRead = 0;
            char buffer[4096];

            WinHttpQueryDataAvailable(hRequest, &dwSize);
            if (dwSize > 0 && dwSize < sizeof(buffer)) {
                WinHttpReadData(hRequest, buffer, dwSize, &dwRead);
                buffer[dwRead] = '\0';
                printf("Response (%lu bytes): %s\n", dwRead, buffer);
            }
        }
    }

    /* Cleanup - handle lifecycle is monitorable via ETW */
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
}

/*
 * Malleable C2 Profile Concepts
 *
 * Malleable profiles transform C2 traffic to mimic legitimate apps.
 * Key transformable elements:
 *
 * 1. URI paths:      /updates/check -> /api/v3/notifications
 * 2. Headers:        Custom headers mimicking CDN/API patterns
 * 3. Parameters:     Session data in cookies vs query params
 * 4. Body encoding:  Base64, JSON wrapping, GZIP
 * 5. Timing:         Sleep interval, jitter percentage
 * 6. HTTP method:    GET for check-in, POST for data return
 *
 * Detection: Profile-specific patterns can be signatured.
 * Research: Analyze Cobalt Strike .profile files on GitHub
 * for patterns used in the wild.
 */
```

## Detection & Evasion

### Detection Matrix

| Detection Layer | Technique | Effectiveness |
|----------------|-----------|---------------|
| **Network Flow** | Beaconing interval analysis (RITA) | High for fixed/low-jitter |
| **TLS Metadata** | JA3/JA3S fingerprinting | High for known C2 frameworks |
| **HTTP Metadata** | URI pattern analysis, header anomalies | Medium (malleable profiles) |
| **Proxy Logs** | Domain categorization, reputation | Medium (domain fronting bypasses) |
| **Endpoint** | Process -> network correlation | High (which process is beaconing?) |
| **Content** | TLS inspection + payload analysis | Very high (if TLS inspection available) |

### Beaconing Detection Rules

```
# Zeek: Log HTTP connections with timing data for RITA analysis
# RITA automatically detects beaconing from Zeek conn.log

# Suricata: Alert on known C2 framework User-Agents
alert http any any -> any any (msg:"Cobalt Strike Default UA"; \
    http.user_agent; content:"Mozilla/5.0 (compatible; MSIE 9.0"; \
    sid:1000020; rev:1;)

# Splunk: Beacon detection query
# index=proxy sourcetype=squid
# | stats count, avg(interval) as avg_int, stdev(interval) as std_int by src_ip, dst_host
# | eval cv = std_int / avg_int
# | where cv < 0.15 AND count > 50
# | sort cv
```

### Known Tools (Academic Reference)
- **Cobalt Strike**: Industry standard, malleable C2 profiles
- **Sliver**: Open-source, HTTP/S + mTLS + DNS + WireGuard
- **Mythic**: Framework with multiple HTTP-based agents
- **Havoc**: Modern C2 with HTTP/S support
- **Merlin**: HTTP/2 based C2 framework

## Cross-References

- [C2 Frameworks Comparison](../../11-command-and-control/c2-frameworks.md)
- [C2 Infrastructure Design](../../11-command-and-control/c2-infrastructure.md)
- [Network Evasion](../../06-defense-evasion/network-evasion.md)
- [Signature Evasion](../../06-defense-evasion/signature-evasion.md)

## References

- MITRE ATT&CK T1071.001 Documentation
- Salesforce: JA3 - A Method for Profiling TLS Clients
- ActiveCountermeasures: RITA Beacon Detection
- Cobalt Strike Malleable C2 Profile Reference

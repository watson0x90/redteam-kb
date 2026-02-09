# ICMP Covert Channel - Educational Protocol Analysis

> **MITRE ATT&CK**: T1095 - Non-Application Layer Protocol
> **Purpose**: Understanding ICMP abuse patterns for detection engineering
> **Detection Priority**: Medium - Requires deep packet inspection

## Strategic Overview

ICMP (Internet Control Message Protocol) covert channels hide data within the payload field of echo request/reply packets (ping). Since ICMP is a network management protocol often allowed through firewalls, attackers can abuse it to create a communication channel that blends with legitimate network monitoring traffic.

### Why This Matters for Red Team Leads
- ICMP is frequently allowed even in restricted networks
- Many organizations don't inspect ICMP payload content
- Low bandwidth but high stealth in certain environments
- Useful for initial connectivity checks and low-volume C2

### Detection Opportunity
ICMP tunneling creates detectable anomalies in packet size, frequency, and payload content.

## Technical Deep-Dive

### ICMP Protocol Structure

```c
/*
 * ICMP Echo Request/Reply Structure (RFC 792)
 * The Data field is where covert data is embedded.
 *
 * Normal ping behavior:
 * - Windows: sends 32 bytes of alphabet data ("abcdefghijklmnop...")
 * - Linux: sends timestamp + incrementing pattern
 * - Fixed, predictable payload content
 *
 * Covert channel indicators:
 * - Variable or unusual payload sizes
 * - High-entropy payload data
 * - Payload content doesn't match OS ping patterns
 */

#include <stdint.h>

/* ICMP Header (8 bytes) */
typedef struct {
    uint8_t  type;       /* 8 = Echo Request, 0 = Echo Reply */
    uint8_t  code;       /* 0 for echo request/reply */
    uint16_t checksum;   /* Internet checksum */
    uint16_t identifier; /* Used to match requests/replies */
    uint16_t sequence;   /* Sequence number */
    /* Variable-length data follows */
} ICMP_HEADER;

/* IP Header (20 bytes minimum, needed for raw sockets) */
typedef struct {
    uint8_t  ver_ihl;    /* Version (4) + IHL (5) */
    uint8_t  tos;        /* Type of Service */
    uint16_t total_len;  /* Total packet length */
    uint16_t ident;      /* Identification */
    uint16_t flags_frag; /* Flags + Fragment Offset */
    uint8_t  ttl;        /* Time to Live */
    uint8_t  protocol;   /* Protocol: 1 = ICMP */
    uint16_t checksum;   /* Header checksum */
    uint32_t src_addr;   /* Source IP */
    uint32_t dst_addr;   /* Destination IP */
} IP_HEADER;

/*
 * ICMP Checksum Calculation
 * Required for valid ICMP packets - same algorithm as IP checksum.
 * Understanding this helps analysts validate packet integrity.
 */
uint16_t calculate_checksum(uint16_t *data, int length) {
    uint32_t sum = 0;
    while (length > 1) {
        sum += *data++;
        length -= 2;
    }
    if (length == 1) {
        sum += *(uint8_t *)data;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

/*
 * Payload Analysis for Detection
 *
 * Expected Windows ping payload (32 bytes):
 * 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70
 * 71 72 73 74 75 76 77 61 62 63 64 65 66 67 68 69
 * ("abcdefghijklmnopqrstuvwabcdefghi")
 *
 * Expected Linux ping payload: 8-byte timestamp + incrementing bytes
 *
 * Covert channel payload: random/encrypted data, high entropy
 *
 * Detection Rule: Flag ICMP echo packets where payload does NOT
 * match known OS ping patterns.
 */
```

### ICMP Packet Construction and Analysis (Python)

```python
"""
Educational: ICMP packet structure analysis for security research.
Demonstrates packet construction and payload analysis concepts
for building detection capabilities.

NOTE: Raw socket operations require elevated privileges.
This is for authorized security testing environments only.
"""
import struct
import socket
import os

# === ICMP PACKET ANALYSIS ===

def parse_icmp_packet(raw_data: bytes) -> dict:
    """
    Parse an ICMP packet for analysis.

    Detection Use Case: Security analysts can use this
    to identify anomalous ICMP payloads in packet captures.
    """
    if len(raw_data) < 28:  # Min IP (20) + ICMP header (8)
        return {'error': 'Packet too small'}

    # Parse IP header
    ip_header = raw_data[:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

    # Parse ICMP header (starts at byte 20)
    icmp_header = raw_data[20:28]
    icmp_type, code, checksum, ident, seq = struct.unpack('!BBHHH', icmp_header)

    # Extract payload
    payload = raw_data[28:]

    return {
        'src_ip': socket.inet_ntoa(iph[8]),
        'dst_ip': socket.inet_ntoa(iph[9]),
        'icmp_type': icmp_type,  # 8=request, 0=reply
        'code': code,
        'identifier': ident,
        'sequence': seq,
        'payload_size': len(payload),
        'payload_hex': payload[:32].hex(),  # First 32 bytes
        'payload_entropy': calculate_payload_entropy(payload),
    }


def calculate_payload_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of ICMP payload.

    Detection Thresholds:
    - Windows ping payload: ~4.0 entropy (repeating alphabet)
    - Linux ping payload:   ~4.5 entropy (timestamp + pattern)
    - Covert channel:       ~7.0+ entropy (encrypted/random data)
    - Threshold alert:      entropy > 6.0 warrants investigation
    """
    import math
    from collections import Counter

    if not data:
        return 0.0

    freq = Counter(data)
    length = len(data)
    entropy = -sum((count/length) * math.log2(count/length)
                   for count in freq.values())
    return round(entropy, 3)


# === DETECTION PATTERN ANALYSIS ===

def is_standard_ping_payload(payload: bytes) -> dict:
    """
    Check if ICMP payload matches known OS ping patterns.

    This is a practical detection function that can be integrated
    into network monitoring systems.
    """
    result = {
        'matches_windows': False,
        'matches_linux': False,
        'suspicious': False,
        'reason': ''
    }

    # Windows ping: repeating "abcdefghijklmnopqrstuvwabcdefghi"
    windows_pattern = b'abcdefghijklmnopqrstuvwabcdefghi'
    if payload[:32] == windows_pattern[:len(payload[:32])]:
        result['matches_windows'] = True
        return result

    # Linux ping: 8-byte timestamp followed by incrementing bytes
    # Bytes 9+ follow pattern: 0x10, 0x11, 0x12, ...
    if len(payload) > 16:
        expected = bytes(range(0x10, 0x10 + len(payload[8:])))
        if payload[8:] == expected[:len(payload[8:])]:
            result['matches_linux'] = True
            return result

    # If neither pattern matches, flag as suspicious
    entropy = calculate_payload_entropy(payload)
    result['suspicious'] = True
    result['reason'] = f'Non-standard payload (entropy: {entropy:.2f})'
    if entropy > 6.0:
        result['reason'] += ' - HIGH ENTROPY: likely encrypted/encoded data'

    return result


# === SIZE ANOMALY DETECTION ===

NORMAL_PING_SIZES = {
    'windows_default': 32,
    'linux_default': 56,
    'common_sizes': {32, 56, 64, 128},
}

def check_size_anomaly(payload_size: int) -> str:
    """
    Flag unusual ICMP payload sizes.

    Normal pings use standard sizes. Covert channels often use
    variable sizes to accommodate different data lengths.
    """
    if payload_size in NORMAL_PING_SIZES['common_sizes']:
        return f"NORMAL: {payload_size} bytes (standard ping size)"
    elif payload_size > 1400:
        return f"ALERT: {payload_size} bytes (near MTU, possible tunnel)"
    elif payload_size > 256:
        return f"WARNING: {payload_size} bytes (larger than typical ping)"
    elif payload_size == 0:
        return f"SUSPICIOUS: {payload_size} bytes (empty payload)"
    else:
        return f"UNUSUAL: {payload_size} bytes (non-standard size)"


# === FREQUENCY ANALYSIS ===

def analyze_icmp_frequency(timestamps: list) -> dict:
    """
    Analyze ICMP timing patterns for covert channel detection.

    Normal pings: regular 1-second intervals (ping -t), short burst
    Covert channels: sustained sessions, irregular intervals, or
    very rapid exchanges
    """
    if len(timestamps) < 2:
        return {'pattern': 'insufficient data'}

    intervals = [timestamps[i+1] - timestamps[i]
                 for i in range(len(timestamps)-1)]

    avg_interval = sum(intervals) / len(intervals)
    duration = timestamps[-1] - timestamps[0]

    result = {
        'total_packets': len(timestamps),
        'duration_seconds': round(duration, 2),
        'avg_interval_ms': round(avg_interval * 1000, 2),
        'packets_per_second': round(len(timestamps) / max(duration, 0.001), 2),
    }

    # Detection heuristics
    if duration > 300 and len(timestamps) > 100:
        result['alert'] = 'SUSPICIOUS: Sustained ICMP session (>5min, >100 packets)'
    elif avg_interval < 0.1:
        result['alert'] = 'SUSPICIOUS: Rapid ICMP exchange (<100ms intervals)'

    return result
```

### Detection Indicators Summary

```
Detection Checklist for ICMP Covert Channels:
═══════════════════════════════════════════════

□ Payload Content Analysis
  ├─ Does payload match Windows/Linux ping patterns?
  ├─ Shannon entropy > 6.0?
  └─ Contains printable ASCII or structured data?

□ Size Anomalies
  ├─ Payload size varies between packets?
  ├─ Payload larger than 128 bytes?
  └─ Payload size near MTU (1472 bytes)?

□ Frequency Anomalies
  ├─ Sustained ICMP sessions (>5 minutes)?
  ├─ High packet rate (>10 pps)?
  └─ Regular intervals suggesting automation?

□ Directional Analysis
  ├─ Large reply payloads (commands coming back)?
  ├─ Asymmetric request/reply sizes?
  └─ Data only in one direction?

□ Network Context
  ├─ ICMP to external IPs from servers?
  ├─ ICMP from hosts that don't normally ping?
  └─ ICMP to unusual destinations?
```

## Detection & Evasion

### Defender Visibility

| Data Source | Detection Capability |
|-------------|---------------------|
| Firewall logs | ICMP allow/deny, packet counts, sizes |
| IDS/IPS | Payload inspection, signature matching |
| Zeek/Bro | ICMP session tracking, payload logging |
| Wireshark | Deep packet analysis, entropy visualization |
| Sysmon | Process creating raw sockets (Event ID 3) |
| NetFlow | ICMP flow volume and duration anomalies |

### Suricata Detection Rules

```
# Alert on ICMP echo with large payload
alert icmp any any -> any any (msg:"ICMP Tunnel - Large Payload"; \
    itype:8; dsize:>128; sid:1000010; rev:1;)

# Alert on high-frequency ICMP
alert icmp any any -> any any (msg:"ICMP Tunnel - High Frequency"; \
    itype:8; threshold:type both, track by_src, count 50, seconds 10; \
    sid:1000011; rev:1;)

# Alert on ICMP with high-entropy payload (requires preprocessor)
alert icmp any any -> any any (msg:"ICMP Tunnel - Non-standard Payload"; \
    itype:8; dsize:>32; content:!"|61 62 63 64 65 66 67 68|"; depth:8; \
    sid:1000012; rev:1;)
```

### Known Tools (Academic Reference)
- **icmpsh**: Simple ICMP reverse shell
- **ptunnel/ptunnel-ng**: TCP-over-ICMP tunnel
- **icmptunnel**: IP-over-ICMP tunnel
- **Hans**: IP-over-ICMP VPN

## Cross-References

- [Covert Channels Theory](../../11-command-and-control/covert-channels.md)
- [Network Evasion](../../06-defense-evasion/network-evasion.md)
- [Exfiltration Channels](../../10-collection-and-exfiltration/exfiltration-channels.md)

## References

- RFC 792: Internet Control Message Protocol
- SANS Reading Room: Covert Channels over ICMP
- MITRE ATT&CK T1095 Documentation
- Ptunnel: Reliable TCP over ICMP (research paper)

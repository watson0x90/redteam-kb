# C2 Communication Channels - Educational Reference

> **Category**: Code Examples - Command & Control Protocols
> **Purpose**: Understanding C2 communication patterns for detection engineering
> **Languages**: C, Python
> **MITRE ATT&CK**: TA0011 (Command and Control)

## Section Overview

This section provides educational analysis of how various network protocols can be abused for command and control communication. Understanding these patterns is essential for:

- **Detection Engineering**: Building signatures and behavioral analytics
- **Threat Hunting**: Knowing what anomalous traffic patterns to search for
- **Purple Team Exercises**: Validating detection coverage

## Contents

| Topic | File | Protocols | Detection Difficulty | Description |
|-------|------|-----------|---------------------|-------------|
| DNS Tunneling | [dns-c2-implementation.md](dns-c2-implementation.md) | DNS (UDP/53) | Medium | Data encoding in DNS queries/responses |
| ICMP Channels | [icmp-c2-implementation.md](icmp-c2-implementation.md) | ICMP | Medium | Covert data in echo request/reply payloads |
| DNS-over-HTTPS | [doh-c2-implementation.md](doh-c2-implementation.md) | DoH (443) | High | DNS tunneling wrapped in HTTPS encryption |
| HTTP/S Beaconing | [http-c2-implementation.md](http-c2-implementation.md) | HTTP/HTTPS | Medium | Structured C2 over web protocols |
| Named Pipes | [named-pipe-c2.md](named-pipe-c2.md) | SMB/IPC | Low-Medium | Internal peer-to-peer via Windows IPC |

## Detection Strategy Summary

| Channel | Key Detection Indicators |
|---------|-------------------------|
| DNS | Query length > 50 chars, high entropy labels, unusual record types, query volume spikes |
| ICMP | Payload size anomalies, non-standard data content, session-like patterns |
| DoH | Connections to known DoH endpoints, TLS fingerprinting, traffic volume to resolver IPs |
| HTTP/S | Beaconing intervals, JA3/JA3S fingerprints, URI pattern regularity, header anomalies |
| Named Pipes | Unusual pipe names (Sysmon 17/18), pipe enumeration activity, SMB lateral patterns |

## Cross-References

- [C2 Frameworks Comparison](../../11-command-and-control/c2-frameworks.md)
- [C2 Infrastructure Design](../../11-command-and-control/c2-infrastructure.md)
- [DNS C2 Theory](../../11-command-and-control/dns-c2.md)
- [Covert Channels Theory](../../11-command-and-control/covert-channels.md)
- [Network Evasion](../../06-defense-evasion/network-evasion.md)

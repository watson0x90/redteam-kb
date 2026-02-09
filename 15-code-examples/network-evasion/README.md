# Network Evasion Code Examples

MITRE ATT&CK Mapping: TA0011 (Command and Control), TA0005 (Defense Evasion)

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

This section contains annotated code examples for network-layer evasion techniques
commonly encountered during red team engagements and threat emulation exercises. Each
file provides production-grade implementation patterns alongside detection guidance so
that both offensive and defensive practitioners can build deeper intuition about the
techniques.

Every example follows the same structure: conceptual explanation, implementation with
extensive inline commentary on OPSEC and detection surface, and a dedicated detection
indicators section that blue team members can use to build analytics.

## Table of Contents

| Topic | File | Languages | Detection Risk | Description |
|---|---|---|---|---|
| Domain Fronting | [domain-fronting.md](domain-fronting.md) | Python, Go | Medium-High | Abuse CDN edge-routing to hide C2 destinations behind high-reputation domains. Covers Cloudflare Workers, Azure CDN, and AWS CloudFront approaches with TLS-level analysis. |
| JA3 Randomization | [ja3-randomization.md](ja3-randomization.md) | Python, Go | Medium | Defeat TLS client fingerprinting by randomizing or mimicking browser JA3 hashes. Covers cipher suite shuffling, extension reordering, GREASE injection, and HTTP/2 fingerprint considerations. |

## Prerequisites

- Python 3.10+ with `requests`, `scapy`, and `cryptography` libraries
- Go 1.21+ with `refraction-networking/utls` module
- A test lab with TLS inspection capability (e.g., mitmproxy, Zeek, Suricata)
- Written authorization (scope document / rules of engagement) before any live testing

## Directory Context

These code examples support the narrative analysis in the following knowledge base files:

- [Network Evasion Techniques](../../06-defense-evasion/network-evasion.md) -- strategic
  overview of network-layer defense evasion, detection gaps, and countermeasures.
- [C2 Infrastructure](../../11-command-and-control/c2-infrastructure.md) -- architecture
  patterns for command-and-control channels including redirectors, CDN fronting, and
  domain categorization.

## How to Use These Examples

1. **Read the narrative first.** The files listed under Directory Context provide the
   strategic "why" behind each technique. Code examples here provide the tactical "how."
2. **Stand up a detection lab.** Run Zeek or Suricata alongside your test traffic so you
   can observe the exact artifacts each technique produces.
3. **Compare fingerprints.** Use tools like `ja3er.com` or Wireshark JA3 plugins to
   verify that your modified ClientHello actually produces the expected hash.
4. **Iterate on detection rules.** Each file ends with a Detection Indicators section --
   use those as starting points for Sigma or Suricata rules in your environment.

## Legal and Ethical Notice

All code in this directory is provided strictly for educational purposes and authorized
security testing. Unauthorized use of these techniques against systems you do not own or
have explicit written permission to test is illegal and unethical. Always operate under
a signed rules-of-engagement document and coordinate with the asset owner's security
operations team.

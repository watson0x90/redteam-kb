# Active Directory Attack Code Examples

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Purpose

This section provides annotated code implementations for core Active Directory attack
techniques. Each file pairs C and Python implementations with protocol-level explanations,
ASCII diagrams, and detailed detection/OPSEC notes. These are companion references to the
narrative deep-dives in [`../../12-active-directory-deep-dive/`](../../12-active-directory-deep-dive/).

## Contents

| Topic | File | Languages | Detection Risk | Description |
|---|---|---|---|---|
| Kerberoasting | [kerberoasting-implementation.md](kerberoasting-implementation.md) | C, Python | Medium | SPN enumeration, TGS-REQ construction, ticket extraction, and offline cracking workflow with RC4 vs AES downgrade analysis |
| AS-REP Roasting | [asrep-roasting.md](asrep-roasting.md) | C, Python | Medium-Low | Pre-authentication bypass, DONT_REQ_PREAUTH enumeration, AS-REQ/AS-REP flow, and hash extraction for offline attacks |
| DCSync | [dcsync-internals.md](dcsync-internals.md) | C, Python | High | MS-DRSR replication protocol internals, DRSGetNCChanges RPC flow, NTLM hash extraction from replicated data |
| AD CS Abuse | [adcs-abuse-code.md](adcs-abuse-code.md) | C, Python | Medium-High | Certificate template exploitation (ESC1-ESC8), CSR construction with alternate SAN, PKINIT authentication flow |

## How to Read These Files

Each file follows a consistent structure:

1. **MITRE ATT&CK mapping** -- links the technique to the framework
2. **Overview** -- concise description of what the technique does and why it matters
3. **Protocol deep-dive** -- ASCII diagrams showing the on-wire flow
4. **Code implementations** -- C and Python with inline comments on detection and OPSEC
5. **Detection indicators** -- specific events, log sources, and behavioral signatures
6. **Cross-references** -- links to narrative files and related techniques

## Detection Risk Ratings

- **Low**: Blends with normal traffic; few reliable signatures
- **Medium-Low**: Detectable with tuned rules but uncommon in default logging
- **Medium**: Standard SOC detections exist; requires OPSEC awareness
- **Medium-High**: Well-known signatures; most mature SOCs will flag
- **High**: Highly anomalous behavior; expect detection in monitored environments

## Related Narrative References

- [Kerberos Attacks Deep-Dive](../../12-active-directory-deep-dive/kerberos-attacks.md)
- [AD CS Attacks Deep-Dive](../../12-active-directory-deep-dive/adcs-attacks.md)
- [Active Directory Persistence](../../12-active-directory-deep-dive/ad-persistence.md)
- [Credential Access Techniques](../../12-active-directory-deep-dive/credential-access.md)

# Credential Access Code - Educational Reference

> **Category**: Code Examples - Credential Access Techniques
> **Purpose**: Understanding credential access mechanisms for detection engineering
> **Languages**: C, Python
> **MITRE ATT&CK**: T1134 (Token Manipulation), T1003.001 (LSASS Dumping), T1555.004 / T1555.003 (DPAPI / Browser Creds), T1003.002 (SAM Dump), T1558 (Kerberos Tickets)

## Section Overview

This section provides educational analysis of Windows credential access mechanisms at the code level. Understanding how credentials are stored and accessed is essential for:

- **Detection Engineering**: Building monitoring rules for credential theft
- **Incident Response**: Recognizing artifacts of credential access
- **Security Architecture**: Designing defenses like Credential Guard

## Contents

| Topic | File | Focus | Description |
|-------|------|-------|-------------|
| Token Manipulation | [token-manipulation.md](token-manipulation.md) | Access Tokens | Token architecture, enumeration, impersonation |
| MiniDump Analysis | [minidump-implementation.md](minidump-implementation.md) | LSASS | LSASS protection, dump format, detection |
| DPAPI Decryption | [dpapi-decryption.md](dpapi-decryption.md) | DPAPI / Browser Creds | DPAPI architecture, Chrome credential decryption chain, domain backup keys |
| SAM Registry Dump | [sam-registry-dump.md](sam-registry-dump.md) | SAM Database | SAM encryption hierarchy, BOOTKEY derivation, offline hash extraction |
| Kerberos Ticket Extraction | [kerberos-ticket-extraction.md](kerberos-ticket-extraction.md) | Kerberos Tickets | Ticket cache internals, kirbi/ccache formats, Pass-the-Ticket |

## Key Concepts

- **Access Tokens**: Security objects that define a user's privileges and group memberships
- **LSASS**: Local Security Authority Subsystem Service - stores credentials in memory
- **Credential Guard**: Virtualization-based isolation of credential material
- **PPL**: Protected Process Light - kernel-level protection for LSASS

## Cross-References

- [LSASS Dumping Theory](../../07-credential-access/lsass-dumping.md)
- [DCSync](../../07-credential-access/dcsync.md)
- [DPAPI Abuse](../../07-credential-access/dpapi-abuse.md)
- [Windows Internals Reference](../../appendices/windows-internals-reference.md)

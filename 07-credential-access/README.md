# Credential Access

This section covers the techniques used to steal credentials, tokens, and authentication material from compromised systems and infrastructure. Credential access is the engine that drives lateral movement and privilege escalation across the environment.

---

**Navigation:**
| Previous | Current | Next |
|----------|---------|------|
| [06 - Defense Evasion](../06-defense-evasion/README.md) | **07 - Credential Access** | [08 - Discovery](../08-discovery/README.md) |

**MITRE ATT&CK Tactic:** [TA0006 - Credential Access](https://attack.mitre.org/tactics/TA0006/)

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| LSASS Dumping | [lsass-dumping.md](lsass-dumping.md) | T1003.001 | Very High | Extracting credentials from the LSASS process using Mimikatz, comsvcs.dll, and other methods |
| SAM & LSA Secrets | [sam-lsa-secrets.md](sam-lsa-secrets.md) | T1003.002, T1003.004 | High | Dumping local SAM database hashes and LSA secrets including service account credentials |
| DCSync | [dcsync.md](dcsync.md) | T1003.006 | High | Simulating domain controller replication to extract password hashes remotely |
| DPAPI Abuse | [dpapi-abuse.md](dpapi-abuse.md) | T1555.004 | Medium | Decrypting Windows Data Protection API protected secrets including browser passwords and certificates |
| Kerberos Credential Attacks | [kerberos-credential-attacks.md](kerberos-credential-attacks.md) | T1558 | Medium | Kerberoasting, AS-REP Roasting, and ticket extraction for offline cracking |
| NTLM Theft | [ntlm-theft.md](ntlm-theft.md) | T1187 | Medium | Forcing NTLM authentication via .lnk files, .scf files, responder, and other coercion methods |
| Password Cracking | [password-cracking.md](password-cracking.md) | T1110.002 | N/A (Offline) | Hashcat and John the Ripper rules, wordlists, and methodology for offline hash cracking |
| Credential Stores | [credential-stores.md](credential-stores.md) | T1555 | Medium | Extracting credentials from browsers, vaults, key managers, and configuration files |
| Cloud Credential Access | [cloud-credential-access.md](cloud-credential-access.md) | T1528 | Medium | Stealing cloud tokens, service principal keys, metadata service credentials, and OAuth tokens |
| Credential Guard Bypass | [credential-guard-bypass.md](credential-guard-bypass.md) | T1003.001 | Medium-High | DumpGuard RCG protocol abuse, NativeBypassCredGuard WDigest patching, CVE-2025-21299/29809 Kerberos bypass |
| Linux Credential Access | [linux-credential-access.md](linux-credential-access.md) | T1003.008, T1552.001 | Medium | Shadow file, SSH agent hijacking, SSSD cache, GNOME Keyring, cloud credential files, history mining |
| macOS Credential Access | [macos-credential-access.md](macos-credential-access.md) | T1555.001, T1539 | Medium | Keychain extraction, TCC database, browser credentials, SSH keys, clipboard monitoring |

---

## Section Overview

Credential access is frequently the most impactful phase of an engagement because a single set of privileged credentials can unlock the entire domain. This section progresses from high-risk, high-reward techniques like LSASS dumping and DCSync to more subtle approaches like DPAPI abuse and NTLM coercion. LSASS dumping remains the gold standard for credential harvesting but is heavily monitored by modern EDR; operators must choose between direct process access, memory dump files, and more creative approaches like SSP loading or MiniDumpWriteDump callbacks. DCSync provides remote credential extraction without touching the target workstation but requires replication rights. Offline password cracking is covered as the complement to hash extraction, with guidance on rule-based attacks and targeted wordlist generation. Operators should map available credential material to their lateral movement plan and prioritize the credentials that advance toward engagement objectives.

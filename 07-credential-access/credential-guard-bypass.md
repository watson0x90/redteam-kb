# Credential Guard Bypass

> **MITRE ATT&CK**: Credential Access > T1003.001 - OS Credential Dumping: LSASS Memory
> **Platforms**: Windows 10/11, Windows Server 2016+
> **Required Privileges**: SYSTEM/Admin (NativeBypassCredGuard), varies (DumpGuard)
> **OPSEC Risk**: Medium-High

## Strategic Overview

Windows Credential Guard uses virtualization-based security (VBS) to isolate LSASS secrets in
a separate Virtual Trust Level (VTL 1), making traditional credential dumping ineffective.
However, 2025 research revealed multiple bypass techniques that undermine this protection.
DumpGuard (SpecterOps) extracts NTLMv1 hashes via the Remote Credential Guard RPC interface
without touching LSASS memory -- and Microsoft has stated they **will not patch** this issue.
NativeBypassCredGuard patches WDigest global variables to re-enable cleartext credential
caching. CVE-2025-21299 and CVE-2025-29809 bypass Credential Guard entirely through Kerberos
canonicalization flaws that cause TGTs to be stored in unprotected LSASS memory instead of the
isolated VTL. These findings significantly impact the defensive value of Credential Guard and
are critical knowledge for both red team operators and defenders assessing their credential
protection posture.

---

## Technical Deep-Dive

### DumpGuard -- RCG Protocol Credential Extraction

```
# DumpGuard (SpecterOps, October 2025)
# Extracts NTLMv1 hashes by abusing Remote Credential Guard (RCG) protocol
# Does NOT touch LSASS memory, does NOT require admin for basic attack
# Microsoft response: "Will not service this issue" (September 24, 2025)

# How it works:
# 1. RCG exposes an RPC interface (NtlmCredIsoRemote) that communicates
#    with either Credential Guard isolated NTLM or standard in-process NTLM
# 2. DumpGuard simulates a remote host connection using a machine account
#    by performing the Terminal Services SSP (TS SSP) flow
# 3. The RCG protocol returns AuthInfo with supplemental credentials
#    as MSV1_0_REMOTE_SUPPLEMENTAL_CREDENTIAL
# 4. Tool forges MSV1_0_REMOTE_ENCRYPTED_SECRETS and passes it to
#    NtlmCalculateNtResponse with a static (known) challenge
# 5. Resulting NTLMv1 response to known challenge can be cracked offline

# Attack paths:
# Unprivileged: Extracts NTLMv1 response for CURRENT USER (no elevation)
# Privileged:   Targets ANY logged-in user session

# Key advantages:
# - No LSASS memory access
# - No process injection
# - No suspicious API calls
# - Works whether Credential Guard is enabled OR disabled
# - Evades most EDR detections

# BOF port available: github.com/0xedh/dumpguard_bof (Cobalt Strike)
```

### NativeBypassCredGuard -- WDigest Memory Patching

```powershell
# NativeBypassCredGuard (Ricardo Joserf)
# Patches two global variables in wdigest.dll within LSASS process
# Uses exclusively NTAPI functions from ntdll.dll

# Target variables in wdigest.dll:
# g_fParameter_UseLogonCredential -> patched to 1 (enable cleartext caching)
# g_IsCredGuardEnabled            -> patched to 0 (disable CG flag in WDigest)

# Attack flow:
# 1. Locate byte signature pattern in on-disk wdigest.dll to calculate offsets
# 2. Resolve wdigest.dll base address in LSASS process
# 3. Compute absolute in-memory addresses of the two globals
# 4. Patch g_fParameter_UseLogonCredential to 1
# 5. Patch g_IsCredGuardEnabled to 0
# 6. Wait for user logon (or force lock/unlock)
# 7. Standard LSASS dump reveals cleartext passwords

# Key advantage: Uses only NTAPI functions, can optionally remap ntdll.dll
# from disk to bypass user-mode EDR hooks

# Requires: Administrative/SYSTEM privileges
# Requires: Subsequent user logon after patching for credentials to be cached

# Available in C# and C++ implementations
# github.com/ricardojoserf/NativeBypassCredGuard
```

### Related Tools in the CredGuard Bypass Lineage

```
# Historical evolution of Credential Guard bypass:
# 2020: @N4k3dTurtl3 (Team Hydra) -- original WDigest patching concept
# 2021: wh0amitz (BypassCredGuard) -- github.com/wh0amitz/BypassCredGuard
# 2022: itm4n (CredGuardBypassOffsets) -- detailed analysis + offset calculator
# 2023: WdToggle (Cobalt Strike BOF) -- operational BOF for CG bypass
# 2024: EDRSandblast -- integrates CG bypass with broader EDR evasion
# 2025: NativeBypassCredGuard -- NTAPI-only, hook-resilient implementation
# 2025: DumpGuard -- paradigm shift: RCG protocol abuse, no LSASS access
```

### CVE-2025-21299 & CVE-2025-29809 -- Kerberos Canonicalization Bypass

```
# Discovered by NetSPI researchers
# Bypasses Credential Guard via Kerberos TGT service name manipulation

# How Credential Guard protects Kerberos TGTs:
# - TGTs are stored in Isolated LSA (IUM) in VTL 1
# - KerbClientShared.dll validates the "krbtgt" service name in the TGT
# - If the name matches "krbtgt", the TGT goes to protected IUM storage
# - Otherwise, it stays in regular LSASS memory

# The vulnerability (CVE-2025-21299):
# KerbGetFlagsForKdcReply function's validation was insufficient
# Using X500 (LDAP DN) formatting of the krbtgt principal bypassed the check:
#   Normal:  krbtgt/DOMAIN.LOCAL
#   Bypass:  CN=krbtgt,CN=Users,DC=domain,DC=com
# The function fails to recognize X500-formatted name as "krbtgt"
# TGT stored in regular LSASS memory instead of IUM

# Once TGT is unprotected in LSASS:
# Standard credential dumping tools (Mimikatz, Rubeus) can extract it

# CVE-2025-29809 (bypass of the initial fix):
# After January 2025 patch, researchers found a second bypass
# CVSS 7.1 (HIGH) -- Local, Low Privileges, Low Complexity
# Fixed in April 2025 Patch Tuesday

# The fix:
# KerbGetFlagsForKdcReply updated to:
# 1. Check for X500 formatting of krbtgt principal name
# 2. Normalize distinguished names by removing character escaping
# 3. Perform comparison after normalization

# Timeline:
# Feb 21, 2025: CVE-2025-21299 reported to MSRC
# Jan 2025:     Initial fix deployed (Patch Tuesday)
# Feb 25, 2025: Bypass of initial fix confirmed
# Apr 2025:     CVE-2025-29809 fix deployed (Patch Tuesday)
```

---

## Detection & Evasion

### What Defenders See

| Technique | Detection Surface |
|-----------|------------------|
| DumpGuard | RPC calls to NtlmCredIsoRemote interface; TS SSP flow anomalies; minimal -- Microsoft won't patch |
| NativeBypassCredGuard | LSASS memory writes; ntdll remapping from disk; SeDebugPrivilege usage |
| CVE-2025-21299/29809 | Kerberos TGT requests with X500-formatted principal names (patched) |
| WdToggle BOF | BOF execution artifacts; wdigest.dll memory modifications |

### Evasion Considerations

- DumpGuard produces almost no detectable artifacts -- no LSASS access, no injection
- NativeBypassCredGuard uses only NTAPI to avoid EDR hooks on Win32 APIs
- Credential caching via WDigest patch is passive -- credentials appear on next logon
- DumpGuard BOF integrates directly into Cobalt Strike for operational deployment

### Defensive Recommendations

```
# Patching:
1. Apply April 2025 Patch Tuesday for CVE-2025-29809
2. Ensure January 2025 patches applied for CVE-2025-21299

# Monitoring:
3. Monitor for writes to wdigest.dll memory regions in LSASS
4. Alert on SeDebugPrivilege token adjustment for non-admin processes
5. Monitor for NTDLL remapping (new file mapping to ntdll from disk)
6. Audit RPC connections to NtlmCredIsoRemote interface

# Hardening:
7. Enable Credential Guard with UEFI lock (prevents runtime disabling)
8. Use Windows Defender Credential Guard with hardware-backed isolation
9. Implement LSASS as a Protected Process Light (PPL)
10. Deploy additional LSASS protections: RunAsPPL + Windows Defender for LSASS
11. Restrict interactive logons to minimize credential caching opportunities
12. Consider phasing out NTLM entirely (eliminates DumpGuard attack surface)

# Note: DumpGuard has NO PATCH and NO PLANNED FIX from Microsoft
# The only mitigation is NTLM deprecation or restricting RCG protocol access
```

---

## Cross-References

- **LSASS Dumping** (07-credential-access/lsass-dumping.md) -- Traditional LSASS dumping techniques that Credential Guard is designed to prevent
- **Kerberos Credential Attacks** (07-credential-access/kerberos-credential-attacks.md) -- TGT extraction enabled by CVE-2025-21299/29809
- **NTLM Theft** (07-credential-access/ntlm-theft.md) -- NTLMv1 hashes extracted by DumpGuard
- **AV/EDR Evasion** (06-defense-evasion/av-edr-evasion.md) -- NTAPI-only approach to bypass hooks
- **Windows Internals Reference** (appendices/windows-internals-reference.md) -- VBS, VTL, LSASS architecture

---

## References

- SpecterOps: Catching Credential Guard Off Guard: https://specterops.io/blog/2025/10/23/catching-credential-guard-off-guard/
- DumpGuard: https://github.com/bytewreck/DumpGuard
- DumpGuard BOF: https://github.com/0xedh/dumpguard_bof
- NativeBypassCredGuard: https://github.com/ricardojoserf/NativeBypassCredGuard
- NetSPI: CVE-2025-21299 & CVE-2025-29809: https://www.netspi.com/blog/technical-blog/adversary-simulation/cve-2025-21299-cve-2025-29809-unguarding-microsoft-credential-guard/
- itm4n: Revisiting a Credential Guard Bypass: https://itm4n.github.io/credential-guard-bypass/
- MITRE ATT&CK T1003.001: https://attack.mitre.org/techniques/T1003/001/

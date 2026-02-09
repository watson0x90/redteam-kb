# Data Destruction Simulation

> **MITRE ATT&CK**: Impact > T1485 - Data Destruction
> **Platforms**: Windows / Linux
> **Required Privileges**: Admin / SYSTEM / root
> **OPSEC Risk**: Critical (simulation only -- NEVER execute destructively)

---

## Strategic Overview

Wiper attack simulation tests organizational resilience against **destructive** threat
actors whose goal is not financial gain but operational disruption or destruction.
Nation-state actors (Russia, Iran, DPRK) have repeatedly deployed wipers against
critical infrastructure, government, and private sector targets.

### Real-World Wiper Campaigns

| Wiper          | Year  | Attribution   | Target                | Technique                        |
|----------------|-------|---------------|-----------------------|----------------------------------|
| Shamoon        | 2012  | Iran (APT33)  | Saudi Aramco          | MBR overwrite + file destruction |
| NotPetya       | 2017  | Russia (Sandworm) | Ukraine (global spread) | MBR + MFT encryption (no recovery) |
| Olympic Destroyer | 2018 | Russia (Sandworm) | Pyeongchang Olympics | Credential theft + wiper deployment |
| WhisperGate    | 2022  | Russia         | Ukraine government    | MBR overwrite + file corruptor   |
| HermeticWiper  | 2022  | Russia         | Ukraine infrastructure| Driver-based disk corruption      |
| CaddyWiper     | 2022  | Russia (Sandworm) | Ukraine energy sector | File + partition destruction     |
| AcidRain       | 2022  | Russia         | Viasat KA-SAT modems  | Firmware wipe                    |
| BiBi-Linux     | 2023  | Iran-linked    | Israel                | File overwrite with "BiBi" string|

### Key Principle

**A red team NEVER executes actual data destruction.** The assessment is always:
1. Could an attacker reach the data?
2. Could an attacker destroy the data?
3. Could the organization recover?

---

## Technical Deep-Dive

### Assessment Methodology (Non-Destructive)

#### Step 1: Critical Data Store Inventory

```powershell
# Identify file servers and shares
Get-ADComputer -Filter 'Name -like "*file*" -or Name -like "*nas*" -or Name -like "*data*"' |
  Select-Object Name, DNSHostName, OperatingSystem

# Enumerate all accessible shares
Invoke-ShareFinder -CheckShareAccess | Export-Csv -Path shares_inventory.csv

# Identify database servers
Get-ADComputer -Filter 'Name -like "*sql*" -or Name -like "*db*" -or Name -like "*oracle*"'
Get-Service -ComputerName (Get-ADComputer -Filter *).Name -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match "MSSQL|Oracle|MySQL|Postgres" }
```

```bash
# Linux -- identify critical data mounts and databases
df -hT | grep -v tmpfs
find / -name "*.mdf" -o -name "*.ldf" -o -name "*.dbf" -o -name "ibdata*" 2>/dev/null
systemctl list-units --type=service | grep -iE "mysql|postgres|mongo|redis|elastic"
```

#### Step 2: Backup Architecture Assessment

```powershell
# Identify backup infrastructure
$backupIndicators = @("Veeam","Commvault","Veritas","Acronis","Datto","Cohesity",
                       "Rubrik","Zerto","Unitrends","Arcserve","BackupExec")
foreach ($product in $backupIndicators) {
    Get-ADComputer -Filter "Name -like '*$product*'" -ErrorAction SilentlyContinue
    Get-Service -DisplayName "*$product*" -ErrorAction SilentlyContinue
}

# Check Volume Shadow Copies on critical servers
vssadmin list shadows
vssadmin list shadowstorage

# Windows Server Backup status
wbadmin get versions
wbadmin get disks

# Check if System Restore is enabled
Get-ComputerRestorePoint -ErrorAction SilentlyContinue
```

```bash
# Linux backup assessment
crontab -l 2>/dev/null | grep -iE "backup|rsync|tar|dump|borg|restic"
systemctl list-units | grep -iE "backup|bacula|amanda|bareos"
ls -la /etc/cron.d/ /etc/cron.daily/ 2>/dev/null | grep -i backup
# Check for backup mount points
mount | grep -iE "backup|nfs|cifs"
```

#### Step 3: Backup Isolation Assessment

Key questions to answer and document:

- Are backups on the same network segment as production?
- Can domain admin credentials access backup infrastructure?
- Are backups air-gapped or immutable (WORM storage)?
- Is there an offline/offsite copy (3-2-1 rule compliance)?
- Can backup agents be uninstalled with current privileges?
- Are backup management consoles accessible from the compromised network?

```powershell
# Test if backup servers are accessible from compromised workstation
$backupServers = @("BACKUP01","VEEAM-SRV","COMMVAULT-MA")
foreach ($srv in $backupServers) {
    Test-NetConnection -ComputerName $srv -Port 445 -WarningAction SilentlyContinue |
      Select-Object ComputerName, TcpTestSucceeded
    Test-NetConnection -ComputerName $srv -Port 3389 -WarningAction SilentlyContinue |
      Select-Object ComputerName, TcpTestSucceeded
}

# Check if current credentials have access to backup shares
$backupServers | ForEach-Object {
    $shares = net view "\\$_" 2>&1
    if ($LASTEXITCODE -eq 0) { "ACCESS: $_ -- $shares" }
    else { "DENIED: $_" }
}
```

#### Step 4: Recovery Testing Coordination

Work **with** the operations team (not against them) to validate:

```
Recovery Test Checklist:
[ ] Select non-critical system for restoration test
[ ] Document current RTO commitment vs actual recovery time
[ ] Test bare-metal restore capability
[ ] Verify backup data integrity (not just backup job success)
[ ] Test AD forest recovery procedure
[ ] Validate DNS and authentication recovery sequence
[ ] Measure time from "total loss" to first service restored
```

---

### Wiper Techniques (Knowledge for Simulation Design)

Understanding how wipers work helps design realistic simulation scenarios and
detection test cases. These are **never executed** against production systems.

#### MBR/VBR Overwrite

```
Technique: Overwrite Master Boot Record (sector 0) with zeroes or junk data
Effect:    System cannot boot; data on disk may still be recoverable
Examples:  Shamoon, WhisperGate (stage 1)
Detection: Direct disk access (PhysicalDrive0), abnormal process writing to \\.\PhysicalDrive
Event IDs: Sysmon ID 9 (RawAccessRead), custom kernel driver detection
```

#### File System Corruption

```
Technique: Corrupt NTFS Master File Table ($MFT) or ext4 superblock
Effect:    File system unreadable; data recovery difficult but possible
Examples:  NotPetya (encrypted MFT with no recovery key)
Detection: Unusual access to $MFT, high-volume NTFS journal changes
```

#### Selective File Destruction

```
Technique: Enumerate and overwrite files matching specific extensions
Effect:    Targeted destruction of documents, databases, backups
Examples:  CaddyWiper, BiBi-Linux wiper
Detection: Mass file modification events, abnormal write I/O patterns
```

```python
# SIMULATION REFERENCE ONLY -- identifies files that would be targeted
# A real wiper would overwrite; simulation only catalogs
target_extensions = [
    ".docx", ".xlsx", ".pptx", ".pdf",    # Documents
    ".sql", ".mdf", ".ldf", ".bak",        # Databases
    ".vmdk", ".vhdx", ".ova",              # Virtual machines
    ".pst", ".ost",                         # Email archives
    ".zip", ".7z", ".tar.gz",              # Archives
    ".key", ".pem", ".pfx",                # Certificates
]
```

#### Active Directory Destruction

```
Target:    ntds.dit, SYSVOL, Group Policy Objects
Effect:    Complete loss of authentication infrastructure
Recovery:  Requires AD forest recovery (multi-day process)
Red Team:  Document access to DCs and ability to reach ntds.dit
Detection: Unusual DC disk access, ntdsutil execution, large AD replication events
```

#### Database Destruction

```powershell
# Assessment: Can we reach database engines with destructive privileges?
# SQL Server -- check for sysadmin access
Invoke-SQLAudit -Instance "SQLSRV01" -Username sa -Password <from_cred_dump>
# Document: DROP DATABASE capability, backup file locations, log shipping targets
```

---

## Simulation Deliverables

### Assessment Report Sections

1. **Data Asset Inventory**: All critical data stores identified during engagement
2. **Backup Architecture Map**: Network diagram showing backup data flows
3. **Isolation Assessment**: Whether backups survive a domain compromise
4. **Recovery Gap Analysis**: Documented gaps between stated RTO/RPO and reality
5. **Wiper Resilience Score**: Custom scoring based on assessment findings

### Wiper Resilience Scoring Matrix

| Category                        | Score 1 (Critical Gap) | Score 5 (Resilient)             |
|---------------------------------|------------------------|---------------------------------|
| Backup isolation                | Same network, domain-joined | Air-gapped, separate credentials |
| Backup immutability             | Mutable, deletable     | WORM/immutable storage          |
| Recovery testing                | Never tested           | Quarterly tested, documented    |
| AD recovery plan                | No plan exists         | Documented, tested forest recovery |
| Detection of destructive activity| No detection          | Real-time alerting with response |

---

## Detection Engineering for Wiper Activity

### Key Indicators to Monitor

```yaml
# Sigma-style detection rules for wiper behavior
title: Potential Wiper Activity - Mass File Overwrite
detection:
  selection:
    EventID: 11        # Sysmon FileCreate
  condition: selection | count(TargetFilename) by Computer > 1000
  timeframe: 5m

title: MBR Access Attempt
detection:
  selection:
    EventID: 9         # Sysmon RawAccessRead
    Device: '*PhysicalDrive*'
  filter:
    Image: '*\System32\*'
  condition: selection and not filter

title: Backup Deletion Commands
detection:
  selection:
    EventID: 1         # Sysmon ProcessCreate
    CommandLine|contains:
      - 'vssadmin delete'
      - 'wbadmin delete'
      - 'bcdedit.*recoveryenabled.*No'
      - 'wmic shadowcopy delete'
  condition: selection
```

---

## Cross-References

- [Ransomware Simulation](ransomware-simulation.md)
- [Business Impact Framing](business-impact-framing.md)
- [Active Directory Attacks](../08-privilege-escalation/ad-privilege-escalation.md)
- [Persistence Mechanisms](../10-persistence/README.md)

